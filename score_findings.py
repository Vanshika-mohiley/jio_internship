"""
score_findings.py

Rough, fast, keyword-based scoring for the 3 categories that don't have a
clean true/false ground truth field (os_config, k8s_manifest, multi_artefact).

This is intentionally approximate -- a quick first pass to get SOME numbers
today, not a substitute for the LLM-judge. It checks:

  1. control_id_match  -- does the response mention the same CIS control ID
                           (or, for multi_artefact, the same reference CVE ID)
                           as the ground truth? Normalized so "CIS 5.2.1",
                           "CIS-5.2.1", and "5.2.1" all count as equal.
  2. keyword_overlap    -- what fraction of meaningful words from the
                           ground truth's expected_finding / reference_note
                           text also appear somewhere in the raw response.

Works on the RAW response text, not parsed JSON -- so a model with broken
JSON (e.g. phi3.5 at 8% valid JSON on os_config) still gets partial credit
if it mentions the right control/CVE and the right concepts.

Usage:
    python score_findings.py --results evaluation_results.csv
"""

import argparse
import csv
import re
from collections import defaultdict

from datasetloader import load_full_dataset


STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "of", "to", "in", "for", "on", "at", "by", "with", "as", "and", "or",
    "but", "if", "this", "that", "these", "those", "it", "its", "not",
    "may", "can", "will", "which", "who", "than", "then", "so", "such",
    "has", "have", "had", "do", "does", "did", "from", "into", "than",
}

TARGET_CATEGORIES = {"os_config", "k8s_manifest", "multi_artefact"}


def normalize_control_id(text: str) -> set:
    """
    Extracts control-ID-like tokens (e.g. "5.2.1", "4.1.2.3") from a string,
    stripping prefixes like "CIS" so "CIS 5.2.1" and "5.2.1" both yield {"5.2.1"}.
    Also captures bare CVE IDs (e.g. "CVE-2022-3294") since multi_artefact's
    ground truth is a reference CVE, not a CIS control.
    """
    ids = set()
    # CIS-style numeric control IDs: 4.1.2.3, 5.2.1, etc.
    for m in re.findall(r"\d+(?:\.\d+){1,4}", text):
        ids.add(m)
    # CVE IDs
    for m in re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE):
        ids.add(m.upper())
    return ids


def extract_keywords(text: str) -> set:
    """Lowercase words, length > 3, stopwords removed."""
    words = re.findall(r"[a-zA-Z]{4,}", text.lower())
    return {w for w in words if w not in STOPWORDS}


def get_ground_truth_text(gt: dict) -> str:
    """Combines whichever ground-truth fields are present into one string."""
    parts = []
    for key in ("expected_finding", "cis_control_id", "reference_note"):
        val = gt.get(key)
        if val:
            parts.append(str(val))
    return " ".join(parts)


def get_input_artefact_text(item: dict) -> str:
    """
    Returns the raw input text the model was actually GIVEN in its prompt
    (config snippet, manifest YAML, or combined bundle fields). Keywords
    appearing here get excluded from the ground-truth keyword set, since a
    model will naturally echo field names/values from its own input
    regardless of whether its diagnosis is correct -- e.g. a response will
    always mention "hostPID" if the manifest has a hostPID field, whether
    or not the model correctly flagged it as the actual problem.
    """
    parts = []
    for key in ("config_snippet", "manifest_yaml", "package_list",
                "kernel_version", "sysctl_output", "service_config"):
        val = item.get(key)
        if val:
            parts.append(str(val))
    return " ".join(parts)


def score_findings(results_csv: str, items_by_id: dict,
                    out_csv: str = "keyword_scored_results.csv",
                    out_summary: str = "keyword_summary.csv",
                    overlap_threshold: float = 0.4):

    with open(results_csv, newline="", encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))

    scored_rows = []
    stats = defaultdict(lambda: {"total": 0, "control_match": 0,
                                  "overlap_sum": 0.0, "likely_correct": 0,
                                  "insufficient_gt": 0})

    for row in rows:
        category = row.get("category")
        if category not in TARGET_CATEGORIES:
            continue

        item_id = row.get("item_id")
        model = row.get("model")
        response = (row.get("response") or "").lower()
        ok = str(row.get("ok", "")).strip().upper() == "TRUE"

        item = items_by_id.get(item_id, {})
        gt = item.get("ground_truth", {})
        gt_text = get_ground_truth_text(gt)
        input_text = get_input_artefact_text(item)

        gt_ids = normalize_control_id(gt_text)
        response_ids = normalize_control_id(response) if ok else set()
        control_match = bool(gt_ids & response_ids)

        # Exclude keywords that already appear in the model's own input --
        # those get echoed regardless of whether the diagnosis is correct,
        # so only count vocabulary that's genuinely diagnostic.
        input_keywords = extract_keywords(input_text)
        gt_keywords = extract_keywords(gt_text) - input_keywords

        overlap_ratio = 0.0
        if ok and gt_keywords:
            response_keywords = extract_keywords(response)
            matched = gt_keywords & response_keywords
            overlap_ratio = len(matched) / len(gt_keywords)

        # If fewer than 2 diagnostic keywords remain after removing input
        # echo, there's not enough ground-truth text to meaningfully test
        # against -- flag this rather than silently scoring it as a miss,
        # since a correct model could score 0 here purely from thin
        # ground-truth annotation, not from being wrong.
        insufficient_ground_truth = len(gt_keywords) < 2

        if insufficient_ground_truth:
            likely_correct = control_match  # only signal we actually have
        else:
            likely_correct = control_match or overlap_ratio >= overlap_threshold

        key = (model, category)
        stats[key]["total"] += 1
        if control_match:
            stats[key]["control_match"] += 1
        stats[key]["overlap_sum"] += overlap_ratio
        if likely_correct:
            stats[key]["likely_correct"] += 1
        if insufficient_ground_truth:
            stats[key]["insufficient_gt"] += 1

        scored_rows.append({
            **row,
            "ground_truth_ids": ",".join(sorted(gt_ids)),
            "diagnostic_keywords_required": len(gt_keywords),
            "insufficient_ground_truth": insufficient_ground_truth,
            "control_id_match": control_match,
            "keyword_overlap_ratio": round(overlap_ratio, 3),
            "likely_correct": likely_correct,
        })

    if scored_rows:
        fieldnames = list(scored_rows[0].keys())
        with open(out_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(scored_rows)

    summary_rows = []
    for (model, category), s in sorted(stats.items()):
        summary_rows.append({
            "model": model,
            "category": category,
            "total_items": s["total"],
            "control_id_match_rate": round(s["control_match"] / s["total"], 3) if s["total"] else 0,
            "avg_keyword_overlap": round(s["overlap_sum"] / s["total"], 3) if s["total"] else 0,
            "likely_correct_rate": round(s["likely_correct"] / s["total"], 3) if s["total"] else 0,
            "insufficient_gt_rate": round(s["insufficient_gt"] / s["total"], 3) if s["total"] else 0,
        })

    with open(out_summary, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()) if summary_rows else [])
        writer.writeheader()
        writer.writerows(summary_rows)

    print(f"Scored {len(scored_rows)} rows across {TARGET_CATEGORIES}.")
    print(f"  -> {out_csv}")
    print(f"  -> {out_summary}")
    print("\nNOTE: this is a rough keyword-overlap pass, not a substitute for")
    print("manual review or an LLM judge -- treat 'likely_correct' as a first")
    print("filter to prioritize what to spot-check, not a final grade.")

    return scored_rows, summary_rows


def _cli():
    parser = argparse.ArgumentParser(description="Rough keyword-overlap scoring for os_config/k8s_manifest/multi_artefact.")
    parser.add_argument("--results", default="evaluation_results.csv")
    parser.add_argument("--threshold", type=float, default=0.4,
                         help="Keyword overlap ratio above which a response counts as 'likely_correct' (default 0.4)")
    args = parser.parse_args()

    dataset = load_full_dataset({
        "cve_known_csv": "category1_final.csv",
        "cve_novel_csv": "category2_final.csv",
        "os_config_index_csv": "os_config_index.csv",
        "os_config_base_dir": "category3snippets",
        "k8s_index_csv": "k8s_index.csv",
        "k8s_base_dir": "category4_manifest",
        "multi_artefact_dir": "category5_scenarios",
    })
    items_by_id = {item["id"]: item for item in dataset}

    score_findings(args.results, items_by_id, overlap_threshold=args.threshold)


if __name__ == "__main__":
    _cli()
