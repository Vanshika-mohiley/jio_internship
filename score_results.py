"""
score_results.py

Day 4 automated scoring -- the OBJECTIVE dimensions only (no LLM judge needed):

  D6: JSON validity rate    -- does each response parse as valid JSON?
  D1/D2: CVE accuracy       -- does "vulnerable" match ground truth? (+ F1)
  D7: base-vs-RAG delta     -- same as D1/D2, but split by model vs model+rag

Reads:
  - evaluation_results.csv (from run_category_eval.py / model-load.py)
  - your dataset (via load_full_dataset), to get ground_truth per item

Writes:
  - scored_results.csv       -- every row + a "json_valid" and "correct" column
  - summary_by_model.csv     -- per-model, per-category aggregate stats
  - rag_delta.csv            -- base vs RAG accuracy comparison for cve_novel

Usage:
    python score_results.py --results evaluation_results.csv
"""

import argparse
import csv
import json
import re
from collections import defaultdict

from datasetloader import load_full_dataset


# ---------------------------------------------------------------------------
# JSON extraction -- models sometimes wrap JSON in ```json ... ``` fences,
# or add stray text before/after. Try to recover the JSON object regardless.
# ---------------------------------------------------------------------------
def extract_json(response_text: str):
    """Returns (parsed_dict, is_valid). parsed_dict is None if unparseable."""
    if not response_text:
        return None, False

    text = response_text.strip()

    # Strip markdown code fences if present: ```json ... ``` or ``` ... ```
    fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    # First attempt: parse as-is
    try:
        return json.loads(text), True
    except (json.JSONDecodeError, ValueError):
        pass

    # Second attempt: extract the first {...} block, in case of leading/
    # trailing prose the model added despite instructions not to.
    brace_match = re.search(r"\{.*\}", text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0)), True
        except (json.JSONDecodeError, ValueError):
            pass

    return None, False


# ---------------------------------------------------------------------------
# Normalizing "vulnerable" / "expected_vulnerable" values so comparisons
# are apples-to-apples: CSV ground truth is often the string "TRUE"/"FALSE",
# while model output is a JSON true/false or the string "unknown".
# ---------------------------------------------------------------------------
def normalize_bool(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("true", "yes", "1"):
        return True
    if s in ("false", "no", "0"):
        return False
    return None  # covers "unknown", empty, or unparseable


# ---------------------------------------------------------------------------
# Load ground truth from the dataset, keyed by item id
# ---------------------------------------------------------------------------
def load_ground_truth(dataset_paths: dict) -> dict:
    dataset = load_full_dataset(dataset_paths)
    return {item["id"]: item.get("ground_truth", {}) for item in dataset}


# ---------------------------------------------------------------------------
# Main scoring pass
# ---------------------------------------------------------------------------
def score_results(results_csv: str, ground_truth: dict,
                   out_scored: str = "scored_results.csv",
                   out_summary: str = "summary_by_model.csv",
                   out_rag_delta: str = "rag_delta.csv"):

    with open(results_csv, newline="", encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))

    scored_rows = []
    # stats[(model, category)] = {"total":.., "json_valid":.., "tp":.., "fp":.., "fn":.., "tn":.., "graded":..}
    stats = defaultdict(lambda: {"total": 0, "json_valid": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0, "graded": 0})

    for row in rows:
        item_id = row.get("item_id")
        category = row.get("category")
        model = row.get("model")
        response = row.get("response", "")
        ok = str(row.get("ok", "")).strip().upper() == "TRUE"

        parsed, json_valid = extract_json(response) if ok else (None, False)

        key = (model, category)
        stats[key]["total"] += 1
        if json_valid:
            stats[key]["json_valid"] += 1

        correct = None
        model_vulnerable = None
        expected_vulnerable = None

        if category in ("cve_known", "cve_novel") and json_valid:
            gt = ground_truth.get(item_id, {})
            expected_vulnerable = normalize_bool(gt.get("expected_vulnerable"))
            model_vulnerable = normalize_bool(parsed.get("vulnerable")) if isinstance(parsed, dict) else None

            if expected_vulnerable is not None and model_vulnerable is not None:
                correct = (expected_vulnerable == model_vulnerable)
                stats[key]["graded"] += 1
                if expected_vulnerable and model_vulnerable:
                    stats[key]["tp"] += 1
                elif not expected_vulnerable and not model_vulnerable:
                    stats[key]["tn"] += 1
                elif not expected_vulnerable and model_vulnerable:
                    stats[key]["fp"] += 1
                elif expected_vulnerable and not model_vulnerable:
                    stats[key]["fn"] += 1

        scored_rows.append({
            **row,
            "json_valid": json_valid,
            "model_vulnerable": model_vulnerable,
            "expected_vulnerable": expected_vulnerable,
            "correct": correct,
        })

    # --- write scored_results.csv ---
    fieldnames = list(scored_rows[0].keys()) if scored_rows else []
    with open(out_scored, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(scored_rows)

    # --- write summary_by_model.csv ---
    summary_rows = []
    for (model, category), s in sorted(stats.items()):
        json_validity_rate = s["json_valid"] / s["total"] if s["total"] else 0
        tp, fp, fn, tn = s["tp"], s["fp"], s["fn"], s["tn"]
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        accuracy = (tp + tn) / s["graded"] if s["graded"] else None
        # coverage: what fraction of items the model actually committed to an
        # answer on (vs. saying "unknown") -- essential context for reading
        # accuracy fairly, since a model that answers 1/20 items and gets it
        # right is NOT comparable to one that answers 20/20 correctly.
        coverage = s["graded"] / s["total"] if s["total"] else 0

        summary_rows.append({
            "model": model,
            "category": category,
            "total_items": s["total"],
            "json_valid_count": s["json_valid"],
            "json_validity_rate": round(json_validity_rate, 3),
            "graded_items": s["graded"],
            "coverage": round(coverage, 3),
            "accuracy": round(accuracy, 3) if accuracy is not None else "",
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        })

    with open(out_summary, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()) if summary_rows else [])
        writer.writeheader()
        writer.writerows(summary_rows)

    # --- write rag_delta.csv: match base model rows against their "+rag" pair ---
    rag_pairs = defaultdict(dict)  # base_model -> {"base": row, "rag": row}
    for r in summary_rows:
        if r["category"] != "cve_novel":
            continue
        if r["model"].endswith("+rag"):
            base_name = r["model"][:-4]
            rag_pairs[base_name]["rag"] = r
        else:
            rag_pairs[r["model"]]["base"] = r

    delta_rows = []
    for base_name, pair in rag_pairs.items():
        if "base" in pair and "rag" in pair:
            base, rag = pair["base"], pair["rag"]
            delta_rows.append({
                "model": base_name,
                "base_coverage": base["coverage"],
                "rag_coverage": rag["coverage"],
                "base_accuracy": base["accuracy"],
                "rag_accuracy": rag["accuracy"],
                "accuracy_delta": (rag["accuracy"] - base["accuracy"])
                                   if base["accuracy"] != "" and rag["accuracy"] != "" else "",
                "base_json_validity": base["json_validity_rate"],
                "rag_json_validity": rag["json_validity_rate"],
                "base_f1": base["f1"],
                "rag_f1": rag["f1"],
                "note": ("base sample too small (<5 graded items) -- accuracy comparison unreliable"
                         if base["graded_items"] < 5 else ""),
            })

    if delta_rows:
        with open(out_rag_delta, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(delta_rows[0].keys()))
            writer.writeheader()
            writer.writerows(delta_rows)

    print(f"Scored {len(scored_rows)} rows.")
    print(f"  -> {out_scored}")
    print(f"  -> {out_summary}")
    if delta_rows:
        print(f"  -> {out_rag_delta}")
    else:
        print("  (no base/RAG pairs found for rag_delta.csv -- check model naming)")

    return scored_rows, summary_rows, delta_rows


def _cli():
    parser = argparse.ArgumentParser(description="Score evaluation_results.csv (D6 JSON validity, D1/D2 CVE accuracy/F1, D7 RAG delta).")
    parser.add_argument("--results", default="evaluation_results.csv")
    args = parser.parse_args()

    ground_truth = load_ground_truth({
        "cve_known_csv": "category1_final.csv",
        "cve_novel_csv": "category2_final.csv",
        "os_config_index_csv": "os_config_index.csv",
        "os_config_base_dir": "category3snippets",
        "k8s_index_csv": "k8s_index.csv",
        "k8s_base_dir": "category4_manifest",
        "multi_artefact_dir": "category5_scenarios",
    })

    score_results(args.results, ground_truth)


if __name__ == "__main__":
    _cli()
