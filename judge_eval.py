"""
judge_eval.py

LLM-judge scoring for the 3 categories keyword-overlap can't reliably grade
(os_config, k8s_manifest, multi_artefact). Uses one of your own Ollama
models as a judge: feeds it the ground truth + the model's raw response,
and asks for a semantic correctness verdict, a 1-5 quality score, and a
hallucination check (D5) -- all in one call, since the judge already has
both texts in front of it.

Usage:
    python judge_eval.py --judge-model qwen2.5:7B --results evaluation_results.csv

    # Only judge rows the keyword pass flagged as insufficient/unreliable:
    python judge_eval.py --judge-model qwen2.5:7B --results evaluation_results.csv \\
        --keyword-scored keyword_scored_results.csv --only-insufficient
"""

import argparse
import csv
import json
import os
import re
import time

import ollama as ola

from datasetloader import load_full_dataset

JUDGE_CATEGORIES = {"os_config", "k8s_manifest", "multi_artefact"}

TASK_CONTEXT = {
    "os_config": "an AI security analyst reviewing an OS configuration file (sysctl/sshd_config/auditd.conf) against CIS Benchmark best practices",
    "k8s_manifest": "an AI security analyst reviewing a Kubernetes manifest (Pod/RBAC/NetworkPolicy) against the CIS Kubernetes Benchmark",
    "multi_artefact": "an AI security analyst inferring a likely vulnerability/exploit chain from combined system artefacts (packages, kernel version, sysctl, service config)",
}

JUDGE_PROMPT_TEMPLATE = """You are an expert security auditor grading another AI's work. The AI being graded was acting as {task_context}.

GROUND TRUTH (the correct answer, verified by a human security analyst):
\"\"\"
{ground_truth_text}
\"\"\"

THE AI'S RESPONSE (to be graded):
\"\"\"
{response_text}
\"\"\"

Grade the AI's response against the ground truth. The AI may use different wording, a different structure, or omit an exact control/CVE ID number while still correctly identifying the same underlying issue -- judge the SUBSTANCE, not exact phrasing.

Answer these questions:
1. Did the AI correctly identify the same core security issue/finding as the ground truth?
2. Did the AI state any specific fact (a CVE ID, CVSS score, CIS control number, version range, etc.) that is fabricated or unsupported by what it was actually given?
3. Overall quality of the AI's diagnosis, 1-5 (1 = completely wrong or irrelevant, 3 = partially correct or vague, 5 = fully correct and well justified).

Respond with ONLY valid JSON in exactly this schema, no other text:
{{
  "correct": true/false,
  "score": <1-5 integer>,
  "hallucination_detected": true/false,
  "hallucination_note": "<brief description, or empty string if none>",
  "judge_reasoning": "<one or two sentence explanation for your verdict>"
}}
"""


def get_ground_truth_text(gt: dict) -> str:
    parts = []
    for key in ("expected_finding", "cis_control_id", "reference_note"):
        val = gt.get(key)
        if val:
            parts.append(str(val))
    return " ".join(parts) if parts else "(no ground truth text available)"


def build_judge_prompt(category: str, ground_truth_text: str, response_text: str) -> str:
    return JUDGE_PROMPT_TEMPLATE.format(
        task_context=TASK_CONTEXT.get(category, "an AI security analyst"),
        ground_truth_text=ground_truth_text,
        response_text=response_text if response_text else "(no response / call failed)",
    )


def extract_json(text: str):
    if not text:
        return None
    t = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)\s*```", t, re.DOTALL)
    if fence:
        t = fence.group(1).strip()
    try:
        return json.loads(t)
    except (json.JSONDecodeError, ValueError):
        pass
    brace = re.search(r"\{.*\}", t, re.DOTALL)
    if brace:
        try:
            return json.loads(brace.group(0))
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def call_judge(judge_model: str, prompt: str) -> dict:
    start = time.perf_counter()
    try:
        convo = ola.generate(
            model=judge_model,
            prompt=prompt,
            keep_alive="30m",
            options={"num_predict": 300},
        )
        elapsed = time.perf_counter() - start
        parsed = extract_json(convo.get("response", ""))
        if parsed is None:
            return {"ok": False, "error": "judge did not return valid JSON",
                     "raw": convo.get("response", ""), "elapsed": elapsed}
        return {"ok": True, "error": "", "parsed": parsed,
                 "raw": convo.get("response", ""), "elapsed": elapsed}
    except Exception as e:
        elapsed = time.perf_counter() - start
        return {"ok": False, "error": str(e), "raw": "", "elapsed": elapsed}


def load_target_ids(keyword_scored_csv: str) -> set:
    """Returns set of (item_id, model) pairs flagged insufficient_ground_truth=True."""
    targets = set()
    with open(keyword_scored_csv, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if str(row.get("insufficient_ground_truth", "")).strip().upper() == "TRUE":
                targets.add((row.get("item_id"), row.get("model")))
    return targets


def load_already_judged(output_csv: str) -> set:
    judged = set()
    if not os.path.isfile(output_csv):
        return judged
    with open(output_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            judged.add((row.get("item_id"), row.get("model")))
    return judged


def run_judge(judge_model: str, results_csv: str, items_by_id: dict,
              output_csv: str = "judged_results.csv",
              only_pairs: set = None, verbose: bool = True):
    with open(results_csv, newline="", encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))

    already_judged = load_already_judged(output_csv)

    rows_to_judge = []
    for row in rows:
        if row.get("category") not in JUDGE_CATEGORIES:
            continue
        pair = (row.get("item_id"), row.get("model"))
        if only_pairs is not None and pair not in only_pairs:
            continue
        if pair in already_judged:
            continue
        rows_to_judge.append(row)

    if not rows_to_judge:
        print("Nothing to judge (either already done, or no matching rows).")
        return []

    print(f"Judging {len(rows_to_judge)} rows with judge model '{judge_model}'...")

    file_exists = os.path.isfile(output_csv)
    judged_rows = []

    with open(output_csv, "a", newline="", encoding="utf-8") as f:
        fieldnames = ["item_id", "category", "model", "judge_model", "correct",
                      "score", "hallucination_detected", "hallucination_note",
                      "judge_reasoning", "judge_ok", "judge_error"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()

        for row in rows_to_judge:
            item_id = row.get("item_id")
            category = row.get("category")
            model = row.get("model")

            item = items_by_id.get(item_id, {})
            gt_text = get_ground_truth_text(item.get("ground_truth", {}))
            response_text = row.get("response", "")

            prompt = build_judge_prompt(category, gt_text, response_text)
            result = call_judge(judge_model, prompt)

            if verbose:
                print(f"\n[{item_id} | {category} | {model}] -> ", end="")

            out_row = {
                "item_id": item_id, "category": category, "model": model,
                "judge_model": judge_model, "judge_ok": result["ok"], "judge_error": result["error"],
                "correct": "", "score": "", "hallucination_detected": "",
                "hallucination_note": "", "judge_reasoning": "",
            }
            if result["ok"]:
                p = result["parsed"]
                out_row.update({
                    "correct": p.get("correct", ""),
                    "score": p.get("score", ""),
                    "hallucination_detected": p.get("hallucination_detected", ""),
                    "hallucination_note": p.get("hallucination_note", ""),
                    "judge_reasoning": p.get("judge_reasoning", ""),
                })
                if verbose:
                    print(f"correct={out_row['correct']}, score={out_row['score']}, "
                          f"hallucination={out_row['hallucination_detected']}")
            else:
                if verbose:
                    print(f"JUDGE FAILED: {result['error']}")

            writer.writerow(out_row)
            f.flush()
            judged_rows.append(out_row)

    print(f"\nDone. Judged {len(judged_rows)} rows. Results in {output_csv}")
    return judged_rows


def _cli():
    parser = argparse.ArgumentParser(description="LLM-judge scoring for os_config/k8s_manifest/multi_artefact.")
    parser.add_argument("--judge-model", required=True, help="Ollama model to use as judge, e.g. qwen2.5:7B")
    parser.add_argument("--results", default="evaluation_results.csv")
    parser.add_argument("--keyword-scored", default=None,
                         help="Path to keyword_scored_results.csv, used with --only-insufficient")
    parser.add_argument("--only-insufficient", action="store_true",
                         help="Only judge rows flagged insufficient_ground_truth=True by score_findings.py")
    parser.add_argument("--output", default="judged_results.csv")
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

    only_pairs = None
    if args.only_insufficient:
        if not args.keyword_scored:
            parser.error("--only-insufficient requires --keyword-scored <path>")
        only_pairs = load_target_ids(args.keyword_scored)

    run_judge(args.judge_model, args.results, items_by_id,
              output_csv=args.output, only_pairs=only_pairs)


if __name__ == "__main__":
    _cli()
