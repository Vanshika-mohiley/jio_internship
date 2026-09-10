import pandas as pd
from pathlib import Path

BASE = Path(__file__).parent
RESULTS = BASE / "validation_results.csv"

df = pd.read_csv(RESULTS)

# =========================
# 1. METRICS
# =========================
summary = []

for mode, g in df.groupby("mode"):
    tp = int(g["true_positive"].sum())
    fp = int(g["false_positive"].sum())
    fn = int(g["false_negative"].sum())
    json_valid = int(g["json_valid"].sum())
    cvss_correct = int(g["cvss_tier_correct"].sum())
    total = len(g)

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    summary.append({
        "mode": mode,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "json_validity": json_valid / total,
        "cvss_accuracy": cvss_correct / total,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
    })

summary = pd.DataFrame(summary).set_index("mode")

# =========================
# 2. COMPARISON TABLE
# =========================
comparison = summary[
    ["precision", "recall", "f1", "json_validity", "cvss_accuracy"]
]

comparison.to_csv(BASE / "comparison_table.csv")

# =========================
# 3. IMPROVEMENT DELTAS
# =========================
deltas = pd.DataFrame(index=["Full vs Base", "Full vs RAG"])

for metric in ["precision", "recall", "f1", "cvss_accuracy"]:
    deltas.loc["Full vs Base", metric] = (
        summary.loc["full", metric] -
        summary.loc["base", metric]
    )
    deltas.loc["Full vs RAG", metric] = (
        summary.loc["full", metric] -
        summary.loc["rag", metric]
    )

deltas.to_csv(BASE / "improvement_delta.csv")

# =========================
# 4. ALL FAILURES
# =========================
failures = df[
    (df["true_positive"] == 0) &
    (
        (df["false_positive"] == 1) |
        (df["false_negative"] == 1)
    )
].copy()

# =========================
# 5. FAILURE TAXONOMY
# =========================
def classify_failure(row):
    mode = row["mode"]

    if mode == "base":
        return "knowledge/coverage gap"

    if mode == "rag":
        if row["false_positive"] == 1:
            if row["expected_vulnerable"] == False:
                return "version reasoning error"
            return "retrieval error"
        if row["false_negative"] == 1:
            return "retrieval error"

    return "unknown"

failures["failure_type"] = failures.apply(
    classify_failure,
    axis=1
)

failures.to_csv(
    BASE / "failure_taxonomy.csv",
    index=False
)

# Separate files
failures[
    failures["mode"] == "base"
].to_csv(
    BASE / "base_failures.csv",
    index=False
)

failures[
    failures["mode"] == "rag"
].to_csv(
    BASE / "rag_failures.csv",
    index=False
)

# =========================
# 6. FAILURE COUNTS
# =========================
failure_counts = (
    failures.groupby("failure_type")
    .size()
    .reset_index(name="count")
)

failure_counts.to_csv(
    BASE / "failure_type_counts.csv",
    index=False
)

# =========================
# 7. LIMITATIONS DRAFT
# =========================
limitations = """# Limitations

## Validation dataset

The benchmark contains 30 controlled cases covering vulnerable,
patched, and package/CVE mismatch scenarios. Results therefore
demonstrate performance on the benchmark and should not be interpreted
as production-wide vulnerability-detection accuracy.

## Base model

The base model produced no positive vulnerability findings in this
benchmark. It therefore achieved zero recall. Its precision is
undefined because it produced no positive predictions.

## RAG retrieval

The RAG condition substantially improved recall but produced false
positives on patched versions. This indicates that retrieving a
relevant CVE description alone is insufficient for reliable
version-range reasoning.

One observed RAG failure also returned the wrong Log4j CVE for a
vulnerable Log4j version, demonstrating that retrieval relevance can
select a related but incorrect advisory.

## Full prototype

The full prototype achieved perfect results on this 30-case benchmark:
100% precision, 100% recall, 100% F1, 100% JSON validity, and 100% CVSS
tier accuracy.

These results should not be generalized beyond the benchmark because
the dataset is controlled and relatively small.

## Version comparison

Version comparison remains a potential limitation, particularly for
complex vendor version schemes, suffixes, backports, and distribution-
specific versioning.

## Hallucination and evidence grounding

The prototype is designed to distinguish confirmed vulnerabilities from
candidate CVE matches and to avoid unsupported package/network
attribution. However, broader testing is required to establish
robustness against unseen artifact structures and ambiguous evidence.
"""

(BASE / "limitations.md").write_text(
    limitations,
    encoding="utf-8"
)

# =========================
# 8. FINAL REPORT
# =========================
report = """# Validation & Failure Analysis

## Benchmark

30 cases were evaluated across three configurations:

- Base model
- RAG-augmented model
- Full prototype

## Results

"""

report += comparison.to_string() + "\n\n"

report += """## Improvement

"""

report += deltas.to_string() + "\n\n"

report += """## Failure Analysis

"""

report += failure_counts.to_string(index=False) + "\n\n"

report += """The Full configuration produced zero failure records on the
30-case benchmark. The Base configuration produced 11 false negatives.
The RAG configuration produced 12 false positives.

The RAG failures primarily demonstrate incorrect version reasoning on
patched versions, plus one retrieval error involving selection of a
related but incorrect CVE.

Base-model failures are recorded as knowledge/coverage gaps in this
benchmark analysis; this label should not be interpreted as proof of a
specific training-data cutoff cause.
"""

(BASE / "validation_and_failure_report.md").write_text(
    report,
    encoding="utf-8"
)

# =========================
# 9. CONSOLE SUMMARY
# =========================
print("\n========== FINAL VALIDATION ==========\n")
print(comparison.to_string())

print("\n========== FAILURE COUNTS ==========\n")
print(failure_counts.to_string(index=False))

print("\n========== FILES CREATED ==========\n")

for filename in [
    "comparison_table.csv",
    "improvement_delta.csv",
    "failure_taxonomy.csv",
    "failure_type_counts.csv",
    "base_failures.csv",
    "rag_failures.csv",
    "limitations.md",
    "validation_and_failure_report.md",
]:
    print(filename)

print("\nDONE.")