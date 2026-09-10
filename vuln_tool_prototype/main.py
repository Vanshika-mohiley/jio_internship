#!/usr/bin/env python3
"""
main.py — Day 4 deliverable. End-to-end CLI:
  collect artefacts -> enrich with local CVE knowledge base -> assess via
  local LLM -> write AssessmentReport JSON -> (optionally) launch the
  Streamlit dashboard on it.

Usage:
    python3 main.py --os linux --chroma-dir ./data/chroma --db-path ./data/advisories.db \\
        --model llama3 --out report.json

    # then view it:
    streamlit run report/report_generator.py -- --report-json report.json
"""

from __future__ import annotations
import argparse
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from collectors.linux_collector import collect as collect_linux
from schema.findings_schema import AssessmentReport, Finding
from cve.cve_index import CVEIndex
from cve.retrieval import enrich_package
from llm.prompt_builder import build_package_prompt, build_host_config_prompt
from llm.llm_engine import assess, filter_security_relevant_kernel_params


def run_pipeline(
    os_choice: str,
    chroma_dir: str,
    db_path: str,
    model: str,
    max_retries: int,
    skip_llm: bool = False,
) -> AssessmentReport:
    print(f"[1/4] Collecting OS artefacts ({os_choice}) ...")
    if os_choice == "linux":
        collection = collect_linux()
    else:
        raise NotImplementedError(
            f"main.py currently wires up the linux collector only; "
            f"container_collector.py / windows_collector.ps1 outputs can be loaded "
            f"and merged the same way once you're ready to wire them in."
        )
    print(f"  {len(collection.packages)} packages, {len(collection.listening_ports)} ports, "
          f"{len(collection.services)} services, {len(collection.suid_binaries)} SUID binaries.")

    print("[2/4] Enriching packages against local CVE knowledge base ...")
    if not Path(db_path).exists():
        raise SystemExit(
            f"No CVE knowledge base found at {db_path}. Run nvd_ingest.py first to build it "
            f"(see cve/nvd_ingest.py) — main.py only ever READS the local knowledge base, "
            f"it never fetches from the network itself."
        )
    cve_index = CVEIndex(persist_dir=chroma_dir)
    enrichments = []
    for pkg in collection.packages:
        result = enrich_package(pkg.name, pkg.version, db_path, cve_index)
        if result["confidence"] != "none":
            enrichments.append((pkg, result))
    print(f"  {len(enrichments)}/{len(collection.packages)} packages have candidate CVE matches "
          f"(exact or semantic) worth sending to the LLM.")

    findings: list[Finding] = []

    if skip_llm:
        print("[3/4] Skipping LLM assessment (--skip-llm) — writing enrichment-only report.")
    else:
        print(f"[3/4] Running LLM assessment via Ollama (model={model}) ...")
        for i, (pkg, enrichment) in enumerate(enrichments, 1):
            prompt = build_package_prompt(pkg.name, pkg.version, enrichment)
            try:
                result = assess(prompt, model=model, max_retries=max_retries)
                findings.extend(result.findings)
            except RuntimeError as e:
                print(f"  [{i}/{len(enrichments)}] {pkg.name}: LLM assessment failed — {e}")
                continue
            print(f"  [{i}/{len(enrichments)}] {pkg.name}: {len(result.findings)} finding(s)")

        relevant_kernel_params = filter_security_relevant_kernel_params(collection.kernel_params)
        host_prompt = build_host_config_prompt(
            hostname=collection.host.hostname or socket.gethostname(),
            os_family=collection.host.os_family,
            listening_ports=collection.listening_ports,
            suid_binaries=collection.suid_binaries,
            services=collection.services,
            kernel_params=relevant_kernel_params,
        )
        try:
            host_result = assess(host_prompt, model=model, max_retries=max_retries)
            findings.extend(host_result.findings)
            print(f"  Host configuration review: {len(host_result.findings)} finding(s)")
        except RuntimeError as e:
            print(f"  Host configuration review failed — {e}")

    print("[4/4] Assembling report ...")
    report = AssessmentReport(
        hostname=collection.host.hostname,
        os_family=collection.host.os_family,
        generated_at=datetime.now(timezone.utc).isoformat(),
        model_used=model if not skip_llm else "none (--skip-llm)",
        findings=findings,
    )
    return report


def main():
    ap = argparse.ArgumentParser(description="AI-augmented vulnerability assessment — end to end.")
    ap.add_argument("--os", dest="os_choice", choices=["linux"], default="linux",
                     help="Only linux is wired into main.py so far (see run_pipeline docstring).")
    ap.add_argument("--chroma-dir", default="./data/chroma")
    ap.add_argument("--db-path", default="./data/advisories.db")
    ap.add_argument("--model", default="llama3", help="Ollama model name (must already be pulled)")
    ap.add_argument("--max-retries", type=int, default=3)
    ap.add_argument("--out", default="report.json")
    ap.add_argument("--skip-llm", action="store_true",
                     help="Run collection + enrichment only, skip Ollama calls (useful without a local model pulled yet)")
    args = ap.parse_args()

    report = run_pipeline(
        os_choice=args.os_choice,
        chroma_dir=args.chroma_dir,
        db_path=args.db_path,
        model=args.model,
        max_retries=args.max_retries,
        skip_llm=args.skip_llm,
    )

    Path(args.out).write_text(report.model_dump_json(indent=2))
    counts = report.counts_by_severity
    print(f"\nDone. {len(report.findings)} total findings "
          f"(Critical={counts['CRITICAL']}, High={counts['HIGH']}, Medium={counts['MEDIUM']}, "
          f"Low={counts['LOW']}, Info={counts['INFORMATIONAL']}).")
    print(f"Report written to {args.out}")
    print(f"View it with: streamlit run report/report_generator.py -- --report-json {args.out}")


if __name__ == "__main__":
    main()
