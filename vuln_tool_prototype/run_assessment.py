"""Day 3 CLI: assess an existing collection + local enrichment through loopback Ollama."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from llm.engine_adapter import assess
from llm.prompt_builder import build_assessment_prompt

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collection", default="windows_artifacts.json")
    parser.add_argument("--enrichment", default="data/enrichment.json")
    parser.add_argument("--out", default="data/assessment.json")
    parser.add_argument("--model")
    args = parser.parse_args()
    collection = json.loads(Path(args.collection).read_text(encoding="utf-8-sig"))
    enrichment = json.loads(Path(args.enrichment).read_text(encoding="utf-8"))
    model, findings = assess(build_assessment_prompt(collection, enrichment), args.model, artifacts= collection)
    report = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_used": model,
        "network_used": False,
        "findings": findings.model_dump()["findings"],
    }
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Local assessment complete: {len(report['findings'])} finding(s); model={model}.")

if __name__ == "__main__":
    main()
