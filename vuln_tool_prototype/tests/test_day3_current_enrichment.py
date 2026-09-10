import sys 
from pathlib import Path 
sys.path.insert(0, str(Path(__file__).resolve().parent.parent)) 
import json
from unittest.mock import patch
from llm.prompt_builder import build_assessment_prompt
from llm import llm_engine


def test_windows_artifacts_and_enrichment_flow_to_structured_json():
    enrichment = json.loads(open("data/enrichment.json", encoding="utf-8").read())
    collection = json.loads(open("windows_artifacts.json", encoding="utf-8").read())
    prompt = build_assessment_prompt(collection, enrichment)

    # Both evidence classes must reach the LLM prompt.
    assert "Git" in prompt
    assert "CVE-1999-1558" in prompt
    assert "tcp/445" in prompt
    assert "LanmanServer" in prompt
    # The known false-positive CVE must remain explicitly unconfirmed.
    assert "confirmed=False" in prompt
    assert "candidate_product_name" in prompt

    fake = '{"findings": []}'
    with patch.object(llm_engine, "_call_ollama_raw", return_value=fake):
        result = llm_engine.assess(prompt, model="fixture", max_retries=1)
    assert result.findings == []


if __name__ == "__main__":
    test_windows_artifacts_and_enrichment_flow_to_structured_json()
    print("Windows artifacts + enrichment -> structured JSON test passed.")
