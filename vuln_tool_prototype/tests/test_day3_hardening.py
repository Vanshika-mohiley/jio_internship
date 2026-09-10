import sys 
from pathlib import Path 
sys.path.insert(0, str(Path(__file__).resolve().parent.parent)) 
from cve.nvd_client import parse_cve_item
from llm.prompt_builder import build_assessment_prompt


def test_rejected_cve_is_ignored():
    assert parse_cve_item({"cve": {"id": "CVE-2020-0001", "vulnStatus": "Rejected", "descriptions": []}}) is None


def test_candidate_is_not_presented_as_confirmed():
    prompt = build_assessment_prompt(
        {"host": {"hostname": "demo", "os_family": "windows"}, "packages": [{"name": "Git", "version": "2.50.1"}]},
        {"matches": [{"package": "Git", "installed_version": "2.50.1", "confidence": "candidate_product_name", "confirmed_vulnerability": False,
                      "candidates": [{"cve_id": "CVE-1999-1558", "product": "digital_openvms", "criteria": "cpe:2.3:a:digital:digital_openvms:7.1:*:*:*:*:*:*:*", "description": "OpenVMS issue"}]}]}
    )
    assert "NOT a confirmed vulnerability" in prompt
    assert "CVE-1999-1558" in prompt

if __name__ == "__main__":
    test_rejected_cve_is_ignored(); test_candidate_is_not_presented_as_confirmed(); print("Day 3 hardening tests passed.")
