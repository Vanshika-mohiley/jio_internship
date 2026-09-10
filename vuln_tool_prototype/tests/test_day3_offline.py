"""
test_day3_offline.py — validates prompt_builder.py output and llm_engine.py's
JSON-extraction + Pydantic-validation + retry logic WITHOUT a live Ollama
instance (mocks the network call), since Ollama isn't installed in this
build sandbox. Run a real end-to-end check against `ollama serve` on your
own machine once it's available.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from unittest.mock import patch
from llm.prompt_builder import build_package_prompt, build_host_config_prompt, OUTPUT_FORMAT_INSTRUCTIONS
from llm import llm_engine
from schema.artifact_schema import ListeningPort, SUIDBinary, ServiceUnit, KernelParam


def test_package_prompt_exact():
    enrichment = {
        "exact_matches": [
            {"cve_id": "CVE-2023-0002", "package_name": "openssl", "fixed_version": "1.1.1f-1ubuntu2.20", "distro": "ubuntu-focal", "source": "usn"}
        ],
        "semantic_matches": [],
    }
    prompt = build_package_prompt("openssl", "1.1.1f-1ubuntu2.16", enrichment)
    assert "CVE-2023-0002" in prompt
    assert "1.1.1f-1ubuntu2.16" in prompt
    assert 'confidence="exact"' in prompt
    assert OUTPUT_FORMAT_INSTRUCTIONS in prompt
    print("PASS: build_package_prompt (exact-match path)")


def test_package_prompt_semantic():
    enrichment = {
        "exact_matches": [],
        "semantic_matches": [
            {"cve_id": "CVE-2023-0001", "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL", "description": "heap overflow"}
        ],
    }
    prompt = build_package_prompt("libexample", "2.1.0", enrichment)
    assert "CVE-2023-0001" in prompt
    assert 'confidence="semantic"' in prompt
    print("PASS: build_package_prompt (semantic-fallback path)")


def test_host_config_prompt():
    ports = [ListeningPort(protocol="tcp", local_address="0.0.0.0", local_port=23, process="telnetd")]
    suid = [SUIDBinary(path="/usr/bin/weird_setuid_tool", owner="root", permissions="-rwsr-xr-x")]
    services = [ServiceUnit(name="telnet.service", state="active")]
    kernel = [KernelParam(key="net.ipv4.ip_forward", value="1")]
    prompt = build_host_config_prompt("test-host", "linux", ports, suid, services, kernel)
    assert "telnetd" in prompt
    assert "weird_setuid_tool" in prompt
    assert "net.ipv4.ip_forward = 1" in prompt
    assert 'confidence="heuristic"' in prompt
    print("PASS: build_host_config_prompt")


def test_extract_json_handles_fences_and_prose():
    fenced = '```json\n{"findings": []}\n```'
    assert llm_engine._extract_json_object(fenced) == '{"findings": []}'

    prose_wrapped = 'Sure, here is the JSON:\n{"findings": [{"title": "x"}]}\nHope that helps!'
    extracted = llm_engine._extract_json_object(prose_wrapped)
    assert extracted.startswith("{") and extracted.endswith("}")
    print("PASS: _extract_json_object handles fences and prose wrapping")


def test_assess_retries_on_malformed_then_succeeds():
    """Simulates: first Ollama response is broken JSON, second is valid."""
    responses = [
        'this is not json at all',
        '{"findings": [{"title": "Outdated OpenSSL", "severity": "high", '
        '"affected_component": "openssl", "installed_version": "1.1.1f", '
        '"cve_ids": ["CVE-2023-0002"], "description": "vulnerable build", '
        '"remediation": "upgrade to 1.1.1f-1ubuntu2.20", "confidence": "exact"}]}',
    ]
    call_count = {"n": 0}

    def fake_call(prompt, model, timeout=120):
        idx = call_count["n"]
        call_count["n"] += 1
        return responses[idx]

    with patch.object(llm_engine, "_call_ollama_raw", side_effect=fake_call):
        result = llm_engine.assess("dummy prompt", model="fake-model", max_retries=3)

    assert call_count["n"] == 2, "Expected exactly one retry"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "HIGH"  # normalised to uppercase by model_post_init
    assert result.findings[0].cve_ids == ["CVE-2023-0002"]
    print("PASS: assess() retries on malformed JSON and succeeds on valid retry")


def test_assess_raises_after_exhausting_retries():
    def always_broken(prompt, model, timeout=120):
        return "still not json"

    with patch.object(llm_engine, "_call_ollama_raw", side_effect=always_broken):
        try:
            llm_engine.assess("dummy prompt", model="fake-model", max_retries=2)
            assert False, "Expected RuntimeError"
        except RuntimeError as e:
            assert "did not return valid" in str(e)
    print("PASS: assess() raises RuntimeError after exhausting retries")


def test_filter_security_relevant_kernel_params():
    params = [
        KernelParam(key="net.ipv4.ip_forward", value="1"),
        KernelParam(key="some.irrelevant.tuning.key", value="42"),
        KernelParam(key="kernel.randomize_va_space", value="2"),
    ]
    filtered = llm_engine.filter_security_relevant_kernel_params(params)
    assert len(filtered) == 2
    assert all(p.key in llm_engine.SECURITY_RELEVANT_SYSCTL_KEYS for p in filtered)
    print("PASS: filter_security_relevant_kernel_params")


if __name__ == "__main__":
    test_package_prompt_exact()
    test_package_prompt_semantic()
    test_host_config_prompt()
    test_extract_json_handles_fences_and_prose()
    test_assess_retries_on_malformed_then_succeeds()
    test_assess_raises_after_exhausting_retries()
    test_filter_security_relevant_kernel_params()
    print("\nAll Day 3 offline checks passed.")
