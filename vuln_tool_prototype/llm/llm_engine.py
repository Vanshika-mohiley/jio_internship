#!/usr/bin/env python3
"""
llm_engine.py — Day 3 deliverable. Sends prompts to a local Ollama instance
and validates the response against schema.findings_schema.FindingsList,
retrying with corrective feedback if the model returns malformed JSON.

CRITICAL DESIGN CONSTRAINT: OLLAMA_URL is hardcoded to localhost. This is
not just a default — it is the architectural enforcement of the
"data never leaves the machine" requirement. If you need to point this at
a different host for testing, do it explicitly and note the deviation in
your report; don't silently parameterise this to an env var that could
point off-box without a visible code change.
"""

from __future__ import annotations
import json
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from schema.findings_schema import FindingsList
from pydantic import ValidationError

OLLAMA_URL = "http://localhost:11434/api/generate"  # local-only, by design — see module docstring

# A representative subset of sysctl keys worth showing the LLM; sending all
# ~800 raw kernel params (see linux_collector.py output) would waste context
# window on irrelevant values (e.g. per-NIC queue tuning).
SECURITY_RELEVANT_SYSCTL_KEYS = {
    "net.ipv4.ip_forward",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.tcp_syncookies",
    "kernel.randomize_va_space",
    "fs.suid_dumpable",
    "kernel.dmesg_restrict",
    "kernel.kptr_restrict",
}

OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"

# Preference order when multiple models are available locally.
# Falls through to whatever's installed if none of these match.
PREFERRED_MODELS = ["qwen2.5:7b", "llama3", "mistral"]

def validate_finding_evidence(findings, artifacts):
    """
    Remove findings that make unsupported package-to-port/process claims.
    """
    listening = artifacts.get("listening_ports", [])

    explicitly_attributed = set()

    for item in listening:
        process = item.get("process")
        if process:
            explicitly_attributed.add(str(process).lower())

    validated = []

    for finding in findings:
        component = finding.affected_component.lower()

        # If the finding claims a package is network-facing,
        # require explicit process attribution.
        network_claim = any(
            word in finding.description.lower()
            for word in [
                "listening",
                "network interface",
                "port",
                "network-facing",
            ]
        )

        if network_claim:
            if component not in explicitly_attributed:
                # Don't allow unsupported package/port attribution.
                continue

        validated.append(finding)

    return validated
def choose_local_model() -> str:
    """
    Queries Ollama for locally-available models and picks one, preferring
    PREFERRED_MODELS in order. Falls back to the first available model if
    none of the preferred ones are pulled. Raises RuntimeError if Ollama
    is unreachable or no models are installed at all.
    """
    req = urllib.request.Request(OLLAMA_TAGS_URL, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Could not reach Ollama at {OLLAMA_TAGS_URL} ({e}). Is `ollama serve` running?"
        ) from e

    available = [m["model"] for m in data.get("models", [])]
    if not available:
        raise RuntimeError(
            "No models found in Ollama. Pull one first, e.g. `ollama pull qwen2.5:7b`."
        )

    for preferred in PREFERRED_MODELS:
        for model in available:
            if model.lower().startswith(preferred.lower()):
                return model

    # None of our preferred models are installed — just use whatever is.
    return available[0]
def _call_ollama_raw(prompt: str, model: str, timeout: int = 600) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",  # Ollama's native JSON-mode constraint, when the model supports it
        "options": {"temperature": 0.1},  # low temperature: we want consistent, non-creative extraction
    }
    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Could not reach Ollama at {OLLAMA_URL} ({e}). Is `ollama serve` running "
            f"and is the model pulled (`ollama pull <model>`)?"
        ) from e
    return data.get("response", "")


def _extract_json_object(text: str) -> str:
    """
    Models occasionally wrap JSON in prose or markdown fences despite
    instructions. Strip fences, then grab the first {...} balanced-looking
    span as a best-effort fallback before giving up.
    """
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()
    if text.startswith("{"):
        return text
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return match.group(0)
    return text


def assess(prompt: str, model: str = "llama3", max_retries: int = 3,artifacts: Optional[dict] = None) -> FindingsList:
    """
    Sends the prompt to Ollama, validates the response against FindingsList.
    On validation failure, re-prompts with the specific Pydantic error
    appended so the model can self-correct, up to max_retries times.
    Raises RuntimeError if it never gets valid JSON.
    """
    current_prompt = prompt
    last_error: Optional[str] = None

    for attempt in range(1, max_retries + 1):
        raw_response = _call_ollama_raw(current_prompt, model=model)
        json_text = _extract_json_object(raw_response)

        try:
            parsed = json.loads(json_text)
            findings = FindingsList.model_validate(parsed)
            if artifacts is not None:
                findings.findings = validate_finding_evidence(findings.findings, artifacts)
            return findings
        except (json.JSONDecodeError, ValidationError) as e:
            last_error = str(e)
            current_prompt = (
                f"{prompt}\n\n---\n"
                f"Your previous response could not be parsed. Error: {last_error}\n"
                f"Your previous response was:\n{raw_response[:1000]}\n\n"
                f"Return ONLY the corrected JSON object, matching the schema exactly. "
                f"No prose, no markdown fences."
            )

    raise RuntimeError(
        f"Ollama did not return valid FindingsList JSON after {max_retries} attempts. "
        f"Last error: {last_error}"
    )


def filter_security_relevant_kernel_params(kernel_params: list) -> list:
    """Helper for main.py: cut ~800 sysctl entries down to the ones prompt_builder wants."""
    return [kp for kp in kernel_params if kp.key in SECURITY_RELEVANT_SYSCTL_KEYS]
