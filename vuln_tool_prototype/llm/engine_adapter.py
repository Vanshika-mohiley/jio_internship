from __future__ import annotations
from .llm_engine import assess as _assess, choose_local_model

def assess(prompt: str, model: str | None = None, artifacts: dict | None = None):
    selected = model or choose_local_model()
    result = _assess(prompt, model=selected, max_retries=2, artifacts=artifacts)
    return selected, result