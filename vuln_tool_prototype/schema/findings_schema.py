"""
findings_schema.py — the contract between llm_engine.py (producer) and
report_generator.py (consumer). The LLM is instructed to emit JSON matching
Finding exactly; llm_engine.py validates against this schema and retries on
failure, so nothing downstream ever has to handle malformed LLM output.
"""

from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
Confidence = Literal["exact", "semantic", "heuristic"]


class Finding(BaseModel):
    title: str = Field(..., description="Short one-line summary of the finding")
    severity: Severity
    affected_component: str = Field(..., description="Package name, service name, or config item")
    installed_version: Optional[str] = None
    cve_ids: list[str] = []
    description: str = Field(..., description="What the issue is and why it matters, 2-4 sentences")
    remediation: str = Field(..., description="Concrete fix: upgrade to version X, disable service Y, etc.")
    confidence: Confidence = Field(..., description="exact = advisory-matched, semantic = RAG-retrieved, heuristic = config-pattern based (no CVE)")

    @field_validator("severity", mode="before")
    @classmethod
    def _normalise_severity_case(cls, v):
        # LLMs are inconsistent about casing ("high" vs "HIGH") even when told
        # the exact literal values to use. Normalise BEFORE the Literal check
        # runs, rather than after (model_post_init runs too late to help here).
        return v.upper() if isinstance(v, str) else v

    @field_validator("confidence", mode="before")
    @classmethod
    def _normalise_confidence_case(cls, v):
        return v.lower() if isinstance(v, str) else v


class FindingsList(BaseModel):
    """Wrapper so the LLM can return {"findings": [...]} — a bare JSON array
    is harder to coax reliably out of some local models than a keyed object."""
    findings: list[Finding] = []


class AssessmentReport(BaseModel):
    hostname: Optional[str] = None
    os_family: Optional[str] = None
    generated_at: str
    model_used: str
    findings: list[Finding] = []

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
