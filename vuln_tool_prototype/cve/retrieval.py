"""
retrieval.py — the single function Day 3's prompt_builder.py calls per
artefact. Exact-match advisory lookup first (highest confidence, since it's
literally "this version fixes this CVE"); semantic search over NVD
descriptions as a fallback so packages with no vendor-advisory coverage
still surface plausible candidates for the LLM to reason over.
"""

from __future__ import annotations
from typing import Optional

from .package_lookup import lookup_exact
from .cve_index import CVEIndex


def enrich_package(
    package_name: str,
    installed_version: str,
    db_path: str,
    cve_index: CVEIndex,
    distro: Optional[str] = None,
    semantic_top_k: int = 3,
) -> dict:
    """
    Returns:
      {
        "package": ..., "version": ...,
        "exact_matches": [ {package_name, fixed_version, cve_id, distro, source}, ... ],
        "semantic_matches": [ {cve_id, description, cvss_v3_score, cvss_v3_severity, distance}, ... ],
        "confidence": "exact" | "semantic" | "none"
      }
    exact_matches is populated first; semantic_matches is only computed if
    exact_matches is empty, to avoid burning embedding calls when we already
    have a high-confidence answer.
    """
    exact = lookup_exact(db_path, package_name, installed_version, distro=distro)
    if exact:
        return {
            "package": package_name,
            "version": installed_version,
            "exact_matches": exact,
            "semantic_matches": [],
            "confidence": "exact",
        }

    semantic = cve_index.semantic_search(f"{package_name} {installed_version}", top_k=semantic_top_k)
    return {
        "package": package_name,
        "version": installed_version,
        "exact_matches": [],
        "semantic_matches": semantic,
        "confidence": "semantic" if semantic else "none",
    }


def enrich_all_packages(
    packages: list,  # list of schema.artifact_schema.Package
    db_path: str,
    cve_index: CVEIndex,
    distro: Optional[str] = None,
) -> list[dict]:
    """Batch version of enrich_package for a full CollectionResult.packages list."""
    return [
        enrich_package(p.name, p.version, db_path, cve_index, distro=distro)
        for p in packages
    ]
