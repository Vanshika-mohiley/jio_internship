"""
package_lookup.py — exact package-name + version -> CVE lookup, backed by
SQLite. Populated from vendor security-advisory feeds (RHSA OVAL, Ubuntu
USN) rather than NVD's CPE matching, because CPE matching is frequently
too coarse or entirely absent for distro-patched package versions — a
vendor advisory says precisely "cve-2024-xxxx is fixed in openssl
1.1.1-1ubuntu2.20", which is exactly the granularity a package-version
lookup needs.

This is checked FIRST during enrichment (see retrieval.py); ChromaDB
semantic search is the fallback for anything with no exact advisory match.
"""

from __future__ import annotations
import sqlite3
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS package_cve (
    package_name TEXT NOT NULL,
    fixed_version TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    distro TEXT NOT NULL,          -- e.g. 'rhel9', 'ubuntu22.04'
    source TEXT NOT NULL,          -- 'rhsa_oval' | 'usn'
    PRIMARY KEY (package_name, fixed_version, cve_id, distro)
);
CREATE INDEX IF NOT EXISTS idx_package_name ON package_cve(package_name);
"""


@dataclass
class AdvisoryEntry:
    package_name: str
    fixed_version: str
    cve_id: str
    distro: str
    source: str


def init_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def insert_entries(db_path: str, entries: list[AdvisoryEntry]) -> int:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executemany(
        "INSERT OR IGNORE INTO package_cve (package_name, fixed_version, cve_id, distro, source) "
        "VALUES (?, ?, ?, ?, ?)",
        [(e.package_name, e.fixed_version, e.cve_id, e.distro, e.source) for e in entries],
    )
    conn.commit()
    n = cur.rowcount
    conn.close()
    return n


def _version_key(v: str) -> tuple:
    """
    Best-effort version comparator for sorting/comparison across dpkg- and
    rpm-style version strings. This is a simplification: production-grade
    comparison should shell out to `dpkg --compare-versions` for Debian
    packages and `rpm.labelCompare` (via python-rpm) for RPM packages, since
    both have epoch/tilde semantics that plain tuple comparison gets wrong
    on edge cases (e.g. "~" sorts *before* nothing in dpkg, which no naive
    string/tuple split reproduces). Flagged here as a known limitation —
    worth a line in the report's "Limitations" section.
    """
    import re
    parts = re.split(r"[.\-+~:]", v)
    key = []
    for p in parts:
        key.append((0, int(p)) if p.isdigit() else (1, p))
    return tuple(key)


def lookup_exact(db_path: str, package_name: str, installed_version: str, distro: Optional[str] = None) -> list[dict]:
    """
    Return CVEs whose fixed_version is *newer* than installed_version for
    this package — i.e. vulnerabilities the installed version has not yet
    patched. Distro filter is optional (omit to search across all distros,
    useful when the collector didn't identify the exact distro release).
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if distro:
        cur.execute(
            "SELECT * FROM package_cve WHERE package_name = ? AND distro = ?",
            (package_name, distro),
        )
    else:
        cur.execute("SELECT * FROM package_cve WHERE package_name = ?", (package_name,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    installed_key = _version_key(installed_version)
    hits = []
    for row in rows:
        try:
            if _version_key(row["fixed_version"]) > installed_key:
                hits.append(row)
        except Exception:
            # if versions aren't comparable, err on the side of surfacing it
            # for human/LLM review rather than silently dropping a potential hit
            hits.append(row)
    return hits
