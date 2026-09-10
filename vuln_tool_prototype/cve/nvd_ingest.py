#!/usr/bin/env python3
"""
nvd_ingest.py — Day 2 deliverable. Builds the complete local, on-premise CVE
knowledge base:
  1. Pulls CVEs from the NVD API 2.0, embeds descriptions, indexes in ChromaDB.
  2. Pulls RHSA OVAL (per RHEL release) and Ubuntu USN advisories, populates
     the SQLite exact-match package/version -> CVE table.

Run this as a standalone maintenance job (e.g. weekly cron), NOT as part of
the per-assessment pipeline — assessment runs only ever read these local
stores, never touch the network. That separation is what makes the
"zero data leaves the machine" claim in Week 3's report hold at inference
time even though the knowledge base itself is sourced from the internet.

Usage:
    python3 nvd_ingest.py --chroma-dir ./data/chroma --db-path ./data/advisories.db \\
        --nvd-cache ./data/nvd_cache --max-pages 5 --rhel-releases RHEL9 RHEL8 \\
        --skip-usn        # flags to skip a source if you only want to (re)build one
"""

from __future__ import annotations
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from .nvd_client import fetch_all_cves
from .cve_index import CVEIndex
from .package_lookup import init_db, insert_entries
from .advisory_ingest import (
    fetch_rhel_oval, parse_rhel_oval,
    fetch_usn_database, parse_usn_database,
)


def main():
    ap = argparse.ArgumentParser(description="Build local CVE knowledge base (NVD + RHSA OVAL + USN).")
    ap.add_argument("--chroma-dir", default="./data/chroma")
    ap.add_argument("--db-path", default="./data/advisories.db")
    ap.add_argument("--nvd-cache", default="./data/nvd_cache")
    ap.add_argument("--advisory-cache", default="./data/advisory_cache")
    ap.add_argument("--api-key", default=None, help="NVD API key (optional, raises rate limit)")
    ap.add_argument("--max-pages", type=int, default=None, help="Limit NVD pages (testing / partial pulls)")
    ap.add_argument("--rhel-releases", nargs="*", default=["RHEL9"])
    ap.add_argument("--skip-nvd", action="store_true")
    ap.add_argument("--skip-rhel", action="store_true")
    ap.add_argument("--skip-usn", action="store_true")
    args = ap.parse_args()

    init_db(args.db_path)

    if not args.skip_nvd:
        print("Fetching CVEs from NVD API 2.0 ...")
        index = CVEIndex(persist_dir=args.chroma_dir)
        records = list(fetch_all_cves(cache_dir=args.nvd_cache, api_key=args.api_key, max_pages=args.max_pages))
        n = index.upsert_records(records)
        print(f"  Indexed {n} CVE records into ChromaDB ({index.count()} total in collection).")
    else:
        print("Skipping NVD ingestion (--skip-nvd).")

    if not args.skip_rhel:
        for release in args.rhel_releases:
            print(f"Fetching RHSA OVAL for {release} ...")
            xml_path = fetch_rhel_oval(release, args.advisory_cache)
            entries = parse_rhel_oval(xml_path, distro=release.lower())
            n = insert_entries(args.db_path, entries)
            print(f"  Inserted {n} advisory rows for {release}.")
    else:
        print("Skipping RHEL OVAL ingestion (--skip-rhel).")

    if not args.skip_usn:
        print("Fetching Ubuntu USN database ...")
        json_path = fetch_usn_database(args.advisory_cache)
        entries = parse_usn_database(json_path)
        n = insert_entries(args.db_path, entries)
        print(f"  Inserted {n} advisory rows from USN.")
    else:
        print("Skipping USN ingestion (--skip-usn).")

    print("Done. Knowledge base is ready for fully offline enrichment via retrieval.py.")


if __name__ == "__main__":
    main()
