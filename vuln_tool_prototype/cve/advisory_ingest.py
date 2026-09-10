"""
advisory_ingest.py — parsers that turn vendor security-advisory feeds into
AdvisoryEntry rows for the SQLite exact-match lookup table.

Sources (fetch these on a machine with access to redhat.com / ubuntu.com —
neither is reachable from this build sandbox, so the fetch_* functions here
raise clearly if attempted from a restricted network):

  Red Hat OVAL v2 (per-release XML, bz2-compressed):
    https://www.redhat.com/security/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2
    (swap RHEL9 for RHEL8, RHEL7, etc.)

  Ubuntu USN database (single JSON file, all releases):
    https://usn.ubuntu.com/usn-db/database.json

Both are large (tens of MB); download once, cache locally, and re-run
ingestion on a schedule (e.g. weekly) rather than per-assessment.
"""

from __future__ import annotations
import bz2
import json
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path

from .package_lookup import AdvisoryEntry

RHEL_OVAL_URL_TMPL = "https://www.redhat.com/security/data/oval/v2/{release}/{release_lower}.oval.xml.bz2"
USN_DB_URL = "https://usn.ubuntu.com/usn-db/database.json"

OVAL_NS = {"oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5"}


def _download(url: str, dest_path: str) -> None:
    try:
        urllib.request.urlretrieve(url, dest_path)
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Could not reach {url} ({e}). This host must be reachable to refresh "
            f"advisory data; re-run this ingestion step from a machine/network with access."
        ) from e


def fetch_rhel_oval(release: str, cache_dir: str) -> str:
    """release e.g. 'RHEL9'. Returns local path to decompressed XML."""
    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)
    bz2_path = cache_path / f"{release}.oval.xml.bz2"
    xml_path = cache_path / f"{release}.oval.xml"
    if not xml_path.exists():
        if not bz2_path.exists():
            url = RHEL_OVAL_URL_TMPL.format(release=release, release_lower=release.lower().replace("rhel", "rhel-"))
            _download(url, str(bz2_path))
        with bz2.open(bz2_path, "rb") as f_in, open(xml_path, "wb") as f_out:
            f_out.write(f_in.read())
    return str(xml_path)


def parse_rhel_oval(xml_path: str, distro: str) -> list[AdvisoryEntry]:
    """
    Parses Red Hat's OVAL definitions. Structure (simplified):
      <definition> has <metadata><reference source="CVE" ref_id="CVE-xxxx-yyyy"/>
      and <criteria> containing <criterion test_ref="oval:...:tst:NNN"/>
      Each rpminfo_test (in <tests>) references an rpminfo_state via
      <state state_ref="oval:...:ste:NNN"/>, and states hold the fixed
      "evr" (epoch:version-release) via <evr operation="less than">.
    We join test_ref -> state_ref -> evr, and definition -> CVE id, and
    test -> package name (via the test's associated object -> name).
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = OVAL_NS

    # Build lookup: object_id -> package name
    objects = {}
    for obj in root.findall(".//oval:objects/oval:rpminfo_object", ns):
        obj_id = obj.get("id")
        name_el = obj.find("oval:name", ns)
        if obj_id and name_el is not None:
            objects[obj_id] = name_el.text

    # Build lookup: state_id -> fixed version string
    states = {}
    for state in root.findall(".//oval:states/oval:rpminfo_state", ns):
        state_id = state.get("id")
        evr_el = state.find("oval:evr", ns)
        if state_id and evr_el is not None and evr_el.get("operation") == "less than":
            states[state_id] = evr_el.text

    # Build lookup: test_id -> (package_name, fixed_version)
    test_to_pkg = {}
    for test in root.findall(".//oval:tests/oval:rpminfo_test", ns):
        test_id = test.get("id")
        obj_ref = test.find("oval:object", ns)
        state_ref = test.find("oval:state", ns)
        if obj_ref is None or state_ref is None:
            continue
        pkg_name = objects.get(obj_ref.get("object_ref"))
        fixed_version = states.get(state_ref.get("state_ref"))
        if pkg_name and fixed_version:
            test_to_pkg[test_id] = (pkg_name, fixed_version)

    entries: list[AdvisoryEntry] = []
    for definition in root.findall(".//oval:definitions/oval:definition", ns):
        cve_ids = [
            ref.get("ref_id")
            for ref in definition.findall(".//oval:reference", ns)
            if ref.get("source") == "CVE"
        ]
        if not cve_ids:
            continue
        for criterion in definition.findall(".//oval:criterion", ns):
            test_ref = criterion.get("test_ref")
            if test_ref in test_to_pkg:
                pkg_name, fixed_version = test_to_pkg[test_ref]
                for cve_id in cve_ids:
                    entries.append(AdvisoryEntry(
                        package_name=pkg_name,
                        fixed_version=fixed_version,
                        cve_id=cve_id,
                        distro=distro,
                        source="rhsa_oval",
                    ))
    return entries


def fetch_usn_database(cache_dir: str) -> str:
    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)
    json_path = cache_path / "usn_database.json"
    if not json_path.exists():
        _download(USN_DB_URL, str(json_path))
    return str(json_path)


def parse_usn_database(json_path: str) -> list[AdvisoryEntry]:
    """
    USN database.json shape (per USN entry, keyed by 'usn-number'):
      {
        "1234-1": {
          "cves": ["CVE-2020-xxxx", ...],
          "releases": {
            "focal": {
              "binaries": {"openssl": {"version": "1.1.1f-1ubuntu2.20"}},
              "sources": {"openssl": {"version": "1.1.1f-1ubuntu2.20"}}
            },
            ...
          }
        },
        ...
      }
    """
    data = json.loads(Path(json_path).read_text())
    entries: list[AdvisoryEntry] = []
    for usn_id, usn_data in data.items():
        cve_ids = usn_data.get("cves", [])
        if not cve_ids:
            continue
        for release_name, release_data in usn_data.get("releases", {}).items():
            binaries = release_data.get("binaries", {}) or release_data.get("sources", {})
            for pkg_name, pkg_info in binaries.items():
                version = pkg_info.get("version")
                if not version:
                    continue
                for cve_id in cve_ids:
                    entries.append(AdvisoryEntry(
                        package_name=pkg_name,
                        fixed_version=version,
                        cve_id=cve_id,
                        distro=f"ubuntu-{release_name}",
                        source="usn",
                    ))
    return entries
