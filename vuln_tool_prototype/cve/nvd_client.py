"""
nvd_client.py — thin client for the NVD CVE REST API 2.0.

NOTE ON THE DATA SOURCE: NVD retired the downloadable JSON feed files
(nvdcve-2.0-*.json.zip) in December 2023. The JSON 2.0 *schema* lives on now
through the REST API instead: https://services.nvd.nist.gov/rest/json/cves/2.0
This client paginates through that API and caches each page to disk, so a
"local feed" is still achieved — just built once, then never re-fetched
during actual assessment runs (which is what preserves the on-premise /
zero-egress guarantee at inference time).

Rate limits (as of NVD's published policy): 5 requests / 30s without an API
key, 50 requests / 30s with one. We sleep conservatively between pages.
"""

from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Optional, Iterator
import urllib.request
import urllib.error

from pydantic import BaseModel

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000


class CVERecord(BaseModel):
    cve_id: str
    description: str
    published: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_severity: Optional[str] = None
    cpe_uris: list[str] = []


def _http_get_json(url: str, api_key: Optional[str] = None, timeout: int = 30) -> dict:
    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_cve_item(raw: dict) -> Optional[CVERecord]:
    """Convert one raw NVD API 2.0 'vulnerabilities[].cve' object into a CVERecord."""
    cve = raw.get("cve", raw)  # allow either the wrapper or the inner object
    cve_id = cve.get("id")
    if not cve_id:
        return None

    # Rejected CVEs are not active vulnerability records and must never be
    # surfaced as assessment evidence.
    if str(cve.get("vulnStatus", "")).lower() == "rejected":
        return None

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    score = None
    severity = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = metrics[key][0].get("baseSeverity") or cvss_data.get("baseSeverity")
            break

    cpe_uris = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and match.get("criteria"):
                    cpe_uris.append(match["criteria"])

    return CVERecord(
        cve_id=cve_id,
        description=description,
        published=cve.get("published"),
        cvss_v3_score=score,
        cvss_v3_severity=severity,
        cpe_uris=cpe_uris,
    )


def fetch_all_cves(
    cache_dir: str,
    api_key: Optional[str] = None,
    max_pages: Optional[int] = None,
    last_mod_start: Optional[str] = None,
    last_mod_end: Optional[str] = None,
) -> Iterator[CVERecord]:
    """
    Paginate through the NVD API, caching each raw page as JSON under
    cache_dir/page_<n>.json so re-running ingestion doesn't re-hit the network.
    Yields parsed CVERecord objects as it goes.

    last_mod_start/end (ISO 8601) let you do incremental updates instead of a
    full re-pull — recommended for any scheduled re-ingestion job.
    """
    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)

    start_index = 0
    page_num = 0
    sleep_seconds = 6 if not api_key else 0.6  # stay under the published rate limits

    while True:
        page_file = cache_path / f"page_{page_num}.json"
        if page_file.exists():
            data = json.loads(page_file.read_text())
        else:
            url = f"{NVD_API_URL}?startIndex={start_index}&resultsPerPage={RESULTS_PER_PAGE}"
            if last_mod_start and last_mod_end:
                url += f"&lastModStartDate={last_mod_start}&lastModEndDate={last_mod_end}"
            try:
                data = _http_get_json(url, api_key=api_key)
            except urllib.error.URLError as e:
                raise RuntimeError(
                    f"Could not reach NVD API ({e}). Ensure nvd.nist.gov is reachable "
                    f"from this environment (network allowlist / firewall)."
                ) from e
            page_file.write_text(json.dumps(data))
            time.sleep(sleep_seconds)

        vulnerabilities = data.get("vulnerabilities", [])
        for item in vulnerabilities:
            record = parse_cve_item(item)
            if record:
                yield record

        total_results = data.get("totalResults", 0)
        start_index += RESULTS_PER_PAGE
        page_num += 1

        if start_index >= total_results:
            break
        if max_pages is not None and page_num >= max_pages:
            break
