"""
test_pipeline_offline.py — validates cve_index.py, package_lookup.py, and
retrieval.py end-to-end using synthetic data, since this build sandbox
can't reach nvd.nist.gov / redhat.com / ubuntu.com. Run the real
nvd_ingest.py against live data once you have network access to those
hosts, then re-run enrich_package against real collector output.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cve.nvd_client import CVERecord
from cve.cve_index import CVEIndex
from cve.package_lookup import init_db, insert_entries, AdvisoryEntry, lookup_exact
from cve.retrieval import enrich_package

CHROMA_DIR = "vuln_tool_prototype/test_data/chroma"
DB_PATH = "vuln_tool_prototype/test_data/advisories.db"


class HashingBagOfWordsEmbedder:
    """
    Deterministic, dependency-free stand-in for SentenceTransformer, used
    ONLY because this build sandbox cannot reach huggingface.co to download
    the real model. It embeds via word-hashing into a fixed-size vector —
    good enough to prove the ChromaDB upsert/query plumbing and the
    retrieval.py control flow are correct, but NOT semantically meaningful
    the way a real transformer embedding is. Swap back to the default
    SentenceTransformer(EMBEDDING_MODEL_NAME) in any environment with
    internet access (i.e. anywhere outside this sandbox).
    """
    DIM = 256

    def encode(self, texts):
        import hashlib
        import re
        vectors = []
        for text in texts:
            vec = [0.0] * self.DIM
            words = re.findall(r"[a-z0-9]+", text.lower())
            for w in words:
                h = int(hashlib.md5(w.encode()).hexdigest(), 16)
                vec[h % self.DIM] += 1.0
            norm = sum(v * v for v in vec) ** 0.5 or 1.0
            vectors.append([v / norm for v in vec])
        return vectors

# --- synthetic CVE records (mimics parsed NVD API output) ---
synthetic_cves = [
    CVERecord(
        cve_id="CVE-2023-0001",
        description="A heap buffer overflow in libexample's XML parser allows remote attackers to execute arbitrary code via a crafted document.",
        published="2023-01-15",
        cvss_v3_score=9.8,
        cvss_v3_severity="CRITICAL",
        cpe_uris=["cpe:2.3:a:example:libexample:*:*:*:*:*:*:*:*"],
    ),
    CVERecord(
        cve_id="CVE-2023-0002",
        description="An out-of-bounds read in the OpenSSL TLS handshake state machine may allow a denial of service.",
        published="2023-02-10",
        cvss_v3_score=5.3,
        cvss_v3_severity="MEDIUM",
        cpe_uris=["cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"],
    ),
    CVERecord(
        cve_id="CVE-2023-0003",
        description="Privilege escalation in sudo via a race condition when handling the --chroot option.",
        published="2023-03-01",
        cvss_v3_score=7.8,
        cvss_v3_severity="HIGH",
        cpe_uris=["cpe:2.3:a:sudo_project:sudo:*:*:*:*:*:*:*:*"],
    ),
]

# --- synthetic advisory entries (mimics parsed RHSA OVAL / USN output) ---
synthetic_advisories = [
    AdvisoryEntry(package_name="openssl", fixed_version="1.1.1f-1ubuntu2.20", cve_id="CVE-2023-0002", distro="ubuntu-focal", source="usn"),
    AdvisoryEntry(package_name="sudo", fixed_version="1.9.9-1ubuntu2.4", cve_id="CVE-2023-0003", distro="ubuntu-focal", source="usn"),
]


def run():
    print("=== 1. Building ChromaDB index from synthetic CVE records ===")
    index = CVEIndex(persist_dir=CHROMA_DIR, embedder=HashingBagOfWordsEmbedder())
    n = index.upsert_records(synthetic_cves)
    print(f"Indexed {n} records. Collection count: {index.count()}")

    print("\n=== 2. Semantic search sanity check ===")
    results = index.semantic_search("buffer overflow in XML parsing library", top_k=2)
    for r in results:
        print(f"  {r['cve_id']}  score={r['cvss_v3_score']}  severity={r['cvss_v3_severity']}  distance={r['distance']:.4f}")
    assert results[0]["cve_id"] == "CVE-2023-0001", "Semantic search did not retrieve the expected top match"
    print("  PASS: correct CVE retrieved as top semantic match.")

    print("\n=== 3. Building SQLite advisory lookup table ===")
    init_db(DB_PATH)
    n = insert_entries(DB_PATH, synthetic_advisories)
    print(f"Inserted {n} advisory rows.")

    print("\n=== 4. Exact-match lookup: vulnerable version ===")
    hits = lookup_exact(DB_PATH, "openssl", "1.1.1f-1ubuntu2.16", distro="ubuntu-focal")
    print(f"  {len(hits)} hit(s): {[h['cve_id'] for h in hits]}")
    assert len(hits) == 1 and hits[0]["cve_id"] == "CVE-2023-0002"
    print("  PASS: vulnerable version correctly flagged.")

    print("\n=== 5. Exact-match lookup: already-patched version ===")
    hits = lookup_exact(DB_PATH, "openssl", "1.1.1f-1ubuntu2.25", distro="ubuntu-focal")
    print(f"  {len(hits)} hit(s) (expect 0 — version is newer than the fix)")
    assert len(hits) == 0
    print("  PASS: patched version correctly excluded.")

    print("\n=== 6. Unified retrieval: exact-match path ===")
    result = enrich_package("sudo", "1.9.9-1ubuntu2.1", DB_PATH, index, distro="ubuntu-focal")
    print(f"  confidence={result['confidence']}  exact_matches={[m['cve_id'] for m in result['exact_matches']]}")
    assert result["confidence"] == "exact"
    print("  PASS")

    print("\n=== 7. Unified retrieval: semantic fallback path (package with no advisory entry) ===")
    result = enrich_package("libexample", "2.1.0", DB_PATH, index)
    print(f"  confidence={result['confidence']}  semantic_matches={[m['cve_id'] for m in result['semantic_matches']]}")
    assert result["confidence"] == "semantic"
    assert result["semantic_matches"][0]["cve_id"] == "CVE-2023-0001"
    print("  PASS")

    print("\nAll offline pipeline checks passed.")


if __name__ == "__main__":
    run()
