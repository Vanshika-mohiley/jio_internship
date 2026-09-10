"""
cve_index.py — embeds CVE descriptions with a sentence-transformer and
stores them in a local, persistent ChromaDB collection for semantic
retrieval. This is the fallback path used when a package/version has no
exact hit in the SQLite lookup table (e.g. novel packages, or CVEs that
don't cleanly map to a CPE string).

Everything here runs against the local filesystem — the embedding model is
downloaded once (during setup, not at inference time) and cached under
~/.cache, and ChromaDB persists to disk. No network calls happen during
actual retrieval.
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional
import os

import chromadb
from sentence_transformers import SentenceTransformer

from .nvd_client import CVERecord

EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"  # 80MB, fast, good enough for short CVE descriptions
COLLECTION_NAME = "cve_index"


def _to_list(embeddings):
    """Normalise whatever the embedder returns (numpy array, list, etc.) into a plain list."""
    return embeddings.tolist() if hasattr(embeddings, "tolist") else list(embeddings)


class CVEIndex:
    def __init__(self, persist_dir: str, model_name: str = EMBEDDING_MODEL_NAME, embedder=None):
        """
        embedder: optional object exposing .encode(list[str]) -> array-like of
        vectors. Defaults to a real SentenceTransformer. Injectable purely so
        this class can be unit-tested in environments with no access to
        huggingface.co (e.g. this build sandbox) using a lightweight stand-in —
        production use should always rely on the default.
        """
        Path(persist_dir).mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(COLLECTION_NAME)
        if embedder is not None:
            self.model = embedder
        else:
            # Assessment must not download an embedding model. The model must
            # already be present in the local Hugging Face cache or be supplied
            # as a local path.
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
            try:
                self.model = SentenceTransformer(model_name, local_files_only=True)
            except TypeError:
                # Compatibility with older sentence-transformers releases.
                self.model = SentenceTransformer(model_name)

    def upsert_records(self, records: list[CVERecord], batch_size: int = 256) -> int:
        """Embed and upsert CVE records in batches. Returns count inserted."""
        count = 0
        batch: list[CVERecord] = []

        def flush(batch: list[CVERecord]):
            nonlocal count
            if not batch:
                return
            texts = [r.description or r.cve_id for r in batch]
            embeddings = _to_list(self.model.encode(texts))
            self.collection.upsert(
                ids=[r.cve_id for r in batch],
                embeddings=embeddings,
                documents=texts,
                metadatas=[
                    {
                        "cvss_v3_score": r.cvss_v3_score or 0.0,
                        "cvss_v3_severity": r.cvss_v3_severity or "UNKNOWN",
                        "published": r.published or "",
                        "cpe_uris": "|".join(r.cpe_uris[:20]),  # Chroma metadata must be scalar
                    }
                    for r in batch
                ],
            )
            count += len(batch)

        for r in records:
            batch.append(r)
            if len(batch) >= batch_size:
                flush(batch)
                batch = []
        flush(batch)
        return count

    def semantic_search(self, query_text: str, top_k: int = 5) -> list[dict]:
        query_embedding = _to_list(self.model.encode([query_text]))
        results = self.collection.query(query_embeddings=query_embedding, n_results=top_k)
        matches = []
        ids = results.get("ids", [[]])[0]
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        dists = results.get("distances", [[]])[0]
        for cve_id, doc, meta, dist in zip(ids, docs, metas, dists):
            matches.append({
                "cve_id": cve_id,
                "description": doc,
                "cvss_v3_score": meta.get("cvss_v3_score"),
                "cvss_v3_severity": meta.get("cvss_v3_severity"),
                "distance": dist,  # lower = more similar (cosine/L2 depending on Chroma config)
            })
        return matches

    def count(self) -> int:
        return self.collection.count()
