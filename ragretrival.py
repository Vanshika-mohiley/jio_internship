import csv
import hashlib
import chromadb
from chromadb import Documents, EmbeddingFunction, Embeddings
from datasetloader import read_csv_rows_safely,read_text_safely
 
 
RAG_MODELS = {'llama3.1:8B', 'qwen2.5:7B'}

class HashEmbeddingFunction(EmbeddingFunction):
    def __call__(self, input: Documents) -> Embeddings:
        vectors = []
        for text in input:
            h = hashlib.sha256(text.encode("utf-8")).digest()
            vectors.append([b / 255.0 for b in h])  # 32-dim pseudo-vector
        return vectors
 
 
def _row_to_document(row: dict) -> str:
    """Formats one CSV row into the text that gets embedded."""
    return (
        f"CVE ID: {row['cve_id']}\n"
        f"Published: {row.get('published', 'unknown')}\n"
        f"CVSS: {row.get('cvss_score', 'unknown')} "
        f"({row.get('cvss_vector', '')})\n"
        f"Description: {row.get('description', '')}\n"
        f"Advisory: {row.get('source_advisory_url', '')}"
    )
 
 
def build_corpus(csv_path: str, collection_name: str = "nvd_novel_feed"):
    """
    Reads category2_final.csv and loads every row into a ChromaDB
    collection, one document per CVE, with the row's own columns kept
    as metadata (used later for chain-partner lookups).
    """
    client = chromadb.Client()
    embed_fn = HashEmbeddingFunction()
 
    # Reset if already exists (useful during dev iteration)
    try:
        client.delete_collection(collection_name)
    except Exception:
        pass
    collection = client.create_collection(collection_name, embedding_function=embed_fn)
 
    ids, docs, metadatas = [], [], []
    for row in read_csv_rows_safely(csv_path):
            ids.append(row["cve_id"])
            docs.append(_row_to_document(row))
            metadatas.append({
                "cve_id": row["cve_id"],
                "chain_partner_cve_id": row.get("chain_partner_cve_id", "") or "",
                "is_chain_candidate": row.get("is_chain_candidate", "") or "",
                "matched_keywords": row.get("matched_keywords", "") or "",
            })
 
    collection.add(ids=ids, documents=docs, metadatas=metadatas)
    return collection
 
 
def retrieve_context(collection, item: dict, top_k: int = 2) -> str:
    """
    Given a cve_novel item, retrieves its own NVD record by exact ID match,
    plus its chain partner's record if one exists, and formats both into
    the block that gets slotted into {retrieved_context}.
    """
    cve_id = item["cve_id"]
    blocks = []
 
    # 1. Exact-match retrieval of the CVE itself (metadata filter, not
    #    semantic search -- a real vuln-intel lookup is ID-based, not fuzzy).
    primary = collection.get(ids=[cve_id], include=["documents", "metadatas"])
    if primary["documents"]:
        blocks.append(f"[NVD Record: {cve_id}]\n{primary['documents'][0]}")
        chain_partner = primary["metadatas"][0].get("chain_partner_cve_id", "")
    else:
        chain_partner = ""
 
    # 2. If this CVE is flagged as part of a chain, pull its partner too --
    #    this is what lets a RAG model correctly answer D7 chain questions
    #    (e.g. the Dirty Frag CVE-2026-43284 / CVE-2026-43500 pair) while
    #    the base model, working from memory alone, cannot.
    if chain_partner:
        partner = collection.get(ids=[chain_partner], include=["documents"])
        if partner["documents"]:
            blocks.append(f"[Related CVE: {chain_partner}]\n{partner['documents'][0]}")
            blocks.append(
                f"Relationship: {cve_id} and {chain_partner} form a linked "
                f"exploit chain per retrieved NVD/advisory data."
            )
 
    return "\n\n".join(blocks) if blocks else ""
 
 
if __name__ == "__main__":
    collection = build_corpus("category2_final.csv")
 
    # Demo: retrieve context for the first row in the CSV

    first_row= read_csv_rows_safely("category2_final.csv")[4]
 
    demo_item = {"cve_id": first_row["cve_id"]}
    context = retrieve_context(collection, demo_item)
    print(f"Retrieved context for {demo_item['cve_id']}:\n")
    print(context if context else "(no chain partner / empty -- expected if not a chain CVE)")
 