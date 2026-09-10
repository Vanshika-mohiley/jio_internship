# 30-case validation benchmark

Compares the same local Ollama model in three controlled modes:

1. **Base** — package/version only.
2. **RAG** — package/version plus local retrieved CVE descriptions.
3. **Full prototype** — current evidence-grounded `build_assessment_prompt()` with local CVE evidence and host artifacts.

The 30 cases contain 11 vulnerable versions, 11 patched versions, and 8 deliberately similar-but-nonmatching products. Results are written to `validation/validation_results.csv`.

Run from the project root:

```powershell
python .\validation\run_validation.py --model qwen2.5:7B
```

All three modes use the same model and JSON schema. The script records JSON validity, retries, latency, detection metrics, and CVSS-tier correctness. It does not fabricate model results.

The benchmark RAG retriever is deliberately deterministic and local for reproducibility. It is a lexical retrieval control; it should not be described as identical to the production SentenceTransformer/Chroma embedding quality.
