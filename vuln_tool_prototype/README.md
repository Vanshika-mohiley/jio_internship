# Vulnerability Assessment Prototype v0.1 — Week 3

## Canonical architecture

Day 1 collectors -> Day 2 local CVE enrichment/RAG -> Day 3 local Ollama assessment -> Day 4 report.

The canonical Day 3 implementation is `llm/prompt_builder.py` + `llm/llm_engine.py` + `schema/findings_schema.py`.
The alternative `engine.py` / `findings.py` implementation from the uploaded material is intentionally not used because it defines a conflicting schema and API.

## Important fixes made

1. Rejected NVD CVEs are ignored during parsing.
2. Chroma embedding-model loading is explicitly offline during assessment; the model must already exist locally.
3. The assessment prompt treats product-name-only matches as candidates, not confirmed vulnerabilities.
4. Package layout is restored so imports such as `schema.findings_schema` and `cve.retrieval` work.
5. Day 3 tests can be run without Ollama; the real test still requires a local Ollama server.

## Real Day 3 run

Start Ollama locally and make sure the selected model is already installed. Then run the project's end-to-end CLI. The assessment client is hardcoded to loopback `http://localhost:11434/api/generate`.
## Zero-egress evidence

For the report, run the assessment while capturing traffic with Wireshark and show that the assessment process only communicates with loopback Ollama. Knowledge-base refresh/download scripts are separate maintenance steps and must not be run during the packet-capture assessment demonstration.

## Known limitation

The current exact package-version comparator is a best-effort parser; distro-native RPM/dpkg version semantics should be used for production.
