# Limitations

## Validation dataset

The benchmark contains 30 controlled cases covering vulnerable,
patched, and package/CVE mismatch scenarios. Results therefore
demonstrate performance on the benchmark and should not be interpreted
as production-wide vulnerability-detection accuracy.

## Base model

The base model produced no positive vulnerability findings in this
benchmark. It therefore achieved zero recall. Its precision is
undefined because it produced no positive predictions.

## RAG retrieval

The RAG condition substantially improved recall but produced false
positives on patched versions. This indicates that retrieving a
relevant CVE description alone is insufficient for reliable
version-range reasoning.

One observed RAG failure also returned the wrong Log4j CVE for a
vulnerable Log4j version, demonstrating that retrieval relevance can
select a related but incorrect advisory.

## Full prototype

The full prototype achieved perfect results on this 30-case benchmark:
100% precision, 100% recall, 100% F1, 100% JSON validity, and 100% CVSS
tier accuracy.

These results should not be generalized beyond the benchmark because
the dataset is controlled and relatively small.

## Version comparison

Version comparison remains a potential limitation, particularly for
complex vendor version schemes, suffixes, backports, and distribution-
specific versioning.

## Hallucination and evidence grounding

The prototype is designed to distinguish confirmed vulnerabilities from
candidate CVE matches and to avoid unsupported package/network
attribution. However, broader testing is required to establish
robustness against unseen artifact structures and ambiguous evidence.
