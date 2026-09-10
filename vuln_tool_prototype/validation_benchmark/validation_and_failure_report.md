# Validation & Failure Analysis

## Benchmark

30 cases were evaluated across three configurations:

- Base model
- RAG-augmented model
- Full prototype

## Results

      precision    recall        f1  json_validity  cvss_accuracy
mode                                                             
base   0.000000  0.000000  0.000000            1.0       0.633333
full   1.000000  1.000000  1.000000            1.0       1.000000
rag    0.454545  0.909091  0.606061            1.0       0.600000

## Improvement

              precision    recall        f1  cvss_accuracy
Full vs Base   1.000000  1.000000  1.000000       0.366667
Full vs RAG    0.545455  0.090909  0.393939       0.400000

## Failure Analysis

           failure_type  count
 knowledge/coverage gap     11
        retrieval error      1
version reasoning error     11

The Full configuration produced zero failure records on the
30-case benchmark. The Base configuration produced 11 false negatives.
The RAG configuration produced 12 false positives.

The RAG failures primarily demonstrate incorrect version reasoning on
patched versions, plus one retrieval error involving selection of a
related but incorrect CVE.

Base-model failures are recorded as knowledge/coverage gaps in this
benchmark analysis; this label should not be interpreted as proof of a
specific training-data cutoff cause.
