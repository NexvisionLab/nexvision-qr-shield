# Security Architecture

## Trust boundaries

1. Uploaded bytes are untrusted and are limited by body size, image type, dimensions, frame count, parser warning policy and decode time/concurrency budgets.
2. Decoded payloads are untrusted data. They are never navigated, rendered as HTML or executed.
3. Secrets are detected and redacted before the result object is constructed. Only the SHA-256 of the original payload is retained for correlation.
4. Offline rules, brand policies, Unicode metadata and administrator indicators are local resources identified by version and SHA-256.
5. Optional destination preflight accepts only HTTP(S), restricts ports, rejects non-public A/AAAA results, pins the connection to an approved address, verifies TLS hostname/SNI, reads bounded headers and revalidates every redirect.

## Risk model

Findings are grouped into identity, deception, action, network, payment, image and intelligence evidence. Each group is capped before saturation so multiple correlated rules cannot increase the score without limit. The score is an explainable index, never a probability.

## Abstention

Conflicting independent decoder output produces `Unable to determine`. A missing local indicator match never produces a safety guarantee. Physical QR replacement cannot be inferred from a cropped code without trusted scene/reference evidence.

## Offline update model

Local policy files are reviewed and replaced manually. Reports record the pack ID, version, Unicode database version and content hashes. No component downloads reputation data automatically.
