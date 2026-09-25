# QR Shield v5.0.1 — Production Readiness Audit

Date: 23 September 2026

## Outcome

NexVision QR Shield v5.0.1 is a hardened production candidate. The application remains offline-first and uses no reputation, WHOIS/RDAP, translation, cloud-AI or professional API. The release passes the available source, test, static-analysis, dependency and clean-install checks.

Deployment is **not yet an unconditional go**. The environment used for this audit did not provide Docker, image/OS vulnerability scanning, deployment identity/TLS, external monitoring or an independently sourced regional accuracy corpus. Those operational gates must be completed in the target environment.

## Confirmed corrections

- Redacted FIDO and account-link sessions, dangerous action schemes, URL fragments, malformed payloads and secret URLs nested in email/SMS before serialization.
- Fixed the personal-redaction path so recipient masking cannot bypass nested URL sanitization.
- Applied authentication-independent rate limiting and bounded its per-client memory state.
- Preserved security headers on early 401, 403, 429 and 503 responses.
- Made production API routes and health checks fail closed for absent, reused, weak or low-entropy secrets.
- Required exact multipart boolean values and disabled evidence signing for weak HMAC keys.
- Corrected QR decoded-count evidence for Micro QR/rMQR.
- Enforced strict UTF-8 EMV TLV parsing and the ISO 11649 creditor-reference checksum.
- Preserved case-sensitive paths and queries in exact-URL blocklist matching.
- Bounded PDF text extraction and narrowed broad exception handling.
- Added the consensus QR decoder to the standard runtime and updated vulnerable dependency pins.
- Added a fully resolved Linux/Python 3.12 runtime lock and included container system tools in the source SBOM.

## Verification

- Automated tests in a fresh virtual environment: **165 passed**.
- Ruff: passed.
- Bandit: passed with reviewed local-tool subprocess suppressions.
- pip-audit: no known vulnerabilities in runtime, development or enhanced requirement sets.
- pip check: no broken requirements.
- Python compilation and JavaScript syntax checks: passed.
- Synthetic smoke corpus and controlled offline QR report: passed.
- Secret canary: absent from serialized controlled-test evidence.
- No visible model/prompt scaffolding, placeholder implementation or embedded credential was found in the audited tree.

The bundled synthetic corpus is regression evidence only. It is not a calibrated field-performance claim.

## Unresolved deployment gates

1. Build the container in CI, record the immutable base-image digest, generate an image SBOM and scan both OS and Python layers.
2. Exercise container startup, readiness, non-root execution, read-only filesystem, resource limits and shutdown behavior in the target orchestrator.
3. Configure TLS, restricted hosts, separate random secrets, upstream identity/tenant controls, distributed rate limits, monitoring, backup/retention and incident response.
4. Keep destination preflight disabled unless it runs in a separately egress-restricted worker.
5. Validate blocking thresholds on a legally usable, independently sourced, time-separated corpus covering deployment regions, languages, QR families and capture conditions.
6. Complete an independent penetration test and privacy/legal review. Production deployment also requires the separate written licence described below.
7. Restore source-control history/provenance for release review; the supplied archive contained no Git metadata.

## Licence

Copyright © 2026 NexVision Lab.

This project is source-available under the PolyForm Noncommercial
License 1.0.0. It may be used, studied and modified for permitted
non-commercial purposes.

Commercial use, paid services, commercial redistribution,
production deployment and hosted services require a separate
written licence from NexVision Lab.

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
