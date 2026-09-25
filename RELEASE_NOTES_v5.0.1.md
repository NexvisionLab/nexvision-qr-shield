# NexVision QR Shield v5.0.1 — Integrity and Production-Hardening Release

Released: 23 September 2026

## Security and correctness

- Extended fail-closed privacy handling to sessions, dangerous schemes, URL fragments, malformed payloads and nested URLs in email/SMS.
- Bounded rate-limit state and moved rate limiting ahead of authentication.
- Added fail-closed readiness checks for distinct, high-entropy API and HMAC secrets.
- Hardened early error responses, multipart boolean parsing, evidence signing and local artifact subprocesses.
- Corrected Micro QR/rMQR evidence counts, strict EMV UTF-8 parsing, ISO 11649 validation and exact-URL blocklist case handling.

## Supply chain and validation

- Updated vulnerable dependencies and made ZXing-C++ part of the standard runtime.
- Added a resolved Linux/Python 3.12 runtime lock and expanded the SBOM declaration.
- Added 23 regression tests; **165 tests pass** in a clean virtual environment.
- Ruff, Bandit, pip-audit, pip check, Python compilation and JavaScript syntax checks pass.

See `BUILD_REPORT.md` for the deployment gates that remain outside the supplied source archive.

## Licence

Copyright © 2026 NexVision Lab.

This project is source-available under the PolyForm Noncommercial
License 1.0.0. It may be used, studied and modified for permitted
non-commercial purposes.

Commercial use, paid services, commercial redistribution,
production deployment and hosted services require a separate
written licence from NexVision Lab.

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
