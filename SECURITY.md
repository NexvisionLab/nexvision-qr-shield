# Security Policy

Report suspected vulnerabilities privately with GitHub's **Security → Report a vulnerability** feature for this repository. Do not open a public issue and do not include live credentials, OTP seeds, payment identifiers or victim data in an initial report.

Please include the affected version, reproducible steps, expected and observed behavior, and a minimal synthetic proof of concept. Allow a reasonable remediation period before public disclosure.

Direct destination preflight is disabled by default. Deployers who enable it are responsible for network-level egress isolation and monitoring; application-level checks alone are not a complete SSRF boundary.

Production mode fails closed unless API authentication, a distinct report HMAC secret and restricted trusted hosts are configured. Both secrets must meet the strength checks documented in `docs/V5_PRODUCTION_ARCHITECTURE.md`.

## Licence

Copyright © 2026 NexVision Lab.

This project is source-available under the PolyForm Noncommercial
License 1.0.0. It may be used, studied and modified for permitted
non-commercial purposes.

Commercial use, paid services, commercial redistribution,
production deployment and hosted services require a separate
written licence from NexVision Lab.

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
