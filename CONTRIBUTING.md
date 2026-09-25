# Contributing

Thank you for helping improve NexVision QR Shield.

## Development principles

- Keep analysis offline-first. Do not add external reputation, analytics, telemetry, or professional API dependencies to the default path.
- Use only synthetic, reserved-domain, or otherwise non-sensitive fixtures. Never commit credentials, personal information, victim data, payment identifiers, or MFA secrets.
- Preserve explainable findings and privacy-safe redaction at every output boundary.
- Treat destination preflight as optional and disabled by default.
- Preserve the project's licence and copyright notice unchanged.

## Local verification

Use Python 3.11 or 3.12 in an isolated environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --requirement requirements-audit.txt
python -m pip check
python -m pip_audit --requirement requirements.lock
detect-secrets scan --all-files --exclude-files '(^|/)(\.git|\.venv|\.pytest_cache|\.ruff_cache|\.hypothesis|build|dist)/'
ruff check .
bandit -q -r app tools
pytest -q
```

## Pull requests

Describe behavior and security impact, add focused tests, and update relevant documentation. Report suspected vulnerabilities privately through GitHub's security reporting flow instead of opening a public issue.

## Licence

Copyright © 2026 NexVision Lab.

This project is source-available under the PolyForm Noncommercial
License 1.0.0. It may be used, studied and modified for permitted
non-commercial purposes.

Commercial use, paid services, commercial redistribution,
production deployment and hosted services require a separate
written licence from NexVision Lab.

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
