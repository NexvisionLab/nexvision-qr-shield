# Public Security Audit

**Version audited:** 5.0.1 (23 September 2026)  
**Scope:** Application, tests, dependencies, container configuration, release metadata, documentation, and distributable Python artifacts.

## Executive summary

NexVision QR Shield v5.0.1 passed the available automated correctness, static-analysis, dependency, secret, privacy, packaging, and controlled-workflow checks. Confirmed defects found during the release audit were repaired before publication. No personal name, private email address, telephone number, street address, live API key, access token, private key, or victim data was found in the publication set.

The project does not use an external reputation or professional API. Optional direct destination preflight is disabled by default and remains a deployment-sensitive capability.

This audit does not prove the absence of vulnerabilities. Container execution and operating-system package scanning were not available in the audit environment; production operators must complete those gates for their exact image and infrastructure.

## Verified controls

| Gate | Result |
| --- | --- |
| Test suite | 165 passed |
| Ruff 0.16.8 | Passed |
| Bandit 1.9.4 | Passed |
| pip-audit 2.10.1, runtime lock | No known vulnerabilities reported |
| pip check | Passed |
| detect-secrets 1.5.0 | No findings in publication set |
| Python byte compilation | Passed |
| Browser JavaScript syntax | Passed |
| Source and wheel build | Passed |
| Installed command-line smoke test | Passed |
| Controlled malicious-QR workflow | Dangerous, 73/100, 9 explainable findings; secret canary absent |
| Documentation links and workflow YAML | Passed |

## Confirmed defects repaired

- Prevented full-secret leakage from `otpauth-migration` exports before results or reports are created.
- Restricted enhanced decoding to QR Code, Micro QR, and rMQR so unrelated barcode families are not silently accepted.
- Closed browser/server URL authority ambiguity by forcing abstention and blocking active inspection.
- Added strict multipart boolean parsing and production readiness checks for distinct high-entropy API and report-signing secrets.
- Bounded request-rate state and hardened file, image, PDF, email, report, and optional preflight processing.
- Removed literal high-entropy test credentials and generated synthetic test secrets at runtime.
- Pinned release-build tools and GitHub workflow actions; added dependency update automation and CodeQL analysis.
- Limited the generated runtime SBOM to runtime dependencies.

## Privacy and publication review

The audit searched source, tests, configuration, documentation, workflows, and release files for common credential formats, high-entropy assignments, private keys, email addresses, telephone patterns, and personal contact fields. The only email-like construction found was the reserved-domain URL-userinfo example `trusted.example@evil.example`; it is synthetic and documents a deception pattern.

## Residual production gates

- Build and execute the Docker image in the target platform.
- Scan the final image and operating-system packages with the organization's approved scanner.
- Put optional network preflight behind network-level egress controls; application checks alone are not a complete SSRF boundary.
- Configure distinct generated secrets, TLS, trusted hosts, authentication, request limits, logs, alerting, backup, and incident response.
- Validate multilingual and country-specific heuristics against representative local datasets and monitor false positives and false negatives.
- Obtain a separate written commercial licence before commercial use, production deployment, a hosted service, paid service, or commercial redistribution.
