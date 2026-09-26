# Changelog

All notable changes to NexVision QR Shield are recorded here.

## [Unreleased]

### Security

- Redirects followed by the optional destination preflight are now held to the same port 80/443 restriction as the first request.
- The preflight follows the normalized (punycode) redirect target, so the host that was analyzed is the host that is contacted.
- IPv4 addresses embedded in NAT64 (`64:ff9b::/96`) and IPv4-mapped IPv6 addresses are checked as IPv4 before a connection is allowed.
- A secret inside a nested URL is redacted even when the nested value contains a quote, and nested `otpauth:` URIs are redacted as authentication secrets.
- A Wi-Fi password or DPP key in the last field without a closing `;` is now redacted.
- `client_secret` and `id_token` are treated as secret query names.

### Fixed

- Official domains under two-part suffixes (for example `www.dbs.com.sg`, `www.cpf.gov.sg`, `www.google.com.sg`) were reported as brand-in-subdomain impersonation and received a Dangerous verdict.
- First-party service domains (`live.com` for Outlook/OneDrive, `googleapis.com`, `googleusercontent.com`, `amazonaws.com`) were added to the brand policy; the intelligence pack is now `2026.09.4`.
- Mixed-radix and single-number octal IPv4 hosts such as `0x7f.0.0.1` and `017700000001` are now recognized as obfuscated IP destinations.
- Exact-URL blocklist entries now match regardless of a missing trailing `/`, a default port, a fragment or an IDN host.
- A server reply with a malformed HTTP status line, or an unparseable `Location` header, no longer aborts the analysis.
- A valid EMV payment QR whose CRC value is itself `6304` was reported as a CRC mismatch.
- Payment amounts, currency codes, IBANs and creditor references only accept ASCII digits; digits from other scripts (for example `١٠`) were accepted as valid.
- EPC QR: amounts up to 999,999,999.99, character sets 1–8 and any well-formed ISO 20022 purpose code are accepted; a missing BIC in version 001, more than 12 lines and a beneficiary name over 70 characters are reported.
- Bitcoin and Litecoin base58 addresses are validated case-sensitively, and bech32 addresses must be a single case.
- EIP-681 Ethereum links (`pay-` prefix, `@chain`, `/function`, scientific-notation `value`) are no longer reported as malformed.
- A payload containing an unpaired UTF-16 surrogate no longer raises during result sealing.
- The command-line tool now prints a short error and exits with status 2 for a missing file or an unreadable image, PDF or email instead of a Python traceback.
- The engine version in results, the preflight `User-Agent` and the SBOM generator now read the package version instead of repeating a hard-coded string.
- `tools/generate_sbom.py` recorded whatever version was installed in the build environment (including test-only packages) and labelled it validated; it now records the pinned `requirements.lock` versions and states whether the environment matched each pin. `SBOM.spdx.json` was regenerated.
- `tools/run_controlled_qr_test.py` writes its report to `build/controlled_qr_test/` inside the checkout instead of the parent directory.

### Changed

- Release notes were consolidated into this changelog; the architecture documents and test modules were renamed without version suffixes.
- The README documents what the production `docker-compose.yml` needs before it is reachable (secrets, an ingress proxy on the internal network, UI authentication).
- Dependabot updates `github/codeql-action/init` and `analyze` together; separate bumps failed CodeQL.
- Dependencies: uvicorn 0.53.0, opencv-python-headless 5.0.0.93, python-multipart 0.0.32, tldextract 5.3.2, pytest 9.1.1; `requirements.lock` re-resolved for Linux/Python 3.12 (filelock 4.0.3) so the container installs the same versions. CI uses actions/checkout v7.0.1, actions/setup-python v7.0.0 and CodeQL v4.38.1.

## [5.0.1] - 2026-09-23

### Security

- Extended redaction to authentication sessions, dangerous action schemes, URL fragments, malformed payloads and URLs nested in email/SMS payloads.
- Rate limiting now runs before authentication and its per-client state is bounded.
- Production readiness fails closed for absent, reused, weak or low-entropy API and HMAC secrets.
- Security headers are kept on early 401, 403, 429 and 503 responses.
- Multipart boolean fields require exactly `true` or `false`; evidence signing is disabled for weak HMAC keys.

### Fixed

- Decoded-count evidence for Micro QR and rMQR.
- Strict UTF-8 EMV TLV parsing and the ISO 11649 creditor-reference checksum.
- Case-sensitive paths and queries in exact-URL blocklist matching.
- Bounded PDF text extraction.

### Changed

- ZXing-C++ is part of the standard runtime; vulnerable dependency pins were updated.
- Added a resolved Linux/Python 3.12 runtime lock (`requirements.lock`) and system tools in the SBOM.

## [5.0.0] - 2026-09-23

### Security

- Authenticator migration (`otpauth-migration`) protobuf data is fully redacted before serialization.
- Enhanced decoding is restricted to QR Code, Micro QR and rMQR.
- Browser/server URL authority ambiguity forces abstention and blocks active inspection.

### Added

- Pix, PromptPay, PayNow, DuitNow and possible QRIS profiles with privacy-safe nested template evidence.
- Structured UPI and cryptocurrency validation, FIDO/account-link sessions, Android intent fallback extraction and GS1 Digital Link validation.
- PDF, EML and TIFF ingestion with optional local OCR context.
- 29 language variants and 22 country/region signal profiles.
- Canonical report hashes and optional HMAC-SHA256 evidence signatures.
- Host allowlisting, optional API authentication, cross-site request rejection and request IDs.
- Hardened non-root, read-only container with dropped capabilities, resource limits and an internal network.
- Synthetic evaluation harness and property-based fuzz tests.

## [4.0.0] - 2026-09-22

### Added

- Recursive percent, HTML-entity, JSON-escape and Base64 decoding with strict resource budgets.
- Hidden URL, concealed dangerous-scheme, multi-stage encoding and disguised security-term detection.
- Cross-field brand/domain mismatch, shared-host authentication lure, fragment lure, encoded delimiter and double-extension detection.
- Attack-chain fusion across concealment, impersonation, pressure and sensitive-action stages.
- WalletConnect session classification with symmetric-key redaction.
- EPC/SEPA payment QR parsing, amount validation and IBAN mod-97 checking.
- Email/SMS CRLF injection and incomplete enterprise Wi-Fi validation warnings.
- QR structural evidence: dark-module density, timing alternation and central-overlay indicator.

## [3.1.0] - 2026-09-22

### Added

- Localized scam-language policies with combination-based categories (parcel/customs, account/MFA, payment/fines/tax, authorities, jobs, investments, prizes, app installation).
- Qualified country cues and an internationalized protected-brand policy.
- Awareness/negation suppression and a dedicated social-engineering score group.
- Versioned, hash-recorded `multilingual_scam_packs.json` evidence in every analysis.

### Changed

- Licence changed to PolyForm Noncommercial 1.0.0.

## [3.0.0]

### Added

- Secret-safe result model with SHA-256 evidence identifiers and default redaction.
- IP-pinned, DNS-rebinding-resistant redirect metadata inspection.
- Strict request validation, local rate limiting and decode concurrency limits.
- Early image dimension/frame/format validation and decompression-bomb rejection.
- OpenCV/ZXing-C++ decoder consensus with abstention on disagreement.
- QR structure metadata, UTS #46/STD3 host handling and Unicode security profiles.
- Bounded recursive destination graph and grouped explainable risk scoring.
- Versioned local intelligence manifest and privacy-safe JSON/HTML reports.

## [2.0.0]

### Removed

- External reputation API adapters and API-key settings. Offline analysis is the default for the web UI and REST API.

### Changed

- `decode_qr()` returns payloads, the image SHA-256 and image-analysis evidence.
- The JSON schema adds `image_analysis`, `decoded_details` and `engine` objects.
- The risk score is a rule-based index, not a probability.
