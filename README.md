# NexVision QR Shield

[![Security and test gate](https://github.com/NexvisionLab/nexvision-qr-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/NexvisionLab/nexvision-qr-shield/actions/workflows/ci.yml)

A self-contained OSINT QR-code checker that decodes images, PDFs and saved email evidence and analyzes their payloads **without opening destinations or depending on any external reputation API**.

This is a source-available, non-commercial project. Before deploying it, review the [public security audit](PUBLIC_SECURITY_AUDIT.md), [security policy](SECURITY.md), [contribution guide](CONTRIBUTING.md), and [production deployment guide](docs/PRODUCTION_DEPLOYMENT.md).

See [CHANGELOG.md](CHANGELOG.md) for the release history.

## Core capabilities

### Advanced layered detection

- Bounded recursive decoding for percent encoding, HTML entities, JSON escapes and standard/URL-safe Base64, with depth, state and size budgets.
- Detects encoded URLs, concealed dangerous schemes, multiple encoding layers and security words disguised with separators or leetspeak.
- Cross-field identity analysis identifies brand claims in paths, queries and fragments when the controlling domain is not approved.
- Detects concentrated authentication language on shared hosting and temporary tunnel infrastructure without treating those services as malicious by themselves.
- Browser-fragment lure detection, repeatedly encoded delimiters and deceptive double-extension downloads.
- Explainable attack-chain fusion correlates concealment, impersonation, pressure and sensitive-action stages.
- WalletConnect session recognition and symmetric-key redaction.
- EPC/SEPA Credit Transfer QR parsing, amount rules and offline IBAN checksum validation without exposing the beneficiary or account number.
- Email/SMS CRLF injection detection and enterprise Wi-Fi server-validation warnings.
- QR structural profile: version, error-correction level, mask, format distance, dark-module ratio, timing-pattern alternation and possible central overlay. Structural observations do not independently declare a QR malicious.

### Multilingual and country-aware scam detection

- Versioned local policy for 29 language variants.
- Detects coordinated combinations of urgency/threat language with credential, payment, delivery, authority, job, investment, prize and app-installation requests.
- Country-specific institution and payment cues for Singapore, Malaysia, Indonesia, India, the Philippines, the UK, US, Australia, Canada, UAE, Saudi Arabia, Japan, South Korea and Hong Kong.
- Region values are explicitly labelled heuristic possibilities—not IP geolocation, attribution or proof of origin.
- Awareness and protective-language suppression prevents examples such as “never share your OTP” and “no action required” from receiving scam points.
- Single generic terms do not trigger a multilingual finding; explainable evidence records matched categories and localized phrases.

### Privacy and application security

- MFA seeds, Wi-Fi passwords, DPP bootstrap keys, URL credentials, action/session bodies, fragments and nested secret-bearing URLs are redacted before results, clipboard actions or reports are created.
- Strict API schemas reject type confusion such as the string `"false"` enabling network checks.
- Image format, dimensions and frame count are validated before full decoding; decompression-bomb warnings are fatal.
- Bounded concurrent decoding, a 15-second decode timeout and a memory-bounded local request-rate limit reduce denial-of-service exposure.
- Direct preflight is restricted to ports 80/443 and uses the already-approved public IP for the connection, closing the application-level DNS-rebinding gap.
- Proxy headers are not trusted by the supplied container configuration.

### Optical, document and email forensics

- PNG, JPEG, WEBP, BMP and single-page TIFF; PDF rasterization for the first 10 pages; saved EML image attachments; up to eight QR payloads per image.
- Optional local Tesseract OCR and native PDF/email text extraction provide surrounding scam context without storing the raw surrounding text in results.
- File SHA-256, format, dimensions, file size, color mode, EXIF presence and animation status.
- Sharpness, contrast, perspective distortion, estimated QR area and edge/quiet-zone indicators.
- Multiple-code warning and decoding reliability observations.
- QR module dimension, version, mask, error-correction level and format-bit validity when recoverable.
- Optional local ZXing-C++ consensus decoding, including Micro QR and rMQR support, with explicit disagreement/abstention handling.
- Clear limitation: a crop alone cannot establish whether someone covered a legitimate physical QR with a malicious sticker.

### Offline URL deception engine

- Strict HTTP(S), hostname, port, IDNA and IPv4/IPv6 normalization.
- Unicode mixed-script, compatibility-character, zero-width and bidirectional-control detection.
- UTS #46 non-transitional IDNA processing with STD3 rules, identifier restriction levels and mixed-number-system detection.
- Confusable skeletons for common Greek/Cyrillic/full-width lookalikes.
- Offline brand impersonation against a bundled, editable brand/domain policy, including Singapore brands and public services.
- Typosquatting edit distance, trusted-looking subdomain, deep subdomain, risky TLD, direct-IP and numeric/hex/octal IPv4 checks.
- Backslash, delimiter, user-info (`trusted.example@evil.example`) and long/encoded URL confusion checks.
- Nested URL, open-redirect parameter, triple percent-decoding and Base64-hidden content detection.
- Bounded recursive destination graph with cycle, depth and node limits.
- Secret-bearing query names, executable/archive extensions, social-engineering language, entropy and digit-pattern checks.
- Local administrator blocklist for exact URLs and domains. No feed is downloaded automatically.

### Structured payload detection

- Wi-Fi: open network, obsolete WEP, hidden SSID and credential presence.
- WPA3/SAE, enterprise EAP and Wi-Fi Easy Connect/DPP handling.
- MFA enrollment: protects `otpauth:` secrets as critical content.
- Payment QR: EMV merchant-presented TLV parsing, UTF-8 byte lengths, CRC-16/CCITT-FALSE validation, static/dynamic mode, amount, currency, country and PayNow/SGQR indicator extraction.
- Cryptocurrency and UPI payment requests.
- SMS/MMS, email, telephone/USSD, vCard/MeCard, calendar, location and application deep links.
- Critical handling for `javascript:`, `data:`, `file:`, `smb:`, Android `intent:` and similar action schemes.
- Embedded web links and social-engineering wording inside non-URL payloads.

### Explainable reporting

- `Low observable risk`, `Caution`, `Suspicious`, `High risk`, `Dangerous` or `Unable to determine` verdict.
- Grouped 0–100 risk index that limits double counting across identity, deception, action, network, payment, image and local-intelligence evidence. It is explicitly **not a probability**.
- Every score is supported by a named finding, severity, explanation and optional evidence.
- Privacy-safe JSON and standalone HTML report export containing payload hashes, image evidence, normalized host, decoded structure, intelligence-pack versions and limitations.

## No-API operating model

The default is **fully offline** after the application and Python dependencies are installed:

- no Google Safe Browsing;
- no URLhaus;
- no VirusTotal;
- no WHOIS or RDAP;
- no cloud AI or LLM;
- no telemetry; and
- no automatic threat-feed download.

An optional “Direct destination preflight” can perform DNS resolution, a certificate-verified TLS handshake and limited redirect-header inspection. This contacts the destination itself, not a reputation API, and is disabled by default.

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate                 # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`. API documentation is at `/api/docs`.

The QR-family consensus decoder is part of the standard runtime; no external decoding service is used.

Command-line offline analysis:

```bash
python -m app.cli --image qr.png
python -m app.cli --file suspicious.pdf
python -m app.cli --file message.eml
python -m app.cli --text 'https://example.com'
```

Docker:

```bash
docker compose up --build
```

`docker-compose.yml` is a hardened production template, not a local demo:

- It starts in production mode, so `/health` and the API return 503 until `QR_SHIELD_API_KEY`, `QR_SHIELD_REPORT_HMAC_KEY` and `QR_SHIELD_ALLOWED_HOSTS` are set.
- The `shield` network is `internal: true` to deny all egress. Docker does not publish ports for a container on an internal-only network, so put a reverse proxy on the `shield` network (and on an ingress network) to reach the service.
- The container health check connects to `127.0.0.1`; keep `127.0.0.1` in `QR_SHIELD_ALLOWED_HOSTS`.
- When `QR_SHIELD_API_KEY` is set, the browser UI asks for it once and exchanges it for an 8-hour, signed, `HttpOnly` session cookie (see [production deployment](docs/PRODUCTION_DEPLOYMENT.md)). API clients keep sending the `X-API-Key` header.

For a quick local trial, use the `uvicorn` command above.

## Local intelligence policy

Edit `app/data/local_blocklist.txt` or set `QR_SHIELD_BLOCKLIST` to an administrator-maintained file:

```text
domain:malicious.example
url:https://malicious.example/specific/path
another-bad-domain.example
```

Edit `app/data/brand_domains.json` to add protected brands and their legitimate domains. These files remain local.

## API examples

Offline text analysis:

```bash
curl -s http://127.0.0.1:8000/api/analyze/text \
  -H 'content-type: application/json' \
  -d '{"payload":"https://singpass-login.example/verify","network_checks":false}'
```

Analyze a QR image without network access:

```bash
curl -s http://127.0.0.1:8000/api/analyze/image \
  -F 'file=@qr.png' -F 'network_checks=false'
```

## Security and production deployment

The image is decoded before any optional network activity. Direct preflight accepts only HTTP(S), rejects non-public IP space, rechecks every redirect, limits redirect depth and time, and streams headers rather than response bodies. The separate TLS probe connects to a previously validated public IP while verifying the original hostname.

For a public production deployment:

1. Place direct-preflight workers in a separate egress sandbox with no route to private, loopback, link-local, cloud-metadata, cluster or management networks.
2. Enforce DNS and HTTP(S) egress at the network layer; application checks alone cannot eliminate every DNS-rebinding or proxy edge case.
3. Configure distinct high-entropy API-authentication and HMAC report-signing secrets (at least 128 estimated entropy bits), host allowlisting, upstream identity/tenant boundaries, distributed rate limiting, monitoring and retention rules. Production readiness fails closed when these controls are absent.
4. Version and review `brand_domains.json`, blocklists and score weights under change control.
5. Validate false-positive/false-negative performance against a legally usable, time-separated local corpus before operational blocking.

## Important limitations

- A clean offline result is not proof of safety. Newly compromised legitimate sites and cloaked, targeted, geo-fenced or time-delayed attacks may have no visible lexical signal.
- A valid payment QR CRC proves internal integrity, not payee legitimacy or authorization.
- HTTPS/TLS proves an encrypted connection to the named host, not that the business behind it is trustworthy.
- The application does not render HTML, execute JavaScript, submit forms, download payloads or inspect post-render page content.
- Physical sticker substitution requires scene/context evidence or comparison with a trusted reference.

## Research basis

- Unicode UTS #39 defines mechanisms for mixed-script, confusable and identifier security analysis: https://www.unicode.org/reports/tr39/
- OWASP recommends strict allowlisting and IP validation when a server makes user-influenced outbound requests: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- EMVCo defines consumer- and merchant-presented QR payment modes: https://www.emvco.com/emv-technologies/qr-codes/
- The UK NCSC explains that QR phishing can hide malicious links, evade image-unaware controls and move users to less-protected personal devices: https://www.ncsc.gov.uk/blog-post/qr-codes-whats-real-risk
- Ireland’s NCSC recommends previewing destinations, verifying official sites and checking physical QR tampering: https://www.ncsc.gov.ie/pdfs/Quick_Guide_QR_Code_Phishing_Scams.pdf
- The US FTC documents QR lures involving failed parcel delivery, account problems, password changes, urgency, spoofed sites and malware: https://consumer.ftc.gov/consumer-alerts/2023/12/scammers-hide-harmful-links-qr-codes-steal-your-information
- The Australian Cyber Security Centre describes QR-driven credential theft and malware, and recommends known payment URLs and trusted app stores: https://www.cyber.gov.au/threats/types-threats/quishing

See `docs/RESEARCH_AND_DETECTION.md` for the feature-to-threat mapping.

## Tests

```bash
pytest -q
```

The suite covers QR-family allowlisting, image/PDF/EML decoding, nested and action/session secret redaction, strict API types, fail-closed production controls, parser abstention, no-network guarantees, IPv4/IPv6/IDNA, Unicode confusables, recursive destinations, international brand impersonation, account-link sessions, regional payments, Wi-Fi/DPP risks, grouped scoring, 29 localized policies, property fuzzing and benign controls.

Run the bundled validation harness with an authorized JSONL corpus:

```bash
python tools/evaluate_corpus.py validation/synthetic_smoke_corpus.jsonl --output metrics.json
```

The bundled smoke corpus is synthetic and must not be used for marketing or accuracy claims. Operational blocking still requires an independently sourced, legally usable, time-separated corpus.

## Licence

Copyright © 2026 NexVision Lab.

This project is source-available under the PolyForm Noncommercial
License 1.0.0. It may be used, studied and modified for permitted
non-commercial purposes.

Commercial use, paid services, commercial redistribution,
production deployment and hosted services require a separate
written licence from NexVision Lab.

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
