# v5 Production Architecture

## Default trust boundary

The default container has an internal-only network and performs no reputation, WHOIS/RDAP, translation, telemetry or cloud-AI calls. PDF rendering, email parsing, OCR, QR decoding and payload analysis occur locally.

## Required deployment controls

1. Terminate TLS at a maintained reverse proxy or ingress.
2. Set `QR_SHIELD_ALLOWED_HOSTS` to the deployed hostname.
3. Set a high-entropy `QR_SHIELD_API_KEY`. The application requires at least 32 characters, 12 distinct characters and 128 estimated entropy bits. A browser UI must sit behind an identity-aware proxy that injects authentication; never embed this key in client-side code.
4. Set a different `QR_SHIELD_REPORT_HMAC_KEY` meeting the same strength requirements and protect it as a signing secret.
5. Keep `QR_SHIELD_ALLOW_NETWORK_PREFLIGHT=0` unless the preflight worker has a separate egress sandbox with no route to loopback, private, link-local, metadata, cluster or management networks.
6. Apply distributed rate limits and queue limits at the reverse proxy. The application limiter is a bounded single-process safety layer, not a distributed quota system.
7. Forward privacy-safe JSON audit events to controlled monitoring. Do not log raw payloads or uploaded files.
8. Define evidence retention, deletion, access-control and incident-response procedures.

In production mode, `/health` returns HTTP 503 and API routes fail closed until the secret and trusted-host checks pass.

## Evidence integrity

Every result contains a SHA-256 over its canonical redacted representation. When an HMAC key is configured, the same representation is authenticated with HMAC-SHA256. HMAC provides tamper detection between trusted holders of the shared key; it is not a public-key digital signature or trusted timestamp.

## File-processing isolation

- Uploads are held in memory except for private, short-lived PDF rasterization files.
- Images are type-verified, frame-limited and pixel-limited before decoding.
- PDF work is capped at 10 pages and executed through Poppler with a timeout.
- EML parsing accepts at most 20 image attachments within global size limits.
- OCR is local, time-bounded and optional.
- No decoded destination is automatically opened.

## Operational validation gate

The included test suite and synthetic corpus demonstrate software behavior, not field accuracy. Before automated blocking, evaluate a legally usable, independently sourced, time-separated corpus with representative benign and malicious samples per deployment language, country, QR family and acquisition condition. Predeclare acceptable precision, recall, false-positive and abstention thresholds.
