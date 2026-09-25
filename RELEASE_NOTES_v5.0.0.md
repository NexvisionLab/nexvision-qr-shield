# NexVision QR Shield v5.0.0 — Production Edition

Released: 23 September 2026

## Security corrections

- Fully redacts authenticator migration protobuf data before serialization.
- Restricts enhanced decoding to QR Code, Micro QR and rMQR.
- Uses structural EMV classification so valid dynamic and regional payment QRs are not treated as ordinary URLs.
- Abstains on browser/server URL authority ambiguity and prevents active inspection.

## New detection and evidence support

- Pix, PromptPay, PayNow, DuitNow and possible QRIS profiles with privacy-safe nested template evidence.
- Structured UPI and cryptocurrency validation, FIDO/account-link sessions, Android intent fallback extraction and GS1 Digital Link validation.
- PDF, EML and TIFF ingestion plus optional fully local OCR context.
- 29 language variants and 22 country/region signal profiles.
- Canonical report hashes and optional HMAC-SHA256 evidence signatures.

## Production controls

- Host allowlisting, optional API authentication, cross-site request rejection, request IDs and bounded in-process rate state.
- Direct preflight requires explicit server enablement and remains off by default.
- Hardened non-root container, read-only filesystem, dropped capabilities, process/memory/CPU limits, internal network and local Poppler/Tesseract tooling.
- Synthetic evaluation harness and property-based fuzz tests.

## Validation

- 142 automated tests pass.
- Synthetic smoke corpus: 6 true positives, 3 true negatives, 0 false classifications and 1 intentional parser-ambiguity abstention.
- These synthetic metrics are regression evidence only, not a calibrated product-performance claim.

## Licence

Copyright © 2026 NexVision Lab.

This project is source-available under the PolyForm Noncommercial
License 1.0.0. It may be used, studied and modified for permitted
non-commercial purposes.

Commercial use, paid services, commercial redistribution,
production deployment and hosted services require a separate
written licence from NexVision Lab.

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
