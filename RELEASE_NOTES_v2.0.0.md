# QR Shield v2.0.0 Release Notes

## Breaking changes

- External reputation API adapters and API-key settings were removed.
- Offline mode is now the default, including for the web UI and REST API.
- `decode_qr()` now returns payloads, image SHA-256 and image-analysis evidence.
- The JSON schema adds `image_analysis`, `decoded_details` and `engine` objects.
- The risk score is explicitly a rule-based index, not a probability.

## New detections

Unicode/confusable impersonation, protected-brand typosquatting, trusted-name subdomains, IPv4 obfuscation, nested/open-redirect links, Base64 parameters, secrets in queries, dangerous schemes, risky downloads, Wi-Fi weaknesses, MFA secrets, EMV payment structure/CRC, PayNow/SGQR indicators, cryptocurrency/UPI requests, USSD codes, embedded links, multiple QR codes and image-quality/geometry indicators.

## Validation

31 automated tests pass. The dependency environment is consistent and the application compiles successfully on Python 3.12.

## Licence

Copyright © 2026 NexVision Lab.

This project is source-available under the PolyForm Noncommercial
License 1.0.0. It may be used, studied and modified for permitted
non-commercial purposes.

Commercial use, paid services, commercial redistribution,
production deployment and hosted services require a separate
written licence from NexVision Lab.

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
