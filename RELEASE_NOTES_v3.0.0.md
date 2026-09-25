# NexVision QR Shield v3.0.0

## Release summary

Version 3.0 is a security and detection upgrade that remains independent of every external or professional API. All reputation and policy data is local; direct destination contact remains optional and disabled by default.

## Major changes

- Secret-safe result model with SHA-256 evidence identifiers and default redaction.
- DNS-rebinding-resistant, IP-pinned redirect metadata inspection.
- Strict request validation, local rate limiting, decode concurrency limits and hardened container proxy settings.
- Early image dimension/frame/format validation and decompression-bomb rejection.
- Optional OpenCV/ZXing-C++ decoder consensus with explicit disagreement abstention.
- QR structure metadata: module dimension, version, error correction, mask and format-bit validation.
- UTS #46/STD3 host handling, expanded obfuscated IPv4 parsing and Unicode security profiles.
- Recursive, bounded destination graph with privacy-safe nodes.
- Grouped explainable risk scoring to reduce correlated double counting.
- Expanded EMV structural checks, Wi-Fi WPA3/EAP/DPP handling and deep-link policy.
- Versioned local intelligence manifest with content hashes and automatic blocklist reload on change.
- Privacy-safe JSON and standalone HTML reports.
- 59-test regression and security suite at release-candidate validation.

## No professional API

The release contains no VirusTotal, Google Safe Browsing, URLhaus, WHOIS/RDAP, cloud AI, commercial threat intelligence, telemetry or automatic feed requests. Optional DNS/TLS/HTTP-header preflight contacts only the submitted destination.

## Licence

Copyright © 2026 NexVision Lab.

This project is source-available under the PolyForm Noncommercial
License 1.0.0. It may be used, studied and modified for permitted
non-commercial purposes.

Commercial use, paid services, commercial redistribution,
production deployment and hosted services require a separate
written licence from NexVision Lab.

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
