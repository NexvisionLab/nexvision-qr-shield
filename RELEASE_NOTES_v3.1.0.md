# NexVision QR Shield v3.1.0

Released: 22 September 2026

Version 3.1 adds deterministic multilingual and country-aware social-engineering detection while preserving the fully offline default and zero external/professional API dependency.

## Added

- 19 localized language policies spanning English, Southeast and East Asian languages, South Asian scripts, Arabic and major European languages.
- Combination-based scam categories for parcel/customs, account/MFA, payment/fines/tax, authorities, jobs/tasks, investments, prizes and app installation.
- Qualified country cues for 14 markets and expanded protected-domain policies.
- Benign awareness/negation suppression and a dedicated social-engineering score group.
- Versioned/hash-recorded `multilingual_scam_packs.json` evidence in every analysis.
- 41 new multilingual, benign-context, country-signal, brand-boundary and no-network tests.

## Changed

- Internationalized brand policy for selected postal, tax, identity, banking and government services.
- Research documentation now maps official US, UK, Australian and Singapore guidance to offline controls.
- Licence changed to PolyForm Noncommercial 1.0.0 with the NexVision Lab required notice.

## Validation

- 100 automated tests pass.
- No runtime API integration, telemetry or automatic threat-feed download was added.
- Language and country outputs are explicitly heuristic; they are not attribution or geolocation.

## Licence

Copyright © 2026 NexVision Lab.

This project is source-available under the PolyForm Noncommercial
License 1.0.0. It may be used, studied and modified for permitted
non-commercial purposes.

Commercial use, paid services, commercial redistribution,
production deployment and hosted services require a separate
written licence from NexVision Lab.

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
