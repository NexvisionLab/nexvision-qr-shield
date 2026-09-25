# Research and Detection Design

## Threat-to-control mapping

| Threat observed in official guidance | Offline control |
|---|---|
| QR hides a link from the user and image-unaware email controls | Decode without navigation; display the exact payload and controlling domain |
| Failed delivery, account problem and password-reset pretexts create urgency | Require combinations of pressure and action language across localized packs |
| QR destinations request credentials or personal data | Detect credential/account requests and hostname impersonation without submitting data |
| QR destinations prompt app or file downloads | Flag executable paths, attachments, dangerous schemes and localized installation wording |
| Open-space parking, station and payment QRs can be replaced | Analyze payment and parking language; explain that physical substitution needs reference/context evidence |
| Mobile scans move users outside corporate protections | Default fully offline analysis; no destination-opening button |
| Shorteners and redirectors hide final destinations | Local shortener recognition; nested URL/open-redirect analysis; optional bounded direct redirect trace |
| Trusted institutions are impersonated across countries | Local protected-brand/domain policy plus qualified country-specific institution cues |
| Unicode homographs and display-order tricks | IDNA display, mixed-script checks, NFKC change, zero-width and bidi controls |
| Parser confusion and obfuscated hosts | User-info, delimiter, backslash, IPv4 integer/hex/octal and port analysis |
| Encoded delivery or hidden redirect | Repeated percent-decoding, Base64 preview and security-term inspection |
| Payment QR manipulation | EMV TLV boundary parsing and CRC-16 validation; amount/currency/country/merchant extraction |
| Malicious device actions | Scheme classification for app links, USSD, MFA, Wi-Fi, file/SMB, JavaScript and data URIs |
| SSRF from server-side URL checking | Offline default; non-global IP blocking, redirect revalidation, limited streaming requests and production egress guidance |

## Multilingual method

The bundled policy covers 29 language variants. It does not try to identify a speaker, nationality or exact location. It normalizes Unicode with NFKC/case-folding, decodes URL text twice, then matches curated phrases by intent category.

A scored finding normally requires both a pressure category (`urgency` or `threat`) and an action category such as credentials, payment, delivery, authority, job, investment, prize or installation. Three distinct categories can also qualify. A single generic term does not score. Protective or training context such as “scam awareness,” “never share your OTP” and localized equivalents suppresses the score and creates an informational finding instead.

Country profiles only activate on distinctive institution/payment terms. Results say “possible country signal” because language and brands can cross borders. The pack is deterministic JSON, reviewable, hash-recorded in reports and never downloaded at runtime.

## Scam families represented

- parcel failure, customs charge and redelivery;
- account suspension, password reset, MFA/OTP and identity verification;
- bank/payment, unpaid fine, tax and refund;
- government, police and public-service impersonation;
- parking, toll and public-payment context;
- fake job/task commission and recruitment;
- investment/cryptocurrency return claims;
- prize/lottery/reward; and
- app or APK installation.

## Research sources

- US Federal Trade Commission, “Scammers hide harmful links in QR codes to steal your information,” 6 December 2023: https://consumer.ftc.gov/consumer-alerts/2023/12/scammers-hide-harmful-links-qr-codes-steal-your-information
- Australian Cyber Security Centre, “Quishing,” 2 November 2023: https://www.cyber.gov.au/threats/types-threats/quishing
- UK National Cyber Security Centre, “QR Codes — what’s the real risk?”, 8 February 2024: https://www.ncsc.gov.uk/blog-post/qr-codes-whats-real-risk
- Singapore ScamShield resources: https://www.scamshield.gov.sg/more-resources/
- Unicode Technical Standard #39, Unicode Security Mechanisms: https://www.unicode.org/reports/tr39/
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- EMVCo QR Code specifications overview: https://www.emvco.com/emv-technologies/qr-codes/

The phrases in the local pack are detection policy, not quotations or claims that every listed country uses the same scam wording. Native-speaker review and region-specific false-positive evaluation are still required before operational blocking.

## Detection philosophy

The engine does not pretend that a deterministic offline method can identify every malicious site. It combines independent, explainable signals and uses a saturating risk index so several moderate indicators raise concern without claiming statistical probability.

Critical action types—MFA secret exposure, dangerous schemes, invalid payment integrity checks, local blocklist matches, credential-host deception and strong brand impersonation—can directly produce a Dangerous verdict. Informational observations such as tracking parameters, valid payment CRC and scam-awareness context do not add risk points.

## Local policy surfaces

- `app/data/multilingual_scam_packs.json`: localized intents, awareness suppressors and qualified country cues.
- `app/data/brand_domains.json`: protected names and approved domains.
- `app/data/local_blocklist.txt`: exact URLs or domain suffixes.
- `SHORTENERS`, `SUSPICIOUS_TLDS` and extensions in `app/analyzer.py`.
- Confusable mappings and redirect/query rules in `app/url_intelligence.py`.

Changes to these files should be versioned, reviewed and regression-tested. Any operational deployment should evaluate accuracy on its own legally usable regional population rather than interpreting the risk index as a universal probability.
