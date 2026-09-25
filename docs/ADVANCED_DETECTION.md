# Advanced Detection Architecture

## Research decision

QR Shield uses several independent evidence layers. Official guidance emphasizes that QR codes conceal destinations and can lead to spoofed credential pages, malware downloads, payment deception and social engineering. Research also shows that QR structural and pixel features can provide signal, but published results are dataset-dependent and do not establish that a particular physical QR is malicious.

For that reason, QR structure is reported as supporting context only. Scored findings are based on the decoded action, destination identity, concealment method, social-engineering intent, payment integrity and correlated attack stages.

## Detection layers

| Layer | Evidence | Decision role |
|---|---|---|
| Image reliability | Decoder consensus, sharpness, contrast, geometry, format bits | Reliability or abstention |
| QR structure | Version, EC level, mask, density, timing pattern, central uniformity | Context only, except invalid/disagreeing decode evidence |
| Payload type | URL, Wi-Fi, MFA, EMV, EPC, UPI, crypto, WalletConnect, message action | Action-specific controls |
| Recursive decoding | Percent, HTML entity, JSON escape and Base64 chains | Concealment findings |
| Destination identity | IDNA, confusables, registrable domain, brand policy | Impersonation findings |
| Cross-field intent | Brand/auth language outside the hostname, fragments, shared infrastructure | Contextual phishing findings |
| Local intelligence | Administrator blocklist and protected domains | Exact local policy evidence |
| Attack-chain fusion | Concealment + impersonation + pressure + sensitive action | Correlated high-risk finding |

## Privacy model

Recursive decoding is limited to 8,192 characters, depth 3 and 16 unique states. Intermediate decoded bodies are represented by SHA-256, length, transform chain and indicator counts. URLs are passed through the existing privacy redactor before evidence is stored. EPC beneficiary and IBAN values and WalletConnect symmetric keys are redacted before results or reports are constructed.

## False-positive controls

- Shared hosting or tunnel use does not score unless authentication or brand cues are also present.
- A brand in a query alone is not enough; it must be paired with authentication wording or a stronger path/fragment claim.
- Ordinary percent-encoded characters in the outer URL are not treated as a hidden destination.
- Structural QR features do not create a malicious verdict by themselves.
- Attack-chain fusion requires evidence from at least three independent stages.
- Existing multilingual scoring still requires coordinated intent rather than one generic word.

## Research sources

- US FTC QR scam guidance: https://consumer.ftc.gov/consumer-alerts/2023/12/scammers-hide-harmful-links-qr-codes-steal-your-information
- Australian Cyber Security Centre quishing guidance: https://www.cyber.gov.au/threats/types-threats/quishing
- UK NCSC QR risk analysis: https://www.ncsc.gov.uk/blog-post/qr-codes-whats-real-risk
- OWASP Unvalidated Redirects and Forwards Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- Unicode Technical Standard #39: https://www.unicode.org/reports/tr39/
- Akram, Sood and Hassan, “QRïS: A Preemptive Novel Method for Quishing Detection Through Structural Features of QR,” 2025: https://arxiv.org/abs/2510.17175
- Trad and Chehab, “Detecting Quishing Attacks with Machine Learning Techniques Through QR Code Analysis,” 2025: https://arxiv.org/abs/2505.03451
- Sharevski, Devine, Pieroni and Jachim, “Gone Quishing: A Field Study of Phishing with Malicious QR Codes,” 2022: https://arxiv.org/abs/2204.04086

## Remaining validation gaps

The engine does not claim a calibrated maliciousness probability. Structural and lexical features require validation on a legally usable, time-separated corpus of real benign and malicious QR images. Physical sticker replacement still requires scene evidence or comparison with a trusted reference. Offline analysis cannot identify a newly compromised legitimate domain or content delivered only after browser execution, login, geolocation or time delay.
