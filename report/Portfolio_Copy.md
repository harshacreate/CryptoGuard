# CryptoGuard — portfolio copy

## GitHub
**Description (≤ 350 chars):** Local password & file-security workbench: explainable strength analysis, CSPRNG generator, AES-256-GCM encryption, John the Ripper demo, and a measured KDF benchmark that shows how much MD5 vs PBKDF2 vs scrypt changes an attacker's speed. Flask · Docker · tested.

**Topics:** `cybersecurity` `cryptography` `password-security` `pbkdf2` `scrypt` `aes-gcm` `john-the-ripper` `flask` `docker` `python`

## LinkedIn — Projects section
**CryptoGuard — Measured Password & File-Security Workbench**
Built a local web app that makes password security measurable. Beyond strength analysis, CSPRNG generation and AES-256-GCM file encryption (PBKDF2 key derivation), it benchmarks MD5, SHA-256, PBKDF2 and scrypt on the host and converts each scheme's cost into "extra password characters". Result: PBKDF2-600k slowed guessing ~231,328× vs MD5, worth ≈ 2.7 random characters. John the Ripper integration (bounded to bundled hashes), strict CSP and OWASP headers, rate limiting, 14 automated tests, Docker, CI.
*Skills:* Python · Applied Cryptography · Flask · Docker · Secure Coding · John the Ripper · OpenSSL

## Resume bullets
- Built **CryptoGuard**, a Flask/Docker password and file-security workbench with AES-256-GCM encryption and PBKDF2 key derivation; integrated John the Ripper, hashid and OpenSSL through hardened subprocess adapters.
- Designed a host-measured KDF benchmark; showed PBKDF2-600k slows guessing **~231,328×** vs MD5 (≈ **+2.7 password characters**).
- Applied OWASP controls (CSP, security headers, rate limiting, safe logging) verified by 14 pytest cases in CI; p50 latency < 5 ms at 1,500+ req/s.
