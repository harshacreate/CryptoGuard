# Changelog

All notable changes to CryptoGuard are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [1.1.0] - Unreleased (prepared; tag after review and merge)

### Added / changed
- Measured KDF benchmark (`cryptoguard/kdf_bench.py`, `POST /api/kdf-bench`, UI section 01.06): times MD5, SHA-1, SHA-256, PBKDF2 (200k/600k) and scrypt on the host and converts the slowdown into equivalent password characters.
- HTTP hardening layer (`web_security.py`): CSP and OWASP security headers, request IDs, structured access logs without bodies, JSON errors, per-client rate limits.
- Security test suite (`tests/test_security.py`) and KDF benchmark tests.
- Fixed tool-status label grammar; 44 px touch targets on small screens.
- Academic report, presentation, synopsis, diagrams, demo script and viva notes under `report/`; showcase page under `docs/`.
- Opt-in Argon2id KDF benchmark with explicit parameters and per-run timing metadata; file-encryption KDF remains unchanged.
- Pattern-aware password findings for repeated strings, keyboard / alphabetic / numeric runs and common l33t substitutions, with transparent score and guess-space penalties.
- Versioned `.cguard` v1 JSON envelope with authenticated metadata, a deterministic test vector, strict version and field validation, and v1.0.0 legacy blob decryption support.

## [1.0.0] - 2026-11-10

### Added
- First complete release: Flask API, interactive dashboard, external tool integrations,
  Docker image and Compose file, unit tests and GitHub Actions CI.
