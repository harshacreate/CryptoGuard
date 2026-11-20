# Change log

This page lists the main CryptoGuard changes. It uses the [Keep a Changelog format](https://keepachangelog.com/en/1.1.0/). Version numbers use [SemVer](https://semver.org/).

## [1.1.0] - 2026-11-10

### Added and changed

- Added a key setup speed test in cryptoguard/kdf_bench.py, at POST /api/kdf-bench and in screen 01.06. It times MD5, SHA-1, SHA-256, PBKDF2 with 200k and 600k steps, and scrypt on the host. It also shows how the slower time compares to extra password characters.
- Added web_security.py for web safety settings: CSP and OWASP headers, request IDs, access logs that leave out request bodies, JSON errors and per-client request limits.
- Added security tests in tests/test_security.py and tests for the key setup speed test.
- Fixed tool status words and made small-screen tap areas 44 pixels tall.
- Added the report, slides, short report, diagrams, demo script and interview notes under report/. Added the project page under docs/.

## [1.0.0] - 2026-11-10

### Added

- First full release. It has a Flask API, a working dashboard, links to outside tools, a Docker image and Compose file, unit tests and GitHub Actions checks.
