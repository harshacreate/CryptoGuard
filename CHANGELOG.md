# Change log

This page lists the main changes to CryptoGuard.

## [1.1.0] - Not released yet

This version is ready for review. Add its release tag after review and merge.

### Added and changed

- Added a test for how long different password key setup methods take. It is in cryptoguard/kdf_bench.py, at POST /api/kdf-bench, and on screen 01.06. It checks MD5, SHA-1, SHA-256, PBKDF2 with 200,000 and 600,000 steps, and scrypt on this computer. It also compares the slowest time with the time added by extra password characters.
- Added web_security.py for browser security settings. It adds CSP and OWASP security headers, request IDs, access logs without request bodies, JSON error replies, and per-client request limits.
- Added security tests in tests/test_security.py and tests for the new speed test.
- Made status words clearer and made phone tap areas 44 pixels high.
- Added the report, slides, short report, diagrams, demo steps, interview questions, and project page.
- Added an optional Argon2id key setup speed test. It saves the settings and time for each run. File encryption still uses the same key setup as before.
- Password checks now flag repeated text, runs of keyboard keys, letters or numbers, and common letter-to-number swaps.
- Added version 1 of the .cguard JSON file format. It checks the file data and metadata, includes a fixed test example, checks input carefully, and can still open files made with version 1.0.0.

## [1.0.0] - 2026-11-10

### Added

- First full release. It includes a Flask API, a dashboard, links to outside tools, a Docker image and Compose file, tests, and GitHub Actions checks.
