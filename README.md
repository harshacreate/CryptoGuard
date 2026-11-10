# CryptoGuard

**A measured password and file-security workbench.**

Design Project I · Semester III (2024–25) · B.Tech, specialisation in Cyber Security, DISC, Hindustan Institute of Technology and Science, Chennai · by **Malepati Sree Harsha**

![tests](https://img.shields.io/badge/tests-14%20passing-2ea44f) ![python](https://img.shields.io/badge/python-3.12-3776AB) ![docker](https://img.shields.io/badge/docker-compose-2496ED) ![license](https://img.shields.io/badge/license-MIT-blue) ![focus](https://img.shields.io/badge/focus-applied%20cryptography-6250d6)

![CryptoGuard workbench](docs/screenshots/01-hero.png)

Password meters print “centuries” without saying how fast the attacker is assumed to guess. That speed depends far more on how the **server stores** the password than on one extra character. CryptoGuard is a local, private workbench for password analysis, secure generation, authenticated file encryption and a real John the Ripper demonstration. It also **measures** each password-storage scheme on your machine and expresses the cost in password characters.

## Key results (measured)

| Result | Value |
|---|---|
| Guessing slowdown, PBKDF2-SHA256 600k vs MD5 (one core, Docker image) | **231,328×** |
| Equivalent extra random characters (95-symbol alphabet) | **+2.71** |
| Weak sample hashes cracked by John the Ripper (16-word list) | **8 / 9** |
| Automated tests | **14 / 14 passing** (unit, integration, security) |
| Password-analysis latency under load | p50 4.8 ms · p95 7.8 ms · 1,535 req/s |

<details><summary>Full benchmark table (Linux aarch64, Python 3.12.16, one core)</summary>

| Scheme | Guesses / s | Slowdown vs MD5 | Worth (chars) |
|---|---|---|---|
| MD5 (unsalted) | 3,516,181.8 | ≈ 1× | — |
| SHA-1 (unsalted) | 4,160,726.7 | ≈ 1× | — |
| SHA-256 + salt | 3,834,115.7 | ≈ 1× | — |
| PBKDF2-SHA256 200k | 45.7 | 76,940× | +2.47 |
| PBKDF2-SHA256 600k | 15.2 | 231,328× | +2.71 |
| scrypt N=2^14 r=8 | 51.7 | 68,011× | +2.44 |

Ratios are the robust result; absolute speeds depend on hardware, and GPUs are far faster on fast hashes. A single-core benchmark does not show scrypt's memory-hardness advantage.
</details>

![KDF benchmark](docs/diagrams/chart-kdf-benchmark.png)

## Features

- **Explainable strength analysis:** entropy, policy checks, common-password and pattern detection, and crack-time scenarios with each guess rate stated.
- **Secure generation:** passwords (12–64 chars) and passphrases (4–8 words) from the OS CSPRNG (`secrets`).
- **AES-256-GCM encryption:** PBKDF2-HMAC-SHA256 key derivation (200k iterations), random salt and nonce, downloadable `.cguard` envelope; tampering and wrong passphrases are rejected.
- **Integrity and hash ID:** SHA-256 / SHA-1 / MD5 digests; format identification with `hashid` and built-in rules.
- **John the Ripper demo:** bounded to the bundled sample hashes and word list; accepts no input.
- **Measured KDF benchmark (novel):** times MD5, SHA-1, SHA-256, PBKDF2 (200k, 600k) and scrypt on the host; slowdown *k* → log(k)/log(c) characters.

## Architecture

![Architecture](docs/diagrams/architecture.png)

UML, DFD and deployment diagrams are in [`docs/diagrams/`](docs/diagrams/) and explained in the [project report](report/CryptoGuard_Project_Report.pdf).

## Quick start

```bash
docker compose up --build -d      # John the Ripper, hashid and OpenSSL included
open http://localhost:8101        # bound to 127.0.0.1 only
docker compose down
```

On macOS you can double-click `Start.command`. Local development without Docker:

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env              # optional
make test                         # 14 tests
make run                          # http://127.0.0.1:8000
python -m cryptoguard.kdf_bench   # benchmark from the CLI
python scripts/loadtest.py        # load test a running instance
```

## Security

Strict same-origin Content-Security-Policy and OWASP headers, request IDs, access logs that never include request bodies, JSON errors without stack traces, per-client rate limits on John and the benchmark, subprocesses without a shell, and a non-root container. See [SECURITY.md](SECURITY.md) for the threat model and how to report a vulnerability.

## Testing

`make test` runs unit tests (strength model, AES-GCM round trip and tamper rejection, generators, hash ID, KDF ordering), integration tests through Flask's test client, and security tests (headers, no-store, request-ID log-injection guard, JSON 404, HTTP 429). CI runs them on every push. Browser checks and screenshots were captured from the Docker build.

## Documentation

| Document | |
|---|---|
| [Project report (PDF)](report/CryptoGuard_Project_Report.pdf) · [Word](report/CryptoGuard_Project_Report.docx) | IEEE-style report: literature survey, SRS, UML/DFD, implementation, testing, results, references |
| [Presentation (PowerPoint)](report/CryptoGuard_Presentation.pptx) · [PDF](report/CryptoGuard_Presentation.pdf) | Review / viva slides with speaker notes |
| [Synopsis](report/CryptoGuard_Synopsis.pdf) | Two-page project synopsis |
| [Demo script](report/Demo_Script.md) | Timed live-demonstration walkthrough |
| [Viva questions](report/Viva_Questions.md) | Likely examiner / interviewer questions with answers |
| [Portfolio copy](report/Portfolio_Copy.md) | GitHub description, LinkedIn and resume text |
| [Showcase page](docs/index.html) | Landing page for GitHub Pages (Settings → Pages → `main` / `docs`) |
| [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) | Threat model, disclosure process, workflow, history |

## Limitations and roadmap

- The strength score is a heuristic. It over-rates dictionary words with l33t substitutions (e.g. `Tr0ub4dor&3-Horse!` scores 100). Next: zxcvbn-style pattern matching.
- The benchmark is single-core CPU only. Next: bcrypt and Argon2id, and a Hashcat GPU measurement.
- A versioned, documented envelope format with interoperability tests.
- Educational, loopback-only tool; not independently audited.

## Repository layout

```
├── .dockerignore
├── .env.example
├── .github/
│   └── workflows/
│       └── ci.yml
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── Dockerfile
├── LICENSE
├── Makefile
├── PROJECT_OVERVIEW.md
├── README.md
├── SECURITY.md
├── Start.command
├── cryptoguard/
│   ├── __init__.py
│   ├── app.py
│   ├── crypto_core.py
│   ├── data/
│   │   ├── sample_hashes.txt
│   │   └── wordlist.txt
│   ├── kdf_bench.py
│   ├── static/
│   │   └── index.html
│   ├── tools.py
│   └── web_security.py
├── docker-compose.yml
├── docs/
│   ├── README.md
│   ├── diagrams/  (10 images)
│   ├── index.html
│   └── screenshots/  (6 images)
├── requirements.txt
├── scripts/
│   └── loadtest.py
└── tests/
    ├── test_cryptoguard.py
    └── test_security.py
```

## License

MIT, see [LICENSE](LICENSE). Bundled hashes and word list are synthetic teaching data.
