# CryptoGuard — project overview

**Portfolio stage:** Year 1 · **Focus:** applied cryptography and credential security

## Goal

Make password estimates, encryption, and integrity checks explainable in one small local web app. The interface emphasizes the threat-model assumptions behind each result.

## Components

- `cryptoguard/crypto_core.py` — password checks, rough guess-rate estimates, secure random generators, AES-GCM, and digests.
- `cryptoguard/tools.py` — bounded subprocess wrappers for John the Ripper, `hashid`, and OpenSSL.
- `cryptoguard/app.py` — Flask JSON API with input validation and an 8 MB decoded file limit.
- `cryptoguard/static/index.html` — responsive interactive browser UI.
- `cryptoguard/data/` — synthetic sample hashes and a short local wordlist.

## Data and scope

All password hashes and wordlist entries are bundled demonstrations, not live account data. No external service is contacted. User files are handled in memory by the local app; the project does not persist them.

## Run and verify

```bash
docker compose up --build -d
make test
```

Open `http://localhost:8101`. See the main README for limitations and design notes.
