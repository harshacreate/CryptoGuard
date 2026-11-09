# CryptoGuard — Project Overview

**Sector:** Applied cryptography / credential security · **Year 1 project**

## Summary
A password-and-file security toolkit that makes cryptography tangible: it scores
password strength and *demonstrates* real cracking with John the Ripper, generates
secure secrets, and performs authenticated AES-256-GCM encryption with PBKDF2 key
derivation — presented through a polished, interactive web UI.

## Real tools
- **John the Ripper** — cracks bundled sample MD5 hashes to show crack times.
- **OpenSSL** — crypto toolkit information and primitives.
- **hashid** — hash-type identification (with a built-in rule fallback).

## How it works
- `cryptoguard/crypto_core.py` — entropy/crack-time model, AES-GCM, hashing, generators.
- `cryptoguard/tools.py` — subprocess wrappers for John/hashid/OpenSSL (graceful fallback).
- `cryptoguard/app.py` — Flask API; `static/index.html` — the UI.

## Run
```bash
docker compose up --build -d   # http://localhost:8101
```

## Scope
Own input / bundled data only. Files processed in memory, never stored.
