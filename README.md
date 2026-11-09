# CryptoGuard — Password & File Security Toolkit

**Year:** 1 · **Stack:** Python (Flask) + HTML/CSS/JS · **Tools:** John the Ripper · OpenSSL · hashid

A hands-on applied-cryptography toolkit with a clean web UI. It analyses password
strength, proves it by actually cracking bundled sample hashes with John the
Ripper, generates strong secrets, and encrypts files with authenticated
encryption — all in the browser, nothing stored server-side.

## Features
- **Password strength analyzer** — entropy, estimated crack time across attacker
  models, policy checks, pattern/reuse detection, live strength meter.
- **“Prove it” with John the Ripper** — cracks a bundled set of sample MD5 hashes
  so you see weak passwords fall in seconds while a strong one survives.
- **Generator** — cryptographically-secure passwords and passphrases.
- **AES-256-GCM encryption** — files/text encrypted in memory, key derived with
  PBKDF2-HMAC-SHA256; authenticated (tamper is detected on decrypt).
- **Integrity & hash ID** — SHA-256/1 + MD5 digests; hash-type identification
  (built-in rules + the `hashid` tool).

## Tools used
| Tool | Where |
|------|-------|
| John the Ripper | cracks bundled sample hashes in the strength demo |
| OpenSSL | crypto toolkit info; backs TLS/crypto primitives |
| hashid | identifies hash types (with a built-in fallback) |

## Run with Docker
```bash
docker compose up --build -d      # then open http://localhost:8101
docker compose down
```
Or double-click **Start.command** (macOS). Local run: `make setup && make run`.

## Tests
```bash
make test     # crypto roundtrip + tamper, analyzer, generator, hash ID, API
```

## Scope & safety
Everything runs on your own input or bundled sample data. John the Ripper only
cracks the bundled sample hashes. Files are processed in memory and never stored.
