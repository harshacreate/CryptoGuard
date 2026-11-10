# Security policy

CryptoGuard is an educational security tool (Design Project I, Semester III, B.Tech with specialisation in Cyber Security). It is
designed to run on your own machine, on loopback, with bundled or user-supplied local data.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x (main) | Yes |
| < 1.1 | No |

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private
vulnerability reporting instead: open the repository's **Security** tab and choose
**Report a vulnerability**. Include the version or commit, steps to reproduce, and the
impact you observed.

What to expect:

- Acknowledgement within 7 days.
- A fix or mitigation plan within 30 days for confirmed issues.
- Credit in the changelog if you would like it.

Good-faith research on your own local install is welcome. Do not test against systems or
accounts you do not own or are not authorized to assess.

## Threat model

**Assets:** passwords typed for analysis, files selected for encryption, passphrases, generated secrets.

**Trust boundary:** the browser and the Flask process on the same machine. The app is not
designed to be exposed to a network and has no user accounts; binding it to a public
interface is out of scope.

| Threat | Mitigation in this codebase |
|---|---|
| Secrets leaking into logs | Request bodies are never logged; access logs record method, path, status and duration only. |
| Weak or unauthenticated encryption | AES-256-GCM (authenticated) with a random 96-bit nonce and a 16-byte salt per file; keys from PBKDF2-HMAC-SHA256, 200,000 iterations. |
| Tampered ciphertext accepted | GCM tag verification fails closed; the API returns a generic error, not partial plaintext. |
| Predictable generated secrets | Generators use Python's `secrets` module (OS CSPRNG), never `random`. |
| Cracking tool aimed at real hashes | John the Ripper only reads the bundled sample file and wordlist; the endpoint accepts no input. |
| Resource exhaustion | 12 MB request cap, 8 MB file cap, 256-char password cap, rate limits on John and the KDF benchmark. |
| Clickjacking / XSS / MIME sniffing | Strict same-origin CSP, `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`; all dynamic text is HTML-escaped in the UI. |

## Secure-development practices

- Input validation on every API route (type, length and range checks) with JSON error bodies.
- Security headers on every response (see `cryptoguard/web_security.py`) and `Cache-Control: no-store` on API responses.
- Structured access logs with a request ID; request bodies are never logged.
- Generic 500 responses: stack traces go to the server log, not the client.
- Subprocess calls use argument lists (no shell) and timeouts.
- Container runs as a non-root user; tests run in CI on every push.

## Known limitations

This project has not had an independent security audit. It has no authentication because it
is single-user and loopback-only. See the README's *Limitations* section for functional limits.
