# Copilot instructions

- Treat CryptoGuard as a local learning tool. Use made-up demo passwords and sample hashes; never add or log real credentials.
- Preserve `.cguard` v1 compatibility and authenticated encryption checks. Do not change the file format or encryption KDF as part of a benchmark-only change.
- Keep Argon2id opt-in and benchmark-only. Describe host timing as a measurement, not a production setting or attacker cracking rate.
- Treat password-pattern feedback as an estimate, not a guarantee that a password is safe or crackable in a stated time.
- Keep John the Ripper confined to the bundled sample hashes and word list; do not add external targets or downloaded credential lists.
- Use Python 3.12 and the existing package structure. Run the relevant pytest checks when code changes; CI also reports coverage.
