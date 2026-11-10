# `.cguard` format v1

The `.cguard` file is UTF-8 JSON. Version 1 encrypts the plaintext with
AES-256-GCM using a 32-byte key derived by PBKDF2-HMAC-SHA256 with 200,000
iterations. Each new envelope uses a random 16-byte salt and 12-byte nonce.
Argon2id is measured by the benchmark only; it does not alter the file format.

## Fields

```json
{
  "format": "cguard",
  "version": 1,
  "algorithm": "AES-256-GCM",
  "kdf": {
    "name": "PBKDF2-HMAC-SHA256",
    "iterations": 200000,
    "salt_hex": "32 lowercase hexadecimal characters"
  },
  "nonce_hex": "24 lowercase hexadecimal characters",
  "filename": "basename only",
  "size": 0,
  "sha256": "64 lowercase hexadecimal characters",
  "ciphertext_b64": "base64(ciphertext || 16-byte GCM tag)"
}
```

The GCM additional authenticated data (AAD) is the canonical UTF-8 JSON
serialization of `format`, `version`, `algorithm`, `kdf`, `nonce_hex`,
`filename`, `size`, and `sha256`, sorted by key with no spaces. This binds the
visible metadata to the ciphertext. Decryption validates the exact v1 field
set, supported KDF parameters, salt and nonce lengths, file size, and digest.
An unknown version or malformed field is rejected before plaintext is
returned. Authentication failure also rejects modified metadata and data.

The password is never stored in the envelope. `filename` is informational and
is reduced to a basename; the application does not write decrypted paths.

## Legacy compatibility

CryptoGuard v1.0.0 files used base64 of `salt[16] || nonce[12] ||
ciphertext_and_tag`. The decryption API continues to accept that legacy blob
through the `ciphertext_b64` field. New encryption returns a structured
`format: cguard`, `version: 1` envelope. Legacy envelopes did not authenticate
their JSON metadata; only their encrypted bytes receive the AES-GCM tag check.

## Fixed test vector

[`vectors/cguard-v1.json`](vectors/cguard-v1.json) uses the public test-only
password `cguard-vector-passphrase`, plaintext `CryptoGuard v1 test vector\n`,
salt `000102030405060708090a0b0c0d0e0f`, and nonce
`000102030405060708090a0b`. It is not a secure password or production
ciphertext. The tests parse it, authenticate/decrypt it, and re-encrypt the
same fields to verify the deterministic vector.
