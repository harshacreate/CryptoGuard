# .cguard file format (version 1)

A .cguard file is a UTF-8 JSON file. Version 1 encrypts the file with AES-256-GCM. It turns the password into a 32-byte key with PBKDF2-HMAC-SHA256 and 200,000 rounds. Each new file gets a random 16-byte salt and 12-byte nonce. Argon2id is only measured by the benchmark. It is not used for this file format.

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

The extra authenticated data (AAD) uses the UTF-8 JSON values for format, version, algorithm, kdf, nonce_hex, filename, size, and sha256. The app sorts the field names and writes the JSON without spaces. This links the visible file details to the encrypted data. When opening a file, the app checks the exact version 1 fields and allowed settings. It also checks the salt and nonce lengths, file size, and SHA-256 digest. It rejects unknown versions, bad fields, or changed data and details before giving back the file.

The password is not saved in the file. The filename only keeps the file name, without its folder path. The app does not save opened files to a path from the file.

## Old file format

CryptoGuard v1.0.0 files stored base64 text made from the 16-byte salt, 12-byte nonce, and encrypted data with its tag. The app can still open this old data from the ciphertext_b64 field. New files use the fields shown above. In old files, the JSON details were not part of the encryption check. Only the encrypted data was checked with the AES-GCM tag.

## Test file

The file [vectors/cguard-v1.json](vectors/cguard-v1.json) is for tests only. It uses the public test password cguard-vector-passphrase, the text CryptoGuard v1 test vector\n, salt 000102030405060708090a0b0c0d0e0f, and nonce 000102030405060708090a0b. Do not use the test password or encrypted data for real files. Tests open the file, check it, and make it again with the same fields.
