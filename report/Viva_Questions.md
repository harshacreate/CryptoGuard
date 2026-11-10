# CryptoGuard — viva and interview questions

**1. Why AES-GCM rather than AES-CBC?** GCM is authenticated encryption: it produces a tag that detects any modification or wrong key. CBC alone gives confidentiality only and needs a separate MAC (and is prone to padding-oracle mistakes).

**2. What happens if a GCM nonce repeats?** With the same key, nonce reuse leaks the XOR of plaintexts and can allow tag forgeries. CryptoGuard derives a new key per encryption from a random 16-byte salt and uses a random 12-byte nonce, so reuse is negligible.

**3. Is it safe to store the salt and nonce next to the ciphertext?** Yes. Neither is secret; the salt prevents precomputation and makes each key unique; the nonce makes each encryption unique.

**4. Why PBKDF2 with 200,000 iterations, when OWASP says 600,000?** File keys are derived once per request and the app is interactive; 200k keeps encryption near 24 ms p50 in the container. The benchmark shows the cost difference explicitly (600k ≈ +0.24 more characters). Raising it is a one-line change and listed as future work.

**5. Why is scrypt faster than PBKDF2-200k in your table, if it is “stronger”?** The benchmark measures one CPU core. scrypt's advantage is memory-hardness (16 MiB per guess at N=2^14, r=8), which limits parallel GPU/ASIC attacks; a single-core benchmark cannot show that. This is a stated limitation.

**6. How do you convert slowdown to characters?** Keyspace is c^n. One more random character multiplies it by c. A slowdown k is equivalent to log(k)/log(c) characters. With c = 95 and k ≈ 231,328, that is ≈ 2.71.

**7. Why does `Tr0ub4dor&3-Horse!` score 100?** The meter counts character classes and length. It does not model dictionary words with l33t substitutions. That is a known flaw of entropy meters (Weir et al., 2010), and the reason zxcvbn exists.

**8. How do you stop the John endpoint from cracking arbitrary hashes?** It accepts no input. Paths are constants in the code, subprocesses use argument lists without a shell, and they have timeouts.

**9. How do you avoid logging secrets?** The access log records method, path, status and duration only. Request bodies are never logged. Client-supplied request IDs are accepted only if they match `[A-Za-z0-9-]{1,64}`, to prevent log injection.

**10. What does your CSP protect against?** It limits scripts, styles, images and connections to the app's own origin, and blocks framing. A cross-site script injection or clickjacking attempt therefore has much less room. Inline code is allowed because the UI is a single file. Moving to external files with hashes or nonces would allow a stricter policy.

**11. Why no database?** Nothing needs to persist; a database would only add an attack surface and a place where secrets could leak.

**12. What would you change for production?** Authentication, a reviewed versioned envelope format, Argon2id, an external audit, stricter CSP (no inline), and deployment behind TLS.
