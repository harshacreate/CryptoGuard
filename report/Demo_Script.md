# CryptoGuard — demonstration script (5–7 minutes)

**Setup (before the audience arrives):** `docker compose up --build -d`, open http://localhost:8101, check the pill reads “3 of 3 tools ready”. Clear the browser's autofill.

| Time | Do | Say |
|---|---|---|
| 0:00 | Show the landing view | "CryptoGuard is a local workbench. Nothing I type leaves this machine or reaches a log." |
| 0:30 | Type `password` | "Blocklisted, score 2. Now a long random one…" (type a 16-char random string) "…and read the four crack-time rows: each states its guess rate." |
| 1:30 | Type `Tr0ub4dor&3-Horse!` | "Scores 100. That's a limitation I document: a dictionary word with l33t substitutions fools charset-based meters. zxcvbn handles this better." |
| 2:15 | Generator tab | "Generated with the OS CSPRNG via `secrets`, never `random`." |
| 2:45 | Encrypt tab: text + passphrase → Encrypt | "AES-256-GCM. The key comes from PBKDF2 with 200,000 iterations and a fresh salt. Salt and nonce are public; the passphrase is never stored." |
| 3:30 | Decrypt with a wrong passphrase | "GCM's tag check fails closed: no garbage output, one generic error." |
| 4:00 | John demo | "Real John the Ripper, fixed to the bundled sample file. 8 of 9 fall in seconds from a 16-word list." |
| 4:45 | Benchmark | "This is my novel part. MD5 runs millions of guesses per second, PBKDF2-600k about 15. That 231,328× slowdown equals +2.7 random characters — free for the user." |
| 5:45 | Close | "Storage choices deserve the same visibility as password rules. Questions?" |

**If something fails:** John not shown → you are outside Docker; say so and show the README screenshot. Benchmark 429 → rate limit of 6/min is working as designed; wait a minute.
