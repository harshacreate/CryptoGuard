# CryptoGuard demo (5 to 7 minutes)

Before the demo, run `docker compose up --build -d`, open http://localhost:8101, check that all three tool lights are green, and clear browser autofill.

| Time | Do | Say |
|---|---|---|
| 0:00 | Show the home page. | “CryptoGuard runs on this computer. It does not save the text I type in its logs.” |
| 0:30 | Check `password`, then a random 16-character password. | “The app blocks `password` and gives it a score of 2. The longer password was made at random. The four rows show how long it could take to guess at different speeds.” |
| 1:30 | Check `Tr0ub4dor&3-Horse!`. | “This gets a score of 100, but it is still a common word with some letters changed. This simple meter misses that kind of pattern. zxcvbn can spot common word patterns.” |
| 2:15 | Open the password maker. | “It uses Python `secrets`, which gets random values from the computer’s secure random source. It does not use Python `random`.” |
| 2:45 | Encrypt some text with a passphrase. | “The app uses AES-256-GCM to lock the file and check for changes. PBKDF2 makes the key with 200,000 steps and a new salt. The salt and nonce are saved with the file. The app does not save the passphrase.” |
| 3:30 | Try to unlock it with the wrong passphrase. | “The check fails. The app shows one general error and does not show the text.” |
| 4:00 | Run the John the Ripper demo. | “John the Ripper can only use the sample hash file and word list in this project. It found 8 of 9 sample passwords in a few seconds.” |
| 4:45 | Show the speed test. | “On this computer, MD5 checks millions of guesses each second. PBKDF2 with 600,000 steps checks about 15. That is about 231,328 times slower, or like adding 2.7 random characters to a password.” |
| 5:45 | Close. | “How passwords are saved matters as much as the rules for making them. Any questions?” |

**If something fails:** If John is missing, the app is not running in Docker. Show the README picture instead. If the speed test shows error 429, the limit of 6 tests per minute is working. Wait one minute and try again.
