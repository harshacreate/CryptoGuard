# CryptoGuard demo (5–7 minutes)

**Before the demo:** Run `docker compose up --build -d`, open http://localhost:8101, check that all three tool lights are green, and clear browser autofill.

| Time | Do | Say |
|---|---|---|
| 0:00 | Show the home page | “CryptoGuard runs on this computer. It does not put the text I type in its logs.” |
| 0:30 | Check `password`, then a 16-character random password | “The app blocks `password` and gives it a score of 2. This longer password is random. The four rows show how long it may take to guess at each speed.” |
| 1:30 | Check `Tr0ub4dor&3-Horse!` | “This gets a score of 100, but it is still based on a known word with letter changes. This kind of meter only looks at character types and can miss that. zxcvbn can catch it.” |
| 2:15 | Open the password maker | “It uses the operating system’s secure random tool through Python `secrets`. It does not use `random`.” |
| 2:45 | Encrypt some text with a passphrase | “The app uses AES-256-GCM. PBKDF2 makes the key with 200,000 steps and a new salt. The salt and nonce can be seen; the app does not save the passphrase.” |
| 3:30 | Try to decrypt with the wrong passphrase | “The AES-GCM check fails. The app shows one general error and no text.” |
| 4:00 | Run the John the Ripper demo | “John the Ripper can only use the sample file and word list in this project. It found 8 of 9 sample passwords in a few seconds.” |
| 4:45 | Show the speed test | “On this computer, MD5 checks millions of guesses each second. PBKDF2 with 600,000 steps checks about 15. That is about 231,328 times slower, or like adding 2.7 random characters to a password.” |
| 5:45 | Close | “How passwords are stored matters as much as the password rules. Any questions?” |

**If something fails:** If John is missing, the app is not running in Docker. Show the README picture instead. If the speed test shows error 429, the limit of 6 tests per minute is working. Wait one minute and try again.
