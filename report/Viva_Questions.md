# CryptoGuard viva questions

1. Why does CryptoGuard use AES-GCM instead of AES-CBC?

AES-GCM checks that a file was not changed and that the right key was used. AES-CBC does not do these checks by itself. It needs a separate check, called a MAC. A mistake in that check can cause a padding attack.

2. What can happen if the same GCM nonce is used twice?

If the same key and nonce are used twice, an attacker may learn how the two messages differ and may fake a check tag. CryptoGuard makes a new key from a random 16-byte salt for each file. It also uses a random 12-byte nonce. This makes a repeat very unlikely.

3. Can the salt and nonce be saved with the encrypted file?

Yes. They are not secret. The salt helps make a new key for each file and stops the use of pre-made guesses. The nonce helps make each encryption different.

4. Why use 200,000 PBKDF2 steps when OWASP lists 600,000?

The app makes a file key once for each request. In the test container, 200,000 steps took about 24 ms at the 50th percentile. The benchmark shows that 600,000 steps would make the work about 0.24 characters harder for a guesser. The app can use more steps later.

5. Why is scrypt faster than PBKDF2 in the table if it is harder to attack?

The test used one CPU core. scrypt uses memory for each guess: 16 MiB with N=2^14 and r=8. This makes it harder to run many guesses at once on a GPU or ASIC. A one-core test does not show this benefit, so the benchmark has this limit.

6. How do you turn a slowdown into extra characters?

If there are c possible choices for each character, a random password with n characters has c^n possible forms. One more character multiplies that number by c. A slowdown of k is like log(k) divided by log(c) extra characters. With c=95 and k about 231,328, the result is about 2.71 characters.

7. Why does Tr0ub4dor&3-Horse! get a score of 100?

The meter looks at length and types of characters. It does not spot common words when letters are changed to numbers, such as 3 for e. This is a known limit of simple password meters. Weir et al. (2010) discuss this issue, and zxcvbn was made to catch word patterns.

8. How does the John endpoint stop people from checking any hash?

The endpoint does not take a hash as input. The file paths are set in the code. The program runs with a list of arguments, not through a shell, and it has time limits.

9. How do you keep secrets out of logs?

The access log stores only the request method, path, status and time. It never stores the request body. A request ID is used only if it has 1 to 64 letters, numbers or dashes, shown by this rule: [A-Za-z0-9-]{1,64}. This helps stop fake log entries.

10. What does the Content Security Policy (CSP) do?

It lets the app load scripts, styles, images and connections from its own site. It also stops other sites from showing the app in a frame. The page uses inline code because the whole screen is in one file. Moving the code to separate files and using hashes or nonces would let the app use a stricter policy.

11. Why does the app have no database?

The app does not need to save data between requests. A database would add more code and another place where secrets could leak.

12. What would you change before using this in a real service?

I would add user sign-in, use a reviewed file format with version numbers, use Argon2id for key setup, get an outside security review, use a stricter CSP with no inline code, and run it over TLS.
