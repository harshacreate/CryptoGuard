# CryptoGuard interview questions

1. Why use AES-GCM instead of AES-CBC?

AES-GCM locks the file and checks that no one changed it. AES-CBC only locks it. AES-CBC needs a second check, called a message authentication code (MAC), to find changes. If that check is done the wrong way, an attacker may be able to learn information by changing the locked file.

2. What if AES-GCM uses the same nonce twice?

A nonce is a number used once for an encryption. Reusing the same nonce with the same key can let an attacker learn from both files or make a fake check tag. CryptoGuard makes a new key from a random 16-byte salt for each file. It also uses a random 12-byte nonce. This makes a repeat very unlikely.

3. Can the salt and nonce be saved with the locked file?

Yes. Neither one is secret. The salt helps make a new key for each file and makes pre-made password guesses less useful. The nonce helps make each encryption different.

4. Why use 200,000 PBKDF2 steps when OWASP lists 600,000?

The app makes a file key for each request. In the test container, 200,000 steps took about 24 ms at the 50th percentile, which is the middle result. The benchmark says 600,000 steps would add about 0.24 random password characters of work for a guesser. The app can use more steps later.

5. Why does scrypt look faster than PBKDF2 in the table if it is harder to attack?

The test used one CPU core. scrypt also uses memory for each guess: 16 MiB with N=2^14 and r=8. This makes it harder to check many guesses at once with a GPU or special chip. A one-core speed test does not show this benefit, so the table has this limit.

6. How can a slower hash be like a longer password?

If each character can be one of `c` choices, a random password with `n` characters has `c^n` possible forms. Adding one character multiplies the number of forms by `c`. A slowdown of `k` is like adding `log(k) / log(c)` characters. With `c=95` and `k` about 231,328, this is about 2.71 characters.

7. Why does `Tr0ub4dor&3-Horse!` get a score of 100?

The meter looks at length and character types. It misses common words when letters are changed to numbers, like 3 for e. This is a limit of simple password meters. Weir et al. (2010) discuss this problem. zxcvbn was made to spot word patterns.

8. How does the John endpoint stop people from checking any password hash?

The endpoint does not take a hash from the user. The input file paths are set in the code. The program runs with a fixed list of options, not through a shell, and it has a time limit.

9. How do you keep private text out of the logs?

The access log saves only the request type, path, result code, and time. It does not save the request body. A request ID is used only if it has 1 to 64 letters, numbers, or dashes. The check is `[A-Za-z0-9-]{1,64}`. This also helps stop fake log lines.

10. What does the Content Security Policy (CSP) do?

It tells the browser which places can load the app's scripts, styles, pictures, and connections. It also stops other sites from showing the app inside a frame. The page has code inside one file, so it uses inline code. Moving that code to separate files and using hashes or nonces would let the app use a stricter policy.

11. Why does the app have no database?

The app does not need to save data between requests. A database would add more code and another place where private text could leak.

12. What would you change before using this in a real service?

I would add user sign-in, use a reviewed file format with version numbers, use Argon2id to make keys from passwords, get an outside security review, use a stricter CSP without inline code, and use TLS to protect data sent over the network.
