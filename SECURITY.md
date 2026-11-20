# Security

CryptoGuard is an educational project for Design Project I, Semester III of B.Tech Cyber Security. It is made to run on your own computer with local data. It is not made for use on a public network.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x (main) | Yes |
| Earlier versions | No |

## Report a security issue

Do not post a security issue in a public issue. Use GitHub’s private report form: open the **Security** tab and choose **Report a vulnerability**. Include the version or commit, steps to repeat the problem, and what happened.

I aim to reply within 7 days. If the issue is confirmed, I aim to share a fix or plan within 30 days. I can add your name to the changelog if you ask.

You may test your own local copy. Do not test a system or account unless you own it or have permission.

## What this app protects

The app handles passwords typed for checks, files picked for encryption, passphrases, and new passwords. The browser and Flask app run on the same computer. There are no user accounts. The app is not meant to be open to a network.

| Risk | What the app does |
|---|---|
| Secret data in logs | It does not log request data. Access logs record only the method, path, result, and time taken. |
| Weak encryption | Files use AES-256-GCM. Each file gets a random 96-bit nonce and a 16-byte salt. PBKDF2-HMAC-SHA256 makes the key with 200,000 steps. |
| Changed encrypted data | AES-GCM checks a tag. If the check fails, the API gives a general error and no partial text. |
| Easy to guess new passwords | The password tool uses Python’s `secrets` module, which gets random values from the operating system. It does not use `random`. |
| Cracking real password hashes | John the Ripper reads only the sample file and word list that come with the app. Its API takes no file or hash as input. |
| Too much work at once | Limits are 12 MB per request, 8 MB per file, and 256 characters per password. John and the key-speed test have rate limits. |
| Clickjacking, script attacks, or wrong file types | The app uses a same-origin Content Security Policy, blocks frames, sends `X-Frame-Options: DENY` and `nosniff`, and escapes changing text in the page. |

## How the code is kept safer

- Each API route checks input type, size, and range. Errors use JSON.
- Each reply has security headers. API replies are marked `Cache-Control: no-store`.
- Logs include a request ID, but never the request data.
- Users see a general error for a server fault. The full error stays in the server log.
- Program calls use fixed argument lists, no shell, and time limits.
- The Docker app runs as a non-root user. CI runs the tests on every push.

## Limits

This project has not had an outside security review. It has no sign-in because it is for one user on one computer. See the README for other limits.
