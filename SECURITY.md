Security

CryptoGuard is a learning project for Design Project I, Semester III of B.Tech Cyber Security. It runs on your computer and uses local data. Do not use it on a public network.

Supported versions

1.1.x (main): Yes

Earlier versions: No

Report a security issue

Do not report a security issue in a public issue. Open GitHub's Security tab and choose Report a vulnerability. Include the version or commit, steps to repeat the problem, and what happened.

I aim to reply within 7 days. If I confirm the issue, I aim to share a fix or plan within 30 days. I can add your name to the change log if you ask.

You may test your own copy on your computer. Do not test a system or account unless you own it or have permission.

What this app does

The app handles passwords you type for checks, files you choose to encrypt, passphrases, and new passwords. Your browser and the Flask app run on the same computer. There are no user accounts. Do not open the app to a network.

Request details in logs: It does not log request contents. Access logs keep only the method, path, result, and time taken.

Weak file encryption: Files use AES-256-GCM. Each file gets a random 96-bit nonce and a 16-byte salt. PBKDF2-HMAC-SHA256 makes the key with 200,000 steps.

Changed encrypted data: AES-GCM checks a tag on the data. If the check fails, the API sends a general error and no partial text.

New passwords that are easy to guess: The password tool uses Python's secrets module to get random values from the operating system. It does not use random.

Cracking real password hashes: John the Ripper reads only the sample file and word list that come with the app. Its API does not take a file or hash as input.

Too many requests at once: Limits are 12 MB per request, 8 MB per file, and 256 characters per password. John and the key speed test also have limits.

Clickjacking, script attacks, or wrong file types: The app uses a same-origin Content Security Policy, blocks frames, sends X-Frame-Options: DENY and nosniff, and escapes changing text on the page.

How the app stays safer

Each API route checks the input type, size, and allowed range. Errors use JSON.

Each reply has security headers. API replies use Cache-Control: no-store so the browser does not save them.

Logs include a request ID, but not the request contents.

A server error shows a general message. The full error stays in the server log.

Program calls use fixed arguments, do not use a shell, and have time limits.

The Docker app does not run as the root user. CI runs the tests after each push.

Limits

This project has not had an outside security review. It has no sign in because it is for one person on one computer. See the README for other limits.
