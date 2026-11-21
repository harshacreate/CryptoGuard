CryptoGuard

Short description

A local app for checking password strength, making passwords, encrypting files, and comparing password storage methods.

Project summary

I made CryptoGuard as a local web app. It checks passwords, makes passwords and passphrases, encrypts files, and tests how fast different password storage methods are on this computer. It also has a John the Ripper demo that uses only the sample hashes in this project.

In one test, PBKDF2-SHA256 with 600,000 rounds took about 231,328 times longer than MD5 on one CPU core. The speed changes with the computer.

Resume notes

- Made a local app for checking passwords, making passwords, and encrypting files with AES-GCM.
- Compared several password storage methods on the computer running the test.
- Added tests for the app and its security settings.

The numbers in this file are from project tests. They are not a promise about other computers.
