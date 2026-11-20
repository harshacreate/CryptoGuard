# CryptoGuard project overview

CryptoGuard is a local app for learning about password and file safety.

## What it does

- Checks password strength and explains the score.
- Makes passwords and passphrases.
- Encrypts files and checks that they have not changed.
- Makes file hashes and checks common hash formats.
- Compares password storage speeds.
- Runs a small John the Ripper demo with sample data.

## Main files

- `cryptoguard/crypto_core.py` checks passwords, makes passwords, encrypts files, and makes hashes.
- `cryptoguard/tools.py` runs the sample tools.
- `cryptoguard/app.py` starts the local web app.
- `cryptoguard/static/index.html` has the web page.
- `cryptoguard/data/` has sample hashes and words made for this project.

## Data and limits

The sample hashes and word list are made for this project. The app does not send them to an outside service. Files stay in memory while the app runs.

This is a learning project, not a security product. The password score is an estimate. Speed tests depend on the computer.

## Run it

```bash
docker compose up --build -d
make test
```

Open http://localhost:8101. See the README for more details.
