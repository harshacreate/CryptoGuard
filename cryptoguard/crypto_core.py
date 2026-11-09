"""Core cryptography and password-analysis logic (no external tools required).

Everything here is self-contained Python so the app works offline; the external
tools (John the Ripper, hashid, OpenSSL) add real, demonstrable depth on top.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
import re
import secrets
import string
from dataclasses import dataclass, asdict
from typing import Dict, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# A small bundled list of the most common weak passwords (for the reuse check).
COMMON = {
    "password", "123456", "123456789", "qwerty", "abc123", "111111", "12345678",
    "iloveyou", "admin", "welcome", "monkey", "dragon", "letmein", "login",
    "princess", "qwerty123", "000000", "password1", "sunshine", "football",
}

_WORDS = [
    "anchor", "breeze", "cobalt", "ember", "falcon", "granite", "harbor", "ivory",
    "jasper", "kestrel", "lumen", "marble", "nimbus", "onyx", "pewter", "quartz",
    "raven", "summit", "timber", "umbra", "vertex", "willow", "xenon", "zephyr",
]


# --------------------------------------------------------------------------
# Password strength
# --------------------------------------------------------------------------

@dataclass
class Strength:
    score: int                 # 0..100
    label: str                 # Very weak .. Very strong
    entropy_bits: float
    charset_size: int
    length: int
    crack_times: Dict[str, str]
    issues: List[str]
    passed: List[str]


_GUESS_RATES = {
    "online throttled (100/s)": 1e2,
    "online unthrottled (10k/s)": 1e4,
    "offline slow hash (1M/s)": 1e6,
    "offline fast hash GPU (10B/s)": 1e10,
}


def _human_time(seconds: float) -> str:
    if seconds < 1:
        return "instant"
    units = [("years", 31557600), ("days", 86400), ("hours", 3600),
             ("minutes", 60), ("seconds", 1)]
    for name, size in units:
        if seconds >= size:
            val = seconds / size
            if val > 1e9:
                return f"{val:.1e} {name}"
            return f"{val:.0f} {name}"
    return "instant"


def analyze_password(pw: str) -> Strength:
    length = len(pw)
    charset = 0
    if re.search(r"[a-z]", pw):
        charset += 26
    if re.search(r"[A-Z]", pw):
        charset += 26
    if re.search(r"\d", pw):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        charset += 33
    charset = max(charset, 1)
    entropy = length * math.log2(charset) if length else 0.0

    issues, passed = [], []
    (passed if length >= 12 else issues).append(
        "at least 12 characters" if length >= 12 else f"too short ({length} chars) — use 12+")
    for name, rx in [("lowercase", r"[a-z]"), ("uppercase", r"[A-Z]"),
                     ("a digit", r"\d"), ("a symbol", r"[^A-Za-z0-9]")]:
        (passed if re.search(rx, pw) else issues).append(
            f"contains {name}" if re.search(rx, pw) else f"add {name}")
    if pw.lower() in COMMON:
        issues.append("appears in common-password lists")
    else:
        passed.append("not a known common password")
    if re.search(r"(.)\1{2,}", pw):
        issues.append("repeated characters (e.g. aaaa)")
    if re.search(r"(?:0123|1234|2345|3456|4567|5678|6789|abcd|qwer)", pw.lower()):
        issues.append("predictable sequence (e.g. 1234, qwer)")

    # Effective guesses ~ half the keyspace; penalise detected weaknesses.
    penalty = 1.0
    if pw.lower() in COMMON:
        penalty = 1e-12
    guesses = (charset ** length) / 2 * penalty if length else 1

    crack_times = {k: _human_time(guesses / rate) for k, rate in _GUESS_RATES.items()}

    score = max(0, min(100, int(entropy / 90 * 100) - 14 * (len(issues))))
    if pw.lower() in COMMON:
        score = 2
    label = (["Very weak", "Weak", "Fair", "Strong", "Very strong"]
             [min(4, score // 20)])
    return Strength(score, label, round(entropy, 1), charset, length,
                    crack_times, issues, passed)


# --------------------------------------------------------------------------
# Generators
# --------------------------------------------------------------------------

def generate_password(length: int = 18, symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits + ("!@#$%^&*-_=+?" if symbols else "")
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_passphrase(words: int = 5) -> str:
    chosen = [secrets.choice(_WORDS) for _ in range(words)]
    return "-".join(chosen) + str(secrets.randbelow(100))


# --------------------------------------------------------------------------
# File / data encryption (AES-256-GCM, PBKDF2 key derivation)
# --------------------------------------------------------------------------

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    return kdf.derive(password.encode())


def encrypt_bytes(data: bytes, password: str) -> Dict:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, data, None)
    blob = salt + nonce + ct
    return {
        "ciphertext_b64": base64.b64encode(blob).decode(),
        "algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256 (200,000 iters)",
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def decrypt_bytes(blob_b64: str, password: str) -> bytes:
    blob = base64.b64decode(blob_b64)
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    key = _derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ct, None)


def file_integrity(data: bytes) -> Dict:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
    }
