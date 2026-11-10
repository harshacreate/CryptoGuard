"""Core cryptography and password-analysis logic (no external tools required).

Everything here is self-contained Python so the app works offline; the external
tools (John the Ripper, hashid, OpenSSL) add real, demonstrable depth on top.
"""

from __future__ import annotations

import base64
import hashlib
import json
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

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a",
                       "5": "s", "7": "t", "@": "a", "$": "s"})
_COMMON_CHUNKS = {
    "password", "welcome", "dragon", "letmein", "admin", "qwerty",
    "football", "iloveyou", "monkey", "sunshine", "princess", "login",
    "secret", "trustno1", "troubador", "correcthorse",
}
_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")


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
    folded = pw.casefold()
    normalized = folded.translate(_LEET)
    if folded in COMMON:
        issues.append("appears in common-password lists")
    else:
        passed.append("not a known common password")
    if re.search(r"(.)\1{2,}", pw):
        issues.append("repeated characters (e.g. aaaa)")
    elif re.search(r"(.{1,3})\1{2,}", pw, re.IGNORECASE):
        issues.append("repeated short pattern (e.g. abcabcabc)")

    sequence = any(run in normalized or run[::-1] in normalized
                   for run in ("0123456789", "abcdefghijklmnopqrstuvwxyz"))
    keyboard = any(any(row[i:i + 4] in normalized or row[i:i + 4][::-1] in normalized
                       for i in range(len(row) - 3)) for row in _KEYBOARD_ROWS)
    if sequence or keyboard:
        issues.append("predictable sequence (e.g. 1234, qwer)")

    chunk = next((word for word in sorted(_COMMON_CHUNKS, key=lambda x: (-len(x), x))
                  if word in normalized and len(normalized) > len(word)), None)
    if chunk and folded not in COMMON:
        issues.append(f"contains a predictable word or l33t substitution ({chunk})")

    # Effective guesses ~ half the keyspace; penalise detected weaknesses.
    penalty = 1.0
    if folded in COMMON:
        penalty = 1e-12
    if re.search(r"(.)\1{2,}|(.{1,3})\2{2,}", pw, re.IGNORECASE):
        penalty = min(penalty, 1e-4)
    if sequence or keyboard:
        penalty = min(penalty, 1e-5)
    if chunk:
        penalty = min(penalty, 1e-6)
    guesses = (charset ** length) / 2 * penalty if length else 1

    crack_times = {k: _human_time(guesses / rate) for k, rate in _GUESS_RATES.items()}

    score = max(0, min(100, int(entropy / 90 * 100) - 14 * (len(issues))))
    if folded in COMMON:
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


CGUARD_FORMAT = "cguard"
CGUARD_VERSION = 1
CGUARD_KDF_ITERATIONS = 200_000


def _safe_filename(filename: str) -> str:
    if not isinstance(filename, str) or not filename or len(filename) > 120:
        raise ValueError("filename must be 1-120 characters")
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if name in ("", ".", ".."):
        raise ValueError("filename is invalid")
    return name


def _envelope_aad(envelope: Dict) -> bytes:
    fields = {key: envelope[key] for key in (
        "format", "version", "algorithm", "kdf", "nonce_hex", "filename",
        "size", "sha256")}
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _encrypt_envelope_with_material(data: bytes, password: str, filename: str,
                                    salt: bytes, nonce: bytes) -> Dict:
    """Create a v1 .cguard JSON object; fixed material exists for test vectors only."""
    envelope = {
        "format": CGUARD_FORMAT,
        "version": CGUARD_VERSION,
        "algorithm": "AES-256-GCM",
        "kdf": {"name": "PBKDF2-HMAC-SHA256", "iterations": CGUARD_KDF_ITERATIONS,
                "salt_hex": salt.hex()},
        "nonce_hex": nonce.hex(),
        "filename": _safe_filename(filename),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, _envelope_aad(envelope))
    envelope["ciphertext_b64"] = base64.b64encode(ciphertext).decode("ascii")
    return envelope


def encrypt_envelope(data: bytes, password: str, filename: str = "text.txt") -> Dict:
    """Encrypt data into the versioned .cguard envelope format."""
    return _encrypt_envelope_with_material(
        data, password, filename, os.urandom(16), os.urandom(12))


def decrypt_envelope(envelope: Dict, password: str) -> bytes:
    """Validate and decrypt a versioned .cguard envelope."""
    if not isinstance(envelope, dict):
        raise ValueError("envelope must be an object")
    expected = {"format", "version", "algorithm", "kdf", "nonce_hex", "filename",
                "size", "sha256", "ciphertext_b64"}
    if set(envelope) != expected:
        raise ValueError("envelope fields are missing or unknown")
    if envelope["format"] != CGUARD_FORMAT or envelope["version"] != CGUARD_VERSION:
        raise ValueError("unsupported .cguard format version")
    if type(envelope["version"]) is not int:
        raise ValueError("unsupported .cguard format version")
    if envelope["algorithm"] != "AES-256-GCM":
        raise ValueError("unsupported .cguard algorithm")
    kdf = envelope["kdf"]
    if not isinstance(kdf, dict) or set(kdf) != {"name", "iterations", "salt_hex"}:
        raise ValueError("invalid .cguard KDF parameters")
    if kdf["name"] != "PBKDF2-HMAC-SHA256" or kdf["iterations"] != CGUARD_KDF_ITERATIONS:
        raise ValueError("unsupported .cguard KDF parameters")
    if not isinstance(envelope["size"], int) or isinstance(envelope["size"], bool) or envelope["size"] < 0:
        raise ValueError("invalid .cguard plaintext size")
    if _safe_filename(envelope["filename"]) != envelope["filename"]:
        raise ValueError(".cguard filename must be a basename")
    try:
        if not re.fullmatch(r"[0-9a-f]{32}", kdf["salt_hex"]):
            raise ValueError("invalid salt")
        if not re.fullmatch(r"[0-9a-f]{24}", envelope["nonce_hex"]):
            raise ValueError("invalid nonce")
        salt = bytes.fromhex(kdf["salt_hex"])
        nonce = bytes.fromhex(envelope["nonce_hex"])
        ciphertext = base64.b64decode(envelope["ciphertext_b64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("malformed .cguard binary field") from exc
    if len(salt) != 16 or len(nonce) != 12 or len(ciphertext) < 16:
        raise ValueError("malformed .cguard binary field")
    if not isinstance(envelope["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", envelope["sha256"]):
        raise ValueError("invalid .cguard digest")
    key = _derive_key(password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, _envelope_aad(envelope))
    if len(plaintext) != envelope["size"] or not secrets.compare_digest(
            hashlib.sha256(plaintext).hexdigest(), envelope["sha256"]):
        raise ValueError(".cguard plaintext metadata mismatch")
    return plaintext


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
