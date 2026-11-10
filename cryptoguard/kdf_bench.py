"""Measured (not assumed) password-hash cost on the machine running the app.

Most strength meters convert entropy into a crack time using a guess rate they
assume. This module instead times each storage scheme here and now, then
answers two questions for a given password:

1. How long would one CPU core take to try every candidate in its keyspace,
   if the password were stored with scheme X?
2. How many extra password characters is choosing scheme X over plain MD5
   "worth"?  (log of the measured slowdown, in base charset_size.)

Numbers are for one core running Python's hashlib (OpenSSL underneath).
Dedicated cracking rigs are far faster, especially on fast hashes, so treat
the absolute times as a lower bound on attacker speed, and the *ratios*
between schemes as the useful result.

Usage: ``python -m cryptoguard.kdf_bench`` (prints JSON).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import time
from typing import Callable, Dict, List, Tuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT = os.urandom(16)


def _md5(pw: bytes) -> bytes:
    return hashlib.md5(pw).digest()


def _sha1(pw: bytes) -> bytes:
    return hashlib.sha1(pw).digest()


def _sha256(pw: bytes) -> bytes:
    return hashlib.sha256(SALT + pw).digest()


def _pbkdf2(iterations: int) -> Callable[[bytes], bytes]:
    return lambda pw: hashlib.pbkdf2_hmac("sha256", pw, SALT, iterations)


def _scrypt(pw: bytes) -> bytes:
    # cryptography's Scrypt works even where hashlib was built without scrypt.
    return Scrypt(salt=SALT, length=32, n=2 ** 14, r=8, p=1).derive(pw)


# name, function, short note shown in the UI and report
SCHEMES: List[Tuple[str, Callable[[bytes], bytes], str]] = [
    ("MD5 (unsalted)", _md5, "legacy fast hash; never use for passwords"),
    ("SHA-1 (unsalted)", _sha1, "legacy fast hash"),
    ("SHA-256 + salt", _sha256, "salted but still fast"),
    ("PBKDF2-SHA256 200k", _pbkdf2(200_000), "what CryptoGuard uses for file keys"),
    ("PBKDF2-SHA256 600k", _pbkdf2(600_000), "OWASP 2023 minimum for PBKDF2-SHA256"),
    ("scrypt N=2^14 r=8", _scrypt, "memory-hard: 16 MiB per guess"),
]


def _rate(fn: Callable[[bytes], bytes], budget_s: float) -> Tuple[float, int]:
    """Return (hashes per second, samples) by timing fn for about budget_s."""
    count = 0
    start = time.perf_counter()
    elapsed = 0.0
    while elapsed < budget_s or count < 2:
        fn(b"candidate-%d" % count)
        count += 1
        elapsed = time.perf_counter() - start
    return count / elapsed, count


def _human(seconds: float) -> str:
    if seconds < 1:
        return "under a second"
    for name, size in (("years", 31_557_600), ("days", 86_400), ("hours", 3_600),
                       ("minutes", 60), ("seconds", 1)):
        if seconds >= size:
            value = seconds / size
            return f"{value:.2e} {name}" if value >= 1e6 else f"{value:,.0f} {name}"
    return "under a second"


def benchmark(charset_size: int = 95, length: int = 10, budget_s: float = 0.15) -> Dict:
    if not 1 <= charset_size <= 256 or not 1 <= length <= 128:
        raise ValueError("charset_size must be 1-256 and length 1-128")
    keyspace_log10 = length * math.log10(charset_size)
    rows = []
    for name, fn, note in SCHEMES:
        rate, samples = _rate(fn, budget_s)
        rows.append({"scheme": name, "note": note,
                     "hashes_per_second": round(rate, 1), "samples": samples})
    base = rows[0]["hashes_per_second"]
    for row in rows:
        slowdown = base / row["hashes_per_second"]
        seconds_log10 = keyspace_log10 - math.log10(row["hashes_per_second"])
        row["slowdown_vs_md5"] = round(slowdown, 1)
        row["extra_chars_equivalent"] = round(math.log(slowdown) / math.log(charset_size), 2) if charset_size > 1 else 0.0
        row["exhaust_keyspace"] = _human(10 ** seconds_log10) if seconds_log10 < 300 else f"10^{seconds_log10:.0f} seconds"
    return {
        "machine": f"{platform.system()} {platform.machine()}, Python {platform.python_version()}, one core",
        "password_model": {"charset_size": charset_size, "length": length,
                           "keyspace": f"{charset_size}^{length} ≈ 10^{keyspace_log10:.1f}"},
        "results": rows,
        "caveat": "Measured on this machine with hashlib; GPU/ASIC attackers are much faster on fast hashes. Compare ratios, not absolute times.",
    }


def main():
    print(json.dumps(benchmark(), indent=2))


if __name__ == "__main__":
    main()
