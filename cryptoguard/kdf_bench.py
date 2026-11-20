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
import argparse
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


def _argon2id(memory_kib: int, time_cost: int, parallelism: int) -> Callable[[bytes], bytes]:
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:
        raise RuntimeError("install argon2-cffi to benchmark Argon2id") from exc
    return lambda pw: hash_secret_raw(pw, SALT, time_cost=time_cost,
                                      memory_cost=memory_kib, parallelism=parallelism,
                                      hash_len=32, type=Type.ID)


def _rate(fn: Callable[[bytes], bytes], budget_s: float) -> Tuple[float, int, float]:
    """Return (hashes per second, samples, elapsed seconds)."""
    count = 0
    start = time.perf_counter()
    elapsed = 0.0
    while elapsed < budget_s or count < 2:
        fn(b"candidate-%d" % count)
        count += 1
        elapsed = time.perf_counter() - start
    return count / elapsed, count, elapsed


def _human(seconds: float) -> str:
    if seconds < 1:
        return "under a second"
    for name, size in (("years", 31_557_600), ("days", 86_400), ("hours", 3_600),
                       ("minutes", 60), ("seconds", 1)):
        if seconds >= size:
            value = seconds / size
            return f"{value:.2e} {name}" if value >= 1e6 else f"{value:,.0f} {name}"
    return "under a second"


def _process_peak_rss_bytes():
    """Return process high-water RSS in bytes where resource is available."""
    try:
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if platform.system() == "Darwin" else value * 1024)
    except (ImportError, OSError, ValueError):
        return None


def benchmark(charset_size: int = 95, length: int = 10, budget_s: float = 0.15,
              include_argon2: bool = False, argon2_memory_kib: int = 65_536,
              argon2_time_cost: int = 3, argon2_parallelism: int = 1) -> Dict:
    if not 1 <= charset_size <= 256 or not 1 <= length <= 128:
        raise ValueError("charset_size must be 1-256 and length 1-128")
    if budget_s <= 0 or budget_s > 10:
        raise ValueError("budget_s must be greater than 0 and at most 10")
    if not 8_192 <= argon2_memory_kib <= 262_144:
        raise ValueError("argon2_memory_kib must be 8192-262144")
    if not 1 <= argon2_time_cost <= 10 or not 1 <= argon2_parallelism <= 8:
        raise ValueError("Argon2id time_cost must be 1-10 and parallelism 1-8")
    if argon2_memory_kib < 8 * argon2_parallelism:
        raise ValueError("Argon2id memory must be at least 8 KiB per parallel lane")
    keyspace_log10 = length * math.log10(charset_size)
    rows = []
    schemes = [(name, fn, note, {}) for name, fn, note in SCHEMES]
    if include_argon2:
        params = {"memory_kib": argon2_memory_kib, "time_cost": argon2_time_cost,
                  "parallelism": argon2_parallelism, "type": "Argon2id"}
        schemes.append((f"Argon2id m={argon2_memory_kib}KiB t={argon2_time_cost} p={argon2_parallelism}",
                        _argon2id(argon2_memory_kib, argon2_time_cost, argon2_parallelism),
                        "memory-hard password KDF; configured memory is per guess", params))
    for name, fn, note, params in schemes:
        rss_before = _process_peak_rss_bytes()
        rate, samples, elapsed = _rate(fn, budget_s)
        rss_after = _process_peak_rss_bytes()
        rows.append({"scheme": name, "note": note,
                     "hashes_per_second": round(rate, 1), "samples": samples,
                     "runtime_seconds": round(elapsed, 4), "parameters": params,
                     "process_peak_rss_bytes": rss_after,
                     "process_peak_rss_delta_bytes": (max(0, rss_after - rss_before)
                                                       if rss_after is not None and rss_before is not None else None)})
    base = rows[0]["hashes_per_second"]
    for row in rows:
        slowdown = base / row["hashes_per_second"]
        seconds_log10 = keyspace_log10 - math.log10(row["hashes_per_second"])
        row["slowdown_vs_md5"] = round(slowdown, 1)
        row["extra_chars_equivalent"] = round(math.log(slowdown) / math.log(charset_size), 2) if charset_size > 1 else 0.0
        row["exhaust_keyspace"] = _human(10 ** seconds_log10) if seconds_log10 < 300 else f"10^{seconds_log10:.0f} seconds"
    return {
        "machine": f"{platform.system()} {platform.machine()}, Python {platform.python_version()}, one core",
        "platform": platform.platform(),
        "password_model": {"charset_size": charset_size, "length": length,
                           "keyspace": f"{charset_size}^{length} ≈ 10^{keyspace_log10:.1f}"},
        "results": rows,
        "caveat": "Measured on this machine with hashlib and argon2-cffi when enabled. GPU/ASIC attackers are much faster on fast hashes. Compare ratios, not absolute times. Argon2id memory_kib is configured working memory per guess; observed process memory also includes interpreter and library overhead.",
    }


def main():
    parser = argparse.ArgumentParser(description="Measure password KDF cost on this machine")
    parser.add_argument("--argon2", action="store_true", help="opt in to the Argon2id measurement")
    parser.add_argument("--argon2-memory-kib", type=int, default=65_536)
    parser.add_argument("--argon2-time-cost", type=int, default=3)
    parser.add_argument("--argon2-parallelism", type=int, default=1)
    args = parser.parse_args()
    print(json.dumps(benchmark(include_argon2=args.argon2,
                               argon2_memory_kib=args.argon2_memory_kib,
                               argon2_time_cost=args.argon2_time_cost,
                               argon2_parallelism=args.argon2_parallelism), indent=2))


if __name__ == "__main__":
    main()
