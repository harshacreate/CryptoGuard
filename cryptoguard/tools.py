"""Wrappers around real security tools: John the Ripper, hashid, OpenSSL.

Each wrapper degrades gracefully when the tool is not installed (so the app still
runs in local development), and returns structured output the UI can render. In
the Docker image the tools ARE installed, so these produce real results.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Dict, List


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# --------------------------------------------------------------------------
# John the Ripper — crack bundled sample hashes to show real crack behaviour
# --------------------------------------------------------------------------

def run_john(hashes_path: str, wordlist_path: str, fmt: str = "raw-md5") -> Dict:
    if not tool_available("john"):
        return {"available": False, "note": "John the Ripper not installed in this environment."}
    pot = os.path.join(tempfile.gettempdir(), "cg_john.pot")
    try:
        if os.path.exists(pot):
            os.remove(pot)
    except OSError:
        pass
    common = ["--format=%s" % fmt, "--pot=%s" % pot]
    try:
        subprocess.run(["john", "--wordlist=%s" % wordlist_path, *common, hashes_path],
                       capture_output=True, text=True, timeout=60)
        shown = subprocess.run(["john", "--show", *common, hashes_path],
                               capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": True, "error": str(exc)}

    cracked: List[Dict] = []
    for line in shown.stdout.splitlines():
        if ":" in line and not line.lower().startswith(("0 password", "1 password")):
            parts = line.split(":")
            if len(parts) >= 2 and parts[1]:
                cracked.append({"hash": parts[0], "password": parts[1]})
    total = 0
    m = re.search(r"(\d+)\s+password hash", shown.stdout)
    if m:
        total = int(m.group(1))
    return {
        "available": True, "format": fmt,
        "cracked": cracked, "cracked_count": len(cracked),
        "total": total or len(cracked),
    }


# --------------------------------------------------------------------------
# Hash identification (hashid CLI if present, else a built-in heuristic)
# --------------------------------------------------------------------------

_BUILTIN = [
    (re.compile(r"^[a-f0-9]{32}$", re.I), "MD5 / NTLM (32 hex)"),
    (re.compile(r"^[a-f0-9]{40}$", re.I), "SHA-1 (40 hex)"),
    (re.compile(r"^[a-f0-9]{64}$", re.I), "SHA-256 (64 hex)"),
    (re.compile(r"^[a-f0-9]{128}$", re.I), "SHA-512 (128 hex)"),
    (re.compile(r"^\$2[aby]\$"), "bcrypt"),
    (re.compile(r"^\$6\$"), "sha512crypt (Unix)"),
    (re.compile(r"^\$1\$"), "md5crypt (Unix)"),
    (re.compile(r"^\$argon2"), "Argon2"),
]


def identify_hash(value: str) -> Dict:
    value = value.strip()
    guesses = [label for rx, label in _BUILTIN if rx.match(value)]
    out = {"input": value, "builtin_guesses": guesses}
    if tool_available("hashid"):
        try:
            r = subprocess.run(["hashid", "-m", value], capture_output=True, text=True, timeout=10)
            tool = [ln.strip("[+] ").strip() for ln in r.stdout.splitlines()
                    if ln.strip() and not ln.startswith("--") and "Analyzing" not in ln]
            out["hashid"] = tool[:8]
            out["available"] = True
        except (subprocess.TimeoutExpired, OSError):
            out["available"] = False
    else:
        out["available"] = False
    return out


# --------------------------------------------------------------------------
# OpenSSL — show the crypto toolkit backing the app
# --------------------------------------------------------------------------

def openssl_info() -> Dict:
    if not tool_available("openssl"):
        return {"available": False}
    try:
        ver = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=10)
        ciphers = subprocess.run(["openssl", "ciphers", "-v", "HIGH:!aNULL"],
                                 capture_output=True, text=True, timeout=10)
        rows = [ln.split()[0] for ln in ciphers.stdout.splitlines() if ln.strip()][:12]
        return {"available": True, "version": ver.stdout.strip(), "strong_ciphers": rows}
    except (subprocess.TimeoutExpired, OSError):
        return {"available": False}
