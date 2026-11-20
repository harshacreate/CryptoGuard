"""Small wrappers for John the Ripper, hashid, and OpenSSL. If a tool is missing, the app still
works and shows its status. The Docker image includes these tools.
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


# John the Ripper: crack bundled sample hashes to show how cracking works

def run_john(hashes_path: str, wordlist_path: str, fmt: str = None) -> Dict:
    """Run John the Ripper on the sample MD5-crypt hashes in this project. John saves results in a
    pot file. Clear it first so each demo starts fresh.
    """
    if not tool_available("john"):
        return {"available": False, "note": "John the Ripper not installed in this environment."}
    # John saves results in <home>/.john/john.pot. Find the same home folder
    # John will use, then clear its saved results for this demo.
    try:
        import pwd as _pwd
        home = _pwd.getpwuid(os.getuid()).pw_dir
    except Exception:
        home = os.path.expanduser("~")
    env = {**os.environ, "HOME": home}
    pot = os.path.join(home, ".john", "john.pot")
    try:
        os.makedirs(os.path.dirname(pot), exist_ok=True)
        if os.path.exists(pot):
            os.remove(pot)
    except OSError:
        pass
    cmd = ["john", "--wordlist=%s" % wordlist_path]
    show = ["john", "--show"]
    if fmt:
        cmd.append("--format=%s" % fmt)
        show.append("--format=%s" % fmt)
    try:
        run = subprocess.run([*cmd, hashes_path], capture_output=True, text=True, timeout=60, env=env)
        shown = subprocess.run([*show, hashes_path], capture_output=True, text=True, timeout=30, env=env)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": True, "error": str(exc)}

    # First, read lines printed by john --show.
    cracked: List[Dict] = []
    for line in shown.stdout.splitlines():
        line = line.strip()
        if not line or "password hash" in line.lower():
            continue
        if ":" in line:
            pw = line.split(":", 1)[1]
            if pw:
                cracked.append({"password": pw})
    # If needed, read the password lines from the run output.
    if not cracked:
        for line in (run.stdout + "\n" + run.stderr).splitlines():
            m = re.match(r"^(.*\S)\s+\([^)]+\)\s*$", line)
            if m and "0:00:" not in line and "g/s" not in line:
                cracked.append({"password": m.group(1).strip()})

    m = re.search(r"(\d+)\s+password hashes?\s+cracked,\s*(\d+)\s+left", shown.stdout)
    total = (int(m.group(1)) + int(m.group(2))) if m else len(cracked)
    return {
        "available": True,
        "cracked": cracked, "cracked_count": len(cracked), "total": total,
    }


# Hash identification (hashid CLI if present, else a built-in heuristic)

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


# OpenSSL: show the crypto toolkit used by the app

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
