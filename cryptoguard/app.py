"""CryptoGuard — Password & File Security Toolkit (Flask backend)."""

from __future__ import annotations

import base64
import os
from dataclasses import asdict

from flask import Flask, jsonify, request, send_from_directory

from cryptoguard import crypto_core as cc
from cryptoguard import kdf_bench, tools
from cryptoguard.web_security import install, rate_limited

HERE = os.path.dirname(__file__)
STATIC = os.path.join(HERE, "static")
DATA = os.path.join(HERE, "data")

app = Flask(__name__, static_folder=STATIC, static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024  # 8 MB file + base64 / JSON overhead
log = install(app, "cryptoguard")


def _body():
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        return None
    return value


@app.route("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.route("/health")
def health():
    return "ok"


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = _body()
    if data is None:
        return jsonify({"error": "expected a JSON object"}), 400
    pw = data.get("password", "")
    if not isinstance(pw, str) or len(pw) > 256:
        return jsonify({"error": "password must be text of at most 256 characters"}), 400
    return jsonify(asdict(cc.analyze_password(pw)))


@app.route("/api/generate")
def generate():
    kind = request.args.get("type", "password")
    try:
        if kind == "passphrase":
            words = int(request.args.get("words", 5))
            if not 4 <= words <= 8:
                raise ValueError
            return jsonify({"value": cc.generate_passphrase(words)})
        if kind != "password":
            return jsonify({"error": "type must be password or passphrase"}), 400
        length = int(request.args.get("length", 18))
        if not 12 <= length <= 64:
            raise ValueError
        return jsonify({"value": cc.generate_password(
            length, request.args.get("symbols", "1") != "0")})
    except ValueError:
        return jsonify({"error": "password length must be 12–64; passphrases use 4–8 words"}), 400


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    d = _body()
    if d is None:
        return jsonify({"error": "expected a JSON object"}), 400
    pw = d.get("password", "")
    if not isinstance(pw, str) or not pw:
        return jsonify({"error": "password required"}), 400
    try:
        raw = base64.b64decode(d["data_b64"], validate=True) if d.get("data_b64") else str(d.get("text", "")).encode()
    except (ValueError, TypeError):
        return jsonify({"error": "file data must be valid base64"}), 400
    if len(raw) > 8 * 1024 * 1024:
        return jsonify({"error": "file must be no larger than 8 MB"}), 413
    result = cc.encrypt_bytes(raw, pw)
    result["filename"] = str(d.get("filename", "text.txt"))[:120]
    return jsonify(result)


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    d = _body()
    if d is None:
        return jsonify({"error": "expected a JSON object"}), 400
    try:
        plain = cc.decrypt_bytes(d.get("ciphertext_b64", ""), d.get("password", ""))
    except Exception:
        return jsonify({"error": "decryption failed — wrong password or corrupted/tampered data"}), 400
    return jsonify({"text": plain.decode("utf-8", "replace"),
                    "data_b64": base64.b64encode(plain).decode(),
                    "sha256": cc.file_integrity(plain)["sha256"]})


@app.route("/api/integrity", methods=["POST"])
def integrity():
    d = _body()
    if d is None:
        return jsonify({"error": "expected a JSON object"}), 400
    try:
        raw = base64.b64decode(d["data_b64"], validate=True) if d.get("data_b64") else str(d.get("text", "")).encode()
    except (ValueError, TypeError):
        return jsonify({"error": "file data must be valid base64"}), 400
    if len(raw) > 8 * 1024 * 1024:
        return jsonify({"error": "file must be no larger than 8 MB"}), 413
    return jsonify(cc.file_integrity(raw))


@app.route("/api/identify", methods=["POST"])
def identify():
    data = _body()
    if data is None:
        return jsonify({"error": "expected a JSON object"}), 400
    h = data.get("hash", "")
    if not isinstance(h, str) or len(h) > 512:
        return jsonify({"error": "hash must be text of at most 512 characters"}), 400
    return jsonify(tools.identify_hash(h))


@app.route("/api/john")
@rate_limited(6)
def john():
    return jsonify(tools.run_john(
        os.path.join(DATA, "sample_hashes.txt"),
        os.path.join(DATA, "wordlist.txt")))   # auto-detect (md5crypt sample hashes)


@app.route("/api/kdf-bench", methods=["POST"])
@rate_limited(6)
def kdf_benchmark():
    """Time each password-storage scheme here, sized to the given password.

    The password only sets the keyspace (charset size and length); it is not
    hashed, stored or logged.
    """
    data = _body()
    if data is None:
        return jsonify({"error": "expected a JSON object"}), 400
    pw = data.get("password", "")
    if not isinstance(pw, str) or len(pw) > 256:
        return jsonify({"error": "password must be text of at most 256 characters"}), 400
    if pw:
        s = cc.analyze_password(pw)
        charset, length = s.charset_size, s.length
    else:
        charset, length = 95, 10
    return jsonify(kdf_bench.benchmark(charset_size=charset, length=length))


@app.route("/api/openssl")
def openssl():
    return jsonify(tools.openssl_info())


@app.route("/api/tools")
def tool_status():
    return jsonify({t: tools.tool_available(t) for t in ("john", "hashid", "openssl")})


def main():
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8000")))


if __name__ == "__main__":
    main()
