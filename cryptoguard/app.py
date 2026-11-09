"""CryptoGuard — Password & File Security Toolkit (Flask backend)."""

from __future__ import annotations

import base64
import os
from dataclasses import asdict

from flask import Flask, jsonify, request, send_from_directory

from cryptoguard import crypto_core as cc
from cryptoguard import tools

HERE = os.path.dirname(__file__)
STATIC = os.path.join(HERE, "static")
DATA = os.path.join(HERE, "data")

app = Flask(__name__, static_folder=STATIC, static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024   # 8 MB upload cap


@app.route("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.route("/health")
def health():
    return "ok"


@app.route("/api/analyze", methods=["POST"])
def analyze():
    pw = (request.get_json(force=True, silent=True) or {}).get("password", "")
    return jsonify(asdict(cc.analyze_password(pw)))


@app.route("/api/generate")
def generate():
    kind = request.args.get("type", "password")
    if kind == "passphrase":
        return jsonify({"value": cc.generate_passphrase(int(request.args.get("words", 5)))})
    return jsonify({"value": cc.generate_password(
        int(request.args.get("length", 18)),
        request.args.get("symbols", "1") != "0")})


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    d = request.get_json(force=True, silent=True) or {}
    pw = d.get("password", "")
    if not pw:
        return jsonify({"error": "password required"}), 400
    raw = base64.b64decode(d["data_b64"]) if d.get("data_b64") else d.get("text", "").encode()
    return jsonify(cc.encrypt_bytes(raw, pw))


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    d = request.get_json(force=True, silent=True) or {}
    try:
        plain = cc.decrypt_bytes(d.get("ciphertext_b64", ""), d.get("password", ""))
    except Exception:
        return jsonify({"error": "decryption failed — wrong password or corrupted/tampered data"}), 400
    return jsonify({"text": plain.decode("utf-8", "replace"),
                    "data_b64": base64.b64encode(plain).decode(),
                    "sha256": cc.file_integrity(plain)["sha256"]})


@app.route("/api/integrity", methods=["POST"])
def integrity():
    d = request.get_json(force=True, silent=True) or {}
    raw = base64.b64decode(d["data_b64"]) if d.get("data_b64") else d.get("text", "").encode()
    return jsonify(cc.file_integrity(raw))


@app.route("/api/identify", methods=["POST"])
def identify():
    h = (request.get_json(force=True, silent=True) or {}).get("hash", "")
    return jsonify(tools.identify_hash(h))


@app.route("/api/john")
def john():
    return jsonify(tools.run_john(
        os.path.join(DATA, "sample_hashes.txt"),
        os.path.join(DATA, "wordlist.txt"),
        fmt="raw-md5"))


@app.route("/api/openssl")
def openssl():
    return jsonify(tools.openssl_info())


@app.route("/api/tools")
def tool_status():
    return jsonify({t: tools.tool_available(t) for t in ("john", "hashid", "openssl")})


def main():
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")))


if __name__ == "__main__":
    main()
