import base64
from cryptoguard import crypto_core as cc
from cryptoguard import tools
from cryptoguard.app import app


def test_weak_vs_strong():
    assert cc.analyze_password("password").score < 10
    s = cc.analyze_password("9xK#mQ2!vP7wZ$tL")
    assert s.score > 80 and s.entropy_bits > 80


def test_encrypt_roundtrip_and_tamper():
    e = cc.encrypt_bytes(b"top secret", "pw")
    assert cc.decrypt_bytes(e["ciphertext_b64"], "pw") == b"top secret"
    import pytest
    with pytest.raises(Exception):
        cc.decrypt_bytes(e["ciphertext_b64"], "wrong")


def test_generator_and_integrity():
    assert len(cc.generate_password(20)) == 20
    assert "-" in cc.generate_passphrase(4)
    assert len(cc.file_integrity(b"x")["sha256"]) == 64


def test_hash_identify_builtin():
    r = tools.identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    assert any("MD5" in g for g in r["builtin_guesses"])


def test_api_endpoints():
    c = app.test_client()
    assert c.get("/health").data == b"ok"
    assert c.post("/api/analyze", json={"password": "abc"}).get_json()["score"] >= 0
    e = c.post("/api/encrypt", json={"text": "hi", "password": "k"}).get_json()
    d = c.post("/api/decrypt", json={"ciphertext_b64": e["ciphertext_b64"], "password": "k"}).get_json()
    assert d["text"] == "hi"
