import base64
import json
from pathlib import Path
from cryptoguard import crypto_core as cc
from cryptoguard import tools
from cryptoguard.app import app


def test_weak_vs_strong():
    assert cc.analyze_password("password").score < 10
    s = cc.analyze_password("9xK#mQ2!vP7wZ$tL")
    assert s.score > 80 and s.entropy_bits > 80


def test_password_analysis_flags_predictable_patterns_and_l33t():
    checks = {
        "aaaaW!9x": "repeated characters",
        "abcabcabc!Q9": "repeated short pattern",
        "xxqwertyZZ8!": "predictable sequence",
        "P@ssw0rd!Long": "l33t substitution",
    }
    for password, expected in checks.items():
        result = cc.analyze_password(password)
        assert any(expected in issue for issue in result.issues), (password, result.issues)
        assert result.score < 100
    assert "predictable word or l33t substitution" in " ".join(
        cc.analyze_password("P@ssw0rd!Long").issues)


def test_encrypt_roundtrip_and_tamper():
    e = cc.encrypt_bytes(b"top secret", "pw")
    assert cc.decrypt_bytes(e["ciphertext_b64"], "pw") == b"top secret"
    import pytest
    with pytest.raises(Exception):
        cc.decrypt_bytes(e["ciphertext_b64"], "wrong")


def test_versioned_cguard_roundtrip_authenticates_metadata():
    envelope = cc.encrypt_envelope(b"message", "passphrase", "notes.txt")
    assert envelope["format"] == "cguard" and envelope["version"] == 1
    assert cc.decrypt_envelope(envelope, "passphrase") == b"message"
    import copy
    import pytest
    changed = copy.deepcopy(envelope)
    changed["filename"] = "other.txt"
    with pytest.raises(Exception):
        cc.decrypt_envelope(changed, "passphrase")
    unknown = copy.deepcopy(envelope)
    unknown["version"] = 2
    with pytest.raises(ValueError, match="version"):
        cc.decrypt_envelope(unknown, "passphrase")
    malformed = copy.deepcopy(envelope)
    malformed["extra"] = True
    with pytest.raises(ValueError, match="fields"):
        cc.decrypt_envelope(malformed, "passphrase")


def test_fixed_cguard_v1_test_vector_parses_and_decrypts():
    vector_path = Path(__file__).parents[1] / "docs" / "vectors" / "cguard-v1.json"
    vector = json.loads(vector_path.read_text())
    password = "cguard-vector-passphrase"
    plaintext = b"CryptoGuard v1 test vector\n"
    assert cc.decrypt_envelope(vector, password) == plaintext
    assert cc._encrypt_envelope_with_material(
        plaintext, password, "vector.txt", bytes(range(16)), bytes(range(12))) == vector


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
    d = c.post("/api/decrypt", json={"envelope": e["envelope"], "password": "k"}).get_json()
    assert d["text"] == "hi"


def test_api_rejects_bad_input_and_bounds_generator():
    c = app.test_client()
    assert c.post("/api/analyze", json={"password": "x" * 257}).status_code == 400
    assert c.get("/api/generate?length=3").status_code == 400
    assert c.get("/api/generate?type=passphrase&words=99").status_code == 400
    assert c.post("/api/integrity", json={"data_b64": "%%%"}).status_code == 400
    assert c.post("/api/encrypt", json={"password": "x", "data_b64": "%%%"}).status_code == 400


def test_cguard_envelope_includes_filename_and_decrypts():
    c = app.test_client()
    encoded = base64.b64encode(b"sample document").decode()
    encrypted = c.post("/api/encrypt", json={
        "password": "correct horse", "data_b64": encoded, "filename": "notes.txt"
    }).get_json()
    assert encrypted["algorithm"] == "AES-256-GCM"
    assert encrypted["filename"] == "notes.txt"
    decrypted = c.post("/api/decrypt", json={
        "password": "correct horse", "envelope": encrypted["envelope"]
    }).get_json()
    assert base64.b64decode(decrypted["data_b64"]) == b"sample document"


def test_legacy_unversioned_cguard_blob_remains_decryptable():
    c = app.test_client()
    legacy = cc.encrypt_bytes(b"legacy payload", "correct horse")
    result = c.post("/api/decrypt", json={
        "password": "correct horse", "ciphertext_b64": legacy["ciphertext_b64"]
    }).get_json()
    assert base64.b64decode(result["data_b64"]) == b"legacy payload"


def test_kdf_benchmark_orders_schemes_by_cost():
    from cryptoguard import kdf_bench
    report = kdf_bench.benchmark(charset_size=62, length=8, budget_s=0.02)
    rates = {r["scheme"]: r["hashes_per_second"] for r in report["results"]}
    assert rates["MD5 (unsalted)"] > 1000 * rates["PBKDF2-SHA256 200k"]
    assert rates["PBKDF2-SHA256 200k"] > rates["PBKDF2-SHA256 600k"]
    pbkdf2 = next(r for r in report["results"] if r["scheme"] == "PBKDF2-SHA256 600k")
    assert pbkdf2["extra_chars_equivalent"] > 2


def test_opt_in_argon2id_benchmark_reports_parameters_and_runtime():
    from cryptoguard import kdf_bench
    report = kdf_bench.benchmark(charset_size=62, length=8, budget_s=0.01,
                                 include_argon2=True, argon2_memory_kib=8192,
                                 argon2_time_cost=1, argon2_parallelism=1)
    row = next(r for r in report["results"] if r["parameters"].get("type") == "Argon2id")
    assert row["parameters"] == {"memory_kib": 8192, "time_cost": 1,
                                 "parallelism": 1, "type": "Argon2id"}
    assert row["hashes_per_second"] > 0 and row["runtime_seconds"] > 0
    assert "process_peak_rss_bytes" in row and "process_peak_rss_delta_bytes" in row
    assert kdf_bench.benchmark(budget_s=0.01)["results"][-1]["scheme"].startswith("scrypt")
    import pytest
    with pytest.raises(ValueError, match="argon2_memory_kib"):
        kdf_bench.benchmark(include_argon2=True, argon2_memory_kib=100)


def test_kdf_endpoint_validates_input():
    from cryptoguard.web_security import reset_rate_limits
    reset_rate_limits()
    c = app.test_client()
    assert c.post("/api/kdf-bench", json={"password": "x" * 300}).status_code == 400
    assert c.post("/api/kdf-bench", data="nope").status_code == 400
