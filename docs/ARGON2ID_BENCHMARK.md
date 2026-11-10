# Argon2id benchmark record

This records one local run of CryptoGuard's opt-in KDF benchmark on 2026-11-11.
The small 8 MiB / one-pass setting makes the run quick to reproduce; it is not
presented as a production password-storage recommendation.

| Field | Recorded value |
|---|---|
| Dataset / license / split | Not applicable: this is a local cryptographic timing benchmark, not a dataset evaluation |
| Algorithm | Argon2id (`argon2-cffi` 25.1.0) |
| Memory, time cost, parallelism | 8,192 KiB, 1 pass, 1 lane |
| Runtime | 0.1501 s for 57 samples; 379.7 hashes/s |
| Process peak RSS after run | 44,318,720 bytes; process high-water mark increased by 8,437,760 bytes during this measurement |
| Platform | macOS 27.0.1, Darwin arm64; Python 3.9.6; one process / one core |
| Timed-measurement budget | 0.15 s (two-sample minimum can make slower KDF rows exceed the budget) |

Exact command from the repository root, after `python -m pip install -r
requirements.txt`:

```bash
python -m cryptoguard.kdf_bench --argon2 --argon2-memory-kib 8192 --argon2-time-cost 1 --argon2-parallelism 1
```

The same run measured MD5 at 3,328,718.2 hashes/s, so this Argon2id setting was
8,766.7× slower in this single-core process on this host. That ratio describes
only these parameters and this machine. It is not an attacker-wide cracking
rate and should not be projected to GPUs, other hosts, or the default 64 MiB / 3
pass benchmark setting. `process_peak_rss_bytes` includes the interpreter and
all earlier benchmark rows; the delta is a process high-water change, not a
per-call allocator measurement.
