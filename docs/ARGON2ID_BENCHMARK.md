# Argon2id benchmark

This page shows one local run of CryptoGuard's optional password key test on 2026-11-11. The test used 8 MiB and one pass to finish quickly. This setting is for a quick test only. It is not advice for storing passwords.

| Item | Value |
|---|---|
| Data | Not used: this is a local speed test, not a data set test |
| Algorithm | Argon2id (argon2-cffi 25.1.0) |
| Memory, time, parallel work | 8,192 KiB, 1 pass, 1 lane |
| Run time | 0.1501 seconds for 57 samples; 379.7 hashes per second |
| Peak process memory (RSS) | 44,318,720 bytes; highest recorded memory use rose by 8,437,760 bytes during this test |
| Computer | macOS 27.0.1, Darwin arm64; Python 3.9.6; one process and one core |
| Test time limit | 0.15 seconds (slow settings may take longer because each needs at least two samples) |

Run these commands from the main project folder to install the needed packages and repeat the test:


```bash
python -m pip install -r requirements.txt
python -m cryptoguard.kdf_bench --argon2 --argon2-memory-kib 8192 --argon2-time-cost 1 --argon2-parallelism 1
```


This run measured MD5 at 3,328,718.2 hashes per second. With these settings, Argon2id was 8,766.7 times slower on this computer using one core. This number only applies to these settings and this computer. It does not show how fast an attacker could guess passwords on other computers or graphics cards. It also does not compare with the default 64 MiB and three-pass setting.

The process_peak_rss_bytes value includes Python and all earlier test rows. The change is the highest increase seen by the process, not the memory used by one call.
