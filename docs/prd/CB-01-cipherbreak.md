# PRD CB-01: CipherBreak

**Owner:** Seedy M. Jahateh
**Status:** Draft for build
**Origin:** rebuilds the 2024 `Enigma-Encryption_-_Decryption` script (65 lines, no tests) into a measured security project.
**One line:** implement a classical polyalphabetic shift cipher correctly, break it three ways, measure exactly how fast it falls, and explain what to use instead.

---

## 1. Problem

The original script encrypts text with four rotating shifts derived from a 5-digit key and the date. It works, but on its own it shows only that a cipher can be written. It does not show the skill security teams hire for: reasoning about how a system fails, attacking it, and measuring the result.

The cipher is weak for well-understood reasons:

- **Tiny key space:** each shift is a key digit (0–9) plus a date digit (0–9), so 0–18. That gives 19⁴ = 130,321 possible shift tuples.
- **Short period:** the shifts repeat every 4 characters, so the ciphertext splits into 4 independent Caesar ciphers.
- **Predictable offsets:** the date-derived offsets are public to anyone who knows, or guesses, the day.
- **Key exposure:** the reference code prints the shifts and passes them around in the clear.

CipherBreak turns those facts into evidence.

## 2. Goals

| ID | Goal | Measure |
|---|---|---|
| G1 | A correct, tested implementation of the cipher | Round-trip property tests pass on random messages; fixed test vectors pass |
| G2 | Three working attacks that recover the key | Each attack's success rate, by ciphertext length, measured and published |
| G3 | Honest measurement | 200 trials at each of 6 lengths; results in a CSV and one chart; failures reported |
| G4 | Clear guidance | The README explains why the cipher is unsafe and shows a working AES-GCM replacement |
| G5 | Reproducible | `pip install -e .` then `pytest` then `python experiments/run.py` reproduces the table on any machine (fixed seeds) |

## 3. Non-goals

- Modelling the WWII Enigma machine (rotors, reflector, plugboard). The README must say plainly that this is a Vigenère-family shift cipher.
- Proposing a new secure cipher.
- Breaking real-world encryption, or attacking anyone else's data.
- A web UI.

## 4. Audience

1. **Security and engineering recruiters and interviewers**, who should understand the attack and the result in two minutes from the README.
2. **Seedy, in interviews**, who needs every number to be reproducible and explainable.
3. **Learners**, who can follow the attack walkthrough.

## 5. Functional requirements

### 5.1 Cipher (`cipherbreak/cipher.py`)

- **FR-1** `Cipher(key: str, on: date)`: a 5-digit key and an explicit date, so runs are reproducible. Never read the system clock inside the class.
- **FR-2** `shifts()` returns the shift tuple. Decide and document whether the 5th key digit is used (the original generates it and never uses it). If it is used, the period becomes 5: update the key-space math everywhere.
- **FR-3** `encrypt(text)` and `decrypt(text)` operate on the 27-symbol alphabet `a–z` plus space. Case handling must be a documented choice: either preserve case (map the case back after shifting) or lowercase with a warning. Characters outside the alphabet pass through unchanged and do **not** advance the shift position, or they do; pick one, document it, and test it.
- **FR-4** `keygen(rng)` returns a random key from an injectable random generator, for experiments.
- **FR-5** Nothing runs at import time. The demo from the original file moves to the CLI.

### 5.2 CLI (`cipherbreak/cli.py`)

- **FR-6** `cipherbreak encrypt --key 12345 --date 2026-10-06 "text"` and `cipherbreak decrypt ...`.
- **FR-7** `cipherbreak attack --method {brute,columns,known} --ciphertext FILE [--known-prefix "hello"] [--date ...]` prints the recovered shifts, the plaintext, and the time taken.
- **FR-8** The CLI never prints a key it was not asked to print.

### 5.3 Attacks (`cipherbreak/attacks.py`)

Every attack returns `AttackResult(shifts, plaintext, candidates_tried, seconds, rank_of_true_key | None)`.

- **FR-9 Brute force (ciphertext only).** Enumerate all 19⁴ shift tuples, decrypt, and score with a chi-squared statistic against English letter-and-space frequencies. Return the best candidate and, in experiments, the rank of the true key.
- **FR-10 Column frequency analysis (ciphertext only).** Split the ciphertext into 4 columns by position mod 4. For each column, try all 27 shifts and keep the one whose frequencies best match English. That is 108 trials instead of 130,321. This is the central result of the project.
- **FR-11 Known-plaintext.** Given a known prefix of at least 4 characters, recover each shift by subtraction modulo 27. A variant takes the date, derives the offsets, and searches only the 10⁴ key-digit combinations.
- **FR-12** Frequency tables come from a documented source and live in `cipherbreak/data/english_freq.json`, with the space frequency included.

### 5.4 Experiments (`experiments/run.py`)

- **FR-13 Corpus:** one public-domain English book from Project Gutenberg, stored with its URL and a SHA-256 checksum. No personal or private text, ever.
- **FR-14 Design:** ciphertext lengths of 10, 20, 40, 80, 160 and 320 characters; 200 random excerpts per length; a random key and a random date for each trial; a fixed master seed.
- **FR-15 Outputs:** `experiments/results.csv` (one row per trial: length, method, success, seconds, candidates, rank) and `experiments/summary.csv` (per length and method: success rate with a 95% Wilson interval, median and p95 time).
- **FR-16 Chart:** `experiments/success_by_length.png`, showing success rate against ciphertext length, one line per method, with error bars.
- **FR-17:** the README table is generated from `summary.csv`, never typed by hand.

### 5.5 Replacement demo (`examples/aesgcm_demo.py`)

- **FR-18** Encrypt and decrypt with `cryptography`'s `AESGCM`: a 256-bit key from `AESGCM.generate_key`, a fresh 96-bit nonce from `os.urandom(12)` for every message, associated data included, and a deliberate tampering test that shows decryption fails with `InvalidTag`.
- **FR-19** The README states the rules: never reuse a nonce with the same key, never write your own cipher for real data, and keep keys out of source code.

## 6. Non-functional requirements

- **NFR-1** Python 3.12, standard library plus `cryptography`, `matplotlib`, `pytest` and optionally `hypothesis`. No heavy dependencies.
- **NFR-2** A full experiment run finishes in under 10 minutes on a laptop. If brute force is too slow at 200 trials per length, cap brute force at a documented smaller trial count and say so.
- **NFR-3** Deterministic: the same seed gives byte-identical `results.csv`.
- **NFR-4** Lint with `ruff`; type-check with `mypy --strict` on `cipherbreak/`.
- **NFR-5** CI (GitHub Actions) runs lint, types and tests on every push. Experiments run on demand (`workflow_dispatch`), not on every push.

## 7. Architecture

```
cipherbreak/
  __init__.py
  alphabet.py        27-symbol alphabet, index maps
  cipher.py          Cipher, keygen
  scoring.py         chi-squared against English frequencies
  attacks.py         brute_force, column_analysis, known_plaintext
  cli.py             argparse entry point
  data/english_freq.json
experiments/
  corpus/README.md   source URL + SHA-256 of the corpus file
  run.py             trials -> results.csv, summary.csv, chart
examples/aesgcm_demo.py
tests/
  test_cipher.py  test_attacks.py  test_scoring.py  test_cli.py
docs/prd/CB-01-cipherbreak.md
.github/workflows/ci.yml
pyproject.toml  README.md  LICENSE
```

## 8. Testing strategy

| Area | Tests |
|---|---|
| Cipher | round trip on random strings (property test); fixed vectors for a known key and date; pass-through characters; case behaviour; the 5th-digit decision |
| Scoring | English text scores better than shuffled text; a uniform distribution scores worst |
| Attacks | each attack recovers the key on a 320-character English sample with a fixed seed; known-plaintext needs only 4 characters; brute force reports the true key's rank as 1 on long text |
| CLI | encrypt then decrypt via subprocess; attack output contains the recovered plaintext |
| Experiments | a tiny run (2 lengths, 5 trials) completes and writes valid CSVs |
| Replacement demo | round trip works; a tampered ciphertext raises `InvalidTag` |

## 9. Milestones

| # | Milestone | Done when |
|---|---|---|
| M1 | Package and cipher | FR-1–FR-6 done; cipher tests green in CI |
| M2 | Attacks | FR-9–FR-12 done; attack tests green |
| M3 | Experiments | FR-13–FR-17 done; results and chart committed |
| M4 | Replacement and write-up | FR-18–FR-19 done; README complete |
| M5 | Polish | CLI help, `ruff` and `mypy` clean, repo description and topics set |

## 10. README outline

1. What CipherBreak is, in one paragraph (and what it is not: not the WWII Enigma).
2. How the cipher works, with a worked example.
3. **How I broke it:** the three attacks, each in a few sentences, with the key insight (period 4 means four Caesar ciphers).
4. **Results:** the generated table and the chart.
5. **Why it is unsafe:** key space, period, predictable offsets, key handling.
6. **What to use instead:** the AES-GCM example and the rules from FR-19.
7. How to run it: install, test, encrypt, attack, reproduce the experiments.

## 11. Risks

| Risk | Mitigation |
|---|---|
| Brute force is slow in pure Python | Precompute index arrays; vectorise per-column scoring; cap trials (NFR-2) |
| Short ciphertexts fail often | Expected: report it honestly; it is part of the result |
| Corpus licensing | Use a Project Gutenberg public-domain text; record the URL and checksum |
| Overclaiming | The README calls it a classical cipher, never "military-grade" or "Enigma machine" |

## 12. Definition of done

- [ ] CI green: lint, types and tests
- [ ] `results.csv`, `summary.csv` and the chart are committed and reproducible from the seed
- [ ] The README has the generated table, the chart, the "why unsafe" section and the AES-GCM example
- [ ] The repo description reads "Classical shift cipher, then broken three ways with measured attacks"

## 13. Resume bullet templates

Use only after M3, with the bracketed values taken from `summary.csv`.

- Built a classical polyalphabetic shift cipher in Python, then broke it three ways (brute force over 130,321 keys, per-column frequency analysis, known-plaintext), recovering the key from [N] characters of ciphertext in [T] ms
- Measured attack success across 6 ciphertext lengths and [1,200] trials with 95% confidence intervals, and documented why short-period ciphers fail and how to replace them with AES-GCM authenticated encryption
