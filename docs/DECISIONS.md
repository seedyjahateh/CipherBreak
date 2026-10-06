# CipherBreak design decisions

Decisions the PRD ([CB-01](prd/CB-01-cipherbreak.md)) leaves open, settled against the original
`enigma.py` from `seedyjahateh/Enigma-Encryption_-_Decryption`.

## D1. Shift derivation (faithful to the original)

- Key: a 5-digit string `k0 k1 k2 k3 k4`, each 0–9.
- Date offsets: `n = int(f"{day:02}{month:02}{year % 100:02}") ** 2`; offsets are the last 4 decimal
  digits of `n`, `o0..o3`. (`n >= 10100**2`, so it always has at least 4 digits.)
- Shifts: `s_i = k_i + o_i` for `i` in 0..3, so each shift is in 0..18.

## D2. The 5th key digit is NOT used (FR-2)

The original generates it and ignores it. Keeping that preserves the original's behaviour, the period of 4,
and the PRD's key-space math: 19^4 = 130,321 shift tuples (and 10^5 keys collapse onto them: the 5th
digit adds no security at all, which the README points out).

## D3. Alphabet and case (FR-3)

- 27 symbols: `a`–`z` then space, indexes 0–26. Shifts apply modulo 27.
- **Uppercase ASCII letters are lowercased, with a warning** (`CaseFoldWarning`, and a stderr note in the
  CLI). Preserving case was tried first and rejected: an uppercase letter can shift onto space (index 26),
  which has no case, so decryption cannot restore it. The round-trip property test found this
  (`'Q'` with shift 37 decrypts to `'q'`). Any case-preserving scheme over this 27-symbol alphabet has the
  same flaw, so the cipher lowercases, as the original did. Only ASCII `A`–`Z` are folded (not
  `str.lower`, which would map the Kelvin sign `K` to `k`).
- **Characters outside the alphabet pass through unchanged and DO advance the shift position**, exactly as
  the original (`enumerate` over every character). The attacks therefore split columns by raw position
  `i % 4`, skipping pass-through characters when counting.

## D4. Frequency table (FR-12)

`cipherbreak/data/english_freq.json` holds 27 probabilities (a–z, space) measured from a Project
Gutenberg book that is **different** from the experiment corpus (so the scorer is not trained on the test
text). The JSON records the source URL, the SHA-256 of the downloaded file and the normalisation used.
`scripts/build_freq.py` regenerates it.

## D5. Text normalisation for experiments

Corpus text is lowercased, Gutenberg header/footer stripped, every run of non-`a–z` characters collapsed to
one space. Excerpts are therefore pure 27-symbol text, and "length" means alphabet characters.

## D6. Success criterion

An attack succeeds when the recovered shift tuple equals the true shift tuple exactly (mod 27). Plaintext
equality is reported too, but success is judged on shifts.

## D7. Brute force is computed on counts (FR-9, NFR-2)

Decrypting with a shift tuple and counting symbols is the same as rotating each column's symbol counts by
its shift and summing. Brute force scores all 19^4 tuples this way, vectorised with NumPy (already a
dependency of matplotlib, declared explicitly). It is mathematically identical to decrypt-then-score; a
test checks that on random tuples. Brute force searches 0–18 per position (the attacker knows the
algorithm); column analysis searches all 27 shifts per column (108 trials).

## D8. Known-plaintext

- Default: shift `s_i = (c_i - p_i) mod 27` from the first 4 alphabet-positioned characters of a known
  prefix (≥ 4 characters). Candidates tried: 0 search, reported as 4 subtractions.
- Date variant: given the date, derive offsets and search the 10^4 key-digit combinations, checking the
  prefix. Reported separately (`known_date`) in tests and CLI; the experiment's `known` line uses the
  default variant with the first 4 plaintext characters as the known prefix.

## D9. Determinism vs timing (NFR-3 vs FR-15)

`results.csv` contains a `seconds` column (FR-15), and wall-clock time cannot be byte-identical across runs.
Every other column is byte-identical for the same seed; the determinism test compares the CSV with the
`seconds` column removed. Summary success rates and intervals are fully deterministic; timing columns are
machine-dependent and labelled as such.

## D10. Rank of the true key

Brute force reports the true tuple's 1-based rank (1 + number of tuples with a strictly better score).
Column analysis reports `None` for the joint rank. Known-plaintext reports `None`.
