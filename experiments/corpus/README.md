# Experiment corpus

| | |
|---|---|
| Book | *Pride and Prejudice*, by Jane Austen (Project Gutenberg eBook #1342) |
| Source URL | https://www.gutenberg.org/cache/epub/1342/pg1342.txt |
| File | `pg1342.txt` (772,386 bytes, CRLF line endings, stored byte-for-byte: see `.gitattributes`) |
| SHA-256 | `3f6bb9d6f78e0293b56acd4714dd68cb7d6d1d293402031ce9d5a216bcaf9d75` |
| Downloaded | 2026-10-06 |
| Licence | Public domain in the USA; distributed under the Project Gutenberg License included in the file |

`experiments/run.py` checks the SHA-256 before every run and refuses to continue if it differs.

Normalisation (docs/DECISIONS.md D5): the Gutenberg header and footer are stripped, the text is
lowercased, and every run of characters outside `a`–`z` becomes one space. That leaves 692,488
symbols of the 27-symbol alphabet.

The scoring frequencies come from a different book (*Moby-Dick*, eBook #2701; see
`cipherbreak/data/english_freq.json`), so the scorer is never fitted to the text it is tested on.

No personal or private text is used, ever (FR-13).
