"""Regenerate cipherbreak/data/english_freq.json from a Project Gutenberg book (FR-12, D4).

The reference book is deliberately different from the experiment corpus, so the scorer is not
fitted to the text it is tested on.

    python scripts/build_freq.py            # downloads the book to a temp dir
    python scripts/build_freq.py --file pg2701.txt
"""

from __future__ import annotations

import argparse
import json
import tempfile
import urllib.request
from collections import Counter
from pathlib import Path

from cipherbreak.alphabet import ALPHABET
from cipherbreak.corpus import load_normalized, sha256_file

SOURCE_URL = "https://www.gutenberg.org/cache/epub/2701/pg2701.txt"
SOURCE_TITLE = "Moby-Dick; or, The Whale, by Herman Melville (Project Gutenberg eBook #2701)"
OUT = Path(__file__).resolve().parent.parent / "cipherbreak" / "data" / "english_freq.json"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--file", type=Path, help="use an already downloaded copy")
    args = parser.parse_args()

    if args.file is not None:
        path: Path = args.file
    else:
        path = Path(tempfile.mkdtemp()) / "pg2701.txt"
        urllib.request.urlretrieve(SOURCE_URL, path)

    text = load_normalized(path)
    counts = Counter(text)
    total = sum(counts[ch] for ch in ALPHABET)
    data = {
        "source_title": SOURCE_TITLE,
        "source_url": SOURCE_URL,
        "source_sha256": sha256_file(path),
        "normalisation": (
            "Gutenberg header and footer stripped; lowercased; every run of characters outside "
            "a-z collapsed to one space (cipherbreak.alphabet.normalize)"
        ),
        "total_symbols": total,
        "symbols": ALPHABET,
        "counts": {("space" if ch == " " else ch): counts[ch] for ch in ALPHABET},
        "frequencies": {
            ("space" if ch == " " else ch): round(counts[ch] / total, 8) for ch in ALPHABET
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT} from {total:,} symbols (sha256 {data['source_sha256']})")


if __name__ == "__main__":
    main()
