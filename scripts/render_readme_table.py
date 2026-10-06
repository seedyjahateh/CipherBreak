"""Generate the README results block from experiments/summary.csv (FR-17).

    python scripts/render_readme_table.py          # rewrite the block in README.md
    python scripts/render_readme_table.py --check  # exit 1 if README.md is out of date

The block sits between ``<!-- results:start -->`` and ``<!-- results:end -->``. Nothing inside it
is typed by hand.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
SUMMARY = ROOT / "experiments" / "summary.csv"
START = "<!-- results:start -->"
END = "<!-- results:end -->"
METHODS = {
    "brute": "Brute force",
    "columns": "Column analysis",
    "known": "Known plaintext",
}


def _pct(x: str) -> str:
    return f"{float(x) * 100:.1f}%"


def _ms(x: str) -> str:
    v = float(x)
    return f"{v:.0f} ms" if v >= 100 else f"{v:.2f} ms" if v >= 1 else f"{v * 1000:.0f} µs"


def render(rows: list[dict[str, str]]) -> str:
    lengths = sorted({int(r["length"]) for r in rows})
    methods = [m for m in METHODS if any(r["method"] == m for r in rows)]
    by = {(int(r["length"]), r["method"]): r for r in rows}
    trials = {m: sorted({by[(n, m)]["trials"] for n in lengths if (n, m) in by}) for m in methods}

    out = [
        "Key recovered, by ciphertext length (success rate, 95% Wilson interval in brackets):",
        "",
        "| Length | " + " | ".join(METHODS[m] for m in methods) + " |",
        "|---:|" + "---:|" * len(methods),
    ]
    for n in lengths:
        cells = []
        for m in methods:
            r = by.get((n, m))
            cells.append(
                "n/a"
                if r is None
                else f"{_pct(r['success_rate'])} [{_pct(r['ci95_low'])}, {_pct(r['ci95_high'])}]"
            )
        out.append(f"| {n} | " + " | ".join(cells) + " |")
    out.append("| Trials per length | " + " | ".join("/".join(trials[m]) for m in methods) + " |")
    out += [
        "",
        "Time per attack (median / p95, measured on one laptop; machine-dependent):",
        "",
        "| Length | " + " | ".join(METHODS[m] for m in methods) + " |",
        "|---:|" + "---:|" * len(methods),
    ]
    for n in lengths:
        cells = []
        for m in methods:
            r = by.get((n, m))
            cells.append("n/a" if r is None else f"{_ms(r['median_ms'])} / {_ms(r['p95_ms'])}")
        out.append(f"| {n} | " + " | ".join(cells) + " |")

    out += ["", "Headlines:", ""]
    for m in methods:
        reliable = [n for n in lengths if (n, m) in by and float(by[(n, m)]["ci95_low"]) >= 0.9]
        if reliable:
            n = reliable[0]
            r = by[(n, m)]
            out.append(
                f"- **{METHODS[m]}** first recovers the key in at least 90% of trials (lower 95% "
                f"bound) at **{n} characters**: {r['successes']}/{r['trials']} trials, median "
                f"{_ms(r['median_ms'])}."
            )
        else:
            out.append(f"- **{METHODS[m]}** never reaches a 90% lower bound in this experiment.")
    return "\n".join(out)


def splice(readme: str, block: str) -> str:
    try:
        head, rest = readme.split(START, 1)
        _, tail = rest.split(END, 1)
    except ValueError:
        raise SystemExit(f"README.md must contain {START} and {END}") from None
    return f"{head}{START}\n{block}\n{END}{tail}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if README.md is out of date")
    args = parser.parse_args()

    with SUMMARY.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    current = README.read_text(encoding="utf-8")
    updated = splice(current, render(rows))
    if args.check:
        if updated != current:
            print("README.md results block is out of date: run this script", file=sys.stderr)
            return 1
        print("README.md results block matches summary.csv")
        return 0
    README.write_text(updated, encoding="utf-8", newline="\n")
    print("README.md results block updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
