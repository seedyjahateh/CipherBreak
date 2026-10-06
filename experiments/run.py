"""Measure how often each attack recovers the key, by ciphertext length (FR-13 to FR-16).

    python experiments/run.py                       # full run: 6 lengths x 200 trials
    python experiments/run.py --lengths 10,20 --trials 5 --out-dir /tmp/cb
    python experiments/run.py --compare a.csv b.csv # compare two results.csv, ignoring seconds

Design (paired): for every trial a random excerpt of the corpus, a random key and a random date are
drawn from one master seed, and all three attacks run on the same ciphertext. Trial parameters are
drawn before any attack runs, so capping brute-force trials never changes the excerpts.

Outputs in --out-dir: results.csv (one row per trial and method), summary.csv (per length and
method: success rate with a 95% Wilson interval, median and p95 time) and success_by_length.png.
Every column except ``seconds`` (and the timing columns derived from it) is byte-identical for the
same seed (docs/DECISIONS.md D9).
"""

from __future__ import annotations

import argparse
import csv
import io
import math
import random
import statistics
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

from cipherbreak.attacks import AttackResult, brute_force, column_analysis, known_plaintext
from cipherbreak.cipher import Cipher, keygen
from cipherbreak.corpus import load_normalized, sha256_file

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus" / "pg1342.txt"
CORPUS_SHA256 = "3f6bb9d6f78e0293b56acd4714dd68cb7d6d1d293402031ce9d5a216bcaf9d75"
DEFAULT_SEED = 20261006
DEFAULT_LENGTHS = (10, 20, 40, 80, 160, 320)
DEFAULT_TRIALS = 200
KNOWN_PREFIX_LENGTH = 4
METHODS = ("brute", "columns", "known")
FIRST_DATE = date(2000, 1, 1)
DATE_SPAN_DAYS = (date(2099, 12, 31) - FIRST_DATE).days + 1
Z_95 = 1.959963984540054

RESULT_FIELDS = [
    "trial",
    "length",
    "method",
    "success",
    "plaintext_match",
    "seconds",
    "candidates",
    "rank",
    "excerpt_start",
    "true_shifts",
    "recovered_shifts",
]
SUMMARY_FIELDS = [
    "length",
    "method",
    "trials",
    "successes",
    "success_rate",
    "ci95_low",
    "ci95_high",
    "median_ms",
    "p95_ms",
]


@dataclass(frozen=True)
class Trial:
    index: int
    length: int
    start: int
    key: str
    on: date


def plan_trials(text_length: int, lengths: Sequence[int], trials: int, seed: int) -> list[Trial]:
    """Draw every trial's excerpt position, key and date from the master seed."""
    rng = random.Random(seed)
    plan: list[Trial] = []
    for length in lengths:
        if length > text_length:
            raise ValueError(f"length {length} exceeds the corpus length {text_length}")
        for i in range(trials):
            start = rng.randrange(text_length - length + 1)
            key = keygen(rng)
            on = FIRST_DATE + timedelta(days=rng.randrange(DATE_SPAN_DAYS))
            plan.append(Trial(i, length, start, key, on))
    return plan


def wilson_interval(successes: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def percentile(values: Sequence[float], q: float) -> float:
    """Linear-interpolation percentile (the same as NumPy's default), ``q`` in [0, 100]."""
    if not values:
        return math.nan
    s = sorted(values)
    pos = (len(s) - 1) * q / 100
    lo = math.floor(pos)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def _fmt_shifts(shifts: Iterable[int]) -> str:
    return " ".join(str(s) for s in shifts)


def run_trials(
    text: str, plan: Sequence[Trial], brute_trials: int, progress: bool = True
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    attacks: dict[str, Callable[[str, Cipher, str], AttackResult]] = {
        "brute": lambda ct, c, _pt: brute_force(ct, true_shifts=c.shifts()),
        "columns": lambda ct, _c, _pt: column_analysis(ct),
        "known": lambda ct, _c, pt: known_plaintext(ct, pt[:KNOWN_PREFIX_LENGTH]),
    }
    for n, t in enumerate(plan, start=1):
        plaintext = text[t.start : t.start + t.length]
        cipher = Cipher(t.key, t.on)
        ciphertext = cipher.encrypt(plaintext)
        for method in METHODS:
            if method == "brute" and t.index >= brute_trials:
                continue
            r = attacks[method](ciphertext, cipher, plaintext)
            rows.append(
                {
                    "trial": str(t.index),
                    "length": str(t.length),
                    "method": method,
                    "success": str(int(r.shifts == cipher.shifts())),
                    "plaintext_match": str(int(r.plaintext == plaintext)),
                    "seconds": f"{r.seconds:.6f}",
                    "candidates": str(r.candidates_tried),
                    "rank": "" if r.rank_of_true_key is None else str(r.rank_of_true_key),
                    "excerpt_start": str(t.start),
                    "true_shifts": _fmt_shifts(cipher.shifts()),
                    "recovered_shifts": _fmt_shifts(r.shifts),
                }
            )
        if progress and (n % 100 == 0 or n == len(plan)):
            print(f"  {n}/{len(plan)} trials", file=sys.stderr, flush=True)
    return rows


def summarise(rows: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    groups: dict[tuple[int, str], list[dict[str, str]]] = {}
    for row in rows:
        groups.setdefault((int(row["length"]), row["method"]), []).append(row)
    out: list[dict[str, str]] = []
    for (length, method), group in sorted(
        groups.items(), key=lambda kv: (kv[0][0], METHODS.index(kv[0][1]))
    ):
        n = len(group)
        k = sum(int(r["success"]) for r in group)
        lo, hi = wilson_interval(k, n)
        ms = [float(r["seconds"]) * 1000 for r in group]
        out.append(
            {
                "length": str(length),
                "method": method,
                "trials": str(n),
                "successes": str(k),
                "success_rate": f"{k / n:.4f}",
                "ci95_low": f"{lo:.4f}",
                "ci95_high": f"{hi:.4f}",
                "median_ms": f"{statistics.median(ms):.3f}",
                "p95_ms": f"{percentile(ms, 95):.3f}",
            }
        )
    return out


def write_csv(path: Path, fields: Sequence[str], rows: Iterable[dict[str, str]]) -> None:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    path.write_text(buf.getvalue(), encoding="utf-8", newline="\n")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def plot(summary: Sequence[dict[str, str]], path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = {
        "brute": "Brute force (130,321 tuples)",
        "columns": "Column frequency analysis (108 trials)",
        "known": f"Known plaintext ({KNOWN_PREFIX_LENGTH}-char prefix)",
    }
    styles = {"brute": ("#2563eb", "o"), "columns": ("#dc2626", "s"), "known": ("#16a34a", "^")}
    fig, ax = plt.subplots(figsize=(8, 5), dpi=120)
    for method in METHODS:
        rows = [r for r in summary if r["method"] == method]
        if not rows:
            continue
        x = [int(r["length"]) for r in rows]
        y = [float(r["success_rate"]) * 100 for r in rows]
        err_lo = [y_i - float(r["ci95_low"]) * 100 for y_i, r in zip(y, rows, strict=True)]
        err_hi = [float(r["ci95_high"]) * 100 - y_i for y_i, r in zip(y, rows, strict=True)]
        n = rows[0]["trials"]
        colour, marker = styles[method]
        ax.errorbar(
            x,
            y,
            yerr=[err_lo, err_hi],
            label=f"{labels[method]}, n={n}/length",
            color=colour,
            marker=marker,
            capsize=4,
            linewidth=1.8,
        )
    ax.set_xscale("log", base=2)
    lengths = sorted({int(r["length"]) for r in summary})
    ax.set_xticks(lengths, [str(v) for v in lengths])
    ax.set_ylim(-3, 103)
    ax.set_xlabel("Ciphertext length (characters)")
    ax.set_ylabel("Key recovered (%)")
    ax.set_title("CipherBreak: attack success by ciphertext length (95% Wilson intervals)")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(path, metadata={"Software": None})
    plt.close(fig)


def compare(a: Path, b: Path) -> int:
    """Compare two results.csv files on every column except ``seconds``."""

    def strip(rows: list[dict[str, str]]) -> list[dict[str, str]]:
        return [{k: v for k, v in r.items() if k != "seconds"} for r in rows]

    ra, rb = strip(read_csv(a)), strip(read_csv(b))
    if ra == rb:
        print(f"identical apart from timing: {len(ra)} rows")
        return 0
    diffs = sum(x != y for x, y in zip(ra, rb, strict=False)) + abs(len(ra) - len(rb))
    print(f"MISMATCH: {diffs} differing rows ({len(ra)} vs {len(rb)})", file=sys.stderr)
    return 1


def _int_list(value: str) -> list[int]:
    return [int(v) for v in value.split(",") if v.strip()]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the CipherBreak attack experiments.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--lengths", type=_int_list, default=list(DEFAULT_LENGTHS))
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    parser.add_argument(
        "--brute-trials",
        type=int,
        default=None,
        help="cap brute-force trials per length (default: same as --trials)",
    )
    parser.add_argument("--out-dir", type=Path, default=HERE)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--no-chart", action="store_true")
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("A", "B"))
    args = parser.parse_args(argv)

    if args.compare:
        return compare(*args.compare)

    digest = sha256_file(args.corpus)
    if args.corpus == CORPUS and digest != CORPUS_SHA256:
        print(f"error: corpus checksum mismatch: {digest}", file=sys.stderr)
        return 2
    text = load_normalized(args.corpus)
    brute_trials = args.trials if args.brute_trials is None else args.brute_trials
    plan = plan_trials(len(text), args.lengths, args.trials, args.seed)
    print(
        f"corpus {args.corpus.name}: {len(text):,} symbols, sha256 {digest[:12]}...; "
        f"seed {args.seed}; lengths {args.lengths}; {args.trials} trials "
        f"({brute_trials} brute force) per length",
        file=sys.stderr,
    )

    rows = run_trials(text, plan, brute_trials)
    summary = summarise(rows)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.out_dir / "results.csv", RESULT_FIELDS, rows)
    write_csv(args.out_dir / "summary.csv", SUMMARY_FIELDS, summary)
    if not args.no_chart:
        plot(summary, args.out_dir / "success_by_length.png")

    for r in summary:
        print(
            f"{r['length']:>4} {r['method']:<8} {float(r['success_rate']) * 100:6.1f}% "
            f"[{float(r['ci95_low']) * 100:5.1f}, {float(r['ci95_high']) * 100:5.1f}]  "
            f"median {float(r['median_ms']):8.3f} ms  p95 {float(r['p95_ms']):8.3f} ms"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
