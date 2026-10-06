from __future__ import annotations

import csv
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUN = ROOT / "experiments" / "run.py"


def load_run() -> ModuleType:
    spec = importlib.util.spec_from_file_location("experiments_run", RUN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["experiments_run"] = module
    spec.loader.exec_module(module)
    return module


run = load_run()


def tiny_run(out: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(RUN),
            "--lengths",
            "10,40",
            "--trials",
            "5",
            "--out-dir",
            str(out),
            *list(extra),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def read(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def test_tiny_run_writes_valid_outputs(tmp_path: Path) -> None:
    proc = tiny_run(tmp_path)
    assert proc.returncode == 0, proc.stderr
    results = read(tmp_path / "results.csv")
    assert list(results[0]) == run.RESULT_FIELDS
    assert len(results) == 2 * 5 * 3
    for r in results:
        assert r["length"] in {"10", "40"}
        assert r["method"] in {"brute", "columns", "known"}
        assert r["success"] in {"0", "1"}
        assert float(r["seconds"]) >= 0
        assert len(r["true_shifts"].split()) == 4
        if r["method"] == "brute":
            assert r["candidates"] == "130321" and int(r["rank"]) >= 1
        elif r["method"] == "columns":
            assert r["candidates"] == "108" and r["rank"] == ""
        else:
            assert r["success"] == "1"  # 4 known characters always suffice

    summary = read(tmp_path / "summary.csv")
    assert list(summary[0]) == run.SUMMARY_FIELDS
    assert len(summary) == 6
    for s in summary:
        assert s["trials"] == "5"
        lo, rate, hi = float(s["ci95_low"]), float(s["success_rate"]), float(s["ci95_high"])
        assert 0 <= lo <= rate <= hi <= 1
        assert float(s["median_ms"]) <= float(s["p95_ms"])

    png = (tmp_path / "success_by_length.png").read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert b"\r\n" not in (tmp_path / "results.csv").read_bytes()


def test_same_seed_is_identical_apart_from_timing(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    assert tiny_run(a, "--no-chart").returncode == 0
    assert tiny_run(b, "--no-chart").returncode == 0
    cmp = subprocess.run(
        [sys.executable, str(RUN), "--compare", str(a / "results.csv"), str(b / "results.csv")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cmp.returncode == 0, cmp.stderr

    def no_seconds(p: Path) -> list[list[str]]:
        rows = list(csv.reader(p.read_text(encoding="utf-8").splitlines()))
        i = rows[0].index("seconds")
        return [r[:i] + r[i + 1 :] for r in rows]

    assert no_seconds(a / "results.csv") == no_seconds(b / "results.csv")


def test_different_seed_differs(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    assert tiny_run(a, "--no-chart").returncode == 0
    assert tiny_run(b, "--no-chart", "--seed", "1").returncode == 0
    cmp = subprocess.run(
        [sys.executable, str(RUN), "--compare", str(a / "results.csv"), str(b / "results.csv")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cmp.returncode == 1


def test_brute_trials_cap_keeps_the_same_excerpts(tmp_path: Path) -> None:
    proc = tiny_run(tmp_path, "--no-chart", "--brute-trials", "2")
    assert proc.returncode == 0, proc.stderr
    rows = read(tmp_path / "results.csv")
    assert sum(r["method"] == "brute" for r in rows) == 2 * 2
    assert sum(r["method"] == "columns" for r in rows) == 2 * 5


def test_corpus_checksum_matches() -> None:
    assert run.sha256_file(run.CORPUS) == run.CORPUS_SHA256
    readme = (ROOT / "experiments" / "corpus" / "README.md").read_text(encoding="utf-8")
    assert run.CORPUS_SHA256 in readme


def test_plan_is_deterministic_and_in_range() -> None:
    a = run.plan_trials(1000, [10, 320], 50, seed=7)
    b = run.plan_trials(1000, [10, 320], 50, seed=7)
    assert a == b
    assert all(0 <= t.start <= 1000 - t.length for t in a)
    assert all(t.on.year in range(2000, 2100) for t in a)
    with pytest.raises(ValueError):
        run.plan_trials(5, [10], 1, seed=0)


@pytest.mark.parametrize(
    ("k", "n", "lo", "hi"),
    [(0, 10, 0.0, 0.2775), (5, 10, 0.2366, 0.7634), (10, 10, 0.7225, 1.0), (200, 200, 0.9812, 1.0)],
)
def test_wilson_interval(k: int, n: int, lo: float, hi: float) -> None:
    got = run.wilson_interval(k, n)
    assert got[0] == pytest.approx(lo, abs=1e-4)
    assert got[1] == pytest.approx(hi, abs=1e-4)


def test_percentile_matches_linear_interpolation() -> None:
    assert run.percentile([1, 2, 3, 4], 50) == 2.5
    assert run.percentile([10.0], 95) == 10.0
    assert run.percentile(list(range(101)), 95) == 95
