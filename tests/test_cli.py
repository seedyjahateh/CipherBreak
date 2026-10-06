from __future__ import annotations

import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from cipherbreak.cipher import Cipher
from cipherbreak.cli import main
from tests.conftest import SAMPLE_320


def run_cli(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "cipherbreak", *args],
        capture_output=True,
        text=True,
        input=stdin,
        encoding="utf-8",
        check=False,
    )


def test_encrypt_then_decrypt_subprocess() -> None:
    text = "meet me at the old mill at nine, bring the map."
    enc = run_cli("encrypt", "--key", "12345", "--date", "2026-10-06", text)
    assert enc.returncode == 0, enc.stderr
    assert enc.stderr == ""
    ct = enc.stdout.rstrip("\n")
    assert ct != text
    dec = run_cli("decrypt", "--key", "12345", "--date", "2026-10-06", ct)
    assert dec.returncode == 0, dec.stderr
    assert dec.stdout.rstrip("\n") == text


def test_uppercase_warns_on_stderr() -> None:
    enc = run_cli("encrypt", "--key", "12345", "--date", "2026-10-06", "Hello World")
    assert enc.stdout == "kmvvrhfyutn\n"
    assert "folded to lowercase" in enc.stderr


def test_encrypt_vector_and_no_key_leak() -> None:
    enc = run_cli("encrypt", "--key", "12345", "--date", "2026-10-06", "hello world")
    assert enc.stdout == "kmvvrhfyutn\n"
    assert "12345" not in enc.stdout + enc.stderr
    assert "shifts" not in enc.stdout + enc.stderr


def test_show_shifts_goes_to_stderr_only_when_asked() -> None:
    enc = run_cli("encrypt", "--key", "12345", "--date", "2026-10-06", "--show-shifts", "hi")
    assert "[3, 8, 10, 10]" in enc.stderr
    assert "[3, 8, 10, 10]" not in enc.stdout


def test_stdin_input() -> None:
    enc = run_cli("encrypt", "--key", "12345", "--date", "2026-10-06", "-", stdin="hello world")
    assert enc.stdout == "kmvvrhfyutn"


def test_bad_key_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["encrypt", "--key", "12", "--date", "2026-10-06", "x"]) == 2
    assert "5 decimal digits" in capsys.readouterr().err


CT_DATE = "2026-10-06"


def _encrypt_to_file(tmp_path: Path, text: str) -> Path:
    f = tmp_path / "ct.txt"
    f.write_text(Cipher("12345", date(2026, 10, 6)).encrypt(text), encoding="utf-8")
    return f


@pytest.mark.parametrize("method", ["brute", "columns"])
def test_ciphertext_only_attack_output(tmp_path: Path, method: str) -> None:
    f = _encrypt_to_file(tmp_path, SAMPLE_320)
    out = run_cli("attack", "--method", method, "--ciphertext", str(f))
    assert out.returncode == 0, out.stderr
    assert SAMPLE_320 in out.stdout
    assert "shifts: [3, 8, 10, 10]" in out.stdout
    assert "time:" in out.stdout and "ms" in out.stdout


def test_known_attack_output(tmp_path: Path) -> None:
    f = _encrypt_to_file(tmp_path, SAMPLE_320)
    out = run_cli("attack", "--method", "known", "--ciphertext", str(f), "--known-prefix", "four")
    assert out.returncode == 0, out.stderr
    assert SAMPLE_320 in out.stdout
    assert "candidates tried: 4" in out.stdout


def test_known_attack_with_date_output(tmp_path: Path) -> None:
    f = _encrypt_to_file(tmp_path, SAMPLE_320)
    out = run_cli(
        "attack", "--method", "known", "--ciphertext", str(f),
        "--known-prefix", "four", "--date", CT_DATE,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    assert "(with date)" in out.stdout
    assert "candidates tried: 1,235" in out.stdout
    assert SAMPLE_320 in out.stdout


def test_attack_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = _encrypt_to_file(tmp_path, "hello world")
    assert main(["attack", "--method", "known", "--ciphertext", str(f)]) == 2
    assert "--known-prefix" in capsys.readouterr().err
    assert main(["attack", "--method", "brute", "--ciphertext", str(f), "--date", CT_DATE]) == 2
    capsys.readouterr()
    assert (
        main(["attack", "--method", "known", "--ciphertext", str(f), "--known-prefix", "he"]) == 1
    )
    assert "column" in capsys.readouterr().err
    assert main(["attack", "--method", "columns", "--ciphertext", str(tmp_path / "nope")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_bad_date_rejected() -> None:
    with pytest.raises(SystemExit):
        main(["encrypt", "--key", "12345", "--date", "06/10/2026", "x"])
