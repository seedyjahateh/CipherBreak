from __future__ import annotations

import subprocess
import sys

import pytest

from cipherbreak.cli import main


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


def test_bad_date_rejected() -> None:
    with pytest.raises(SystemExit):
        main(["encrypt", "--key", "12345", "--date", "06/10/2026", "x"])
