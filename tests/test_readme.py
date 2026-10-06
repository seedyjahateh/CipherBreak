from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_readme_results_block_is_generated_from_summary() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "render_readme_table.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_readme_does_not_overclaim() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    assert "military-grade" not in text
    assert "not** a model of the wwii enigma machine" in text
