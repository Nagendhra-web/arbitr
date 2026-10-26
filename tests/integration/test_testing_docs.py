"""Every code block on the testing kit's docs page is a test file that passes."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "docs" / "testing.md"
BLOCK = re.compile(r"^```python\n(.*?)^```", re.DOTALL | re.MULTILINE)


def test_the_docs_examples_run_as_tests(tmp_path: Path) -> None:
    blocks = BLOCK.findall(PAGE.read_text(encoding="utf-8"))
    assert len(blocks) >= 2
    for number, code in enumerate(blocks, 1):
        (tmp_path / f"test_docs_block_{number}.py").write_text(code, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")  # no repo settings

    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tmp_path)],
        cwd=tmp_path, env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        capture_output=True, text=True, timeout=180, check=False,
    )  # fmt: skip

    assert done.returncode == 0, done.stdout + done.stderr
    tests = sum(len(re.findall(r"^def test_", code, re.MULTILINE)) for code in blocks)
    assert f"{tests} passed" in done.stdout
