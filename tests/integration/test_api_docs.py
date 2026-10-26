"""The examples in the public API design doc are complete programs that run."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "docs" / "design" / "api.md"
BLOCKS = re.findall(r"^```python\n(.*?)^```", PAGE.read_text(encoding="utf-8"), re.S | re.M)


def test_the_page_has_three_examples() -> None:
    assert len(BLOCKS) == 3


@pytest.mark.parametrize("number", range(len(BLOCKS)))
def test_example_runs(number: int, tmp_path: Path) -> None:
    script = tmp_path / f"example_{number}.py"
    script.write_text(BLOCKS[number], encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")}
    done = subprocess.run(
        [sys.executable, str(script)], cwd=tmp_path, env=env,
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stdout + done.stderr
