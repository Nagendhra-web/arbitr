"""Every example runs in scripted mode, offline, and tells the same story."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"
SCRIPTS = sorted(p.name for p in EXAMPLES.glob("*.py") if not p.name.startswith("_"))


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        env.pop(name, None)  # scripted mode must never need a key
    return subprocess.run(
        [sys.executable, *args], cwd=cwd, env=env, capture_output=True, text=True,
        timeout=180, check=False,
    )  # fmt: skip


def test_there_is_an_example_per_integration() -> None:
    assert SCRIPTS == [
        "anthropic_tool_runner.py",
        "guard_decorator.py",
        "langgraph_tool_node.py",
        "openai_agents_runner.py",
    ]


@pytest.mark.parametrize("script", SCRIPTS)
def test_example_runs_in_scripted_mode(script: str) -> None:
    done = run([str(EXAMPLES / script)], cwd=ROOT)
    assert done.returncode == 0, done.stderr
    out = done.stdout
    assert out.count("refunded re_000001") == 2 or out.count("'refund_id': 're_000001'") == 2
    assert "Blocked by policy 'no-destructive-sql'" in out
    assert "needs human approval" in out
    assert "refunds made: 1" in out
    assert "audit chain ok: True" in out


def test_the_testing_kit_example_suite_passes() -> None:
    done = run(["-m", "pytest", "-q", "-p", "no:cacheprovider", "."], cwd=EXAMPLES / "testing_kit")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "4 passed" in done.stdout
