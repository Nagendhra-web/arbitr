"""Agents cannot operate Arbitr itself or touch its ledger, key, policy or config."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from arbitr.core.errors import ActionDenied
from arbitr.core.spec import ToolSpec
from arbitr.executor import Ledger
from arbitr.policy.schema import load_policy

if TYPE_CHECKING:
    from pathlib import Path

KEY = b"self-protection!" * 2
SHADOW = load_policy("version: 1\nmode: shadow\ndefault: { write: allow, destructive: allow }\n")
SHELL = ToolSpec(name="shell.run", effect="write")
FILES = ToolSpec(name="fs.read", effect="read")


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    arbitr_dir = tmp_path / ".arbitr"
    arbitr_dir.mkdir()
    (arbitr_dir / "key").write_text("00" * 32, encoding="utf-8")
    protected = (arbitr_dir / "key", tmp_path / "policy.yaml", tmp_path / "arbitr.yaml")
    return Ledger.open(arbitr_dir / "ledger.db", SHADOW, key=KEY, protected_paths=protected)


@pytest.mark.parametrize(
    "command",
    [
        "arbitr approvals approve 01ABC --as bob",
        "ARBITR_APPROVER=x arbitr approvals approve 01ABC",
        "cd /tmp && arbitr.exe config check",
        "python -m arbitr.cli policy lint p.yaml",
        "sh -c 'arbitr init --force'",
        "cat .arbitr/key",
        "rm -rf ./.arbitr",
    ],
)
def test_agent_commands_aimed_at_arbitr_are_denied_even_in_shadow_mode(
    ledger: Ledger, command: str
) -> None:
    calls: list[str] = []
    with ledger, ledger.run("alice", "bot"), pytest.raises(ActionDenied) as err:
        ledger.execute(SHELL, {"command": command}, calls.append)
    assert err.value.rule_id == "arbitr-self-protection"
    assert calls == []


def test_protected_files_cannot_be_read_by_a_tool(ledger: Ledger, tmp_path: Path) -> None:
    for path in (tmp_path / "policy.yaml", tmp_path / "arbitr.yaml", tmp_path / ".arbitr" / "key",
                 tmp_path / ".arbitr" / "ledger.db"):  # fmt: skip
        with ledger.run("alice", "bot"), pytest.raises(ActionDenied):
            ledger.execute(FILES, {"path": str(path)}, lambda path: "contents")
    ledger.close()


def test_ordinary_commands_still_run(ledger: Ledger) -> None:
    with ledger, ledger.run("alice", "bot"):
        for command in ("ls -la", "echo arbitrary text", "grep -r arbitration docs"):
            assert ledger.execute(SHELL, {"command": command}, lambda command: "ok") == "ok"


@pytest.mark.parametrize(
    "command",
    [
        '"arbitr" approvals approve 01ABC',
        "ar''bitr approvals approve 01ABC",
        "/usr/local/bin/arbitr-script.py approvals ls",
        "C:\\tools\\arbitr.cmd verify",
        "env X=1 arbitr",
    ],
)
def test_quoting_and_paths_do_not_hide_the_cli(ledger: Ledger, command: str) -> None:
    with ledger, ledger.run("alice", "bot"), pytest.raises(ActionDenied):
        ledger.execute(SHELL, {"command": command}, lambda command: None)
