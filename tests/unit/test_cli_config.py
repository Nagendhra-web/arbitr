"""Tests for ``arbitr init`` and ``arbitr config check``."""

from __future__ import annotations

import base64
import json
import os
import sys
from typing import TYPE_CHECKING, Any

import pytest
from typer.testing import CliRunner

from arbitr.cli import main as cli_main

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ARBITR_CONFIG",
        "ARBITR_LEDGER",
        "ARBITR_POLICY",
        "ARBITR_KEY_FILE",
        "ARBITR_LEDGER_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def invoke(*args: str) -> Any:
    return CliRunner().invoke(cli_main._build_app(), list(args))


def init(folder: Path, *extra: str) -> Any:
    return invoke("init", "--dir", str(folder), *extra)


def key_forms(folder: Path) -> list[str]:
    """Every way the key could show up in output."""
    text = (folder / ".arbitr" / "key").read_text(encoding="ascii").strip()
    raw = bytes.fromhex(text)
    return [text, text.upper(), repr(raw), base64.b64encode(raw).decode(), raw.hex(" ")]


def test_help_lists_the_new_commands() -> None:
    output = invoke("--help").output
    assert "init" in output
    assert "config" in output
    assert "check" in invoke("config", "--help").output


def test_init_text(tmp_path: Path) -> None:
    result = init(tmp_path, "--packs", "databases, git")
    assert result.exit_code == 0, result.output
    assert "Created arbitr.yaml, policy.yaml and a new ledger key" in result.output
    assert "No .gitignore here" in result.output
    assert "Next: arbitr config check" in result.output
    assert (tmp_path / ".arbitr" / "ledger.db").is_file()
    assert "include: [databases, git]" in (tmp_path / "policy.yaml").read_text(encoding="utf-8")


def test_init_json(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("dist/\n", encoding="utf-8")
    result = init(tmp_path, "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["gitignore"] == "added"
    assert payload["packs"] == []
    assert payload["ledger_created"] is True
    assert payload["key_file"] == str(tmp_path / ".arbitr" / "key")
    assert set(payload) == {
        "ok",
        "folder",
        "config",
        "policy",
        "key_file",
        "ledger",
        "ledger_created",
        "packs",
        "gitignore",
    }


def test_init_says_it_updated_the_gitignore(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("dist/\n", encoding="utf-8")
    result = init(tmp_path)
    assert result.exit_code == 0
    assert "Added .arbitr/ to .gitignore." in result.output


def test_init_reports_a_gitignore_that_already_covers_the_folder(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".arbitr/\n", encoding="utf-8")
    result = init(tmp_path)
    assert result.exit_code == 0
    assert ".gitignore" not in result.output


def test_init_refuses_to_overwrite(tmp_path: Path) -> None:
    assert init(tmp_path).exit_code == 0
    again = init(tmp_path)
    assert again.exit_code == 1
    assert "error:" in again.output
    assert "--force" in again.output
    as_json = json.loads(init(tmp_path, "--json").output)
    assert as_json["ok"] is False
    assert "already exist" in as_json["error"]


def test_init_force_replaces_and_keeps_the_ledger(tmp_path: Path) -> None:
    assert init(tmp_path).exit_code == 0
    result = init(tmp_path, "--force")
    assert result.exit_code == 0, result.output
    assert "kept the existing one" in result.output


def test_init_refuses_an_unknown_pack(tmp_path: Path) -> None:
    result = init(tmp_path, "--packs", "nope")
    assert result.exit_code == 1
    assert "unknown pack 'nope'" in result.output


def test_config_check_passes_after_init(tmp_path: Path) -> None:
    assert init(tmp_path).exit_code == 0
    config = str(tmp_path / "arbitr.yaml")
    result = invoke("config", "check", "--config", config)
    assert result.exit_code == 0, result.output
    assert f"Configuration OK: {config}" in result.output
    assert "audit chain verifies" in result.output
    payload = json.loads(invoke("config", "check", "--config", config, "--json").output)
    assert payload == {
        "ok": True,
        "config": config,
        "ledger": str(tmp_path / ".arbitr" / "ledger.db"),
        "policy": str(tmp_path / "policy.yaml"),
        "problems": [],
    }


def test_config_check_uses_arbitr_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert init(tmp_path).exit_code == 0
    monkeypatch.setenv("ARBITR_CONFIG", str(tmp_path / "arbitr.yaml"))
    assert invoke("config", "check").exit_code == 0


def test_config_check_lists_problems(tmp_path: Path) -> None:
    assert init(tmp_path).exit_code == 0
    (tmp_path / "policy.yaml").write_text("version: 1\nmode: loud\n", encoding="utf-8")
    (tmp_path / ".arbitr" / "key").unlink()
    config = str(tmp_path / "arbitr.yaml")
    result = invoke("config", "check", "--config", config)
    assert result.exit_code == 1
    assert f"Problems in {config}:" in result.output
    assert result.output.count("\n- ") == 2
    payload = json.loads(invoke("config", "check", "--config", config, "--json").output)
    assert payload["ok"] is False
    assert len(payload["problems"]) == 2


def test_config_check_reports_a_missing_file(tmp_path: Path) -> None:
    missing = str(tmp_path / "absent.yaml")
    result = invoke("config", "check", "--config", missing)
    assert result.exit_code == 1
    assert "does not exist" in result.output
    payload = json.loads(invoke("config", "check", "--config", missing, "--json").output)
    assert payload == {"ok": False, "config": missing, "problems": [payload["problems"][0]]}


def test_config_check_without_any_file_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = invoke("config", "check")
    assert result.exit_code == 1
    assert "Problems in the configuration:" in result.output
    assert "arbitr init" in result.output


def test_config_check_refuses_a_shared_key_file_on_posix(tmp_path: Path) -> None:
    assert init(tmp_path).exit_code == 0
    result_args = ("config", "check", "--config", str(tmp_path / "arbitr.yaml"))
    if sys.platform == "win32":  # Windows has no group or other mode bits to check
        assert invoke(*result_args).exit_code == 0
        return
    os.chmod(tmp_path / ".arbitr" / "key", 0o644)
    result = invoke(*result_args)
    assert result.exit_code == 1
    assert "readable by other users" in result.output


def test_the_key_never_appears_in_any_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = [init(tmp_path).output]
    forms = key_forms(tmp_path)
    outputs.append(init(tmp_path / "second", "--json").output)
    forms += key_forms(tmp_path / "second")
    config = str(tmp_path / "arbitr.yaml")
    outputs.append(invoke("config", "check", "--config", config).output)
    outputs.append(invoke("config", "check", "--config", config, "--json").output)
    outputs.append(init(tmp_path).output)  # the refusal
    outputs.append(init(tmp_path, "--json").output)
    # A key from the environment, both a good one and a bad one.
    for env_key in ("cd" * 32, "ef" * 8):
        monkeypatch.setenv("ARBITR_LEDGER_KEY", env_key)
        forms.append(env_key)
        outputs.append(invoke("config", "check", "--config", config).output)
        outputs.append(invoke("config", "check", "--config", config, "--json").output)
    joined = "\n".join(outputs)
    assert "Configuration OK" in joined
    assert "at least 32 bytes" in joined
    for form in forms:
        assert form not in joined
