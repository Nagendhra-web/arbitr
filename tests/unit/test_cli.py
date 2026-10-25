"""Tests for the CLI entry point."""

from __future__ import annotations

import builtins
import json
from typing import Any

import pytest
from typer.testing import CliRunner

import arbitr
from arbitr.cli import main as cli_main


def _app() -> Any:
    return cli_main._build_app()


def test_help_lists_commands() -> None:
    result = CliRunner().invoke(_app(), ["--help"])
    assert result.exit_code == 0
    assert "version" in result.output


def test_no_args_shows_help() -> None:
    result = CliRunner().invoke(_app(), [])
    assert "Usage" in result.output


def test_version_text() -> None:
    result = CliRunner().invoke(_app(), ["version"])
    assert result.exit_code == 0
    assert arbitr.__version__ in result.output


def test_version_json() -> None:
    result = CliRunner().invoke(_app(), ["version", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["arbitr"] == arbitr.__version__
    assert set(payload) == {"arbitr", "python", "platform"}


def test_main_runs_app(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["arbitr", "version", "--json"])
    with pytest.raises(SystemExit) as exc:
        cli_main.main()
    assert exc.value.code == 0


def test_missing_cli_extra_prints_install_hint(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "typer":
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SystemExit) as exc:
        cli_main.main()
    assert exc.value.code == 1
    assert 'pip install "arbitr[cli]"' in capsys.readouterr().err
