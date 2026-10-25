"""Package level checks: version, typing marker, minimal core dependencies."""

from __future__ import annotations

import importlib.metadata
import importlib.resources
import re

import arbitr


def test_version_matches_metadata() -> None:
    assert arbitr.__version__ == importlib.metadata.version("arbitr")


def test_py_typed_is_shipped() -> None:
    assert importlib.resources.files("arbitr").joinpath("py.typed").is_file()


def test_core_dependencies_stay_minimal() -> None:
    """The core needs pydantic, pyyaml and RE2. Everything else is an extra.

    RE2 is in the core because policy regexes match agent-controlled text and
    must run in linear time; a backtracking engine would let input stall the gate.
    """
    requires = importlib.metadata.requires("arbitr") or []
    core = {
        re.split(r"[ <>=!~;\[]", r, maxsplit=1)[0].lower() for r in requires if "extra ==" not in r
    }
    assert core == {"pydantic", "pyyaml", "google-re2"}


def test_declared_extras() -> None:
    extras = set(importlib.metadata.metadata("arbitr").get_all("Provides-Extra") or [])
    expected = {"cli", "server", "postgres", "mcp", "anthropic", "openai-agents"}
    expected |= {"langgraph", "otel", "all"}
    assert expected <= extras
