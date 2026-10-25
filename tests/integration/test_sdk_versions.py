"""Every integration SDK in the lock file imports cleanly.

Integration code is written against the installed versions, checked
against current docs. This test records the versions the adapters target, so a
lock file upgrade that changes a major version is a visible, reviewed change.
The adapters themselves are not built yet.
"""

from __future__ import annotations

import importlib
import importlib.metadata

import pytest

# distribution name -> (import name, supported major version)
SDKS = {
    "anthropic": ("anthropic", 2),
    "openai-agents": ("agents", 0),
    "langgraph": ("langgraph", 1),
    "mcp": ("mcp", 2),
    "fastapi": ("fastapi", 0),
    "psycopg": ("psycopg", 3),
    "opentelemetry-api": ("opentelemetry", 1),
}


@pytest.mark.parametrize("dist", sorted(SDKS))
def test_sdk_imports_and_major_version(dist: str) -> None:
    module, major = SDKS[dist]
    importlib.import_module(module)
    installed = importlib.metadata.version(dist)
    assert int(installed.split(".")[0]) == major, (
        f"{dist} {installed} is a new major version. Re-read its docs and update the adapter."
    )
