"""Every integration SDK in the lock file imports cleanly.

Integration code is written against the installed versions, checked
against current docs. This test records the versions the adapters target, so a
lock file upgrade that changes a major version is a visible, reviewed change.
The adapters are in arbitr.integrations; their tests sit next to this file.
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


def test_the_private_langgraph_names_the_adapter_uses_exist() -> None:
    """The LangGraph adapter reuses ToolNode's own error handling and its request routing.

    These names are private, so a langgraph-prebuilt upgrade may move them;
    the extras pin the tested range and this test makes a move loud.
    """
    from langgraph.prebuilt import tool_node  # noqa: PLC0415

    for name in ("_handle_tool_error", "_infer_handled_types", "_default_handle_tool_errors"):
        assert callable(getattr(tool_node, name)), name
    assert hasattr(tool_node.ToolCallRequest, "override")


def test_the_mcp_http_era_routing_still_reads_the_version_header() -> None:
    """The proxy refuses session-less HTTP requests by the same header the SDK routes on."""
    from mcp.server import streamable_http_manager  # noqa: PLC0415
    from mcp.shared.inbound import MCP_PROTOCOL_VERSION_HEADER  # noqa: PLC0415
    from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS  # noqa: PLC0415

    assert MCP_PROTOCOL_VERSION_HEADER.lower() == "mcp-protocol-version"
    assert "MCP_PROTOCOL_VERSION_HEADER" in vars(streamable_http_manager)  # still what it routes on
    assert "2025-06-18" in HANDSHAKE_PROTOCOL_VERSIONS
