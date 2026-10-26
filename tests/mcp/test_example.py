"""The Claude Code example, step by step, with a scripted MCP client in Claude Code's place."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import anyio
import mcp_types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "mcp_proxy_with_claude_code"
MCP_SECTION = "mcp:\n  principal: you@example.com\n  on_tool_change: require_approval\n"


def text(result: types.CallToolResult) -> str:
    return " ".join(b.text for b in result.content if isinstance(b, types.TextContent))


def environment(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ARBITR_", "NOTES_"))}
    return {**env, "PYTHONIOENCODING": "utf-8", **extra}


def arbitr(folder: Path, *args: str) -> str:
    done = subprocess.run(
        [sys.executable, "-m", "arbitr", *args], cwd=folder, env=environment(),
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def proxy(folder: Path, **extra: str) -> StdioServerParameters:
    """The command line from the example's .mcp.json, with this Python in front."""
    upstream = f'"{sys.executable}" notes_server.py'
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "arbitr", "mcp-proxy", "--server", "notes", "--upstream", upstream,
              "--upstream-env", "NOTES_EVIL"],
        env=environment(**extra), cwd=folder,
    )  # fmt: skip


async def test_the_documented_manual_check(tmp_path: Path) -> None:
    arbitr(tmp_path, "init")
    for name in ("notes_server.py", "policy.yaml", ".mcp.json"):
        shutil.copy(EXAMPLE / name, tmp_path / name)
    with (tmp_path / "arbitr.yaml").open("a", encoding="utf-8") as config:
        config.write(MCP_SECTION)

    with anyio.fail_after(60):
        async with stdio_client(proxy(tmp_path)) as (r, w), ClientSession(r, w) as client:
            await client.initialize()
            assert (await client.list_tools()).tools == []
    assert "held     notes/add_note" in arbitr(tmp_path, "mcp", "pin", "ls")
    for tool in ("list_notes", "add_note", "delete_all_notes"):
        shown = arbitr(tmp_path, "mcp", "pin", "show", "notes", tool)
        command = shown.splitlines()[-1].split()  # the exact accept line it prints
        assert command[:4] == ["arbitr", "mcp", "pin", "accept"]
        arbitr(tmp_path, *command[1:])

    with anyio.fail_after(60):
        async with stdio_client(proxy(tmp_path)) as (r, w), ClientSession(r, w) as client:
            await client.initialize()
            names = sorted(t.name for t in (await client.list_tools()).tools)
            added = await client.call_tool("add_note", {"text": "hello"})
            listed = await client.call_tool("list_notes", {})
            wiped = await client.call_tool("delete_all_notes", {})
    assert names == ["add_note", "delete_all_notes", "list_notes"]
    assert text(added) == "1 notes"
    assert text(listed) == "hello"
    assert wiped.is_error
    assert "Blocked by policy 'no-mass-delete'" in text(wiped)
    assert '["hello"]' in (tmp_path / "notes.json").read_text(encoding="utf-8")

    with anyio.fail_after(60):
        async with (
            stdio_client(proxy(tmp_path, NOTES_EVIL="1")) as (r, w),
            ClientSession(r, w) as client,
        ):
            await client.initialize()
            names = sorted(t.name for t in (await client.list_tools()).tools)
            held = await client.call_tool("add_note", {"text": "x"})
    assert names == ["delete_all_notes", "list_notes"]
    assert held.is_error
    assert "arbitr mcp pin accept notes add_note" in text(held)
    assert "id_rsa" in arbitr(tmp_path, "mcp", "pin", "show", "notes", "add_note")
    assert "ok" in arbitr(tmp_path, "verify").lower()
