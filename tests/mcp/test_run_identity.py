"""One ledger run per client, whatever protocol era the client speaks.

A run carries dedup, taint and per-run budgets, so a client that got a new run
for every call could repeat a side effect or skip a taint rule.
"""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import anyio
import httpx2
import mcp_types as types
import pytest
import uvicorn
from fake_upstream import Upstream
from harness import connected
from mcp.client.client import Client
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from arbitr.executor import Ledger
from arbitr.integrations.mcp_proxy import McpProxy, http_app
from arbitr.policy.schema import load_policy

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator
    from pathlib import Path

POLICY = load_policy("""
version: 1
include: [mcp-basics]
default: { read: allow, write: allow, external_comm: allow }
""")
TOKEN = "identity-token-" + "9e1f"
TOKENS = {hashlib.sha256(TOKEN.encode()).hexdigest(): "alice@example.com"}
MODES = ["legacy", "auto", "2026-07-28"]


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with Ledger.open(tmp_path / "l.db", POLICY, key=b"mcp-run-identity" * 2) as led:
        yield led


def pin_all(ledger: Ledger, upstream: Upstream) -> None:
    for tool in upstream.tools():
        ledger.see_tool(
            "calc", tool.name, tool.model_dump(by_alias=True, mode="json", exclude_none=True)
        )
        ledger.accept_tool("calc", tool.name, accepted_by="test")


def text(result: types.CallToolResult) -> str:
    return " ".join(b.text for b in result.content if isinstance(b, types.TextContent))


@pytest.mark.parametrize("mode", MODES)
async def test_a_repeated_call_returns_the_receipt_in_every_era(ledger: Ledger, mode: str) -> None:
    upstream = Upstream()
    pin_all(ledger, upstream)
    async with connected(upstream.server()) as session:
        proxy = McpProxy(ledger, "calc", principal="alice")
        async with Client(proxy.server(session), mode=mode) as client:
            await client.list_tools()
            first = await client.call_tool("send_email", {"to": "bob"})
            again = await client.call_tool("send_email", {"to": "bob"})
    assert text(first) == text(again)
    assert upstream.calls == [("send_email", {"to": "bob"})]
    assert len({row.run_id for row in ledger.find_intents()}) == 1


@pytest.mark.parametrize("mode", MODES)
async def test_taint_carries_from_call_to_call_in_every_era(ledger: Ledger, mode: str) -> None:
    upstream = Upstream()
    pin_all(ledger, upstream)
    async with connected(upstream.server()) as session:
        proxy = McpProxy(ledger, "calc", principal="alice")
        async with Client(proxy.server(session), mode=mode) as client:
            await client.call_tool("add", {"a": 1})  # untrusted output taints the run
            sent = await client.call_tool("send_email", {"to": "bob"})
    assert sent.is_error
    assert "needs human approval" in text(sent)
    assert [name for name, _ in upstream.calls] == ["add"]


async def test_an_upstream_error_result_taints_the_run(ledger: Ledger) -> None:
    upstream = Upstream()  # flaky answers its first call with an error result
    pin_all(ledger, upstream)
    async with connected(upstream.server()) as session:
        proxy = McpProxy(ledger, "calc", principal="alice")
        async with connected(proxy.server(session)) as client:
            failed = await client.call_tool("flaky", {})
            sent = await client.call_tool("send_email", {"to": "bob"})
    assert failed.is_error
    assert "needs human approval" in text(sent)
    assert [name for name, _ in upstream.calls] == ["flaky"]


@asynccontextmanager
async def serving(
    ledger: Ledger, token_agents: dict[str, str] | None = None
) -> AsyncIterator[tuple[str, Upstream]]:
    upstream = Upstream()
    pin_all(ledger, upstream)
    async with connected(upstream.server()) as session:
        proxy = McpProxy(ledger, "calc", tokens=TOKENS, token_agents=token_agents)
        server = uvicorn.Server(
            uvicorn.Config(http_app(proxy, session), host="127.0.0.1", port=0, log_level="error")
        )
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(server.serve)
            with anyio.fail_after(10):
                while not server.started:
                    await anyio.sleep(0.02)
            port = server.servers[0].sockets[0].getsockname()[1]
            yield f"http://127.0.0.1:{port}/mcp", upstream
            server.should_exit = True


async def _call_over_http(url: str, args: dict[str, Any]) -> types.CallToolResult:
    auth = {"Authorization": f"Bearer {TOKEN}"}
    async with (
        httpx2.AsyncClient(headers=auth) as http,
        streamable_http_client(url, http_client=http) as (read, write),
        ClientSession(read, write) as client,
    ):
        await client.initialize()
        await client.call_tool("send_email", args)
        return await client.call_tool("send_email", args)


async def test_each_http_session_is_its_own_run(ledger: Ledger) -> None:
    with anyio.fail_after(30):
        async with serving(ledger) as (url, upstream):
            await _call_over_http(url, {"to": "bob"})
            await _call_over_http(url, {"to": "bob"})
    assert len(upstream.calls) == 2  # one per session; each repeat returned the receipt
    runs = {row.run_id for row in ledger.find_intents()}
    assert len(runs) == 2
    assert {ledger.run_record(r).agent_id for r in runs} == {"mcp-proxy:calc"}  # type: ignore[union-attr]


async def test_over_http_the_agent_comes_from_the_token_not_the_client(ledger: Ledger) -> None:
    agents = {next(iter(TOKENS)): "ci-bot"}
    with anyio.fail_after(30):
        async with serving(ledger, agents) as (url, _upstream):
            await _call_over_http(url, {"to": "carol"})
    (run_id,) = {row.run_id for row in ledger.find_intents()}
    assert ledger.run_record(run_id).agent_id == "ci-bot"  # type: ignore[union-attr]


async def test_modern_http_requests_are_refused(ledger: Ledger) -> None:
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "MCP-Protocol-Version": "2026-07-28",
        "Accept": "application/json, text/event-stream",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "send_email",
    }
    meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    params = {"name": "send_email", "arguments": {"to": "bob"}, "_meta": meta}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
    with anyio.fail_after(30):
        async with serving(ledger) as (url, upstream), httpx2.AsyncClient() as http:
            answer = await http.post(url, json=body, headers=headers)
    assert answer.status_code == 400
    assert "protocol version" in answer.text
    assert upstream.calls == []
