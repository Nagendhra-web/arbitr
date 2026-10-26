"""Edges of the MCP proxy: upstream connections, paging, odd tools and failures."""

from __future__ import annotations

import hashlib
import socket
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio
import httpx2
import mcp_types as types
import pytest
import uvicorn
from fake_upstream import Upstream as FakeUpstream
from harness import connected
from mcp.client.session import ClientSession
from mcp.client.stdio import get_default_environment
from mcp.client.streamable_http import streamable_http_client

from arbitr.core.errors import RunContextError
from arbitr.executor import Ledger
from arbitr.integrations import mcp_proxy
from arbitr.integrations.mcp_proxy import McpProxy, Upstream, connect_upstream, serve_http
from arbitr.policy.schema import load_policy

if TYPE_CHECKING:
    from collections.abc import Iterator

FAKE = Path(__file__).parent / "fake_upstream.py"
CRASH = Path(__file__).parent / "crash_upstream.py"
POLICY = load_policy("version: 1\ndefault: { read: allow, write: allow, external_comm: allow }\n")


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    with Ledger.open(tmp_path / "l.db", POLICY, key=b"mcp-proxy-edges!" * 2) as led:
        yield led


def text(result: types.CallToolResult) -> str:
    return " ".join(b.text for b in result.content if isinstance(b, types.TextContent))


def test_an_upstream_is_a_command_or_a_url() -> None:
    for bad in ({}, {"command": ("x",), "url": "http://127.0.0.1/mcp"}):
        with pytest.raises(ValueError, match="either"):
            Upstream(**bad)  # type: ignore[arg-type]


async def test_paged_tool_lists_are_read_to_the_end(ledger: Ledger) -> None:
    upstream = FakeUpstream(page_size=2)
    async with connected(upstream.server()) as session:
        proxy = McpProxy(ledger, "calc", on_tool_change="allow", principal="alice")
        async with connected(proxy.server(session)) as client:
            listed = await client.list_tools()
    assert len(listed.tools) == len(upstream.descriptions)


async def test_a_tool_that_cannot_be_pinned_is_held_alone(ledger: Ledger) -> None:
    upstream = FakeUpstream()
    schema = {"type": "object"}
    upstream.extra = [
        types.Tool(name="huge", description="x" * 70_000, input_schema=schema),
        types.Tool(name="n" * 200, description="A long name.", input_schema=schema),
        types.Tool(name="odd", input_schema={"type": "object", "maximum": 2**70 + 1}),
    ]
    async with connected(upstream.server()) as session:
        proxy = McpProxy(ledger, "calc", on_tool_change="allow", principal="alice")
        async with connected(proxy.server(session)) as client:
            listed = {t.name for t in (await client.list_tools()).tools}
            refused = await client.call_tool("huge", {})
    assert listed == set(upstream.descriptions)  # the others are still there
    assert refused.is_error
    assert "cannot be pinned" in text(refused)
    assert upstream.calls == []
    assert {c.tool for c in ledger.tool_candidates()} == set()  # nothing oversized was stored


async def test_odd_tools_and_failures_become_error_results(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    upstream = FakeUpstream()
    upstream.descriptions["bad name!"] = "A tool whose name the ledger cannot store."
    upstream.descriptions["explode"] = "Crashes on the server."
    async with connected(upstream.server(), raise_exceptions=False) as session:
        proxy = McpProxy(ledger, "calc", on_tool_change="allow", principal="alice", agent_id="bot")
        async with connected(proxy.server(session)) as client:
            odd = await client.call_tool("bad name!", {})
            crashed = await client.call_tool("explode", {})
            fine = await client.call_tool("add", {"a": 1})

            def refuse(*args: object, **kwargs: object) -> object:
                raise RunContextError("run calc belongs to another principal")

            monkeypatch.setattr(mcp_proxy, "ensure_run", refuse)
            no_run = await client.call_tool("add", {"a": 2})
    assert odd.is_error
    assert "cannot be used" in text(odd)
    assert crashed.is_error
    assert "The call to explode failed" in text(crashed)
    assert not fine.is_error
    assert no_run.is_error
    assert text(no_run).startswith("Nothing ran: run calc belongs to another principal")
    (row,) = ledger.find_intents(tool="mcp:calc/add")
    assert ledger.run_record(row.run_id).agent_id == "bot"  # type: ignore[union-attr]
    assert [r.state.value for r in ledger.find_intents(tool="mcp:calc/explode")] == ["FAILED"]


async def test_an_http_call_without_an_mcp_session_never_runs(ledger: Ledger) -> None:
    class Request:
        def __init__(self) -> None:
            self.headers = {"authorization": "Bearer t0ken"}  # a known token, no mcp-session-id

    class Ctx:
        request = Request()
        session = object()

    upstream = FakeUpstream()
    async with connected(upstream.server()) as session:
        tokens = {hashlib.sha256(b"t0ken").hexdigest(): "alice"}
        proxy = McpProxy(ledger, "calc", on_tool_change="allow", tokens=tokens)
        proxy.server(session, shared=True)
        params = types.CallToolRequestParams(name="add", arguments={"a": 1})
        result = await proxy._call_tool(Ctx(), params)  # type: ignore[arg-type]
    assert result.is_error
    assert "no MCP session" in text(result)
    assert upstream.calls == []


async def test_a_transport_failure_mid_call_is_an_unknown_outcome(ledger: Ledger) -> None:
    class Broken:
        """An upstream whose transport breaks while a call is in flight."""

        async def list_tools(self, params: object = None) -> types.ListToolsResult:
            return types.ListToolsResult(tools=[types.Tool(name="pay", input_schema={})])

        async def call_tool(self, name: str, args: object) -> types.CallToolResult:
            raise OSError("the stream broke")

    proxy = McpProxy(ledger, "pay", on_tool_change="allow", principal="alice")
    async with connected(proxy.server(Broken())) as client:  # type: ignore[arg-type]
        result = await client.call_tool("pay", {})
    assert result.is_error
    assert [r.state.value for r in ledger.find_intents(tool="mcp:pay/pay")] == ["UNKNOWN"]


async def test_a_client_that_went_away_misses_the_change_notice(ledger: Ledger) -> None:
    class Gone:
        async def send_tool_list_changed(self) -> None:
            raise ConnectionError("closed")

    proxy = McpProxy(ledger, "calc")
    proxy._sessions["gone"] = Gone()
    await proxy.upstream_tools_changed()  # no error


async def test_a_stdio_upstream_connects_in_process(ledger: Ledger) -> None:
    proxy = McpProxy(ledger, "calc", on_tool_change="allow", principal="alice")
    upstream = Upstream(command=(sys.executable, str(FAKE)))
    with anyio.fail_after(30):
        async with connect_upstream(upstream, proxy) as session:
            listed = await session.list_tools()
    assert "add" in [t.name for t in listed.tools]


async def test_an_upstream_lost_mid_call_is_an_unknown_outcome(
    ledger: Ledger, tmp_path: Path
) -> None:
    calls = tmp_path / "calls.txt"
    env = {**get_default_environment(), "CRASH_MCP_CALLS": str(calls)}
    upstream = Upstream(command=(sys.executable, str(CRASH)), env=env)
    proxy = McpProxy(ledger, "pay", on_tool_change="allow", principal="alice")
    with anyio.fail_after(30):
        async with (
            connect_upstream(upstream, proxy) as session,
            connected(proxy.server(session)) as client,
        ):
            lost = await client.call_tool("pay", {"amount": 5})
            retried = await client.call_tool("pay", {"amount": 5})
    assert lost.is_error
    assert retried.is_error
    assert calls.read_text(encoding="utf-8") == "pay\n"  # it ran once, and never again
    assert [r.state.value for r in ledger.find_intents(tool="mcp:pay/pay")] == ["UNKNOWN"]


async def test_an_upstream_change_notice_reaches_the_client(ledger: Ledger) -> None:
    heard: list[object] = []

    async def on_message(message: object) -> None:
        heard.append(message)

    proxy = McpProxy(ledger, "calc", principal="alice")
    upstream = Upstream(command=(sys.executable, str(FAKE)))
    with anyio.fail_after(30):
        async with (
            connect_upstream(upstream, proxy) as session,
            connected(proxy.server(session), on_message) as client,
        ):
            await client.list_tools()
            for candidate in ledger.tool_candidates("calc"):
                ledger.accept_tool("calc", candidate.tool, accepted_by="test")
            await client.call_tool("change_tools", {})
            while not any(isinstance(m, types.ToolListChangedNotification) for m in heard):
                await anyio.sleep(0.02)
            listed = {t.name for t in (await client.list_tools()).tools}
    assert "add" not in listed  # its changed definition is held
    assert "change_tools" in listed


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _refused(port: int) -> bool:
    """True when nothing accepts connections on ``port`` any more."""
    try:
        stream = await anyio.connect_tcp("127.0.0.1", port)
    except OSError:
        return True
    await stream.aclose()
    return False


async def _serve(app: Any, port: int) -> uvicorn.Server:
    return uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))


async def test_an_http_upstream_and_serving_over_http(ledger: Ledger) -> None:
    fake = FakeUpstream()
    upstream_port, proxy_port = _free_port(), _free_port()
    upstream_app = fake.server().streamable_http_app(streamable_http_path="/mcp", host="127.0.0.1")
    upstream_server = await _serve(upstream_app, upstream_port)
    token = "edge-token-" + "7f2a"
    tokens = {hashlib.sha256(token.encode()).hexdigest(): "carol"}
    proxy = McpProxy(ledger, "calc", on_tool_change="allow", tokens=tokens)
    target = Upstream(url=f"http://127.0.0.1:{upstream_port}/mcp", headers={"X-Test": "1"})

    proxy_scope = anyio.CancelScope()

    async def run_proxy() -> None:
        with proxy_scope:
            await serve_http(proxy, target, host="127.0.0.1", port=proxy_port)

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(upstream_server.serve)
        with anyio.fail_after(10):
            while not upstream_server.started:
                await anyio.sleep(0.02)
        tasks.start_soon(run_proxy)
        url = f"http://127.0.0.1:{proxy_port}/mcp"
        auth = {"Authorization": f"Bearer {token}"}
        with anyio.fail_after(20):
            while True:
                try:
                    async with httpx2.AsyncClient() as probe:
                        await probe.get(url)
                    break
                except httpx2.TransportError:
                    await anyio.sleep(0.05)
            async with (
                httpx2.AsyncClient(headers=auth) as http,
                streamable_http_client(url, http_client=http) as (read, write),
                ClientSession(read, write) as client,
            ):
                await client.initialize()
                result = await client.call_tool("add", {"a": 4, "b": 4})
        proxy_scope.cancel()  # how a stopped proxy ends: its port must be released
        await anyio.sleep(0.2)
        assert await _refused(proxy_port)
        upstream_server.should_exit = True

    assert text(result) == "8.0"
    assert fake.calls == [("add", {"a": 4, "b": 4})]
