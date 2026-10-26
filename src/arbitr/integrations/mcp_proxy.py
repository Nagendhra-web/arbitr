"""The MCP proxy: MCP clients (Claude Code, Cursor) reach an MCP server only through Arbitr.

The proxy is an MCP server toward the client and an MCP client toward one
upstream server (a stdio command or a streamable HTTP URL).

- ``tools/list``: every upstream tool definition is hashed and compared with
  its pin. Only pinned definitions reach the client. A new or changed one is
  held, recorded as ``tool_def_changed``, and never shown to the model until
  someone runs ``arbitr mcp pin accept`` (with ``on_tool_change: allow`` it
  is accepted at once, and the acceptance is recorded). This stops a server
  that changes a tool's description after install to slip instructions in.
- ``tools/call``: the call goes through the ledger like any tool call, in one
  ledger run per client: per proxy process over stdio (one client each),
  per MCP session over HTTP. The upstream answer is the receipt, so a repeat
  returns it without calling the server again. A stop comes back as an MCP
  error result with the plain-English message; an upstream error result is
  passed back as it is and recorded as a failure; a timeout or a connection
  lost mid-call is an unknown outcome.

Example::

    proxy = McpProxy(ledger, "github", principal="alice@example.com")
    anyio.run(serve_stdio, proxy, Upstream(command=("npx", "-y", "some-mcp-server")))
"""

from __future__ import annotations

import hashlib
import hmac
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Literal

import anyio
import mcp_types as types
from mcp.server.lowlevel.server import NotificationOptions, Server
from mcp.shared.exceptions import MCPError
from mcp_types.jsonrpc import CONNECTION_CLOSED, REQUEST_TIMEOUT
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS

from arbitr.core.canonical import canonical_json
from arbitr.core.errors import (
    ActionError,
    AmbiguousToolError,
    CanonicalizationError,
    IntentError,
    RunContextError,
)
from arbitr.core.intent import new_ulid
from arbitr.integrations._common import ensure_run
from arbitr.integrations.mcp_specs import ServerSettings, spec_for_tool

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    from mcp.client.session import ClientSession
    from mcp.server.context import ServerRequestContext
    from starlette.types import ASGIApp, Receive, Scope, Send

    from arbitr.executor import Ledger

__all__ = [
    "McpProxy",
    "ToolChange",
    "Upstream",
    "connect_upstream",
    "http_app",
    "serve_http",
    "serve_stdio",
]

ToolChange = Literal["deny", "require_approval", "allow"]

_MAX_PAGES: Final = 100
_MAX_CLIENTS: Final = 10_000
# A tool larger than this is never pinned or stored: it stays hidden.
_MAX_NAME: Final = 128
_MAX_DEFINITION: Final = 64 * 1024
_ALLOW_BY: Final = "policy:on_tool_change=allow"
_ONE_CLIENT: Final = "stdio"
# Errors the SDK raises when the request may have reached the server but no
# answer came back: the connection closed, or the SDK's own timeout.
_LOST: Final = frozenset({CONNECTION_CLOSED, REQUEST_TIMEOUT})


class _UpstreamError(Exception):
    """The upstream answered with an error result: the ledger records a failure."""


@dataclass(frozen=True)
class Upstream:
    """The MCP server behind the proxy: a stdio command, or a streamable HTTP URL."""

    command: tuple[str, ...] = ()
    url: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    env: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        """Exactly one of ``command`` and ``url``."""
        if bool(self.command) == bool(self.url):
            raise ValueError("give the upstream either a command or a URL, not both")


class McpProxy:
    """The proxy's logic: which tools the client sees, and how calls reach the upstream."""

    def __init__(  # noqa: PLR0913 - the proxy's independent settings
        self,
        ledger: Ledger,
        server_name: str,
        *,
        settings: ServerSettings | None = None,
        on_tool_change: ToolChange = "require_approval",
        principal: str | None = None,
        tokens: Mapping[str, str] | None = None,
        token_agents: Mapping[str, str] | None = None,
        agent_id: str | None = None,
        call_timeout: float = 60.0,
    ) -> None:
        """Proxy one upstream server, named ``server_name`` in pins and tool names.

        ``principal`` is who the agent acts for (stdio). ``tokens`` maps the
        SHA-256 hex of an HTTP bearer token to its principal, and
        ``token_agents`` to its agent id (HTTP). With no ``agent_id``, a stdio
        client's own (self-reported) name is used, and over HTTP the token's
        agent or ``mcp-proxy:<server>``.
        """
        self.ledger = ledger
        self.server_name = server_name
        self.settings = settings or ServerSettings()
        self.on_tool_change = on_tool_change
        self.principal = principal
        self.tokens = dict(tokens or {})
        self.token_agents = dict(token_agents or {})
        self.agent_id = agent_id
        self.call_timeout = call_timeout
        self._upstream: ClientSession | None = None
        self._visible: dict[str, types.Tool] = {}
        self._held: dict[str, str] = {}
        # Per client (one over stdio, an MCP session id over HTTP): its run id and
        # agent, and its latest session for sending change notifications. The
        # SDK's own session objects are per request, so they cannot name a client.
        self._shared = False
        self._runs: OrderedDict[str, tuple[str, str]] = OrderedDict()
        self._sessions: OrderedDict[str, Any] = OrderedDict()

    def server(self, upstream: ClientSession, *, shared: bool = False) -> Server[Any]:
        """The MCP server the client talks to, forwarding to ``upstream``.

        By default the server has one client (stdio), and every call from it
        is in one ledger run, whatever protocol era it speaks. ``shared``
        (HTTP) gives each MCP session its own run.
        """
        from arbitr import __version__  # noqa: PLC0415 - the package metadata

        self._upstream = upstream
        self._shared = shared
        self._runs.clear()
        self._sessions.clear()
        return Server(
            f"arbitr-{self.server_name}",
            version=__version__,
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
        )

    async def upstream_tools_changed(self) -> None:
        """The upstream's tools changed: tell every client, so it lists them again."""
        self._visible = {}
        for session in list(self._sessions.values()):
            try:
                await session.send_tool_list_changed()
            except Exception:  # noqa: BLE001, S112 - a closed client simply misses it
                continue

    # ------------------------------------------------------------ handlers

    async def _list_tools(
        self, ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        self._client(ctx)  # remember this client, for change notifications
        return types.ListToolsResult(tools=await self._refresh())

    async def _call_tool(  # noqa: C901, PLR0911 - one return per MCP outcome
        self, ctx: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        name = params.name
        if name not in self._visible:
            await self._refresh()
        tool = self._visible.get(name)
        if tool is None:
            return _error(self._not_listed(name))
        principal = self._principal(ctx)
        if principal is None:
            return _error(
                "The Arbitr proxy has no principal for this call, so nothing ran. Set mcp.principal"
                " in the config (or ARBITR_PRINCIPAL), or send a known token over HTTP."
            )
        try:
            spec = spec_for_tool(self.server_name, name, _annotations(tool), self.settings)
        except IntentError as exc:
            return _error(str(exc))
        client = self._client(ctx)
        if client is None:
            return _error(
                "Nothing ran: this HTTP request belongs to no MCP session, so the Arbitr proxy"
                " cannot tell which run it is part of. Reconnect the MCP client."
            )
        run_id, agent = client
        args = dict(params.arguments or {})
        seen: dict[str, types.CallToolResult] = {}

        async def forward(**_injected: object) -> object:
            # Ledger values (an idempotency key) are never sent to the upstream.
            upstream = self._connected()
            try:
                with anyio.fail_after(self.call_timeout):
                    result = await upstream.call_tool(name, args)
            except MCPError as exc:
                if exc.code in _LOST:
                    raise AmbiguousToolError(f"the call to {name} got no answer: {exc}") from exc
                raise  # the server answered with an error: nothing happened that we know of
            except TimeoutError:
                raise  # the executor records a timeout as an unknown outcome
            except Exception as exc:
                raise AmbiguousToolError(
                    f"the call to {name} may have reached the server: {type(exc).__name__}"
                ) from exc
            if result.is_error:
                seen["error"] = result
                raise _UpstreamError(name)
            return result.model_dump(by_alias=True, mode="json", exclude_none=True)

        try:
            with ensure_run(self.ledger, run_id, principal, agent):
                stored = await self.ledger.aexecute(spec, args, forward)
        except ActionError as exc:
            return _error(exc.to_tool_message())
        except RunContextError as exc:
            return _error(f"Nothing ran: {exc}.")
        except _UpstreamError:
            return seen["error"]
        except Exception as exc:  # noqa: BLE001 - recorded by the ledger; the client gets text
            return _error(f"The call to {name} failed: {type(exc).__name__}: {exc}")
        return types.CallToolResult.model_validate(stored)

    # ------------------------------------------------------------ helpers

    async def _refresh(self) -> list[types.Tool]:
        """List the upstream's tools; keep the pinned ones (or all, when changes are allowed)."""
        upstream = self._connected()
        tools: list[types.Tool] = []
        cursor: str | None = None
        for _ in range(_MAX_PAGES):
            page = await upstream.list_tools(
                params=types.PaginatedRequestParams(cursor=cursor) if cursor else None
            )
            tools.extend(page.tools)
            cursor = page.next_cursor
            if not cursor:
                break
        visible: dict[str, types.Tool] = {}
        held: dict[str, str] = {}
        for tool in tools:
            status = await anyio.to_thread.run_sync(self._admit, tool)
            if status == "pinned":
                visible[tool.name] = tool
            else:
                held[tool.name] = status
        self._visible, self._held = visible, held
        return list(visible.values())

    def _admit(self, tool: types.Tool) -> str:
        """``pinned`` when the client may see the tool, else ``new``, ``changed`` or ``refused``.

        A tool whose name or definition is too large, or has no canonical JSON
        form, is refused on its own: the server's other tools stay usable.
        """
        definition = tool.model_dump(by_alias=True, mode="json", exclude_none=True)
        try:
            size = len(canonical_json(definition))
        except CanonicalizationError:
            return "refused"
        if len(tool.name) > _MAX_NAME or size > _MAX_DEFINITION:
            return "refused"
        seen = self.ledger.see_tool(self.server_name, tool.name, definition)
        if seen.status != "pinned" and self.on_tool_change == "allow":
            self.ledger.accept_tool(
                self.server_name, tool.name, accepted_by=_ALLOW_BY,
                definition_hash=seen.definition_hash,
            )  # fmt: skip
            return "pinned"
        return seen.status

    def _not_listed(self, name: str) -> str:
        status = self._held.get(name)
        if status is None:
            return f"There is no tool named {name!r} on {self.server_name}. Nothing ran."
        if status == "refused":
            return (
                f"The tool {name[:_MAX_NAME]} on {self.server_name} cannot be pinned: its name or"
                " definition is too large or not valid JSON. Nothing ran. Tell the user."
            )
        verdict = "is refused by policy" if self.on_tool_change == "deny" else "is held"
        return (
            f"The tool {name} on {self.server_name} is {status} and {verdict} until someone"
            f" reviews and accepts it: arbitr mcp pin accept {self.server_name} {name}."
            " Nothing ran. Tell the user."
        )

    def _connected(self) -> ClientSession:
        if self._upstream is None:  # pragma: no cover - server() sets it first
            raise RuntimeError("the proxy has no upstream session")
        return self._upstream

    def _principal(self, ctx: ServerRequestContext[Any, Any]) -> str | None:
        if not self.tokens:
            return self.principal
        return principal_for_token(_header(ctx, "authorization"), self.tokens)

    def _client(self, ctx: ServerRequestContext[Any, Any]) -> tuple[str, str] | None:
        """The run id and agent of the client behind this request, or None if unknown."""
        if self._shared:
            key = _header(ctx, "mcp-session-id")
            if not key:
                return None
        else:
            key = _ONE_CLIENT
        self._sessions[key] = ctx.session
        self._sessions.move_to_end(key)
        found = self._runs.get(key)
        if found is None:
            found = self._runs[key] = (f"mcp-{new_ulid()}", self._agent(ctx))
        self._runs.move_to_end(key)
        for table in (self._runs, self._sessions):
            while len(table) > _MAX_CLIENTS:
                table.popitem(last=False)
        return found

    def _agent(self, ctx: ServerRequestContext[Any, Any]) -> str:
        """The configured agent; over HTTP the token's; over stdio the client's own name."""
        if self.agent_id:
            return self.agent_id
        if self._shared:
            digest = _token_digest(_header(ctx, "authorization"), self.tokens)
            return self.token_agents.get(digest or "", f"mcp-proxy:{self.server_name}")
        client = getattr(ctx.session, "client_params", None)
        name = client.client_info.name if client is not None else "unknown"
        return f"mcp-client:{name}"[:128]


def principal_for_token(header: str, tokens: Mapping[str, str]) -> str | None:
    """The principal of a ``Bearer`` token, compared by SHA-256 in constant time, or None."""
    digest = _token_digest(header, tokens)
    return tokens[digest] if digest is not None else None


def _token_digest(header: str, tokens: Mapping[str, str]) -> str | None:
    """The configured digest (as written in ``tokens``) a ``Bearer`` header matches, or None."""
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    digest = hashlib.sha256(token.strip().encode()).hexdigest()
    found = None
    for known in tokens:
        if hmac.compare_digest(digest, known.lower()):
            found = known
    return found


def _header(ctx: ServerRequestContext[Any, Any], name: str) -> str:
    """A header of the HTTP request behind ``ctx`` (empty over stdio)."""
    return str(getattr(ctx.request, "headers", {}).get(name, ""))


def _annotations(tool: types.Tool) -> dict[str, object] | None:
    if tool.annotations is None:
        return None
    return dict(tool.annotations.model_dump(by_alias=True, exclude_none=True))


def _error(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(text=text)], is_error=True)


# ---------------------------------------------------------------- transports


@asynccontextmanager
async def connect_upstream(upstream: Upstream, proxy: McpProxy) -> AsyncIterator[ClientSession]:
    """An initialized session with the upstream; its tool changes are passed on to clients."""
    from mcp.client.session import ClientSession  # noqa: PLC0415

    async def on_message(message: object) -> None:
        if isinstance(message, types.ToolListChangedNotification):
            await proxy.upstream_tools_changed()

    async with (
        _upstream_streams(upstream) as (read, write),
        ClientSession(read, write, message_handler=on_message) as session,
    ):
        await session.initialize()
        yield session


@asynccontextmanager
async def _upstream_streams(upstream: Upstream) -> AsyncIterator[tuple[Any, Any]]:
    if upstream.url is not None:
        import httpx2  # noqa: PLC0415 - the MCP SDK's HTTP library
        from mcp.client.streamable_http import streamable_http_client  # noqa: PLC0415

        async with (
            httpx2.AsyncClient(headers=dict(upstream.headers)) as http,
            streamable_http_client(upstream.url, http_client=http) as streams,
        ):
            yield streams[0], streams[1]
        return
    from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: PLC0415

    params = StdioServerParameters(
        command=upstream.command[0], args=list(upstream.command[1:]),
        env=dict(upstream.env) if upstream.env is not None else None,
    )  # fmt: skip
    async with stdio_client(params) as streams:
        yield streams[0], streams[1]


async def serve_stdio(
    proxy: McpProxy, upstream: Upstream
) -> None:  # pragma: no cover - its own process
    """Serve one client over stdio (how Claude Code and most clients start a server).

    It owns the process's standard input and output, so it is tested by
    running the CLI as a subprocess (tests/mcp/test_transports.py).
    """
    from mcp.server.stdio import stdio_server  # noqa: PLC0415

    async with connect_upstream(upstream, proxy) as session:
        server = proxy.server(session)
        options = server.create_initialization_options(NotificationOptions(tools_changed=True))
        async with stdio_server() as (read, write):
            await server.run(read, write, options)


def http_app(proxy: McpProxy, session: ClientSession, *, host: str = "127.0.0.1") -> ASGIApp:
    """The streamable HTTP app at ``/mcp``. Every request needs a known bearer token.

    Raises:
        ValueError: the proxy has no tokens (HTTP mode never runs open).
    """
    if not proxy.tokens:
        raise ValueError("HTTP mode needs at least one token (mcp.http.tokens in the config)")
    app = proxy.server(session, shared=True).streamable_http_app(
        streamable_http_path="/mcp", host=host
    )
    return _RequireToken(app, proxy.tokens)


async def serve_http(proxy: McpProxy, upstream: Upstream, *, host: str, port: int) -> None:
    """Serve clients over streamable HTTP at ``http://<host>:<port>/mcp``."""
    import uvicorn  # noqa: PLC0415

    async with connect_upstream(upstream, proxy) as session:
        config = uvicorn.Config(
            http_app(proxy, session, host=host), host=host, port=port, log_level="warning"
        )
        server = uvicorn.Server(config)
        try:
            await server.serve()
        finally:
            # A cancelled serve() never reaches its own shutdown: stop listening here,
            # or the port keeps accepting connections with nobody answering.
            for listener in getattr(server, "servers", []):
                listener.close()


class _RequireToken:
    """Refuse any HTTP request without a known bearer token (401).

    Requests in the stateless protocol era (an ``MCP-Protocol-Version`` that is
    not a handshake version) are refused too (400): they carry no MCP session,
    so their calls could not share a ledger run.
    """

    def __init__(self, app: ASGIApp, tokens: Mapping[str, str]) -> None:
        self.app = app
        self.tokens = tokens

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
            if principal_for_token(headers.get("authorization", ""), self.tokens) is None:
                await send({
                    "type": "http.response.start", "status": 401,
                    "headers": [(b"content-type", b"text/plain"), (b"www-authenticate", b"Bearer")],
                })  # fmt: skip
                await send(
                    {"type": "http.response.body", "body": b"a valid bearer token is required"}
                )
                return
            version = headers.get("mcp-protocol-version")
            if version is not None and version not in HANDSHAKE_PROTOCOL_VERSIONS:
                await send({
                    "type": "http.response.start", "status": 400,
                    "headers": [(b"content-type", b"text/plain")],
                })  # fmt: skip
                await send({
                    "type": "http.response.body",
                    "body": b"the Arbitr MCP proxy serves HTTP clients only with a session-based"
                    b" protocol version (" + ", ".join(HANDSHAKE_PROTOCOL_VERSIONS).encode() + b")",
                })  # fmt: skip
                return
        await self.app(scope, receive, send)
