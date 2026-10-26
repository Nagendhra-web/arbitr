"""MCP commands: run the proxy, and review and accept tool definitions.

``arbitr mcp-proxy --server NAME --upstream "<command or URL>"`` serves over
stdio (point your MCP client at it instead of the server), or over streamable
HTTP with ``--http``. ``arbitr mcp pin ls | show | accept`` reviews the tool
definitions a server lists and pins the ones you trust.

In stdio mode the proxy never writes to standard output: that is the MCP
channel. Errors go to standard error.
"""

from __future__ import annotations

import difflib
import json
import os
import shlex
from pathlib import Path  # noqa: TC003 - typer reads the annotations at runtime
from typing import TYPE_CHECKING, Any

from arbitr.approvals import clean_text
from arbitr.cli.ops import CONFIG_HELP, JSON_HELP, _approver, _emit, _fail, _ledger

if TYPE_CHECKING:
    import typer

    from arbitr.storage.sqlite import ToolCandidateRow, ToolPinRow

SERVER_HELP = "The upstream server's name, as pins and tool names use it (mcp:<server>/<tool>)."


def register(app: typer.Typer) -> None:
    """Add ``mcp-proxy`` and ``mcp pin`` to the ``arbitr`` app."""
    import typer  # noqa: PLC0415

    _add_proxy_command(app)
    mcp = typer.Typer(help="Review MCP tool definitions.", no_args_is_help=True)
    mcp.add_typer(_pin_app(), name="pin")
    app.add_typer(mcp, name="mcp")


def split_command(value: str, *, windows: bool = os.name == "nt") -> tuple[str, ...]:
    r"""A command line as its parts, with the quotes around a part removed.

    Windows paths keep their backslashes, and a quoted program path such as
    ``"C:\Program Files\x\server.exe"`` works there.

    Example:
        >>> split_command('"C:\\Program Files\\x.exe" --flag', windows=True)
        ('C:\\Program Files\\x.exe', '--flag')
    """
    if not windows:
        return tuple(shlex.split(value))
    parts = shlex.split(value, posix=False)
    return tuple(p[1:-1] if len(p) > 1 and p[0] == p[-1] and p[0] in "\"'" else p for p in parts)


def warn_if_exposed(host: str) -> None:
    """Warn on standard error when HTTP mode listens beyond this machine."""
    import typer  # noqa: PLC0415

    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.echo(
            f"warning: listening on {host}: the proxy has no TLS, so bearer tokens and tool calls"
            " cross the network in clear text. Put it behind a TLS proxy, or keep it on 127.0.0.1.",
            err=True,
        )


def upstream_from(value: str, headers: list[str], env_names: list[str] | None = None) -> Any:  # noqa: ANN401 - mcp_proxy.Upstream
    """A stdio command line or an http(s) URL as an upstream.

    A stdio upstream gets the MCP SDK's small default environment plus the
    variables named in ``env_names``, taken from this process. A header
    written ``Name: env:VAR`` takes its value from the variable ``VAR``, so a
    secret need not be on the command line.
    """
    from arbitr.integrations.mcp_proxy import Upstream  # noqa: PLC0415 - needs the mcp extra

    if value.startswith(("http://", "https://")):
        pairs = {}
        for header in headers:
            name, sep, text = header.partition(":")
            if not sep or not name.strip():
                _fail(f"--upstream-header {name.strip()!r}: write it as 'Name: value'")
            text = text.strip()
            if text.startswith("env:"):
                variable = text[4:]
                if variable not in os.environ:
                    _fail(f"--upstream-header {name.strip()}: {variable} is not set")
                text = os.environ[variable]
            pairs[name.strip()] = text
        return Upstream(url=value, headers=pairs)
    if headers:
        _fail("--upstream-header only applies to an http(s) upstream")
    command = split_command(value)
    if not command:
        _fail("--upstream is empty")
    env = None
    if env_names:
        from mcp.client.stdio import get_default_environment  # noqa: PLC0415

        env = {
            **get_default_environment(),
            **{n: os.environ[n] for n in env_names if n in os.environ},
        }
    return Upstream(command=command, env=env)


def _add_proxy_command(app: typer.Typer) -> None:
    import typer  # noqa: PLC0415

    @app.command("mcp-proxy")
    def proxy_cmd(
        server: str = typer.Option(..., "--server", help=SERVER_HELP),
        upstream: str = typer.Option(
            ..., "--upstream", help="The server's command line, or its http(s) URL."
        ),
        header: list[str] = typer.Option(
            [],
            "--upstream-header",
            help="'Name: value' for an HTTP upstream; 'Name: env:VAR' reads the value from VAR.",
        ),
        env_names: list[str] = typer.Option(
            [],
            "--upstream-env",
            help="Pass this environment variable to a stdio upstream (repeat).",
        ),
        http: bool = typer.Option(False, "--http", help="Serve streamable HTTP instead of stdio."),
        host: str = typer.Option("127.0.0.1", "--host", help="The HTTP address to listen on."),
        port: int = typer.Option(8765, "--port", min=1, max=65535, help="The HTTP port."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
    ) -> None:
        """Run the MCP proxy in front of one server."""
        import anyio  # noqa: PLC0415

        from arbitr.config import ConfigError, load_config  # noqa: PLC0415
        from arbitr.integrations.mcp_proxy import McpProxy, serve_http, serve_stdio  # noqa: PLC0415

        try:
            settings = load_config(config)
        except ConfigError as exc:
            _fail(str(exc), 2)
        mcp = settings.mcp
        if server not in mcp.servers and not _valid_name(server):
            _fail(f"--server {server!r}: use letters, digits, '.', '_' or '-'")
        target = upstream_from(upstream, header, env_names)
        if http and not mcp.http_tokens:
            _fail("--http needs at least one token in mcp.http_tokens in the config", 2)
        if http:
            warn_if_exposed(host)
        with _ledger(config) as ledger:
            proxy = McpProxy(
                ledger, server, settings=mcp.settings_for(server),
                on_tool_change=mcp.on_tool_change,
                principal=os.environ.get("ARBITR_PRINCIPAL") or mcp.principal,
                tokens=mcp.tokens() if http else None,
                token_agents=mcp.token_agents() if http else None,
                agent_id=mcp.agent_id, call_timeout=mcp.call_timeout,
            )  # fmt: skip
            if http:
                anyio.run(lambda: serve_http(proxy, target, host=host, port=port))
            else:
                anyio.run(serve_stdio, proxy, target)


def _valid_name(name: str) -> bool:
    import re  # noqa: PLC0415

    return re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) is not None


def _pin_app() -> typer.Typer:  # noqa: C901, PLR0915 - one Typer app with its three commands
    import typer  # noqa: PLC0415

    app = typer.Typer(help="List, show and accept MCP tool definitions.", no_args_is_help=True)

    @app.command("ls")
    def ls_cmd(
        server: str | None = typer.Option(None, "--server", help="Only this server."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """Pinned tools, and new or changed ones waiting to be accepted."""
        with _ledger(config) as ledger:
            pins = ledger.tool_pins(server)
            held = ledger.tool_candidates(server)
        data = {"pinned": [_pin_view(p) for p in pins], "held": [_held_view(c) for c in held]}
        lines = [f"held     {_name(c)}  {'changed' if c.pinned_hash else 'new'}"
                 f"  {c.definition_hash}  ({c.first_seen})" for c in held]  # fmt: skip
        lines += [f"pinned   {_name(p)}  by {clean_text(p.accepted_by or '?')}  ({p.accepted_at})"
                  for p in pins]  # fmt: skip
        _emit(as_json, data, lines or ["No MCP tools seen yet."])

    @app.command("show")
    def show_cmd(
        server: str = typer.Argument(..., help="The server name."),
        tool: str = typer.Argument(..., help="The tool name."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """A held definition, and how it differs from the pinned one."""
        with _ledger(config) as ledger:
            held = [c for c in ledger.tool_candidates(server) if c.tool == tool]
            pins = [p for p in ledger.tool_pins(server) if p.tool == tool]
        if not held and not pins:
            _fail(f"no definition of {server}/{tool} has been seen")
        new = _pretty(held[0].definition) if held else None
        old = _pretty(pins[0].definition) if pins and pins[0].definition else None
        data = {
            "held": _held_view(held[0]) if held else None,
            "pinned": _pin_view(pins[0]) if pins else None,
        }
        if new is None:
            lines = [
                f"{server}/{tool} is pinned and nothing new is held.",
                *(old or "").splitlines(),
            ]
        elif old is None:
            lines = [f"{server}/{tool} is new. Its definition:", *new.splitlines()]
        else:
            lines = [f"{server}/{tool} changed:"]
            lines += list(
                difflib.unified_diff(
                    old.splitlines(), new.splitlines(), "pinned", "held", lineterm=""
                )
            )
        if held:
            digest = held[0].definition_hash
            lines += [
                f"Held definition: {digest}",
                "To pin exactly this definition:",
                f"  arbitr mcp pin accept {clean_text(server)} {clean_text(tool)} --hash {digest}",
            ]
        _emit(as_json, data, [_printable(line) for line in lines])

    @app.command("accept")
    def accept_cmd(
        server: str = typer.Argument(..., help="The server name."),
        tool: str | None = typer.Argument(None, help="The tool (or use --all)."),
        all_tools: bool = typer.Option(
            False, "--all", help="Accept every held tool of the server."
        ),
        hashes: list[str] = typer.Option(
            [],
            "--hash",
            help="The held definition's hash, from 'pin show' (repeat for --all).",
        ),
        yes: bool = typer.Option(
            False, "--yes", help="Accept whatever is held now, without naming its hash."
        ),
        approver: str | None = typer.Option(
            None, "--as", help="Who accepts (default: your user name)."
        ),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """Pin held definitions, so the proxy shows and runs those tools.

        Name each definition by the hash 'pin show' printed, so a server that
        changes it again after you looked cannot get the new one pinned; or
        pass --yes to take whatever is held now.
        """
        from arbitr.core.errors import StorageError  # noqa: PLC0415

        if (tool is None) == (not all_tools):
            _fail("name one tool, or use --all")
        if not hashes and not yes:
            _fail(
                "pass --hash with the hash 'arbitr mcp pin show' printed, to pin exactly the"
                " definition you reviewed (or --yes to accept whatever is held now)"
            )
        who = _approver(approver)
        with _ledger(config) as ledger:
            held = [c for c in ledger.tool_candidates(server) if all_tools or c.tool == tool]
            if not held:
                _fail(f"nothing is held for {server}" + ("" if all_tools else f"/{tool}"))
            unreviewed = [c for c in held if hashes and c.definition_hash not in hashes]
            if unreviewed:
                _fail(
                    "the --hash values do not match the held definition of "
                    + ", ".join(f"{_name(c)} (now {c.definition_hash})" for c in unreviewed)
                    + "; nothing was pinned. Review it again with 'arbitr mcp pin show'."
                )
            checked = {c.tool: c.definition_hash for c in held}
            try:  # bound to the hashes just checked, all or none: a newer definition is refused
                accepted = ledger.accept_tools(server, checked, accepted_by=who)
            except StorageError as exc:
                _fail(str(exc))
        lines = [f"Pinned {_name(p)} ({p.definition_hash})." for p in accepted]
        _emit(as_json, [_pin_view(p) for p in accepted], lines)

    return app


def _printable(line: str) -> str:
    """The line without control or format characters (an upstream wrote it), spaces kept."""
    return "".join(ch for ch in line if ch.isprintable())


def _name(row: ToolPinRow | ToolCandidateRow) -> str:
    return f"{clean_text(row.server)}/{clean_text(row.tool)}"


def _pretty(definition: str) -> str:
    return json.dumps(json.loads(definition), indent=2, sort_keys=True)


def _pin_view(pin: ToolPinRow) -> dict[str, object]:
    return {
        "server": pin.server,
        "tool": pin.tool,
        "definition_hash": pin.definition_hash,
        "first_seen": pin.first_seen,
        "accepted_by": pin.accepted_by,
        "accepted_at": pin.accepted_at,
    }


def _held_view(held: ToolCandidateRow) -> dict[str, object]:
    return {
        "server": held.server, "tool": held.tool, "definition_hash": held.definition_hash,
        "pinned_hash": held.pinned_hash, "first_seen": held.first_seen,
        "definition": json.loads(held.definition),
    }  # fmt: skip
