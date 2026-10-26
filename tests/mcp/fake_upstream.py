"""A fake upstream MCP server for the proxy tests: a few tools, recorded calls, no network.

Run as a script, it serves over stdio (for the subprocess tests). Calls are then
appended to the file named by ``FAKE_MCP_CALLS``, one JSON line each.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any

import anyio
import mcp_types as types
from mcp.server.lowlevel.server import NotificationOptions, Server


@dataclass
class Upstream:
    """The fake server's state: its tools, how they answer, and every call made."""

    descriptions: dict[str, str] = field(
        default_factory=lambda: {
            "add": "Add two numbers.",
            "send_email": "Send an email.",
            "drop_table": "Drop a table.",
            "refund": "Refund an order.",
            "flaky": "Fails the first time it is called.",
            "slow": "Takes a long time.",
            "change_tools": "Changes add's description and says so.",
        }
    )
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    calls_file: str | None = None
    flaky_failures: int = 1
    slow_seconds: float = 5.0
    page_size: int | None = None
    extra: list[types.Tool] = field(default_factory=list)

    def tools(self) -> list[types.Tool]:
        schema: dict[str, Any] = {"type": "object", "properties": {}}
        hints = {
            "add": types.ToolAnnotations(read_only_hint=True),
            "send_email": types.ToolAnnotations(open_world_hint=True),
            "drop_table": types.ToolAnnotations(destructive_hint=True),
        }
        return [
            types.Tool(
                name=name,
                description=text,
                input_schema=schema,
                annotations=hints.get(name),
            )
            for name, text in self.descriptions.items()
        ] + self.extra

    def server(self) -> Server[Any]:
        async def list_tools(
            ctx: Any,
            params: types.PaginatedRequestParams | None,
        ) -> types.ListToolsResult:
            tools = self.tools()
            if self.page_size is None:
                return types.ListToolsResult(tools=tools)
            start = int(params.cursor) if params is not None and params.cursor else 0
            end = start + self.page_size
            more = str(end) if end < len(tools) else None
            return types.ListToolsResult(tools=tools[start:end], next_cursor=more)

        async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
            args = dict(params.arguments or {})
            self.calls.append((params.name, args))
            if self.calls_file:
                with open(self.calls_file, "a", encoding="utf-8") as out:
                    out.write(json.dumps([params.name, args]) + "\n")
            if params.name == "add":
                total = float(args.get("a", 0)) + float(args.get("b", 0))
                return types.CallToolResult(
                    content=[types.TextContent(text=str(total))],
                    structured_content={"sum": total},
                )
            if params.name == "flaky" and self.flaky_failures > 0:
                self.flaky_failures -= 1
                return types.CallToolResult(
                    content=[types.TextContent(text="service busy")], is_error=True
                )
            if params.name == "change_tools":
                self.descriptions["add"] = "Add two numbers, changed."
                await ctx.session.send_tool_list_changed()
            if params.name == "explode":
                raise ValueError("the upstream crashed")
            if params.name == "slow":
                await anyio.sleep(self.slow_seconds)
            return types.CallToolResult(content=[types.TextContent(text=f"{params.name} done")])

        return Server(
            "fake-upstream", version="1.0", on_list_tools=list_tools, on_call_tool=call_tool
        )


async def _main() -> None:
    from mcp.server.stdio import stdio_server  # noqa: PLC0415

    upstream = Upstream(calls_file=os.environ.get("FAKE_MCP_CALLS"))
    changed = os.environ.get("FAKE_MCP_ADD_DESCRIPTION")
    if changed:
        upstream.descriptions["add"] = changed
    server = upstream.server()
    async with stdio_server() as (read, write):
        options = server.create_initialization_options(NotificationOptions(tools_changed=True))
        await server.run(read, write, options)


if __name__ == "__main__":
    asyncio.run(_main())
