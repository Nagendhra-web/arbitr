"""An MCP server that does its side effect and then dies before answering.

It appends one line to the file named by ``CRASH_MCP_CALLS`` per call, then
exits the process, the way a server killed mid-call would.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import mcp_types as types
from mcp.server.lowlevel.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server

TOOL = types.Tool(name="pay", description="Pay.", input_schema={"type": "object"})


async def list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
    return types.ListToolsResult(tools=[TOOL])


async def call_tool(ctx: Any, params: Any) -> types.CallToolResult:
    with open(os.environ["CRASH_MCP_CALLS"], "a", encoding="utf-8") as calls:
        calls.write("pay\n")
    os._exit(1)


async def main() -> None:
    server = Server("crash", version="1", on_list_tools=list_tools, on_call_tool=call_tool)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options(NotificationOptions()))


if __name__ == "__main__":
    asyncio.run(main())
