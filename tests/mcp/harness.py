"""Connect an MCP client to a server in memory, with no subprocess and no network."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import anyio
from mcp.client.session import ClientSession
from mcp.server.lowlevel.server import NotificationOptions, Server
from mcp.shared.memory import create_client_server_memory_streams

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable


@asynccontextmanager
async def connected(
    server: Server[Any],
    message_handler: Callable[[Any], Awaitable[None]] | None = None,
    *,
    raise_exceptions: bool = True,
) -> AsyncIterator[ClientSession]:
    """A ClientSession talking to ``server`` over memory streams, initialized.

    With ``raise_exceptions=False`` a handler that raises answers with an MCP
    error, as a real server does, instead of failing the test.
    """
    streams = create_client_server_memory_streams()
    async with streams as (client_streams, server_streams), anyio.create_task_group() as tasks:
        options = server.create_initialization_options(NotificationOptions(tools_changed=True))

        async def serve() -> None:
            await server.run(
                server_streams[0], server_streams[1], options, raise_exceptions=raise_exceptions
            )

        tasks.start_soon(serve)
        kwargs: dict[str, Any] = {}
        if message_handler is not None:
            kwargs["message_handler"] = message_handler
        async with ClientSession(client_streams[0], client_streams[1], **kwargs) as session:
            await session.initialize()
            yield session
        tasks.cancel_scope.cancel()
