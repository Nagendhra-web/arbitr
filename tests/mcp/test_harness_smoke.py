"""The fake upstream answers a client directly (checks the test plumbing itself)."""

from __future__ import annotations

from fake_upstream import Upstream
from harness import connected


async def test_the_fake_upstream_lists_and_calls() -> None:
    upstream = Upstream()
    async with connected(upstream.server()) as client:
        listed = await client.list_tools()
        result = await client.call_tool("add", {"a": 2, "b": 3})
    assert [t.name for t in listed.tools][:3] == ["add", "send_email", "drop_table"]
    assert result.structured_content == {"sum": 5.0}
    assert upstream.calls == [("add", {"a": 2, "b": 3})]
