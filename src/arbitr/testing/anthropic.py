"""A scripted Claude: the Anthropic SDK's agent loop runs offline, from a script of turns.

A script is a list of turns. A turn is either the final text, or a list of
tool calls as ``(tool name, arguments)`` pairs. When the script runs out, the
model answers ``"Done."``. Nothing goes to the network and no API key is used.

Example:
    >>> script = [[("refund", {"order_id": "o-1", "amount": 25})], "Refunded."]
    >>> claude = ScriptedClaude(script)
    >>> client = claude.client()  # an anthropic.Anthropic that answers from the script
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Final

from arbitr.testing._script import Script, Turn

if TYPE_CHECKING:
    import anthropic

__all__ = ["ScriptedClaude", "Turn"]

_MODEL: Final = "claude-opus-5-5"


class ScriptedClaude(Script):
    """An Anthropic client whose Messages API answers come from a script.

    It is a real ``anthropic.Anthropic`` (or ``AsyncAnthropic``) with an HTTP
    transport that never leaves the process, so the SDK's own tool runner and
    types are exercised. ``requests`` holds every request body the agent sent,
    so a test can read the ``tool_result`` blocks it sent back.
    """

    def client(self) -> anthropic.Anthropic:
        """A sync client that answers from the script."""
        import anthropic  # noqa: PLC0415 - optional dependency
        import httpx2  # noqa: PLC0415 - the SDK's own HTTP library

        return anthropic.Anthropic(
            api_key="scripted",
            base_url="http://scripted.invalid",
            max_retries=0,
            http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(self._answer)),
        )

    def async_client(self) -> anthropic.AsyncAnthropic:
        """An async client that answers from the script."""
        import anthropic  # noqa: PLC0415 - optional dependency
        import httpx2  # noqa: PLC0415 - the SDK's own HTTP library

        return anthropic.AsyncAnthropic(
            api_key="scripted",
            base_url="http://scripted.invalid",
            max_retries=0,
            http_client=anthropic.DefaultAsyncHttpxClient(
                transport=httpx2.MockTransport(self._answer)
            ),
        )

    def tool_results(self) -> list[dict[str, Any]]:
        """Every ``tool_result`` block the agent sent, in order."""
        found: list[dict[str, Any]] = []
        for body in self.requests:
            last = body.get("messages", [])[-1:] or [{}]
            content = last[0].get("content")
            if isinstance(content, list):
                found += [
                    b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"
                ]
        # The runner resends the whole history; keep each result once.
        unique: dict[str, dict[str, Any]] = {}
        for block in found:
            unique.setdefault(str(block["tool_use_id"]), block)
        return list(unique.values())

    def _answer(self, request: Any) -> Any:  # noqa: ANN401 - an httpx2 request and response
        import httpx2  # noqa: PLC0415

        self.requests.append(json.loads(request.content or b"{}"))
        turn = self.next_turn()
        if isinstance(turn, str):
            content: list[dict[str, object]] = [{"type": "text", "text": turn}]
            stop = "end_turn"
        else:
            content = [
                {
                    "type": "tool_use",
                    "id": self.call_id("toolu_"),
                    "name": name,
                    "input": dict(args),
                }
                for name, args in turn
            ]
            stop = "tool_use"
        message = {
            "id": f"msg_{len(self.requests):03d}",
            "type": "message",
            "role": "assistant",
            "model": _MODEL,
            "content": content,
            "stop_reason": stop,
            "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        return httpx2.Response(200, json=message)
