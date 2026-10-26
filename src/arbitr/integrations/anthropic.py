"""Anthropic SDK: Claude's tool calls go through the ledger.

Two ways in, both built on the SDK's own tool types (``anthropic`` 2.x):

- With the tool runner (``client.beta.messages.tool_runner``), wrap each tool
  made by ``@beta_tool`` or ``@beta_async_tool`` with ``guard_tool``. A denial
  or a pending approval becomes an ``is_error`` tool result with a short
  message for Claude; the run keeps going.
- With your own loop, pass the response content and the guarded tools to
  ``tool_results`` (or ``atool_results``). It returns the ``tool_result``
  blocks for the next user message, all in one list.

Example::

    from anthropic import beta_tool
    @beta_tool
    def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
        '''Refund an order.'''
        return payments.refund(order_id, amount, idempotency_key=idempotency_key)
    tools = [guard_tool(ledger, ToolSpec(name="refund", effect="financial",
                                         idempotency="native"), refund)]
    with ledger.run(principal="alice", agent_id="support-bot"):
        for message in client.beta.messages.tool_runner(
            model="claude-opus-5-5", max_tokens=16000, tools=tools, messages=messages
        ):
            ...

The model never sees ``idempotency_key`` or ``credentials``: they are removed
from the tool's input schema and from what the model sends, and the ledger
injects them when the tool runs.

A call made outside ``ledger.run(...)`` never runs the tool. With
``tool_results`` it raises ``RunContextError``; the SDK's tool runner catches
every error a tool raises, so there it becomes an ``is_error`` result that
names the missing run, and the conversation goes on.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, cast

from anthropic.lib.tools import (
    BetaAsyncBuiltinFunctionTool,
    BetaAsyncFunctionTool,
    BetaBuiltinFunctionTool,
    BetaFunctionTool,
    BetaFunctionToolResultType,
    ToolError,
)

from arbitr.core.errors import ActionError, RunContextError
from arbitr.guarding import require_injected
from arbitr.integrations._common import (
    BadArguments,
    coerce,
    hide_injected,
    model_args,
    signature_model,
    spec_for,
)

if TYPE_CHECKING:
    from anthropic.types.beta import BetaToolParam, BetaToolResultBlockParam, BetaToolUnionParam

    from arbitr.core.spec import ToolSpec
    from arbitr.executor import Ledger

__all__ = [
    "GuardedAsyncTool",
    "GuardedTool",
    "atool_results",
    "guard_tool",
    "guard_tools",
    "tool_results",
]


def _definition(tool: BetaFunctionTool[Any] | BetaAsyncFunctionTool[Any]) -> BetaToolUnionParam:
    raw: BetaToolParam = tool.to_dict()
    clean = dict(raw)
    clean["input_schema"] = hide_injected(raw["input_schema"])
    return cast("BetaToolUnionParam", clean)


class GuardedTool(BetaBuiltinFunctionTool):
    """A sync tool whose every call goes through the ledger. Use ``guard_tool`` to make one."""

    def __init__(self, ledger: Ledger, spec: ToolSpec, tool: BetaFunctionTool[Any]) -> None:
        """Wrap ``tool``; ``spec`` says what it does to the world."""
        self.ledger = ledger
        self.spec = spec
        self.tool = tool
        self._arguments = signature_model(tool.func)

    def to_dict(self) -> BetaToolUnionParam:
        """The tool definition sent to Claude, without the injected parameters."""
        return _definition(self.tool)

    def call(self, input: object) -> BetaFunctionToolResultType:  # noqa: A002 - the SDK's name
        """Run the call through the ledger. Stops become ``ToolError`` (an ``is_error`` result)."""
        try:
            args = coerce(self._arguments, model_args(input))
            result = self.ledger.execute(self.spec, args, lambda **kw: self.tool.call(kw))
        except (ActionError, BadArguments) as exc:
            raise ToolError(_message(exc)) from None
        return _as_content(result)


class GuardedAsyncTool(BetaAsyncBuiltinFunctionTool):
    """An async tool whose every call goes through the ledger. Use ``guard_tool`` to make one."""

    def __init__(self, ledger: Ledger, spec: ToolSpec, tool: BetaAsyncFunctionTool[Any]) -> None:
        """Wrap ``tool``; ``spec`` says what it does to the world."""
        self.ledger = ledger
        self.spec = spec
        self.tool = tool
        self._arguments = signature_model(tool.func)

    def to_dict(self) -> BetaToolUnionParam:
        """The tool definition sent to Claude, without the injected parameters."""
        return _definition(self.tool)

    async def call(self, input: object) -> BetaFunctionToolResultType:  # noqa: A002 - the SDK's name
        """Run the call through the ledger. Stops become ``ToolError`` (an ``is_error`` result)."""
        try:
            args = coerce(self._arguments, model_args(input))
            result = await self.ledger.aexecute(self.spec, args, lambda **kw: self.tool.call(kw))
        except (ActionError, BadArguments) as exc:
            raise ToolError(_message(exc)) from None
        return _as_content(result)


def guard_tool(
    ledger: Ledger,
    spec: ToolSpec,
    tool: BetaFunctionTool[Any] | BetaAsyncFunctionTool[Any],
) -> GuardedTool | GuardedAsyncTool:
    """Guard one tool made by ``@beta_tool`` or ``@beta_async_tool``.

    Raises:
        TypeError: ``tool`` is not such a tool, or cannot take what the ledger
            injects for ``spec``.
    """
    if isinstance(tool, BetaFunctionTool | BetaAsyncFunctionTool):
        params = inspect.signature(tool.func).parameters
        open_kwargs = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
        require_injected(tool.name, spec, None if open_kwargs else set(params))
    if isinstance(tool, BetaAsyncFunctionTool):
        return GuardedAsyncTool(ledger, spec, tool)
    if isinstance(tool, BetaFunctionTool):
        return GuardedTool(ledger, spec, tool)
    raise TypeError("guard_tool takes a tool made by @beta_tool or @beta_async_tool")


def guard_tools(
    ledger: Ledger,
    tools: Iterable[BetaFunctionTool[Any] | BetaAsyncFunctionTool[Any]],
    specs: Mapping[str, ToolSpec] | None = None,
) -> list[GuardedTool | GuardedAsyncTool]:
    """Guard several tools; ``specs`` maps tool names to specs.

    A tool without a spec is treated as a write (``default_tool_spec``), so
    nothing reaches the world unclassified.
    """
    return [guard_tool(ledger, spec_for(tool.name, specs), tool) for tool in tools]


def tool_results(
    content: Iterable[object],
    tools: Sequence[GuardedTool],
) -> list[BetaToolResultBlockParam]:
    """Run every ``tool_use`` block in a response and build the matching ``tool_result`` blocks.

    Send them back together in one user message. A stop (denied, waiting for
    approval) or a tool error becomes a result with ``is_error``. A tool Claude
    named that is not in ``tools`` is never run.
    """
    by_name = {tool.name: tool for tool in tools}
    results: list[BetaToolResultBlockParam] = []
    for block in _tool_uses(content):
        tool_id, name, tool_input = block
        tool = by_name.get(name)
        if tool is None:
            results.append(_error(tool_id, f"There is no tool named {name!r}."))
            continue
        try:
            results.append(_ok(tool_id, tool.call(tool_input)))
        except ToolError as exc:
            results.append(_error(tool_id, exc.content))
        except RunContextError:
            raise  # a setup mistake (no ledger.run around the loop), not a tool error
        except Exception as exc:  # noqa: BLE001 - the tool failed; Claude gets the error
            results.append(_error(tool_id, f"{type(exc).__name__}: {exc}"))
    return results


async def atool_results(
    content: Iterable[object],
    tools: Sequence[GuardedTool | GuardedAsyncTool],
) -> list[BetaToolResultBlockParam]:
    """The async form of ``tool_results``; sync and async tools may be mixed."""
    by_name = {tool.name: tool for tool in tools}
    results: list[BetaToolResultBlockParam] = []
    for tool_id, name, tool_input in _tool_uses(content):
        tool = by_name.get(name)
        if tool is None:
            results.append(_error(tool_id, f"There is no tool named {name!r}."))
            continue
        try:
            if isinstance(tool, GuardedAsyncTool):
                value = await tool.call(tool_input)
            else:
                value = tool.call(tool_input)
            results.append(_ok(tool_id, value))
        except ToolError as exc:
            results.append(_error(tool_id, exc.content))
        except RunContextError:
            raise  # a setup mistake (no ledger.run around the loop), not a tool error
        except Exception as exc:  # noqa: BLE001 - the tool failed; Claude gets the error
            results.append(_error(tool_id, f"{type(exc).__name__}: {exc}"))
    return results


def _as_content(value: object) -> BetaFunctionToolResultType:
    """A result Claude can read: text, content blocks, or anything else as JSON text.

    A repeat or a recovery hands back the stored receipt, which may be any
    JSON value (a probe's finding, say), so it is never passed through raw.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(b, dict) and "type" in b for b in value):
        return cast("BetaFunctionToolResultType", value)
    return json.dumps(value, default=str, ensure_ascii=False)


def _tool_uses(content: Iterable[object]) -> list[tuple[str, str, object]]:
    """(id, name, input) of each ``tool_use`` block; SDK objects and plain dicts both work."""
    found: list[tuple[str, str, object]] = []
    for block in content:
        if isinstance(block, Mapping):
            if block.get("type") == "tool_use":
                found.append((str(block["id"]), str(block["name"]), block.get("input")))
        elif getattr(block, "type", None) == "tool_use":
            found.append((str(block.id), str(block.name), block.input))  # type: ignore[attr-defined]
    return found


def _message(exc: ActionError | BadArguments) -> str:
    return exc.to_tool_message() if isinstance(exc, ActionError) else str(exc)


def _ok(tool_id: str, value: BetaFunctionToolResultType) -> BetaToolResultBlockParam:
    block: dict[str, object] = {"type": "tool_result", "tool_use_id": tool_id}
    if value is not None:
        block["content"] = value if isinstance(value, str) else list(value)
    return cast("BetaToolResultBlockParam", block)


def _error(tool_id: str, content: BetaFunctionToolResultType) -> BetaToolResultBlockParam:
    value = content if isinstance(content, str) else list(content)
    return cast(
        "BetaToolResultBlockParam",
        {"type": "tool_result", "tool_use_id": tool_id, "content": value, "is_error": True},
    )
