"""LangGraph: a ``ToolNode`` whose every tool call goes through the ledger.

``guarded_tool_node`` builds the prebuilt ``ToolNode`` with Arbitr's gate in
its official hooks (``wrap_tool_call`` and ``awrap_tool_call``), so it works
with ``graph.invoke`` and ``graph.ainvoke``. A denial or a pending approval
becomes an error ``ToolMessage`` with a short message for the model, and the
graph keeps going.

Example::

    node = guarded_tool_node(ledger, [refund, run_sql], specs={
        "refund": ToolSpec(name="payments.refund", effect="financial", idempotency="native"),
        "run_sql": ToolSpec(name="db.execute", effect="write"),
    }, principal=principal_of)
    builder.add_node("tools", node)

Runs: when the graph runs inside ``ledger.run(...)``, its tool calls belong to
that run. Otherwise each LangGraph thread is one ledger run
(``thread-<agent_id>-<thread_id>``) for the principal the node is given: a
fixed name, or a function of the graph config that reads your own
authenticated user. A call with no principal is refused.

Tools mark ``idempotency_key`` and ``credentials`` as ``InjectedToolArg``, so
the model never sees them and callbacks never log them. ToolNode strips
injected arguments before a tool runs; the ledger's values are added back
right before the real tool is called.

Tool errors: the inner ToolNode never handles them, so the ledger sees the
real exception (a timeout is an unknown outcome, not a failure). The node's
``handle_tool_errors`` (same meaning as ToolNode's) is applied after the
ledger has recorded the outcome.
"""

from __future__ import annotations

import dataclasses
import functools
from typing import TYPE_CHECKING, Any, Final, NoReturn, TypedDict, Unpack, cast

from langchain_core.messages import BaseMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.errors import GraphBubbleUp
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.tool_node import (
    _default_handle_tool_errors,
    _handle_tool_error,
    _infer_handled_types,
)
from langgraph.types import Command
from pydantic import BaseModel

from arbitr.core.errors import (
    ActionError,
    AmbiguousToolError,
    RunContextError,
    ScrubbedToolError,
)
from arbitr.executor import scrub_injected, scrubbed_error
from arbitr.guarding import INJECTED, require_injected
from arbitr.integrations._common import (
    BadArguments,
    coerce,
    ensure_run,
    model_args,
    plain,
    spec_for,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

    from langchain_core.runnables import RunnableConfig
    from langchain_core.tools import BaseTool
    from langgraph.prebuilt.tool_node import ToolCallRequest

    from arbitr.core.spec import ToolSpec
    from arbitr.executor import Ledger

    ErrorHandling = bool | str | Callable[..., str] | type[Exception] | tuple[type[Exception], ...]
    Principal = str | Callable[[RunnableConfig], str | None]

__all__ = ["ArbitrGate", "ToolNodeOptions", "guarded_tool_node"]

_REPLAYED_UPDATE: Final = (
    "This action already ran earlier in this conversation. It changed the graph state then;"
    " it was not run again."
)


class ToolNodeOptions(TypedDict, total=False):
    """Options passed through to ``ToolNode``."""

    name: str
    tags: list[str] | None
    messages_key: str


class _ToolFailed(Exception):  # noqa: N818 - a signal to the ledger, never shown
    """The tool answered with an error message: the ledger records a failure, not a receipt."""


class _Injecting:
    """The real tool, with the ledger's values added after ToolNode stripped injected arguments.

    ToolNode removes every ``InjectedToolArg`` value from the model's call (so
    a model cannot forge them) right before ``tool.invoke``. This stands in for
    the tool in that one call and puts the ledger's ``idempotency_key`` and
    ``credentials`` back.
    """

    def __init__(self, tool: BaseTool, values: Mapping[str, object], seen: dict[str, Any]) -> None:
        self._tool = tool
        self._values = dict(values)
        self._seen = seen

    def __getattr__(self, name: str) -> object:
        return getattr(self._tool, name)

    def _with_values(self, value: object) -> object:
        self._seen["injected_into_tool"] = True
        if isinstance(value, dict) and isinstance(value.get("args"), dict):
            return {**value, "args": {**value["args"], **self._values}}
        return value

    def invoke(
        self, value: object, config: RunnableConfig | None = None, **kwargs: object
    ) -> object:
        return self._tool.invoke(self._with_values(value), config, **kwargs)  # type: ignore[arg-type]

    async def ainvoke(
        self, value: object, config: RunnableConfig | None = None, **kwargs: object
    ) -> object:
        return await self._tool.ainvoke(self._with_values(value), config, **kwargs)  # type: ignore[arg-type]


class ArbitrGate:
    """The hooks a ``ToolNode`` calls for each tool call. ``guarded_tool_node`` wires them up."""

    def __init__(
        self,
        ledger: Ledger,
        specs: Mapping[str, ToolSpec] | None = None,
        *,
        principal: Principal | None = None,
        agent_id: str = "langgraph",
        handle_tool_errors: ErrorHandling = _default_handle_tool_errors,
    ) -> None:
        """Gate tool calls with ``ledger``; ``specs`` maps tool names to specs.

        A tool without a spec counts as a write. ``principal`` names who the
        agent acts for in threads run outside ``ledger.run``: a fixed name, or
        a function of the graph config. Take it from your own authentication,
        never from config a client can send.
        """
        self.ledger = ledger
        self.specs = specs
        self.principal = principal
        self.agent_id = agent_id
        self.handle_tool_errors = handle_tool_errors

    def wrap(
        self,
        request: ToolCallRequest,
        execute: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        """The sync hook (``wrap_tool_call``)."""
        if request.tool is None:
            return execute(request)  # not a registered tool: ToolNode answers, nothing runs
        call = request.tool_call
        spec = spec_for(call["name"], self.specs)
        try:
            args = coerce(_arguments(request.tool), model_args(call["args"]))
        except BadArguments as exc:
            return _error(call, str(exc))
        seen: dict[str, Any] = {}

        def run(**kwargs: object) -> object:
            try:
                answer = execute(_prepared(request, args, kwargs, seen))
            except GraphBubbleUp:
                raise  # an interrupt, not a tool outcome
            except Exception:
                _check_injected(seen)
                raise
            _check_injected(seen)
            return _record(answer, seen)

        rid, principal = self._run_for(request)
        with ensure_run(self.ledger, rid, principal, self.agent_id):
            try:
                stored = self.ledger.execute(spec, args, run)
            except ActionError as exc:
                return _error(call, exc.to_tool_message())
            except Exception as exc:  # noqa: BLE001 - recorded by the ledger; handled as ToolNode would
                return self._failed(call, exc)
        return _answer(call, stored, seen)

    async def awrap(
        self,
        request: ToolCallRequest,
        execute: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        """The async hook (``awrap_tool_call``)."""
        if request.tool is None:
            return await execute(request)
        call = request.tool_call
        spec = spec_for(call["name"], self.specs)
        try:
            args = coerce(_arguments(request.tool), model_args(call["args"]))
        except BadArguments as exc:
            return _error(call, str(exc))
        seen: dict[str, Any] = {}

        async def run(**kwargs: object) -> object:
            try:
                answer = await execute(_prepared(request, args, kwargs, seen))
            except GraphBubbleUp:
                raise  # an interrupt, not a tool outcome
            except Exception:
                _check_injected(seen)
                raise
            _check_injected(seen)
            return _record(answer, seen)

        rid, principal = self._run_for(request)
        with ensure_run(self.ledger, rid, principal, self.agent_id):
            try:
                stored = await self.ledger.aexecute(spec, args, run)
            except ActionError as exc:
                return _error(call, exc.to_tool_message())
            except Exception as exc:  # noqa: BLE001 - recorded by the ledger; handled as ToolNode would
                return self._failed(call, exc)
        return _answer(call, stored, seen)

    def _failed(self, call: Mapping[str, Any], exc: Exception) -> ToolMessage:
        """A tool error, after the ledger recorded it, handled as the node's settings say.

        The text comes only from the exception the ledger raised, which it has
        scrubbed of injected credentials.
        """
        if isinstance(exc, RunContextError):
            raise exc
        if isinstance(exc, _ToolFailed | ScrubbedToolError):
            return _error(call, str(exc))
        flag = self.handle_tool_errors
        if not flag or not isinstance(exc, _handled_types(flag)):
            raise exc
        return _error(call, _handle_tool_error(exc, flag=flag))

    def _run_for(self, request: ToolCallRequest) -> tuple[str, str]:
        """The run and principal for a call made outside ``ledger.run`` (unused inside one)."""
        from arbitr.executor import current_run  # noqa: PLC0415 - the executor is heavy to import

        handle = current_run()
        if handle is not None:
            return handle.run_id, handle.principal
        config = cast("RunnableConfig", getattr(request.runtime, "config", None) or {})
        thread = (config.get("configurable") or {}).get("thread_id")
        principal = self.principal(config) if callable(self.principal) else self.principal
        if not thread or not principal:
            raise RunContextError(
                "tool calls need a run: run the graph inside ledger.run(...), or give the node"
                " a principal and invoke the graph with a configurable thread_id"
            )
        return f"thread-{self.agent_id}-{thread}", str(principal)


def guarded_tool_node(  # noqa: PLR0913 - the gate's settings and ToolNode's
    ledger: Ledger,
    tools: Sequence[BaseTool | Callable[..., Any]],
    specs: Mapping[str, ToolSpec] | None = None,
    *,
    principal: Principal | None = None,
    agent_id: str = "langgraph",
    handle_tool_errors: ErrorHandling = _default_handle_tool_errors,
    **options: Unpack[ToolNodeOptions],
) -> ToolNode:
    """A prebuilt ``ToolNode`` whose every call goes through the ledger.

    ``handle_tool_errors`` means what it means for ``ToolNode``; it is applied
    after the ledger has recorded the error. ``options`` go to ``ToolNode``.
    See ``ArbitrGate`` for ``specs``, ``principal`` and ``agent_id``.

    Raises:
        TypeError: a tool cannot take what the ledger injects for its spec, or
            takes it as a parameter the model would see.
    """
    gate = ArbitrGate(
        ledger, specs, principal=principal, agent_id=agent_id,
        handle_tool_errors=handle_tool_errors,
    )  # fmt: skip
    node = ToolNode(
        tools,
        wrap_tool_call=gate.wrap,
        awrap_tool_call=gate.awrap,
        handle_tool_errors=False,
        **options,
    )
    for name, tool in node.tools_by_name.items():
        _check_tool(name, spec_for(name, specs), tool)
    return node


def _check_tool(name: str, spec: ToolSpec, tool: BaseTool) -> None:
    """The tool takes what the ledger injects, and the model cannot see it."""
    require_injected(name, spec, _fields(tool.get_input_schema()))
    if spec.credentials and not isinstance(tool, StructuredTool):
        raise TypeError(
            f"{name}: a tool that needs credentials must be made with @tool (a StructuredTool),"
            " so Arbitr can scrub them from its results before callbacks see them"
        )
    shown = _fields(tool.tool_call_schema) or set()
    visible = sorted(shown & INJECTED)
    if visible:
        raise TypeError(
            f"{name}: mark {', '.join(visible)} as InjectedToolArg, so the model never sees it"
        )


def _arguments(tool: BaseTool | None) -> type[BaseModel] | None:
    """The schema of the arguments the model sends (injected ones left out), if a model."""
    schema = getattr(tool, "tool_call_schema", None)
    if isinstance(schema, type) and issubclass(schema, BaseModel):
        return schema
    return None


def _fields(schema: object) -> set[str] | None:
    """The property names of a pydantic model class or a JSON schema dict."""
    if isinstance(schema, dict):
        return set(schema.get("properties", {}))
    render = getattr(schema, "model_json_schema", None)
    if not callable(render):
        return None
    return set(render().get("properties", {}))


def _handled_types(flag: ErrorHandling) -> tuple[type[Exception], ...]:
    """The exceptions ``handle_tool_errors`` covers, by ToolNode's own rule."""
    if isinstance(flag, type) and issubclass(flag, Exception):
        return (flag,)
    if isinstance(flag, tuple):
        return flag
    if callable(flag) and not isinstance(flag, type):
        return _infer_handled_types(flag)
    return (Exception,)


def _prepared(
    request: ToolCallRequest,
    args: Mapping[str, object],
    kwargs: Mapping[str, object],
    seen: dict[str, Any],
) -> ToolCallRequest:
    """The request ToolNode runs: the model's arguments, and the ledger's values for the tool."""
    values = {k: v for k, v in kwargs.items() if k in INJECTED}
    seen["injected"] = values
    tool = cast("BaseTool", request.tool)
    if values:
        tool = cast("BaseTool", _Injecting(_scrubbing(tool, values), values, seen))
    return request.override(tool_call={**request.tool_call, "args": dict(args)}, tool=tool)


def _scrubbing(tool: BaseTool, injected: Mapping[str, object]) -> BaseTool:
    """A copy of the tool whose own function scrubs its result and errors of credentials.

    LangChain callbacks (tracing) see a tool's output and errors inside
    ``tool.invoke``, before Arbitr does, so for a tool that gets credentials
    the scrubbing happens in the tool's function itself.
    """
    if not injected.get("credentials") or not isinstance(tool, StructuredTool):
        return tool
    updates: dict[str, object] = {}
    if tool.func is not None:
        updates["func"] = _scrubbed_sync(tool.func, injected)
    if tool.coroutine is not None:
        updates["coroutine"] = _scrubbed_async(tool.coroutine, injected)
    return tool.model_copy(update=updates)


def _scrubbed_sync(
    func: Callable[..., object], injected: Mapping[str, object]
) -> Callable[..., object]:
    @functools.wraps(func)  # keeps the signature LangChain reads for callbacks
    def run(*args: object, **kwargs: object) -> object:
        try:
            result = func(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - raised again, scrubbed
            _reraise_scrubbed(exc, injected)
        return _scrubbed_result(result, injected)

    return run


def _scrubbed_async(
    func: Callable[..., Awaitable[object]], injected: Mapping[str, object]
) -> Callable[..., Awaitable[object]]:
    @functools.wraps(func)
    async def run(*args: object, **kwargs: object) -> object:
        try:
            result = await func(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - raised again, scrubbed
            _reraise_scrubbed(exc, injected)
        return _scrubbed_result(result, injected)

    return run


def _reraise_scrubbed(exc: Exception, injected: Mapping[str, object]) -> NoReturn:
    safe = scrubbed_error(exc, injected)
    if safe is exc:
        raise exc
    raise safe from None


def _scrubbed_result(result: object, injected: Mapping[str, object]) -> object:
    if isinstance(result, Command):
        return dataclasses.replace(result, update=_scrub_update(result.update, injected))
    return _scrub_update(result, injected)


def _check_injected(seen: Mapping[str, Any]) -> None:
    """Fail closed when ToolNode ran the tool without going through the injecting proxy.

    That would mean a future ToolNode calls tools another way: the tool may
    have acted without its idempotency key, so the outcome is unknown, whether
    the tool answered or raised.
    """
    if seen.get("injected") and not seen.get("injected_into_tool"):
        raise AmbiguousToolError(
            "the tool ran without the values Arbitr injects; its outcome cannot be checked"
        ) from None


def _record(result: ToolMessage | Command[Any], seen: dict[str, Any]) -> object:
    """What the ledger stores for a tool's answer; the answer itself is kept for this call."""
    seen["result"] = result
    if isinstance(result, ToolMessage):
        if result.status == "error":
            raise _ToolFailed(str(result.content))
        return {"content": plain(result.content)}
    return {"update": True}


def _answer(
    call: Mapping[str, Any], stored: object, seen: Mapping[str, Any]
) -> ToolMessage | Command[Any]:
    """The tool's answer: this call's own, or one rebuilt from the stored receipt.

    Text the model reads always comes from what the ledger returned, which it
    has scrubbed of injected credentials.
    """
    fresh = seen.get("result")
    injected = seen.get("injected", {})
    if fresh is not None and not isinstance(fresh, ToolMessage):
        command = cast("Command[Any]", fresh)  # a state update, scrubbed of injected credentials
        return dataclasses.replace(command, update=_scrub_update(command.update, injected))
    record = stored if isinstance(stored, dict) else {}
    if record.get("update") and fresh is None:
        return ToolMessage(_REPLAYED_UPDATE, name=call["name"], tool_call_id=call["id"])
    content = record.get("content", "" if stored is None else stored)
    message = ToolMessage(
        content=content if isinstance(content, str | list) else str(content),
        name=call["name"],
        tool_call_id=call["id"],
    )
    if isinstance(fresh, ToolMessage) and fresh.artifact is not None:
        # Kept in the graph state, so scrubbed of injected credentials too.
        message.artifact = scrub_injected(fresh.artifact, injected)
    return message


def _scrub_update(value: object, injected: Mapping[str, object]) -> object:
    """A state update with injected credentials scrubbed; messages stay messages."""
    if not injected:
        return value
    if isinstance(value, BaseMessage):
        fields: dict[str, object] = {"content": scrub_injected(value.content, injected)}
        artifact = getattr(value, "artifact", None)
        if artifact is not None:
            fields["artifact"] = scrub_injected(artifact, injected)
        return value.model_copy(update=fields)
    if isinstance(value, dict):
        return {k: _scrub_update(v, injected) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return type(value)(_scrub_update(v, injected) for v in value)
    return scrub_injected(value, injected)


def _error(call: Mapping[str, Any], text: str) -> ToolMessage:
    return ToolMessage(text, name=call["name"], tool_call_id=call["id"], status="error")
