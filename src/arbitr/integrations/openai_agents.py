"""OpenAI Agents SDK: function tools whose every call goes through the ledger.

Use ``guarded_function_tool`` where you would use the SDK's ``function_tool``.
It takes the same options and builds a normal ``FunctionTool`` whose
``on_invoke_tool`` (the SDK's extension point for running a tool) asks the
ledger first. A denial or a pending approval comes back to the model as the
tool's output, a short message it can act on, and the run goes on.

Example::

    @guarded_function_tool(ledger, ToolSpec(name="payments.refund", effect="financial",
                                            idempotency="native"))
    def refund(order_id: str, amount: float, idempotency_key: str | None = None) -> str:
        '''Refund an order.'''
        return payments.refund(order_id, amount, idempotency_key=idempotency_key)

    agent = Agent(name="support", tools=[refund])
    with ledger.run(principal="alice", agent_id="support"):
        result = await Runner.run(agent, "Refund order o-1")

The SDK only ever sees the model's arguments. ``idempotency_key`` and
``credentials`` are left out of the function the SDK wraps (so they are not
in the schema, strict mode works, and the SDK never logs them) and are handed
to your function directly when the ledger runs it.

Tool errors are handled outside the ledger: the error is recorded as a
failure (so the call can run again) and then ``failure_error_function``
writes the text the model sees, as in the SDK. The SDK's default never shows
the exception to the model.
"""

from __future__ import annotations

import contextvars
import dataclasses
import functools
import inspect
import json
import typing
from typing import TYPE_CHECKING, Any, TypedDict, Unpack, overload

from agents import FunctionTool, RunContextWrapper, default_tool_error_function
from agents import function_tool as sdk_function_tool

from arbitr.core.errors import ActionError, RunContextError
from arbitr.core.spec import default_tool_spec
from arbitr.executor import scrub_injected, scrubbed_error
from arbitr.guarding import INJECTED, require_injected
from arbitr.integrations._common import (
    BadArguments,
    coerce,
    hide_injected,
    model_args,
    plain,
    signature_model,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from agents.function_schema import DocstringStyle
    from agents.tool import FunctionToolCustomDataExtractor, ToolCaller, ToolTimeoutBehavior
    from agents.tool_context import ToolContext
    from agents.tool_guardrails import ToolInputGuardrail, ToolOutputGuardrail
    from pydantic import BaseModel

    from arbitr.core.spec import ToolSpec
    from arbitr.executor import Ledger

    ErrorFunction = Callable[[RunContextWrapper[Any], Exception], str | Awaitable[str]]

__all__ = ["FunctionToolOptions", "guard_function_tool", "guarded_function_tool"]

_INJECTED_VALUES: contextvars.ContextVar[Mapping[str, object] | None] = contextvars.ContextVar(
    "arbitr_injected_values", default=None
)


class FunctionToolOptions(TypedDict, total=False):
    """Options passed through to the SDK's ``function_tool``."""

    name_override: str | None
    description_override: str | None
    docstring_style: DocstringStyle | None
    use_docstring_info: bool
    strict_mode: bool
    is_enabled: bool | Callable[..., Any]
    needs_approval: bool | Callable[..., Awaitable[bool]]
    tool_input_guardrails: list[ToolInputGuardrail[Any]] | None
    tool_output_guardrails: list[ToolOutputGuardrail[Any]] | None
    timeout: float | None
    timeout_behavior: ToolTimeoutBehavior
    timeout_error_function: ErrorFunction | None
    defer_loading: bool
    custom_data_extractor: FunctionToolCustomDataExtractor | None
    allowed_callers: list[ToolCaller] | None
    output_type: type | None
    output_json_schema: dict[str, object] | None


@overload
def guarded_function_tool(
    ledger: Ledger | Callable[[], Ledger],
    spec: ToolSpec | None = None,
    func: None = None,
    *,
    failure_error_function: ErrorFunction | None = ...,
    **options: Unpack[FunctionToolOptions],
) -> Callable[[Callable[..., object]], FunctionTool]: ...


@overload
def guarded_function_tool(
    ledger: Ledger | Callable[[], Ledger],
    spec: ToolSpec | None,
    func: Callable[..., object],
    *,
    failure_error_function: ErrorFunction | None = ...,
    **options: Unpack[FunctionToolOptions],
) -> FunctionTool: ...


def guarded_function_tool(
    ledger: Ledger | Callable[[], Ledger],
    spec: ToolSpec | None = None,
    func: Callable[..., object] | None = None,
    *,
    failure_error_function: ErrorFunction | None = default_tool_error_function,
    **options: Unpack[FunctionToolOptions],
) -> FunctionTool | Callable[[Callable[..., object]], FunctionTool]:
    """Make a guarded ``FunctionTool`` from a function, like the SDK's ``function_tool``.

    ``spec`` says what the tool does; without one the tool counts as a write.
    ``options`` go to the SDK's ``function_tool``. ``ledger`` may be a
    zero-argument callable, so tools can be declared before the ledger exists.

    Raises:
        TypeError: the function cannot take what the ledger injects for ``spec``.
    """

    def build(fn: Callable[..., object]) -> FunctionTool:
        name = str(options.get("name_override") or getattr(fn, "__name__", "tool"))
        tool_spec = spec or default_tool_spec(name)
        params = inspect.signature(fn).parameters
        open_kwargs = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
        require_injected(name, tool_spec, None if open_kwargs else set(params))
        inner = sdk_function_tool(_without_injected(fn), failure_error_function=None, **options)
        arguments = signature_model(fn, skip_first=_takes_context(fn))
        return _guarded(
            ledger, tool_spec, inner, failure_error_function,
            through_context=True, arguments=arguments,
        )  # fmt: skip

    return build if func is None else build(func)


def guard_function_tool(
    ledger: Ledger | Callable[[], Ledger],
    spec: ToolSpec,
    tool: FunctionTool,
    *,
    failure_error_function: ErrorFunction | None = default_tool_error_function,
) -> FunctionTool:
    """Guard an existing ``FunctionTool``.

    Build ``tool`` with ``failure_error_function=None``: a tool that turns its
    own errors into text would look like a success to the ledger, and the
    stored error text would come back on every retry. Errors are handled here,
    after the ledger has recorded them, by ``failure_error_function``.

    Raises:
        TypeError: ``spec`` declares credentials (build such tools with
            ``guarded_function_tool``, which keeps them out of the SDK's input),
            or the tool has no ``idempotency_key`` parameter for a native or
            probe spec.
    """
    if spec.credentials:
        raise TypeError(
            f"{tool.name}: build tools that need credentials with guarded_function_tool,"
            " so the credentials never pass through the SDK's input"
        )
    properties = tool.params_json_schema.get("properties", {})
    require_injected(tool.name, spec, set(properties) if isinstance(properties, dict) else set())
    return _guarded(
        ledger, spec, tool, failure_error_function, through_context=False, arguments=None
    )


def _guarded(  # noqa: PLR0913 - the tool and how to guard it
    ledger: Ledger | Callable[[], Ledger],
    spec: ToolSpec,
    tool: FunctionTool,
    failure_error_function: ErrorFunction | None,
    *,
    through_context: bool,
    arguments: type[BaseModel] | None,
) -> FunctionTool:
    invoke = tool.on_invoke_tool

    async def on_invoke_tool(ctx: ToolContext[Any], input_json: str) -> object:
        async def run(**kwargs: object) -> object:
            if not through_context:
                return plain(await invoke(ctx, json.dumps(kwargs)))
            values = {k: kwargs.pop(k) for k in INJECTED & kwargs.keys()}
            token = _INJECTED_VALUES.set(values)
            try:
                return plain(await invoke(ctx, json.dumps(kwargs)))
            finally:
                _INJECTED_VALUES.reset(token)

        try:
            args = coerce(arguments, model_args(input_json))
            return await _resolve(ledger).aexecute(spec, args, run)
        except ActionError as exc:
            return exc.to_tool_message()
        except BadArguments as exc:
            return str(exc)
        except RunContextError:
            raise  # a setup mistake (no ledger.run around the agent), not a tool error
        except Exception as exc:
            if failure_error_function is None:
                raise
            text = failure_error_function(ctx, exc)
            return await text if inspect.isawaitable(text) else text

    return dataclasses.replace(
        tool,
        on_invoke_tool=on_invoke_tool,
        params_json_schema=hide_injected(tool.params_json_schema),
    )


def _without_injected(fn: Callable[..., object]) -> Callable[..., object]:
    """``fn`` as the SDK should see it: no injected parameters; their values come from the ledger.

    The wrapper's signature and resolved annotations leave out
    ``idempotency_key`` and ``credentials``. When the SDK calls it, the
    values the ledger injected for this call are added back.
    """
    signature = inspect.signature(fn)
    hints = typing.get_type_hints(fn, include_extras=True)
    kept = [p for p in signature.parameters.values() if p.name not in INJECTED]
    takes = {p.name for p in signature.parameters.values()}
    open_kwargs = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in kept)

    def values() -> dict[str, object]:
        current = _INJECTED_VALUES.get()
        if current is None:
            # Called without the ledger: the function would run with no key or
            # credentials, so it does not run at all.
            raise RunContextError(
                f"{getattr(fn, '__name__', 'tool')} must be called through its guarded tool"
            )
        return {k: v for k, v in current.items() if open_kwargs or k in takes}

    # The SDK logs a tool's result and error before the ledger sees them, so
    # injected credentials are scrubbed here first, as the ledger would.
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def run_async(*args: object, **kwargs: object) -> object:
            injected = values()
            try:
                result = fn(*args, **kwargs, **injected)
                result = await result if inspect.isawaitable(result) else result
            except Exception as exc:  # noqa: BLE001 - raised again, scrubbed
                _reraise_scrubbed(exc, injected)
            return scrub_injected(result, injected)

        wrapper: Callable[..., object] = run_async
    else:

        @functools.wraps(fn)
        def run_sync(*args: object, **kwargs: object) -> object:
            injected = values()
            try:
                result = fn(*args, **kwargs, **injected)
            except Exception as exc:  # noqa: BLE001 - raised again, scrubbed
                _reraise_scrubbed(exc, injected)
            return scrub_injected(result, injected)

        wrapper = run_sync
    wrapper.__signature__ = signature.replace(  # type: ignore[attr-defined]
        parameters=[p.replace(annotation=hints.get(p.name, p.annotation)) for p in kept]
    )
    wrapper.__annotations__ = {k: v for k, v in hints.items() if k not in INJECTED}
    del wrapper.__wrapped__  # type: ignore[attr-defined]  # so nothing reads fn's signature
    return wrapper


def _reraise_scrubbed(exc: Exception, injected: Mapping[str, object]) -> typing.NoReturn:
    safe = scrubbed_error(exc, injected)
    if safe is exc:
        raise exc
    raise safe from None


def _takes_context(fn: Callable[..., object]) -> bool:
    """Whether the function's first parameter is the SDK's run context (not a tool argument)."""
    params = list(inspect.signature(fn).parameters.values())
    if not params:
        return False
    try:
        hint = typing.get_type_hints(fn).get(params[0].name)
    except (NameError, TypeError):
        return False
    origin = typing.get_origin(hint) or hint
    return isinstance(origin, type) and issubclass(origin, RunContextWrapper)


def _resolve(ledger: Ledger | Callable[[], Ledger]) -> Ledger:
    from arbitr.executor import Ledger  # noqa: PLC0415 - the executor is heavy to import

    return ledger if isinstance(ledger, Ledger) else ledger()
