"""The ``guard`` decorator: a plain function or coroutine that always goes through the ledger.

Example::

    from arbitr import ToolSpec, guard
    spec = ToolSpec(name="payments.refund", effect="financial", idempotency="native")
    @guard(lambda: ledger, spec)
    def refund(order_id: str, amount: float, *, idempotency_key: str | None = None):
        return payments.refund(order_id, amount, idempotency_key=idempotency_key)

Calls must happen inside ``ledger.run(...)``. The bound arguments, with their
defaults filled in, are the intent's arguments, so ``refund("o-1", 25)`` and
``refund(order_id="o-1", amount=25)`` are the same action. ``idempotency_key``
and ``credentials`` are never arguments: the ledger injects them when the tool
runs. A caller may pass ``idempotency_key`` to choose the key itself.

When a call repeats one that already succeeded, the stored receipt comes back
instead of a new call. A receipt is stored as redacted JSON, so a tool that
returns objects gets their JSON form on a repeat; return plain data from
guarded tools.
"""

from __future__ import annotations

import functools
import inspect
from typing import TYPE_CHECKING, Any, Final, ParamSpec, TypeVar, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Mapping

    from arbitr.core.spec import ToolSpec
    from arbitr.executor import Ledger

P = ParamSpec("P")
R = TypeVar("R")

INJECTED: Final = frozenset({"idempotency_key", "credentials"})
"""Parameters the ledger fills in when a tool runs. Never part of a tool's arguments."""


def guard(
    ledger: Ledger | Callable[[], Ledger],
    spec: ToolSpec,
    *,
    step_id: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Route every call of the decorated function through ``ledger.execute``.

    ``ledger`` may be a zero-argument callable, so tools can be declared before
    the ledger exists. Async functions go through ``aexecute``.

    Raises:
        TypeError: when decorating, the function has a shape the ledger cannot
            call (positional-only parameters, ``*args``) or lacks a parameter the
            spec needs injected (``idempotency_key`` for native and probe tools,
            ``credentials`` for tools that declare credentials); or ``step_id``
            is fixed for a tool that allows duplicates (every call would then
            be the same action).
    """
    if step_id is not None and spec.allow_duplicates:
        raise TypeError(
            "a fixed step_id makes every call with the same arguments one action, which a tool"
            " that allows duplicates must not do; leave step_id out"
        )

    def decorate(fn: Callable[P, R]) -> Callable[P, R]:
        signature = inspect.signature(fn)
        _check_shape(fn, signature, spec)

        def resolve() -> Ledger:
            from arbitr.executor import Ledger  # noqa: PLC0415 - the executor is heavy to import

            return ledger if isinstance(ledger, Ledger) else ledger()

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def run_async(*args: P.args, **kwargs: P.kwargs) -> Any:  # noqa: ANN401
                call_args, key = _bind(signature, args, kwargs)
                return await resolve().aexecute(
                    spec, call_args, fn, step_id=step_id, idempotency_key=key
                )

            wrapper: Callable[..., Any] = run_async
        else:

            @functools.wraps(fn)
            def run_sync(*args: P.args, **kwargs: P.kwargs) -> Any:  # noqa: ANN401
                call_args, key = _bind(signature, args, kwargs)
                return resolve().execute(spec, call_args, fn, step_id=step_id, idempotency_key=key)

            wrapper = run_sync
        wrapper.spec = spec  # type: ignore[attr-defined]
        return cast("Callable[P, R]", wrapper)

    return decorate


def _check_shape(fn: Callable[..., object], signature: inspect.Signature, spec: ToolSpec) -> None:
    params = signature.parameters
    name = getattr(fn, "__qualname__", repr(fn))
    for param in params.values():
        if param.kind is inspect.Parameter.POSITIONAL_ONLY:
            raise TypeError(f"{name}: positional-only parameters cannot be guarded; name them")
        if param.kind is inspect.Parameter.VAR_POSITIONAL:
            raise TypeError(f"{name}: *args cannot be guarded; every argument needs a name")
    open_kwargs = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
    require_injected(name, spec, None if open_kwargs else set(params))


def require_injected(name: str, spec: ToolSpec, accepted: Collection[str] | None) -> None:
    """Refuse a tool that cannot take what the ledger injects for ``spec``.

    ``accepted`` is the set of parameter names the tool takes, or None when it
    takes any name. Every integration calls this when it wraps a tool, so a
    native tool can never run without its idempotency key.

    Raises:
        TypeError: a native or probe tool without ``idempotency_key``, or a tool
            that declares credentials without ``credentials``.
    """
    if accepted is None:
        return
    if spec.idempotency in ("native", "probe") and "idempotency_key" not in accepted:
        raise TypeError(
            f"{name}: a {spec.idempotency} tool gets the ledger's key, so it needs an"
            " idempotency_key parameter"
        )
    if spec.credentials and "credentials" not in accepted:
        raise TypeError(
            f"{name}: this tool declares credentials, so it needs a credentials parameter"
        )


def _bind(
    signature: inspect.Signature, args: tuple[object, ...], kwargs: dict[str, object]
) -> tuple[dict[str, object], str | None]:
    """The intent's arguments (defaults filled in, injected names removed) and a caller's key."""
    bound = signature.bind(*args, **kwargs)
    passed = _flatten(signature, bound.arguments)
    if passed.get("credentials") is not None:
        raise TypeError(
            "credentials are injected by the ledger when the tool runs; do not pass them"
        )
    key = passed.get("idempotency_key")
    bound.apply_defaults()
    call_args = _flatten(signature, bound.arguments)
    for name in INJECTED:
        call_args.pop(name, None)
    if key is not None and not isinstance(key, str):
        raise TypeError("idempotency_key must be a string")
    return call_args, key


def _flatten(signature: inspect.Signature, arguments: Mapping[str, object]) -> dict[str, object]:
    """Bound arguments by name, with ``**kwargs`` spread out."""
    flat: dict[str, object] = {}
    for name, value in arguments.items():
        if signature.parameters[name].kind is inspect.Parameter.VAR_KEYWORD:
            flat.update(cast("dict[str, object]", value))
        else:
            flat[name] = value
    return flat
