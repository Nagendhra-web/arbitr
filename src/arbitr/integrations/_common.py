"""Pieces every framework adapter shares: argument cleanup, schemas, specs and runs."""

from __future__ import annotations

import copy
import inspect
import json
import threading
import typing
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Final, Literal, cast

from pydantic import BaseModel, ConfigDict, ValidationError, create_model

from arbitr.core.errors import LedgerUnavailable, RunContextError
from arbitr.core.spec import ToolSpec, default_tool_spec
from arbitr.guarding import INJECTED

if TYPE_CHECKING:
    from collections.abc import Iterator

    from arbitr.executor import Ledger

_RUNS_LOCK: Final = threading.Lock()


class BadArguments(ValueError):  # noqa: N818 - what the model sent
    """The model's arguments are not a JSON object. The text is written for the model."""


def model_args(raw: object) -> dict[str, object]:
    """The model's arguments as a dict, without the names the ledger injects.

    A model must not choose the idempotency key (that would let it make a
    retry look like a new action) or pass credentials, so those names are
    dropped. ``raw`` may be a mapping or a JSON text.

    Raises:
        BadArguments: the arguments are not a JSON object.
    """
    if isinstance(raw, str | bytes):
        try:
            raw = json.loads(raw) if raw.strip() else {}
        except ValueError:
            raise BadArguments(
                "The tool arguments were not valid JSON. Send a JSON object."
            ) from None
    if not isinstance(raw, Mapping):
        raise BadArguments("The tool arguments must be a JSON object of names to values.")
    return {str(k): v for k, v in raw.items() if k not in INJECTED}


def signature_model(
    fn: Callable[..., object], *, skip_first: bool = False
) -> type[BaseModel] | None:
    """A pydantic model of a function's parameters, without the ones the ledger injects.

    ``skip_first`` leaves out a leading context parameter. Returns None when
    the signature cannot be modeled (the arguments are then used as sent).
    """
    try:
        hints = typing.get_type_hints(fn, include_extras=True)
        params = list(inspect.signature(fn).parameters.values())
    except (NameError, TypeError, ValueError):
        return None
    if skip_first and params:
        params = params[1:]
    fields: dict[str, Any] = {}
    extra: Literal["allow", "forbid"] = "forbid"
    for param in params:
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            extra = "allow"
            continue
        if param.kind is inspect.Parameter.VAR_POSITIONAL or param.name in INJECTED:
            continue
        default = ... if param.default is inspect.Parameter.empty else param.default
        fields[param.name] = (hints.get(param.name, Any), default)
    try:
        name = f"{getattr(fn, '__name__', 'tool')}_arguments"
        return create_model(name, __config__=ConfigDict(extra=extra), **fields)
    except Exception:  # noqa: BLE001 - a type pydantic cannot model: no coercion
        return None


def coerce(model: type[BaseModel] | None, args: Mapping[str, object]) -> dict[str, object]:
    """The model's arguments as the tool will receive them, validated by the tool's own types.

    The gate, the ledger and the tool must see the same values: a tool's
    validator turns ``"500"`` into ``500``, so the policy has to see ``500``
    too. Values come back in their JSON form.

    Raises:
        BadArguments: the arguments do not fit the tool's parameters.
    """
    if model is None:
        return dict(args)
    try:
        dumped = model.model_validate(dict(args)).model_dump(mode="json")
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or 'arguments'}: {error['msg']}"
            for error in exc.errors()[:5]
        )
        raise BadArguments(f"The tool arguments do not fit its parameters ({problems}).") from None
    except Exception:  # noqa: BLE001 - a value pydantic cannot dump: keep what was sent
        return dict(args)
    return cast("dict[str, object]", dumped)


def hide_injected(schema: Mapping[str, object]) -> dict[str, object]:
    """A copy of a JSON schema without the parameters the ledger injects.

    The model never sees ``idempotency_key`` or ``credentials``, so it cannot
    try to fill them in.
    """
    clean = copy.deepcopy(dict(schema))
    properties = clean.get("properties")
    if isinstance(properties, dict):
        clean["properties"] = {k: v for k, v in properties.items() if k not in INJECTED}
    required = clean.get("required")
    if isinstance(required, list):
        clean["required"] = [name for name in required if name not in INJECTED]
    return clean


def spec_for(name: str, specs: Mapping[str, ToolSpec] | None) -> ToolSpec:
    """The spec registered for a tool name, or the default for an unregistered tool (a write)."""
    if specs is not None and name in specs:
        return specs[name]
    return default_tool_spec(name)


def plain(value: object) -> object:
    """A JSON form of a tool result, so a stored receipt can stand in for it on a repeat.

    Objects with ``model_dump`` (pydantic) or ``to_dict`` are converted; other
    values that are not JSON become their text.
    """
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [plain(item) for item in value]
    for method in ("model_dump", "to_dict"):
        convert = getattr(value, method, None)
        if callable(convert):
            try:
                return plain(convert())
            except Exception:  # noqa: BLE001, S112 - fall back to the text form
                continue
    return str(value)


@contextmanager
def ensure_run(ledger: Ledger, run_id: str, principal: str, agent_id: str) -> Iterator[None]:
    """Run the block in the current ledger run, or in run ``run_id`` (created on first use).

    A framework thread maps to one run, so a repeated call in the same
    conversation returns the stored receipt. A stored run keeps its principal
    and agent: resuming it for anyone else is refused.

    Raises:
        RunContextError: the stored run belongs to another principal or agent.
        LedgerUnavailable: the run could not be recorded.
    """
    from arbitr.executor import current_run  # noqa: PLC0415 - the executor is heavy to import

    if current_run() is not None:
        yield
        return
    with _RUNS_LOCK:
        record = ledger.run_record(run_id)
        if record is None:
            try:
                with ledger.run(principal, agent_id, run_id=run_id):
                    pass
            except LedgerUnavailable:
                if ledger.run_record(run_id) is None:  # not another process creating it first
                    raise
            record = ledger.run_record(run_id)
    if record is None:  # pragma: no cover, the run was just written
        raise LedgerUnavailable("the run could not be recorded")
    if record.principal != principal:
        raise RunContextError(
            f"run {run_id} belongs to another principal; start a new thread for this one"
        )
    if record.agent_id != agent_id:
        raise RunContextError(f"run {run_id} belongs to another agent; use a thread of its own")
    with ledger.run(record.principal, record.agent_id, run_id=run_id, resume=True):
        yield
