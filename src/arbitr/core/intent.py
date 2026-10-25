"""Action intents: one proposed tool call, hashed and keyed.

``intent_hash`` identifies exactly what is being done and for whom; approvals
are bound to it. ``idempotency_key`` identifies the logical action within a
run; a retry of the same action gets the same key, so it never runs twice.

Example:
    >>> from arbitr.core.spec import ToolSpec
    >>> spec = ToolSpec(name="payments.refund", effect="financial")
    >>> a = build_intent(spec, {"order": "o1", "amount": 40}, run_id="r1", principal="alice")
    >>> b = build_intent(spec, {"amount": 40, "order": "o1"}, run_id="r1", principal="alice")
    >>> a.idempotency_key == b.idempotency_key and a.intent_hash == b.intent_hash
    True
"""

from __future__ import annotations

import copy
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from arbitr.core.canonical import MAX_DEPTH, canonicalize, sha256_hex
from arbitr.core.errors import CanonicalizationError, IntentError

if TYPE_CHECKING:
    from arbitr.core.spec import Effect, ResourceRef, ToolSpec

_CROCKFORD: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
MAX_KEY_LENGTH: Final = 256
_ULID_RANDOM_BYTES: Final = 10


def new_ulid(timestamp_ms: int | None = None, randomness: bytes | None = None) -> str:
    """Return a ULID: 26 characters, sortable by creation time.

    48 bits of milliseconds since the epoch, then 80 random bits, in Crockford
    base32.

    Example:
        >>> new_ulid(0, bytes(10))
        '00000000000000000000000000'
        >>> len(new_ulid())
        26
    """
    ms = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    if not 0 <= ms < 2**48:
        raise ValueError("ULID timestamp must fit in 48 bits")
    rand = os.urandom(_ULID_RANDOM_BYTES) if randomness is None else randomness
    if len(rand) != _ULID_RANDOM_BYTES:
        raise ValueError("ULID randomness must be 10 bytes")
    value = (ms << 80) | int.from_bytes(rand, "big")
    return "".join(_CROCKFORD[(value >> shift) & 31] for shift in range(125, -1, -5))


def compute_intent_hash(tool: str, args: Mapping[str, object], run_id: str, principal: str) -> str:
    """SHA-256 of the canonical ``{tool, args, run_id, principal}``.

    Example:
        >>> a = compute_intent_hash("t", {"a": 1}, "r", "p")
        >>> a == compute_intent_hash("t", {"a": 1.0}, "r", "p")
        True
    """
    return sha256_hex({"tool": tool, "args": args, "run_id": run_id, "principal": principal})


def compute_idempotency_key(
    run_id: str, step_id: str | None, tool: str, args: Mapping[str, object]
) -> str:
    """SHA-256 of the canonical ``{run_id, step_id, tool, args}``.

    Example:
        >>> k1 = compute_idempotency_key("r", None, "t", {"a": 1})
        >>> k2 = compute_idempotency_key("r", "step-2", "t", {"a": 1})
        >>> k1 != k2
        True
    """
    return sha256_hex({"run_id": run_id, "step_id": step_id, "tool": tool, "args": args})


def snapshot(value: object) -> object:
    """Deep-copy a JSON value into exact built-in types, reading each container once.

    Subclasses of dict, list, str, int and float become their plain base types,
    so nothing the caller holds can change the snapshot later.

    Nesting deeper than ``MAX_DEPTH`` and containers that contain themselves
    are refused with ``IntentError``.

    Example:
        >>> snapshot({"a": (1, [2.5, True]), "b": None})
        {'a': [1, [2.5, True]], 'b': None}
    """
    return _snapshot(value, 0, set())


def _snapshot_scalar(value: object) -> object:
    if value is None or value is True or value is False:
        return value
    if isinstance(value, str):
        return str.__str__(value)
    if isinstance(value, int):
        return int.__index__(value)
    if isinstance(value, float):
        return float.__float__(value)
    raise IntentError(f"{type(value).__name__} is not a JSON value")


def _snapshot(value: object, depth: int, active: set[int]) -> object:
    if not isinstance(value, Mapping | list | tuple):
        return _snapshot_scalar(value)
    if depth >= MAX_DEPTH:
        raise IntentError(f"arguments are nested deeper than {MAX_DEPTH} levels")
    marker = id(value)
    if marker in active:
        raise IntentError("arguments contain a cycle (a container inside itself)")
    active.add(marker)
    try:
        if isinstance(value, Mapping):
            out: dict[str, object] = {}
            for key, item in list(value.items()):
                if not isinstance(key, str):
                    raise IntentError(f"argument keys must be strings, not {type(key).__name__}")
                out[str.__str__(key)] = _snapshot(item, depth + 1, active)
            return out
        return [_snapshot(item, depth + 1, active) for item in list(value)]
    finally:
        active.discard(marker)  # shared, non-cyclic values are fine


@dataclass(frozen=True)
class ActionIntent:
    """One proposed tool call, ready for the ledger.

    The arguments are a private snapshot taken once when the intent is built;
    both hashes are computed from that snapshot. ``args`` returns a fresh copy
    on every access, so nothing outside can change what was hashed. The full
    arguments live in memory only; storage keeps a redacted form.
    """

    intent_id: str
    run_id: str
    principal: str
    tool: str
    _args: Mapping[str, object] = field(repr=False, compare=False)
    effect: Effect
    intent_hash: str
    idempotency_key: str
    step_id: str | None = None
    resources: tuple[ResourceRef, ...] = field(default_factory=tuple)
    redact_paths: tuple[str, ...] = ()

    @property
    def args(self) -> dict[str, object]:
        """A fresh deep copy of the arguments that were hashed."""
        return copy.deepcopy(dict(self._args))


def build_intent(  # noqa: PLR0913, every argument is a distinct part of the intent
    spec: ToolSpec,
    args: Mapping[str, object],
    *,
    run_id: str,
    principal: str,
    step_id: str | None = None,
    idempotency_key: str | None = None,
    intent_id: str | None = None,
    resources: tuple[ResourceRef, ...] = (),
) -> ActionIntent:
    """Build an intent from a tool call.

    The arguments must have a canonical JSON form; anything that would hash
    ambiguously is refused with ``IntentError``. When the tool allows duplicates
    and the caller gave no step id or key, the intent id is appended to the key
    so repeated calls are separate actions.

    Example:
        >>> from arbitr.core.spec import ToolSpec
        >>> spec = ToolSpec(name="email.send", effect="external_comm", allow_duplicates=True)
        >>> a = build_intent(spec, {"to": "x@example.com"}, run_id="r", principal="p")
        >>> b = build_intent(spec, {"to": "x@example.com"}, run_id="r", principal="p")
        >>> a.idempotency_key != b.idempotency_key
        True
    """
    for name, value in (("run_id", run_id), ("principal", principal), ("tool", spec.name)):
        if not value:
            raise IntentError(f"{name} must not be empty")
    if not isinstance(args, Mapping):
        raise IntentError("tool arguments must be a mapping of names to values")
    # One read of the caller's arguments; everything below uses only this copy.
    frozen = snapshot(args)
    if not isinstance(frozen, dict):  # pragma: no cover, a Mapping always snapshots to a dict
        raise IntentError("tool arguments must be a mapping of names to values")
    try:
        canonicalize(frozen)
    except CanonicalizationError as exc:
        raise IntentError(f"arguments for {spec.name} cannot be hashed safely: {exc}") from exc

    iid = intent_id or new_ulid()
    if idempotency_key is not None:
        if not idempotency_key or len(idempotency_key) > MAX_KEY_LENGTH:
            raise IntentError(f"idempotency_key must be 1 to {MAX_KEY_LENGTH} characters")
        key = idempotency_key
    else:
        key = compute_idempotency_key(run_id, step_id, spec.name, frozen)
        if spec.allow_duplicates and step_id is None:
            key = f"{key}:{iid}"

    return ActionIntent(
        intent_id=iid,
        run_id=run_id,
        principal=principal,
        tool=spec.name,
        _args=frozen,
        effect=spec.effect,
        intent_hash=compute_intent_hash(spec.name, frozen, run_id, principal),
        idempotency_key=key,
        step_id=step_id,
        resources=resources,
        redact_paths=spec.redact,
    )
