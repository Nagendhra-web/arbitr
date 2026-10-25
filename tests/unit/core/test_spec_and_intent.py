"""ToolSpec validation and intent hashing and keying."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from arbitr.core.canonical import sha256_hex
from arbitr.core.errors import IntentError
from arbitr.core.intent import (
    build_intent,
    compute_idempotency_key,
    compute_intent_hash,
    new_ulid,
)
from arbitr.core.spec import (
    EFFECT_RANK,
    ResourceRef,
    ToolSpec,
    default_tool_spec,
    raise_effect,
)

REFUND = ToolSpec(name="payments.refund", effect="financial", idempotency="native")


# ---------------------------------------------------------------- ToolSpec


def test_defaults() -> None:
    spec = ToolSpec(name="db.query", effect="read")
    assert (spec.reversible, spec.idempotency, spec.allow_duplicates, spec.redact) == (
        False,
        "none",
        False,
        (),
    )


def test_spec_is_immutable() -> None:
    with pytest.raises(ValidationError):
        REFUND.effect = "read"  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "", "effect": "read"},
        {"name": "has space", "effect": "read"},
        {"name": "x" * 201, "effect": "read"},
        {"name": "t", "effect": "delete_everything"},
        {"name": "t", "effect": "read", "probe": "not a path"},
        {"name": "t", "effect": "read", "compensate": "module.only"},
        {"name": "t", "effect": "read", "redact": ["password"]},
        {"name": "t", "effect": "read", "idempotency": "probe"},
        {"name": "t", "effect": "read", "idempotency_header": "Idempotency-Key"},
        {"name": "t", "effect": "read", "surprise": True},
    ],
)
def test_invalid_specs_are_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ToolSpec(**kwargs)  # type: ignore[arg-type]


def test_valid_full_spec() -> None:
    spec = ToolSpec(
        name="payments.refund",
        effect="financial",
        idempotency="probe",
        probe="myapp.payments:find_refund",
        compensate="myapp.payments:charge_back",
        resource_extractor="myapp.resources:from_order",
        redact=["$.card.number"],
    )
    assert spec.redact == ("$.card.number",)


def test_native_idempotency_header() -> None:
    assert REFUND.model_copy(update={"idempotency_header": "Idempotency-Key"}).idempotency_header


def test_unregistered_tools_default_to_write() -> None:
    assert default_tool_spec("mystery").effect == "write"
    assert default_tool_spec("mystery", effect="destructive").effect == "destructive"


def test_effects_only_go_up() -> None:
    effects = list(EFFECT_RANK)
    for a in effects:
        for b in effects:
            result = raise_effect(a, b)  # type: ignore[arg-type]
            assert EFFECT_RANK[result] == max(EFFECT_RANK[a], EFFECT_RANK[b])


def test_resource_ref() -> None:
    ref = ResourceRef(kind="path", uri="/var/backups/db.dump", attrs={"host": "h1"})
    assert ref.attrs == {"host": "h1"}
    with pytest.raises(ValidationError):
        ResourceRef(kind="", uri="x")


# ---------------------------------------------------------------- ULIDs


def test_ulid_shape_and_order() -> None:
    a = new_ulid(1_000, bytes(10))
    b = new_ulid(1_001, bytes(10))
    assert len(a) == 26
    assert a < b
    assert set(a) <= set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")


def test_ulids_are_unique() -> None:
    assert len({new_ulid() for _ in range(2000)}) == 2000


def test_ulid_known_value() -> None:
    assert new_ulid(2**48 - 1, b"\xff" * 10) == "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"


@pytest.mark.parametrize(("ms", "rand"), [(-1, bytes(10)), (2**48, bytes(10)), (0, bytes(9))])
def test_ulid_rejects_bad_input(ms: int, rand: bytes) -> None:
    with pytest.raises(ValueError, match="ULID"):
        new_ulid(ms, rand)


# ---------------------------------------------------------------- hashing


def test_intent_hash_definition() -> None:
    expected = sha256_hex({"tool": "t", "args": {"a": 1}, "run_id": "r", "principal": "p"})
    assert compute_intent_hash("t", {"a": 1}, "r", "p") == expected


def test_idempotency_key_definition() -> None:
    expected = sha256_hex({"run_id": "r", "step_id": None, "tool": "t", "args": {"a": 1}})
    assert compute_idempotency_key("r", None, "t", {"a": 1}) == expected


@pytest.mark.parametrize(
    "change",
    [
        {"args": {"order": "o1", "amount": 41}},
        {"run_id": "r2"},
        {"principal": "bob"},
    ],
)
def test_intent_hash_changes_with_any_part(change: dict[str, object]) -> None:
    base = {"args": {"order": "o1", "amount": 40}, "run_id": "r1", "principal": "alice"}
    a = build_intent(REFUND, base["args"], run_id="r1", principal="alice")  # type: ignore[arg-type]
    merged = {**base, **change}
    b = build_intent(
        REFUND,
        merged["args"],  # type: ignore[arg-type]
        run_id=merged["run_id"],  # type: ignore[arg-type]
        principal=merged["principal"],  # type: ignore[arg-type]
    )
    assert a.intent_hash != b.intent_hash


def test_principal_is_not_part_of_the_idempotency_key() -> None:
    a = build_intent(REFUND, {"amount": 1}, run_id="r", principal="alice")
    b = build_intent(REFUND, {"amount": 1}, run_id="r", principal="bob")
    assert a.idempotency_key == b.idempotency_key
    assert a.intent_hash != b.intent_hash


def test_retry_of_the_same_call_gets_the_same_key() -> None:
    a = build_intent(REFUND, {"order": "o1", "amount": 40}, run_id="r", principal="p")
    b = build_intent(REFUND, {"amount": 40.0, "order": "o1"}, run_id="r", principal="p")
    assert a.idempotency_key == b.idempotency_key
    assert a.intent_id != b.intent_id


def test_step_id_separates_otherwise_equal_calls() -> None:
    a = build_intent(REFUND, {"amount": 1}, run_id="r", principal="p", step_id="s1")
    b = build_intent(REFUND, {"amount": 1}, run_id="r", principal="p", step_id="s2")
    assert a.idempotency_key != b.idempotency_key


def test_allow_duplicates_makes_each_call_its_own_action() -> None:
    spec = ToolSpec(name="metrics.ping", effect="write", allow_duplicates=True)
    a = build_intent(spec, {}, run_id="r", principal="p", intent_id="01A")
    assert a.idempotency_key.endswith(":01A")
    with_step = build_intent(spec, {}, run_id="r", principal="p", step_id="s")
    again = build_intent(spec, {}, run_id="r", principal="p", step_id="s")
    assert with_step.idempotency_key == again.idempotency_key


def test_explicit_key_wins() -> None:
    intent = build_intent(REFUND, {"amount": 1}, run_id="r", principal="p", idempotency_key="k-1")
    assert intent.idempotency_key == "k-1"


@pytest.mark.parametrize("key", ["", "x" * 257])
def test_explicit_key_bounds(key: str) -> None:
    with pytest.raises(IntentError, match="idempotency_key"):
        build_intent(REFUND, {}, run_id="r", principal="p", idempotency_key=key)


@pytest.mark.parametrize(
    ("args", "run_id", "principal"),
    [
        ({"amount": float("nan")}, "r", "p"),
        ({"amount": 2**53 + 1}, "r", "p"),
        ({1: "x"}, "r", "p"),
        ({}, "", "p"),
        ({}, "r", ""),
    ],
)
def test_unhashable_or_incomplete_calls_are_refused(
    args: dict[object, object], run_id: str, principal: str
) -> None:
    with pytest.raises(IntentError):
        build_intent(REFUND, args, run_id=run_id, principal=principal)  # type: ignore[arg-type]


def test_non_mapping_args_are_refused() -> None:
    with pytest.raises(IntentError, match="mapping"):
        build_intent(REFUND, ["a"], run_id="r", principal="p")  # type: ignore[arg-type]


def test_intent_carries_spec_effect_and_resources() -> None:
    ref = ResourceRef(kind="database", uri="postgres://prod")
    intent = build_intent(REFUND, {}, run_id="r", principal="p", resources=(ref,))
    assert intent.effect == "financial"
    assert intent.tool == "payments.refund"
    assert intent.resources == (ref,)
