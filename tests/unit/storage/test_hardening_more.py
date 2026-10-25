"""More hardening: field-name spellings, deep arguments, full intent
cross-checks, clear verify messages and reserved event kinds."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from arbitr.core.audit import VerifyResult
from arbitr.core.canonical import canonical_json
from arbitr.core.errors import IntentError, StorageError
from arbitr.core.intent import build_intent
from arbitr.core.redact import MARKER_PREFIX, Redactor, is_sensitive_key
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.storage.sqlite import SQLiteStorage

if TYPE_CHECKING:
    from collections.abc import Iterator

KEY = b"storage-harden-2" * 2
S = IntentState
SPEC = ToolSpec(name="payments.refund", effect="financial")


@pytest.fixture
def db(tmp_path: Path) -> Iterator[SQLiteStorage]:
    with SQLiteStorage.open(tmp_path / "ledger.db", Redactor(KEY)) as storage:
        with storage.transaction() as tx:
            tx.insert_run("r1", "alice", "bot")
        yield storage


# ---------------------------------------------------------------- key spellings


@pytest.mark.parametrize(
    "key",
    [
        "accessToken",
        "clientSecret",
        "privateKey",
        "dbPassword",
        "refreshToken",
        "sessionToken",
        "authToken",
        "secretKey",
        "AccessToken",
        "DBPassword",
        "passphrase",
        "credentials",
        "awsCredentials",
        "user_passphrase",
    ],
)
def test_camel_and_pascal_case_keys_are_sensitive(key: str) -> None:
    assert is_sensitive_key(key)
    out = Redactor(KEY).redact({key: "v4lue-in-clear"})
    assert isinstance(out, dict)
    assert str(out[key]).startswith(MARKER_PREFIX)


@pytest.mark.parametrize("key", ["tokenizer", "tokenCount", "keyboard", "idempotencyKey", "userId"])
def test_ordinary_camel_case_keys_are_not(key: str) -> None:
    assert not is_sensitive_key(key)


def test_camel_case_secrets_never_reach_the_file(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    with SQLiteStorage.open(path, Redactor(KEY)) as db, db.transaction() as tx:
        tx.insert_run("r1", "alice", "bot")
        args = {"accessToken": "Zq7tokenA1", "clientSecret": "Zq7secretB2", "dbPassword": "Zq7pwC3"}
        tx.insert_intent(build_intent(SPEC, args, run_id="r1", principal="alice"))
    data = b"".join(
        Path(str(path) + s).read_bytes()
        for s in ("", "-wal", "-shm")
        if Path(str(path) + s).exists()
    )
    for value in (b"Zq7tokenA1", b"Zq7secretB2", b"Zq7pwC3"):
        assert value not in data


# ---------------------------------------------------------------- deep and cyclic args


def test_cyclic_args_raise_a_clean_error() -> None:
    args: dict[str, object] = {"a": 1}
    args["self"] = args
    with pytest.raises(IntentError, match="cycle"):
        build_intent(SPEC, args, run_id="r", principal="p")


def test_very_deep_args_raise_a_clean_error() -> None:
    args: dict[str, object] = {}
    node = args
    for _ in range(5000):
        child: dict[str, object] = {}
        node["n"] = child
        node = child
    with pytest.raises(IntentError, match="nested"):
        build_intent(SPEC, args, run_id="r", principal="p")


def test_shared_but_acyclic_values_are_fine() -> None:
    shared = [1, 2]
    intent = build_intent(SPEC, {"a": shared, "b": shared}, run_id="r", principal="p")
    assert intent.args == {"a": [1, 2], "b": [1, 2]}


# ---------------------------------------------------------------- verify covers every column


def lifecycle(db: SQLiteStorage) -> str:
    intent = build_intent(SPEC, {"order": "o1"}, run_id="r1", principal="alice", step_id="s1")
    with db.transaction() as tx:
        tx.insert_intent(intent)
        tx.transition(
            intent.intent_id,
            S.APPROVED,
            expected=S.PROPOSED,
            fields={
                "decision": "allow",
                "decision_rule": "default",
                "decision_reason": "ok",
                "shadow_decision": "allow",
            },
        )
        tx.transition(
            intent.intent_id,
            S.EXECUTING,
            expected=S.APPROVED,
            fields={"attempt": 1, "lease_owner": "w1", "lease_expires_at": "2099-01-01T00:00:00Z"},
        )
    return intent.intent_id


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("attempt", 7),
        ("lease_owner", "w9"),
        ("lease_expires_at", "2100-01-01T00:00:00Z"),
        ("decision", "deny"),
        ("decision_rule", "forged-rule"),
        ("decision_reason", "forged"),
        ("shadow_decision", "deny"),
        ("tool", "other.tool"),
        ("effect", "read"),
        ("step_id", "s2"),
        ("run_id", "r2"),
    ],
)
def test_editing_any_recorded_column_is_caught(
    db: SQLiteStorage, column: str, value: object
) -> None:
    iid = lifecycle(db)
    if column == "run_id":
        with db.transaction() as tx:
            tx.insert_run("r2", "alice", "bot")
    assert db.verify().ok
    db._conn.execute(f"UPDATE intents SET {column} = ? WHERE intent_id = ?", (value, iid))  # noqa: S608
    result = db.verify()
    assert not result.ok, column
    assert iid in (result.reason or "")


# ---------------------------------------------------------------- messages


def test_describe_for_a_broken_link() -> None:
    result = VerifyResult(
        ok=False, checked=4, broken_seq=5, reason="it does not link to the event before it"
    )
    assert result.describe() == (
        "Audit chain broken at event 5: it does not link to the event before it."
    )


def test_describe_for_a_record_mismatch() -> None:
    result = VerifyResult(
        ok=False, checked=9, reason="intent abc attempt does not match its events"
    )
    assert result.describe() == (
        "Ledger does not match its audit chain: intent abc attempt does not match its events."
    )


def test_describe_when_ok() -> None:
    assert VerifyResult(ok=True, checked=2).describe() == (
        "Audit chain verified: 2 events, no broken links."
    )


# ---------------------------------------------------------------- reserved kinds


@pytest.mark.parametrize(
    "kind", ["intent_created", "run_started", "approved", "executing", "succeeded"]
)
def test_public_append_event_refuses_reserved_kinds(db: SQLiteStorage, kind: str) -> None:
    with pytest.raises(StorageError, match="reserved"), db.transaction() as tx:
        tx.append_event(kind, {"from": "PROPOSED", "to": "APPROVED"}, intent_id="x")


def test_ordinary_kinds_are_allowed(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        event = tx.append_event("note", {"text": "hello"})
    assert event.kind == "note"
    assert db.verify().ok


def test_payload_is_canonical(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        event = tx.append_event("note", {"b": 1, "a": 2})
    assert event.payload == canonical_json({"a": 2, "b": 1})
    assert tempfile.gettempdir()


@pytest.mark.parametrize("key", ["Proxy-Authorization", "HTTPAuthorization", "x_session_cookie"])
def test_authorization_and_cookie_suffixes(key: str) -> None:
    assert is_sensitive_key(key)
