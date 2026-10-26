"""Previews through Ledger.execute: they reach the gate, fail safe and are recorded."""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING

import pytest

import custom_previewers
from arbitr.core.errors import ActionDenied, ApprovalPending
from arbitr.core.spec import ToolSpec
from arbitr.executor import Ledger, RunHandle
from arbitr.policy.schema import load_policy
from arbitr.preview.files import PATH_TAGS
from arbitr.preview.sql import CONNECTION

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from arbitr.preview import Preview

KEY = b"preview-tests!!!" * 2
POLICY = load_policy(
    """
version: 1
rules:
  - id: big-delete
    when:
      tool: db.exec
      preview: [{ path: "$.rows_affected", op: gt, value: 1000 }]
    then: deny
    reason: Deleting more than 1000 rows is not allowed.
  - id: small-delete
    when:
      tool: db.exec
      preview: [{ path: "$.rows_affected", op: lte, value: 1000 }]
    then: allow
    reason: Small deletes are fine.
  - id: backups
    when:
      tool: shell.run
      preview: [{ path: "$.files_tagged_backups", op: gt, value: 0 }]
    then: require_approval
    reason: Touching backups needs a human.
  - id: shell-ok
    when: { tool: shell.run }
    then: allow
    reason: Other shell commands are fine.
"""
)
DB_SPEC = ToolSpec(name="db.exec", effect="destructive")


@pytest.fixture
def shop(tmp_path: Path) -> Path:
    path = tmp_path / "shop.db"
    conn = sqlite3.connect(path)
    with conn:
        conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT)")
        conn.executemany(
            "INSERT INTO orders (status) VALUES (?)",
            [("old" if i <= 1500 else "new",) for i in range(1, 2001)],
        )
    conn.close()
    return path


def _rows(path: Path) -> int:
    conn = sqlite3.connect(path)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0])
    finally:
        conn.close()


@pytest.fixture
def ledger(tmp_path: Path, shop: Path) -> Iterator[Ledger]:
    def connect() -> sqlite3.Connection:
        # A fresh read-only connection per preview; the previewer closes it.
        return sqlite3.connect(f"file:{shop.as_posix()}?mode=ro", uri=True)

    context: dict[str, object] = {CONNECTION: connect, PATH_TAGS: {"backups": ["**/backups/**"]}}
    with Ledger.open(tmp_path / "ledger.db", POLICY, key=KEY, preview_context=context,
                     preview_timeout=5.0) as opened_ledger:  # fmt: skip
        yield opened_ledger


def _recorder() -> tuple[list[dict[str, object]], Callable[..., object]]:
    calls: list[dict[str, object]] = []

    def tool(**kwargs: object) -> object:
        calls.append(kwargs)
        return {"ok": True}

    return calls, tool


def _preview(ledger: Ledger, handle: RunHandle) -> Preview | None:
    """The stored preview of the run's last call."""
    intent = ledger.intent_by_key(handle.last_idempotency_key)
    assert intent is not None
    return ledger.preview_of(intent.intent_id)


def test_a_rule_on_rows_affected_denies_a_big_delete(ledger: Ledger, shop: Path) -> None:
    calls, tool = _recorder()
    with ledger.run("alice", "agent") as handle, pytest.raises(ActionDenied) as denied:
        ledger.execute(DB_SPEC, {"sql": "DELETE FROM orders WHERE status = 'old'"}, tool)
    assert denied.value.rule_id == "big-delete"
    assert calls == []
    assert _rows(shop) == 2000  # the preview counted, it did not delete
    preview = _preview(ledger, handle)
    assert preview is not None
    assert preview.ok
    assert preview.summary == "DELETE would remove 1,500 rows from orders"
    assert preview.facts["rows_affected"] == 1500


def test_a_small_delete_is_allowed_and_runs(ledger: Ledger) -> None:
    calls, tool = _recorder()
    with ledger.run("alice", "agent") as handle:
        result = ledger.execute(DB_SPEC, {"sql": "DELETE FROM orders WHERE id <= 10"}, tool)
    assert result == {"ok": True}
    assert len(calls) == 1
    preview = _preview(ledger, handle)
    assert preview is not None
    assert preview.facts["rows_affected"] == 10


async def test_async_calls_are_previewed_too(ledger: Ledger) -> None:
    calls, tool = _recorder()
    with ledger.run("alice", "agent"), pytest.raises(ActionDenied):
        await ledger.aexecute(DB_SPEC, {"sql": "DELETE FROM orders"}, tool)
    assert calls == []
    with ledger.run("alice", "agent"):
        await ledger.aexecute(DB_SPEC, {"sql": "DELETE FROM orders WHERE id = 1"}, tool)
    assert len(calls) == 1


def test_a_failed_preview_takes_the_stricter_outcome(tmp_path: Path) -> None:
    calls, tool = _recorder()
    with Ledger.open(tmp_path / "l.db", POLICY, key=KEY) as plain:
        # No connection in the preview context: the preview fails, and the
        # deny rule counts as matching rather than the allow rule.
        with plain.run("a", "b") as handle, pytest.raises(ActionDenied) as denied:
            plain.execute(DB_SPEC, {"sql": "DELETE FROM orders WHERE id = 1"}, tool)
        assert denied.value.rule_id == "big-delete"
        preview = _preview(plain, handle)
    assert preview is not None
    assert not preview.ok
    assert calls == []


def test_a_slow_preview_times_out_and_fails_safe(tmp_path: Path) -> None:
    policy = load_policy(
        """
version: 1
rules:
  - id: small
    when: { tool: db.exec, preview: [{ path: "$.rows_affected", op: lt, value: 10 }] }
    then: allow
    reason: Small changes are fine.
"""
    )
    spec = ToolSpec(name="db.exec", effect="destructive", preview="custom_previewers:slow")
    calls, tool = _recorder()
    custom_previewers.RELEASE.clear()
    try:
        with Ledger.open(tmp_path / "l.db", policy, key=KEY, preview_timeout=0.05) as slow:
            with slow.run("a", "b") as handle, pytest.raises(ApprovalPending) as pending:
                slow.execute(spec, {"sql": "DELETE FROM orders WHERE id = 1"}, tool)
            assert pending.value.rule_id == "default"  # not the allow rule
            preview = _preview(slow, handle)
    finally:
        custom_previewers.RELEASE.set()
    assert preview is not None
    assert preview.summary == "Preview timed out after 0.05s"
    assert calls == []


def test_the_stored_preview_is_redacted(tmp_path: Path) -> None:
    spec = ToolSpec(name="db.exec", effect="destructive", preview="custom_previewers:big")
    _, tool = _recorder()
    with Ledger.open(tmp_path / "l.db", POLICY, key=KEY) as led:
        with led.run("a", "b") as handle, pytest.raises(ActionDenied):
            led.execute(spec, {"sql": "DELETE FROM orders"}, tool)
        preview = _preview(led, handle)
        assert "tok-123456789" not in led.export_text()
        assert led.verify().ok
    assert preview is not None
    assert preview.facts["rows_affected"] == 5000
    assert "tok-123456789" not in str(preview.facts["api_token"])
    assert preview.summary == "DELETE would remove 5,000 rows from orders"


def test_file_previews_reach_the_gate(ledger: Ledger, tmp_path: Path) -> None:
    folder = tmp_path / "srv"
    (folder / "backups").mkdir(parents=True)
    (folder / "backups" / "db.bak").write_bytes(b"x")
    (folder / "app.log").write_bytes(b"y")
    spec = ToolSpec(name="shell.run", effect="write")
    calls, tool = _recorder()
    with ledger.run("a", "b"), pytest.raises(ApprovalPending) as pending:
        ledger.execute(spec, {"command": f"rm -rf {folder.as_posix()}"}, tool)
    assert pending.value.rule_id == "backups"
    assert (folder / "backups" / "db.bak").exists()
    with ledger.run("a", "b"):
        ledger.execute(spec, {"command": f"rm -rf {(folder / 'app.log').as_posix()}"}, tool)
    assert len(calls) == 1


def test_reads_and_inserts_are_not_previewed(ledger: Ledger) -> None:
    read = ToolSpec(name="db.query", effect="read", preview="custom_previewers:big")
    insert = ToolSpec(name="db.exec", effect="write")
    custom_previewers.CALLS.clear()
    _, tool = _recorder()
    with ledger.run("a", "b") as handle:
        ledger.execute(read, {"sql": "SELECT * FROM orders"}, tool)
        assert _preview(ledger, handle) is None
        ledger.execute(insert, {"sql": "INSERT INTO orders (status) VALUES ('x')"}, tool)
        assert _preview(ledger, handle) is None
    assert custom_previewers.CALLS == []
    assert ledger.preview_of("no-such-intent") is None


APPROVE_DELETES = load_policy("""
version: 1
rules:
  - id: deletes-need-a-human
    when: { tool: db.exec }
    then: require_approval
    reason: Deletes need a human.
""")


def test_the_approval_card_shows_the_preview(tmp_path: Path) -> None:
    spec = ToolSpec(name="db.exec", effect="destructive", preview="custom_previewers:big")
    with Ledger.open(tmp_path / "l.db", APPROVE_DELETES, key=KEY) as led:
        with led.run("a", "b"), pytest.raises(ApprovalPending) as err:
            led.execute(spec, {"sql": "DELETE FROM orders"}, lambda **kw: None)
        card = led.approval_card(err.value.approval_id)
    assert card["preview"]["summary"] == "DELETE would remove 5,000 rows from orders"
    assert card["preview"]["facts"]["rows_affected"] == 5000
    assert "tok-123456789" not in json.dumps(card)
    assert "Preview: DELETE would remove 5,000 rows from orders" in card["text"]


def test_a_preview_that_timed_out_is_marked_on_the_card(tmp_path: Path) -> None:
    spec = ToolSpec(name="db.exec", effect="destructive", preview="custom_previewers:slow")
    custom_previewers.RELEASE.clear()
    try:
        with Ledger.open(tmp_path / "l.db", APPROVE_DELETES, key=KEY, preview_timeout=0.2) as led:
            with led.run("a", "b"), pytest.raises(ApprovalPending) as err:
                led.execute(spec, {"sql": "DELETE FROM orders"}, lambda **kw: None)
            card = led.approval_card(err.value.approval_id)
    finally:
        custom_previewers.RELEASE.set()
    assert card["preview"]["ok"] is False
    assert "PREVIEW FAILED" in card["text"]
    assert "timed out" in card["text"]


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM orders WHERE status = 'old' RETURNING id",
        "WITH x AS (SELECT 1) DELETE FROM orders WHERE status = 'old'",
        "UPDATE orders SET status = 'x' FROM orders AS o2 WHERE orders.id = o2.id",
        "DELETE FROM orders WHERE status = 'old'; SELECT 1",
    ],
)
def test_sql_a_preview_cannot_count_still_fails_safe(ledger: Ledger, sql: str) -> None:
    """A write the previewer cannot count is held by the stricter rule, never let through."""
    spec = ToolSpec(name="db.exec", effect="write")
    _, tool = _recorder()
    with ledger.run("a", "b"), pytest.raises(ActionDenied):
        ledger.execute(spec, {"sql": sql}, tool)
