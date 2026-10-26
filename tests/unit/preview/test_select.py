"""Which previewer runs for an action, and when none does."""

from __future__ import annotations

import pytest

from arbitr.core.spec import ResourceRef, ToolSpec
from arbitr.preview import default_previewer, load_previewer, preview_action
from arbitr.preview.email import preview_email
from arbitr.preview.files import preview_files
from arbitr.preview.payments import preview_payments
from arbitr.preview.sql import preview_sql


def _refs(*kinds: str) -> tuple[ResourceRef, ...]:
    return tuple(ResourceRef(kind=k, uri=f"{k}-x") for k in kinds)


@pytest.mark.parametrize(
    ("effect", "kinds", "expected"),
    [
        ("destructive", ("table", "path"), preview_sql),
        ("destructive", ("path", "email"), preview_files),
        ("destructive", ("email",), preview_email),
        ("financial", (), preview_payments),
        ("financial", ("url",), preview_payments),
        ("destructive", ("url",), None),
        ("destructive", (), None),
    ],
)
def test_default_previewer_follows_resource_kinds(
    effect: str, kinds: tuple[str, ...], expected: object
) -> None:
    assert default_previewer(effect, _refs(*kinds)) is expected


def test_reads_and_unlisted_effects_are_never_previewed() -> None:
    spec = ToolSpec(name="db.exec", effect="write")
    sql = {"sql": "DELETE FROM t WHERE id = 1"}
    assert preview_action(spec, "read", _refs("table"), sql, context={}, timeout_s=1.0) is None
    assert preview_action(spec, "destructive", _refs("url"), {}, context={}, timeout_s=1.0) is None


@pytest.mark.parametrize(
    ("sql", "previewed"),
    [
        ("DELETE FROM orders WHERE id < 10", True),
        ("UPDATE orders SET paid = 1 WHERE id = 3", True),
        ("INSERT INTO orders VALUES (1)", False),
        ("SELECT * FROM orders", False),
    ],
)
def test_sql_writes_that_change_rows_are_previewed(sql: str, previewed: bool) -> None:
    spec = ToolSpec(name="db.exec", effect="write")
    preview = preview_action(spec, "write", _refs("table"), {"sql": sql}, context={}, timeout_s=1.0)
    assert (preview is not None) is previewed


def test_messages_with_recipients_are_previewed() -> None:
    spec = ToolSpec(name="email.send", effect="external_comm")
    args = {"to": ["a@example.com", "b@other.org"]}
    preview = preview_action(spec, "external_comm", _refs("email"), args, context={},
                             timeout_s=1.0)  # fmt: skip
    assert preview is not None
    assert preview.facts["recipients"] == 2
    assert preview_action(spec, "external_comm", _refs("url"), {}, context={},
                          timeout_s=1.0) is None  # fmt: skip


def test_a_named_previewer_runs_for_any_effect_but_read() -> None:
    spec = ToolSpec(name="db.exec", effect="write", preview="custom_previewers:big")
    preview = preview_action(spec, "write", (), {}, context={}, timeout_s=1.0)
    assert preview is not None
    assert preview_action(spec, "read", (), {}, context={}, timeout_s=1.0) is None


def test_a_named_previewer_wins_over_the_default() -> None:
    spec = ToolSpec(name="db.exec", effect="destructive", preview="custom_previewers:big")
    preview = preview_action(spec, "destructive", _refs("path"), {}, context={}, timeout_s=1.0)
    assert preview is not None
    assert preview.facts["rows_affected"] == 5000


@pytest.mark.parametrize(
    "path", ["custom_previewers:missing", "no_such_module:fn", "custom_previewers:NOT_CALLABLE"]
)
def test_a_previewer_that_cannot_load_gives_a_failed_preview(path: str) -> None:
    spec = ToolSpec(name="t", effect="destructive", preview=path)
    preview = preview_action(spec, "destructive", (), {}, context={}, timeout_s=1.0)
    assert preview is not None
    assert not preview.ok
    assert "could not be loaded" in preview.summary


def test_load_previewer_resolves_nested_names() -> None:
    assert load_previewer("arbitr.preview.sql:preview_sql") is preview_sql


def test_spec_checks_the_preview_path() -> None:
    with pytest.raises(ValueError, match=r"package\.module:function"):
        ToolSpec(name="t", effect="write", preview="not a path")


@pytest.mark.parametrize(
    ("sql", "changes"),
    [
        ("REPLACE INTO orders VALUES (1)", True),
        ("INSERT INTO orders VALUES (1) ON CONFLICT (id) DO UPDATE SET status = 'x'", True),
        ("CALL purge_everything()", True),
        ("SELECT * INTO orders_copy FROM orders", True),
        ("VACUUM", True),
        ("INSERT INTO orders VALUES (1)", False),
        ("SELECT * FROM orders", False),
    ],
)
def test_only_plain_reads_and_inserts_count_as_not_changing_rows(sql: str, changes: bool) -> None:
    from arbitr.preview.sql import changes_rows  # noqa: PLC0415

    assert changes_rows({"sql": sql}) is changes
