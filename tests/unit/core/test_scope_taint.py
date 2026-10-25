"""Run scope manifests and taint."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from hypothesis import given
from hypothesis import strategies as st

from arbitr.core.errors import ScopeError, StorageError
from arbitr.core.redact import Redactor
from arbitr.core.scope import Scope, check_scope
from arbitr.core.spec import ToolSpec
from arbitr.core.taint import after_tool, merge
from arbitr.policy.engine import GateInput, ResolvedResource, Taint, decide
from arbitr.policy.schema import load_policy
from arbitr.storage.sqlite import SQLiteStorage

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

KEY = b"scope-taint-key!" * 2
PROD = ResolvedResource(id="prod", kind="path", uri="/srv/prod/x", tags=frozenset({"production"}))
TESTS = ResolvedResource(id="tests", kind="path", uri="/repo/tests/x", tags=frozenset({"test"}))
BARE = ResolvedResource(id=None, kind="path", uri="/var/scratch/x")

FIX_TEST = Scope(
    task="Fix the failing test in tests/test_api.py",
    allowed_tools=("fs.read", "fs.write", "shell.pytest*"),
    allowed_resource_tags=("test",),
    max_effect="write",
    spend_limit=None,
)


# ---------------------------------------------------------------- scope checks


def test_in_scope_action() -> None:
    v = check_scope(FIX_TEST, tool="fs.write", effect="write", resources=(TESTS,))
    assert not v.outside
    assert v.reasons == ()


@pytest.mark.parametrize(
    ("tool", "effect", "resources", "reason"),
    [
        ("db.exec", "write", (TESTS,), "tool db.exec"),
        ("fs.write", "destructive", (TESTS,), "effect destructive"),
        ("fs.write", "write", (PROD,), "resource"),
        ("fs.write", "write", (BARE,), "resource"),
        ("shell.pytest-x", "write", (TESTS, PROD), "resource"),
    ],
)
def test_out_of_scope_actions(
    tool: str, effect: str, resources: tuple[ResolvedResource, ...], reason: str
) -> None:
    v = check_scope(FIX_TEST, tool=tool, effect=effect, resources=resources)  # type: ignore[arg-type]
    assert v.outside
    assert any(reason in r for r in v.reasons)


def test_tool_globs() -> None:
    assert not check_scope(
        FIX_TEST, tool="shell.pytest-k", effect="read", resources=(TESTS,)
    ).outside


def test_spend_limit() -> None:
    scope = Scope(task="Refund order 123", allowed_tools=("payments.refund",), spend_limit=50)
    ok = check_scope(scope, tool="payments.refund", effect="financial", amount=40, spent=0)
    over = check_scope(scope, tool="payments.refund", effect="financial", amount=40, spent=20)
    assert not ok.outside
    assert over.outside
    assert "spend" in over.reasons[0]


def test_spend_limit_with_unknown_amount_is_outside() -> None:
    scope = Scope(task="t", spend_limit=50)
    assert check_scope(scope, tool="pay", effect="financial", amount=None).outside


def test_empty_scope_allows_everything() -> None:
    assert not check_scope(Scope(task="anything"), tool="x", effect="destructive").outside


def test_reasons_never_quote_the_task_or_arguments() -> None:
    v = check_scope(FIX_TEST, tool="db.exec", effect="destructive", resources=(PROD,))
    assert all("failing test" not in r for r in v.reasons)


# ---------------------------------------------------------------- subsets


@pytest.mark.parametrize(
    "child",
    [
        Scope(
            task="t", allowed_tools=("fs.read",), allowed_resource_tags=("test",), max_effect="read"
        ),
        Scope(
            task="t",
            allowed_tools=("fs.write",),
            allowed_resource_tags=("test",),
            max_effect="write",
        ),
        Scope(
            task="t",
            allowed_tools=("fs.read",),
            allowed_resource_tags=("test",),
            max_effect="write",
            spend_limit=10,
        ),
    ],
)
def test_narrower_child_is_a_subset(child: Scope) -> None:
    assert child.is_within(FIX_TEST)


@pytest.mark.parametrize(
    "child",
    [
        Scope(task="t", allowed_tools=("fs.read", "db.exec"), allowed_resource_tags=("test",)),
        Scope(task="t", allowed_tools=("fs.read",), allowed_resource_tags=("test", "production")),
        Scope(
            task="t",
            allowed_tools=("fs.read",),
            allowed_resource_tags=("test",),
            max_effect="destructive",
        ),
        Scope(task="t", allowed_tools=None, allowed_resource_tags=("test",), max_effect="write"),
        Scope(
            task="t",
            allowed_tools=("shell.*",),
            allowed_resource_tags=("test",),
            max_effect="write",
        ),
        Scope(task="t", allowed_tools=("fs.rea?",), allowed_resource_tags=("test",)),
        Scope(task="t", allowed_tools=("fs.[rw]*",), allowed_resource_tags=("test",)),
    ],
)
def test_wider_child_is_not_a_subset(child: Scope) -> None:
    assert not child.is_within(FIX_TEST)


@pytest.mark.parametrize(
    ("child", "parent", "inside"),
    [
        ("fs.read", "fs.*", True),
        ("fs.*", "fs.*", True),
        ("fs.read*", "fs.*", True),
        ("fs.[ab]", "fs.*", True),
        ("a*c", "a?c", False),
        ("a?c", "a?c", True),
        ("abc", "a?c", True),
        ("fs.r*", "fs.read*", False),
        ("x[*]", "x?", False),
        ("*", "fs.*", False),
    ],
)
def test_tool_glob_subsets(child: str, parent: str, inside: bool) -> None:
    c = Scope(task="t", allowed_tools=(child,))
    assert c.is_within(Scope(task="t", allowed_tools=(parent,))) is inside


def test_spend_limits_nest() -> None:
    parent = Scope(task="t", spend_limit=100)
    assert Scope(task="t", spend_limit=50).is_within(parent)
    assert not Scope(task="t", spend_limit=150).is_within(parent)
    assert not Scope(task="t").is_within(parent)


# ---------------------------------------------------------------- gate integration


POLICY = load_policy("version: 1\n")


def gate(**kw: object) -> GateInput:
    base = GateInput(
        tool="fs.write",
        effect="write",
        args={},
        principal="p",
        agent_id="a",
        run_id="r",
        now=datetime(2026, 10, 25, tzinfo=UTC),
    )
    return replace(base, **kw)  # type: ignore[arg-type]


def test_outside_scope_needs_approval_by_default() -> None:
    d = decide(gate(outside_scope=True), POLICY, {})
    assert (d.outcome, d.rule_id) == ("require_approval", "outside-scope")
    assert "outside the scope" in d.reason


def test_outside_scope_outcome_is_configurable() -> None:
    policy = load_policy("version: 1\non_outside_scope: deny\n")
    assert decide(gate(outside_scope=True), policy, {}).outcome == "deny"


def test_inside_scope_uses_normal_rules() -> None:
    assert decide(gate(), POLICY, {}).rule_id == "default"


def test_a_rule_about_other_tools_does_not_switch_the_scope_floor_off() -> None:
    policy = load_policy(
        "version: 1\nrules:\n"
        "  - id: pay-outside\n"
        "    when: {tool: payments.*, outside_scope: true}\n"
        "    then: deny\n"
        "    reason: Payments outside the run's scope are refused.\n"
    )
    d = decide(gate(outside_scope=True), policy, {})
    assert (d.outcome, d.rule_id) == ("require_approval", "outside-scope")


def test_on_outside_scope_allow_never_lowers_the_default() -> None:
    policy = load_policy("version: 1\non_outside_scope: allow\n")
    d = decide(gate(outside_scope=True, effect="destructive"), policy, {})
    assert (d.outcome, d.rule_id) == ("require_approval", "default")


def test_an_allow_rule_cannot_go_below_the_scope_floor() -> None:
    policy = load_policy(
        "version: 1\nrules:\n  - id: writes-ok\n    when: {tool: fs.write}\n    then: allow\n"
        "    reason: Writes are fine.\n"
    )
    d = decide(gate(outside_scope=True), policy, {})
    assert (d.outcome, d.rule_id) == ("require_approval", "outside-scope")
    assert decide(gate(), policy, {}).outcome == "allow"


def test_a_stricter_rule_still_wins_outside_scope() -> None:
    policy = load_policy(
        "version: 1\nrules:\n  - id: no-writes\n    when: {tool: fs.write}\n    then: deny\n"
        "    reason: No writes.\n"
    )
    d = decide(gate(outside_scope=True), policy, {})
    assert (d.outcome, d.rule_id) == ("deny", "no-writes")


# ---------------------------------------------------------------- taint


def test_taint_only_turns_on() -> None:
    t = Taint(untrusted_input=True, sources=("web.fetch",))
    assert merge(t, Taint()) == t
    assert merge(Taint(), t) == t
    both = merge(t, Taint(private_data=True, sources=("repo.read",)))
    assert (both.untrusted_input, both.private_data) == (True, True)
    assert both.sources == ("repo.read", "web.fetch")


def test_after_tool_sets_flags_from_the_spec() -> None:
    web = ToolSpec(name="web.fetch", effect="read", untrusted_output=True)
    repo = ToolSpec(name="repo.read", effect="read", private_output=True)
    plain = ToolSpec(name="math.add", effect="read")
    t = after_tool(Taint(), web)
    t = after_tool(t, plain)
    t = after_tool(t, repo)
    assert (t.untrusted_input, t.private_data, t.sources) == (
        True,
        True,
        ("repo.read", "web.fetch"),
    )
    assert after_tool(Taint(), plain) == Taint()


flags = st.builds(
    Taint,
    st.booleans(),
    st.booleans(),
    st.lists(st.sampled_from(["a", "b", "c"]), unique=True).map(lambda x: tuple(sorted(x))),
)


@given(flags, flags)
def test_merge_never_decreases(a: Taint, b: Taint) -> None:
    m = merge(a, b)
    assert m.untrusted_input >= max(a.untrusted_input, b.untrusted_input)
    assert m.private_data >= max(a.private_data, b.private_data)
    assert set(a.sources) | set(b.sources) == set(m.sources)
    assert merge(m, a) == m


# ---------------------------------------------------------------- storage


@pytest.fixture
def db(tmp_path: Path) -> Iterator[SQLiteStorage]:
    with SQLiteStorage.open(tmp_path / "ledger.db", Redactor(KEY)) as storage:
        yield storage


def test_schema_is_migrated_to_version_2(db: SQLiteStorage) -> None:
    assert db.schema_version() == 2


def test_run_scope_and_task_are_stored_redacted(db: SQLiteStorage) -> None:
    secret = "sk-ant-api03-" + "z" * 30
    scope = Scope(task=f"Refund order 123 using {secret}", allowed_tools=("payments.refund",))
    with db.transaction() as tx:
        tx.insert_run("r1", "alice", "bot", scope=scope)
        run = tx.get_run("r1")
    assert run is not None
    assert run.scope is not None
    assert run.scope.allowed_tools == ("payments.refund",)
    assert secret not in (run.scope.task or "")
    assert "Refund order 123" in (run.scope.task or "")


def test_child_run_cannot_widen_its_parent_scope(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.insert_run("p", "alice", "bot", scope=FIX_TEST, scopes=("tests",))
        tx.insert_run(
            "c1",
            "alice",
            "sub",
            parent_run_id="p",
            scope=Scope(
                task="read only",
                allowed_tools=("fs.read",),
                allowed_resource_tags=("test",),
                max_effect="read",
            ),
            scopes=("tests",),
        )
    with pytest.raises(ScopeError, match="wider"), db.transaction() as tx:
        tx.insert_run(
            "c2",
            "alice",
            "sub",
            parent_run_id="p",
            scope=Scope(task="t", allowed_tools=("db.exec",)),
        )
    with pytest.raises(ScopeError, match="scopes"), db.transaction() as tx:
        tx.insert_run(
            "c3", "alice", "sub", parent_run_id="p", scope=FIX_TEST, scopes=("tests", "admin")
        )


def test_child_of_an_unknown_parent_is_refused(db: SQLiteStorage) -> None:
    with pytest.raises(StorageError), db.transaction() as tx:
        tx.insert_run("c", "alice", "sub", parent_run_id="nope")


def test_child_inherits_the_parent_scope_when_it_declares_none(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.insert_run("p", "alice", "bot", scope=FIX_TEST)
        tx.insert_run("c", "alice", "sub", parent_run_id="p")
        child = tx.get_run("c")
    assert child is not None
    assert child.scope is not None
    assert child.scope.allowed_tools == FIX_TEST.allowed_tools


def test_taint_flows_down_the_run_tree_and_never_decreases(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.insert_run("p", "alice", "bot")
        tx.insert_run("c", "alice", "sub", parent_run_id="p")
        tx.insert_run("g", "alice", "subsub", parent_run_id="c")
        tx.add_taint("p", Taint(untrusted_input=True, sources=("web.fetch",)))
        tx.add_taint("c", Taint(private_data=True, sources=("repo.read",)))
        tx.add_taint("g", Taint())  # adding nothing changes nothing
        p, c, g = tx.get_run("p"), tx.get_run("c"), tx.get_run("g")
    assert p is not None
    assert c is not None
    assert g is not None
    # The child's private data flows up to the parent too.
    assert (p.taint.untrusted_input, p.taint.private_data) == (True, True)
    assert (c.taint.untrusted_input, c.taint.private_data) == (True, True)
    assert (g.taint.untrusted_input, g.taint.private_data) == (True, True)
    assert db.verify().ok


def test_new_child_starts_with_the_parent_taint(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.insert_run("p", "alice", "bot")
        tx.add_taint("p", Taint(untrusted_input=True))
        tx.insert_run("c", "alice", "sub", parent_run_id="p")
        child = tx.get_run("c")
    assert child is not None
    assert child.taint.untrusted_input


def test_taint_events_are_reserved(db: SQLiteStorage) -> None:
    with pytest.raises(StorageError, match="reserved"), db.transaction() as tx:
        tx.append_event("taint_added", {})


def test_taint_flows_up_to_every_ancestor_but_not_to_siblings(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.insert_run("p", "alice", "bot")
        tx.insert_run("c", "alice", "sub", parent_run_id="p")
        tx.insert_run("s", "alice", "sibling", parent_run_id="p")
        tx.insert_run("g", "alice", "subsub", parent_run_id="c")
        tx.add_taint("g", Taint(untrusted_input=True, sources=("web.fetch",)))
        runs = {rid: tx.get_run(rid) for rid in ("p", "c", "s", "g")}
    assert all(r is not None for r in runs.values())
    assert runs["p"].taint.untrusted_input  # type: ignore[union-attr]
    assert runs["c"].taint.untrusted_input  # type: ignore[union-attr]
    assert not runs["s"].taint.untrusted_input  # type: ignore[union-attr]
    assert db.verify().ok


def test_a_sub_agent_cannot_launder_untrusted_input(db: SQLiteStorage) -> None:
    from arbitr.policy.packs import PACKS  # noqa: PLC0415

    assert "lethal-trifecta" in PACKS
    policy = load_policy("version: 1\ninclude: [lethal-trifecta]\n")
    with db.transaction() as tx:
        tx.insert_run("parent", "alice", "bot")
        tx.insert_run("child", "alice", "browser", parent_run_id="parent")
        tx.add_taint("child", Taint(untrusted_input=True, sources=("web.fetch",)))
        tx.add_taint("parent", Taint(private_data=True, sources=("repo.read",)))
        parent = tx.get_run("parent")
    assert parent is not None
    d = decide(gate(tool="email.send", effect="external_comm", taint=parent.taint), policy, {})
    assert (d.outcome, d.rule_id) == ("require_approval", "lethal-trifecta.outbound-after-both")


def test_a_child_cannot_shadow_an_enforcing_parent(db: SQLiteStorage) -> None:
    with db.transaction() as tx:
        tx.insert_run("p", "alice", "bot", mode="enforce")
    with pytest.raises(ScopeError, match="shadow"), db.transaction() as tx:
        tx.insert_run("c", "alice", "sub", parent_run_id="p", mode="shadow")
    with db.transaction() as tx:
        tx.insert_run("sp", "alice", "bot", mode="shadow")
        tx.insert_run("sc", "alice", "sub", parent_run_id="sp", mode="enforce")
    with pytest.raises(StorageError, match="mode"), db.transaction() as tx:
        tx.insert_run("x", "alice", "bot", mode="audit")
