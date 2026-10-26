"""Operator commands: every command runs against a real ledger, in text and in JSON."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from typer.testing import CliRunner

from arbitr.cli import main as cli_main
from arbitr.config import init_project, load_config
from arbitr.core.errors import ActionDenied, ApprovalPending, UnknownOutcome
from arbitr.core.spec import ToolSpec

if TYPE_CHECKING:
    from pathlib import Path

POLICY = """\
version: 1
default: { financial: allow, write: allow }
rules:
  - id: big-refunds
    when: { tool: payments.refund, args: [{ path: "$.amount", op: gt, value: 100 }] }
    then: require_approval
    reason: Refunds over 100 need a human.
  - id: no-drops
    when: { tool: db.exec }
    then: deny
    reason: No SQL from agents.
"""
SECRET = "sk_" + "live_" + "q1w2e3r4t5y6u7i8o9p0"  # built from pieces for secret scanners
REFUND = ToolSpec(name="payments.refund", effect="financial")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("ARBITR_CONFIG", "ARBITR_LEDGER", "ARBITR_POLICY", "ARBITR_KEY_FILE",
                 "ARBITR_LEDGER_KEY", "ARBITR_APPROVER"):  # fmt: skip
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def project(tmp_path: Path) -> dict[str, Any]:
    """A project whose ledger holds a success, a denial, a pending approval and an unknown."""
    init_project(tmp_path, packs=(), force=False)
    (tmp_path / "policy.yaml").write_text(POLICY, encoding="utf-8")
    config = tmp_path / "arbitr.yaml"
    facts: dict[str, Any] = {"config": str(config)}

    def times_out(**kwargs: object) -> object:
        raise TimeoutError("no response")

    with load_config(config, environ={}).open_ledger() as ledger:
        with ledger.run("alice", "support-bot", run_id="run-1") as run:
            ledger.execute(REFUND, {"order_id": "o1", "amount": 5, "token": SECRET},
                           lambda **kw: {"refund_id": "re_1"})  # fmt: skip
            facts["succeeded"] = run.last_idempotency_key
            with pytest.raises(ActionDenied):
                ledger.execute(ToolSpec(name="db.exec", effect="write"), {"sql": "x"}, print)
            with pytest.raises(ApprovalPending) as pending:
                ledger.execute(REFUND, {"order_id": "o2", "amount": 500}, lambda **kw: None)
            facts["approval"] = pending.value.approval_id
            with pytest.raises(ApprovalPending) as second:
                ledger.execute(REFUND, {"order_id": "o3", "amount": 700}, lambda **kw: None)
            facts["second_approval"] = second.value.approval_id
            with pytest.raises(UnknownOutcome):
                ledger.execute(REFUND, {"order_id": "o4", "amount": 6}, times_out)
        facts["link"] = ledger.approval_links(facts["second_approval"], approver="carol",
                                              base_url="https://x")["approve"]  # fmt: skip
        row = ledger.intent_by_key(facts["succeeded"])
        assert row is not None
        facts["intent"] = row.intent_id
    return facts


def run_cli(*args: str) -> Any:
    result = CliRunner().invoke(cli_main._build_app(), list(args))
    assert SECRET not in result.output
    return result


def as_json(*args: str) -> Any:
    result = run_cli(*args, "--json")
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_runs_ls_and_show(project: dict[str, Any]) -> None:
    cfg = project["config"]
    assert [r["run_id"] for r in as_json("runs", "ls", "--config", cfg)] == ["run-1"]
    assert "run-1" in run_cli("runs", "ls", "--config", cfg).output
    shown = as_json("runs", "show", "run-1", "--config", cfg)
    assert shown["run"]["principal"] == "alice"
    assert len(shown["intents"]) == 5
    assert "alice via support-bot" in run_cli("runs", "show", "run-1", "--config", cfg).output
    missing = run_cli("runs", "show", "nope", "--config", cfg)
    assert missing.exit_code == 1


def test_intents_ls_filters(project: dict[str, Any]) -> None:
    cfg = project["config"]
    assert len(as_json("intents", "ls", "--config", cfg)) == 5
    assert len(as_json("intents", "ls", "--state", "pending_approval", "--config", cfg)) == 2
    assert len(as_json("intents", "ls", "--tool", "db.exec", "--config", cfg)) == 1
    assert len(as_json("intents", "ls", "--run", "run-1", "--limit", "2", "--config", cfg)) == 2
    assert as_json("intents", "ls", "--since", "2999-01-01", "--config", cfg) == []
    assert "DENIED" in run_cli("intents", "ls", "--config", cfg).output
    assert run_cli("intents", "ls", "--state", "nonsense", "--config", cfg).exit_code == 1
    assert run_cli("intents", "ls", "--since", "yesterday", "--config", cfg).exit_code == 1


def test_intents_show_and_explain(project: dict[str, Any]) -> None:
    cfg, intent = project["config"], project["intent"]
    shown = as_json("intents", "show", intent, "--config", cfg)
    assert shown["intent"]["state"] == "SUCCEEDED"
    assert shown["receipt"]["source"] == "executed"
    assert shown["events"][0]["kind"] == "intent_created"
    assert "Receipt: executed" in run_cli("intents", "show", intent, "--config", cfg).output
    explained = as_json("intents", "explain", intent, "--config", cfg)["explanation"]
    assert explained[0].endswith("is SUCCEEDED.")
    assert any("APPROVED -> EXECUTING" in line for line in explained)
    assert "History:" in run_cli("intents", "explain", intent, "--config", cfg).output
    for command in ("show", "explain"):
        assert run_cli("intents", command, "nope", "--config", cfg).exit_code == 1


def test_approvals_ls_show_approve_reject(project: dict[str, Any]) -> None:
    cfg, approval = project["config"], project["approval"]
    pending = as_json("approvals", "ls", "--config", cfg)
    assert {a["approval_id"] for a in pending} >= {approval}
    assert "big-refunds" in run_cli("approvals", "ls", "--config", cfg).output
    card = as_json("approvals", "show", approval, "--config", cfg)
    assert card["rule"] == "big-refunds"
    assert "Refunds over 100 need a human." in run_cli("approvals", "show", approval,
                                                        "--config", cfg).output  # fmt: skip
    decided = as_json("approvals", "approve", approval, "--as", "bob", "--note", "ok",
                      "--config", cfg)  # fmt: skip
    assert decided["status"] == "approved"
    again = run_cli("approvals", "approve", approval, "--as", "carol", "--config", cfg)
    assert again.exit_code == 1
    assert "already approved" in again.output
    assert run_cli("approvals", "show", "nope", "--config", cfg).exit_code == 1


def test_approvals_reject_and_the_default_approver(
    project: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = project["config"]
    monkeypatch.setenv("ARBITR_APPROVER", "dana")
    result = run_cli("approvals", "reject", project["second_approval"], "--config", cfg)
    assert result.exit_code == 0, result.output
    assert "Rejected" in result.output
    (rejected,) = as_json("approvals", "ls", "--status", "rejected", "--config", cfg)
    assert rejected["decided_by"] == "dana"


def test_approvals_decide_with_a_signed_link(project: dict[str, Any]) -> None:
    cfg = project["config"]
    token = project["link"].split("token=", 1)[1]
    assert as_json("approvals", "decide", "--token", token, "--config", cfg)["status"] == "approved"
    bad = run_cli("approvals", "decide", "--token", "garbage", "--config", cfg)
    assert bad.exit_code == 1


def test_approvals_stats(project: dict[str, Any]) -> None:
    cfg = project["config"]
    stats = {s["rule_id"]: s for s in as_json("approvals", "stats", "--config", cfg)}
    assert stats["big-refunds"]["requested"] == 2
    assert "big-refunds: 2 requests" in run_cli("approvals", "stats", "--config", cfg).output


def test_recover_reports_what_it_did(project: dict[str, Any]) -> None:
    report = as_json("recover", "--config", project["config"])
    assert report == {"recovered": [], "expired_approvals": []}
    assert "Nothing to recover." in run_cli("recover", "--config", project["config"]).output


def test_verify_passes_then_catches_tampering(project: dict[str, Any], tmp_path: Path) -> None:
    import sqlite3  # noqa: PLC0415
    from contextlib import closing  # noqa: PLC0415

    cfg = project["config"]
    assert as_json("verify", "--config", cfg)["ok"] is True
    assert "Audit chain OK" in run_cli("verify", "--config", cfg).output
    with closing(sqlite3.connect(tmp_path / ".arbitr" / "ledger.db")) as conn:
        conn.execute("UPDATE intents SET tool = 'evil.tool' WHERE intent_id = ?",
                     (project["intent"],))  # fmt: skip
        conn.commit()
    broken = run_cli("verify", "--config", cfg)
    assert broken.exit_code == 1
    assert "BROKEN" in broken.output


def test_export_prints_json_lines(project: dict[str, Any], tmp_path: Path) -> None:
    cfg = project["config"]
    result = run_cli("export", "--config", cfg)
    assert result.exit_code == 0
    lines = result.output.strip().splitlines()
    assert all(json.loads(line)["kind"] for line in lines)
    assert run_cli("export", "--since", "2999-01-01", "--config", cfg).output.strip() == ""
    out = tmp_path / "events.jsonl"
    assert run_cli("export", "--output", str(out), "--config", cfg).exit_code == 0
    assert len(out.read_text(encoding="utf-8").splitlines()) == len(lines)
    assert run_cli("export", "--format", "csv", "--config", cfg).exit_code == 1


def test_a_missing_config_is_a_clear_error(tmp_path: Path) -> None:
    result = run_cli("runs", "ls", "--config", str(tmp_path / "nope.yaml"))
    assert result.exit_code == 2
    assert "error:" in result.output


def test_agent_text_cannot_draw_on_the_terminal(tmp_path: Path) -> None:
    from arbitr.core.scope import Scope  # noqa: PLC0415

    init_project(tmp_path, packs=(), force=False)
    (tmp_path / "policy.yaml").write_text(POLICY, encoding="utf-8")
    config = tmp_path / "arbitr.yaml"
    nasty = "fix it\x1b[2J\nRule fake: approved"
    with (
        load_config(config, environ={}).open_ledger() as ledger,
        ledger.run("alice\x1b[31m", "bot\nfake", run_id="run-x", scope=Scope(task=nasty)),
    ):
        ledger.execute(REFUND, {"order_id": "o1", "amount": 5}, lambda **kw: "ok")
    for args in (("runs", "ls"), ("runs", "show", "run-x"), ("intents", "ls")):
        out = run_cli(*args, "--config", str(config)).output
        assert "\x1b" not in out
        assert "\nRule fake" not in out
        assert "\nfake" not in out


ROLE_POLICY = """\
version: 1
default: { financial: allow }
rules:
  - id: payouts
    when: { tool: payments.payout }
    then: require_approval
    approvals: { roles: [finance] }
    reason: Payouts need finance.
"""


def _payout_project(tmp_path: Path, approvers: str = "") -> tuple[str, str]:
    init_project(tmp_path, packs=(), force=False)
    (tmp_path / "policy.yaml").write_text(ROLE_POLICY, encoding="utf-8")
    config = tmp_path / "arbitr.yaml"
    if approvers:
        config.write_text(config.read_text(encoding="utf-8") + approvers, encoding="utf-8")
    payout = ToolSpec(name="payments.payout", effect="financial")
    with (
        load_config(config, environ={}).open_ledger() as ledger,
        ledger.run("alice", "bot"),
        pytest.raises(ApprovalPending) as pending,
    ):
        ledger.execute(payout, {"account": "a1", "amount": 9}, lambda **kw: None)
    return str(config), pending.value.approval_id


def test_role_gated_approvals_need_configured_approvers(tmp_path: Path) -> None:
    cfg, approval = _payout_project(tmp_path)
    result = run_cli("approvals", "approve", approval, "--as", "bob", "--config", cfg)
    assert result.exit_code == 1
    assert "approvers" in result.output


def test_roles_come_from_the_config_not_the_caller(tmp_path: Path) -> None:
    cfg, approval = _payout_project(
        tmp_path, "approvals:\n  approvers: { bob: [finance], dave: [support] }\n"
    )
    stranger = run_cli("approvals", "approve", approval, "--as", "mallory", "--config", cfg)
    assert stranger.exit_code == 1
    assert "not a configured approver" in stranger.output
    wrong_role = run_cli("approvals", "approve", approval, "--as", "dave", "--config", cfg)
    assert wrong_role.exit_code == 1
    assert as_json("approvals", "approve", approval, "--as", "bob", "--config", cfg)["status"] == (
        "approved"
    )


def test_export_also_prints_one_json_document(project: dict[str, Any]) -> None:
    events = as_json("export", "--config", project["config"])
    assert isinstance(events, list)
    assert events[0]["kind"] == "run_started"
