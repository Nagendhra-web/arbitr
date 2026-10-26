"""Operator commands: runs, intents, approvals, recovery, verification and export.

Every command opens the ledger from the configuration (``--config``, then
``ARBITR_CONFIG``, then ``arbitr.yaml``) and supports ``--json``, which prints
one JSON document (``export`` prints JSON lines). Nothing here prints secrets:
arguments and results are shown as the ledger stores them, redacted. Text
output puts anything an agent supplied on one line with control characters
removed, so it cannot draw on the terminal or fake a line.
"""

from __future__ import annotations

import getpass
import json
import os
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 - typer reads the annotations at runtime
from typing import TYPE_CHECKING, Any, NoReturn

from arbitr.approvals import clean_text, quote_text

if TYPE_CHECKING:
    from collections.abc import Iterator

    import typer

    from arbitr.core.audit import Event
    from arbitr.executor import Ledger
    from arbitr.storage.sqlite import ApprovalRow, IntentRow, RunRow

CONFIG_HELP = "The config file (default: ARBITR_CONFIG, then arbitr.yaml)."
JSON_HELP = "Print machine-readable JSON."
APPROVER_HELP = "Who decides (default: ARBITR_APPROVER, then your user name)."
STATUS_HELP = "pending, approved, rejected, expired or all."
SINCE_HELP = "Only from this time on (an ISO date or time, UTC unless it says otherwise)."


def _fail(message: str, code: int = 1) -> NoReturn:
    import typer  # noqa: PLC0415 - the cli extra is imported lazily

    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code)


@contextmanager
def _ledger(config: Path | None) -> Iterator[Ledger]:
    from arbitr.config import ConfigError, load_config  # noqa: PLC0415

    try:
        ledger = load_config(config).open_ledger()
    except ConfigError as exc:
        _fail(str(exc), 2)
    with ledger:
        yield ledger


def _emit(as_json: bool, data: object, lines: list[str]) -> None:
    import typer  # noqa: PLC0415

    if as_json:
        typer.echo(json.dumps(data, sort_keys=True, default=str))
        return
    for line in lines:
        typer.echo(line)


def _since(value: str | None) -> str | None:
    """An ISO date or time (UTC when no zone is given) as a database time."""
    if value is None:
        return None
    from arbitr.storage.sqlite import format_db_time  # noqa: PLC0415

    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        _fail(f"--since needs an ISO date or time (2026-10-25 or 2026-10-25T14:00), not {value!r}")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return format_db_time(moment)


def _approver(name: str | None) -> str:
    return name or os.environ.get("ARBITR_APPROVER") or getpass.getuser()


def _configured_approvers(config: Path | None) -> dict[str, tuple[str, ...]]:
    from arbitr.config import load_config  # noqa: PLC0415

    return dict(load_config(config).approvals.approvers)


def _roles_for(
    name: str, approval: ApprovalRow, approvers: dict[str, tuple[str, ...]]
) -> tuple[str, ...]:
    """The roles an approver holds, from the config. Callers cannot claim roles.

    Without configured approvers, only approvals anyone may give alone can be
    decided here: a quorum or a role means the config must say who is who.
    """
    if approvers:
        if name not in approvers:
            _fail(f"{name} is not a configured approver (see approvals.approvers in the config)")
        return approvers[name]
    if approval.required > 1 or approval.allowed_roles():
        _fail("this approval needs specific roles or several people; list who holds which roles"
              " under approvals.approvers in the config")  # fmt: skip
    return ()


# ---------------------------------------------------------------- views


def _run_view(run: RunRow) -> dict[str, object]:
    return {
        "run_id": run.run_id,
        "principal": run.principal,
        "agent_id": run.agent_id,
        "parent_run_id": run.parent_run_id,
        "mode": run.mode,
        "created_at": run.created_at,
        "taint": run.taint.to_dict(),
        "scopes": list(run.scopes),
        "task": run.scope.task if run.scope is not None else None,
    }


def _intent_view(row: IntentRow) -> dict[str, object]:
    return {
        "intent_id": row.intent_id,
        "run_id": row.run_id,
        "tool": row.tool,
        "state": row.state.value,
        "decision": row.decision,
        "rule": row.decision_rule,
        "reason": row.decision_reason,
        "attempt": row.attempt,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "args": json.loads(row.args_redacted),
    }


def _intent_line(row: IntentRow) -> str:
    rule = f" by {clean_text(row.decision_rule)}" if row.decision_rule else ""
    return (
        f"{row.intent_id}  {row.state.value:<16} {clean_text(row.tool)}{rule}  ({row.created_at})"
    )


def _approval_view(row: ApprovalRow) -> dict[str, object]:
    return {
        "approval_id": row.approval_id,
        "intent_id": row.intent_id,
        "status": row.status,
        "rule": row.rule_id,
        "required": row.required,
        "roles": list(row.allowed_roles()),
        "requested_at": row.requested_at,
        "expires_at": row.expires_at,
        "decided_by": row.decided_by,
        "decided_at": row.decided_at,
        "summary": json.loads(row.summary) if row.summary else None,
    }


def _approval_line(row: ApprovalRow) -> str:
    card = json.loads(row.summary) if row.summary else {}
    need = f", needs {row.required}" if row.required > 1 else ""
    tool = clean_text(card.get("tool", "?"))
    until = f"(until {row.expires_at})"
    return f"{row.approval_id}  {row.status:<9} {tool}  rule {row.rule_id}{need}  {until}"


def explain_lines(row: IntentRow, events: list[Event]) -> list[str]:
    """What happened to an intent, in plain English, from its own events."""
    lines = [f"{clean_text(row.tool)} (intent {row.intent_id}) is {row.state.value}."]
    if row.decision is not None:
        rule = clean_text(row.decision_rule)
        lines.append(f"The gate decided {row.decision} by rule {rule}.")
        lines.append(f"Reason: {clean_text(row.decision_reason)}")
    if row.shadow_decision and row.shadow_decision != row.decision:
        lines.append(f"Enforce mode would have decided {row.shadow_decision}.")
    lines.append("History:")
    for event in events:
        payload = json.loads(event.payload)
        lines.append(f"  {event.created_at}  {_event_text(event.kind, payload)}")
    return lines


def _event_text(kind: str, payload: dict[str, Any]) -> str:
    if "to" in payload and "from" in payload:
        extra = clean_text(payload.get("reason") or payload.get("error") or "")
        moved = f"{clean_text(payload['from'])} -> {clean_text(payload['to'])}"
        return moved + (f" ({extra})" if extra else "")
    if kind == "approval_vote":
        return f"{clean_text(payload.get('approver'))} voted {clean_text(payload.get('decision'))}"
    if kind == "approval_decided":
        return f"approval {clean_text(payload.get('status'))}"
    return clean_text(kind.replace("_", " "))


# ---------------------------------------------------------------- commands


def register(app: typer.Typer) -> None:
    """Add the operator commands to the ``arbitr`` app."""
    app.add_typer(_runs_app(), name="runs")
    app.add_typer(_intents_app(), name="intents")
    approvals = _approvals_app()
    _add_vote_commands(approvals)
    app.add_typer(approvals, name="approvals")
    _add_ledger_commands(app)


def _add_ledger_commands(app: typer.Typer) -> None:
    """recover, verify and export."""
    import typer  # noqa: PLC0415

    @app.command("recover")
    def recover_cmd(
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """Mark stale running actions UNKNOWN and expire approval requests past their time."""
        with _ledger(config) as ledger:
            stale = ledger.recover_stale()
            expired = ledger.expire_approvals()
        data = {
            "recovered": [
                {"intent_id": r.intent_id, "state": r.state.value, "action": r.action}
                for r in stale
            ],
            "expired_approvals": [a.approval_id for a in expired],
        }
        lines = [f"{r.intent_id}  {r.state.value}: {r.action}" for r in stale]
        lines += [f"{a.approval_id}  approval expired" for a in expired]
        _emit(as_json, data, lines or ["Nothing to recover."])

    @app.command("verify")
    def verify_cmd(
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """Check the audit chain and every record against it. Exits 1 when it is broken."""
        with _ledger(config) as ledger:
            result = ledger.verify()
        data = {
            "ok": result.ok,
            "checked": result.checked,
            "broken_seq": result.broken_seq,
            "reason": result.reason,
        }
        if result.ok:
            line = f"Audit chain OK: {result.checked} events checked."
        else:
            line = f"Audit chain BROKEN at event {result.broken_seq}: {result.reason}"
        _emit(as_json, data, [line])
        if not result.ok:
            raise typer.Exit(1)

    @app.command("export")
    def export_cmd(
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        output_format: str = typer.Option("jsonl", "--format", help="Only jsonl for now."),
        since: str | None = typer.Option(None, "--since", help=SINCE_HELP),
        output: Path | None = typer.Option(None, "--output", "-o", help="Write to a file."),
        as_json: bool = typer.Option(False, "--json", help="Print one JSON array instead."),
    ) -> None:
        """Print the audit events as JSON lines, for a SIEM or an archive."""
        from arbitr.core.audit import export_jsonl  # noqa: PLC0415

        if output_format != "jsonl":
            _fail(f"unknown format {output_format!r}; use jsonl")
        start = _since(since)
        with _ledger(config) as ledger:
            events = [e for e in ledger.events() if start is None or e.created_at >= start]
        lines = list(export_jsonl(events))
        if as_json:
            lines = [json.dumps([json.loads(line) for line in lines])]
        if output is None:
            for line in lines:
                typer.echo(line)
            return
        output.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
        typer.echo(f"Wrote {len(lines)} events to {output}.", err=True)


def _runs_app() -> typer.Typer:
    import typer  # noqa: PLC0415

    app = typer.Typer(help="List and show runs.", no_args_is_help=True)

    @app.command("ls")
    def ls_cmd(
        limit: int = typer.Option(20, "--limit", min=1, help="How many runs to show."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """The most recent runs, newest first."""
        with _ledger(config) as ledger:
            runs = ledger.runs(limit=limit)
        lines = [
            f"{clean_text(r.run_id)}  {clean_text(r.principal)} via {clean_text(r.agent_id)}"
            f"  {r.mode}  ({r.created_at})"
            for r in runs
        ]
        _emit(as_json, [_run_view(r) for r in runs], lines or ["No runs yet."])

    @app.command("show")
    def show_cmd(
        run_id: str = typer.Argument(..., help="The run id."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """One run and its actions."""
        with _ledger(config) as ledger:
            run = ledger.run_record(run_id)
            intents = ledger.find_intents(run_id=run_id, limit=1000) if run else []
        if run is None:
            _fail(f"run {run_id} does not exist")
        data = {"run": _run_view(run), "intents": [_intent_view(i) for i in intents]}
        who = f"{clean_text(run.principal)} via {clean_text(run.agent_id)}"
        lines = [f"Run {clean_text(run.run_id)}: {who} ({run.mode})"]
        if run.scope is not None and run.scope.task:
            lines.append(f"Task: {quote_text(run.scope.task)}")
        lines += [f"  {_intent_line(i)}" for i in reversed(intents)]
        _emit(as_json, data, lines)

    return app


def _intents_app() -> typer.Typer:
    import typer  # noqa: PLC0415

    from arbitr.core.states import IntentState  # noqa: PLC0415

    app = typer.Typer(help="List, show and explain actions.", no_args_is_help=True)

    @app.command("ls")
    def ls_cmd(
        run: str | None = typer.Option(None, "--run", help="Only this run."),
        state: str | None = typer.Option(None, "--state", help="Only this state, e.g. UNKNOWN."),
        tool: str | None = typer.Option(None, "--tool", help="Only this tool."),
        since: str | None = typer.Option(None, "--since", help=SINCE_HELP),
        limit: int = typer.Option(50, "--limit", min=1, help="How many to show."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """Actions, newest first, filtered by run, state, tool and time."""
        wanted = None
        if state is not None:
            try:
                wanted = IntentState(state.upper())
            except ValueError:
                names = ", ".join(s.value for s in IntentState)
                _fail(f"unknown state {state!r}; use one of {names}")
        start = _since(since)
        with _ledger(config) as ledger:
            rows = ledger.find_intents(
                run_id=run, state=wanted, tool=tool, since=start, limit=limit
            )
        lines = [_intent_line(r) for r in rows] or ["No matching actions."]
        _emit(as_json, [_intent_view(r) for r in rows], lines)

    @app.command("show")
    def show_cmd(
        intent_id: str = typer.Argument(..., help="The intent id."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """One action: its record, receipt and events."""
        with _ledger(config) as ledger:
            row = ledger.intent(intent_id)
            receipt = ledger.receipt(intent_id) if row else None
            events = ledger.intent_events(intent_id) if row else []
        if row is None:
            _fail(f"intent {intent_id} does not exist")
        view = _intent_view(row)
        receipt_view = None
        if receipt is not None:
            receipt_view = {
                "source": receipt.source,
                "external_id": receipt.external_id,
                "result_hash": receipt.result_hash,
                "result": json.loads(receipt.result_redacted) if receipt.result_redacted else None,
            }
        event_views = [
            {"seq": e.seq, "kind": e.kind, "created_at": e.created_at,
             "payload": json.loads(e.payload)}
            for e in events
        ]  # fmt: skip
        lines = [_intent_line(row), f"Arguments: {json.dumps(view['args'])}"]
        if receipt is not None:
            external = clean_text(receipt.external_id)
            lines.append(f"Receipt: {receipt.source}, external id {external}")
        lines += [f"  {e.seq:>6}  {e.kind}  ({e.created_at})" for e in events]
        _emit(as_json, {"intent": view, "receipt": receipt_view, "events": event_views}, lines)

    @app.command("explain")
    def explain_cmd(
        intent_id: str = typer.Argument(..., help="The intent id."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """Why an action is in its state: the decision and its history in plain English."""
        with _ledger(config) as ledger:
            row = ledger.intent(intent_id)
            events = ledger.intent_events(intent_id) if row else []
        if row is None:
            _fail(f"intent {intent_id} does not exist")
        lines = explain_lines(row, events)
        _emit(as_json, {"intent_id": intent_id, "explanation": lines}, lines)

    return app


def _approvals_app() -> typer.Typer:
    import typer  # noqa: PLC0415

    from arbitr.approvals import approval_stats  # noqa: PLC0415
    from arbitr.core.errors import ApprovalError  # noqa: PLC0415

    app = typer.Typer(
        help="Review, approve and reject actions waiting for a human.", no_args_is_help=True
    )

    @app.command("ls")
    def ls_cmd(
        status: str = typer.Option("pending", "--status", help=STATUS_HELP),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """Approval requests, newest first (pending ones by default)."""
        with _ledger(config) as ledger:
            rows = ledger.approvals(None if status == "all" else status)
        lines = [_approval_line(r) for r in rows] or [f"No {status} approval requests."]
        _emit(as_json, [_approval_view(r) for r in rows], lines)

    @app.command("show")
    def show_cmd(
        approval_id: str = typer.Argument(..., help="The approval id."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """The readable card for one request, with its votes."""
        with _ledger(config) as ledger:
            try:
                card = ledger.approval_card(approval_id)
            except ApprovalError as exc:
                _fail(str(exc))
        lines = [f"Approval {approval_id} ({card['status']}, until {card['expires_at']})"]
        lines += str(card.get("text", "")).splitlines()
        votes = card.get("votes")
        for vote in votes if isinstance(votes, list) else []:
            lines.append(f"Vote: {clean_text(vote['approver'])} {clean_text(vote['decision'])}")
        _emit(as_json, card, lines)

    @app.command("stats")
    def stats_cmd(
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """Approval rates and time to decision per rule, flagging rubber-stamped rules."""
        with _ledger(config) as ledger:
            stats = approval_stats(ledger)
        lines: list[str] = []
        for s in stats:
            median = "n/a" if s.median_seconds is None else f"{s.median_seconds:.1f}s"
            flag = "  RUBBER STAMP" if s.rubber_stamp else ""
            lines.append(
                f"{clean_text(s.rule_id)}: {s.requested} requests, {s.approval_rate:.0%} approved,"
                f" median {median}{flag}"
            )
            if s.suggestion:
                lines.append(f"  {s.suggestion}")
        _emit(as_json, [vars(s) for s in stats], lines or ["No approval requests yet."])

    return app


def _add_vote_commands(app: typer.Typer) -> None:
    """approve, reject and decide (with a signed link) on the approvals app."""
    import typer  # noqa: PLC0415

    from arbitr.core.errors import ApprovalError  # noqa: PLC0415

    def vote(
        approval_id: str,
        verdict: str,
        approver: str | None,
        note: str | None,
        config: Path | None,
        as_json: bool,
    ) -> None:
        name = _approver(approver)
        with _ledger(config) as ledger:
            current = ledger.approval(approval_id)
            if current is None:
                _fail(f"approval {approval_id} does not exist")
            roles = _roles_for(name, current, _configured_approvers(config))
            cast = ledger.approve if verdict == "approve" else ledger.reject
            try:
                row = cast(approval_id, approver=name, roles=roles, note=note)
            except ApprovalError as exc:
                _fail(str(exc))
        words = {"approved": "Approved", "rejected": "Rejected", "pending": "Vote recorded"}
        line = f"{words.get(row.status, row.status)}: {approval_id}"
        if row.status == "pending":
            line += f" (needs {row.required} approvals)"
        _emit(as_json, _approval_view(row), [line])

    @app.command("approve")
    def approve_cmd(
        approval_id: str = typer.Argument(..., help="The approval id."),
        approver: str | None = typer.Option(None, "--as", help=APPROVER_HELP),
        note: str | None = typer.Option(None, "--note", help="Why."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """Approve a request. The action runs on the agent's next call.

        Your roles come from approvals.approvers in the config, never from you.
        """
        vote(approval_id, "approve", approver, note, config, as_json)

    @app.command("reject")
    def reject_cmd(
        approval_id: str = typer.Argument(..., help="The approval id."),
        approver: str | None = typer.Option(None, "--as", help=APPROVER_HELP),
        note: str | None = typer.Option(None, "--note", help="Why."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """Reject a request. The action never runs.

        Your roles come from approvals.approvers in the config, never from you.
        """
        vote(approval_id, "reject", approver, note, config, as_json)

    @app.command("decide")
    def decide_cmd(
        token: str = typer.Option(..., "--token", help="The token from a signed approval link."),
        note: str | None = typer.Option(None, "--note", help="Why."),
        config: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
        as_json: bool = typer.Option(False, "--json", help=JSON_HELP),
    ) -> None:
        """Apply the decision in a signed approval link."""
        with _ledger(config) as ledger:
            try:
                row = ledger.decide_by_link(token, note=note)
            except ApprovalError as exc:
                _fail(str(exc))
        _emit(as_json, _approval_view(row), [f"{row.status.capitalize()}: {row.approval_id}"])
