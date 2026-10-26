"""The executor: every tool call goes through the ledger and the gate, exactly once.

``Ledger.execute(spec, args, fn)`` is the whole protocol:

1. Build the intent: extract resources, raise the effect, hash, derive the key.
2. In one transaction, look up the idempotency key. A finished intent returns
   its receipt without running again; a running one raises ``InFlight``; an
   expired or unknown one goes to recovery. Otherwise record PROPOSED, decide
   with the gate, record the decision, and reserve budgets.
3. Deny raises ``ActionDenied``; require approval raises ``ApprovalPending``.
4. In a second transaction, move to EXECUTING with a lease on the database
   clock. This is durable before the tool runs. If the ledger cannot be
   written, the tool does not run (``LedgerUnavailable``): fail closed.
5. Call the tool, heartbeating the lease. Native and probe tools get the idempotency key;
   tools that declare credentials get them now, never earlier.
6. Record the receipt and SUCCEEDED, update the run's taint. A failure is
   recorded as FAILED (budgets released) or, when the side effect may have
   happened (timeouts, lost connections), as UNKNOWN.

Recovery (an expired lease, or UNKNOWN): ``native`` tools run again with the
same key, so the service deduplicates; ``probe`` tools ask the service first;
``none`` tools stay UNKNOWN and follow the policy's ``on_unknown``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import contextvars
import dataclasses
import gc
import importlib
import inspect
import json
import math
import socket
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from types import (
    BuiltinFunctionType,
    CodeType,
    FrameType,
    FunctionType,
    MethodType,
    ModuleType,
)
from typing import TYPE_CHECKING, Any, Final, Literal, Self, TypedDict, Unpack
from urllib.parse import quote

from arbitr.approvals import (
    LinkClaim,
    card_text,
    check_link,
    link_token,
    link_url,
    read_link,
)
from arbitr.core.errors import (
    ActionDenied,
    ActionError,
    ActionScheduled,
    AmbiguousToolError,
    ApprovalError,
    ApprovalPending,
    ApprovalRejected,
    InFlight,
    IntentError,
    LedgerUnavailable,
    RunContextError,
    ScrubbedToolError,
    StaleStateError,
    StorageError,
    UnknownOutcome,
)
from arbitr.core.intent import build_intent, new_ulid
from arbitr.core.redact import Redactor
from arbitr.core.scope import check_scope
from arbitr.core.states import IntentState
from arbitr.core.taint import Taint, after_tool
from arbitr.policy.dlp import PrivateFingerprints, outbound_findings
from arbitr.policy.engine import BudgetCharge, Decision, GateInput, decide
from arbitr.preview import Preview, preview_action
from arbitr.protect import REASON as SELF_REASON
from arbitr.protect import RULE_ID as SELF_RULE
from arbitr.protect import protected_forms, touches_arbitr
from arbitr.resources.registry import extract, resolve
from arbitr.storage.sqlite import SQLiteStorage, parse_db_time

if TYPE_CHECKING:
    import os
    from datetime import datetime
    from types import TracebackType

    from arbitr.approvals import ApprovalNotifier
    from arbitr.core.audit import Event, VerifyResult
    from arbitr.core.intent import ActionIntent
    from arbitr.core.scope import Scope
    from arbitr.core.spec import ToolSpec
    from arbitr.credentials import CredentialProvider
    from arbitr.policy.schema import ApprovalRequirement, Policy
    from arbitr.storage.sqlite import (
        ApprovalRow,
        IntentRow,
        ReceiptRow,
        RunRow,
        Transaction,
        VoteRow,
    )

S = IntentState
AMBIGUOUS: Final = (TimeoutError, ConnectionError, AmbiguousToolError)
"""Failures after which the side effect may have happened: recorded as UNKNOWN."""

_CURRENT: contextvars.ContextVar[RunHandle | None] = contextvars.ContextVar(
    "arbitr_run", default=None
)
_PREVIEW: contextvars.ContextVar[Preview | None] = contextvars.ContextVar(
    "arbitr_preview", default=None
)
"""The preview of the call being decided, taken before the deciding transaction."""


def _with_preview(preview: Preview | None) -> contextvars.Context:
    """A copy of the current context in which the gate sees ``preview``."""
    context = contextvars.copy_context()
    context.run(_PREVIEW.set, preview)
    return context


def _record_preview(tx: Transaction, intent: ActionIntent) -> None:
    """Store the preview next to the decision, redacted, so an approver can see it."""
    preview = _PREVIEW.get()
    if preview is not None:
        tx.append_event("preview", preview.to_record(), intent_id=intent.intent_id,
                        run_id=intent.run_id)  # fmt: skip


@dataclass
class RunHandle:
    """The run a tool call belongs to. Set by ``Ledger.run`` through a context variable."""

    run_id: str
    principal: str
    agent_id: str
    mode: Literal["enforce", "shadow"] | None
    fingerprints: PrivateFingerprints = field(default_factory=PrivateFingerprints)
    last_idempotency_key: str = ""


def current_run() -> RunHandle | None:
    """The run of the current context, or None."""
    return _CURRENT.get()


@dataclass(frozen=True)
class ProbeCall:
    """What a probe function gets: enough to ask the service whether the effect happened."""

    intent_id: str
    tool: str
    args: Mapping[str, object]
    idempotency_key: str
    context: Mapping[str, object]


@dataclass(frozen=True)
class RecoveryResult:
    """What recovery did with one stale intent."""

    intent_id: str
    state: IntentState
    action: str


@dataclass
class _Plan:
    """An intent that is EXECUTING under this worker's lease, ready to call.

    Attempt 0 means not started yet: ``_prepare`` moves it from ``start_from``
    to EXECUTING in its own commit, after the decision commit.
    """

    intent: ActionIntent
    attempt: int
    start_from: IntentState = IntentState.APPROVED
    started: float = field(default_factory=time.monotonic)
    """When this worker last knew its lease was fresh (monotonic seconds)."""


@dataclass(frozen=True)
class _Stop:
    """The call ends here: raise ``error`` or return ``result``."""

    error: Exception | None = None
    result: object = None
    delivered: bool = False  # ``result`` is a tool result handed to the agent
    new_approval: ApprovalRow | None = None  # an approval request created by this call


@dataclass(frozen=True)
class _Probe:
    """Recovery needs to ask the probe before deciding to run again."""

    intent: ActionIntent
    row: IntentRow


@lru_cache(maxsize=256)
def _resolve(path: str) -> Callable[..., Any]:
    module_name, _, attr_path = path.partition(":")
    target: Any = importlib.import_module(module_name)
    for attr in attr_path.split("."):
        target = getattr(target, attr)
    return target  # type: ignore[no-any-return]


class _Counters(Mapping[str, float]):
    """Budget counters read lazily inside the deciding transaction."""

    def __init__(self, tx: Transaction) -> None:
        self._tx = tx

    def __getitem__(self, key: str) -> float:
        return self._tx.budget_counters([key])[key]

    def __iter__(self) -> Iterator[str]:
        return iter(())

    def __len__(self) -> int:
        return 0


def _scope_spend_key(run_id: str) -> str:
    return f"scope-spend|run:{run_id}"


def _measured(amount: object) -> float | None:
    """A spend amount as a number, or None when it is not one (a bool is not)."""
    if isinstance(amount, bool) or not isinstance(amount, int | float):
        return None
    return float(amount)


def _spend_amount(intent: ActionIntent) -> float | None:
    amount = _measured(intent.args.get("amount"))
    if intent.effect != "financial" or amount is None:
        return None
    if not math.isfinite(amount) or amount <= 0:
        return None
    return amount


def _scope_charges(tx: Transaction, run_id: str, intent: ActionIntent) -> tuple[BudgetCharge, ...]:
    """Charge the spend to every run in the chain that has a spend limit.

    A child run inherits its parent's limit, so siblings together must stay
    under it: the parent's counter is charged along with the child's.
    Unmeasurable amounts are already outside the scope (``check_scope``).
    """
    amount = _spend_amount(intent)
    if amount is None:
        return ()
    charges: list[BudgetCharge] = []
    seen: set[str] = set()
    current: str | None = run_id
    while current is not None and current not in seen:
        seen.add(current)
        run = tx.get_run(current)
        if run is None:
            break
        if run.scope is not None and run.scope.spend_limit is not None:
            charges.append(
                BudgetCharge("scope", _scope_spend_key(run.run_id), amount, run.scope.spend_limit)
            )
        current = run.parent_run_id
    return tuple(charges)


def _with_scope_charges(
    tx: Transaction, handle: RunHandle, intent: ActionIntent, decision: Decision
) -> Decision:
    """Add the run's spend to what the decision reserves.

    A request for approval holds its budget too, so an approved action cannot
    find the budget gone; a rejection or expiry gives it back. The human
    approves the spend even past the run's limit, so for an approval the run's
    spend is counted but its limit does not refuse it.
    """
    scope = _scope_charges(tx, handle.run_id, intent)
    if decision.outcome == "require_approval":
        scope = _counted_only(tx, scope)
    return dataclasses.replace(decision, charges=decision.charges + scope)


def _counted_only(tx: Transaction, charges: tuple[BudgetCharge, ...]) -> tuple[BudgetCharge, ...]:
    """The same charges, with each limit raised just enough that they always fit."""
    current = tx.budget_counters([c.scope_key for c in charges])
    return tuple(
        dataclasses.replace(c, limit=max(c.limit, current[c.scope_key] + c.amount)) for c in charges
    )


def _taint_run(tx: Transaction, run_id: str, spec: ToolSpec) -> None:
    """Taint the run with what this tool's output carries."""
    added = after_tool(Taint(), spec)
    if added != Taint():
        tx.add_taint(run_id, added)


def _stop(handle: RunHandle, spec: ToolSpec, stop: _Stop) -> object:
    """Raise the stop's error, or hand back its result (fingerprinted when private)."""
    if stop.error is not None:
        raise stop.error
    if stop.delivered and spec.private_output:
        handle.fingerprints.add_value(stop.result)
    return stop.result


_NEVER_STARTED: Final = (
    "waiting: approved but never started (the worker stopped first);"
    " the next call with the same key runs it"
)
_FAILED_UNKNOWN: Final = (
    "This action failed after an unknown outcome, so it may have acted; it will not run"
    " again on its own. A human must decide."
)


def _may_have_acted(tx: Transaction, spec: ToolSpec, row: IntentRow) -> bool:
    """A none tool that went through UNKNOWN may have acted, so a retry could duplicate it."""
    duplicates_ok = spec.idempotency != "none" or spec.allow_duplicates
    return not duplicates_ok and tx.has_been(row.intent_id, S.UNKNOWN)


_NO_DELAY: Final = (
    "The arguments contain redacted values, so the action needs approval instead of a delay."
)
_STALE: Final = "the approval went stale before the action ran; ask for approval again"
_NEEDS_HUMAN: Final = "the outcome is unknown and needs a human to resolve it"
_UNKNOWN_DECISION: Final = Decision(
    "require_approval", "require_approval", "on-unknown",
    "The outcome is unknown: approve to run it again, reject to record it as failed.",
    "enforce",
)  # fmt: skip
_CARD_TEXT_LIMIT: Final = 120
_NO_WINDOW: Final = "This retry never had its cancel window, so it needs approval instead."


class LedgerOptions(TypedDict, total=False):
    """The keyword settings of ``Ledger.open`` (and ``Ledger.from_config``).

    ``clock``, ``heartbeat`` and ``on_step`` are test seams (deterministic
    simulation and crash injection); leave them at their defaults elsewhere.
    """

    worker_id: str | None
    lease_ttl: float
    approval_ttl: float | None
    credentials: CredentialProvider | None
    on_step: Callable[[str], None] | None
    notifier: ApprovalNotifier | None
    protected_paths: Sequence[str | os.PathLike[str]]
    clock: Callable[[], datetime] | None
    heartbeat: bool
    preview_context: Mapping[str, object] | None
    preview_timeout: float


class Ledger:
    """The write-ahead ledger and gate in front of an agent's tools.

    Thread safe: each thread gets its own database connection.

    Two options exist for deterministic simulation tests and should stay at
    their defaults elsewhere: ``clock`` replaces the database clock (see
    ``SQLiteStorage.open``), and ``heartbeat=False`` turns off the background
    heartbeat that extends a running call's lease on wall time.
    """

    def __init__(  # noqa: PLR0913 - every setting is an independent knob
        self,
        path: str | Path,
        policy: Policy,
        *,
        key: bytes,
        worker_id: str | None = None,
        lease_ttl: float = 30.0,
        approval_ttl: float | None = None,
        credentials: CredentialProvider | None = None,
        on_step: Callable[[str], None] | None = None,
        notifier: ApprovalNotifier | None = None,
        protected_paths: Sequence[str | os.PathLike[str]] = (),
        clock: Callable[[], datetime] | None = None,
        heartbeat: bool = True,
        preview_context: Mapping[str, object] | None = None,
        preview_timeout: float = 2.0,
    ) -> None:
        """Use ``Ledger.open`` instead; it also checks the ledger opens.

        ``preview_context`` is what previewers get (a read-only database
        connection, tagged folders, internal email domains); ``preview_timeout``
        is how many seconds a preview may take before it counts as failed.
        """
        self.path = Path(path)
        self.policy = policy
        self.worker_id = worker_id or f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
        self.lease_ttl = lease_ttl
        self.approval_ttl = (
            approval_ttl
            if approval_ttl is not None
            else policy.approval.expires_after.total_seconds()
        )
        self.notifier = notifier
        # The ledger file is always protected; the config adds the key, policy and config.
        self._protected = protected_forms((self.path, *protected_paths))
        self.credentials = credentials
        self.on_step = on_step
        self.clock = clock
        self.heartbeat = heartbeat
        self.probe_context: dict[str, object] = {}
        self.preview_context: dict[str, object] = dict(preview_context or {})
        self.preview_timeout = preview_timeout
        self._key = key
        self._local = threading.local()
        self._opened: list[SQLiteStorage] = []
        self._closed = False
        self._lock = threading.Lock()

    @classmethod
    def open(
        cls, path: str | Path, policy: Policy, *, key: bytes, **options: Unpack[LedgerOptions]
    ) -> Ledger:
        """Open (or create) the ledger at ``path`` with ``policy``.

        Raises:
            StorageError: the ledger file cannot be opened or migrated.
        """
        ledger = cls(path, policy, key=key, **options)
        ledger._storage()
        return ledger

    @classmethod
    def from_config(
        cls, path: str | Path | None = None, **options: Unpack[LedgerOptions]
    ) -> Ledger:
        """Open the ledger described by ``arbitr.yaml`` (or ``path``, or ``ARBITR_CONFIG``).

        ``options`` go to ``Ledger.open`` and win over the config.

        Raises:
            ConfigError: the config, policy, key or ledger is unusable.
        """
        from arbitr.config import load_config  # noqa: PLC0415 - config imports this module

        return load_config(path).open_ledger(**options)

    def __enter__(self) -> Self:
        """Use the ledger as a context manager; closing releases every connection."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close every connection."""
        self.close()

    def close(self) -> None:
        """Close the connections of every thread that used this ledger. It cannot reopen."""
        with self._lock:
            self._closed = True
            for storage in self._opened:
                storage.close()
            self._opened.clear()
        self._local = threading.local()

    def _storage(self) -> SQLiteStorage:
        storage: SQLiteStorage | None = getattr(self._local, "storage", None)
        if storage is None:
            if self._closed:  # a silent reopen would leak a connection nobody closes
                raise StorageError("the ledger is closed")
            storage = SQLiteStorage.open(
                self.path,
                Redactor(self._key),
                busy_timeout_ms=30_000,
                any_thread=True,
                clock=self.clock,
            )
            self._local.storage = storage
            with self._lock:
                self._opened.append(storage)
        return storage

    def _step(self, name: str) -> None:
        if self.on_step is not None:
            self.on_step(name)

    # ------------------------------------------------------------ runs

    @contextmanager
    def run(  # noqa: PLR0913 - a run has these independent attributes
        self,
        principal: str,
        agent_id: str,
        *,
        run_id: str | None = None,
        scope: Scope | None = None,
        scopes: tuple[str, ...] = (),
        mode: Literal["enforce", "shadow"] | None = None,
        resume: bool = False,
        metadata: Mapping[str, object] | None = None,
    ) -> Iterator[RunHandle]:
        """Start a run (or resume one) for the tool calls made inside the block.

        A run started inside another run is its child: its scope must fit
        inside the parent's, and taint flows between them.
        """
        rid = run_id or new_ulid()
        parent = current_run()
        if not resume:
            try:
                with self._storage().transaction() as tx:
                    tx.insert_run(
                        rid,
                        principal,
                        agent_id,
                        mode=mode or self.policy.mode,
                        parent_run_id=parent.run_id if parent else None,
                        scopes=scopes,
                        scope=scope,
                        metadata=metadata,
                    )
            except StorageError as exc:
                raise LedgerUnavailable("the run could not be recorded") from exc
        handle = RunHandle(rid, principal, agent_id, mode)
        token = _CURRENT.set(handle)
        try:
            yield handle
        finally:
            _CURRENT.reset(token)

    # ------------------------------------------------------------ execute

    def execute(
        self,
        spec: ToolSpec,
        args: Mapping[str, object],
        fn: Callable[..., object],
        *,
        step_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> object:
        """Run one tool call through the ledger and the gate. See the module docstring.

        Raises:
            ActionDenied, ApprovalPending, ApprovalRejected, ActionScheduled,
            InFlight, UnknownOutcome, LedgerUnavailable: the action did not run
                (or its outcome is not known); see each error's to_tool_message().
            Exception: whatever the tool raised, after the failure is recorded.
        """
        handle, intent = self._intent(spec, args, step_id, idempotency_key)
        context = _with_preview(self._preview(spec, intent))
        outcome = context.run(self._prepare, handle, spec, intent)
        if isinstance(outcome, _Stop) and outcome.new_approval is not None:
            self._notify(outcome.new_approval)
        if isinstance(outcome, _Probe):
            outcome = self._run_probe(handle, spec, outcome)
        if isinstance(outcome, _Stop):
            return _stop(handle, spec, outcome)
        return self._call_sync(handle, spec, outcome, fn)

    async def aexecute(
        self,
        spec: ToolSpec,
        args: Mapping[str, object],
        fn: Callable[..., Any],
        *,
        step_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> object:
        """The async form of ``execute``. Ledger writes run in a worker thread."""
        handle, intent = self._intent(spec, args, step_id, idempotency_key)
        context = _with_preview(await asyncio.to_thread(self._preview, spec, intent))
        outcome = await asyncio.to_thread(context.run, self._prepare, handle, spec, intent)
        if isinstance(outcome, _Stop) and outcome.new_approval is not None:
            await asyncio.to_thread(self._notify, outcome.new_approval)
        if isinstance(outcome, _Probe):
            outcome = await asyncio.to_thread(self._run_probe, handle, spec, outcome)
        if isinstance(outcome, _Stop):
            return _stop(handle, spec, outcome)
        return await self._call_async(handle, spec, outcome, fn)

    def _intent(
        self,
        spec: ToolSpec,
        args: Mapping[str, object],
        step_id: str | None,
        key: str | None,
    ) -> tuple[RunHandle, ActionIntent]:
        handle = current_run()
        if handle is None:
            raise RunContextError("tool calls must happen inside ledger.run(...)")
        found = extract(spec, args)
        effect = spec.effect
        if found.effect is not None:
            from arbitr.core.spec import raise_effect  # noqa: PLC0415

            effect = raise_effect(spec.effect, found.effect)
        intent = build_intent(
            spec.model_copy(update={"effect": effect}),
            args,
            run_id=handle.run_id,
            principal=handle.principal,
            step_id=step_id,
            idempotency_key=key,
            resources=found.resources,
        )
        handle.last_idempotency_key = intent.idempotency_key
        return handle, intent

    def _preview(self, spec: ToolSpec, intent: ActionIntent) -> Preview | None:
        """The blast radius preview, for destructive and financial intents. Never raises."""
        return preview_action(
            spec,
            intent.effect,
            intent.resources,
            intent.args,
            context=self.preview_context,
            timeout_s=self.preview_timeout,
        )

    # ------------------------------------------------------------ prepare

    def _prepare(
        self, handle: RunHandle, spec: ToolSpec, intent: ActionIntent
    ) -> _Plan | _Stop | _Probe:
        """Steps 2 to 4: everything before the tool runs. Fails closed."""
        try:
            with self._storage().transaction() as tx:
                existing = tx.get_intent_by_key(intent.idempotency_key)
                outcome: _Plan | _Stop | _Probe
                if existing is None:
                    tx.insert_intent(intent, redact_paths=spec.redact)
                    outcome = self._decide(tx, handle, spec, intent, S.PROPOSED)
                else:
                    if existing.intent_hash != intent.intent_hash:
                        raise IntentError(
                            "this idempotency key was already used for different arguments"
                        )
                    intent = dataclasses.replace(intent, intent_id=existing.intent_id)
                    outcome = self._resume(tx, handle, spec, intent, existing)
            self._step("after_decision_commit")
            if isinstance(outcome, _Plan) and outcome.attempt == 0:
                outcome = self._start(outcome, outcome.start_from)
        except StorageError as exc:
            return _Stop(LedgerUnavailable(f"the ledger could not be written: {exc}"))
        except StaleStateError:
            return _Stop(InFlight("another worker changed this action at the same moment"))
        return outcome

    def _start(self, plan: _Plan, expected: IntentState) -> _Plan:
        """Step 5: EXECUTING with a lease, durable before the tool runs."""
        self._step("before_executing_commit")
        with self._storage().transaction() as tx:
            row = tx.start_execution(
                plan.intent.intent_id,
                expected=expected,
                worker=self.worker_id,
                ttl_seconds=self.lease_ttl,
            )
        self._step("after_executing_commit")
        return _Plan(plan.intent, row.attempt, plan.start_from)

    def _gate_input(
        self, tx: Transaction, handle: RunHandle, spec: ToolSpec, intent: ActionIntent
    ) -> GateInput:
        run = tx.get_run(handle.run_id)
        if run is None:
            raise StorageError(f"run {handle.run_id} is missing")
        args = intent.args
        resources = resolve(self.policy, intent.resources)
        outside = False
        if run.scope is not None:
            amount = args.get("amount")
            verdict = check_scope(
                run.scope,
                tool=intent.tool,
                effect=intent.effect,
                resources=resources,
                amount=_measured(amount),  # the same measure that is charged
                spent=_Counters(tx).get(_scope_spend_key(run.run_id), 0.0),
            )
            outside = verdict.outside
        mode = handle.mode if handle.mode is not None else _run_mode(run)
        preview = _PREVIEW.get()
        return GateInput(
            tool=intent.tool,
            effect=intent.effect,
            args=args,
            principal=handle.principal,
            agent_id=handle.agent_id,
            run_id=handle.run_id,
            now=parse_db_time(tx.now),
            resources=resources,
            taint=run.taint,
            scopes=frozenset(run.scopes),
            outside_scope=outside,
            outbound_findings=outbound_findings(
                intent.effect, args, fingerprints=handle.fingerprints
            ),
            mode=mode,
            preview=preview.facts if preview is not None else {},
            preview_ok=preview is None or preview.ok,
        )

    def _decide(
        self,
        tx: Transaction,
        handle: RunHandle,
        spec: ToolSpec,
        intent: ActionIntent,
        state: IntentState,
    ) -> _Plan | _Stop:
        inp, decision = self._gate(tx, handle, spec, intent)
        _record_preview(tx, intent)
        if decision.outcome == "delay":
            decision = self._delay_or_approval(tx, intent, decision, state)
        holds = decision.outcome in ("allow", "delay", "require_approval")
        if holds:
            decision = _with_scope_charges(tx, handle, intent, decision)
        fields = _decision_fields(decision)
        if holds and not tx.reserve_all(decision.charges, intent_id=intent.intent_id):
            fields.update(decision="deny", decision_rule="budget", decision_reason=_BUDGET)
            decision = Decision("deny", "deny", "budget", _BUDGET, decision.mode)
        if decision.outcome == "deny":
            if state == S.PROPOSED:
                tx.transition(intent.intent_id, S.DENIED, expected=state, fields=fields)
            return _Stop(ActionDenied(decision.rule_id, decision.reason))
        if decision.outcome == "require_approval":
            # A retry after FAILED waits for a human just like a new action.
            if state in (S.PROPOSED, S.FAILED):
                tx.transition(intent.intent_id, S.PENDING_APPROVAL, expected=state, fields=fields)
            approval, created = self._open_approval(tx, handle, intent, decision, inp)
            return _Stop(ApprovalPending(approval.approval_id, decision.rule_id, decision.reason),
                         new_approval=approval if created else None)  # fmt: skip
        if state == S.PROPOSED:
            tx.transition(intent.intent_id, S.APPROVED, expected=state, fields=fields)
            if decision.outcome == "delay":
                row = tx.schedule(intent.intent_id, delay_seconds=decision.delay_seconds)
                return _Stop(ActionScheduled(intent.intent_id, row.scheduled_for or "later"))
            return _Plan(intent, 0)
        # A retry after FAILED: run again under a fresh lease and reservation.
        row = tx.start_execution(
            intent.intent_id, expected=state, worker=self.worker_id, ttl_seconds=self.lease_ttl
        )
        return _Plan(intent, row.attempt)

    def _open_approval(
        self,
        tx: Transaction,
        handle: RunHandle,
        intent: ActionIntent,
        decision: Decision,
        inp: GateInput | None,
    ) -> tuple[ApprovalRow, bool]:
        """The intent's open approval request, or a new one. True when it is new."""
        approval = tx.approval_for_intent(intent.intent_id)
        if approval is not None and approval.status == "pending" and approval.expires_at > tx.now:
            return approval, False
        need = decision.approval or self.policy.approval
        card = self._card(tx, intent, decision, inp)
        approval = tx.create_approval(
            intent.intent_id, ttl_seconds=self.approval_ttl, required=need.required,
            roles=need.roles or (), rule_id=decision.rule_id, summary=card,
            separate_from=handle.principal if need.separate_from_principal else None,
        )  # fmt: skip
        return approval, True

    def _card(
        self, tx: Transaction, intent: ActionIntent, decision: Decision, inp: GateInput | None
    ) -> dict[str, object]:
        """The readable card an approver sees (redacted again when it is stored)."""
        row = tx.get_intent(intent.intent_id)
        stored = json.loads(row.args_redacted) if row is not None else {}
        full = stored if isinstance(stored, dict) else {}
        args = {k: _short(v) for k, v in full.items()}
        run = tx.get_run(intent.run_id)
        card: dict[str, object] = {
            "tool": intent.tool, "effect": intent.effect, "args": args, "args_full": full,
            "truncated": args != full,
            "rule": decision.rule_id, "reason": decision.reason,
            "resources": [{"kind": r.kind, "uri": r.uri, "tags": sorted(r.tags)}
                          for r in (inp.resources if inp is not None else ())],
            "taint": inp.taint.to_dict() if inp is not None else {},
            "outside_scope": bool(inp is not None and inp.outside_scope),
            "task": run.scope.task if run is not None and run.scope is not None else None,
        }  # fmt: skip
        preview = _PREVIEW.get()
        if preview is not None:
            card["preview"] = {"summary": preview.summary, "facts": dict(preview.facts),
                               "ok": preview.ok, "error": preview.error}  # fmt: skip
        card["text"] = card_text(card)
        return card

    def _gate(
        self, tx: Transaction, handle: RunHandle, spec: ToolSpec, intent: ActionIntent
    ) -> tuple[GateInput, Decision]:
        """The gate's decision, after the self-protection check that no mode can loosen."""
        inp = self._gate_input(tx, handle, spec, intent)
        if touches_arbitr(intent.args, self._protected):
            # An agent may not operate Arbitr or touch its ledger, key, policy or config.
            return inp, Decision("deny", "deny", SELF_RULE, SELF_REASON, "enforce")
        return inp, decide(inp, self.policy, _Counters(tx))

    def _delay_or_approval(
        self, tx: Transaction, intent: ActionIntent, decision: Decision, state: IntentState
    ) -> Decision:
        """A delay needs the real arguments stored, or the scheduler could not run it.

        When redaction changed the arguments, ask for approval instead (stricter).
        A retry after FAILED runs now only if it already waited out a window;
        one that never did (the delay rule came later) needs approval, because
        a failed action cannot go back to SCHEDULED.
        """
        if state != S.PROPOSED:
            if tx.has_been(intent.intent_id, S.SCHEDULED):
                return dataclasses.replace(decision, outcome="allow", delay_seconds=0.0)
            return dataclasses.replace(
                decision, outcome="require_approval", delay_seconds=0.0,
                reason=f"{decision.reason} {_NO_WINDOW}",
            )  # fmt: skip
        row = tx.get_intent(intent.intent_id)
        if row is not None and row.args_exact:
            return decision
        return dataclasses.replace(
            decision, outcome="require_approval", delay_seconds=0.0,
            reason=f"{decision.reason} {_NO_DELAY}",
        )  # fmt: skip

    def _resume(  # noqa: PLR0911 - one branch per state
        self,
        tx: Transaction,
        handle: RunHandle,
        spec: ToolSpec,
        intent: ActionIntent,
        row: IntentRow,
    ) -> _Plan | _Stop | _Probe:
        state = row.state
        if state in (S.SUCCEEDED, S.COMPENSATED):
            receipt = tx.get_receipt(row.intent_id)
            tx.append_event("dedup_hit", {"source": "idempotency_key"}, intent_id=row.intent_id,
                            run_id=row.run_id)  # fmt: skip
            _taint_run(tx, handle.run_id, spec)
            return _Stop(result=_stored_result(receipt), delivered=True)
        if state == S.DENIED:
            return _Stop(ActionDenied(row.decision_rule or "policy", row.decision_reason or ""))
        if state in (S.REJECTED, S.EXPIRED, S.CANCELLED):
            return _Stop(ApprovalRejected(f"the action was {state.value.lower()}"))
        if state == S.PENDING_APPROVAL:
            return self._still_pending(tx, row)
        if state == S.SCHEDULED:
            if row.scheduled_for is None or row.scheduled_for > tx.now:
                return _Stop(ActionScheduled(row.intent_id, row.scheduled_for or "later"))
            return _Plan(intent, 0, S.SCHEDULED)  # the window has passed
        if state == S.PROPOSED:
            return self._decide(tx, handle, spec, intent, S.PROPOSED)
        if state == S.APPROVED:
            return self._approved(tx, row, intent)
        if state == S.FAILED:
            return self._retry_failed(tx, handle, spec, intent, row)
        return self._recover(tx, handle, spec, intent, row)

    def _retry_failed(
        self,
        tx: Transaction,
        handle: RunHandle,
        spec: ToolSpec,
        intent: ActionIntent,
        row: IntentRow,
    ) -> _Plan | _Stop | _Probe:
        """A failed action runs again after a fresh decision, unless it may have acted."""
        if _may_have_acted(tx, spec, row):
            return _Stop(UnknownOutcome(_FAILED_UNKNOWN))
        return self._decide(tx, handle, spec, intent, S.FAILED)

    def _recover(
        self,
        tx: Transaction,
        handle: RunHandle,
        spec: ToolSpec,
        intent: ActionIntent,
        row: IntentRow,
    ) -> _Plan | _Stop | _Probe:
        """EXECUTING (lease expired) or UNKNOWN: section on recovery in the module docstring."""
        if row.state == S.EXECUTING:
            expires = row.lease_expires_at
            if expires is not None and expires > tx.now:
                return _Stop(InFlight("this action is running in another worker"))
            row = tx.transition(
                row.intent_id, S.UNKNOWN, expected=S.EXECUTING,
                expected_attempt=row.attempt, detail={"reason": "lease expired"},
            )  # fmt: skip
        if spec.idempotency == "native":
            started = tx.start_execution(row.intent_id, expected=S.UNKNOWN, worker=self.worker_id,
                                         ttl_seconds=self.lease_ttl)  # fmt: skip
            return _Plan(intent, started.attempt)
        if spec.idempotency == "probe":
            return _Probe(intent, row)
        return self._on_unknown(tx, handle, spec, intent, row)

    def _approved(self, tx: Transaction, row: IntentRow, intent: ActionIntent) -> _Plan | _Stop:
        """An approved action runs, unless its approval went stale before it started."""
        approval = tx.approval_for_intent(row.intent_id)
        if approval is not None and approval.status == "approved" and approval.decided_at:
            stale = tx.stale_approvals(self.approval_ttl)
            if any(a.approval_id == approval.approval_id for a in stale):
                tx.expire_stale(approval)
                return _Stop(ApprovalRejected(_STALE))
        return _Plan(intent, 0)

    def _still_pending(self, tx: Transaction, row: IntentRow) -> _Stop:
        """A call while waiting for approval: still waiting, or expired just now."""
        approval = tx.approval_for_intent(row.intent_id)
        if approval is not None and approval.status == "pending" and approval.expires_at <= tx.now:
            tx.expire_approval(approval.approval_id)
            return _Stop(ApprovalRejected("the approval request expired"))
        approval_id = approval.approval_id if approval else "unknown"
        return _Stop(ApprovalPending(approval_id, row.decision_rule or "policy",
                                     row.decision_reason or ""))  # fmt: skip

    def _on_unknown(
        self,
        tx: Transaction,
        handle: RunHandle,
        spec: ToolSpec,
        intent: ActionIntent,
        row: IntentRow,
    ) -> _Plan | _Stop:
        rule = self.policy.on_unknown
        if rule == "retry" and spec.allow_duplicates:
            started = tx.start_execution(row.intent_id, expected=S.UNKNOWN, worker=self.worker_id,
                                         ttl_seconds=self.lease_ttl)  # fmt: skip
            return _Plan(intent, started.attempt)
        if rule == "fail":
            tx.transition(row.intent_id, S.FAILED, expected=S.UNKNOWN,
                          detail={"reason": "outcome unknown; policy says fail"})  # fmt: skip
            return _Stop(UnknownOutcome("the outcome is unknown; it was recorded as failed"))
        approval = tx.approval_for_intent(row.intent_id)
        if approval is not None and approval.attempt == row.attempt:
            if approval.status == "approved":  # a human chose to run it again
                started = tx.start_execution(
                    row.intent_id, expected=S.UNKNOWN, worker=self.worker_id,
                    ttl_seconds=self.lease_ttl,
                )  # fmt: skip
                return _Plan(intent, started.attempt)
            if approval.status == "pending" and approval.expires_at > tx.now:
                return _Stop(UnknownOutcome(_NEEDS_HUMAN))
        need = self._requirement_for(row)
        run = tx.get_run(row.run_id)
        tx.create_approval(
            row.intent_id, ttl_seconds=self.approval_ttl, rule_id="on-unknown",
            required=need.required, roles=need.roles or (),
            separate_from=run.principal if run is not None and need.separate_from_principal
            else None,
            summary=self._card(tx, intent, _UNKNOWN_DECISION,
                               self._gate_input(tx, handle, spec, intent)),
        )  # fmt: skip
        return _Stop(UnknownOutcome(_NEEDS_HUMAN))

    def _requirement_for(self, row: IntentRow) -> ApprovalRequirement:
        """Who must approve re-running an action: its rule's approvers, else the policy's."""
        rule = next((r for r in self.policy.rules if r.id == row.decision_rule), None)
        if rule is not None and rule.approvals is not None:
            return rule.approvals
        return self.policy.approval

    def _run_probe(self, handle: RunHandle, spec: ToolSpec, pending: _Probe) -> _Plan | _Stop:
        """Ask the service whether the side effect happened, outside any transaction."""
        intent = pending.intent
        call = ProbeCall(intent.intent_id, intent.tool, intent.args, intent.idempotency_key,
                         self.probe_context)  # fmt: skip
        try:
            found = _resolve(str(spec.probe))(call)
        except Exception:  # noqa: BLE001 - a failing probe leaves the outcome unknown
            return _Stop(UnknownOutcome("the probe failed, so the outcome is still unknown"))
        try:
            with self._storage().transaction() as tx:
                if found is not None:
                    tx.insert_receipt(intent.intent_id, result=found,
                                      external_id=_external_id(found), source="probe")  # fmt: skip
                    tx.transition(intent.intent_id, S.SUCCEEDED, expected=S.UNKNOWN,
                                  expected_attempt=pending.row.attempt,
                                  detail={"reason": "probe found the side effect"})  # fmt: skip
                    _taint_run(tx, handle.run_id, spec)
                    return _Stop(result=found, delivered=True)
                # The probe answered about attempt N; if another worker started
                # attempt N+1 meanwhile, that answer is stale and must not re-run.
                started = tx.start_execution(
                    intent.intent_id, expected=S.UNKNOWN, worker=self.worker_id,
                    ttl_seconds=self.lease_ttl, expected_attempt=pending.row.attempt,
                )  # fmt: skip
        except StorageError as exc:
            return _Stop(LedgerUnavailable(f"the ledger could not be written: {exc}"))
        except StaleStateError:
            return _Stop(InFlight("another worker is recovering this action"))
        self._step("after_executing_commit")
        return _Plan(intent, started.attempt)

    # ------------------------------------------------------------ call and finish

    def _kwargs(self, spec: ToolSpec, plan: _Plan) -> dict[str, object]:
        kwargs = dict(plan.intent.args)
        if spec.idempotency in ("native", "probe"):
            # Native services deduplicate on the key; probe tools tag the side
            # effect with it so the probe can find it after a crash.
            kwargs["idempotency_key"] = plan.intent.idempotency_key
        if spec.credentials:
            if self.credentials is None:
                raise LedgerUnavailable("this tool needs credentials but no provider is set")
            kwargs["credentials"] = {name: self.credentials.get(name) for name in spec.credentials}
        return kwargs

    def _call_sync(
        self, handle: RunHandle, spec: ToolSpec, plan: _Plan, fn: Callable[..., object]
    ) -> object:
        stop = threading.Event()
        beat = threading.Thread(target=self._heartbeat, args=(plan, stop), daemon=True)
        kwargs: dict[str, object] = {}
        secrets: tuple[str, ...] = ()
        called = False
        failure: BaseException | None = None
        raw: object = None
        outer = sys.exc_info()[1]  # the caller's own error, if it calls from an except block
        try:
            kwargs = self._kwargs(spec, plan)
            secrets = _secret_values(kwargs)
            self._confirm_lease(plan)
            self._step("before_call")
            beat.start()
            called = True
            raw = _sync_result(fn(**kwargs))
        except BaseException as exc:  # noqa: BLE001 - recorded, scrubbed, raised below
            failure = exc
        _stop_beat(stop, beat)
        kwargs = {}  # no credential stays in this frame for a traceback to show
        if failure is not None:
            safe = _present(failure, secrets, outer)
            error = _as_outcome(
                failure, safe, ambiguous=self._finish_error(plan, failure, called=called)
            )
            secrets, failure = (), None
            del safe
            raise error  # outside the except block, so nothing unscrubbed is attached
        self._step("after_side_effect")
        # Scrubbing happens after the outcome is known: it never raises, and a
        # result that cannot be shown must not turn a success into a failure.
        result, raw = _scrub(raw, secrets), None
        return self._finish_ok(handle, spec, plan, result)

    async def _call_async(
        self, handle: RunHandle, spec: ToolSpec, plan: _Plan, fn: Callable[..., Any]
    ) -> object:
        stop = threading.Event()
        beat = threading.Thread(target=self._heartbeat, args=(plan, stop), daemon=True)
        kwargs: dict[str, object] = {}
        secrets: tuple[str, ...] = ()
        called = False
        failure: BaseException | None = None
        raw: object = None
        outer = sys.exc_info()[1]  # the caller's own error, if it calls from an except block
        try:
            kwargs = self._kwargs(spec, plan)
            secrets = _secret_values(kwargs)
            await asyncio.to_thread(self._confirm_lease, plan)
            self._step("before_call")
            beat.start()
            called = True
            raw = fn(**kwargs)
            if inspect.isawaitable(raw):
                raw = await raw
        except BaseException as exc:  # noqa: BLE001 - recorded, scrubbed, raised below
            failure = exc
        _stop_beat(stop, beat)
        kwargs = {}  # no credential stays in this frame for a traceback to show
        if failure is not None:
            # Scrub and clear frames here, on the event loop, where this coroutine
            # is running: from a worker thread, clearing its suspended frame would
            # close it. Only the ledger write goes to a thread.
            safe = _present(failure, secrets, outer)
            ambiguous = await asyncio.to_thread(self._finish_error, plan, failure, called=called)
            error = _as_outcome(failure, safe, ambiguous=ambiguous)
            secrets, failure = (), None
            del safe
            raise error  # outside the except block, so nothing unscrubbed is attached
        self._step("after_side_effect")
        result, raw = _scrub(raw, secrets), None
        context = contextvars.copy_context()
        return await asyncio.to_thread(context.run, self._finish_ok, handle, spec, plan, result)

    def _confirm_lease(self, plan: _Plan) -> None:
        """Right before the call: if time has passed since the lease was taken, renew it.

        Credential fetches and hooks can be slow. If another worker took the
        action over meanwhile, this worker must not call the tool.
        """
        fresh = time.monotonic() - plan.started < self.lease_ttl / 3
        if fresh and self.clock is None:  # with an injected clock, always renew (deterministic)
            return
        try:
            with self._storage().transaction() as tx:
                tx.heartbeat(plan.intent.intent_id, worker=self.worker_id,
                             attempt=plan.attempt, ttl_seconds=self.lease_ttl)  # fmt: skip
        except StaleStateError as exc:
            raise InFlight("the lease ran out before the call; another worker owns it") from exc
        except StorageError as exc:
            raise LedgerUnavailable(f"the lease could not be renewed: {exc}") from exc
        plan.started = time.monotonic()

    def _heartbeat(self, plan: _Plan, stop: threading.Event) -> None:
        """Extend the lease every third of its life until the call returns.

        A storage error (a locked or briefly unavailable database) is retried at
        the next beat; only a lost lease (another attempt or owner) stops it.
        """
        if not self.heartbeat:
            return
        interval = max(self.lease_ttl / 3, 0.05)
        storage: SQLiteStorage | None = None
        try:
            while not stop.wait(interval):
                try:
                    if storage is None:
                        storage = SQLiteStorage.open(
                            self.path, Redactor(self._key), busy_timeout_ms=30_000,
                            clock=self.clock,
                        )  # fmt: skip
                    with storage.transaction() as tx:
                        tx.heartbeat(plan.intent.intent_id, worker=self.worker_id,
                                     attempt=plan.attempt, ttl_seconds=self.lease_ttl)  # fmt: skip
                except StorageError:
                    if storage is not None:
                        storage.close()
                        storage = None
        except StaleStateError:
            return  # the lease is lost; the fences refuse this worker's late writes
        finally:
            if storage is not None:
                storage.close()

    def _finish_ok(self, handle: RunHandle, spec: ToolSpec, plan: _Plan, result: object) -> object:
        """Step 7: receipt, SUCCEEDED, taint. The side effect already happened."""
        try:
            with self._storage().transaction() as tx:
                tx.insert_receipt(plan.intent.intent_id, result=result,
                                  external_id=_external_id(result), source="executed")  # fmt: skip
                tx.transition(
                    plan.intent.intent_id, S.SUCCEEDED, expected=S.EXECUTING,
                    expected_attempt=plan.attempt, expected_lease_owner=self.worker_id,
                )  # fmt: skip
                _taint_run(tx, handle.run_id, spec)
        except StaleStateError:
            # The lease was lost and another worker owns the record, but this
            # result still reaches the agent, so the run must carry its taint.
            self._taint_only(handle, spec)
        except StorageError as exc:
            raise LedgerUnavailable("the action ran, but it could not be recorded") from exc
        if spec.private_output:
            handle.fingerprints.add_value(result)
        return result

    def _taint_only(self, handle: RunHandle, spec: ToolSpec) -> None:
        """Taint the run in a transaction of its own. Taint only ever turns on."""
        try:
            with self._storage().transaction() as tx:
                _taint_run(tx, handle.run_id, spec)
        except StorageError as exc:
            raise LedgerUnavailable("the action ran, but its taint could not be recorded") from exc

    def _finish_error(self, plan: _Plan, exc: BaseException, *, called: bool = True) -> bool:
        """The tool raised: FAILED (budgets released) or UNKNOWN when it may have run.

        A failure before the tool was called (a credential fetch, a lost lease)
        is always FAILED: nothing can have happened yet. Returns True when the
        outcome was recorded as UNKNOWN.
        """
        ambiguous = called and (isinstance(exc, AMBIGUOUS) or not isinstance(exc, Exception))
        target = S.UNKNOWN if ambiguous else S.FAILED
        detail = {"error": type(exc).__name__}
        if not called:
            detail["reason"] = "not started"
        try:
            with self._storage().transaction() as tx:
                tx.transition(
                    plan.intent.intent_id, target, expected=S.EXECUTING,
                    expected_attempt=plan.attempt, expected_lease_owner=self.worker_id,
                    detail=detail,
                )  # fmt: skip
                if target == S.FAILED:
                    tx.release_reservations(plan.intent.intent_id)
        except (StorageError, StaleStateError):
            return False  # recovery will find the expired lease
        return ambiguous

    # ------------------------------------------------------------ operations

    def recover_stale(self) -> list[RecoveryResult]:
        """Mark every EXECUTING intent whose lease ran out as UNKNOWN (run it on startup).

        Recovery itself needs the caller's arguments and function, so it
        happens on the next call with the same key: native tools re-run with
        the key, probe tools ask their probe, none tools wait for a human or
        the policy's ``on_unknown``. Scheduled actions are recovered by
        ``run_due``. Approved actions that never started are reported too.
        """
        results: list[RecoveryResult] = []
        with self._storage().transaction() as tx:
            stale = tx.stale_executions()
            for row in stale:
                tx.transition(row.intent_id, S.UNKNOWN, expected=S.EXECUTING,
                              expected_attempt=row.attempt,
                              detail={"reason": "lease expired; found by recovery"})  # fmt: skip
                results.append(RecoveryResult(row.intent_id, S.UNKNOWN, "marked unknown"))
            cutoff = parse_db_time(tx.now) - timedelta(seconds=self.lease_ttl)
            results.extend(
                RecoveryResult(row.intent_id, S.APPROVED, _NEVER_STARTED)
                for row in tx.intents_in(S.APPROVED)
                if parse_db_time(row.updated_at) <= cutoff
            )
        return results

    def cancel(self, intent_id: str, *, reason: str = "cancelled") -> IntentRow:
        """Cancel a scheduled action inside its window. Its budget is given back.

        Raises:
            StaleStateError: the action is no longer scheduled (it ran, started
                or was cancelled already); nothing changed.
        """
        try:
            with self._storage().transaction() as tx:
                row = tx.transition(intent_id, S.CANCELLED, expected=S.SCHEDULED,
                                    detail={"reason": reason})  # fmt: skip
                tx.release_reservations(intent_id)
        except StaleStateError as exc:
            raise StaleStateError(f"intent {intent_id} is no longer scheduled") from exc
        return row

    def run_due(
        self, tools: Mapping[str, tuple[ToolSpec, Callable[..., object]]]
    ) -> list[RecoveryResult]:
        """Run every scheduled action whose cancel window has passed (the scheduler).

        Each one goes through ``execute`` with its stored arguments and key, so
        the lease, idempotency and recovery rules are the same as for a direct
        call. Scheduled actions that a crashed scheduler left EXECUTING (lease
        expired) or UNKNOWN are recovered the same way, because no agent will
        call them again. ``tools`` maps tool names to their spec and function;
        an action whose tool is missing is left as it is.
        """
        with self._storage().transaction() as tx:
            rows = tx.due_scheduled() + [
                row
                for row in tx.stale_executions() + tx.intents_in(S.UNKNOWN)
                if row.scheduled_for is not None
            ]
            due = [(row, tx.get_run(row.run_id)) for row in sorted(rows, key=_by_id)]
        results: list[RecoveryResult] = []
        for row, run in due:
            entry = tools.get(row.tool)
            if entry is None or run is None:
                action = f"waiting: no function registered for {row.tool}"
                results.append(RecoveryResult(row.intent_id, row.state, action))
                continue
            spec, fn = entry
            action = self._run_scheduled(run, row, spec, fn)
            final = self.intent(row.intent_id)
            results.append(
                RecoveryResult(row.intent_id, final.state if final else row.state, action)
            )
        return results

    def _run_scheduled(
        self, run: RunRow, row: IntentRow, spec: ToolSpec, fn: Callable[..., object]
    ) -> str:
        args = json.loads(row.args_redacted)  # exact: only such intents are scheduled
        context = contextvars.Context()  # never a child of whatever run the caller is in
        try:
            context.run(self._execute_in_run, run, row, spec, args, fn)
        except ActionError as exc:
            return f"stopped: {exc.code}"
        except Exception as exc:  # noqa: BLE001 - the tool's failure is recorded, report it
            return f"failed: {type(exc).__name__}"
        return "ran"

    def _execute_in_run(
        self,
        run: RunRow,
        row: IntentRow,
        spec: ToolSpec,
        args: Mapping[str, object],
        fn: Callable[..., object],
    ) -> object:
        with self.run(run.principal, run.agent_id, run_id=run.run_id, resume=True):
            return self.execute(spec, args, fn, step_id=row.step_id,
                                idempotency_key=row.idempotency_key)  # fmt: skip

    # ------------------------------------------------------------ approvals

    def approve(
        self, approval_id: str, *, approver: str, roles: Sequence[str] = (), note: str | None = None
    ) -> ApprovalRow:
        """Approve a request as ``approver``. The action runs on the agent's next call.

        Raises:
            ApprovalError: unknown, already decided, expired, the wrong role,
                the principal approving their own action, or a second vote.
        """
        return self._vote(approval_id, approver=approver, roles=roles, decision="approve",
                          note=note)  # fmt: skip

    def reject(
        self, approval_id: str, *, approver: str, roles: Sequence[str] = (), note: str | None = None
    ) -> ApprovalRow:
        """Reject a request. The action never runs, and its budget hold is released."""
        return self._vote(approval_id, approver=approver, roles=roles, decision="reject",
                          note=note)  # fmt: skip

    def _vote(  # noqa: PLR0913 - a vote has these parts
        self,
        approval_id: str,
        *,
        approver: str,
        roles: Sequence[str],
        decision: str,
        note: str | None,
        token_hash: str | None = None,
    ) -> ApprovalRow:
        with self._storage().transaction() as tx:
            row = tx.get_approval(approval_id)
            if row is None:
                raise ApprovalError(f"approval {approval_id} does not exist")
            result = tx.vote(approval_id, approver=approver, roles=tuple(roles),
                             decision=decision, note=note,
                             intent_hash=token_hash or row.intent_hash)  # fmt: skip
        if result.status == "expired":
            raise ApprovalError(f"approval {approval_id} expired before the decision")
        return result

    def approval(self, approval_id: str) -> ApprovalRow | None:
        """One approval request, or None."""
        with self._storage().transaction() as tx:
            return tx.get_approval(approval_id)

    def approvals(self, status: str | None = None) -> list[ApprovalRow]:
        """Approval requests, newest first, optionally only one status."""
        with self._storage().transaction() as tx:
            return tx.approvals(status)

    def approval_votes(self, approval_id: str) -> list[VoteRow]:
        """The votes cast on one approval."""
        with self._storage().transaction() as tx:
            return tx.approval_votes(approval_id)

    def expire_approvals(self) -> list[ApprovalRow]:
        """Expire requests past their time and approvals whose action never started in time.

        Either way the action will not run, and its budget hold is released.
        """
        with self._storage().transaction() as tx:
            return tx.expire_approvals(stale_after=self.approval_ttl)

    def approval_card(self, approval_id: str) -> dict[str, object]:
        """The readable card for an approval, with its status and votes."""
        with self._storage().transaction() as tx:
            row = tx.get_approval(approval_id)
            if row is None:
                raise ApprovalError(f"approval {approval_id} does not exist")
            votes = tx.approval_votes(approval_id)
        card: dict[str, object] = json.loads(row.summary) if row.summary else {}
        card.update(
            approval_id=row.approval_id, intent_id=row.intent_id, status=row.status,
            requested_at=row.requested_at, expires_at=row.expires_at, required=row.required,
            roles=list(row.allowed_roles()),
            votes=[{"approver": v.approver, "decision": v.decision, "note": v.note}
                   for v in votes],
        )  # fmt: skip
        return card

    def approval_links(
        self, approval_id: str, *, approver: str, base_url: str, roles: Sequence[str] = ()
    ) -> dict[str, str]:
        """Signed one-tap approve and reject links for one approver."""
        row = self.approval(approval_id)
        if row is None:
            raise ApprovalError(f"approval {approval_id} does not exist")
        return {
            decision: link_url(base_url, link_token(
                self._key, row, LinkClaim(approval_id, approver, tuple(roles), decision)))
            for decision in ("approve", "reject")
        }  # fmt: skip

    def decide_by_link(self, token: str, *, note: str | None = None) -> ApprovalRow:
        """Apply the decision in a signed link. A link works for its own approval only, once."""
        claim, _ = read_link(token)
        row = self.approval(claim.approval_id)
        if row is None:
            raise ApprovalError("this approval link's signature does not match")
        check_link(self._key, token, row)
        return self._vote(claim.approval_id, approver=claim.approver, roles=claim.roles,
                          decision=claim.decision, note=note,
                          token_hash=row.intent_hash)  # fmt: skip

    def _notify(self, approval: ApprovalRow) -> None:
        if self.notifier is None:
            return
        with contextlib.suppress(Exception):  # a channel failure must never fail the call
            self.notifier.notify(self, approval, self.approval_card(approval.approval_id))

    # ------------------------------------------------------------ reading

    def runs(self, *, limit: int = 50) -> list[RunRow]:
        """The most recent runs, newest first."""
        with self._storage().transaction() as tx:
            return tx.runs(limit=limit)

    def run_record(self, run_id: str) -> RunRow | None:
        """One run as stored, or None."""
        with self._storage().transaction() as tx:
            return tx.get_run(run_id)

    def find_intents(
        self,
        *,
        run_id: str | None = None,
        state: IntentState | None = None,
        tool: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[IntentRow]:
        """Intents matching every filter given, newest first."""
        with self._storage().transaction() as tx:
            return tx.find_intents(run_id=run_id, state=state, tool=tool, since=since, limit=limit)

    def intent_events(self, intent_id: str) -> list[Event]:
        """One intent's history, in order."""
        with self._storage().transaction() as tx:
            return tx.intent_events(intent_id)

    def events(self) -> list[Event]:
        """Every audit event, in order."""
        return list(self._storage().events())

    def intent(self, intent_id: str) -> IntentRow | None:
        """The intent with this id, or None."""
        with self._storage().transaction() as tx:
            return tx.get_intent(intent_id)

    def intent_by_key(self, key: str) -> IntentRow | None:
        """The intent with this idempotency key, or None."""
        with self._storage().transaction() as tx:
            return tx.get_intent_by_key(key)

    def preview_of(self, intent_id: str) -> Preview | None:
        """The latest preview recorded for an intent (redacted, for approvers), or None."""
        with self._storage().transaction() as tx:
            event = tx.latest_event(intent_id, "preview")
        return None if event is None else Preview.from_record(json.loads(event.payload))

    def receipt(self, intent_id: str) -> ReceiptRow | None:
        """The receipt of an intent, or None."""
        with self._storage().transaction() as tx:
            return tx.get_receipt(intent_id)

    def stale_count(self) -> int:
        """How many EXECUTING intents have an expired lease right now."""
        with self._storage().transaction() as tx:
            return len(tx.stale_executions())

    def verify(self) -> VerifyResult:
        """Check the audit chain and every record against it."""
        return self._storage().verify()

    def export_text(self) -> str:
        """Everything the ledger stores, as text (for audits and secret checks)."""
        return "\n".join(self._storage()._conn.iterdump())


_BUDGET: Final = "A budget limit would be exceeded."


_MIN_SCRUB: Final = 4
"""Shorter credential values are not scrubbed: they would match ordinary text."""
_CREDENTIAL_MARK: Final = "[credential]"
_UNREPRESENTABLE: Final = "[unrepresentable result]"
_CARRY_BUDGET: Final = 10_000
_NOT_FOLLOWED: Final = (type, ModuleType, CodeType, FrameType, BuiltinFunctionType)
_SCRUB_DEPTH: Final = 64


def _stop_beat(stop: threading.Event, beat: threading.Thread) -> None:
    stop.set()
    if beat.is_alive():
        beat.join()


def scrub_injected(value: object, injected: Mapping[str, object]) -> object:
    """``value`` with the credentials in ``injected`` replaced, as the ledger does to results.

    For integrations whose framework sees a tool's result before the ledger
    does (and may log it). Never raises.
    """
    return _scrub(value, _secret_values(injected))


def scrubbed_error(exc: BaseException, injected: Mapping[str, object]) -> BaseException:
    """``exc`` as the caller may see it: credentials in ``injected`` scrubbed or replaced.

    Returns ``exc`` itself when it shows no credential (its type kept, so the
    ledger can still tell a timeout from a failure).
    """
    return _present(exc, _secret_values(injected), None)


def _secret_values(kwargs: Mapping[str, object]) -> tuple[str, ...]:
    """The injected credential values worth scrubbing, with common encodings, longest first."""
    creds = kwargs.get("credentials")
    if not isinstance(creds, dict):
        return ()
    found: set[str] = set()
    for value in creds.values():
        if isinstance(value, str) and len(value) >= _MIN_SCRUB:
            found.update(_encodings(value))
    return tuple(sorted((s for s in found if len(s) >= _MIN_SCRUB), key=len, reverse=True))


def _encodings(secret: str) -> set[str]:
    """The secret as written, base64 (standard and URL-safe), URL-quoted and JSON-escaped."""
    raw = secret.encode()
    b64 = base64.b64encode(raw).decode()
    urlsafe = base64.urlsafe_b64encode(raw).decode()
    return {
        secret,
        b64,
        b64.rstrip("="),
        urlsafe,
        urlsafe.rstrip("="),
        quote(secret, safe=""),
        json.dumps(secret)[1:-1],
    }


def _scrub(value: object, secrets: tuple[str, ...], depth: int = 0) -> object:
    """Replace injected credential values anywhere in a tool result. Never raises.

    Containers are rebuilt; any other object whose text shows a credential is
    replaced by its scrubbed text, so neither the receipt nor the agent sees it.
    An object that cannot even be shown is replaced by a placeholder.
    """
    if not secrets or value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str | bytes):
        return _scrub_text(value, secrets)
    if depth < _SCRUB_DEPTH and isinstance(value, dict | list | tuple):
        return _scrub_container(value, secrets, depth + 1)
    try:
        text = repr(value)
    except Exception:  # noqa: BLE001 - a broken repr must not turn success into failure
        return _UNREPRESENTABLE
    if any(s in text for s in secrets) or _carries(value, secrets, [_CARRY_BUDGET]):
        # An object holding a credential (a response with its auth header, say)
        # is replaced by its scrubbed text: the agent must not get the object.
        return _scrub_text(text, secrets)
    return value


def _carries(value: object, secrets: tuple[str, ...], budget: list[int], depth: int = 0) -> bool:
    """Whether a credential hides anywhere inside an object's attributes.

    Too deep or too big to search counts as carrying one (fail safe).
    """
    budget[0] -= 1
    if budget[0] < 0 or depth > _SCRUB_DEPTH:
        return True
    if isinstance(value, str):
        return any(s in value for s in secrets)
    if isinstance(value, bytes):
        return any(s.encode() in value for s in secrets)
    if value is None or isinstance(value, bool | int | float):
        return False
    if isinstance(value, dict):
        items: list[object] = [*value.keys(), *value.values()]
    elif isinstance(value, list | tuple | set | frozenset):
        items = list(value)
    else:
        items = _attributes(value)
    return any(_carries(item, secrets, budget, depth + 1) for item in items)


def _attributes(value: object) -> list[object]:
    """What an object holds, for the credential search.

    Closure cells and defaults of functions, the bound object of methods, and
    the referents of anything else (instance dicts and every slot, inherited or
    private). Types, modules, code and frames are not followed: they lead into
    the whole program, not into the result.
    """
    if isinstance(value, FunctionType):
        found: list[object] = list(value.__defaults__ or ())
        found += list((value.__kwdefaults__ or {}).values())
        for cell in value.__closure__ or ():
            with contextlib.suppress(ValueError):  # an empty cell
                found.append(cell.cell_contents)
    elif isinstance(value, MethodType):
        found = [value.__self__, value.__func__]
    else:
        found = list(gc.get_referents(value))
    return [item for item in found if not isinstance(item, _NOT_FOLLOWED)]


def _scrub_text(value: str | bytes, secrets: tuple[str, ...]) -> str | bytes:
    for secret in secrets:
        if isinstance(value, str):
            value = value.replace(secret, _CREDENTIAL_MARK)
        else:
            value = value.replace(secret.encode(), _CREDENTIAL_MARK.encode())
    return value


def _scrub_container(
    value: dict[object, object] | list[object] | tuple[object, ...],
    secrets: tuple[str, ...],
    depth: int,
) -> object:
    if isinstance(value, dict):
        return {_scrub(k, secrets, depth): _scrub(v, secrets, depth) for k, v in value.items()}
    items = [_scrub(v, secrets, depth) for v in value]
    return items if isinstance(value, list) else tuple(items)


def _present(
    exc: BaseException, secrets: tuple[str, ...], outer: BaseException | None
) -> BaseException:
    """What the caller sees of a tool error: scrubbed or replaced, its frames' locals cleared.

    ``outer`` is the error the caller was already handling when it made the
    call. It and everything behind it belong to the caller and are left alone.
    """
    safe = _scrubbed_exception(exc, secrets, outer)
    _clear_tool_frames(exc, outer)
    return safe


def _as_outcome(exc: BaseException, safe: BaseException, *, ambiguous: bool) -> BaseException:
    """UnknownOutcome (caused by the scrubbed error) when the tool may have acted."""
    if not ambiguous or not isinstance(exc, Exception):
        return safe
    unknown = UnknownOutcome("the tool failed after it may have acted")
    unknown.__cause__ = safe
    unknown.__suppress_context__ = True
    return unknown


def _exception_chain(exc: BaseException, stop: BaseException | None = None) -> list[BaseException]:
    """The exception, its causes and contexts, and group members, up to ``stop`` (excluded)."""
    found: list[BaseException] = []
    pending: list[BaseException] = [exc]
    seen: set[int] = set() if stop is None else {id(stop)}
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        found.append(current)
        pending.extend(e for e in (current.__cause__, current.__context__) if e is not None)
        pending.extend(getattr(current, "exceptions", ()))
    return found


def _clear_tool_frames(exc: BaseException, outer: BaseException | None) -> None:
    """Drop the local variables of every finished frame the tool's error passed through.

    Only errors raised during the call are touched (the walk stops at the
    caller's own ``outer`` error). The first frame of the error's traceback is
    the executor's, which is still running, so it is skipped; its credential
    locals are reset by hand.
    """
    for current in _exception_chain(exc, outer):
        tb = current.__traceback__
        if current is exc and tb is not None:
            tb = tb.tb_next
        while tb is not None:
            with contextlib.suppress(RuntimeError):  # a frame that is still executing
                tb.tb_frame.clear()
            tb = tb.tb_next


def _scrubbed_exception(
    exc: BaseException, secrets: tuple[str, ...], outer: BaseException | None = None
) -> BaseException:
    """Scrub credentials from an exception, its group members, causes and attributes.

    Scrubbing happens in place. If the text still shows a credential (a custom
    ``__str__``, say), a replacement with the scrubbed text is returned instead,
    to be raised without the original attached: a ScrubbedToolError for
    ordinary errors, and the nearest class that can carry the text safely for
    interrupts and cancellations, which must keep their meaning.
    """
    if not secrets:
        return exc
    for current in _exception_chain(exc, outer):
        _scrub_one_exception(current, secrets)
    if not _shows(exc, secrets, seen=set() if outer is None else {id(outer)}):
        return exc
    text = str(_scrub_text(f"{type(exc).__name__}: {_safe_str(exc)}", secrets))
    if isinstance(exc, Exception):
        return ScrubbedToolError(text)
    for cls in type(exc).__mro__:
        if not (isinstance(cls, type) and issubclass(cls, BaseException)):
            continue
        try:
            candidate = cls(text)
        except Exception:  # noqa: BLE001, S112 - a constructor with other arguments
            continue
        if not _shows(candidate, secrets, seen=set()):
            return candidate
    return BaseException(text)  # pragma: no cover, BaseException(text) always qualifies


def _scrub_one_exception(exc: BaseException, secrets: tuple[str, ...]) -> None:
    try:
        exc.args = tuple(_scrub(a, secrets) for a in exc.args)
        notes = getattr(exc, "__notes__", None)
        if isinstance(notes, list):
            exc.__notes__ = [str(_scrub(n, secrets)) for n in notes]
        for name, attr in list(vars(exc).items()):
            if not name.startswith("__"):
                setattr(exc, name, _scrub(attr, secrets))
    except Exception:  # noqa: BLE001, S110 - read-only attributes; _shows decides the rest
        pass


def _shows(exc: BaseException, secrets: tuple[str, ...], seen: set[int]) -> bool:
    """Whether the exception or anything it carries still shows a credential."""
    if id(exc) in seen:
        return False
    seen.add(id(exc))
    text = _safe_str(exc) + _safe_repr(exc)
    if any(s in text for s in secrets):
        return True
    linked = [e for e in (exc.__cause__, exc.__context__) if e is not None]
    linked += list(getattr(exc, "exceptions", ()))
    return any(_shows(e, secrets, seen) for e in linked)


def _safe_str(exc: BaseException) -> str:
    try:
        return str(exc)
    except Exception:  # noqa: BLE001 - only used to look for credentials
        return ""


def _safe_repr(exc: BaseException) -> str:
    try:
        return repr(exc) + repr(vars(exc))
    except Exception:  # noqa: BLE001 - only used to look for credentials
        return ""


def _short(value: object) -> object:
    """A card shows short values: long text keeps its head and tail and says how long it is.

    The card also carries ``args_full`` and ``truncated``, so nothing is hidden
    from an approver who looks.
    """
    if isinstance(value, str) and len(value) > _CARD_TEXT_LIMIT:
        return f"{value[:80]} ... {value[-40:]} ({len(value):,} characters)"
    if isinstance(value, dict | list) and len(json.dumps(value)) > _CARD_TEXT_LIMIT:
        return f"<{type(value).__name__} of {len(value)} items, cut>"
    return value


def _by_id(row: IntentRow) -> str:
    return row.intent_id


def _decision_fields(decision: Decision) -> dict[str, object]:
    # A delay is stored as allow: the SCHEDULED state, scheduled_for and the
    # shadow decision (what enforce mode decided) record the window.
    return {
        "decision": "allow" if decision.outcome == "delay" else decision.outcome,
        "decision_rule": decision.rule_id,
        "decision_reason": decision.reason,
        "shadow_decision": decision.shadow_outcome,
    }


def _run_mode(run: RunRow) -> Literal["enforce", "shadow"] | None:
    return "shadow" if run.mode == "shadow" else "enforce"


def _sync_result(result: object) -> object:
    if inspect.isawaitable(result):
        close = getattr(result, "close", None)
        if callable(close):
            close()  # never awaited: close it so it does not warn later
        raise TypeError("this tool is async; call it with aexecute")
    return result


def _external_id(result: object) -> str | None:
    if isinstance(result, Mapping):
        for name in ("id", "external_id", "refund_id", "charge_id", "message_id"):
            value = result.get(name)
            if isinstance(value, str):
                return value
    return None


def _stored_result(receipt: ReceiptRow | None) -> object:
    if receipt is None or receipt.result_redacted is None:
        return None
    return json.loads(receipt.result_redacted)
