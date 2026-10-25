"""The real executor under the simulator: racing workers, crashes, a cancel window.

Several virtual workers share one run and race on a few idempotency keys
through the real ``Ledger`` (real SQLite file, real executor). Each worker is
a ``Fiber``; the executor's ``on_step`` hook pauses it at every protocol
step, so the seeded scheduler decides every interleaving and can crash a
worker at any step. A crashed worker restarts as a new process would: a new
worker id, ``recover_stale`` on startup, then its plan again from the top.
Some seeds also run a scheduler worker (``run_due``) for a tool with a one
second cancel window, while clients cancel some of those actions.

Determinism. The ledger runs on the simulator's virtual clock (the ``clock``
option) with the heartbeat thread off (``heartbeat=False``). Virtual time
only moves when every live worker is sleeping, so a live worker keeps its
lease as the heartbeat would keep it, and only a crashed worker's lease runs
out. Ids (intents, approvals, the install id) come from a seeded ULID
generator while a seed runs (``seeded_ids``). With that, the whole event
chain, hashes included, is a pure function of the seed.

After the run, a final recovery pass moves virtual time past every lease and
window, runs ``recover_stale`` and ``run_due``, and calls every key once more.
Then ``check`` tests the protocol invariants on the ledger and the services:

- AtMostOnceEffect: native and probe tools take effect at most once per key.
- NoSilentRetry: a ``none`` tool takes effect again only after its intent
  went UNKNOWN and the policy explicitly chose to retry (UNKNOWN to EXECUTING).
- NoExecuteWithoutLedger: the n-th side effect of a key happens while its
  intent is EXECUTING, after at least n EXECUTING transitions.
- CancelMeansNoEffect: a cancelled action never took effect.
- The ledger verifies, and every intent is settled: no PROPOSED, APPROVED or
  EXECUTING intent is left.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import sqlite3
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal

from bench.fakes.payments import FakePayments, LostResponse
from engine import FaultPlan, Simulator, Sleep, Step
from fiber import Fiber, fiber_worker
from workloads import InvariantError

import arbitr.core.intent
import arbitr.executor
import arbitr.storage.sqlite
from arbitr.core.errors import ActionError, ActionScheduled, StaleStateError
from arbitr.core.intent import new_ulid
from arbitr.core.redact import Redactor
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.executor import Ledger
from arbitr.policy.schema import load_policy
from arbitr.storage.sqlite import SQLiteStorage

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from engine import VirtualClock, WorkerGen

    from arbitr.policy.schema import Policy

Mode = Literal["native", "probe", "none", "delayed"]
S = IntentState

KEY: Final = b"deterministic-simulation-key!!!!"
EPOCH: Final = datetime(2030, 1, 1, tzinfo=UTC)
RUN_ID: Final = "sim-run"
PRINCIPAL: Final = "alice"
AGENT: Final = "bot"
LEASE_TTL: Final = 30.0
"""Virtual seconds. Long, because the executor's lease check right before a call
(``_confirm_lease``) measures wall time: a third of this (10 s of wall time)
must never pass between a fiber taking a lease and calling the tool."""
BACKOFF: Final = (4.0, 16.0)
WINDOW_SECONDS: Final = 1
MAX_TRIES: Final = 6
SCHEDULER_ROUNDS: Final = 10
OUTCOMES: Final = ("ok", "lost", "declined", "timeout")
WEIGHTS: Final = (0.75, 0.1, 0.08, 0.07)
UNSETTLED: Final = frozenset({S.PROPOSED, S.APPROVED, S.EXECUTING})
AT_MOST_ONCE: Final = frozenset({"native", "probe", "delayed"})


class Declined(Exception):  # noqa: N818 - named after what happens
    """The service refused before acting: a plain failure, recorded as FAILED."""


@dataclass(frozen=True)
class Order:
    """One idempotency key the workers race on."""

    key: str
    order_id: str
    mode: Mode
    amount: float


@dataclass(frozen=True)
class Effect:
    """A side effect the fake service applied, with the ledger's last event seq then."""

    order_id: str
    seq: int


@contextmanager
def seeded_ids(clock: VirtualClock, seed: int) -> Iterator[None]:
    """Make every ULID the ledger creates come from the virtual clock and the seed.

    The time part is virtual time and the random part is a hash of the seed
    and a counter, so ids look like real ULIDs (and sort the same way) but
    repeat exactly when a seed is replayed. Only for one simulated run.
    """
    counter = itertools.count()
    epoch_ms = int(EPOCH.timestamp() * 1000)

    def make(timestamp_ms: int | None = None, randomness: bytes | None = None) -> str:
        noise = hashlib.sha256(f"{seed}:{next(counter)}".encode()).digest()[:10]
        return new_ulid(epoch_ms + int(clock.now * 1000), noise)

    modules = (arbitr.core.intent, arbitr.executor, arbitr.storage.sqlite)
    name = "new_ulid"
    saved = [vars(m)[name] for m in modules]
    for module in modules:
        setattr(module, name, make)
    try:
        yield
    finally:
        for module, original in zip(modules, saved, strict=True):
            setattr(module, name, original)


@lru_cache(maxsize=8)
def policy_for(on_unknown: str) -> Policy:
    """The simulation policy: allow refunds, hold payouts for a cancel window, cap them."""
    return load_policy(f"""
version: 1
default: {{ financial: allow }}
on_unknown: {on_unknown}
rules:
  - id: hold-payouts
    when: {{ tool: payments.payout }}
    then: delay {WINDOW_SECONDS}s
    reason: Payouts wait so someone can cancel them.
  - id: payout-cap
    when: {{ tool: payments.payout }}
    budget: {{ scope: [run], sum_path: "$.amount", limit: 100 }}
    then_exceeded: deny
    reason: Payout cap for the run.
""")


def specs_for(on_unknown: str) -> dict[Mode, ToolSpec]:
    """One tool per idempotency mode, plus the delayed payout."""
    return {
        "native": ToolSpec(name="payments.refund", effect="financial", idempotency="native"),
        "probe": ToolSpec(
            name="payments.refund_probed",
            effect="financial",
            idempotency="probe",
            probe="bench.fakes.probes:find_refund",
        ),
        "none": ToolSpec(
            name="payments.refund_plain",
            effect="financial",
            idempotency="none",
            allow_duplicates=on_unknown == "retry",
        ),
        "delayed": ToolSpec(name="payments.payout", effect="financial", idempotency="native"),
    }


class LedgerWorkload:
    """Racing workers on the real ledger, with crashes, recovery and a cancel window."""

    def __init__(self, sim: Simulator, root: Path) -> None:
        """Choose this seed's setup with the simulator's rng and spawn the workers."""
        self.sim = sim
        self.db = root / "ledger.db"
        self.dead = root / "gone" / "ledger.db"  # never created: a killed worker's writes fail
        rng = sim.rng
        self.on_unknown = rng.choice(["require_approval", "require_approval", "fail", "retry"])
        self.delayed = rng.random() < 0.4
        modes: list[Mode] = ["native", "probe", "none"]
        if self.delayed:
            modes.append("delayed")
        self.orders = [
            Order(f"order-{i}", f"o{i}", rng.choice(modes), float(rng.choice([25, 60])))
            for i in range(rng.randint(2, 4))
        ]
        if self.delayed and all(o.mode != "delayed" for o in self.orders):
            self.orders[0] = Order("order-0", "o0", "delayed", 60.0)
        sim.faults = FaultPlan(rng.uniform(0.03, 0.2), rng.randint(0, 6))
        self.policy = policy_for(self.on_unknown)
        self.specs = specs_for(self.on_unknown)
        self.services = {m: FakePayments(native=m in ("native", "delayed")) for m in self.specs}
        self.tools = {self.specs[m].name: (self.specs[m], self._tool(m)) for m in self.specs}
        self.effects: list[Effect] = []
        self.kills: list[str] = []
        self.settling = False
        self.verified = (False, "the final pass did not run")
        self._live: dict[str, Ledger] = {}
        self._fibers: list[Fiber] = []
        self._incarnations: dict[str, int] = {}
        with self._ledger("setup") as ledger, ledger.run(PRINCIPAL, AGENT, run_id=RUN_ID):
            pass
        self._reader = sqlite3.connect(str(self.db), check_same_thread=False)
        for w in range(rng.randint(2, 4)):
            plan = [rng.choice(self.orders) for _ in range(rng.randint(2, 5))]
            self._spawn(f"w{w}", self._client_body(plan))
        if self.delayed:
            self._spawn("scheduler", self._scheduler)

    # ------------------------------------------------------------ plumbing

    def _now(self) -> datetime:
        return EPOCH + timedelta(seconds=self.sim.clock.now)

    def _ledger(self, worker_id: str, fiber: Fiber | None = None) -> Ledger:
        on_step = None if fiber is None else (lambda step: fiber.pause(Step(step)))
        ledger = Ledger.open(
            self.db, self.policy, key=KEY, worker_id=worker_id, lease_ttl=LEASE_TTL,
            on_step=on_step, clock=self._now, heartbeat=False,
        )  # fmt: skip
        ledger.probe_context["payments"] = self.services["probe"]
        return ledger

    def _spawn(self, name: str, body: Callable[[Fiber, int], None]) -> None:
        self._incarnations[name] = 0

        def start() -> WorkerGen:
            incarnation = self._incarnations[name]
            self._incarnations[name] += 1
            fiber = Fiber(f"{name}.{incarnation}", lambda f: body(f, incarnation))
            self._fibers.append(fiber)
            return fiber_worker(
                fiber, lambda: self._cut_off(fiber.name), lambda at: self._killed(fiber.name, at)
            )

        self.sim.spawn(name, start)

    def _open(self, fiber: Fiber) -> Ledger:
        ledger = self._ledger(fiber.name, fiber)
        self._live[fiber.name] = ledger
        return ledger

    def _cut_off(self, name: str) -> None:
        """Before a kill: close the worker's connections so nothing it does is durable."""
        ledger = self._live.pop(name, None)
        if ledger is not None:
            ledger.close()
            ledger.path = self.dead

    def _killed(self, name: str, at: str) -> None:
        self.kills.append(at)
        self.sim.record("killed", worker=name, at=at)

    def _last_seq(self) -> int:
        row = self._reader.execute("SELECT COALESCE(MAX(seq), 0) FROM events").fetchone()
        return int(row[0])

    def _tool(self, mode: Mode) -> Callable[..., object]:
        service = self.services[mode]

        def call(order_id: str, amount: float, idempotency_key: str | None = None) -> object:
            roll = "ok" if self.settling else self.sim.rng.choices(OUTCOMES, WEIGHTS)[0]
            if roll == "declined":
                raise Declined("the service declined the refund")
            if roll == "timeout":
                raise TimeoutError("no reply before the deadline")
            before = service.count(order_id)
            result = service.refund(order_id, amount, idempotency_key=idempotency_key)
            if service.count(order_id) > before:
                self.effects.append(Effect(order_id, self._last_seq()))
                self.sim.record("effect", order=order_id, mode=mode)
            if roll == "lost":
                raise LostResponse("the refund was made but the reply was lost")
            return result

        return call

    # ------------------------------------------------------------ workers

    def _client_body(self, plan: list[Order]) -> Callable[[Fiber, int], None]:
        def body(fiber: Fiber, incarnation: int) -> None:
            ledger = self._open(fiber)
            fiber.pause(Step("opened"))
            if incarnation > 0:
                self._recover(ledger, fiber)
            with ledger.run(PRINCIPAL, AGENT, run_id=RUN_ID, resume=True):
                for order in plan:
                    self._settle(ledger, fiber, order)
                    fiber.pause(Sleep(self.sim.rng.uniform(0.0, 0.1)))

        return body

    def _scheduler(self, fiber: Fiber, incarnation: int) -> None:
        ledger = self._open(fiber)
        fiber.pause(Step("opened"))
        if incarnation > 0:
            self._recover(ledger, fiber)
        for _ in range(SCHEDULER_ROUNDS):
            fiber.pause(Sleep(self.sim.rng.uniform(0.3, 6.0)))
            results = ledger.run_due(self.tools)
            self.sim.record("run_due", worker=fiber.name, actions=[r.action for r in results])

    def _recover(self, ledger: Ledger, fiber: Fiber) -> None:
        results = ledger.recover_stale()
        self.sim.record("recovered", worker=fiber.name, actions=[r.action for r in results])
        fiber.pause(Step("after_recover"))

    def _settle(self, ledger: Ledger, fiber: Fiber, order: Order) -> None:
        """Call one key like an agent: retry while in flight, sometimes after a failure."""
        rng = self.sim.rng
        for _ in range(MAX_TRIES):
            code, intent_id = self._attempt(ledger, order)
            self.sim.record("call", worker=fiber.name, key=order.key, outcome=code)
            retry = code in ("in_flight", "ledger_unavailable") or (
                code in ("failed", "unknown_outcome") and rng.random() < 0.5
            )
            if retry:
                fiber.pause(Sleep(rng.uniform(*BACKOFF)))
                continue
            if intent_id is not None and rng.random() < 0.5:
                fiber.pause(Sleep(rng.uniform(0.0, 1.5)))
                self._cancel(ledger, fiber, intent_id)
            return

    def _attempt(self, ledger: Ledger, order: Order) -> tuple[str, str | None]:
        """One ``execute``; the outcome code, and the intent id when it was scheduled."""
        mode = order.mode
        args = {"order_id": order.order_id, "amount": order.amount}
        try:
            ledger.execute(self.specs[mode], args, self.tools[self.specs[mode].name][1],
                           idempotency_key=order.key)  # fmt: skip
        except ActionScheduled as exc:
            return exc.code, exc.intent_id
        except ActionError as exc:
            return exc.code, None
        except Declined:
            return "failed", None
        return "ok", None

    def _cancel(self, ledger: Ledger, fiber: Fiber, intent_id: str) -> None:
        try:
            ledger.cancel(intent_id, reason="the agent changed its mind")
            outcome = "cancelled"
        except StaleStateError:
            outcome = "too_late"
        self.sim.record("cancel", worker=fiber.name, outcome=outcome)
        fiber.pause(Step("after_cancel"))

    # ------------------------------------------------------------ after the run

    def finish(self) -> None:
        """The final recovery pass, after every worker finished or crashed for good."""
        self.settling = True
        self.sim.clock.advance_to(self.sim.clock.now + LEASE_TTL + WINDOW_SECONDS + 1.0)
        with self._ledger("final") as ledger:
            recovered = ledger.recover_stale()
            self.sim.record("final_recover", actions=[r.action for r in recovered])
            due = ledger.run_due(self.tools)
            self.sim.record("final_run_due", actions=[r.action for r in due])
            with ledger.run(PRINCIPAL, AGENT, run_id=RUN_ID, resume=True):
                for order in self.orders:
                    if ledger.intent_by_key(order.key) is not None:
                        code, _ = self._attempt(ledger, order)
                        self.sim.record("final_call", key=order.key, outcome=code)
            verdict = ledger.verify()
            self.verified = (verdict.ok, verdict.describe())

    def close(self) -> None:
        """Kill any fiber still parked and close every connection and service."""
        for name in list(self._live):
            self._cut_off(name)
        for fiber in self._fibers:
            fiber.kill()
        self._reader.close()
        for service in self.services.values():
            service.close()

    def _intents(self) -> list[tuple[str, str, str, str]]:
        cur = self._reader.execute(
            "SELECT intent_id, idempotency_key, state, tool FROM intents ORDER BY intent_id"
        )
        return [(str(a), str(b), str(c), str(d)) for a, b, c, d in cur.fetchall()]

    def _events(self) -> list[tuple[object, ...]]:
        with SQLiteStorage.open(self.db, Redactor(KEY)) as db:
            return [
                (e.seq, e.intent_id, e.run_id, e.kind, e.payload, e.created_at, e.hash)
                for e in db.events()
            ]

    def digest(self) -> str:
        """A hash of the simulator history, the whole event chain and the final intents."""
        blob = json.dumps(
            [self.sim.history, self._events(), self._intents()],
            sort_keys=True, separators=(",", ":"),
        )  # fmt: skip
        return hashlib.sha256(blob.encode()).hexdigest()

    def check(self) -> None:
        """Check every invariant. Raises ``InvariantError`` naming the seed."""
        ok, description = self.verified
        if not ok:
            self._fail(f"the ledger does not verify: {description}")
        intents = {key: (iid, state) for iid, key, state, _ in self._intents()}
        history = _intent_history(self._events())
        for order in self.orders:
            found = intents.get(order.key)
            events = history.get(found[0], []) if found else []
            self._check_order(order, found[1] if found else None, events)
        for key, (_, state) in intents.items():
            if S(state) in UNSETTLED:
                self._fail(f"intent {key} ended in {state}")

    def _check_order(self, order: Order, state: str | None, events: list[_Ev]) -> None:
        effects = [e for e in self.effects if e.order_id == order.order_id]
        count = self.services[order.mode].count(order.order_id)
        if count != len(effects):
            self._fail(
                f"{order.key}: the service shows {count} effects, the tool saw {len(effects)}"
            )
        if order.mode in AT_MOST_ONCE and count > 1:
            self._fail(f"AtMostOnceEffect: {order.key} ({order.mode}) took effect {count} times")
        retries = sum(1 for e in events if e.kind == "executing" and e.source == "UNKNOWN")
        if order.mode == "none" and count > 1 + retries:
            self._fail(
                f"NoSilentRetry: {order.key} took effect {count} times with {retries}"
                " explicit retries after UNKNOWN"
            )
        if order.mode == "none" and retries and self.on_unknown != "retry":
            self._fail(
                f"NoSilentRetry: {order.key} ran again after UNKNOWN"
                f" under on_unknown={self.on_unknown}"
            )
        if state == S.CANCELLED and count:
            self._fail(f"CancelMeansNoEffect: cancelled {order.key} took effect")
        for n, effect in enumerate(effects, start=1):
            started = sum(1 for e in events if e.kind == "executing" and e.seq <= effect.seq)
            if started < n or _state_at(events, effect.seq) != S.EXECUTING:
                self._fail(
                    f"NoExecuteWithoutLedger: effect {n} of {order.key} at event {effect.seq}"
                    f" with {started} EXECUTING transitions, state {_state_at(events, effect.seq)}"
                )

    def _fail(self, message: str) -> None:
        raise InvariantError(f"seed {self.sim.seed}: {message}")


@dataclass(frozen=True)
class _Ev:
    seq: int
    kind: str
    source: str | None  # the "from" state of a transition


_LIFECYCLE: Final = {s.value.lower(): s for s in IntentState}


def _intent_history(events: list[tuple[object, ...]]) -> dict[str, list[_Ev]]:
    """Each intent's lifecycle events, in order."""
    out: dict[str, list[_Ev]] = {}
    for seq, intent_id, _, kind, payload, _, _ in events:
        if intent_id is None or (kind not in _LIFECYCLE and kind != "intent_created"):
            continue
        body = json.loads(str(payload))
        source = body.get("from") if isinstance(body, dict) else None
        ev = _Ev(int(str(seq)), str(kind), None if source is None else str(source))
        out.setdefault(str(intent_id), []).append(ev)
    return out


def _state_at(events: list[_Ev], seq: int) -> IntentState | None:
    """The intent's state right after event ``seq``, from its lifecycle events."""
    state: IntentState | None = None
    for ev in events:
        if ev.seq > seq:
            break
        state = S.PROPOSED if ev.kind == "intent_created" else _LIFECYCLE[ev.kind]
    return state


def run_ledger_seed(
    seed: int,
    *,
    verbose: bool = False,
    observe: Callable[[LedgerWorkload], None] | None = None,
) -> str:
    """Run one seed of the ledger workload, check its invariants, return its digest.

    ``observe`` (for tests) sees the workload after the checks pass, before it closes.
    """
    sim = Simulator(seed)
    with (
        tempfile.TemporaryDirectory(prefix="arbitr-sim-", ignore_cleanup_errors=True) as tmp,
        seeded_ids(sim.clock, seed),
    ):
        workload = LedgerWorkload(sim, Path(tmp))
        try:
            sim.run()
            workload.finish()
            if verbose:
                for event in sim.history:
                    print(event)  # noqa: T201 - the replay output
            workload.check()
            if observe is not None:
                observe(workload)
            return workload.digest()
        finally:
            workload.close()
