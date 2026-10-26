"""No injected credential reaches the agent: results, errors, causes and traceback frames."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from arbitr.core.errors import LedgerUnavailable, ScrubbedToolError, StorageError, UnknownOutcome
from arbitr.core.spec import ToolSpec
from arbitr.core.states import IntentState
from arbitr.credentials import EnvCredentials
from arbitr.executor import Ledger, current_run
from arbitr.policy.schema import load_policy
from arbitr.storage import sqlite

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

KEY = b"scrubbing-tests!" * 2
POLICY = load_policy("version: 1\ndefault: { financial: allow }\n")
ARGS = {"order_id": "o1", "amount": 5}
TOKEN = "tok_" + "live_" + "5a6b7c8d9e0f"  # a fake credential, built from pieces for scanners
SPEC = ToolSpec(name="payments.refund", effect="financial", credentials=("stripe",))


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[Ledger]:
    creds = EnvCredentials(environ={"ARBITR_CRED_STRIPE": TOKEN})
    with Ledger.open(tmp_path / "l.db", POLICY, key=KEY, credentials=creds) as led:
        yield led


def chain(exc: BaseException) -> Iterator[BaseException]:
    """The exception, its causes and contexts, and group members."""
    pending, seen = [exc], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        pending += [e for e in (current.__cause__, current.__context__) if e is not None]
        pending += list(getattr(current, "exceptions", ()))


def frame_locals(exc: BaseException) -> Iterator[str]:
    """repr of every local in every traceback frame of the chain."""
    for current in chain(exc):
        tb = current.__traceback__
        while tb is not None:
            for name, value in tb.tb_frame.f_locals.items():
                yield f"{tb.tb_frame.f_code.co_name}:{name}={value!r}"
            tb = tb.tb_next


def leaks(exc: BaseException) -> list[str]:
    found = [repr(e) for e in chain(exc) if TOKEN in f"{e!s}{e!r}{vars(e)!r}"]
    found += [line for line in frame_locals(exc) if TOKEN in line]
    return found


def call(ledger: Ledger, tool: Callable[..., object], spec: ToolSpec = SPEC) -> BaseException:
    with ledger.run("alice", "bot"):
        try:
            ledger.execute(spec, ARGS, tool)
        except BaseException as exc:  # noqa: BLE001 - the test inspects what came back
            return exc
    raise AssertionError("the call did not raise")


def acall(ledger: Ledger, tool: Callable[..., object], spec: ToolSpec = SPEC) -> BaseException:
    async def go() -> BaseException:
        with ledger.run("alice", "bot"):
            try:
                await ledger.aexecute(spec, ARGS, tool)
            except BaseException as exc:  # noqa: BLE001 - the test inspects what came back
                return exc
        raise AssertionError("the call did not raise")

    return asyncio.run(go())


class SneakyTimeoutError(TimeoutError):
    def __str__(self) -> str:
        return f"timed out talking to the API with {TOKEN}"


def times_out_loudly(order_id: str, amount: float, credentials: dict[str, str]) -> object:
    raise SneakyTimeoutError


async def async_times_out_loudly(
    order_id: str, amount: float, credentials: dict[str, str]
) -> object:
    raise SneakyTimeoutError


def fails_plainly(order_id: str, amount: float, credentials: dict[str, str]) -> object:
    key = credentials["stripe"]
    raise ValueError(f"declined for {key}")


async def async_fails_plainly(order_id: str, amount: float, credentials: dict[str, str]) -> object:
    key = credentials["stripe"]
    raise ValueError(f"declined for {key}")


@pytest.mark.parametrize(
    ("runner", "tool"), [(call, times_out_loudly), (acall, async_times_out_loudly)]
)
def test_an_unknown_outcome_never_carries_the_credential(
    ledger: Ledger, runner: Callable[..., BaseException], tool: Callable[..., object]
) -> None:
    exc = runner(ledger, tool)
    assert isinstance(exc, UnknownOutcome)
    assert leaks(exc) == []


@pytest.mark.parametrize(("runner", "tool"), [(call, fails_plainly), (acall, async_fails_plainly)])
def test_no_traceback_frame_holds_the_credential(
    ledger: Ledger, runner: Callable[..., BaseException], tool: Callable[..., object]
) -> None:
    exc = runner(ledger, tool)
    assert isinstance(exc, ValueError)
    assert leaks(exc) == []


UNTRUSTED = ToolSpec(
    name="payments.refund", effect="financial", credentials=("stripe",), untrusted_output=True
)


def _fail_outcome_writes(monkeypatch: pytest.MonkeyPatch, *, taint_too: bool) -> None:
    """The ledger cannot record FAILED or UNKNOWN (and, with ``taint_too``, the taint)."""
    transition = sqlite.Transaction.transition

    def no_outcome(
        self: object, intent_id: str, target: IntentState, *a: object, **k: object
    ) -> object:
        if target in (IntentState.FAILED, IntentState.UNKNOWN):
            raise StorageError("disk full")
        return transition(self, intent_id, target, *a, **k)  # type: ignore[arg-type]

    def no_taint(self: object, *a: object, **k: object) -> None:
        raise StorageError("disk full")

    monkeypatch.setattr(sqlite.Transaction, "transition", no_outcome)
    if taint_too:
        monkeypatch.setattr(sqlite.Transaction, "add_taint", no_taint)


@pytest.mark.parametrize(("runner", "tool"), [(call, fails_plainly), (acall, async_fails_plainly)])
def test_a_lost_taint_write_fails_closed_without_the_credential(
    ledger: Ledger,
    monkeypatch: pytest.MonkeyPatch,
    runner: Callable[..., BaseException],
    tool: Callable[..., object],
) -> None:
    _fail_outcome_writes(monkeypatch, taint_too=True)
    exc = runner(ledger, tool, UNTRUSTED)
    assert isinstance(exc, LedgerUnavailable)
    assert "the action ran" not in str(exc)
    assert leaks(exc) == []


@pytest.mark.parametrize(("runner", "tool"), [(call, fails_plainly), (acall, async_fails_plainly)])
def test_a_lost_outcome_write_still_taints_the_run(
    ledger: Ledger,
    monkeypatch: pytest.MonkeyPatch,
    runner: Callable[..., BaseException],
    tool: Callable[..., object],
) -> None:
    _fail_outcome_writes(monkeypatch, taint_too=False)
    exc = runner(ledger, tool, UNTRUSTED)
    assert isinstance(exc, ValueError)
    assert leaks(exc) == []
    (row,) = ledger.find_intents(tool="payments.refund")
    assert ledger.run_record(row.run_id).taint.untrusted_input  # type: ignore[union-attr]


def test_async_errors_that_cannot_be_scrubbed_are_replaced(ledger: Ledger) -> None:
    class StubbornError(Exception):
        def __str__(self) -> str:
            return f"key {TOKEN}"

    async def tool(order_id: str, amount: float, credentials: dict[str, str]) -> object:
        raise StubbornError

    exc = acall(ledger, tool)
    assert isinstance(exc, ScrubbedToolError)
    assert leaks(exc) == []


def test_an_interrupt_keeps_its_class(ledger: Ledger) -> None:
    class Halt(KeyboardInterrupt):
        def __str__(self) -> str:
            return f"stopped while holding {TOKEN}"

    def tool(order_id: str, amount: float, credentials: dict[str, str]) -> object:
        raise Halt

    exc = call(ledger, tool)
    assert isinstance(exc, KeyboardInterrupt)
    assert TOKEN not in f"{exc!s}{exc!r}"


class Response:
    """Like an HTTP client response: a harmless repr, the credential inside."""

    def __init__(self, token: str) -> None:
        self.status = 200
        self.headers = {"Authorization": f"Bearer {token}"}

    def __repr__(self) -> str:
        return "<Response [200]>"


@pytest.mark.parametrize("asynchronous", [False, True])
def test_a_result_object_that_hides_the_credential_is_replaced(
    ledger: Ledger, asynchronous: bool
) -> None:
    def tool(order_id: str, amount: float, credentials: dict[str, str]) -> object:
        return Response(credentials["stripe"])

    async def atool(order_id: str, amount: float, credentials: dict[str, str]) -> object:
        return Response(credentials["stripe"])

    with ledger.run("alice", "bot"):
        if asynchronous:
            seen = asyncio.run(ledger.aexecute(SPEC, ARGS, atool))
        else:
            seen = ledger.execute(SPEC, ARGS, tool)
        run = current_run()
        assert run is not None
        row = ledger.intent_by_key(run.last_idempotency_key)
    assert TOKEN not in repr(seen)
    assert TOKEN not in repr(getattr(seen, "__dict__", {}))
    assert row is not None
    assert row.state == IntentState.SUCCEEDED


def test_an_object_without_the_credential_is_returned_as_is(ledger: Ledger) -> None:
    keep = Response("not-the-token")
    with ledger.run("alice", "bot"):
        assert ledger.execute(SPEC, ARGS, lambda order_id, amount, credentials: keep) is keep


# ---------------------------------------------------------------- the caller keeps its own errors


def agent_problem() -> None:
    """Raises from a frame that has finished by the time the tool is called."""
    note = "the agent's own local"
    raise LookupError(f"agent problem ({len(note)})")


def helper_locals(exc: BaseException) -> dict[str, object]:
    tb = exc.__traceback__
    assert tb is not None
    assert tb.tb_next is not None
    return dict(tb.tb_next.tb_frame.f_locals)


def test_a_call_from_an_except_block_leaves_the_agents_error_alone(ledger: Ledger) -> None:
    def agent() -> tuple[BaseException, BaseException]:
        try:
            agent_problem()
        except LookupError as own:
            try:
                ledger.execute(SPEC, ARGS, fails_plainly)
            except ValueError as tool_error:
                return own, tool_error
        raise AssertionError("unreachable")  # pragma: no cover

    with ledger.run("alice", "bot"):
        own, tool_error = agent()
    assert leaks(tool_error) == []
    assert helper_locals(own).get("note") == "the agent's own local"


def test_an_async_call_from_an_except_block_keeps_the_agent_running(ledger: Ledger) -> None:
    async def agent() -> tuple[str, BaseException, BaseException]:
        note = "kept"
        try:
            agent_problem()
        except LookupError as own:
            try:
                await ledger.aexecute(SPEC, ARGS, async_fails_plainly)
            except ValueError as tool_error:
                await asyncio.sleep(0)  # the agent's coroutine must still be alive
                return note, own, tool_error
        raise AssertionError("unreachable")  # pragma: no cover

    with ledger.run("alice", "bot"):
        note, own, tool_error = asyncio.run(agent())
    assert note == "kept"
    assert leaks(tool_error) == []
    assert helper_locals(own).get("note") == "the agent's own local"


# ---------------------------------------------------------------- credentials hidden in odd places


class Base:
    __slots__ = ("token",)


class Child(Base):
    __slots__ = ()

    def __repr__(self) -> str:
        return "<Child>"


class OneSlot:
    __slots__ = "token"  # noqa: PLC0205 - a single string on purpose

    def __repr__(self) -> str:
        return "<OneSlot>"


class Private:
    __slots__ = ("__token",)

    def __init__(self, token: str) -> None:
        self.__token = token

    def __repr__(self) -> str:
        return "<Private>"


class Client:
    def __init__(self, token: str) -> None:
        self.auth = lambda: f"Bearer {token}"  # the token lives in a closure cell

    def __repr__(self) -> str:
        return "<Client>"


def build(kind: str, token: str) -> object:
    if kind == "inherited":
        child = Child()
        child.token = token
        return child
    if kind == "string-slots":
        one = OneSlot()
        one.token = token
        return one
    if kind == "private":
        return Private(token)
    return Client(token)


@pytest.mark.parametrize("kind", ["inherited", "string-slots", "private", "closure"])
def test_credentials_in_slots_and_closures_are_found(ledger: Ledger, kind: str) -> None:
    def tool(order_id: str, amount: float, credentials: dict[str, str]) -> object:
        return build(kind, credentials["stripe"])

    with ledger.run("alice", "bot"):
        seen = ledger.execute(SPEC, ARGS, tool)
    assert isinstance(seen, str), f"the {kind} object was returned as it is"
    assert TOKEN not in seen
