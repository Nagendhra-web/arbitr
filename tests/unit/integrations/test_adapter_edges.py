"""Edges of the shared adapter code and the LangGraph gate that whole agent runs rarely reach."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import SimpleNamespace
from typing import TYPE_CHECKING, Annotated, Any

import pytest
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool, InjectedToolArg, InjectedToolCallId, tool
from langgraph.types import Command
from pydantic import BaseModel

from adapter_support import KEY, POLICY, SPECS
from arbitr.core.errors import LedgerUnavailable, RunContextError
from arbitr.core.spec import ToolSpec
from arbitr.executor import Ledger as LedgerType
from arbitr.integrations import _common
from arbitr.integrations._common import (
    BadArguments,
    ensure_run,
    hide_injected,
    model_args,
    plain,
    spec_for,
)
from arbitr.integrations.langgraph import (
    ArbitrGate,
    _fields,
    _handled_types,
    _Injecting,
    guarded_tool_node,
)
from arbitr.testing.langgraph import ScriptedAgent, tool_messages

if TYPE_CHECKING:
    from arbitr.executor import Ledger

CONFIG: Any = {"configurable": {"thread_id": "t-e"}}


# ------------------------------------------------------------------ _common


def test_model_args_drop_injected_names_and_refuse_bad_shapes() -> None:
    assert model_args('{"a": 1, "idempotency_key": "x", "credentials": {}}') == {"a": 1}
    assert model_args(b'{"a": 2}') == {"a": 2}
    assert model_args("  ") == {}
    for bad in ("not json", "[1, 2]", 5):
        with pytest.raises(BadArguments):
            model_args(bad)


def test_hide_injected_handles_schemas_with_and_without_lists() -> None:
    schema = {
        "type": "object",
        "properties": {"a": {}, "idempotency_key": {}, "credentials": {}},
        "required": ["a", "credentials"],
    }
    assert hide_injected(schema) == {"type": "object", "properties": {"a": {}}, "required": ["a"]}
    assert schema["required"] == ["a", "credentials"]  # the original is left alone
    assert hide_injected({"type": "object"}) == {"type": "object"}


def test_spec_for_falls_back_to_a_write() -> None:
    assert spec_for("refund", SPECS) is SPECS["refund"]
    assert spec_for("other", SPECS).effect == "write"
    assert spec_for("other", None).name == "other"


@dataclass
class Point:
    x: int

    def to_dict(self) -> dict[str, int]:
        return {"x": self.x}


class Model(BaseModel):
    y: int


class Broken:
    def model_dump(self) -> object:
        raise ValueError("cannot")

    def __str__(self) -> str:
        return "broken"


def test_plain_turns_results_into_json_values() -> None:
    assert plain({"a": (1, Point(2)), 3: Model(y=4)}) == {"a": [1, {"x": 2}], "3": {"y": 4}}
    assert plain(Broken()) == "broken"
    assert plain(None) is None


def test_ensure_run_refuses_another_agent_and_tolerates_a_race(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    with ensure_run(ledger, "r-1", "alice", "billing"):
        pass
    with (
        pytest.raises(RunContextError, match="another agent"),
        ensure_run(ledger, "r-1", "alice", "support"),
    ):
        pass  # pragma: no cover

    # Another process creates the run between the check and the insert.
    real_run = ledger.run

    def racing_run(*args: object, **kwargs: object) -> object:
        if not kwargs.get("resume"):
            with real_run("alice", "bot", run_id="r-2"):
                pass
            raise LedgerUnavailable("the run could not be recorded")
        return real_run(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ledger, "run", racing_run)
    with ensure_run(ledger, "r-2", "alice", "bot"):
        pass

    def failing_run(*args: object, **kwargs: object) -> object:
        raise LedgerUnavailable("the disk is full")

    monkeypatch.setattr(ledger, "run", failing_run)
    with pytest.raises(LedgerUnavailable), ensure_run(ledger, "r-3", "alice", "bot"):
        pass  # pragma: no cover
    assert _common._RUNS_LOCK.acquire(blocking=False)  # never left held
    _common._RUNS_LOCK.release()


# ------------------------------------------------------------------ LangGraph gate


def test_injecting_proxy_passes_everything_else_through() -> None:
    @tool
    def echo(text: str) -> str:
        """Echo."""
        return text

    proxy = _Injecting(echo, {"idempotency_key": "k"}, {})
    assert proxy.name == "echo"
    assert proxy._with_values("plain text") == "plain text"


def test_fields_and_handled_types() -> None:
    assert _fields({"properties": {"a": {}}}) == {"a"}
    assert _fields(object()) is None
    assert _handled_types(KeyError) == (KeyError,)
    assert _handled_types((KeyError, ValueError)) == (KeyError, ValueError)
    assert _handled_types(True) == (Exception,)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_arguments_that_are_not_an_object_never_run(ledger: Ledger, asynchronous: bool) -> None:
    gate = ArbitrGate(ledger, SPECS, principal="alice")
    request = SimpleNamespace(
        tool=object(), tool_call={"name": "run_sql", "args": "DROP TABLE x", "id": "c1"}
    )

    def execute(_: object) -> ToolMessage:  # pragma: no cover - must not run
        raise AssertionError("ran")

    async def aexecute(_: object) -> ToolMessage:  # pragma: no cover - must not run
        raise AssertionError("ran")

    if asynchronous:
        message = asyncio.run(gate.awrap(request, aexecute))  # type: ignore[arg-type]
    else:
        message = gate.wrap(request, execute)  # type: ignore[arg-type]
    assert isinstance(message, ToolMessage)
    assert message.status == "error"
    assert "JSON object" in str(message.content)


def test_async_unknown_tools_and_errors(ledger: Ledger) -> None:
    @tool
    async def lookup(order_id: str) -> str:
        """Look up an order."""
        raise KeyError(order_id)

    node = guarded_tool_node(ledger, [lookup], principal="alice", handle_tool_errors=KeyError)
    agent = ScriptedAgent([[("lookup", {"order_id": "o-1"}), ("missing", {})]])
    state = asyncio.run(agent.graph(node).ainvoke({"messages": [("user", "go")]}, CONFIG))
    messages = tool_messages(state)
    assert [m.status for m in messages] == ["error", "error"]
    assert "KeyError('o-1')" in str(messages[0].content)


def test_a_tool_raising_a_setup_error_is_not_turned_into_a_message(ledger: Ledger) -> None:
    @tool
    def nested(text: str) -> str:
        """Call something that needs a run of its own."""
        raise RunContextError("tool calls must happen inside ledger.run(...)")

    node = guarded_tool_node(ledger, [nested], principal="alice", handle_tool_errors=True)
    agent = ScriptedAgent([[("nested", {"text": "x"})]])
    with pytest.raises(RunContextError):
        agent.graph(node).invoke({"messages": [("user", "go")]}, CONFIG)


def test_artifacts_go_back_with_the_message(ledger: Ledger) -> None:
    @tool(response_format="content_and_artifact")
    def chart(name: str) -> tuple[str, dict[str, int]]:
        """Draw a chart."""
        return f"chart {name}", {"points": 3}

    node = guarded_tool_node(ledger, [chart], principal="alice")
    state = (
        ScriptedAgent([[("chart", {"name": "sales"})]])
        .graph(node)
        .invoke({"messages": [("user", "go")]}, CONFIG)
    )
    (message,) = tool_messages(state)
    assert message.content == "chart sales"
    assert message.artifact == {"points": 3}


def test_artifacts_are_scrubbed_of_credentials(tmp_path: Any) -> None:
    secret = "cred-" + "value-3310"

    class Creds:
        def get(self, name: str) -> str:
            return secret

    @tool(response_format="content_and_artifact")
    def call_api(
        path: str, credentials: Annotated[dict[str, str] | None, InjectedToolArg] = None
    ) -> tuple[str, dict[str, str]]:
        """Call the API."""
        return "ok", {"auth_header": f"Bearer {(credentials or {}).get('api')}"}

    spec = ToolSpec(name="api.call", effect="write", credentials=("api",))
    with LedgerType.open(tmp_path / "a.db", POLICY, key=KEY, credentials=Creds()) as led:
        node = guarded_tool_node(led, [call_api], {"call_api": spec}, principal="alice")
        state = (
            ScriptedAgent([[("call_api", {"path": "/x"})]])
            .graph(node)
            .invoke({"messages": [("user", "go")]}, CONFIG)
        )
    (message,) = tool_messages(state)
    assert secret not in str(message.artifact)


def test_state_updates_are_scrubbed_of_credentials(tmp_path: Any) -> None:
    secret = "cred-" + "value-7781"

    class Creds:
        def get(self, name: str) -> str:
            return secret

    @tool
    def connect(
        account: str,
        tool_call_id: Annotated[str, InjectedToolCallId],
        credentials: Annotated[dict[str, str] | None, InjectedToolArg] = None,
    ) -> Command[Any]:
        """Connect an account."""
        token = (credentials or {}).get("api")
        note = ToolMessage(f"connected with {token}", tool_call_id=tool_call_id)
        return Command(update={"messages": [note], "token": [token]})

    spec = ToolSpec(name="api.connect", effect="write", credentials=("api",))
    with LedgerType.open(tmp_path / "s.db", POLICY, key=KEY, credentials=Creds()) as led:
        node = guarded_tool_node(led, [connect], {"connect": spec}, principal="alice")
        state = (
            ScriptedAgent([[("connect", {"account": "a-1"})]])
            .graph(node)
            .invoke({"messages": [("user", "go")]}, CONFIG)
        )
    (message,) = tool_messages(state)
    assert isinstance(message, ToolMessage)  # still a tool message, not text
    assert secret not in str(message.content)


def test_a_tool_run_around_the_injecting_proxy_ends_unknown(
    ledger: LedgerType, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arbitr.integrations import langgraph as adapter  # noqa: PLC0415

    keys: list[str | None] = []

    @tool
    def refund(
        order_id: str, idempotency_key: Annotated[str | None, InjectedToolArg] = None
    ) -> str:
        """Refund an order."""
        keys.append(idempotency_key)
        return "refunded"

    def bypass(self: Any, value: Any, config: Any = None, **kwargs: Any) -> Any:
        return self._tool.invoke(value, config, **kwargs)  # as if ToolNode called the tool directly

    monkeypatch.setattr(adapter._Injecting, "invoke", bypass)
    node = guarded_tool_node(ledger, [refund], {"refund": SPECS["refund"]}, principal="alice")
    state = (
        ScriptedAgent([[("refund", {"order_id": "o-1"})]])
        .graph(node)
        .invoke({"messages": [("user", "go")]}, CONFIG)
    )
    assert keys == [None]  # it ran without its key...
    (row,) = ledger.find_intents(tool="payments.refund")
    assert row.state.value == "UNKNOWN"  # ...so the ledger does not claim it succeeded
    assert "may or may not have happened" in str(tool_messages(state)[0].content)


def test_an_openai_tool_function_called_around_the_ledger_never_runs() -> None:
    from arbitr.integrations.openai_agents import _without_injected  # noqa: PLC0415

    ran: list[str] = []

    def refund(order_id: str, idempotency_key: str | None = None) -> str:
        ran.append(order_id)
        return "refunded"

    with pytest.raises(RunContextError, match="guarded tool"):
        _without_injected(refund)(order_id="o-1")
    assert ran == []


@pytest.mark.parametrize("asynchronous", [False, True])
def test_a_bypassed_tool_that_fails_also_ends_unknown(
    ledger: LedgerType, monkeypatch: pytest.MonkeyPatch, asynchronous: bool
) -> None:
    from arbitr.integrations import langgraph as adapter  # noqa: PLC0415

    def bypass(self: Any, value: Any, config: Any = None, **kwargs: Any) -> Any:
        return self._tool.invoke(value, config, **kwargs)

    async def abypass(self: Any, value: Any, config: Any = None, **kwargs: Any) -> Any:
        return await self._tool.ainvoke(value, config, **kwargs)

    monkeypatch.setattr(adapter._Injecting, "invoke", bypass)
    monkeypatch.setattr(adapter._Injecting, "ainvoke", abypass)

    @tool
    def refund(
        order_id: str, idempotency_key: Annotated[str | None, InjectedToolArg] = None
    ) -> str:
        """Refund an order."""
        raise ValueError("the payment service said no, after it may have acted")

    node = guarded_tool_node(
        ledger, [refund], {"refund": SPECS["refund"]}, principal="alice", handle_tool_errors=True
    )
    graph = ScriptedAgent([[("refund", {"order_id": "o-1"})]]).graph(node)
    state_in: Any = {"messages": [("user", "go")]}
    state = (
        asyncio.run(graph.ainvoke(state_in, CONFIG))
        if asynchronous
        else graph.invoke(state_in, CONFIG)
    )
    (row,) = ledger.find_intents(tool="payments.refund")
    assert row.state.value == "UNKNOWN"  # not FAILED: a retry must not run it again
    assert "may or may not have happened" in str(tool_messages(state)[0].content)


class _Tracer(BaseCallbackHandler):
    """Records what tracing (LangSmith and the like) would see of each tool call."""

    def __init__(self) -> None:
        self.seen: list[str] = []

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        self.seen.append(repr(output))

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        self.seen.append(repr(error))


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("fails", [False, True])
def test_callbacks_never_see_injected_credentials(
    tmp_path: Any, asynchronous: bool, fails: bool
) -> None:
    secret = "cred-" + "value-5521"

    class Creds:
        def get(self, name: str) -> str:
            return secret

    def body(credentials: dict[str, str] | None) -> str:
        token = (credentials or {}).get("api")
        if fails:
            raise ValueError(f"the API refused token {token}")
        return f"called with {token}"

    if asynchronous:

        @tool
        async def call_api(
            path: str, credentials: Annotated[dict[str, str] | None, InjectedToolArg] = None
        ) -> str:
            """Call the API."""
            return body(credentials)
    else:

        @tool
        def call_api(
            path: str, credentials: Annotated[dict[str, str] | None, InjectedToolArg] = None
        ) -> str:
            """Call the API."""
            return body(credentials)

    spec = ToolSpec(name="api.call", effect="write", credentials=("api",))
    tracer = _Tracer()
    config: Any = {"configurable": {"thread_id": "t-cb"}, "callbacks": [tracer]}
    with LedgerType.open(tmp_path / "cb.db", POLICY, key=KEY, credentials=Creds()) as led:
        node = guarded_tool_node(
            led, [call_api], {"call_api": spec}, principal="alice", handle_tool_errors=True
        )
        graph = ScriptedAgent([[("call_api", {"path": "/x"})]]).graph(node)
        state_in: Any = {"messages": [("user", "go")]}
        state = (
            asyncio.run(graph.ainvoke(state_in, config))
            if asynchronous
            else graph.invoke(state_in, config)
        )
    assert tracer.seen  # the tool call was traced
    assert all(secret not in seen for seen in tracer.seen)
    assert secret not in str(tool_messages(state)[0].content)


def test_tools_that_need_credentials_must_be_structured_tools(ledger: LedgerType) -> None:
    class Custom(BaseTool):
        name: str = "custom"
        description: str = "A tool with its own _run."

        def _run(
            self, path: str, credentials: Annotated[dict[str, str] | None, InjectedToolArg] = None
        ) -> str:
            return "ok"

    spec = ToolSpec(name="api.call", effect="write", credentials=("api",))
    with pytest.raises(TypeError, match="@tool"):
        guarded_tool_node(ledger, [Custom()], {"custom": spec}, principal="alice")
