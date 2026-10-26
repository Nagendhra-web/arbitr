"""A scripted agent node for LangGraph: a tool-calling graph runs offline from a script.

Example::

    agent = ScriptedAgent([[("refund", {"order_id": "o-1", "amount": 25})], "Refunded."])
    graph = agent.graph(guarded_tool_node(ledger, tools, specs, principal="alice"))
    state = graph.invoke({"messages": [("user", "Refund o-1")]},
                         {"configurable": {"thread_id": "t-1"}})
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import tools_condition

from arbitr.testing._script import Script, Turn

if TYPE_CHECKING:
    from langgraph.graph.state import CompiledStateGraph
    from langgraph.prebuilt import ToolNode

__all__ = ["ScriptedAgent", "Turn", "tool_messages"]


class ScriptedAgent(Script):
    """A graph node that plays the model's side of the conversation from a script."""

    def __call__(self, state: MessagesState) -> dict[str, list[AIMessage]]:
        """The next scripted turn as an ``AIMessage``."""
        self.requests.append(list(state["messages"]))
        turn = self.next_turn()
        if isinstance(turn, str):
            return {"messages": [AIMessage(content=turn)]}
        calls: list[Any] = [
            {"name": name, "args": dict(args), "id": self.call_id("call_"), "type": "tool_call"}
            for name, args in turn
        ]
        return {"messages": [AIMessage(content="", tool_calls=calls)]}

    def graph(self, tools: ToolNode) -> CompiledStateGraph[Any, Any, Any, Any]:
        """The usual agent loop: this agent, then ``tools`` while it calls tools."""
        builder = StateGraph(MessagesState)
        builder.add_node("agent", self)
        builder.add_node("tools", tools)
        builder.add_edge(START, "agent")
        builder.add_conditional_edges("agent", tools_condition)
        builder.add_edge("tools", "agent")
        return builder.compile()


def tool_messages(state: MessagesState) -> list[ToolMessage]:
    """The tool messages in a graph's final state, in order."""
    return [m for m in state["messages"] if isinstance(m, ToolMessage)]
