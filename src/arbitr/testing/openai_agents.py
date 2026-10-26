"""A scripted model for the OpenAI Agents SDK: ``Runner.run`` works offline from a script.

Example::

    from agents import Agent, Runner
    model = ScriptedModel([[("refund", {"order_id": "o-1", "amount": 25})], "Refunded."])
    result = await Runner.run(agent, "Refund o-1", run_config=model.run_config())

``run_config()`` also turns tracing off, so nothing is exported and no API
key is needed.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from agents import RunConfig
from agents.items import ModelResponse
from agents.models.interface import Model, ModelProvider
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from arbitr.testing._script import Script, Turn

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

__all__ = ["ScriptedModel", "Turn"]


class ScriptedModel(Script, Model):
    """A ``Model`` that answers each turn from a script. ``requests`` holds each input sent."""

    def __init__(self, turns: Sequence[Turn]) -> None:
        """Play ``turns`` in order."""
        Script.__init__(self, turns)

    async def get_response(  # noqa: PLR0913, PLR0917 - the SDK's signature
        self,
        system_instructions: str | None,
        input: Any,  # noqa: A002, ANN401 - the SDK's name and type
        model_settings: Any,  # noqa: ANN401
        tools: Any,  # noqa: ANN401
        output_schema: Any,  # noqa: ANN401
        handoffs: Any,  # noqa: ANN401
        tracing: Any,  # noqa: ANN401
        *,
        previous_response_id: str | None = None,
        conversation_id: str | None = None,
        prompt: Any = None,  # noqa: ANN401
    ) -> ModelResponse:
        """The next scripted turn as a model response."""
        self.requests.append(input)
        turn = self.next_turn()
        usage = Usage(requests=1, input_tokens=1, output_tokens=1, total_tokens=2)
        if isinstance(turn, str):
            message = ResponseOutputMessage(
                id=self.call_id("msg_"),
                type="message",
                role="assistant",
                status="completed",
                content=[ResponseOutputText(type="output_text", text=turn, annotations=[])],
            )
            return ModelResponse(output=[message], usage=usage, response_id=None)
        calls = [
            ResponseFunctionToolCall(
                type="function_call",
                call_id=self.call_id("call_"),
                name=name,
                arguments=json.dumps(dict(args)),
            )
            for name, args in turn
        ]
        return ModelResponse(output=list(calls), usage=usage, response_id=None)

    def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:  # noqa: ANN401
        """Not scripted: use ``Runner.run``, not ``Runner.run_streamed``."""
        raise NotImplementedError("the scripted model does not stream; use Runner.run")

    def tool_outputs(self) -> list[str]:
        """The output of every tool call the agent sent back, in order, each once."""
        seen: dict[str, str] = {}
        for sent in self.requests:
            if not isinstance(sent, list):
                continue
            for item in sent:
                if isinstance(item, dict) and item.get("type") == "function_call_output":
                    output = item.get("output")
                    text = output if isinstance(output, str) else json.dumps(output)
                    seen.setdefault(str(item.get("call_id")), text)
        return list(seen.values())

    def run_config(self) -> RunConfig:
        """A run config that uses this model and exports no traces."""
        return RunConfig(model_provider=_Provider(self), tracing_disabled=True)


class _Provider(ModelProvider):
    def __init__(self, model: Model) -> None:
        self._model = model

    def get_model(self, model_name: str | None) -> Model:
        return self._model
