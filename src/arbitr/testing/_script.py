"""The script a scripted model plays: turns of tool calls, then text."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

Call = tuple[str, Mapping[str, object]]
"""One tool call: the tool's name and its arguments."""
Turn = str | Sequence[Call]
"""A model turn: the final text, or the tool calls to make."""

DONE: Final = "Done."
"""What a scripted model says once its script has run out."""


class Script:
    """The turns left to play, and what the agent sent each time."""

    def __init__(self, turns: Sequence[Turn]) -> None:
        """Play ``turns`` in order."""
        self.turns: list[Turn] = list(turns)
        self.requests: list[Any] = []
        self._calls = 0

    def next_turn(self) -> Turn:
        """The next turn, or the final ``DONE`` text once the script has run out."""
        return self.turns.pop(0) if self.turns else DONE

    def call_id(self, prefix: str) -> str:
        """A fresh tool call id."""
        self._calls += 1
        return f"{prefix}{self._calls:03d}"
