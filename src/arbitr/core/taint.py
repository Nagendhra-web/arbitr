"""Run taint: what a run has been exposed to.

A run becomes tainted with ``untrusted_input`` after a tool that returns text
an attacker may control (web pages, issues, emails), and with ``private_data``
after a tool that returns private data. Both together, plus an outbound
message, is the lethal trifecta the policy guards against.

Taint only ever turns on: flags are merged with OR, sources with set union,
and a run's taint flows down to every run it spawns.

Example:
    >>> t = merge(Taint(untrusted_input=True, sources=("web.fetch",)), Taint(private_data=True))
    >>> t.untrusted_input, t.private_data
    (True, True)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arbitr.core.spec import ToolSpec


@dataclass(frozen=True)
class Taint:
    """What a run has been exposed to. Flags only ever turn on."""

    untrusted_input: bool = False
    private_data: bool = False
    sources: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """The stored form."""
        return {
            "untrusted_input": self.untrusted_input,
            "private_data": self.private_data,
            "sources": list(self.sources),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Taint:
        """Rebuild from the stored form. Missing fields read as clean."""
        sources = data.get("sources") or []
        return cls(
            untrusted_input=bool(data.get("untrusted_input", False)),
            private_data=bool(data.get("private_data", False)),
            sources=tuple(sorted({str(s) for s in sources})) if isinstance(sources, list) else (),
        )


def merge(a: Taint, b: Taint) -> Taint:
    """Combine two taints. The result is never less tainted than either."""
    return Taint(
        untrusted_input=a.untrusted_input or b.untrusted_input,
        private_data=a.private_data or b.private_data,
        sources=tuple(sorted(set(a.sources) | set(b.sources))),
    )


def after_tool(taint: Taint, spec: ToolSpec) -> Taint:
    """Taint after a tool returned successfully, from what its spec says it returns."""
    if not (spec.untrusted_output or spec.private_output):
        return taint
    return merge(
        taint,
        Taint(
            untrusted_input=spec.untrusted_output,
            private_data=spec.private_output,
            sources=(spec.name,),
        ),
    )
