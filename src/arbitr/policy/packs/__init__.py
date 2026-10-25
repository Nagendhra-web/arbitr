"""Ready-made policy packs: tested rules a policy can include and override.

A policy includes packs by name and can replace any pack rule by giving a rule
with the same id, or drop it with ``exclude_rules``::

    version: 1
    include: [databases, git, filesystem]
    exclude_rules: [git.push-protected]

Every pack has its own case table (``<pack>.cases.yaml``) that runs in the
test suite, so a pack never ships a rule that does not do what it says.
"""

from __future__ import annotations

from importlib import resources
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Sequence

PACKS: Final = (
    "databases",
    "filesystem",
    "git",
    "cloud-cli",
    "kubernetes",
    "payments",
    "email-and-messaging",
    "github",
    "mcp-basics",
    "lethal-trifecta",
)


def pack_text(name: str) -> str:
    """The YAML of one pack."""
    if name not in PACKS:
        raise KeyError(name)
    return resources.files(__name__).joinpath(f"{name}.yaml").read_text(encoding="utf-8")


def pack_cases_text(name: str) -> str:
    """The case table that tests one pack."""
    if name not in PACKS:
        raise KeyError(name)
    return resources.files(__name__).joinpath(f"{name}.cases.yaml").read_text(encoding="utf-8")


ALWAYS_INCLUDED: Final = ("email-and-messaging", "lethal-trifecta")
"""Packs every starter policy includes: without them, outbound data loss findings
and run taint decide nothing."""


def starter_policy(packs: Sequence[str]) -> str:
    """A starter policy that includes the given packs and the always-included ones.

    Example:
        >>> print(starter_policy(["git"]).splitlines()[1])
        include: [git, email-and-messaging, lethal-trifecta]
    """
    unknown = [p for p in packs if p not in PACKS]
    if unknown:
        raise ValueError(f"unknown packs: {', '.join(unknown)}; packs: {', '.join(PACKS)}")
    chosen = list(dict.fromkeys([*packs, *ALWAYS_INCLUDED]))
    return (
        "version: 1\n"
        f"include: [{', '.join(chosen)}]\n"
        "# Replace a pack rule by adding a rule with the same id, or drop it:\n"
        "# exclude_rules: [git.push-protected]\n"
        "resources: []\n"
        "rules: []\n"
    )
