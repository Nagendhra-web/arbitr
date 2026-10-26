"""Email previews: how many people a message reaches, and how many are outside.

Recipients come from the email extractor the gate uses (``to``, ``cc``,
``bcc``, ``recipients`` and similar arguments), counted once each. A
recipient is internal when its domain, or a parent of it, is in the context's
``internal_domains`` list (``eng.corp.example`` is inside ``corp.example``).
A recipient that cannot be parsed makes the preview fail: the count would be
a guess.

Example:
    >>> preview_email({"to": "a@corp.example, b@other.example"},
    ...               {"internal_domains": ["corp.example"]}).summary
    'email to 2 recipients, 1 external'
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from arbitr.core.spec import ToolSpec
from arbitr.preview.base import Preview, plural
from arbitr.resources.extractors.email import UNPARSED
from arbitr.resources.registry import extract

if TYPE_CHECKING:
    from collections.abc import Mapping

INTERNAL_DOMAINS: Final = "internal_domains"

_SPEC: Final = ToolSpec(name="arbitr.preview", effect="read")


def _internal_domains(context: Mapping[str, object]) -> tuple[str, ...]:
    raw = context.get(INTERNAL_DOMAINS)
    if not isinstance(raw, list | tuple):
        return ()
    return tuple(str(d).lower().strip(".") for d in raw if isinstance(d, str))


def _is_internal(domain: str, internal: tuple[str, ...]) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in internal)


def preview_email(args: Mapping[str, object], context: Mapping[str, object]) -> Preview:
    """Count recipients, external recipients and distinct domains."""
    refs = [r for r in extract(_SPEC, args).resources if r.kind == "email"]
    if not refs:
        return Preview.failed("No preview: no email recipients were found in the arguments")
    internal = _internal_domains(context)
    recipients = [r for r in refs if r.uri != UNPARSED]
    domains = {r.attrs.get("domain", "") for r in recipients}
    external = sum(not _is_internal(r.attrs.get("domain", ""), internal) for r in recipients)
    facts: dict[str, int | float | str] = {
        "recipients": len(recipients), "external_recipients": external,
        "internal_recipients": len(recipients) - external, "domains": len(domains),
    }  # fmt: skip
    summary = f"email to {plural(len(recipients), 'recipient')}, {external:,} external"
    if len(recipients) != len(refs):
        return Preview.failed(f"{summary}; some recipients could not be parsed", facts=facts)
    return Preview(summary, facts)
