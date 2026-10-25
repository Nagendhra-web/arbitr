"""The result type every extractor returns.

Example:
    >>> a = Extraction(effect="write", labels=("sql:insert",))
    >>> b = Extraction(effect="destructive", labels=("sql:drop",))
    >>> a.merge(b).effect
    'destructive'
"""

from __future__ import annotations

from dataclasses import dataclass

from arbitr.core.spec import EFFECT_RANK, Effect, ResourceRef

_MAX_URI = 2048


def make_ref(kind: str, uri: str, attrs: dict[str, str] | None = None) -> ResourceRef:
    """Build a ResourceRef, cutting an over-long URI to the allowed length.

    Cutting keeps the prefix, so prefix globs in the policy still match.
    """
    return ResourceRef(kind=kind, uri=uri[:_MAX_URI] or "-", attrs=attrs or {})


def max_effect(a: Effect | None, b: Effect | None) -> Effect | None:
    """The more severe of two effects, where ``None`` means "cannot tell".

    Example:
        >>> max_effect(None, "read"), max_effect("destructive", "write")
        ('read', 'destructive')
    """
    if a is None:
        return b
    if b is None:
        return a
    return a if EFFECT_RANK[a] >= EFFECT_RANK[b] else b


@dataclass(frozen=True)
class Extraction:
    """What an extractor found in a tool call's arguments.

    ``effect`` is the most severe effect observed, or ``None`` when the
    extractor cannot tell. ``labels`` name what was seen (``sql:drop``,
    ``shell:rm``) and never quote argument values.
    """

    resources: tuple[ResourceRef, ...] = ()
    effect: Effect | None = None
    labels: tuple[str, ...] = ()

    def merge(self, other: Extraction) -> Extraction:
        """Combine two extractions: the stronger effect, every resource and label."""
        return Extraction(
            resources=self.resources + other.resources,
            effect=max_effect(self.effect, other.effect),
            labels=self.labels + tuple(x for x in other.labels if x not in self.labels),
        )

    def raised(self, effect: Effect, label: str) -> Extraction:
        """This extraction with ``effect`` observed under ``label``."""
        return self.merge(Extraction(effect=effect, labels=(label,)))

    def normalized(self) -> Extraction:
        """Resources deduplicated and sorted, labels deduplicated in order."""
        unique = {(r.kind, r.uri, tuple(sorted(r.attrs.items()))): r for r in self.resources}
        return Extraction(
            resources=tuple(unique[k] for k in sorted(unique)),
            effect=self.effect,
            labels=tuple(dict.fromkeys(self.labels)),
        )
