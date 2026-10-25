"""Tool-specific resource extractors used by the registry tests."""

from __future__ import annotations

from collections.abc import Mapping

from arbitr.core.spec import ResourceRef


def tables(args: Mapping[str, object]) -> list[ResourceRef]:
    """One table resource named by the 'table' argument."""
    return [ResourceRef(kind="table", uri=str(args.get("table", "unknown")))]


def broken(args: Mapping[str, object]) -> list[ResourceRef]:
    """Always fails."""
    raise RuntimeError("extractor bug")


def wrong_type(args: Mapping[str, object]) -> object:
    """Returns something that is not a list of resources."""
    return 5
