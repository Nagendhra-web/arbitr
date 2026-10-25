"""A small, safe JSON path subset.

Supported: ``$`` (the root), ``.name``, ``['quoted name']``, ``[index]`` and
``[*]`` (every element of a list or every value of an object). No filters, no
scripts, no recursion, so evaluation is always linear in the path length.

Example:
    >>> doc = {"cards": [{"number": "4111"}, {"number": "5500"}]}
    >>> [v for _, v in find(doc, "$.cards[*].number")]
    ['4111', '5500']
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final

from arbitr.core.errors import JsonPathError

MAX_PATH_LENGTH: Final = 512

_NAME = re.compile(r"\.([A-Za-z_][A-Za-z0-9_-]*)")
_QUOTED = re.compile(r"\['((?:[^'\\]|\\.)*)'\]")
_INDEX = re.compile(r"\[(\d{1,9})\]")
_WILD = re.compile(r"\[\*\]")


@dataclass(frozen=True)
class Key:
    """Select one member of an object."""

    name: str


@dataclass(frozen=True)
class Index:
    """Select one element of a list."""

    index: int


@dataclass(frozen=True)
class Wildcard:
    """Select every element of a list or every value of an object."""


Segment = Key | Index | Wildcard
Location = tuple[str | int, ...]


def parse(path: str) -> tuple[Segment, ...]:
    """Parse a path into segments.

    Raises:
        JsonPathError: the path is empty, too long, or uses syntax outside the subset.

    Example:
        >>> parse("$.a[0]['b c'][*]")
        (Key(name='a'), Index(index=0), Key(name='b c'), Wildcard())
    """
    if not path.startswith("$") or len(path) > MAX_PATH_LENGTH:
        raise JsonPathError(f"invalid JSON path {path!r}: must start with $ and be short")
    segments: list[Segment] = []
    pos = 1
    while pos < len(path):
        for pattern, build in (
            (_NAME, lambda m: Key(m.group(1))),
            (_QUOTED, lambda m: Key(re.sub(r"\\(.)", r"\1", m.group(1)))),
            (_INDEX, lambda m: Index(int(m.group(1)))),
            (_WILD, lambda _m: Wildcard()),
        ):
            match = pattern.match(path, pos)
            if match:
                segments.append(build(match))
                pos = match.end()
                break
        else:
            raise JsonPathError(f"invalid JSON path {path!r} at position {pos}")
    return tuple(segments)


def find(value: object, path: str) -> list[tuple[Location, object]]:
    """Return ``(location, value)`` for every match, in document order.

    Missing members and out-of-range indexes simply match nothing.

    Example:
        >>> find({"a": [10, 20]}, "$.a[1]")
        [(('a', 1), 20)]
    """
    matches: list[tuple[Location, object]] = [((), value)]
    for segment in parse(path):
        matches = [m for loc, v in matches for m in _step(loc, v, segment)]
    return matches


def _children(value: object) -> list[tuple[str | int, object]]:
    if isinstance(value, Mapping):
        return list(value.items())
    if isinstance(value, list | tuple):
        return list(enumerate(value))
    return []


def _step(loc: Location, value: object, segment: Segment) -> list[tuple[Location, object]]:
    children = _children(value)
    if isinstance(segment, Wildcard):
        selected = children
    else:
        wanted: str | int = segment.name if isinstance(segment, Key) else segment.index
        want_key = isinstance(segment, Key)
        selected = [(k, v) for k, v in children if k == wanted and isinstance(k, str) == want_key]
    return [((*loc, k), v) for k, v in selected]


def replace(value: object, path: str, fn: Callable[[object], object]) -> object:
    """Return a copy of ``value`` with every match of ``path`` replaced by ``fn(match)``.

    The input is never modified.

    Example:
        >>> replace({"a": {"pw": "x", "u": "y"}}, "$.a.pw", lambda v: "***")
        {'a': {'pw': '***', 'u': 'y'}}
    """
    result = value
    for loc, old in find(value, path):
        result = _set(result, loc, fn(old))
    return result


def _set(value: object, loc: Location, new: object) -> object:
    if not loc:
        return new
    head, rest = loc[0], loc[1:]
    if isinstance(value, Mapping) and isinstance(head, str):
        copy = dict(value)
        copy[head] = _set(value[head], rest, new)
        return copy
    if isinstance(value, list | tuple) and isinstance(head, int):
        items = list(value)
        items[head] = _set(items[head], rest, new)
        return items
    raise JsonPathError(f"location {loc!r} does not exist")  # pragma: no cover, find() guards it
