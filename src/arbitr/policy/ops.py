"""Argument operators for policy rules.

A condition ``{path, op, value}`` looks up every value the JSON path matches.
Positive operators hold if any matched value satisfies them; ``ne`` and
``not_in`` hold only if every matched value does. A path that matches
nothing satisfies no operator except ``exists: false``.

Equality is JSON equality: ``5`` equals ``5.0``, but ``true`` never equals
``1`` and a string never equals a number.

Example:
    >>> from arbitr.policy.schema import ArgCondition
    >>> evaluate(ArgCondition(path="$.amount", op="gt", value=100), {"amount": 150})
    True
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Final

from arbitr.policy import jsonpath
from arbitr.policy.regex import search_rule

if TYPE_CHECKING:
    from arbitr.policy.schema import ArgCondition

MAX_REGEX_INPUT: Final = 10_000
"""Only this many characters of a value are searched by a regex rule."""


def _is_number(v: object) -> bool:
    return isinstance(v, int | float) and not isinstance(v, bool)


def json_equal(a: object, b: object) -> bool:
    """Equality with JSON semantics.

    Example:
        >>> json_equal(5, 5.0), json_equal(True, 1), json_equal("5", 5)
        (True, False, False)
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if _is_number(a) and _is_number(b):
        return a == b
    if type(a) is not type(b) and not (isinstance(a, list | tuple) and isinstance(b, list | tuple)):
        return False
    return a == b


def _compare(op: str) -> Callable[[object, object], bool]:
    def check(v: object, target: object) -> bool:
        if not (_is_number(v) and _is_number(target)):
            return False
        a, b = float(v), float(target)  # type: ignore[arg-type]
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]

    return check


def _contains(v: object, target: object) -> bool:
    if isinstance(v, str):
        return isinstance(target, str) and target in v
    if isinstance(v, list | tuple):
        return any(json_equal(item, target) for item in v)
    if isinstance(v, Mapping):
        return isinstance(target, str) and target in v
    return False


def _len_gt(v: object, target: object) -> bool:
    if isinstance(v, str | list | tuple | Mapping) and _is_number(target):
        return len(v) > float(target)  # type: ignore[arg-type]
    return False


_POSITIVE: Final[dict[str, Callable[[object, object], bool]]] = {
    "eq": json_equal,
    "in": lambda v, t: any(json_equal(v, x) for x in t),  # type: ignore[attr-defined]
    "gt": _compare("gt"),
    "gte": _compare("gte"),
    "lt": _compare("lt"),
    "lte": _compare("lte"),
    "glob": lambda v, t: isinstance(v, str) and fnmatch.fnmatchcase(v, str(t)),
    "regex": lambda v, t: isinstance(v, str) and search_rule(str(t), v[:MAX_REGEX_INPUT]),
    "contains": _contains,
    "len_gt": _len_gt,
}
_NEGATIVE: Final[dict[str, Callable[[object, object], bool]]] = {
    "ne": lambda v, t: not json_equal(v, t),
    "not_in": lambda v, t: not any(json_equal(v, x) for x in t),  # type: ignore[attr-defined]
}


def evaluate(condition: ArgCondition, args: Mapping[str, object]) -> bool:
    """Return whether ``condition`` holds for ``args``."""
    values = [v for _, v in jsonpath.find(args, condition.path)]
    if condition.op == "exists":
        wanted = True if condition.value is None else bool(condition.value)
        return bool(values) is wanted
    if not values:
        return False
    if condition.op in _NEGATIVE:
        check = _NEGATIVE[condition.op]
        return all(check(v, condition.value) for v in values)
    check = _POSITIVE[condition.op]
    return any(check(v, condition.value) for v in values)
