"""The safe JSON path subset."""

from __future__ import annotations

import pytest

from arbitr.core.errors import JsonPathError
from arbitr.policy.jsonpath import Index, Key, Wildcard, find, parse, replace

DOC = {
    "a": {"b": [1, {"c": "x"}, {"c": "y"}]},
    "odd key": 5,
    "list": [[1, 2], [3]],
}


def test_parse_segments() -> None:
    assert parse("$") == ()
    assert parse("$.a.b[2]") == (Key("a"), Key("b"), Index(2))
    assert parse("$['odd key'][*]") == (Key("odd key"), Wildcard())
    assert parse("$['it\\'s']") == (Key("it's"),)


@pytest.mark.parametrize(
    "path",
    ["", "a.b", "$..a", "$.a[?(@.x)]", "$.a[-1]", "$.1a", "$[", "$.a.", "$" + ".a" * 300, "$.a()"],
)
def test_parse_rejects_anything_outside_the_subset(path: str) -> None:
    with pytest.raises(JsonPathError):
        parse(path)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("$", [DOC]),
        ("$.a.b[0]", [1]),
        ("$.a.b[*].c", ["x", "y"]),
        ("$['odd key']", [5]),
        ("$.list[*][*]", [1, 2, 3]),
        ("$.missing", []),
        ("$.a.b[9]", []),
        ("$.a.b[0].c", []),
        ("$.odd", []),
    ],
)
def test_find(path: str, expected: list[object]) -> None:
    assert [v for _, v in find(DOC, path)] == expected


def test_find_reports_locations() -> None:
    assert [loc for loc, _ in find(DOC, "$.a.b[*].c")] == [("a", "b", 1, "c"), ("a", "b", 2, "c")]


def test_wildcard_over_object_values() -> None:
    assert sorted(v for _, v in find({"x": 1, "y": 2}, "$[*]")) == [1, 2]  # type: ignore[type-var]


def test_replace_copies_and_never_mutates() -> None:
    original = {"a": {"b": [{"c": "x"}, {"c": "y"}]}}
    out = replace(original, "$.a.b[*].c", lambda v: f"<{v}>")
    assert out == {"a": {"b": [{"c": "<x>"}, {"c": "<y>"}]}}
    assert original == {"a": {"b": [{"c": "x"}, {"c": "y"}]}}


def test_replace_root_and_missing() -> None:
    assert replace({"a": 1}, "$", lambda _v: "all") == "all"
    assert replace({"a": 1}, "$.nope", lambda _v: "x") == {"a": 1}


def test_tuples_are_treated_as_lists() -> None:
    assert replace(("a", "b"), "$[1]", lambda _v: "z") == ["a", "z"]
