"""The policy loader and the extractors never fail with an unexpected error."""

from __future__ import annotations

import contextlib

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from arbitr.core.errors import JsonPathError, PolicyError
from arbitr.policy import jsonpath
from arbitr.policy.schema import load_policy
from arbitr.resources.extractors.shell import classify_shell
from arbitr.resources.extractors.sql import classify_sql

scalars = (
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=12)
)
values = st.recursive(
    scalars,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=10), children, max_size=4)
    ),
    max_leaves=25,
)
POLICY_KEYS = ["version", "mode", "default", "include", "exclude_rules", "resources", "rules",
               "windows", "approval", "on_unknown", "on_outside_scope"]  # fmt: skip
policies = st.dictionaries(st.sampled_from(POLICY_KEYS), values, max_size=6).map(
    lambda d: {"version": 1, **d}
)


@settings(max_examples=400)
@given(policies)
def test_load_policy_raises_only_policy_errors(data: dict[str, object]) -> None:
    with contextlib.suppress(PolicyError):
        load_policy(yaml.safe_dump(data))


@pytest.mark.parametrize(
    "text",
    [
        "version: 1\nrules: [5]\n",
        "version: 1\nrules: abc\n",
        "version: 1\ninclude: [git]\nrules: abc\n",
        "version: 1\ninclude: [git]\nrules: [5, {id: x}]\n",
        "version: 1\nresources: [1]\n",
        "version: 1\ninclude: [git]\nresources: {a: 1}\n",
        "version: 1\ninclude: [git]\nwindows: [1]\n",
        "version: 1\ninclude: git\n",
        "version: 1\ninclude: [5]\n",
        "version: 1\nexclude_rules: [5]\n",
    ],
)
def test_malformed_policies_raise_policy_error(text: str) -> None:
    with pytest.raises(PolicyError):
        load_policy(text)


BIG_INPUTS = [
    "select " + "(" * 50_000 + "1" + ")" * 50_000,
    "(" * 100_000,
    "'" * 100_000,
    "$(" * 50_000,
    "`" * 100_000,
    "a" * 100_000,
    "-- " * 33_000,
    "/*" * 50_000,
    "\\" * 100_000,
]


@pytest.mark.parametrize("text", BIG_INPUTS, ids=[f"input-{i}" for i in range(len(BIG_INPUTS))])
def test_extractors_never_raise_on_big_inputs(text: str) -> None:
    classify_sql(text)
    classify_shell(text)


def test_deep_sql_nesting_fails_safe() -> None:
    result = classify_sql("SELECT " + "(" * 1000 + "1" + ")" * 1000)
    assert result.effect == "destructive"
    assert "sql:too-deep" in result.labels


@settings(max_examples=300)
@given(st.text(alphabet=st.sampled_from(list("()'\"`$;-*/\\ selctdropSELECT\n")), max_size=400))
def test_extractors_never_raise_on_nested_punctuation(text: str) -> None:
    classify_sql(text)
    classify_shell(text)


path_text = st.text(alphabet=st.sampled_from(list("$.[]*'\"0123abc_-\\ ")), max_size=30)


@settings(max_examples=400)
@given(path_text, values)
def test_json_paths_raise_only_json_path_errors(path: str, data: object) -> None:
    with contextlib.suppress(JsonPathError):
        jsonpath.parse(path)
        jsonpath.find(data, path)
        jsonpath.replace(data, path, lambda v: v)
