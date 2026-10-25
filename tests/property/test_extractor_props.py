"""Fuzz and composition properties of the SQL and shell extractors."""

from __future__ import annotations

import shlex

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from arbitr.core.spec import EFFECT_RANK
from arbitr.resources.extractors import sql as sql_module
from arbitr.resources.extractors.shell import classify_shell
from arbitr.resources.extractors.sql import classify_sql
from extractor_cases import SHELL_CASES, SQL_CASES


def rank(effect: str | None) -> int:
    return -1 if effect is None else EFFECT_RANK[effect]


sql_texts = st.text(
    alphabet=st.sampled_from(list("abcSELECTDROPWHERE ;'\"`$()-*/=1\n\\")), max_size=80
)
shell_texts = st.text(alphabet=st.sampled_from(list("abrm -f;&|<>()'\"`$\\\n#~/.")), max_size=80)


@pytest.mark.parametrize("parser", [True, False])
@settings(max_examples=300)
@given(text=st.one_of(st.text(max_size=200), sql_texts))
def test_sql_never_crashes(text: str, parser: bool) -> None:
    original = sql_module._PARSER
    sql_module._PARSER = parser and original
    try:
        result = classify_sql(text)
    finally:
        sql_module._PARSER = original
    assert result.effect is None or result.effect in EFFECT_RANK


@settings(max_examples=300)
@given(st.one_of(st.text(max_size=200), shell_texts))
def test_shell_never_crashes(text: str) -> None:
    result = classify_shell(text)
    assert result.effect is None or result.effect in EFFECT_RANK


@given(st.sampled_from(SQL_CASES), st.sampled_from(SQL_CASES))
def test_joining_sql_statements_never_lowers_the_effect(
    a: tuple[str, str | None], b: tuple[str, str | None]
) -> None:
    joined = classify_sql(f"{a[0]}\n;\n{b[0]}").effect
    assert rank(joined) >= max(rank(a[1]), rank(b[1]))


def _parses(command: str) -> bool:
    try:
        shlex.split(command)
    except ValueError:
        return False
    return True


# An unbalanced quote in one command can close in the next, so joining is only
# monotone for commands that parse on their own.
WELL_FORMED = [case for case in SHELL_CASES if _parses(case[0])]


@given(st.sampled_from(WELL_FORMED), st.sampled_from(WELL_FORMED))
def test_joining_shell_commands_never_lowers_the_effect(
    a: tuple[str, str | None], b: tuple[str, str | None]
) -> None:
    joined = classify_shell(f"{a[0]}\n{b[0]}").effect
    assert rank(joined) >= max(rank(a[1]), rank(b[1]))


@given(st.sampled_from([c for c, e in SHELL_CASES if e == "destructive"]))
def test_wrapping_a_destructive_command_keeps_it_destructive(command: str) -> None:
    quoted = shlex.quote(command)
    for wrapped in (f"sudo {command}", f"bash -c {quoted}", f"echo ok && {command}"):
        assert classify_shell(wrapped).effect == "destructive", wrapped
