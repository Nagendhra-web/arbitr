"""The preview's SQL search and resource extraction read exactly the same SQL values.

``registry.sql_texts`` repeats the extractor's walk so the previewer can see
the text itself. If the two ever drifted, SQL the extractor classifies could
escape the previewer (a fail-open), so every value the extractor hands to the
SQL classifier must be found by ``sql_texts``, and nothing else.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from arbitr.resources import registry
from arbitr.resources.base import Extraction

KEYS = st.sampled_from([
    "sql", "query", "statement", "statements", "raw_sql", "my_sql", "SQL",
    "command", "path", "url", "to", "payload", "items", "options", "name",
])  # fmt: skip
TEXT = st.text(alphabet="abc DELETE FROM;", max_size=12)
VALUES: Any = st.recursive(
    TEXT | st.integers() | st.none(),
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(KEYS, inner, max_size=4),
    max_leaves=25,
)


@settings(max_examples=300, deadline=None)
@given(args=st.dictionaries(KEYS, VALUES, max_size=5))
def test_sql_texts_finds_exactly_what_extraction_classifies_as_sql(
    args: dict[str, object],
) -> None:
    seen: list[str] = []

    def record(value: str) -> Extraction:
        seen.append(value)
        return Extraction()

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(registry, "classify_sql", record)
        registry._walk(args)
    found, complete = registry.sql_texts(args)
    assert complete
    assert sorted(seen) == sorted(v for v in found if isinstance(v, str))
