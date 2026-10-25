"""SQL statements: which tables they touch and how destructive they are.

Two classifiers run and the stronger result wins, so the optional parser can
only add to what the token scanner finds:

- A token scanner that always runs. It skips comments, string literals and
  quoted identifiers, splits statements on ``;`` and looks at the leading verb
  of every statement and every parenthesized subquery.
- ``sqlglot``, when the ``sql`` extra is installed.

Destructive: ``DROP``, ``TRUNCATE``, ``ALTER``, ``DELETE`` or ``UPDATE``
without a ``WHERE`` (or with an always-true one such as ``WHERE 1=1``),
``CREATE OR REPLACE TABLE`` and ``MERGE ... THEN DELETE``. ``EXPLAIN`` is
classified by the statement it explains, because ``EXPLAIN ANALYZE`` runs it.

Code inside strings is classified when it runs or will run: ``DO`` blocks,
``EXECUTE``/``EXEC``/``PREPARE`` statements and function, procedure and
trigger bodies. SQL built at run time (``EXECUTE format(...)``, string
concatenation, ``EXEC(@sql)``), functions that run SQL or programs (``dblink``,
``xp_cmdshell``) and ``COPY ... PROGRAM`` count as destructive. MySQL and
MariaDB executable comments (``/*! ... */``, ``/*M! ... */``) are scanned.

Example:
    >>> classify_sql("DELETE FROM users").effect
    'destructive'
    >>> classify_sql("DELETE FROM users WHERE id = 7").effect
    'write'
    >>> classify_sql("SELECT 'DROP TABLE users'").effect
    'read'
"""

from __future__ import annotations

import itertools
import logging
import re
from dataclasses import dataclass, field
from typing import Final

from arbitr.core.spec import Effect, ResourceRef
from arbitr.resources.base import Extraction

try:
    import sqlglot
    from sqlglot import exp
except ImportError:  # pragma: no cover - sqlglot is the optional "sql" extra
    _PARSER = False
else:
    _PARSER = True
    # sqlglot logs a warning for every statement it cannot fully parse. Give its
    # logger a handler so the warnings do not fall through to stderr; records
    # still reach the application's own handlers.
    logging.getLogger("sqlglot").addHandler(logging.NullHandler())

_PARSER_LIMIT: Final = 100_000
"""Longer texts are classified by the token scanner alone."""

_WORD: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
_NUMBER: Final = re.compile(r"\d+(?:\.\d*)?(?:[eE][+-]?\d+)?")
_DOLLAR_TAG: Final = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")
_MERGE_DELETE: Final = re.compile(r"\bTHEN\s+DELETE\b", re.IGNORECASE)

_SIMPLE_VERBS: Final[dict[str, tuple[Effect, str]]] = {
    "DROP": ("destructive", "sql:drop"),
    "TRUNCATE": ("destructive", "sql:truncate"),
    "ALTER": ("destructive", "sql:alter"),
    "INSERT": ("write", "sql:insert"),
    "REPLACE": ("write", "sql:insert"),
    "UPSERT": ("write", "sql:insert"),
    "GRANT": ("write", "sql:grant"),
    "REVOKE": ("write", "sql:grant"),
    "COPY": ("write", "sql:copy"),
    "RENAME": ("write", "sql:rename"),
    "LOAD": ("write", "sql:load"),
    "SHOW": ("read", "sql:read"),
    "DESCRIBE": ("read", "sql:read"),
    "DESC": ("read", "sql:read"),
    "VALUES": ("read", "sql:read"),
    "TABLE": ("read", "sql:read"),
}
_VERBS: Final = frozenset(_SIMPLE_VERBS) | {
    "SELECT",
    "DELETE",
    "UPDATE",
    "MERGE",
    "CREATE",
    "EXPLAIN",
}
_CODE_WORDS: Final = frozenset(
    {"EXECUTE", "EXEC", "PREPARE", "SP_EXECUTESQL", "IMMEDIATE", "FUNCTION", "PROCEDURE", "TRIGGER"}
)
_MAX_NESTING: Final = 4
_MAX_GROUPS: Final = 64
"""Parenthesis depth beyond this is treated as destructive (``sql:too-deep``)."""
_SQL_RUNNERS: Final = frozenset(
    {
        "DBLINK",
        "DBLINK_EXEC",
        "DBLINK_OPEN",
        "QUERY_TO_XML",
        "QUERY_TO_XMLSCHEMA",
        "QUERY_TO_XML_AND_XMLSCHEMA",
        "XP_CMDSHELL",
        "SP_OACREATE",
        "OPENROWSET",
        "OPENQUERY",
    }
)
_EXPLAIN_OPTIONS: Final = frozenset({"ANALYZE", "ANALYSE", "VERBOSE", "QUERY", "PLAN"})
_WHERE_END: Final = frozenset({"RETURNING", "LIMIT", "ORDER", "OFFSET", "FETCH"})
_TABLE_MODIFIERS: Final = frozenset(
    {"TEMP", "TEMPORARY", "TRANSIENT", "GLOBAL", "LOCAL", "UNLOGGED", "EXTERNAL", "VOLATILE"}
)
_NAME_INTRODUCERS: Final = frozenset({"FROM", "JOIN", "INTO", "TABLE", "USING"})
_NAME_SKIP: Final = frozenset({"IF", "NOT", "EXISTS", "ONLY", "LATERAL"})
_NOT_NAMES: Final = _VERBS | {"WITH", "WHERE", "SET", "AS", "ON", "TO", "IS", "NULL", "DUAL"}
_CLAUSE_WORDS: Final = frozenset(
    {
        "JOIN",
        "INNER",
        "LEFT",
        "RIGHT",
        "FULL",
        "CROSS",
        "NATURAL",
        "OUTER",
        "WHERE",
        "SET",
        "ON",
        "USING",
        "ORDER",
        "GROUP",
        "HAVING",
        "LIMIT",
        "UNION",
        "EXCEPT",
        "INTERSECT",
        "RETURNING",
        "WINDOW",
        "FOR",
        "OFFSET",
        "FETCH",
        "RESTART",
        "CONTINUE",
        "CASCADE",
        "RESTRICT",
        "TO",
        "RENAME",
        "ADD",
        "DEFAULT",
        "WHEN",
        "THEN",
        "PARTITION",
        "TABLESAMPLE",
        "OWNER",
        "ENGINE",
    }
)


# ---------------------------------------------------------------- scanning


@dataclass(frozen=True)
class _Tok:
    kind: str  # word, ident, num, str, punct
    text: str  # words upper-cased; idents as written
    raw: str = ""


@dataclass
class _Group:
    items: list[_Tok | _Group] = field(default_factory=list)


def _skip_quoted(text: str, start: int, quote: str, *, backslash: bool) -> int:
    """Index just past the quoted run starting at ``start`` (doubled quotes escape)."""
    i, n = start + 1, len(text)
    while i < n:
        c = text[i]
        if backslash and c == "\\":
            i += 2
            continue
        if c == quote:
            if text.startswith(quote, i + 1):
                i += 2
                continue
            return i + 1
        i += 1
    return n


def _scan(text: str, *, backslash: bool) -> list[_Tok]:  # noqa: C901, PLR0912 - one pass over the text
    out: list[_Tok] = []
    i, n = 0, len(text)
    executable = 0  # open MySQL /*! ... */ comments, whose contents run as code
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif text.startswith(("/*!", "/*M!"), i):
            executable += 1
            i += 3 if text.startswith("/*!", i) else 4
            while i < n and text[i].isdigit():
                i += 1
        elif executable and text.startswith("*/", i):
            executable -= 1
            i += 2
        elif text.startswith("--", i):
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif c == "'":
            end = _skip_quoted(text, i, "'", backslash=backslash)
            out.append(_Tok("str", "", text[i + 1 : end - 1].replace("''", "'")))
            i = end
        elif c in '"`':
            end = _skip_quoted(text, i, c, backslash=False)
            name = text[i + 1 : end - 1].replace(c + c, c)
            out.append(_Tok("ident", name, name))
            i = end
        elif c == "$" and (tag := _DOLLAR_TAG.match(text, i)):
            end = text.find(tag.group(0), tag.end())
            out.append(_Tok("str", "", text[tag.end() : n if end < 0 else end]))
            i = n if end < 0 else end + len(tag.group(0))
        elif word := _WORD.match(text, i):
            out.append(_Tok("word", word.group(0).upper(), word.group(0)))
            i = word.end()
        elif number := _NUMBER.match(text, i):
            out.append(_Tok("num", number.group(0)))
            i = number.end()
        else:
            out.append(_Tok("punct", c))
            i += 1
    return out


def _statements(tokens: list[_Tok]) -> tuple[list[list[_Tok | _Group]], bool]:
    """Split on ``;`` and nest parentheses. Unbalanced parentheses are tolerated.

    Nesting deeper than _MAX_GROUPS is flattened (so classification cannot
    recurse without bound) and reported, so the caller can fail safe.
    """
    statements: list[list[_Tok | _Group]] = []
    stack: list[list[_Tok | _Group]] = [[]]
    too_deep = False
    for tok in tokens:
        if tok.text == ";" and tok.kind == "punct":
            statements.append(stack[0])
            stack = [[]]
        elif tok.text == "(" and tok.kind == "punct" and len(stack) > _MAX_GROUPS:
            too_deep = True
        elif tok.text == "(" and tok.kind == "punct":
            group = _Group()
            stack[-1].append(group)
            stack.append(group.items)
        elif tok.text == ")" and tok.kind == "punct" and len(stack) > 1:
            stack.pop()
        else:
            stack[-1].append(tok)
    statements.append(stack[0])
    return [s for s in statements if s], too_deep


def _is_word_at(items: list[_Tok | _Group], j: int, *words: str) -> bool:
    return j < len(items) and _is_word(items[j], *words)


def _is_word(item: _Tok | _Group, *words: str) -> bool:
    return isinstance(item, _Tok) and item.kind == "word" and item.text in words


# ---------------------------------------------------------------- token classifier


def _always_true(tail: list[_Tok | _Group]) -> bool:
    while len(tail) == 1 and isinstance(tail[0], _Group):
        tail = tail[0].items
    toks = [t for t in tail if isinstance(t, _Tok)]
    if len(toks) != len(tail):
        return False
    texts = [t.text for t in toks]
    if texts in (["TRUE"], ["NOT", "FALSE"]):
        return True
    if len(toks) == 1 and toks[0].kind == "num":
        return float(toks[0].text) != 0
    return (
        len(toks) == 3  # noqa: PLR2004 - left = right
        and toks[0].kind == toks[2].kind == "num"
        and texts[1] == "="
        and float(texts[0]) == float(texts[2])
    )


def _where_effect(items: list[_Tok | _Group], start: int, what: str) -> tuple[Effect, str]:
    for i in range(start, len(items)):
        if _is_word(items[i], "WHERE"):
            tail: list[_Tok | _Group] = []
            for item in items[i + 1 :]:
                if _is_word(item, *_WHERE_END):
                    break
                tail.append(item)
            if _always_true(tail):
                return "destructive", f"sql:{what}-without-where"
            return "write", f"sql:{what}"
    return "destructive", f"sql:{what}-without-where"


def _create_effect(items: list[_Tok | _Group], start: int) -> tuple[Effect, str]:
    words = [t.text for t in items[start + 1 :] if isinstance(t, _Tok)]
    if words[:2] == ["OR", "REPLACE"]:
        rest = [w for w in words[2:] if w not in _TABLE_MODIFIERS]
        if rest[:1] == ["TABLE"]:
            return "destructive", "sql:create-or-replace-table"
    return "write", "sql:create"


def _verb_effect(items: list[_Tok | _Group], index: int, verb: str) -> tuple[Effect | None, str]:
    if verb in _SIMPLE_VERBS:
        return _SIMPLE_VERBS[verb]
    if verb in ("DELETE", "UPDATE"):
        return _where_effect(items, index + 1, verb.lower())
    if verb == "MERGE":
        words = [t.text for t in items[index:] if isinstance(t, _Tok)]
        merge_delete = any(a == "THEN" and b == "DELETE" for a, b in itertools.pairwise(words))
        return ("destructive", "sql:merge-delete") if merge_delete else ("write", "sql:merge")
    if verb == "CREATE":
        return _create_effect(items, index)
    if verb == "SELECT":
        into = any(_is_word(item, "INTO") for item in items[index + 1 :])
        return ("write", "sql:select-into") if into else ("read", "sql:select")
    return None, ""


def _explained(items: list[_Tok | _Group], index: int) -> list[_Tok | _Group]:
    rest = items[index + 1 :]
    while rest and (_is_word(rest[0], *_EXPLAIN_OPTIONS) or isinstance(rest[0], _Group)):
        rest = rest[1:]
    return rest


def _strings_in(items: list[_Tok | _Group]) -> list[str]:
    out: list[str] = []
    for item in items:
        if isinstance(item, _Group):
            out.extend(_strings_in(item.items))
        elif item.kind == "str" and item.raw.strip():
            out.append(item.raw)
    return out


def _runs_code(items: list[_Tok | _Group]) -> bool:
    """Whether string bodies at this level are SQL that runs: DO, EXECUTE, functions."""
    return bool(items) and (
        _is_word(items[0], "DO") or any(_is_word(item, *_CODE_WORDS) for item in items)
    )


def _is_literal_at(items: list[_Tok | _Group], j: int) -> bool:
    """A single string literal at ``j`` (``N'...'`` allowed), not joined to anything."""
    if j < len(items) and _is_word(items[j], "N"):
        j += 1
    if j >= len(items):
        return False
    item = items[j]
    if isinstance(item, _Group):
        return all(isinstance(t, _Tok) and t.kind == "str" for t in item.items)
    after = items[j + 1] if j + 1 < len(items) else None
    joined = after is not None and (_is_punct(after, "|") or _is_punct(after, "+"))
    return item.kind == "str" and not joined


def _next_runs_dynamic_sql(items: list[_Tok | _Group], j: int) -> bool:
    """Whether what follows EXECUTE/EXEC is built at run time (not one literal).

    ``EXECUTE name`` of a prepared statement or procedure stays opaque, like
    CALL. ``EXECUTE IMMEDIATE`` always takes SQL text, so a variable there is
    dynamic.
    """
    immediate = False
    while j < len(items) and _is_word(items[j], "IMMEDIATE"):
        immediate = True
        j += 1
    if j >= len(items) or _is_literal_at(items, j):
        return False
    item = items[j]
    after = items[j + 1] if j + 1 < len(items) else None
    if immediate or isinstance(item, _Group) or (isinstance(item, _Tok) and item.kind == "str"):
        return True
    named = isinstance(item, _Tok) and item.kind in ("word", "ident")
    return named and isinstance(after, _Group)  # format(...)


def _is_runner(item: _Tok | _Group) -> bool:
    """A function that runs SQL or programs, also quoted (``"xp_cmdshell"``)."""
    return (
        isinstance(item, _Tok)
        and item.kind in ("word", "ident")
        and item.text.upper().strip("[]") in _SQL_RUNNERS
    )


def _prepare_is_dynamic(items: list[_Tok | _Group], j: int) -> bool:
    """``PREPARE name FROM <not a literal>``."""
    for k in range(j, min(j + 3, len(items))):
        if _is_word(items[k], "FROM"):
            return not _is_literal_at(items, k + 1)
    return False


def _dynamic_sql(items: list[_Tok | _Group]) -> Extraction:
    """SQL whose text is only known at run time, or that runs programs. Fails closed."""
    if items and _is_word(items[0], "GRANT", "REVOKE"):
        return Extraction()
    if items and _is_word(items[0], "COPY") and any(_is_word(i, "PROGRAM") for i in items):
        return Extraction(effect="destructive", labels=("sql:copy-program",))
    if any(_dynamic_at(items, j) for j in range(len(items))):
        return Extraction(effect="destructive", labels=("sql:dynamic",))
    return Extraction()


def _dynamic_at(items: list[_Tok | _Group], j: int) -> bool:
    item = items[j]
    if _is_runner(item):
        return True
    if _is_word(item, "SP_EXECUTESQL"):
        return not _is_literal_at(items, j + 1)
    if _is_word(item, "EXECUTE", "EXEC") and not _is_word_at(items, j + 1, "SP_EXECUTESQL"):
        return _next_runs_dynamic_sql(items, j + 1)
    return _is_word(item, "PREPARE") and _prepare_is_dynamic(items, j + 1)


def _classify_body(text: str, depth: int) -> Extraction:
    if depth > _MAX_NESTING:
        return Extraction(effect="destructive", labels=("sql:too-deep",))
    result = _classify_scanned(text, backslash=False, depth=depth)
    return result.merge(_classify_scanned(text, backslash=True, depth=depth))


def _classify_level(items: list[_Tok | _Group], depth: int = 0) -> Extraction:
    result = Extraction()
    for item in items:
        if isinstance(item, _Group):
            result = result.merge(_classify_level(item.items, depth))
    result = result.merge(_dynamic_sql(items))
    if _runs_code(items):
        for body in _strings_in(items):
            result = result.merge(_classify_body(body, depth + 1))
    if any(_is_word(item, "DROP", "TRUNCATE") for item in items):
        result = result.raised("destructive", "sql:drop")
    index = next((i for i, t in enumerate(items) if _is_word(t, *_VERBS)), None)
    if index is None:
        return result
    verb = items[index].text  # type: ignore[union-attr]
    if verb == "EXPLAIN":
        rest = _explained(items, index)
        explained = _classify_level(rest, depth)
        if explained.effect is None:
            return result.raised("read", "sql:read")
        return result.merge(explained)
    effect, label = _verb_effect(items, index, verb)
    return result if effect is None else result.raised(effect, label)


# ---------------------------------------------------------------- names


def _is_punct(item: _Tok | _Group, char: str) -> bool:
    return isinstance(item, _Tok) and item.kind == "punct" and item.text == char


def _name_part(item: _Tok | _Group) -> str | None:
    if isinstance(item, _Tok) and item.kind == "ident":
        return item.raw
    if isinstance(item, _Tok) and item.kind == "word" and item.text not in _NOT_NAMES:
        return item.raw.lower()
    return None


def _read_name(items: list[_Tok | _Group], i: int, *, after_from: bool) -> tuple[str | None, int]:
    """Read ``a.b.c`` at ``i``. Returns the name (or None) and the index after it."""
    while i < len(items) and _is_word(items[i], *_NAME_SKIP):
        i += 1
    parts: list[str] = []
    while i < len(items) and (part := _name_part(items[i])) is not None:
        parts.append(part)
        i += 1
        if not (i < len(items) and _is_punct(items[i], ".")):
            break
        i += 1
    if not parts:
        return None, i
    if after_from and i < len(items) and isinstance(items[i], _Group):
        return None, i  # a table function such as generate_series(1, 10)
    return ".".join(parts), i


def _names_after(items: list[_Tok | _Group], i: int, *, after_from: bool) -> list[str]:
    """Names in a comma list such as ``FROM a x, b AS y``."""
    names: list[str] = []
    while True:
        name, i = _read_name(items, i, after_from=after_from)
        if name is None:
            return names
        names.append(name)
        if i < len(items) and _is_word(items[i], "AS"):
            i += 1
        if (
            i < len(items)
            and _name_part(items[i]) is not None
            and not _is_word(items[i], *_CLAUSE_WORDS)
        ):
            i += 1  # an alias
        if not (i < len(items) and _is_punct(items[i], ",")):
            return names
        i += 1


def _cte_names(items: list[_Tok | _Group]) -> set[str]:
    names: set[str] = set()
    for i, item in enumerate(items):
        if isinstance(item, _Group):
            names |= _cte_names(item.items)
        elif item.kind in ("word", "ident"):
            j = i + 1
            if j < len(items) and isinstance(items[j], _Group):
                j += 1  # WITH RECURSIVE name(cols) AS (...)
            if j + 1 < len(items) and _is_word(items[j], "AS") and isinstance(items[j + 1], _Group):
                names.add(item.raw if item.kind == "ident" else item.raw.lower())
    return names


def _level_names(items: list[_Tok | _Group]) -> list[ResourceRef]:
    refs: list[ResourceRef] = []
    for item in items:
        if isinstance(item, _Group):
            refs.extend(_level_names(item.items))
    verb_index = next((i for i, t in enumerate(items) if _is_word(t, *_VERBS)), None)
    for i, item in enumerate(items):
        if not isinstance(item, _Tok) or item.kind != "word":
            continue
        kind = "table"
        if item.text in ("DATABASE", "SCHEMA"):
            if not (i > 0 and _is_word(items[i - 1], "DROP", "CREATE", "ALTER")):
                continue
            kind = "database"
        elif item.text not in _NAME_INTRODUCERS and not (
            i == verb_index and item.text in ("UPDATE", "TRUNCATE", "COPY")
        ):
            continue
        after_from = item.text in ("FROM", "JOIN", "USING")
        names = _names_after(items, i + 1, after_from=after_from)
        refs.extend(ResourceRef(kind=kind, uri=name) for name in names)
    return refs


# ---------------------------------------------------------------- parser


def _parser_true(node: exp.Expr | None) -> bool:
    while isinstance(node, exp.Paren):
        node = node.this
    if isinstance(node, exp.Boolean):
        return bool(node.this)
    if isinstance(node, exp.Not) and isinstance(node.this, exp.Boolean):
        return not node.this.this
    if isinstance(node, exp.Literal) and not node.is_string:
        return float(node.this) != 0
    return (
        isinstance(node, exp.EQ)
        and isinstance(node.this, exp.Literal)
        and isinstance(node.expression, exp.Literal)
        and not node.this.is_string
        and not node.expression.is_string
        and float(node.this.this) == float(node.expression.this)
    )


def _parsed_where(node: exp.Expr, what: str) -> tuple[Effect, str]:
    where = node.args.get("where")
    if where is None or _parser_true(where.this):
        return "destructive", f"sql:{what}-without-where"
    return "write", f"sql:{what}"


def _parsed_node(node: exp.Expr) -> tuple[Effect | None, str]:  # noqa: PLR0911 - one branch per node type
    simple: dict[type[exp.Expr], tuple[Effect, str]] = {
        exp.Drop: ("destructive", "sql:drop"),
        exp.TruncateTable: ("destructive", "sql:truncate"),
        exp.Alter: ("destructive", "sql:alter"),
        exp.Insert: ("write", "sql:insert"),
        exp.Grant: ("write", "sql:grant"),
        exp.Revoke: ("write", "sql:grant"),
        exp.Copy: ("write", "sql:copy"),
        exp.Describe: ("read", "sql:read"),
    }
    if type(node) in simple:
        return simple[type(node)]
    if isinstance(node, exp.Delete):
        return _parsed_where(node, "delete")
    if isinstance(node, exp.Update):
        if isinstance(node.parent, exp.When):
            return "write", "sql:merge"
        return _parsed_where(node, "update")
    if isinstance(node, exp.Merge):
        if _MERGE_DELETE.search(node.sql()):
            return "destructive", "sql:merge-delete"
        return "write", "sql:merge"
    if isinstance(node, exp.Create):
        kind = str(node.args.get("kind") or "").upper()
        if node.args.get("replace") and kind == "TABLE":
            return "destructive", "sql:create-or-replace-table"
        return "write", "sql:create"
    if isinstance(node, exp.Select):
        return ("write", "sql:select-into") if node.args.get("into") else ("read", "sql:select")
    return None, ""


def _parsed_names(tree: exp.Expr) -> list[ResourceRef]:
    ctes = {cte.alias_or_name.lower() for cte in tree.find_all(exp.CTE)}
    databases: set[int] = set()
    refs: list[ResourceRef] = []
    for node in tree.find_all(exp.Drop, exp.Create):
        kind = str(node.args.get("kind") or "").upper()
        if kind in ("DATABASE", "SCHEMA") and isinstance(node.this, exp.Table):
            databases.add(id(node.this))
            name = ".".join(str(p.this) for p in node.this.parts).lower()
            if name:
                refs.append(ResourceRef(kind="database", uri=name))
    for table in tree.find_all(exp.Table):
        parts = [p for p in table.parts if isinstance(p, exp.Identifier)]
        if id(table) in databases or not parts or len(parts) != len(table.parts):
            continue
        name = ".".join(str(p.this) if p.quoted else str(p.this).lower() for p in parts)
        if len(parts) == 1 and name.lower() in ctes:
            continue
        refs.append(ResourceRef(kind="table", uri=name))
    return refs


def _classify_parsed(text: str) -> Extraction:
    if not _PARSER or len(text) > _PARSER_LIMIT:
        return Extraction()
    try:
        trees = sqlglot.parse(text)
    except Exception:  # noqa: BLE001 - the parser is best effort; the scanner always runs
        return Extraction()
    result = Extraction()
    for tree in trees:
        if tree is None:
            continue
        for node in tree.walk():
            effect, label = _parsed_node(node)
            if effect is not None:
                result = result.raised(effect, label)
        result = result.merge(Extraction(resources=tuple(_parsed_names(tree))))
    return result


# ---------------------------------------------------------------- public


def _classify_scanned(text: str, *, backslash: bool, depth: int = 0) -> Extraction:
    statements, too_deep = _statements(_scan(text, backslash=backslash))
    ctes: set[str] = set()
    for statement in statements:
        ctes |= _cte_names(statement)
    result = Extraction()
    for statement in statements:
        refs = [r for r in _level_names(statement) if r.uri not in ctes or r.kind != "table"]
        level = _classify_level(statement, depth)
        result = result.merge(level).merge(Extraction(resources=tuple(refs)))
    if too_deep:
        result = result.raised("destructive", "sql:too-deep")
    return result


def classify_sql(text: str) -> Extraction:
    """Classify one or more SQL statements.

    Backslash escapes inside strings differ between databases, so the text is
    scanned both ways and the stronger result is kept.

    Example:
        >>> [r.uri for r in classify_sql("TRUNCATE orders").resources]
        ['orders']
    """
    result = _classify_scanned(text, backslash=False)
    result = result.merge(_classify_scanned(text, backslash=True))
    return result.merge(_classify_parsed(text)).normalized()
