"""The resource registry: from a tool call's arguments to tagged resources.

``extract`` walks the arguments and runs the built-in extractor that fits each
argument name (``sql``, ``command``, ``path``, ``url``, ``repo``, ``to`` and
similar). A tool can name its own ``resource_extractor``. It then supplies the
resources, but the built-in effect checks still run, so a custom extractor
cannot hide a ``DROP TABLE``.

``resolve`` gives each resource the tags of every policy resource definition
that matches it. ``classify`` does both and raises the tool's effect to the
most severe effect observed. Effects are never lowered.

Example:
    >>> from arbitr.core.spec import ToolSpec
    >>> from arbitr.policy.schema import load_policy
    >>> spec = ToolSpec(name="db.exec", effect="write")
    >>> classify(spec, {"sql": "DROP TABLE users"}, load_policy("version: 1")).effect
    'destructive'
"""

from __future__ import annotations

import fnmatch
import functools
import importlib
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from arbitr.core.errors import ResourceError
from arbitr.core.spec import Effect, ResourceRef, ToolSpec, raise_effect
from arbitr.policy.engine import ResolvedResource
from arbitr.resources.base import Extraction, make_ref
from arbitr.resources.extractors.email import email_refs
from arbitr.resources.extractors.github import repo_ref
from arbitr.resources.extractors.paths import (
    has_drive,
    is_unresolved,
    literal_base,
    normalize_path,
    path_ref,
)
from arbitr.resources.extractors.shell import classify_shell
from arbitr.resources.extractors.sql import classify_sql
from arbitr.resources.extractors.urls import url_refs

if TYPE_CHECKING:
    from arbitr.policy.schema import Policy, ResourceMatch

UNRESOLVED_PATH: Final = "arbitr:unresolved-path"
"""Tag for paths whose location depends on the working directory or environment."""

_MAX_NODES: Final = 10_000
_MAX_DEPTH: Final = 64

_SQL_KEYS: Final = frozenset({"sql", "query", "statement", "statements", "sql_query", "raw_sql"})
_SHELL_KEYS: Final = frozenset({"command", "cmd", "script", "shell", "bash", "sh", "argv"})
_SHELL_LIST_KEYS: Final = frozenset({"commands", "scripts"})
_PATH_KEYS: Final = frozenset(
    {
        "path",
        "paths",
        "file",
        "files",
        "filename",
        "filenames",
        "filepath",
        "src",
        "source",
        "dst",
        "dest",
        "destination",
        "target",
        "dir",
        "directory",
        "cwd",
        "folder",
        "output",
    }
)
_URL_KEYS: Final = frozenset({"url", "urls", "uri", "endpoint", "href", "link", "webhook"})
_DB_KEYS: Final = frozenset(
    {
        "dsn",
        "database_url",
        "db_url",
        "connection_string",
        "conn_str",
        "connection",
        "database",
        "db",
    }
)
_REPO_KEYS: Final = frozenset({"repo", "repository", "repo_name", "full_name"})
_EMAIL_KEYS: Final = frozenset(
    {
        "to",
        "cc",
        "bcc",
        "recipient",
        "recipients",
        "email",
        "emails",
        "to_address",
        "to_addresses",
        "reply_to",
        "to_email",
    }
)
_TOO_LARGE: Final = Extraction(effect="destructive", labels=("args:too-large",))


# ---------------------------------------------------------------- built-in extraction


_DSN_PAIR: Final = re.compile(r"([A-Za-z][A-Za-z ]*?)\s*=\s*('[^']*'|[^\s;]+)")
_DSN_HOST_KEYS: Final = ("host", "hostaddr", "server", "data source", "address", "addr")
_DSN_DB_KEYS: Final = ("dbname", "database", "initial catalog")


def _key_value_dsn(value: str) -> list[ResourceRef]:
    """``host=db port=5432 dbname=x`` (libpq) or ``Server=db;Database=x`` (SQL Server).

    Every location key gives its own resource (libpq uses ``hostaddr`` over
    ``host``), so no host can hide behind another.
    """
    pairs = {k.strip().lower(): v.strip("'") for k, v in _DSN_PAIR.findall(value)}
    hosts = [h.lower() for k in _DSN_HOST_KEYS if k in pairs for h in pairs[k].split(",")]
    database = next((pairs[k] for k in _DSN_DB_KEYS if k in pairs), "")
    if not hosts and not database:
        return []
    sqlserver = "server" in pairs or "data source" in pairs
    port = f":{pairs['port']}" if "port" in pairs else ""
    scheme = "mssql" if sqlserver else "postgresql"
    return [
        make_ref("database", f"{scheme}://{host.strip()}{port}/{database}")
        for host in hosts or [""]
    ]


def _database(value: str) -> Extraction:
    if "://" in value:
        return Extraction(resources=tuple(url_refs(value)))
    if "=" in value:
        refs = _key_value_dsn(value)
        if refs:
            return Extraction(resources=tuple(refs))
    return (
        Extraction(resources=(make_ref("database", value.strip()),))
        if value.strip()
        else Extraction()
    )


def _one(ref: ResourceRef | None) -> Extraction:
    return Extraction(resources=(ref,)) if ref is not None else Extraction()


def _string_extractor(key: str) -> Callable[[str], Extraction] | None:  # noqa: PLR0911 - one branch per shape
    if key in _SQL_KEYS or key.endswith("_sql"):
        return classify_sql
    if key in _SHELL_KEYS or key.endswith("command"):
        return classify_shell
    if key in _DB_KEYS:
        return _database
    if key in _REPO_KEYS:
        return lambda v: _one(repo_ref(v))
    if key in _EMAIL_KEYS:
        return lambda v: Extraction(resources=tuple(email_refs(v)))
    if key in _URL_KEYS or key.endswith(("_url", "_uri", "_urls")):
        return lambda v: Extraction(resources=tuple(url_refs(v)))
    if key in _PATH_KEYS or key.endswith(("_path", "_file", "_dir", "_paths", "_files")):
        return lambda v: _one(path_ref(v))
    return None


def _owner_repo(value: Mapping[object, object]) -> Extraction:
    owner, repo = value.get("owner"), value.get("repo")
    if isinstance(owner, str) and isinstance(repo, str) and "/" not in repo:
        return _one(repo_ref(f"{owner}/{repo}"))
    return Extraction()


def _list_value(key: str, items: list[object] | tuple[object, ...]) -> Extraction | None:
    """Lists that are one command (argv) or several commands, else None."""
    if not items or not all(isinstance(i, str) for i in items):
        return None
    strings = [str(i) for i in items]
    if key in _SHELL_LIST_KEYS:
        result = Extraction()
        for command in strings:
            result = result.merge(classify_shell(command))
        return result
    if key in _SHELL_KEYS or key.endswith("command"):
        return classify_shell(strings)
    return None


def _safely(extractor: Callable[[str], Extraction], value: str) -> Extraction:
    """Run a built-in extractor. A bug in one must fail closed, not open."""
    try:
        return extractor(value)
    except Exception:  # noqa: BLE001 - any failure is treated as the worst case
        return Extraction(effect="destructive", labels=("extractor:error",))


def _walk(args: Mapping[str, object]) -> Extraction:
    result = Extraction()
    stack: list[tuple[str, object, int]] = [("", args, 0)]
    seen = 0
    while stack:
        key, value, depth = stack.pop()
        seen += 1
        if seen > _MAX_NODES or depth > _MAX_DEPTH:
            return result.merge(_TOO_LARGE)
        if isinstance(value, Mapping):
            result = result.merge(_owner_repo(value))
            stack.extend((str(k).lower(), v, depth + 1) for k, v in value.items())
        elif isinstance(value, list | tuple):
            as_command = _list_value(key, value)
            if as_command is not None:
                result = result.merge(as_command)
            else:
                stack.extend((key, v, depth + 1) for v in value)
        elif isinstance(value, str):
            extractor = _string_extractor(key)
            if extractor is not None:
                result = result.merge(_safely(extractor, value))
    return result


# ---------------------------------------------------------------- custom extractors


@functools.lru_cache(maxsize=256)
def _load(path: str) -> Callable[[Mapping[str, object]], object]:
    module_name, _, attr_path = path.partition(":")
    target: object = importlib.import_module(module_name)
    for attr in attr_path.split("."):
        target = getattr(target, attr)
    if not callable(target):
        raise TypeError(f"{path} is not callable")
    return target


def _custom(spec: ToolSpec, args: Mapping[str, object]) -> Extraction:
    path = spec.resource_extractor
    assert path is not None  # noqa: S101 - checked by the caller
    message = f"the resource extractor for tool {spec.name} failed"
    try:
        found = _load(path)(args)
    except Exception as exc:
        raise ResourceError(message) from exc
    if isinstance(found, Extraction):
        return found
    if isinstance(found, list | tuple) and all(isinstance(r, ResourceRef) for r in found):
        return Extraction(resources=tuple(found))
    raise ResourceError(f"{message}: it must return a list of ResourceRef")


def extract(spec: ToolSpec, args: Mapping[str, object]) -> Extraction:
    """Resources and the observed effect for one tool call.

    Raises:
        ResourceError: the tool's own extractor failed. The action must not run.
    """
    built_in = _walk(args)
    if spec.resource_extractor is None:
        return built_in.normalized()
    custom = _custom(spec, args)
    checked = Extraction(effect=built_in.effect, labels=built_in.labels)
    return checked.merge(custom).normalized()


# ---------------------------------------------------------------- policy tags


@functools.lru_cache(maxsize=1024)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("/**", i) and i + 3 == len(pattern):
            out.append("(?:/.*)?")
            i += 3
        elif pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        else:
            char = pattern[i]
            close = pattern.find("]", i + 1) if char == "[" else -1
            if close > i + 1:
                body = pattern[i + 1 : close].replace("\\", "\\\\")
                out.append("[" + ("^" + body[1:] if body.startswith("!") else body) + "]")
                i = close + 1
                continue
            out.append({"*": "[^/]*", "?": "[^/]"}.get(char, re.escape(char)))
            i += 1
    return re.compile("".join(out) + r"\Z", re.DOTALL)


def path_glob_match(pattern: str, path: str) -> bool:
    """Match a path glob: ``*`` and ``?`` stay inside one segment, ``**`` crosses them.

    ``dir/**`` matches ``dir`` itself too, so deleting the folder counts.

    Example:
        >>> path_glob_match("/var/backups/**", "/var/backups"), path_glob_match("/a/*", "/a/b/c")
        (True, False)
    """
    return _glob_regex(pattern).match(normalize_path(path)) is not None


def _descendant_could_match(glob: str, base: str) -> bool:
    """Whether some path inside ``base`` (or ``base`` itself) could match ``glob``.

    Compares segment by segment, so ``/var`` covers ``/var/backups/**`` and
    ``/srv/app`` covers ``/srv/*/logs``, while ``/srv/web`` does not cover
    ``/var/**``.
    """
    pattern = [s for s in glob.split("/") if s]
    parts = [s for s in base.split("/") if s]
    if pattern and pattern[0] == "**":
        # Anywhere-patterns: only a path that already reaches into the match
        # counts (``/srv/repo/.github`` for ``**/.github/workflows/**``), or
        # every path would carry the tag.
        return any(_prefix_could_match(pattern[1:], parts[k:]) for k in range(len(parts)))
    if not base.startswith("/") and not has_drive(base):
        return False
    return _prefix_could_match(pattern, parts)


def _prefix_could_match(pattern: list[str], parts: list[str]) -> bool:
    for i, part in enumerate(parts):
        if i >= len(pattern):
            return False
        if "**" in pattern[i]:
            return True
        if not fnmatch.fnmatchcase(part, pattern[i]):
            return False
    return len(pattern) > len(parts)


def _path_covers(glob: str, uri: str) -> bool:
    """A path matches a glob when it is inside it, or contains something inside it.

    Deleting ``/var`` deletes ``/var/backups``, so a destructive action on an
    ancestor carries the tags of what it contains. A path with glob characters
    is judged by its literal folder (``/var/back*`` by ``/var``).
    """
    if has_drive(glob) or has_drive(uri):
        glob, uri = glob.lower(), uri.lower()
    if path_glob_match(glob, uri):
        return True
    return _descendant_could_match(glob, literal_base(uri))


def _matches(match: ResourceMatch, ref: ResourceRef, uri: str) -> bool:
    if match.kind != ref.kind:
        return False
    # Names such as hosts and databases are matched without case (``*prod*``
    # also finds ``Orders_PROD``); paths use the case-aware ``glob``.
    if match.uri_glob is not None and not fnmatch.fnmatchcase(uri.lower(), match.uri_glob.lower()):
        return False
    if match.glob is not None and not _path_covers(match.glob, uri):
        return False
    return all(ref.attrs.get(k) == v for k, v in (match.attrs or {}).items())


def resolve(policy: Policy, refs: Iterable[ResourceRef]) -> tuple[ResolvedResource, ...]:
    """Tag each resource with every matching policy resource definition.

    ``id`` is the first matching definition in policy order, ``ids`` all of them.
    A path whose location cannot be known (relative, ``~``, ``$VAR``) also gets
    the tag ``arbitr:unresolved-path``, so a policy can hold it for approval.
    """
    out: dict[tuple[str, str, tuple[tuple[str, str], ...]], ResolvedResource] = {}
    for ref in refs:
        uri = normalize_path(ref.uri) if ref.kind == "path" else ref.uri
        matched = [d for d in policy.resources if _matches(d.match, ref, uri)]
        tags = {t for d in matched for t in d.tags}
        if ref.kind == "path" and is_unresolved(uri):
            tags.add(UNRESOLVED_PATH)
        resolved = ResolvedResource(
            id=matched[0].id if matched else None,
            kind=ref.kind,
            uri=uri,
            tags=frozenset(tags),
            ids=frozenset(d.id for d in matched),
        )
        out.setdefault((ref.kind, uri, tuple(sorted(ref.attrs.items()))), resolved)
    return tuple(out[k] for k in sorted(out))


@dataclass(frozen=True)
class Classified:
    """What the gate needs about a tool call's resources."""

    effect: Effect
    resources: tuple[ResolvedResource, ...]
    labels: tuple[str, ...]


def classify(spec: ToolSpec, args: Mapping[str, object], policy: Policy) -> Classified:
    """Extract, tag and raise the effect for one tool call."""
    found = extract(spec, args)
    effect = raise_effect(spec.effect, found.effect) if found.effect else spec.effect
    return Classified(
        effect=effect, resources=resolve(policy, found.resources), labels=found.labels
    )
