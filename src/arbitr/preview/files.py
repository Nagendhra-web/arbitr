"""File previews: what ``rm``, ``mv`` and path arguments would touch.

Paths come from the same extractors the gate uses: the shell extractor for
commands (``rm -rf /srv/app``, ``mv a b``, ``find /x -delete``) and the path
extractor for arguments named like paths. Each one is walked read-only with
``os.scandir`` and ``os.lstat``: nothing is opened, changed or followed.
Symbolic links and junctions count as one entry, the way ``rm`` removes them.

The walk stops at a file limit and at the preview deadline. A walk that
stopped early, or could not read a folder, reports ``ok=False`` with the
counts so far: they are a lower bound, not the answer.

Context keys:

- ``path_tags``: tag names mapped to lists of path globs (the same glob rules
  as policy resources), for example ``{"backups": ["/srv/**/backups/**"]}``.
  Files under them are counted as ``files_tagged`` and ``files_tagged_<tag>``.
- ``cwd``: an absolute folder that relative paths are resolved against.
  Without it a relative path cannot be previewed.
- ``max_files``: the most entries to visit (default 100,000).

Example:
    >>> preview_files({"command": "echo hi"}, {}).summary
    'No preview: no file paths were found in the arguments'
"""

from __future__ import annotations

import glob as globbing
import os
import posixpath
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from arbitr.core.spec import ToolSpec
from arbitr.preview.base import Preview, deadline_passed, format_bytes, plural
from arbitr.resources.extractors.paths import has_drive, is_unresolved, normalize_path
from arbitr.resources.registry import extract, path_glob_match

PATH_TAGS: Final = "path_tags"
CWD: Final = "cwd"
MAX_FILES: Final = "max_files"
DEFAULT_MAX_FILES: Final = 100_000

_SPEC: Final = ToolSpec(name="arbitr.preview", effect="read")
_VERBS: Final = (
    ("shell:rm", "rm would delete"),
    ("shell:find-delete", "find would delete"),
    ("shell:mv", "mv would move"),
)
_GLOB: Final = frozenset("*?[")


class Unsupported(Exception):  # noqa: N818 - a reason, not an error the caller handles
    """A path cannot be located without guessing."""


def _resolve(uri: str, cwd: object) -> str:
    if "{" in uri:
        raise Unsupported("a path uses brace expansion")
    if uri.startswith("~") or "$" in uri:
        raise Unsupported("a path depends on the home folder or an environment variable")
    if not is_unresolved(uri):
        return uri
    if not isinstance(cwd, str) or is_unresolved(normalize_path(cwd)):
        raise Unsupported("a relative path needs an absolute 'cwd' in the preview context")
    return normalize_path(posixpath.join(normalize_path(cwd), uri))


def _expand(path: str, limit: int, context: Mapping[str, object]) -> list[str]:
    """A glob's matches, expanded lazily so the entry limit and the deadline apply."""
    if not _GLOB & set(path):
        return [path]
    found: list[str] = []
    for match in globbing.iglob(path):
        found.append(normalize_path(match))
        if len(found) > limit:
            raise Unsupported(f"the paths expand past the {limit:,} entry limit")
        if deadline_passed(context):
            raise Unsupported("expanding the paths ran out of time")
    return sorted(found) or [path]


def _inside(path: str, folder: str) -> bool:
    return path == folder or path.startswith(folder.rstrip("/") + "/")


def _roots(uris: list[str], cwd: object, limit: int, context: Mapping[str, object]) -> list[str]:
    """Absolute paths to walk, globs expanded, each counted once."""
    paths = sorted({p for uri in uris for p in _expand(_resolve(uri, cwd), limit, context)})
    roots: list[str] = []
    for path in paths:
        if not any(_inside(path, root) for root in roots):
            roots.append(path)
    return roots


def _tag_globs(context: Mapping[str, object]) -> dict[str, tuple[str, ...]]:
    raw = context.get(PATH_TAGS)
    if not isinstance(raw, Mapping):
        return {}
    tags: dict[str, tuple[str, ...]] = {}
    for name, globs in raw.items():
        if isinstance(globs, list | tuple) and all(isinstance(g, str) for g in globs):
            tags[str(name)] = tuple(str(g).replace("\\", "/") for g in globs)
    return tags


def _limit(context: Mapping[str, object]) -> int:
    value = context.get(MAX_FILES)
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return DEFAULT_MAX_FILES


def _matches(pattern: str, path: str) -> bool:
    if has_drive(pattern) or has_drive(path):
        pattern, path = pattern.lower(), path.lower()
    return path_glob_match(pattern, path)


def _is_link(path: str, info: os.stat_result) -> bool:
    junction = getattr(os.path, "isjunction", None)
    return stat.S_ISLNK(info.st_mode) or bool(junction is not None and junction(path))


@dataclass
class _Walk:
    """Counts gathered so far, and why the walk stopped (if it did)."""

    context: Mapping[str, object]
    tags: dict[str, tuple[str, ...]]
    limit: int
    files: int = 0
    dirs: int = 0
    size: int = 0
    missing: int = 0
    unreadable: int = 0
    tagged: dict[str, int] = field(default_factory=dict)
    tagged_total: int = 0
    stopped: str | None = None

    def exhausted(self) -> bool:
        """Whether the limit or the deadline has been reached."""
        if self.stopped is None and self.files + self.dirs >= self.limit:
            self.stopped = f"the walk stopped at the {self.limit:,} entry limit"
        if self.stopped is None and deadline_passed(self.context):
            self.stopped = "the walk ran out of time"
        return self.stopped is not None

    def _file(self, path: str, size: int) -> None:
        self.files += 1
        self.size += size
        # Match where the path is written and where it really points, so a
        # symlink into a tagged folder still counts as that folder.
        forms = {normalize_path(path), normalize_path(os.path.realpath(path))}
        hit = False
        for tag, patterns in self.tags.items():
            if any(_matches(p, form) for p in patterns for form in forms):
                self.tagged[tag] = self.tagged.get(tag, 0) + 1
                hit = True
        self.tagged_total += hit

    def root(self, path: str) -> None:
        """Count one path, and everything under it when it is a real folder."""
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            self.missing += 1
            return
        except OSError:
            self.unreadable += 1
            return
        if stat.S_ISDIR(info.st_mode) and not _is_link(path, info):
            self.dirs += 1
            self._folder(path)
        else:
            self._file(path, info.st_size)

    def _folder(self, top: str) -> None:
        pending = [top]
        while pending and not self.exhausted():
            current = pending.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        if self.exhausted():
                            return
                        self._entry(entry, pending)
            except OSError:
                self.unreadable += 1

    def _entry(self, entry: os.DirEntry[str], pending: list[str]) -> None:
        junction = getattr(entry, "is_junction", None)
        if entry.is_dir(follow_symlinks=False) and not (junction is not None and junction()):
            self.dirs += 1
            pending.append(entry.path)
        else:
            self._file(entry.path, entry.stat(follow_symlinks=False).st_size)

    def facts(self, roots: int) -> dict[str, int | float | str]:
        """The counts as preview facts."""
        facts: dict[str, int | float | str] = {
            "files": self.files, "dirs": self.dirs, "bytes": self.size, "paths": roots,
            "missing": self.missing, "files_tagged": self.tagged_total,
        }  # fmt: skip
        facts.update({f"files_tagged_{tag}": self.tagged.get(tag, 0) for tag in self.tags})
        return facts

    def summary(self, lead: str) -> str:
        """One line: the lead, the counts and the tagged folders."""
        bound = "at least " if self.stopped is not None else ""
        text = f"{lead} {bound}{plural(self.files, 'file')} ({format_bytes(self.size)})"
        if self.dirs:
            text += f" in {plural(self.dirs, 'folder')}"
        text += "".join(f", {self.tagged[t]:,} in {t}" for t in self.tags if self.tagged.get(t))
        if self.stopped is not None:
            return f"{text} ({self.stopped})"
        if self.unreadable:
            return f"{text} ({plural(self.unreadable, 'path')} could not be read)"
        return text


def _lead(labels: tuple[str, ...]) -> str:
    return next((lead for label, lead in _VERBS if label in labels), "The paths hold")


def preview_files(args: Mapping[str, object], context: Mapping[str, object]) -> Preview:
    """Count the files, folders and bytes the paths in a call would touch."""
    found = extract(_SPEC, args)
    uris = [r.uri for r in found.resources if r.kind == "path"]
    if not uris:
        return Preview.failed("No preview: no file paths were found in the arguments")
    try:
        roots = _roots(uris, context.get(CWD), _limit(context), context)
    except Unsupported as exc:
        return Preview.failed(f"No preview: {exc}")
    walk = _Walk(context, _tag_globs(context), _limit(context))
    for root in roots:
        if walk.exhausted():
            break
        walk.root(root)
    summary = walk.summary(_lead(found.labels))
    facts = walk.facts(len(roots))
    if walk.stopped is not None or walk.unreadable:
        return Preview.failed(summary, facts=facts)
    return Preview(summary, facts)
