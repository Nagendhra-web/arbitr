r"""File paths.

Paths are normalized before they are stored or matched, so ``/srv/../var/x``
cannot slip past a rule about ``/var/**``. Backslashes become forward slashes
and repeated leading slashes collapse to one. Windows drive paths are
case-insensitive, so they are lower-cased. UNC paths keep their ``//`` prefix.

A path that is relative, starts with ``~`` or holds a ``$`` variable cannot be
resolved without knowing the working directory or environment, so it counts
as unresolved.

Example:
    >>> normalize_path("/srv/../var/backups//db")
    '/var/backups/db'
    >>> normalize_path("C:\\Data\\..\\b.txt")
    'c:/b.txt'
    >>> normalize_path("\\\\server\\share\\x")
    '//server/share/x'
"""

from __future__ import annotations

import posixpath
import re
from typing import TYPE_CHECKING, Final

from arbitr.resources.base import make_ref

if TYPE_CHECKING:
    from arbitr.core.spec import ResourceRef

_DRIVE: Final = re.compile(r"^[A-Za-z]:/")
GLOB_CHARS: Final = frozenset("*?[{")


def _windows_segments(path: str) -> str:
    """Windows ignores trailing dots and spaces in names: ``C:/Data. /x`` is ``C:/Data/x``."""
    return "/".join(s if s in (".", "..") else s.rstrip(". ") or s for s in path.split("/"))


def normalize_path(raw: str) -> str:
    """Normalize a path for storage and matching."""
    if raw.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./")):
        rest = raw[4:]
        raw = "\\\\" + rest[4:] if rest.upper().startswith(("UNC\\", "UNC/")) else rest
    if raw.startswith("\\\\"):
        rest = posixpath.normpath("/" + raw[2:].replace("\\", "/"))
        return "/" + rest
    path = raw.replace("\\", "/")
    if _DRIVE.match(path):
        rest = re.sub(r"^/+", "/", _windows_segments(path[2:]))
        return (path[:2] + posixpath.normpath(rest)).lower()
    path = re.sub(r"^/+", "/", path)
    return posixpath.normpath(path) if path else raw


def has_drive(path: str) -> bool:
    """Whether the path starts with a Windows drive letter."""
    return bool(_DRIVE.match(path.replace("\\", "/")))


def is_unresolved(path: str) -> bool:
    """Whether the real location depends on the working directory or environment."""
    absolute = path.startswith("/") or has_drive(path)
    return not absolute or path.startswith("~") or "$" in path


def literal_base(path: str) -> str:
    """The part of a path before its first glob character, cut back to a folder.

    Example:
        >>> literal_base("/var/back*/x"), literal_base("/var/backups")
        ('/var', '/var/backups')
    """
    cut = next((i for i, c in enumerate(path) if c in GLOB_CHARS), None)
    if cut is None:
        return path
    head = path[:cut]
    return head[: head.rfind("/")] or "/" if "/" in head else ""


def looks_like_path(arg: str) -> bool:
    """Whether a bare argument is clearly a path (absolute, relative or home)."""
    return arg.startswith(("/", "./", "../", "~")) or arg in (".", "..") or has_drive(arg)


def path_ref(raw: str) -> ResourceRef | None:
    """A ``path`` resource, or None for an empty string."""
    if not raw.strip():
        return None
    return make_ref("path", normalize_path(raw.strip()))
