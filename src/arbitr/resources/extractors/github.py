"""GitHub repositories, written ``owner/repo``, as a URL or as an SSH remote.

GitHub names are case-insensitive, so the URI is lower-cased.

Example:
    >>> repo_ref("git@github.com:Octo/Hello.git").uri
    'octo/hello'
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from arbitr.resources.base import make_ref
from arbitr.resources.extractors.urls import url_refs

if TYPE_CHECKING:
    from arbitr.core.spec import ResourceRef

_REPO: Final = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def repo_ref(value: str) -> ResourceRef | None:
    """A ``github_repo`` resource, or None when the value is not a repo name."""
    text = value.strip()
    if text.startswith("git@github.com:"):
        text = text.split(":", 1)[1]
    elif "://" in text:
        repos = [r for r in url_refs(text) if r.kind == "github_repo"]
        return repos[0] if repos else None
    text = text.strip("/").removesuffix(".git")
    if not _REPO.match(text):
        return None
    return make_ref("github_repo", text.lower())
