"""The resource registry: what an action touches, and how severe it really is.

Extractors read a tool call's arguments and return the resources it touches
(tables, paths, URLs, repos, recipients) and the effect they observed. A SQL
statement or shell command that is destructive raises the action's effect to
``destructive`` even when the tool was registered as a write. Effects are only
ever raised, never lowered.
"""

from arbitr.resources.base import Extraction, max_effect
from arbitr.resources.registry import Classified, classify, extract, path_glob_match, resolve

__all__ = [
    "Classified",
    "Extraction",
    "classify",
    "extract",
    "max_effect",
    "path_glob_match",
    "resolve",
]
