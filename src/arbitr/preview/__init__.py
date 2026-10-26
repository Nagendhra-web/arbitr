"""Blast radius previews: what an action would affect, measured before it runs.

A preview tells a human approver what is at stake ("DELETE would remove
48,212 rows from orders") and gives policy rules numbers to test
(``when.preview: [{path: "$.rows_affected", op: gt, value: 1000}]``).

Previewers only read. They run with a time limit, and a preview that times
out or fails has ``ok=False``; the gate then treats rules on preview facts
as matching whenever that is stricter, so a failed preview never makes a
decision looser.
"""

from __future__ import annotations

from arbitr.preview.base import (
    DEADLINE,
    FactValue,
    Preview,
    Previewer,
    deadline_passed,
    run_preview,
)
from arbitr.preview.select import (
    PREVIEW_EFFECTS,
    default_previewer,
    load_previewer,
    preview_action,
)

__all__ = [
    "DEADLINE",
    "PREVIEW_EFFECTS",
    "FactValue",
    "Preview",
    "Previewer",
    "deadline_passed",
    "default_previewer",
    "load_previewer",
    "preview_action",
    "run_preview",
]
