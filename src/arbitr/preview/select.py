"""Choosing and running the previewer for one action.

A tool can name its own previewer with ``ToolSpec.preview``
(``"package.module:function"``). Otherwise a built-in one is chosen from the
resources the extractors found, in this order: tables (SQL), paths (shell
and file arguments), email recipients, and for financial actions the payment
amounts. Terraform plans have no resource of their own, so a terraform tool
names ``arbitr.preview.terraform:preview_terraform``.

Previews run only for destructive and financial actions.

Example:
    >>> from arbitr.core.spec import ResourceRef
    >>> default_previewer("destructive", (ResourceRef(kind="table", uri="t"),)).__name__
    'preview_sql'
"""

from __future__ import annotations

import functools
import importlib
from typing import TYPE_CHECKING, Final

from arbitr.preview.base import Preview, Previewer, run_preview
from arbitr.preview.email import preview_email
from arbitr.preview.files import preview_files
from arbitr.preview.payments import preview_payments
from arbitr.preview.sql import DIALECT, changes_rows, preview_sql

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from arbitr.core.spec import ResourceRef, ToolSpec

PREVIEW_EFFECTS: Final = frozenset({"destructive", "financial"})
"""Effects whose actions are always previewed when a built-in previewer fits.

Writes are previewed when they are SQL that changes rows (DELETE, UPDATE),
and outbound messages when they have recipients. A tool that names its own
previewer is previewed for every effect but read."""

_BY_KIND: Final[tuple[tuple[str, Previewer], ...]] = (
    ("table", preview_sql),
    ("path", preview_files),
    ("email", preview_email),
)


def default_previewer(effect: str, resources: Iterable[ResourceRef]) -> Previewer | None:
    """The built-in previewer for these resources, or None when none fits."""
    kinds = {r.kind for r in resources}
    for kind, previewer in _BY_KIND:
        if kind in kinds:
            return previewer
    return preview_payments if effect == "financial" else None


@functools.lru_cache(maxsize=256)
def load_previewer(path: str) -> Previewer:
    """Import a previewer named ``package.module:function``.

    Raises:
        ImportError, AttributeError, TypeError: it cannot be imported or is not callable.
    """
    module_name, _, attr_path = path.partition(":")
    target: object = importlib.import_module(module_name)
    for attr in attr_path.split("."):
        target = getattr(target, attr)
    if not callable(target):
        raise TypeError(f"{path} is not callable")
    return target


def preview_action(  # noqa: PLR0913 - the parts of one action, plus the two settings
    spec: ToolSpec,
    effect: str,
    resources: Iterable[ResourceRef],
    args: Mapping[str, object],
    *,
    context: Mapping[str, object],
    timeout_s: float,
) -> Preview | None:
    """Preview one action, or return None when it is not previewed. Never raises."""
    if effect == "read":
        return None
    if spec.preview is not None:
        try:
            previewer = load_previewer(spec.preview)
        except Exception as exc:  # noqa: BLE001 - a missing previewer is a failed preview
            return Preview.failed(
                f"Preview failed: the previewer {spec.preview} could not be loaded",
                error=type(exc).__name__,
            )
    else:
        found = _builtin_for(effect, list(resources), args, context)
        if found is None:
            return None
        previewer = found
    return run_preview(previewer, args, context, timeout_s)


def _builtin_for(
    effect: str,
    resources: list[ResourceRef],
    args: Mapping[str, object],
    context: Mapping[str, object],
) -> Previewer | None:
    if effect in PREVIEW_EFFECTS:
        return default_previewer(effect, resources)
    kinds = {r.kind for r in resources}
    # Any write whose SQL changes rows is previewed. One the previewer cannot
    # count gives a failed preview, so a preview rule fails safe, never open.
    dialect = context.get(DIALECT)
    if (
        effect == "write"
        and "table" in kinds
        and changes_rows(args, dialect if isinstance(dialect, str) else None)
    ):
        return preview_sql
    if effect == "external_comm" and "email" in kinds:
        return preview_email
    return None
