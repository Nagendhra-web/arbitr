"""The ``arbitr`` command line entry point.

The CLI needs the ``cli`` extra (typer and rich). Without it, ``arbitr`` prints
an install hint instead of a traceback.
"""

from __future__ import annotations

import json
import platform
import sys
from typing import TYPE_CHECKING

import arbitr

if TYPE_CHECKING:
    import typer

INSTALL_HINT = 'The arbitr CLI needs the "cli" extra. Install it with: pip install "arbitr[cli]"'


def version_info() -> dict[str, str]:
    """Return version details for the running install.

    Example:
        >>> sorted(version_info())
        ['arbitr', 'platform', 'python']
    """
    return {
        "arbitr": arbitr.__version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
    }


def _build_app() -> typer.Typer:
    import typer  # noqa: PLC0415, imported lazily so the core install works without the extra
    from rich.console import Console  # noqa: PLC0415

    app = typer.Typer(
        name="arbitr",
        help="Arbitr: the final say on every action your AI agents take.",
        no_args_is_help=True,
        add_completion=False,
    )

    @app.callback()
    def _root() -> None:
        """Arbitr: the final say on every action your AI agents take."""

    @app.command("version")
    def version_cmd(
        as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    ) -> None:
        """Show the installed Arbitr version."""
        info = version_info()
        if as_json:
            typer.echo(json.dumps(info, sort_keys=True))
        else:
            Console().print(f"arbitr {info['arbitr']} (Python {info['python']})")

    return app


def main() -> None:
    """Run the CLI."""
    try:
        app = _build_app()
    except ImportError:
        sys.stderr.write(INSTALL_HINT + "\n")
        raise SystemExit(1) from None
    app()
