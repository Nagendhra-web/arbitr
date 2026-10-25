"""The ``arbitr`` command line entry point.

The CLI needs the ``cli`` extra (typer and rich). Without it, ``arbitr`` prints
an install hint instead of a traceback.
"""

from __future__ import annotations

import json
import platform
import sys
from pathlib import Path  # noqa: TC003 - typer reads the annotations at runtime
from typing import TYPE_CHECKING, NoReturn

import arbitr

if TYPE_CHECKING:
    import typer

    from arbitr.core.spec import ToolSpec

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

    app.add_typer(_policy_app(), name="policy")
    return app


def _fail(message: str) -> NoReturn:
    import typer  # noqa: PLC0415

    typer.echo(f"error: {message}")
    raise typer.Exit(2)


def _load_tools(path: Path | None) -> tuple[ToolSpec, ...]:
    from arbitr.core.spec import ToolSpec  # noqa: PLC0415
    from arbitr.policy.schema import load_yaml  # noqa: PLC0415

    if path is None:
        return ()
    data = load_yaml(path, "tool file")
    items = data.get("tools") if isinstance(data, dict) else None
    if not isinstance(items, list):
        _fail("a tool file needs a 'tools' list of {name, effect}")
    return tuple(ToolSpec.model_validate(item) for item in items)


def _policy_app() -> typer.Typer:  # noqa: C901 - one nested function per command
    import typer  # noqa: PLC0415

    from arbitr.core.errors import PolicyError  # noqa: PLC0415
    from arbitr.policy.lint import lint_policy  # noqa: PLC0415
    from arbitr.policy.schema import json_schema, load_policy  # noqa: PLC0415
    from arbitr.policy.testing import load_cases, run_cases  # noqa: PLC0415

    app = typer.Typer(help="Check, test and inspect policies.", no_args_is_help=True)

    @app.command("test")
    def test_cmd(
        policy: Path = typer.Argument(..., help="The policy YAML file."),
        cases: Path = typer.Argument(..., help="The case table YAML file."),
        explain: bool = typer.Option(False, "--explain", help="Explain every decision."),
        as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    ) -> None:
        """Run a case table against a policy. Exits 1 if any case fails."""
        try:
            report = run_cases(load_policy(policy), load_cases(cases))
        except (PolicyError, OSError, ValueError) as exc:
            _fail(str(exc))
        if as_json:
            typer.echo(json.dumps(report.to_dict(), sort_keys=True))
        else:
            typer.echo(report.describe(explain=explain))
        if not report.ok:
            raise typer.Exit(1)

    @app.command("lint")
    def lint_cmd(
        policy: Path = typer.Argument(..., help="The policy YAML file."),
        tools: Path | None = typer.Option(None, "--tools", help="YAML with a 'tools' list."),
        strict: bool = typer.Option(False, "--strict", help="Exit 1 when there are warnings."),
        as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    ) -> None:
        """Warn about rules that never match, shadowed rules and unprotected tools."""
        try:
            warnings = lint_policy(load_policy(policy), _load_tools(tools))
        except (PolicyError, OSError, ValueError) as exc:
            _fail(str(exc))
        if as_json:
            typer.echo(json.dumps([w.to_dict() for w in warnings], sort_keys=True))
        elif not warnings:
            typer.echo("No warnings.")
        for w in [] if as_json else warnings:
            where = f" (rule {w.rule_id})" if w.rule_id else ""
            typer.echo(f"{w.code}{where}: {w.message}")
        if strict and warnings:
            raise typer.Exit(1)

    @app.command("packs")
    def packs_cmd(
        as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    ) -> None:
        """List the policy packs a policy can include."""
        from arbitr.policy.packs import PACKS  # noqa: PLC0415

        if as_json:
            typer.echo(json.dumps(list(PACKS)))
            return
        for name in PACKS:
            typer.echo(name)

    @app.command("schema")
    def schema_cmd(
        as_json: bool = typer.Option(
            True, "--json", help="Print machine-readable JSON (the only format)."
        ),
    ) -> None:
        """Print the JSON Schema for policy files."""
        typer.echo(json.dumps(json_schema(), indent=2, sort_keys=True))

    return app


def main() -> None:
    """Run the CLI."""
    try:
        app = _build_app()
    except ImportError:
        sys.stderr.write(INSTALL_HINT + "\n")
        raise SystemExit(1) from None
    app()
