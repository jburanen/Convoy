"""Command-line interface (Typer).

Verbs map to orchestration actions. Mutating verbs are dry-run by default; real
execution requires an explicit ``--execute``. See
.claude/memory/safety-constraints.md.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from . import __version__
from .config import Config
from .errors import OrchestratorError
from .inventory import Inventory
from .orchestrator import Orchestrator
from .reporting import configure_logging

app = typer.Typer(
    name="convoy",
    help="Orchestrate Check Point CDT/CPUSE patching across management servers and firewalls.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

InventoryOpt = Annotated[Path, typer.Option("--inventory", "-i", help="Path to inventory YAML.")]
ConfigOpt = Annotated[Path | None, typer.Option("--config", "-c", help="Path to config YAML.")]


def _load(inventory: Path, config: Path | None) -> Orchestrator:
    inv = Inventory.load(inventory)
    cfg = Config.load(config)
    return Orchestrator(inv, cfg)


@app.callback()
def _main(
    json_logs: bool = typer.Option(False, "--json-logs", help="Emit structured JSON logs."),
) -> None:
    configure_logging(json_output=json_logs)


@app.command()
def version() -> None:
    """Print the tool version."""
    console.print(f"convoy {__version__}")


@app.command()
def validate(inventory: InventoryOpt, config: ConfigOpt = None) -> None:
    """Load and validate the inventory and config without touching any host."""
    try:
        orch = _load(inventory, config)
    except OrchestratorError as exc:
        console.print(f"[red]invalid:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    n_hosts = sum(len(s.hosts) for s in orch.inventory.sites)
    console.print(f"[green]ok[/green]: {len(orch.inventory.sites)} site(s), {n_hosts} host(s)")


@app.command()
def plan(
    package: Annotated[str, typer.Argument(help="Package identifier to deploy.")],
    inventory: InventoryOpt,
    config: ConfigOpt = None,
) -> None:
    """Build and print a deployment run plan (never touches live hosts)."""
    try:
        orch = _load(inventory, config)
        run_plan = orch.build_plan(package)
    except OrchestratorError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(run_plan.describe())


@app.command()
def deploy(
    package: Annotated[str, typer.Argument(help="Package identifier to deploy.")],
    inventory: InventoryOpt,
    config: ConfigOpt = None,
    execute: Annotated[
        bool, typer.Option("--execute", help="Actually run it. Omit for dry-run.")
    ] = False,
) -> None:
    """Execute a deployment. DRY-RUN unless --execute is given."""
    try:
        orch = _load(inventory, config)
        run_plan = orch.build_plan(package, dry_run=not execute)
        console.print(run_plan.describe())
        if not execute:
            console.print("[yellow]dry-run:[/yellow] pass --execute to apply.")
        orch.execute(run_plan)
    except NotImplementedError:
        console.print("[yellow]not yet wired:[/yellow] execution stubs are pending implementation.")
        raise typer.Exit(code=2) from None
    except OrchestratorError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":  # pragma: no cover
    app()
