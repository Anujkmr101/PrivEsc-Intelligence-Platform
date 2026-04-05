#!/usr/bin/env python3
"""
PIP — PrivEsc Intelligence Platform
Entry point. All commands route through this file.
"""

import sys
import signal
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from pip.core.orchestrator import Orchestrator
from pip.core.context_engine import ContextEngine
from pip.models.context import ScanMode, StealthProfile, ReportType, CloudProvider

app = typer.Typer(
    name="pip",
    help="PrivEsc Intelligence Platform — verified, ranked paths to root.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()


def _handle_sigint(sig, frame):
    console.print("\n[bold red]Kill-switch activated. Halting all activity.[/bold red]")
    sys.exit(0)


signal.signal(signal.SIGINT, _handle_sigint)


@app.command()
def scan(
    mode: ScanMode = typer.Option(ScanMode.DEEP, "--mode", "-m", help="Scan depth profile."),
    stealth: StealthProfile = typer.Option(StealthProfile.NORMAL, "--stealth", "-s", help="Noise control profile."),
    report: list[ReportType] = typer.Option([ReportType.ALL], "--report", "-r", help="Report types to generate."),
    exploit: bool = typer.Option(False, "--exploit", help="Enable controlled exploit execution (requires consent gate)."),
    confirm_each: bool = typer.Option(False, "--confirm-each", help="Require confirmation before each exploit step."),
    mitre_map: bool = typer.Option(True, "--mitre-map/--no-mitre-map", help="Tag findings to MITRE ATT&CK T-codes."),
    blue_team: bool = typer.Option(False, "--blue-team", help="Include per-finding remediation output."),
    cis_level: int = typer.Option(1, "--cis-level", min=1, max=2, help="CIS Benchmark level for audit mode."),
    cloud: CloudProvider = typer.Option(None, "--cloud", help="Cloud environment hint (aws/gcp/azure)."),
    imds_check: bool = typer.Option(False, "--imds-check", help="Check cloud instance metadata endpoints."),
    output: Path = typer.Option(Path("./pip-output"), "--output", "-o", help="Output directory for reports."),
    output_format: str = typer.Option("json", "--output-format", help="Structured output format (json/sarif/html)."),
    no_disk: bool = typer.Option(False, "--no-disk", help="Memory-only mode — no artifacts written to target."),
    timeout: int = typer.Option(300, "--timeout", help="Global scan timeout in seconds."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
):
    """
    Run a privilege escalation intelligence scan.

    Examples:

      pip scan --mode deep --stealth normal --report all

      pip scan --mode audit --blue-team --cis-level 2

      pip scan --mode quick --stealth silent --exploit --confirm-each

      pip scan --mode deep --cloud aws --imds-check --output ./reports/
    """
    console.print(
        Panel.fit(
            "[bold]PIP — PrivEsc Intelligence Platform[/bold] [dim]v2.0.0[/dim]",
            border_style="blue",
        )
    )

    output.mkdir(parents=True, exist_ok=True)

    orchestrator = Orchestrator(
        mode=mode,
        stealth=stealth,
        report_types=report,
        exploit_enabled=exploit,
        confirm_each=confirm_each,
        mitre_map=mitre_map,
        blue_team=blue_team,
        cis_level=cis_level,
        cloud_hint=cloud,
        imds_check=imds_check,
        output_dir=output,
        output_format=output_format,
        no_disk=no_disk,
        timeout=timeout,
        verbose=verbose,
    )

    orchestrator.run()


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host."),
    port: int = typer.Option(8443, "--port", help="Bind port."),
    auth: str = typer.Option("jwt", "--auth", help="Authentication method (jwt/apikey/none)."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code changes (dev mode)."),
):
    """Start the REST API server."""
    import uvicorn
    from pip.api.server import create_app

    console.print(f"[green]Starting PIP API server on {host}:{port}[/green]")
    api_app = create_app(auth_method=auth)
    uvicorn.run(api_app, host=host, port=port, reload=reload)


@app.command()
def update():
    """Sync the knowledge base (GTFOBins, NVD, MITRE ATT&CK)."""
    from pip.analysis.knowledge_base import KnowledgeBase

    console.print("[yellow]Syncing knowledge base...[/yellow]")
    kb = KnowledgeBase()
    kb.sync()
    console.print("[green]Knowledge base updated.[/green]")


@app.command()
def plugins():
    """List loaded plugins."""
    from pip.core.orchestrator import Orchestrator

    loaded = Orchestrator.list_plugins()
    for category, names in loaded.items():
        console.print(f"[bold]{category}[/bold]: {', '.join(names) or 'none'}")


if __name__ == "__main__":
    app()