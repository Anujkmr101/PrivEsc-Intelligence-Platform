"""pip/decision/decision_engine.py — Presents ranked paths to the operator."""
from __future__ import annotations
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from pip.models.attack_path import AttackPath
from pip.models.context import ScanConfig, SystemContext, UserContext

console = Console()

class DecisionEngine:
    def __init__(self, config: ScanConfig):
        self.config = config

    def present(self, paths: list[AttackPath], sys_ctx: SystemContext, user_ctx: UserContext) -> None:
        if not paths:
            console.print("\n[yellow]No viable privilege escalation paths found.[/yellow]")
            return
        self._print_summary(paths, sys_ctx)
        self._print_top_path(paths[0])
        self._print_all_paths_table(paths)

    def _print_summary(self, paths: list[AttackPath], sys_ctx: SystemContext) -> None:
        top = paths[0]
        risk_color = "red" if top.composite_score >= 9.0 else "yellow" if top.composite_score >= 6.0 else "green"
        summary = (
            f"[bold]Risk Level[/bold]    : [{risk_color}]{top.score_label}[/{risk_color}]\n"
            f"[bold]Root Access[/bold]   : {'[red]POSSIBLE[/red]' if any(p.composite_score >= 5.0 for p in paths) else '[green]UNLIKELY[/green]'}\n"
            f"[bold]Paths Found[/bold]   : {len(paths)}\n"
            f"[bold]Verified[/bold]      : {sum(1 for p in paths if p.verified)}\n"
            f"[bold]Top Score[/bold]     : {top.composite_score}/10\n"
            f"[bold]Environment[/bold]   : {sys_ctx.environment_type.value.replace('_',' ').title()}"
        )
        console.print(Panel(summary, title="[bold]SCAN SUMMARY[/bold]", border_style=risk_color))

    def _print_top_path(self, path: AttackPath) -> None:
        lines = [
            f"[bold]Method[/bold]   : {path.title}",
            f"[bold]Score[/bold]    : [red]{path.composite_score}/10[/red]",
            f"[bold]MITRE[/bold]    : {', '.join(path.mitre_ids) or 'n/a'}",
            f"[bold]Verified[/bold] : {'[green]YES[/green]' if path.verified else '[yellow]NO[/yellow]'}",
            "",
        ]
        for step in path.steps:
            lines.append(f"  {step.order}. {step.description}")
            if step.command:
                lines.append(f"     [dim]$ {step.command}[/dim]")
        console.print(Panel("\n".join(lines), title="[bold]TOP PATH[/bold]", border_style="red"))

    def _print_all_paths_table(self, paths: list[AttackPath]) -> None:
        table = Table(title="All Paths", show_lines=False, box=None)
        table.add_column("#", style="dim", width=4)
        table.add_column("Method", min_width=30)
        table.add_column("Score", width=8)
        table.add_column("Verified", width=10)
        table.add_column("MITRE", width=16)
        for i, path in enumerate(paths, 1):
            table.add_row(str(i), path.title[:50], f"{path.composite_score:.1f}",
                          "[green]YES[/green]" if path.verified else "no",
                          ", ".join(path.mitre_ids[:2]))
        console.print(table)
