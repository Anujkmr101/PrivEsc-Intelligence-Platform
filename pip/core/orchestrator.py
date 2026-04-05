"""
pip/core/orchestrator.py

Adaptive Orchestrator — the central coordinator for a PIP scan.

Responsibilities:
  - Build the module execution plan based on ScanConfig and detected context.
  - Run enumeration modules in parallel (asyncio).
  - Pass findings through the analysis → scoring → decision pipeline.
  - Trigger reporting.
  - Enforce the global timeout and kill-switch.
"""

from __future__ import annotations

import asyncio
import importlib
import pkgutil
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from pip.models.context import ScanConfig, SystemContext, UserContext, ScanMode, EnvironmentType
from pip.models.finding import Finding
from pip.models.attack_path import AttackPath
from pip.core.context_engine import ContextEngine
from pip.core.stealth_engine import StealthEngine
from pip.core.shell_compat import ShellCompat

console = Console()


class Orchestrator:
    """
    Central scan coordinator.

    Usage:
        orchestrator = Orchestrator(**config_kwargs)
        orchestrator.run()
    """

    def __init__(self, **config_kwargs):
        from pip.models.context import ScanConfig
        self.config = ScanConfig(**config_kwargs)
        self.context_engine = ContextEngine(self.config)
        self.stealth_engine = StealthEngine(self.config)
        self.shell = ShellCompat(self.config)

        self.system_ctx: Optional[SystemContext] = None
        self.user_ctx: Optional[UserContext] = None
        self.findings: list[Finding] = []
        self.attack_paths: list[AttackPath] = []
        self._start_time: float = 0.0

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self) -> None:
        """Execute the full scan pipeline synchronously."""
        self._start_time = time.time()
        try:
            asyncio.run(self._pipeline(), debug=self.config.verbose)
        except asyncio.TimeoutError:
            console.print("[bold red]Global scan timeout reached. Generating partial report.[/bold red]")
            self._generate_reports()

    # ── Pipeline stages ───────────────────────────────────────────────────────

    async def _pipeline(self) -> None:
        async with asyncio.timeout(self.config.timeout):
            await self._stage_fingerprint()
            await self._stage_enumerate()
            await self._stage_correlate()
            await self._stage_validate()
            await self._stage_decide()
            self._stage_report()

    async def _stage_fingerprint(self) -> None:
        """Stage 1: Detect environment, security controls, shell type."""
        console.print("\n[dim][ 1/6 ] Fingerprinting environment...[/dim]")
        self.system_ctx, self.user_ctx = await self.context_engine.fingerprint()
        self.stealth_engine.configure(self.system_ctx)
        self.shell.configure(self.system_ctx)
        self._print_context_summary()

    async def _stage_enumerate(self) -> None:
        """Stage 2: Run all enumeration modules in parallel."""
        console.print("\n[dim][ 2/6 ] Running enumeration modules...[/dim]")
        modules = self._build_module_plan()
        tasks = [mod.run(self.system_ctx, self.user_ctx, self.shell) for mod in modules]

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            task_id = progress.add_task("Enumerating...", total=len(tasks))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            progress.update(task_id, completed=len(tasks))

        for result in results:
            if isinstance(result, Exception):
                if self.config.verbose:
                    console.print(f"[yellow]Module error: {result}[/yellow]")
                continue
            self.findings.extend(result)

        console.print(f"[green]  {len(self.findings)} raw findings collected.[/green]")

    async def _stage_correlate(self) -> None:
        """Stage 3: Build attack graph and extract multi-hop paths."""
        console.print("\n[dim][ 3/6 ] Building correlation graph...[/dim]")
        from pip.analysis.correlation_graph import CorrelationGraphEngine
        from pip.analysis.gtfobins import GTFOBinsIntegration
        from pip.analysis.mitre_mapper import MitreMapper

        # Enrich findings with GTFOBins and MITRE data before graphing
        gtfo = GTFOBinsIntegration()
        mitre = MitreMapper()
        for finding in self.findings:
            gtfo.enrich(finding)
            if self.config.mitre_map:
                mitre.tag(finding)

        graph_engine = CorrelationGraphEngine(self.config)
        self.attack_paths = graph_engine.build_paths(self.findings, self.system_ctx)
        console.print(f"[green]  {len(self.attack_paths)} attack paths identified.[/green]")

    async def _stage_validate(self) -> None:
        """Stage 4: Dry-run validate top-ranked paths."""
        console.print("\n[dim][ 4/6 ] Validating paths...[/dim]")
        from pip.scoring.exploit_validator import ExploitValidator
        from pip.scoring.risk_scorer import RiskScorer
        from pip.scoring.fp_reducer import FPReducer

        fp_reducer = FPReducer(self.system_ctx)
        self.findings = fp_reducer.filter(self.findings)

        validator = ExploitValidator(self.config, self.shell)
        scorer = RiskScorer(self.system_ctx)

        for path in self.attack_paths:
            await validator.validate(path)
            scorer.score(path)

        self.attack_paths.sort(key=lambda p: p.composite_score, reverse=True)
        console.print(f"[green]  {sum(1 for p in self.attack_paths if p.verified)} paths verified.[/green]")

    async def _stage_decide(self) -> None:
        """Stage 5: Produce ranked decision output."""
        console.print("\n[dim][ 5/6 ] Generating decision output...[/dim]")
        from pip.decision.decision_engine import DecisionEngine

        engine = DecisionEngine(self.config)
        engine.present(self.attack_paths, self.system_ctx, self.user_ctx)

        if self.config.exploit_enabled and self.attack_paths:
            from pip.decision.exploit_runner import ExploitRunner
            runner = ExploitRunner(self.config, self.shell)
            await runner.run(self.attack_paths[0])

    def _stage_report(self) -> None:
        """Stage 6: Generate all configured reports."""
        console.print("\n[dim][ 6/6 ] Generating reports...[/dim]")
        self._generate_reports()

    def _generate_reports(self) -> None:
        from pip.models.context import ReportType
        from pip.reporting.executive import ExecutiveReporter
        from pip.reporting.technical import TechnicalReporter
        from pip.reporting.blue_team import BlueTeamReporter

        scan_meta = {
            "duration_seconds": round(time.time() - self._start_time, 1),
            "mode": self.config.mode.value,
            "stealth": self.config.stealth.value,
            "findings_count": len(self.findings),
            "paths_count": len(self.attack_paths),
        }

        types = self.config.report_types
        all_reports = ReportType.ALL in types

        if all_reports or ReportType.EXECUTIVE in types:
            ExecutiveReporter(self.config).generate(
                self.attack_paths, self.system_ctx, self.user_ctx, scan_meta
            )

        if all_reports or ReportType.TECHNICAL in types:
            TechnicalReporter(self.config).generate(
                self.findings, self.attack_paths, self.system_ctx, scan_meta
            )

        if all_reports or ReportType.BLUE_TEAM in types or self.config.blue_team:
            BlueTeamReporter(self.config).generate(
                self.findings, self.attack_paths, self.system_ctx, scan_meta
            )

        console.print(f"\n[bold green]Reports written to: {self.config.output_dir}[/bold green]")

    # ── Module plan builder ───────────────────────────────────────────────────

    def _build_module_plan(self) -> list:
        """
        Decide which enumeration modules to activate based on scan mode and context.
        Returns a list of instantiated module objects ready to call .run().
        """
        from pip.enum.smart_enum import SmartEnumModule
        from pip.enum.credential_intel import CredentialIntelModule
        from pip.enum.cloud_container import CloudContainerModule
        from pip.enum.lateral_awareness import LateralAwarenessModule

        modules = [SmartEnumModule(self.config)]

        if self.config.mode in (ScanMode.DEEP, ScanMode.STEALTH):
            modules.append(CredentialIntelModule(self.config))
            modules.append(LateralAwarenessModule(self.config))

        if (
            self.config.cloud_hint
            or self.system_ctx.environment_type in (
                EnvironmentType.DOCKER, EnvironmentType.KUBERNETES, EnvironmentType.CLOUD
            )
            or self.config.imds_check
        ):
            modules.append(CloudContainerModule(self.config))

        # Load drop-in plugins
        modules.extend(self._load_plugins("enum"))
        return modules

    @staticmethod
    def _load_plugins(category: str) -> list:
        """Dynamically load drop-in modules from the plugins/ directory."""
        plugins = []
        plugin_path = Path(__file__).parent.parent.parent / "plugins" / category
        if not plugin_path.exists():
            return plugins
        for finder, name, _ in pkgutil.iter_modules([str(plugin_path)]):
            try:
                mod = importlib.import_module(f"plugins.{category}.{name}")
                for attr in dir(mod):
                    cls = getattr(mod, attr)
                    if isinstance(cls, type) and hasattr(cls, "run") and attr != "EnumPlugin":
                        plugins.append(cls())
            except Exception:
                pass
        return plugins

    @staticmethod
    def list_plugins() -> dict[str, list[str]]:
        """Return a dict of category → plugin names for the `plugins` CLI command."""
        result = {}
        for category in ("enum", "exploit", "cloud", "correlation"):
            path = Path(__file__).parent.parent.parent / "plugins" / category
            result[category] = [
                name for _, name, _ in pkgutil.iter_modules([str(path)])
            ] if path.exists() else []
        return result

    # ── Display helpers ───────────────────────────────────────────────────────

    def _print_context_summary(self) -> None:
        ctx = self.system_ctx
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="dim", width=22)
        table.add_column()
        table.add_row("Environment", ctx.environment_type.value.replace("_", " ").title())
        table.add_row("OS", f"{ctx.os_name} {ctx.os_version}")
        table.add_row("Kernel", ctx.kernel_version)
        table.add_row("User", f"{self.user_ctx.username} (uid={self.user_ctx.uid})")
        table.add_row("SELinux", "enforcing" if ctx.security_controls.selinux_enforcing else
                      ("enabled" if ctx.security_controls.selinux_enabled else "disabled"))
        table.add_row("AppArmor", "enabled" if ctx.security_controls.apparmor_enabled else "disabled")
        table.add_row("Shell", ctx.shell_type.value)
        console.print(table)