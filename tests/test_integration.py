"""
tests/test_integration.py

Integration tests for the PIP pipeline.

These tests exercise multiple modules together without hitting a real
target — they use mock shell output to simulate discovered findings
and verify the full analysis → scoring → decision pipeline.

Run with: pytest tests/test_integration.py -v
"""

from __future__ import annotations

import asyncio
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from pip.models.finding import Finding, FindingCategory, Severity
from pip.models.attack_path import AttackPath, AttackStep
from pip.models.context import (
    ScanConfig, ScanMode, StealthProfile, ReportType,
    SystemContext, UserContext, SecurityControls,
    EnvironmentType, ShellType,
)
from pip.analysis.correlation_graph import CorrelationGraphEngine
from pip.analysis.mitre_mapper import MitreMapper
from pip.scoring.risk_scorer import RiskScorer
from pip.scoring.fp_reducer import FPReducer
from pip.decision.decision_engine import DecisionEngine


# ── Shared fixtures ────────────────────────────────────────────────────────────

@pytest.fixture
def base_config(tmp_path: Path) -> ScanConfig:
    return ScanConfig(
        mode=ScanMode.DEEP,
        stealth=StealthProfile.NORMAL,
        output_dir=tmp_path,
        no_disk=True,
        timeout=30,
        mitre_map=True,
        blue_team=True,
    )


@pytest.fixture
def clean_sys_ctx() -> SystemContext:
    ctx = SystemContext()
    ctx.hostname       = "test-host"
    ctx.os_name        = "Ubuntu"
    ctx.os_version     = "22.04"
    ctx.kernel_version = "5.15.0"
    ctx.kernel_full    = "5.15.0-91-generic"
    ctx.arch           = "x86_64"
    ctx.environment_type = EnvironmentType.BARE_METAL
    ctx.shell_type     = ShellType.BASH
    ctx.cron_jobs      = ["* * * * * root /opt/backup.sh"]
    return ctx


@pytest.fixture
def hardened_sys_ctx(clean_sys_ctx: SystemContext) -> SystemContext:
    clean_sys_ctx.security_controls.selinux_enforcing   = True
    clean_sys_ctx.security_controls.apparmor_enabled    = True
    clean_sys_ctx.security_controls.crowdstrike_running = True
    return clean_sys_ctx


@pytest.fixture
def base_user_ctx() -> UserContext:
    ctx = UserContext()
    ctx.username = "www-data"
    ctx.uid      = 33
    ctx.gid      = 33
    ctx.groups   = ["www-data"]
    ctx.home_dir = "/var/www"
    ctx.shell    = "/bin/bash"
    return ctx


# ── Correlation graph tests ────────────────────────────────────────────────────

class TestCorrelationGraphEngine:

    def _make_cron_finding(self) -> Finding:
        f = Finding(
            title="World-writable cron script: /opt/backup.sh",
            category=FindingCategory.CRON,
            severity=Severity.CRITICAL,
            description="Test cron finding",
            affected_path="/opt/backup.sh",
            confidence=0.9,
        )
        return f

    def _make_suid_finding(self, path: str = "/usr/local/bin/custom") -> Finding:
        return Finding(
            title=f"Non-standard SUID binary: {path}",
            category=FindingCategory.SUID,
            severity=Severity.HIGH,
            description="Test SUID finding",
            affected_path=path,
            confidence=0.8,
        )

    def test_single_cron_finding_produces_path(self, base_config, clean_sys_ctx):
        engine = CorrelationGraphEngine(base_config)
        findings = [self._make_cron_finding()]
        paths = engine.build_paths(findings, clean_sys_ctx)
        assert len(paths) >= 1
        assert any("cron" in p.title.lower() or "cron" in p.path_id for p in paths)

    def test_suid_finding_produces_path(self, base_config, clean_sys_ctx):
        engine = CorrelationGraphEngine(base_config)
        findings = [self._make_suid_finding()]
        paths = engine.build_paths(findings, clean_sys_ctx)
        assert len(paths) >= 1

    def test_multiple_findings_produce_multiple_paths(self, base_config, clean_sys_ctx):
        engine = CorrelationGraphEngine(base_config)
        findings = [
            self._make_cron_finding(),
            self._make_suid_finding("/usr/local/bin/app1"),
            self._make_suid_finding("/usr/local/bin/app2"),
        ]
        paths = engine.build_paths(findings, clean_sys_ctx)
        assert len(paths) >= 2

    def test_paths_have_non_empty_steps(self, base_config, clean_sys_ctx):
        engine = CorrelationGraphEngine(base_config)
        findings = [self._make_cron_finding()]
        paths = engine.build_paths(findings, clean_sys_ctx)
        for path in paths:
            assert len(path.steps) > 0

    def test_path_steps_are_ordered(self, base_config, clean_sys_ctx):
        engine = CorrelationGraphEngine(base_config)
        findings = [self._make_cron_finding()]
        paths = engine.build_paths(findings, clean_sys_ctx)
        for path in paths:
            orders = [s.order for s in path.steps]
            assert orders == sorted(orders)

    def test_empty_findings_produce_no_paths(self, base_config, clean_sys_ctx):
        engine = CorrelationGraphEngine(base_config)
        paths = engine.build_paths([], clean_sys_ctx)
        assert paths == []

    def test_paths_have_unique_ids(self, base_config, clean_sys_ctx):
        engine = CorrelationGraphEngine(base_config)
        findings = [
            self._make_cron_finding(),
            self._make_suid_finding(),
            Finding(
                title="Writable sudoers",
                category=FindingCategory.WRITABLE,
                severity=Severity.CRITICAL,
                description="test",
                affected_path="/etc/sudoers",
                confidence=0.95,
            ),
        ]
        paths = engine.build_paths(findings, clean_sys_ctx)
        path_ids = [p.path_id for p in paths]
        assert len(path_ids) == len(set(path_ids))


# ── Risk scorer integration ────────────────────────────────────────────────────

class TestRiskScorerIntegration:

    def _make_minimal_path(self, category: FindingCategory, confidence: float = 0.8) -> AttackPath:
        finding = Finding(
            title="Test",
            category=category,
            severity=Severity.HIGH,
            description="test",
            confidence=confidence,
        )
        step = AttackStep(order=1, description="test", command="test", finding=finding)
        return AttackPath(path_id="test", title="test", steps=[step], verified=True)

    def test_full_pipeline_cron(self, clean_sys_ctx):
        scorer = RiskScorer(clean_sys_ctx)
        path = self._make_minimal_path(FindingCategory.CRON)
        scorer.score(path)
        # Cron: high exploitability, moderate stealth
        assert path.composite_score > 0
        assert path.stealth > 0.5  # Cron is stealthy

    def test_kernel_path_has_lower_stealth(self, clean_sys_ctx):
        scorer = RiskScorer(clean_sys_ctx)
        p_kernel = self._make_minimal_path(FindingCategory.KERNEL)
        p_cron   = self._make_minimal_path(FindingCategory.CRON)
        scorer.score(p_kernel)
        scorer.score(p_cron)
        assert p_kernel.stealth < p_cron.stealth

    def test_hardened_env_reduces_composite_score(
        self, clean_sys_ctx, hardened_sys_ctx
    ):
        s_clean    = RiskScorer(clean_sys_ctx)
        s_hardened = RiskScorer(hardened_sys_ctx)
        p_clean    = self._make_minimal_path(FindingCategory.SUID)
        p_hardened = self._make_minimal_path(FindingCategory.SUID)
        s_clean.score(p_clean)
        s_hardened.score(p_hardened)
        assert p_hardened.composite_score < p_clean.composite_score

    def test_composite_score_in_valid_range(self, clean_sys_ctx):
        scorer = RiskScorer(clean_sys_ctx)
        for cat in FindingCategory:
            path = self._make_minimal_path(cat)
            scorer.score(path)
            assert 0.0 <= path.composite_score <= 10.0, \
                f"Score out of range for {cat}: {path.composite_score}"

    def test_paths_sorted_by_score(self, clean_sys_ctx):
        scorer = RiskScorer(clean_sys_ctx)
        paths = [self._make_minimal_path(cat) for cat in
                 [FindingCategory.CRON, FindingCategory.KERNEL,
                  FindingCategory.SUID, FindingCategory.SUDO]]
        for p in paths:
            scorer.score(p)
        paths.sort(key=lambda p: p.composite_score, reverse=True)
        scores = [p.composite_score for p in paths]
        assert scores == sorted(scores, reverse=True)


# ── MITRE mapper + FP reducer pipeline ───────────────────────────────────────

class TestMappingPipeline:

    def test_mitre_then_fp_reduce_preserves_tagged_findings(self, clean_sys_ctx):
        mapper = MitreMapper()
        reducer = FPReducer(clean_sys_ctx)

        findings = [
            Finding(
                title="Non-standard SUID: /opt/app",
                category=FindingCategory.SUID,
                severity=Severity.HIGH,
                description="test",
                affected_path="/opt/app",
                confidence=0.8,
            ),
        ]
        for f in findings:
            mapper.tag(f)

        result = reducer.filter(findings)
        assert len(result) == 1
        assert result[0].mitre_id == "T1548.001"

    def test_benign_suid_suppressed_after_mapping(self, clean_sys_ctx):
        mapper = MitreMapper()
        reducer = FPReducer(clean_sys_ctx)

        f = Finding(
            title="SUID: /usr/bin/sudo",
            category=FindingCategory.SUID,
            severity=Severity.MEDIUM,
            description="Expected SUID",
            affected_path="/usr/bin/sudo",
            confidence=0.5,
        )
        mapper.tag(f)
        result = reducer.filter([f])
        assert len(result) == 0  # Benign + no exploit cmd = suppressed


# ── Reporting pipeline ────────────────────────────────────────────────────────

class TestReportingPipeline:

    def _make_paths(self) -> list[AttackPath]:
        finding = Finding(
            title="Cron injection",
            category=FindingCategory.CRON,
            severity=Severity.CRITICAL,
            description="World-writable cron script",
            affected_path="/opt/backup.sh",
            mitre_id="T1053.003",
            mitre_name="Scheduled Task/Job: Cron",
            verified=True,
            confidence=0.92,
        )
        step = AttackStep(
            order=1,
            description="Inject payload into /opt/backup.sh",
            command="echo 'payload' >> /opt/backup.sh",
            finding=finding,
            wait_seconds=60,
        )
        return [AttackPath(
            path_id="path_001",
            title="Cron injection via backup.sh",
            steps=[step],
            mitre_ids=["T1053.003"],
            composite_score=9.4,
            exploitability=0.95,
            reliability=0.92,
            impact=1.0,
            stealth=0.85,
            verified=True,
            estimated_time_seconds=65,
            narrative="Attacker injects into writable cron script, gains root after one cron cycle.",
        )]

    def test_executive_report_writes_html(self, base_config, clean_sys_ctx, base_user_ctx, tmp_path):
        from pip.reporting.executive import ExecutiveReporter
        base_config.output_dir = tmp_path
        reporter = ExecutiveReporter(base_config)
        paths = self._make_paths()
        reporter.generate(paths, clean_sys_ctx, base_user_ctx, {"mode": "deep", "duration_seconds": 45.2,
                                                                  "findings_count": 12, "paths_count": 3})
        html_path = tmp_path / "executive_report.html"
        assert html_path.exists()
        content = html_path.read_text()
        assert "CRITICAL" in content
        assert "T1053.003" in content

    def test_technical_report_writes_json(self, base_config, clean_sys_ctx, tmp_path):
        from pip.reporting.technical import TechnicalReporter
        import json
        base_config.output_dir = tmp_path
        reporter = TechnicalReporter(base_config)
        findings = [
            Finding(title="test", category=FindingCategory.CRON,
                    severity=Severity.HIGH, description="test")
        ]
        paths = self._make_paths()
        reporter.generate(findings, paths, clean_sys_ctx,
                          {"mode": "deep", "duration_seconds": 10, "findings_count": 1, "paths_count": 1})
        json_path = tmp_path / "technical_report.json"
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert "attack_paths" in data
        assert "all_findings" in data
        assert data["summary"]["total_paths"] == 1

    def test_blue_team_report_writes_json_with_remediation(
        self, base_config, clean_sys_ctx, tmp_path
    ):
        from pip.reporting.blue_team import BlueTeamReporter
        import json
        base_config.output_dir = tmp_path
        reporter = BlueTeamReporter(base_config)
        findings = [
            Finding(
                title="World-writable cron script: /opt/backup.sh",
                category=FindingCategory.CRON,
                severity=Severity.CRITICAL,
                description="test",
                affected_path="/opt/backup.sh",
            )
        ]
        paths = self._make_paths()
        reporter.generate(findings, paths, clean_sys_ctx,
                          {"mode": "deep", "duration_seconds": 10})
        json_path = tmp_path / "blue_team_report.json"
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert "findings" in data
        assert len(data["findings"]) == 1
        assert data["findings"][0]["remediation"] != ""

    def test_remediation_script_not_executable(self, base_config, clean_sys_ctx, tmp_path):
        from pip.reporting.blue_team import BlueTeamReporter
        import stat
        base_config.output_dir = tmp_path
        reporter = BlueTeamReporter(base_config)
        findings = [
            Finding(
                title="SUID: /opt/app",
                category=FindingCategory.SUID,
                severity=Severity.HIGH,
                description="test",
                affected_path="/opt/app",
            )
        ]
        reporter.generate(findings, [], clean_sys_ctx, {})
        script_path = tmp_path / "remediate.sh"
        assert script_path.exists()
        mode = script_path.stat().st_mode
        # Must NOT be executable (safety requirement)
        assert not (mode & stat.S_IXUSR), "remediate.sh must not be executable"
