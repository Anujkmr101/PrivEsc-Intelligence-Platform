"""
tests/test_scoring.py

Unit tests for the scoring and analysis engines.
"""

import pytest
from pip.models.finding import Finding, FindingCategory, Severity
from pip.models.attack_path import AttackPath, AttackStep
from pip.models.context import SystemContext, SecurityControls, EnvironmentType
from pip.scoring.risk_scorer import RiskScorer
from pip.scoring.fp_reducer import FPReducer
from pip.analysis.mitre_mapper import MitreMapper


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_finding(category: FindingCategory, severity: Severity = Severity.HIGH,
                 path: str = "/test", confidence: float = 0.8) -> Finding:
    return Finding(
        title=f"Test {category.value}",
        category=category,
        severity=severity,
        description="Test finding",
        affected_path=path,
        confidence=confidence,
    )

def make_path(steps_categories: list[FindingCategory], verified: bool = True) -> AttackPath:
    steps = [
        AttackStep(
            order=i + 1,
            description="test step",
            command="echo test",
            finding=make_finding(cat),
        )
        for i, cat in enumerate(steps_categories)
    ]
    return AttackPath(
        path_id=f"path_test",
        title="test path",
        steps=steps,
        verified=verified,
    )

def make_sys_ctx(**kwargs) -> SystemContext:
    ctx = SystemContext()
    for k, v in kwargs.items():
        if hasattr(ctx.security_controls, k):
            setattr(ctx.security_controls, k, v)
        else:
            setattr(ctx, k, v)
    return ctx


# ── RiskScorer tests ───────────────────────────────────────────────────────────

class TestRiskScorer:
    def test_score_assigns_all_components(self):
        ctx = make_sys_ctx()
        scorer = RiskScorer(ctx)
        path = make_path([FindingCategory.CRON])
        scorer.score(path)
        assert 0.0 <= path.exploitability <= 1.0
        assert 0.0 <= path.reliability    <= 1.0
        assert 0.0 <= path.impact         <= 1.0
        assert 0.0 <= path.stealth        <= 1.0
        assert 0.0 <= path.composite_score <= 10.0

    def test_selinux_enforcing_reduces_reliability(self):
        ctx_clean  = make_sys_ctx(selinux_enforcing=False)
        ctx_se     = make_sys_ctx(selinux_enforcing=True)
        scorer_c   = RiskScorer(ctx_clean)
        scorer_se  = RiskScorer(ctx_se)
        path_c     = make_path([FindingCategory.SUID])
        path_se    = make_path([FindingCategory.SUID])
        scorer_c.score(path_c)
        scorer_se.score(path_se)
        assert path_se.reliability < path_c.reliability

    def test_crowdstrike_reduces_stealth(self):
        ctx_clean = make_sys_ctx(crowdstrike_running=False)
        ctx_cs    = make_sys_ctx(crowdstrike_running=True)
        s_clean   = RiskScorer(ctx_clean)
        s_cs      = RiskScorer(ctx_cs)
        p_clean   = make_path([FindingCategory.SUDO])
        p_cs      = make_path([FindingCategory.SUDO])
        s_clean.score(p_clean)
        s_cs.score(p_cs)
        assert p_cs.stealth < p_clean.stealth

    def test_cron_path_has_higher_stealth_than_kernel(self):
        ctx = make_sys_ctx()
        scorer = RiskScorer(ctx)
        p_cron   = make_path([FindingCategory.CRON])
        p_kernel = make_path([FindingCategory.KERNEL])
        scorer.score(p_cron)
        scorer.score(p_kernel)
        assert p_cron.stealth > p_kernel.stealth

    def test_multi_step_path_lower_exploitability(self):
        ctx = make_sys_ctx()
        scorer = RiskScorer(ctx)
        p_one   = make_path([FindingCategory.SUID])
        p_three = make_path([FindingCategory.SUID, FindingCategory.CRON, FindingCategory.LATERAL])
        scorer.score(p_one)
        scorer.score(p_three)
        assert p_three.exploitability < p_one.exploitability

    def test_sudo_nopasswd_bonus(self):
        ctx = make_sys_ctx()
        scorer = RiskScorer(ctx)
        p_sudo = make_path([FindingCategory.SUDO])
        p_suid = make_path([FindingCategory.SUID])
        scorer.score(p_sudo)
        scorer.score(p_suid)
        assert p_sudo.exploitability >= p_suid.exploitability

    def test_impact_always_one(self):
        ctx = make_sys_ctx()
        scorer = RiskScorer(ctx)
        for cat in [FindingCategory.CRON, FindingCategory.KERNEL, FindingCategory.CONTAINER]:
            path = make_path([cat])
            scorer.score(path)
            assert path.impact == 1.0

    def test_estimated_time_set(self):
        ctx = make_sys_ctx()
        scorer = RiskScorer(ctx)
        path = make_path([FindingCategory.CRON])
        path.steps[0].finding  # wait_seconds = 0 by default
        scorer.score(path)
        assert path.estimated_time_seconds >= 0


# ── FPReducer tests ────────────────────────────────────────────────────────────

class TestFPReducer:
    def test_expected_suid_without_exploit_cmd_suppressed(self):
        ctx = make_sys_ctx()
        reducer = FPReducer(ctx)
        f = make_finding(FindingCategory.SUID, path="/usr/bin/sudo")
        f.exploit_cmd = ""  # No GTFOBins command = expected/benign
        result = reducer.filter([f])
        assert len(result) == 0

    def test_suid_with_exploit_cmd_not_suppressed(self):
        ctx = make_sys_ctx()
        reducer = FPReducer(ctx)
        f = make_finding(FindingCategory.SUID, path="/usr/bin/sudo")
        f.exploit_cmd = "sudo su"
        result = reducer.filter([f])
        assert len(result) == 1

    def test_non_standard_suid_not_suppressed(self):
        ctx = make_sys_ctx()
        reducer = FPReducer(ctx)
        f = make_finding(FindingCategory.SUID, path="/opt/custom/app")
        result = reducer.filter([f])
        assert len(result) == 1

    def test_low_confidence_kernel_without_cve_suppressed(self):
        ctx = make_sys_ctx()
        reducer = FPReducer(ctx)
        f = make_finding(FindingCategory.KERNEL, confidence=0.2)
        f.cve = ""
        result = reducer.filter([f])
        assert len(result) == 0

    def test_kernel_with_cve_not_suppressed(self):
        ctx = make_sys_ctx()
        reducer = FPReducer(ctx)
        f = make_finding(FindingCategory.KERNEL, confidence=0.2)
        f.cve = "CVE-2021-3156"
        result = reducer.filter([f])
        assert len(result) == 1


# ── MitreMapper tests ──────────────────────────────────────────────────────────

class TestMitreMapper:
    def test_suid_maps_to_t1548(self):
        mapper = MitreMapper()
        f = make_finding(FindingCategory.SUID)
        mapper.tag(f)
        assert f.mitre_id == "T1548.001"
        assert "Setuid" in f.mitre_name

    def test_cron_maps_to_t1053(self):
        mapper = MitreMapper()
        f = make_finding(FindingCategory.CRON)
        mapper.tag(f)
        assert f.mitre_id == "T1053.003"

    def test_container_maps_to_t1611(self):
        mapper = MitreMapper()
        f = make_finding(FindingCategory.CONTAINER)
        mapper.tag(f)
        assert f.mitre_id == "T1611"

    def test_cloud_maps_to_t1552(self):
        mapper = MitreMapper()
        f = make_finding(FindingCategory.CLOUD)
        mapper.tag(f)
        assert "T1552" in f.mitre_id

    @pytest.mark.parametrize("category", [
        FindingCategory.SUID, FindingCategory.SUDO, FindingCategory.CRON,
        FindingCategory.CAPABILITY, FindingCategory.SERVICE, FindingCategory.KERNEL,
        FindingCategory.CONTAINER, FindingCategory.CLOUD, FindingCategory.NFS,
        FindingCategory.PATH, FindingCategory.LIBRARY, FindingCategory.CREDENTIAL,
    ])
    def test_all_mapped_categories_have_nonempty_id(self, category):
        mapper = MitreMapper()
        f = make_finding(category)
        mapper.tag(f)
        assert f.mitre_id != "", f"Category {category} has no MITRE mapping"
