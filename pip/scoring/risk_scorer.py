"""
pip/scoring/risk_scorer.py

Risk Scoring Engine.

Scores each AttackPath using the composite formula:
    composite = (exploitability × reliability × impact × stealth) × 10

Each component is 0.0–1.0. The final score is 0.0–10.0.

Component definitions:
    exploitability  — how easy is it for an unprivileged user to attempt this path?
                      (auth requirements, tool availability, complexity)
    reliability     — how likely is this path to succeed?
                      (confidence from ExploitValidator, false-positive history)
    impact          — what is the outcome? root = 1.0, write-only = 0.5, info = 0.1
    stealth         — how unlikely is this to be detected?
                      (commands used, file writes, audit log exposure)
"""

from __future__ import annotations

from pip.models.attack_path import AttackPath
from pip.models.context import SystemContext
from pip.models.finding import FindingCategory, Severity


class RiskScorer:
    """Computes and assigns composite risk scores to AttackPath objects."""

    def __init__(self, sys_ctx: SystemContext):
        self.sys_ctx = sys_ctx

    def score(self, path: AttackPath) -> None:
        """
        Compute and assign all scoring components to the given AttackPath.
        Modifies the path object in-place.
        """
        path.exploitability = self._score_exploitability(path)
        path.reliability    = self._score_reliability(path)
        path.impact         = self._score_impact(path)
        path.stealth        = self._score_stealth(path)

        # Geometric mean-style composite: penalizes any weak component
        product = (
            path.exploitability
            * path.reliability
            * path.impact
            * path.stealth
        )
        path.composite_score = round(product ** 0.25 * 10, 2)

        # Estimate execution time from step wait times
        path.estimated_time_seconds = sum(
            s.wait_seconds for s in path.steps
        ) + len(path.steps) * 5

    # ── Component scorers ─────────────────────────────────────────────────────

    def _score_exploitability(self, path: AttackPath) -> float:
        """
        Higher score = easier to exploit.
        Factors: step count, tool availability, no special preconditions.
        """
        base = 1.0
        # Penalise multi-step paths (each extra step adds friction)
        base -= (len(path.steps) - 1) * 0.1
        # Penalise kernel exploits (require compilation/transfer)
        if any(s.finding.category == FindingCategory.KERNEL for s in path.steps):
            base -= 0.2
        # Bonus for NOPASSWD sudo (trivial execution)
        if any(s.finding.category == FindingCategory.SUDO for s in path.steps):
            base += 0.1
        return max(0.1, min(1.0, base))

    def _score_reliability(self, path: AttackPath) -> float:
        """
        Higher score = more likely to succeed.
        Anchored to validation confidence of the least reliable step.
        """
        if not path.steps:
            return 0.1
        # Bottleneck: weakest link determines reliability
        min_confidence = min(s.finding.confidence for s in path.steps)
        base = min_confidence
        # Bonus if the whole path was dry-run validated
        if path.verified:
            base = min(1.0, base + 0.15)
        # Penalise for security controls
        sc = self.sys_ctx.security_controls
        if sc.selinux_enforcing:
            base *= 0.6
        if sc.apparmor_enabled:
            base *= 0.8
        return round(max(0.05, min(1.0, base)), 3)

    @staticmethod
    def _score_impact(path: AttackPath) -> float:
        """
        All paths in PIP lead to root_shell, so impact is always 1.0.
        Partial paths (write-only, info-leak) would score lower.
        """
        return 1.0

    def _score_stealth(self, path: AttackPath) -> float:
        """
        Higher score = less likely to be detected.
        Factors: commands used, disk writes, auditd presence, EDR presence.
        """
        base = 0.8
        sc = self.sys_ctx.security_controls

        if sc.auditd_running:
            base -= 0.2
        if sc.crowdstrike_running or sc.defender_running:
            base -= 0.25

        # Cron-based attacks are stealthy (no interactive shell spawned)
        if any(s.finding.category == FindingCategory.CRON for s in path.steps):
            base += 0.15

        # Kernel exploits tend to be loud (crash risk, dmesg)
        if any(s.finding.category == FindingCategory.KERNEL for s in path.steps):
            base -= 0.3

        # Container escape may trigger Falco/sysdig rules
        if any(s.finding.category == FindingCategory.CONTAINER for s in path.steps):
            base -= 0.2

        return round(max(0.05, min(1.0, base)), 3)
