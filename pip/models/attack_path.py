"""
pip/models/attack_path.py

Represents a complete multi-hop attack path from current user to root.
Produced by the CorrelationGraphEngine and scored by the RiskScorer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from pip.models.finding import Finding


@dataclass
class AttackStep:
    """
    A single step within a multi-hop attack path.

    Attributes:
        order:       Step index (1-based).
        description: Human-readable action description.
        command:     Exact command to execute.
        finding:     The underlying Finding that enables this step.
        expected:    What the attacker expects to happen after this step.
        wait_seconds: Estimated wait time (e.g. for cron execution).
    """

    order: int
    description: str
    command: str
    finding: Finding
    expected: str = ""
    wait_seconds: int = 0

    def to_dict(self) -> dict:
        return {
            "order": self.order,
            "description": self.description,
            "command": self.command,
            "expected": self.expected,
            "wait_seconds": self.wait_seconds,
            "finding": self.finding.to_dict(),
        }


@dataclass
class AttackPath:
    """
    A complete, ranked privilege escalation path from the current context to root.

    Scoring formula:
        composite_score = exploitability * reliability * impact * stealth
        (each component 0.0–1.0, composite mapped to 0.0–10.0)

    Attributes:
        path_id:        Unique identifier (e.g. "path_001").
        title:          Short name for this path (e.g. "Cron injection via backup.sh").
        steps:          Ordered list of AttackStep objects.
        mitre_ids:      All ATT&CK T-codes involved in this path.
        composite_score: Final risk score 0.0–10.0.
        exploitability: How easy the path is to execute (0.0–1.0).
        reliability:    Likelihood of success (0.0–1.0).
        impact:         Outcome severity (0.0–1.0).
        stealth:        How unlikely detection is (0.0–1.0).
        verified:       True if ExploitValidator confirmed at least one step.
        estimated_time_seconds: Rough time to complete the full path.
        narrative:      Attack story for executive / consultant report.
        remediation_summary: High-level fix description for blue team report.
    """

    path_id: str
    title: str
    steps: list[AttackStep] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    composite_score: float = 0.0
    exploitability: float = 0.0
    reliability: float = 0.0
    impact: float = 0.0
    stealth: float = 0.0
    verified: bool = False
    estimated_time_seconds: int = 0
    narrative: str = ""
    remediation_summary: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.steps)

    @property
    def is_critical(self) -> bool:
        return self.composite_score >= 9.0

    @property
    def score_label(self) -> str:
        if self.composite_score >= 9.0:
            return "CRITICAL"
        if self.composite_score >= 7.0:
            return "HIGH"
        if self.composite_score >= 5.0:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "title": self.title,
            "composite_score": round(self.composite_score, 2),
            "score_label": self.score_label,
            "verified": self.verified,
            "exploitability": round(self.exploitability, 2),
            "reliability": round(self.reliability, 2),
            "impact": round(self.impact, 2),
            "stealth": round(self.stealth, 2),
            "estimated_time_seconds": self.estimated_time_seconds,
            "mitre_ids": self.mitre_ids,
            "steps": [s.to_dict() for s in self.steps],
            "narrative": self.narrative,
            "remediation_summary": self.remediation_summary,
        }

    def __repr__(self) -> str:
        return f"<AttackPath [{self.score_label}] {self.title} score={self.composite_score:.1f}>"
