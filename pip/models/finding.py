"""
pip/models/finding.py

Core data model for a single discovered finding.
All enumeration modules produce Finding instances.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    SUID = "suid"
    SUDO = "sudo"
    CRON = "cron"
    WRITABLE = "writable"
    CAPABILITY = "capability"
    KERNEL = "kernel"
    SERVICE = "service"
    CREDENTIAL = "credential"
    CLOUD = "cloud"
    CONTAINER = "container"
    LATERAL = "lateral"
    NFS = "nfs"
    PATH = "path_hijack"
    LIBRARY = "library_hijack"
    ENV = "environment"
    OTHER = "other"


@dataclass
class Finding:
    """
    A single privilege escalation finding produced by an enumeration module.

    Attributes:
        title:          Short human-readable name (e.g. "World-writable cron script").
        category:       FindingCategory enum value.
        severity:       Severity enum value.
        description:    Full technical description of the finding.
        evidence:       Raw command output or file content that proved the finding.
        command:        The command used to discover this finding.
        affected_path:  File, binary, or resource path (if applicable).
        mitre_id:       MITRE ATT&CK technique ID (e.g. "T1053.003"). Set by MitreMapper.
        mitre_name:     Human-readable technique name.
        gtfobins_url:   GTFOBins link if a binary abuse path exists.
        exploit_cmd:    Generated exploit command (if GTFOBins-correlated or validated).
        cve:            CVE identifier if kernel/software vulnerability.
        verified:       True if ExploitValidator has confirmed exploitability.
        confidence:     Float 0.0–1.0. Set by FPReducer and ExploitValidator.
        remediation:    Short remediation command(s). Set by BlueTeam reporter.
        tags:           Arbitrary string tags for filtering.
        source_module:  Name of the module that produced this finding.
    """

    title: str
    category: FindingCategory
    severity: Severity
    description: str
    evidence: str = ""
    command: str = ""
    affected_path: str = ""
    mitre_id: str = ""
    mitre_name: str = ""
    gtfobins_url: str = ""
    exploit_cmd: str = ""
    cve: str = ""
    verified: bool = False
    confidence: float = 0.5
    remediation: str = ""
    tags: list[str] = field(default_factory=list)
    source_module: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "command": self.command,
            "affected_path": self.affected_path,
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
            "gtfobins_url": self.gtfobins_url,
            "exploit_cmd": self.exploit_cmd,
            "cve": self.cve,
            "verified": self.verified,
            "confidence": self.confidence,
            "remediation": self.remediation,
            "tags": self.tags,
            "source_module": self.source_module,
        }

    def __repr__(self) -> str:
        return f"<Finding [{self.severity.value.upper()}] {self.title}>"
