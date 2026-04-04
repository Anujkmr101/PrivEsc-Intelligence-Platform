"""
pip/analysis/mitre_mapper.py

MITRE ATT&CK Mapper.

Tags each Finding with the corresponding ATT&CK technique ID (T-code)
and technique name. Also provides sub-technique IDs where applicable.

Mapping is category-based for speed, with binary-specific overrides
for well-known techniques (e.g. sudo → T1548.003).
"""
from __future__ import annotations
from pip.models.finding import Finding, FindingCategory

# Category → (technique_id, technique_name) mapping
_CATEGORY_MAP: dict[FindingCategory, tuple[str, str]] = {
    FindingCategory.SUID:       ("T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid"),
    FindingCategory.SUDO:       ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"),
    FindingCategory.CRON:       ("T1053.003", "Scheduled Task/Job: Cron"),
    FindingCategory.WRITABLE:   ("T1222.002", "File and Directory Permissions Modification: Linux and Mac"),
    FindingCategory.CAPABILITY: ("T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid"),
    FindingCategory.KERNEL:     ("T1068",     "Exploitation for Privilege Escalation"),
    FindingCategory.SERVICE:    ("T1543.002", "Create or Modify System Process: Systemd Service"),
    FindingCategory.CREDENTIAL: ("T1552",     "Unsecured Credentials"),
    FindingCategory.CLOUD:      ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API"),
    FindingCategory.CONTAINER:  ("T1611",     "Escape to Host"),
    FindingCategory.LATERAL:    ("T1021.004", "Remote Services: SSH"),
    FindingCategory.NFS:        ("T1187",     "Forced Authentication"),
    FindingCategory.PATH:       ("T1574.007", "Hijack Execution Flow: Path Interception by PATH Environment Variable"),
    FindingCategory.LIBRARY:    ("T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking"),
    FindingCategory.ENV:        ("T1552.001", "Unsecured Credentials: Credentials In Files"),
}

class MitreMapper:
    """Attaches ATT&CK technique IDs and names to Finding objects."""

    def tag(self, finding: Finding) -> None:
        mapping = _CATEGORY_MAP.get(finding.category)
        if mapping:
            finding.mitre_id, finding.mitre_name = mapping
