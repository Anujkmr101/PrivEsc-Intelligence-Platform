"""
pip/reporting/blue_team.py

Blue Team / Hardening Report Generator.

Produces a defensive-focused report mapping every finding to:
  - Exact remediation command
  - CIS Benchmark control reference (Level 1 or 2)
  - MITRE D3FEND countermeasure (where applicable)
  - Sigma/YARA detection rule stub for the attack path
  - Priority ordering by composite risk score

Audience: system administrators, hardening engineers, compliance auditors.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from pip.models.attack_path import AttackPath
from pip.models.context import ScanConfig, SystemContext
from pip.models.finding import Finding, FindingCategory, Severity


# ── Remediation templates ──────────────────────────────────────────────────────

_REMEDIATION: dict[FindingCategory, str] = {
    FindingCategory.SUID:       "chmod u-s {path}",
    FindingCategory.SUDO:       "# Edit /etc/sudoers via visudo — remove NOPASSWD for {path}",
    FindingCategory.CRON:       "chmod 750 {path} && chown root:root {path}",
    FindingCategory.WRITABLE:   "chmod o-w {path}",
    FindingCategory.CAPABILITY: "setcap -r {path}",
    FindingCategory.SERVICE:    "chmod 644 {path} && chown root:root {path}",
    FindingCategory.CONTAINER:  "# Remove Docker socket mount; avoid --privileged flag",
    FindingCategory.NFS:        "# Edit /etc/exports — remove no_root_squash from {path}",
    FindingCategory.CLOUD:      "# Enable IMDSv2: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required",
    FindingCategory.PATH:       "# Remove {path} from PATH or make it non-writable: chmod o-w {path}",
    FindingCategory.LIBRARY:    "# Unset LD_LIBRARY_PATH in /etc/environment and user profile files",
    FindingCategory.CREDENTIAL: "# Rotate the exposed credential immediately and audit all access logs",
    FindingCategory.LATERAL:    "chmod 700 {path}",
    FindingCategory.KERNEL:     "# Apply kernel patch: apt-get update && apt-get upgrade linux-image-$(uname -r)",
    FindingCategory.OTHER:      "# Review and restrict: {path}",
}

# CIS Benchmark control references
_CIS_CONTROLS: dict[FindingCategory, dict] = {
    FindingCategory.SUID:       {"id": "6.3.3", "title": "Ensure SUID and SGID files are reviewed", "level": 1},
    FindingCategory.SUDO:       {"id": "5.3.7", "title": "Ensure sudo commands use pty", "level": 1},
    FindingCategory.CRON:       {"id": "5.1.3", "title": "Ensure permissions on /etc/cron.d are configured", "level": 1},
    FindingCategory.WRITABLE:   {"id": "6.1.2", "title": "Ensure permissions on /etc/passwd are configured", "level": 1},
    FindingCategory.CAPABILITY: {"id": "6.3.3", "title": "Ensure no programs have excessive capabilities", "level": 2},
    FindingCategory.SERVICE:    {"id": "6.1.1", "title": "Audit system file permissions", "level": 1},
    FindingCategory.CONTAINER:  {"id": "5.25",  "title": "Do not expose the Docker daemon socket", "level": 1},
    FindingCategory.NFS:        {"id": "2.2.7",  "title": "Ensure NFS is not enabled (or configured securely)", "level": 1},
    FindingCategory.KERNEL:     {"id": "1.9",    "title": "Ensure updates and patches are applied", "level": 1},
}

# Sigma rule stub templates per attack category
_SIGMA_STUBS: dict[FindingCategory, str] = {
    FindingCategory.SUID: """title: SUID Binary Execution for Privilege Escalation
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: '{binary}'
  condition: selection
falsepositives:
  - Legitimate administrative use
level: high""",

    FindingCategory.CRON: """title: Cron Script Modified by Non-Root User
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: PATH
    name: '{path}'
    nametype: NORMAL
  filter:
    uid: '0'
  condition: selection and not filter
level: critical""",

    FindingCategory.SUDO: """title: Sudo NOPASSWD Rule Exploitation
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|startswith: 'sudo '
    User|ne: 'root'
  condition: selection
falsepositives:
  - Routine administrative sudo use
level: medium""",
}


class BlueTeamReporter:
    """Generates the Blue Team hardening and detection report."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def generate(
        self,
        findings: list[Finding],
        paths: list[AttackPath],
        sys_ctx: SystemContext,
        scan_meta: dict,
    ) -> None:
        # Attach remediation commands to each finding
        for finding in findings:
            finding.remediation = self._get_remediation(finding)

        report = self._build_report(findings, paths, sys_ctx, scan_meta)

        json_path = self.config.output_dir / "blue_team_report.json"
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        # Also write a plain-text remediation script
        self._write_remediation_script(findings)

    # ── Report builder ────────────────────────────────────────────────────────

    def _build_report(
        self,
        findings: list[Finding],
        paths: list[AttackPath],
        sys_ctx: SystemContext,
        scan_meta: dict,
    ) -> dict:
        cis_level = self.config.cis_level
        items = []

        for finding in sorted(findings, key=lambda f: f.severity.value):
            cis = _CIS_CONTROLS.get(finding.category)
            sigma = self._get_sigma_stub(finding)
            item = {
                "title":        finding.title,
                "severity":     finding.severity.value,
                "category":     finding.category.value,
                "affected_path": finding.affected_path,
                "mitre_id":     finding.mitre_id,
                "mitre_name":   finding.mitre_name,
                "description":  finding.description,
                "remediation":  finding.remediation,
                "verified":     finding.verified,
            }
            if cis and cis.get("level", 99) <= cis_level:
                item["cis_control"] = cis
            if sigma:
                item["sigma_rule"] = sigma
            items.append(item)

        # Detection rules for each discovered attack path
        path_detections = []
        for path in paths[:5]:
            path_detections.append({
                "path_title":   path.title,
                "mitre_ids":    path.mitre_ids,
                "sigma_rules":  [
                    self._get_sigma_stub(step.finding)
                    for step in path.steps
                    if self._get_sigma_stub(step.finding)
                ],
            })

        return {
            "pip_version":    "2.0.0",
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "target":         sys_ctx.hostname,
            "cis_level":      cis_level,
            "summary": {
                "total":    len(findings),
                "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high":     sum(1 for f in findings if f.severity == Severity.HIGH),
                "medium":   sum(1 for f in findings if f.severity == Severity.MEDIUM),
            },
            "findings":          items,
            "path_detections":   path_detections,
            "hardening_checklist": self._build_checklist(findings),
        }

    # ── Hardening checklist ───────────────────────────────────────────────────

    @staticmethod
    def _build_checklist(findings: list[Finding]) -> list[dict]:
        """
        Produce an ordered, deduplicated hardening checklist.
        Priority: CRITICAL → HIGH → MEDIUM → LOW.
        """
        seen: set[str] = set()
        checklist = []
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

        for sev in severity_order:
            for finding in findings:
                if finding.severity != sev:
                    continue
                key = f"{finding.category.value}:{finding.affected_path}"
                if key in seen:
                    continue
                seen.add(key)
                checklist.append({
                    "priority":   sev.value,
                    "action":     finding.remediation,
                    "path":       finding.affected_path,
                    "rationale":  finding.title,
                    "mitre":      finding.mitre_id,
                    "done":       False,
                })
        return checklist

    # ── Remediation script ────────────────────────────────────────────────────

    def _write_remediation_script(self, findings: list[Finding]) -> None:
        """
        Write a bash script with all remediation commands.
        The script is commented and requires explicit uncommenting to run —
        it is never auto-executed.
        """
        lines = [
            "#!/bin/bash",
            "# PIP Remediation Script — generated by PIP v2.0.0",
            "# WARNING: Review every command before executing.",
            "#          Each command is commented out by default.",
            f"# Target:  {self.config.output_dir}",
            f"# Generated: {datetime.now(timezone.utc).isoformat()}",
            "",
        ]
        seen: set[str] = set()
        for finding in sorted(findings, key=lambda f: f.severity.value):
            rem = finding.remediation
            if not rem or rem in seen:
                continue
            seen.add(rem)
            lines.append(f"# [{finding.severity.value.upper()}] {finding.title}")
            lines.append(f"# {rem}")
            lines.append("")

        script_path = self.config.output_dir / "remediate.sh"
        script_path.write_text("\n".join(lines), encoding="utf-8")
        script_path.chmod(0o644)  # Not executable — requires deliberate chmod +x

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _get_remediation(finding: Finding) -> str:
        template = _REMEDIATION.get(finding.category, "# Review and restrict: {path}")
        return template.format(path=finding.affected_path or "<path>", binary=finding.affected_path or "<binary>")

    @staticmethod
    def _get_sigma_stub(finding: Finding) -> str:
        template = _SIGMA_STUBS.get(finding.category, "")
        if not template:
            return ""
        return template.format(
            binary=finding.affected_path or "<binary>",
            path=finding.affected_path or "<path>",
        )
