"""
pip/reporting/technical.py

Technical Report Generator.

Produces machine-readable output for the security team:
  - JSON report: full findings + attack paths + scan metadata
  - SARIF 2.1.0: compatible with GitHub Advanced Security, VS Code,
    and any SARIF-aware CI/CD tooling

Audience: penetration testers, security engineers, DevSecOps pipelines.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pip.models.attack_path import AttackPath
from pip.models.context import ScanConfig, SystemContext
from pip.models.finding import Finding, Severity


class TechnicalReporter:
    """Generates JSON and SARIF technical reports."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def generate(
        self,
        findings: list[Finding],
        paths: list[AttackPath],
        sys_ctx: SystemContext,
        scan_meta: dict,
    ) -> None:
        self._write_json(findings, paths, sys_ctx, scan_meta)
        if self.config.output_format == "sarif":
            self._write_sarif(findings, paths)

    # ── JSON ──────────────────────────────────────────────────────────────────

    def _write_json(
        self,
        findings: list[Finding],
        paths: list[AttackPath],
        sys_ctx: SystemContext,
        scan_meta: dict,
    ) -> None:
        report = {
            "pip_version": "2.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_meta": scan_meta,
            "system": {
                "hostname":    sys_ctx.hostname,
                "os":          f"{sys_ctx.os_name} {sys_ctx.os_version}",
                "kernel":      sys_ctx.kernel_full,
                "arch":        sys_ctx.arch,
                "environment": sys_ctx.environment_type.value,
                "cloud":       sys_ctx.cloud_provider.value if sys_ctx.cloud_provider else None,
                "security_controls": {
                    "selinux_enforcing":   sys_ctx.security_controls.selinux_enforcing,
                    "apparmor_enabled":    sys_ctx.security_controls.apparmor_enabled,
                    "auditd_running":      sys_ctx.security_controls.auditd_running,
                    "crowdstrike_running": sys_ctx.security_controls.crowdstrike_running,
                },
            },
            "summary": {
                "total_findings":  len(findings),
                "total_paths":     len(paths),
                "verified_paths":  sum(1 for p in paths if p.verified),
                "critical_findings": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high_findings":     sum(1 for f in findings if f.severity == Severity.HIGH),
                "top_score":       paths[0].composite_score if paths else 0.0,
                "mitre_ids":       sorted({mid for p in paths for mid in p.mitre_ids}),
            },
            "attack_paths":  [p.to_dict() for p in paths],
            "all_findings":  [f.to_dict() for f in findings],
        }
        out = self.config.output_dir / "technical_report.json"
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # ── SARIF 2.1.0 ───────────────────────────────────────────────────────────

    def _write_sarif(self, findings: list[Finding], paths: list[AttackPath]) -> None:
        """
        Emit SARIF 2.1.0 output.

        Each Finding becomes a SARIF result. Attack paths are encoded as
        related locations on the result's primary finding.
        """
        level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH:     "error",
            Severity.MEDIUM:   "warning",
            Severity.LOW:      "note",
            Severity.INFO:     "none",
        }

        rules = self._build_sarif_rules(findings)
        results = []

        for finding in findings:
            result: dict = {
                "ruleId":   finding.mitre_id or finding.category.value,
                "level":    level_map.get(finding.severity, "warning"),
                "message":  {"text": finding.description},
                "properties": {
                    "severity":     finding.severity.value,
                    "category":     finding.category.value,
                    "verified":     finding.verified,
                    "confidence":   finding.confidence,
                    "source_module": finding.source_module,
                },
            }
            if finding.affected_path:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.affected_path.lstrip("/"),
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                }]
            if finding.exploit_cmd:
                result["fixes"] = [{
                    "description": {"text": finding.remediation or "See blue team report for remediation."}
                }]
            results.append(result)

        sarif = {
            "version": "2.1.0",
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                "master/Schemata/sarif-schema-2.1.0.json"
            ),
            "runs": [{
                "tool": {
                    "driver": {
                        "name":           "PIP",
                        "fullName":       "PrivEsc Intelligence Platform",
                        "version":        "2.0.0",
                        "informationUri": "https://github.com/yourusername/pip-toolkit",
                        "rules":          rules,
                    }
                },
                "results": results,
            }],
        }

        out = self.config.output_dir / "technical_report.sarif"
        out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    @staticmethod
    def _build_sarif_rules(findings: list[Finding]) -> list[dict]:
        seen: set[str] = set()
        rules = []
        for f in findings:
            rule_id = f.mitre_id or f.category.value
            if rule_id in seen:
                continue
            seen.add(rule_id)
            rules.append({
                "id":               rule_id,
                "name":             f.mitre_name or f.category.value.replace("_", " ").title(),
                "shortDescription": {"text": f.title},
                "fullDescription":  {"text": f.description},
                "helpUri":          (
                    f"https://attack.mitre.org/techniques/{f.mitre_id.replace('.', '/')}/"
                    if f.mitre_id else ""
                ),
            })
        return rules
