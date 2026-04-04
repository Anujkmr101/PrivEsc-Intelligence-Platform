"""
pip/enum/credential_intel.py

Credential Intelligence Module.

Discovers credentials from multiple sources without active bruteforcing:
  - Environment variables (tokens, passwords, API keys)
  - Shell history files (.bash_history, .zsh_history)
  - Cloud metadata endpoints (AWS/GCP/Azure IMDS)
  - Application config files (database credentials, .env files)
  - Git repository history (accidental credential commits)
  - /proc/[pid]/environ for running processes (safe read)
"""
from __future__ import annotations
import os, re
from pip.models.context import ScanConfig, SystemContext, UserContext
from pip.models.finding import Finding, FindingCategory, Severity
from pip.core.shell_compat import ShellCompat

# Regex patterns for credential detection
_CRED_PATTERNS = {
    "aws_access_key":    (re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    "api_key_generic":   (re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})"), Severity.HIGH),
    "password_var":      (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?(\S{6,})"), Severity.HIGH),
    "private_key_header":(re.compile(r"-----BEGIN [A-Z]+ PRIVATE KEY-----"), Severity.CRITICAL),
    "db_url":            (re.compile(r"(?i)(mysql|postgres|mongodb|redis)://[^@\s]+@[^@\s]+"), Severity.HIGH),
    "github_token":      (re.compile(r"ghp_[A-Za-z0-9]{36}"), Severity.CRITICAL),
    "jwt_token":         (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}"), Severity.MEDIUM),
}

class CredentialIntelModule:
    name = "credential_intel"

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, sys_ctx: SystemContext, user_ctx: UserContext, shell: ShellCompat) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_environment_vars())
        findings.extend(self._check_shell_history(user_ctx, shell))
        findings.extend(self._check_config_files(shell))
        findings.extend(self._check_git_history(shell))
        if sys_ctx.imds_accessible:
            findings.extend(self._check_cloud_imds(sys_ctx, shell))
        return findings

    def _check_environment_vars(self) -> list[Finding]:
        findings = []
        env_dump = "\n".join(f"{k}={v}" for k, v in os.environ.items())
        for pattern_name, (pattern, sev) in _CRED_PATTERNS.items():
            match = pattern.search(env_dump)
            if match:
                findings.append(Finding(
                    title=f"Credential in environment: {pattern_name}",
                    category=FindingCategory.CREDENTIAL,
                    severity=sev,
                    description=f"Pattern '{pattern_name}' matched in environment variables.",
                    evidence=match.group(0)[:80] + "...",
                    command="env",
                    source_module=self.name,
                ))
        return findings

    def _check_shell_history(self, user_ctx: UserContext, shell: ShellCompat) -> list[Finding]:
        findings = []
        history_files = [
            os.path.join(user_ctx.home_dir, ".bash_history"),
            os.path.join(user_ctx.home_dir, ".zsh_history"),
            os.path.join(user_ctx.home_dir, ".sh_history"),
        ]
        for hist_file in history_files:
            content = shell.read_file(hist_file)
            if not content:
                continue
            for pattern_name, (pattern, sev) in _CRED_PATTERNS.items():
                match = pattern.search(content)
                if match:
                    findings.append(Finding(
                        title=f"Credential in shell history: {pattern_name}",
                        category=FindingCategory.CREDENTIAL,
                        severity=sev,
                        description=f"Pattern '{pattern_name}' found in {hist_file}.",
                        evidence=match.group(0)[:80],
                        affected_path=hist_file,
                        source_module=self.name,
                    ))
        return findings

    def _check_config_files(self, shell: ShellCompat) -> list[Finding]:
        findings = []
        result = shell.run(
            "find /home /var/www /opt /srv /etc/app -name '*.env' -o -name 'config.php' "
            "-o -name 'database.yml' -o -name 'settings.py' -o -name '.env' 2>/dev/null | head -30",
            timeout=20,
        )
        for cfg_file in result.stdout.splitlines():
            cfg_file = cfg_file.strip()
            content = shell.read_file(cfg_file)
            if not content:
                continue
            for pattern_name, (pattern, sev) in _CRED_PATTERNS.items():
                match = pattern.search(content)
                if match:
                    findings.append(Finding(
                        title=f"Credential in config file: {cfg_file}",
                        category=FindingCategory.CREDENTIAL,
                        severity=sev,
                        description=f"Pattern '{pattern_name}' found in {cfg_file}.",
                        evidence=match.group(0)[:80],
                        affected_path=cfg_file,
                        source_module=self.name,
                    ))
        return findings

    def _check_git_history(self, shell: ShellCompat) -> list[Finding]:
        """Search git log for accidentally committed credentials."""
        findings = []
        result = shell.run(
            "find /home /var/www /opt -name '.git' -type d 2>/dev/null | head -5",
            timeout=10,
        )
        for git_dir in result.stdout.splitlines():
            repo_dir = git_dir.replace("/.git", "")
            log_result = shell.run(
                f"git -C {repo_dir} log --all -p --since='1 year ago' 2>/dev/null | grep -E '(password|apikey|token|secret)\\s*=' | head -10",
                timeout=15,
            )
            if log_result.output:
                findings.append(Finding(
                    title=f"Credential pattern in git history: {repo_dir}",
                    category=FindingCategory.CREDENTIAL,
                    severity=Severity.HIGH,
                    description=f"Possible credentials found in git commit history of {repo_dir}.",
                    evidence=log_result.output[:200],
                    affected_path=repo_dir,
                    command=f"git -C {repo_dir} log --all -p",
                    source_module=self.name,
                ))
        return findings

    def _check_cloud_imds(self, sys_ctx: SystemContext, shell: ShellCompat) -> list[Finding]:
        """Retrieve cloud IAM role credentials from IMDS (read-only, no authentication required)."""
        findings = []
        from pip.models.context import CloudProvider
        if sys_ctx.cloud_provider == CloudProvider.AWS:
            result = shell.run(
                "curl -s --max-time 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null",
                timeout=5,
            )
            if result.output:
                findings.append(Finding(
                    title=f"AWS IAM role accessible via IMDS: {result.output.strip()}",
                    category=FindingCategory.CLOUD,
                    severity=Severity.CRITICAL,
                    description="AWS IMDSv1 is accessible without authentication. "
                                "IAM role credentials can be retrieved and used for privilege escalation.",
                    evidence=result.output[:200],
                    command="curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    source_module=self.name,
                ))
        return findings
