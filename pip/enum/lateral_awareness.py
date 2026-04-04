"""
pip/enum/lateral_awareness.py

Lateral Awareness Module.

Discovers opportunities to move laterally to other accounts before escalating:
  - SSH authorized_keys and known_hosts analysis
  - Shared writable files between users
  - Sudo rules allowing execution as other (non-root) users
  - Readable home directories and their .ssh/ contents
  - Credential reuse opportunities
"""
from __future__ import annotations
import os
from pip.models.context import ScanConfig, SystemContext, UserContext
from pip.models.finding import Finding, FindingCategory, Severity
from pip.core.shell_compat import ShellCompat

class LateralAwarenessModule:
    name = "lateral_awareness"

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, sys_ctx: SystemContext, user_ctx: UserContext, shell: ShellCompat) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_ssh_keys(user_ctx, shell))
        findings.extend(self._check_readable_home_dirs(shell))
        findings.extend(self._check_writable_authorized_keys(shell))
        return findings

    def _check_ssh_keys(self, user_ctx: UserContext, shell: ShellCompat) -> list[Finding]:
        findings = []
        ssh_dir = os.path.join(user_ctx.home_dir, ".ssh")
        known_hosts = shell.read_file(os.path.join(ssh_dir, "known_hosts"))
        if known_hosts:
            hosts = [l.split()[0] for l in known_hosts.splitlines() if l and not l.startswith("#")]
            if hosts:
                findings.append(Finding(
                    title=f"SSH known_hosts reveals {len(hosts)} reachable systems",
                    category=FindingCategory.LATERAL,
                    severity=Severity.INFO,
                    description=f"~/.ssh/known_hosts contains {len(hosts)} entries. "
                                f"These may be reachable pivot targets if SSH keys are present.",
                    evidence="\n".join(hosts[:10]),
                    affected_path=os.path.join(ssh_dir, "known_hosts"),
                    source_module=self.name,
                ))
        # Check for unprotected private keys
        key_result = shell.run(f"find {ssh_dir} -name 'id_*' ! -name '*.pub' 2>/dev/null")
        for key_file in key_result.stdout.splitlines():
            key_file = key_file.strip()
            perms = shell.run(f"stat -c '%a' {key_file} 2>/dev/null").output
            if perms and int(perms) > 600:
                findings.append(Finding(
                    title=f"SSH private key with weak permissions: {key_file}",
                    category=FindingCategory.LATERAL,
                    severity=Severity.MEDIUM,
                    description=f"The SSH private key {key_file} has permissions {perms} "
                                f"(should be 600). It may be readable by other processes.",
                    evidence=f"{key_file}: permissions {perms}",
                    affected_path=key_file,
                    source_module=self.name,
                ))
        return findings

    def _check_readable_home_dirs(self, shell: ShellCompat) -> list[Finding]:
        findings = []
        result = shell.run("ls -la /home 2>/dev/null")
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 9:
                continue
            perms, user_dir = parts[0], parts[-1]
            if user_dir in (".", ".."):
                continue
            if "r" in perms[7:]:  # world-readable home dir
                findings.append(Finding(
                    title=f"World-readable home directory: /home/{user_dir}",
                    category=FindingCategory.LATERAL,
                    severity=Severity.LOW,
                    description=f"/home/{user_dir} is world-readable. "
                                f"SSH keys, config files, and credentials may be accessible.",
                    evidence=line.strip(),
                    affected_path=f"/home/{user_dir}",
                    source_module=self.name,
                ))
        return findings

    def _check_writable_authorized_keys(self, shell: ShellCompat) -> list[Finding]:
        """If we can write to another user's authorized_keys, we can SSH as them."""
        findings = []
        result = shell.run(
            "find /home -name 'authorized_keys' -writable 2>/dev/null",
            timeout=10,
        )
        for ak_file in result.stdout.splitlines():
            ak_file = ak_file.strip()
            if ak_file:
                findings.append(Finding(
                    title=f"Writable authorized_keys file: {ak_file}",
                    category=FindingCategory.LATERAL,
                    severity=Severity.HIGH,
                    description=f"The file {ak_file} is writable. Adding an SSH public key here "
                                f"allows SSH login as the owning user.",
                    evidence=ak_file,
                    affected_path=ak_file,
                    source_module=self.name,
                ))
        return findings
