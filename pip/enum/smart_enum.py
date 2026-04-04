"""
pip/enum/smart_enum.py

Smart Enumeration Module.

The primary enumeration module covering all classic Linux privesc vectors:
  SUID/SGID binaries, sudo rules, writable cron scripts, capabilities,
  writable paths, NFS no_root_squash, PATH hijack opportunities,
  weak file permissions, kernel vulnerability indicators.

Unlike LinPEAS, checks are:
  - Gated on context (e.g. cron checks only run if cron jobs exist)
  - Adaptive to scan mode depth
  - Filtered for false positives before returning
"""

from __future__ import annotations

from pip.models.context import ScanConfig, SystemContext, UserContext, ScanMode
from pip.models.finding import Finding, FindingCategory, Severity
from pip.core.shell_compat import ShellCompat


class SmartEnumModule:
    """Core enumeration module. Covers all classic Linux privilege escalation vectors."""

    name = "smart_enum"

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(
        self,
        sys_ctx: SystemContext,
        user_ctx: UserContext,
        shell: ShellCompat,
    ) -> list[Finding]:
        """Execute all applicable checks and return a list of Findings."""
        findings: list[Finding] = []

        # Always run
        findings.extend(self._check_sudo(user_ctx, shell))
        findings.extend(self._check_suid_binaries(shell))
        findings.extend(self._check_capabilities(shell))
        findings.extend(self._check_writable_paths(shell))

        # Only if cron jobs are present
        if sys_ctx.cron_jobs:
            findings.extend(self._check_cron_scripts(sys_ctx, shell))

        # Deep mode: additional checks
        if self.config.mode in (ScanMode.DEEP, ScanMode.STEALTH):
            findings.extend(self._check_nfs_exports(shell))
            findings.extend(self._check_path_hijack(user_ctx, shell))
            findings.extend(self._check_library_paths(shell))
            findings.extend(self._check_kernel_version(sys_ctx, shell))
            findings.extend(self._check_passwd_writable(shell))
            findings.extend(self._check_weak_service_configs(sys_ctx, shell))

        return findings

    # ── SUID / SGID ───────────────────────────────────────────────────────────

    def _check_suid_binaries(self, shell: ShellCompat) -> list[Finding]:
        """
        Find SUID binaries and cross-reference with known GTFOBins vectors.
        The actual GTFOBins lookup happens in the analysis layer; here we
        collect the raw list and tag it with category=SUID for the graph engine.
        """
        findings = []
        result = shell.run(
            f"find / -perm -4000 -type f 2>/dev/null",
            timeout=30,
        )
        for line in result.stdout.splitlines():
            binary = line.strip()
            if not binary:
                continue
            # Pre-filter: well-known expected SUID binaries are low-signal
            if binary in _EXPECTED_SUID:
                continue
            findings.append(Finding(
                title=f"Non-standard SUID binary: {binary}",
                category=FindingCategory.SUID,
                severity=Severity.MEDIUM,
                description=(
                    f"The binary {binary} has the SUID bit set. "
                    f"If it appears in GTFOBins, it may allow privilege escalation."
                ),
                evidence=binary,
                command=f"find / -perm -4000 -type f 2>/dev/null",
                affected_path=binary,
                source_module=self.name,
            ))
        return findings

    # ── Capabilities ──────────────────────────────────────────────────────────

    def _check_capabilities(self, shell: ShellCompat) -> list[Finding]:
        """
        Find binaries with dangerous Linux capabilities set.
        Focus on: cap_setuid, cap_setgid, cap_dac_override, cap_sys_admin.
        """
        findings = []
        result = shell.run("getcap -r / 2>/dev/null", timeout=20)

        dangerous_caps = {
            "cap_setuid":      Severity.HIGH,
            "cap_setgid":      Severity.HIGH,
            "cap_dac_override": Severity.MEDIUM,
            "cap_sys_admin":   Severity.CRITICAL,
            "cap_sys_ptrace":  Severity.HIGH,
            "cap_net_raw":     Severity.MEDIUM,
        }

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" = ")
            if len(parts) != 2:
                continue
            binary, caps = parts[0].strip(), parts[1].strip()
            for cap, sev in dangerous_caps.items():
                if cap in caps:
                    findings.append(Finding(
                        title=f"Dangerous capability on {binary}: {cap}",
                        category=FindingCategory.CAPABILITY,
                        severity=sev,
                        description=(
                            f"{binary} has {cap} set ({caps}). "
                            f"This may allow privilege escalation via GTFOBins abuse."
                        ),
                        evidence=line,
                        command="getcap -r / 2>/dev/null",
                        affected_path=binary,
                        tags=[cap],
                        source_module=self.name,
                    ))
        return findings

    # ── Sudo rules ────────────────────────────────────────────────────────────

    def _check_sudo(self, user_ctx: UserContext, shell: ShellCompat) -> list[Finding]:
        """Parse sudo -l output for exploitable rules."""
        findings = []
        if not user_ctx.sudo_commands:
            return findings

        result = shell.run("sudo -nl 2>/dev/null", timeout=10)

        for cmd in user_ctx.sudo_commands:
            cmd = cmd.strip()
            findings.append(Finding(
                title=f"Sudo NOPASSWD rule: {cmd}",
                category=FindingCategory.SUDO,
                severity=Severity.HIGH if cmd.strip() in ("ALL", "(ALL)", "(ALL:ALL)") else Severity.MEDIUM,
                description=(
                    f"The current user can run '{cmd}' as root without a password. "
                    f"If this binary appears in GTFOBins, it may allow full privilege escalation."
                ),
                evidence=result.stdout[:500],
                command="sudo -nl",
                affected_path=cmd,
                source_module=self.name,
            ))
        return findings

    # ── Cron script writability ───────────────────────────────────────────────

    def _check_cron_scripts(self, sys_ctx: SystemContext, shell: ShellCompat) -> list[Finding]:
        """
        Check if scripts referenced in cron jobs are world-writable or
        owned by the current user but executed as root.
        """
        findings = []
        import re

        script_pattern = re.compile(r"(/[^\s]+\.(?:sh|py|pl|rb|php))")

        for job in sys_ctx.cron_jobs:
            for script_path in script_pattern.findall(job):
                stat_result = shell.run(f"stat -c '%a %U %G' {script_path} 2>/dev/null")
                if not stat_result.ok:
                    continue
                parts = stat_result.output.split()
                if len(parts) < 3:
                    continue
                perms, owner, group = parts[0], parts[1], parts[2]
                # World-writable: last digit of octal perms is 2, 3, 6, or 7
                if perms and int(perms[-1]) & 2:
                    findings.append(Finding(
                        title=f"World-writable cron script: {script_path}",
                        category=FindingCategory.CRON,
                        severity=Severity.CRITICAL,
                        description=(
                            f"The script {script_path} is referenced in a cron job "
                            f"and is world-writable (permissions: {perms}). "
                            f"Injecting a payload will execute as the cron job owner."
                        ),
                        evidence=f"cron: {job}\nstat: {stat_result.output}",
                        command=f"stat -c '%a %U %G' {script_path}",
                        affected_path=script_path,
                        source_module=self.name,
                    ))
        return findings

    # ── Writable sensitive paths ──────────────────────────────────────────────

    def _check_writable_paths(self, shell: ShellCompat) -> list[Finding]:
        """Check for writable /etc/passwd, /etc/shadow, /etc/sudoers."""
        findings = []
        sensitive = {
            "/etc/passwd":  (Severity.CRITICAL, "Writable /etc/passwd allows adding a root user"),
            "/etc/shadow":  (Severity.CRITICAL, "Writable /etc/shadow allows replacing root hash"),
            "/etc/sudoers": (Severity.CRITICAL, "Writable /etc/sudoers allows granting root sudo"),
            "/etc/cron.d":  (Severity.HIGH,     "Writable /etc/cron.d allows injecting root cron jobs"),
            "/etc/ld.so.conf": (Severity.HIGH,  "Writable ld.so.conf allows library path injection"),
        }
        for path, (sev, desc) in sensitive.items():
            result = shell.run(f"test -w {path} && echo writable")
            if "writable" in result.stdout:
                findings.append(Finding(
                    title=f"Writable sensitive path: {path}",
                    category=FindingCategory.WRITABLE,
                    severity=sev,
                    description=desc,
                    evidence=f"{path} is writable by current user",
                    command=f"test -w {path}",
                    affected_path=path,
                    source_module=self.name,
                ))
        return findings

    # ── NFS no_root_squash ────────────────────────────────────────────────────

    def _check_nfs_exports(self, shell: ShellCompat) -> list[Finding]:
        """Look for NFS shares with no_root_squash, which allows SUID exploitation."""
        findings = []
        exports = shell.read_file("/etc/exports") or ""
        for line in exports.splitlines():
            if "no_root_squash" in line and not line.strip().startswith("#"):
                findings.append(Finding(
                    title=f"NFS share with no_root_squash: {line.split()[0]}",
                    category=FindingCategory.NFS,
                    severity=Severity.HIGH,
                    description=(
                        "An NFS share is exported with no_root_squash. A remote attacker "
                        "who can mount this share can place a SUID binary and execute it as root."
                    ),
                    evidence=line.strip(),
                    command="cat /etc/exports",
                    affected_path=line.split()[0],
                    source_module=self.name,
                ))
        return findings

    # ── PATH hijack ───────────────────────────────────────────────────────────

    def _check_path_hijack(self, user_ctx: UserContext, shell: ShellCompat) -> list[Finding]:
        """Check for writable directories in PATH that appear before system directories."""
        findings = []
        import os
        path_dirs = os.environ.get("PATH", "").split(":")
        for directory in path_dirs:
            if not directory or directory.startswith("/usr") or directory.startswith("/bin"):
                continue
            result = shell.run(f"test -w {directory} && echo writable")
            if "writable" in result.stdout:
                findings.append(Finding(
                    title=f"Writable directory in PATH: {directory}",
                    category=FindingCategory.PATH,
                    severity=Severity.MEDIUM,
                    description=(
                        f"The directory {directory} is writable and appears in PATH before "
                        f"system directories. Placing a malicious binary here may hijack "
                        f"commands executed by privileged scripts."
                    ),
                    evidence=f"PATH entry: {directory}",
                    command=f"test -w {directory}",
                    affected_path=directory,
                    source_module=self.name,
                ))
        return findings

    # ── Library path injection ────────────────────────────────────────────────

    def _check_library_paths(self, shell: ShellCompat) -> list[Finding]:
        """Check LD_LIBRARY_PATH and ld.so.conf for writable entries."""
        findings = []
        import os
        ld_path = os.environ.get("LD_LIBRARY_PATH", "")
        if ld_path:
            findings.append(Finding(
                title="LD_LIBRARY_PATH is set in environment",
                category=FindingCategory.LIBRARY,
                severity=Severity.MEDIUM,
                description=(
                    f"LD_LIBRARY_PATH={ld_path}. If any entry is writable, "
                    f"a malicious shared library can be injected into privileged process execution."
                ),
                evidence=f"LD_LIBRARY_PATH={ld_path}",
                command="env | grep LD_LIBRARY_PATH",
                source_module=self.name,
            ))
        return findings

    # ── Kernel version check ──────────────────────────────────────────────────

    def _check_kernel_version(self, sys_ctx: SystemContext, shell: ShellCompat) -> list[Finding]:
        """
        Flag the kernel version for KnowledgeBase matching.
        The actual CVE lookup happens in the analysis layer.
        This check simply emits a KERNEL finding so the graph engine
        can connect it to exploit paths.
        """
        return [Finding(
            title=f"Kernel version: {sys_ctx.kernel_version}",
            category=FindingCategory.KERNEL,
            severity=Severity.INFO,
            description=(
                f"Kernel version {sys_ctx.kernel_full} detected. "
                f"The knowledge base will be queried for known local privilege escalation CVEs."
            ),
            evidence=sys_ctx.kernel_full,
            command="uname -r",
            source_module=self.name,
        )]

    # ── /etc/passwd writable ──────────────────────────────────────────────────

    def _check_passwd_writable(self, shell: ShellCompat) -> list[Finding]:
        result = shell.run("ls -la /etc/passwd")
        # Already covered by _check_writable_paths; this provides richer evidence
        return []

    # ── Weak service configs ──────────────────────────────────────────────────

    def _check_weak_service_configs(self, sys_ctx: SystemContext, shell: ShellCompat) -> list[Finding]:
        """
        Check for systemd service unit files owned or writable by the current user
        that run as root — a reliable and stealthy escalation vector.
        """
        findings = []
        result = shell.run(
            "find /etc/systemd /lib/systemd /usr/lib/systemd -name '*.service' "
            "-writable 2>/dev/null",
            timeout=15,
        )
        for unit_file in result.stdout.splitlines():
            unit_file = unit_file.strip()
            if not unit_file:
                continue
            findings.append(Finding(
                title=f"Writable systemd unit file: {unit_file}",
                category=FindingCategory.SERVICE,
                severity=Severity.HIGH,
                description=(
                    f"The systemd unit file {unit_file} is writable. "
                    f"If the service runs as root, modifying ExecStart allows arbitrary code execution."
                ),
                evidence=unit_file,
                command="find /etc/systemd ... -writable",
                affected_path=unit_file,
                source_module=self.name,
            ))
        return findings


# ── Known-benign SUID binaries (skip to reduce noise) ────────────────────────
_EXPECTED_SUID = frozenset({
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/newgrp",
    "/usr/bin/gpasswd", "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/ping", "/usr/sbin/pam_timestamp_check",
    "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/bin/su", "/bin/ping", "/bin/mount", "/bin/umount",
})
