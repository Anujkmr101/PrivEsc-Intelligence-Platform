"""
pip/core/context_engine.py

Context Fingerprinting Engine.

Detects the full environment before any enumeration begins:
  - Bare metal / VM / Docker / Kubernetes / Cloud
  - Active security controls (SELinux, AppArmor, seccomp, auditd, EDR)
  - Cloud provider and IMDS availability
  - Shell type and restriction level
  - Current user context (uid, groups, sudo rules)

All subsequent modules consult the SystemContext to:
  - Skip irrelevant checks (e.g. skip IMDS checks on bare metal)
  - Adapt command selection to the shell type
  - Adjust stealth based on detected security controls
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Optional

from pip.models.context import (
    ScanConfig, SystemContext, UserContext, SecurityControls,
    EnvironmentType, ShellType, CloudProvider
)
from pip.core.shell_compat import ShellCompat


class ContextEngine:
    """
    Fingerprints the target environment.

    Call fingerprint() to get a (SystemContext, UserContext) tuple.
    This is always the first stage of any scan.
    """

    # Cloud provider IMDS endpoints
    _IMDS_ENDPOINTS = {
        CloudProvider.AWS:   "http://169.254.169.254/latest/meta-data/",
        CloudProvider.GCP:   "http://metadata.google.internal/computeMetadata/v1/",
        CloudProvider.AZURE: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    }

    def __init__(self, config: ScanConfig):
        self.config = config
        self._shell = ShellCompat(config)

    async def fingerprint(self) -> tuple[SystemContext, UserContext]:
        """
        Run all detection checks and return populated context objects.
        Non-blocking: uses asyncio-safe subprocess calls via ShellCompat.
        """
        sys_ctx = SystemContext()
        user_ctx = UserContext()

        self._detect_user(user_ctx)
        self._detect_os(sys_ctx)
        self._detect_kernel(sys_ctx)
        self._detect_environment_type(sys_ctx)
        self._detect_security_controls(sys_ctx)
        self._detect_shell(sys_ctx)
        self._detect_network(sys_ctx)
        self._detect_services(sys_ctx)

        if self.config.imds_check or self.config.cloud_hint:
            self._detect_cloud(sys_ctx)

        if sys_ctx.environment_type in (EnvironmentType.DOCKER, EnvironmentType.KUBERNETES):
            self._detect_container_specifics(sys_ctx)

        return sys_ctx, user_ctx

    # ── User detection ────────────────────────────────────────────────────────

    def _detect_user(self, ctx: UserContext) -> None:
        """Populate current user identity and sudo permissions."""
        import platform
        ctx.username = self._run("whoami").strip()

        # uid/gid are Linux-only — use safe fallbacks on Windows
        if hasattr(os, "getuid"):
            ctx.uid = os.getuid()
            ctx.gid = os.getgid()
        else:
            # Windows: no real uid concept; use 0 as placeholder
            ctx.uid = 0
            ctx.gid = 0

        ctx.home_dir = os.environ.get("HOME", os.environ.get("USERPROFILE", ""))
        ctx.shell    = os.environ.get("SHELL", os.environ.get("COMSPEC", ""))

        # Group membership — id works on Linux/WSL; skip on native Windows
        if platform.system() != "Windows":
            groups_out = self._run("id").strip()
            ctx.groups = re.findall(r"\((\w+)\)", groups_out)
        else:
            ctx.groups = []

        # Sudo rules only exist on Linux/macOS
        if platform.system() != "Windows":
            sudo_out = self._run("sudo -nl 2>/dev/null").strip()
            if "NOPASSWD" in sudo_out:
                ctx.sudo_nopasswd = True
                ctx.sudo_commands = re.findall(r"NOPASSWD:\s*(.+)", sudo_out)

        ctx.is_service_account = ctx.uid >= 1000 and ctx.username not in ("root",)

    # ── OS detection ──────────────────────────────────────────────────────────

    def _detect_os(self, ctx: SystemContext) -> None:
        """Detect OS name, version, hostname."""
        import platform
        ctx.hostname = self._run("hostname").strip() or platform.node()
        ctx.arch     = platform.machine() or self._run("uname -m").strip()

        if platform.system() == "Windows":
            ctx.os_name    = "Windows"
            ctx.os_version = platform.version()
            return

        os_release = self._read_file("/etc/os-release")
        if os_release:
            name_match = re.search(r'^NAME="?([^"\n]+)"?', os_release, re.MULTILINE)
            ver_match  = re.search(r'^VERSION_ID="?([^"\n]+)"?', os_release, re.MULTILINE)
            ctx.os_name    = name_match.group(1) if name_match else "Unknown"
            ctx.os_version = ver_match.group(1) if ver_match else ""
        else:
            ctx.os_name = self._run("cat /etc/issue 2>/dev/null | head -1").strip()

    # ── Kernel detection ──────────────────────────────────────────────────────

    def _detect_kernel(self, ctx: SystemContext) -> None:
        """Extract kernel version for exploit-suggester matching."""
        import platform
        if platform.system() == "Windows":
            ctx.kernel_full    = platform.version()
            ctx.kernel_version = platform.release()
            return
        ctx.kernel_full    = self._run("uname -r").strip()
        ctx.kernel_version = self._parse_kernel_version(ctx.kernel_full)

    @staticmethod
    def _parse_kernel_version(full: str) -> str:
        """Extract major.minor.patch from full kernel string."""
        match = re.match(r"(\d+\.\d+\.\d+)", full)
        return match.group(1) if match else full

    # ── Environment type detection ────────────────────────────────────────────

    def _detect_environment_type(self, ctx: SystemContext) -> None:
        """Distinguish bare metal, VM, Docker, K8s, or cloud instance."""
        import platform

        # On Windows: skip all Linux-specific checks
        if platform.system() == "Windows":
            ctx.environment_type = EnvironmentType.BARE_METAL
            return

        # Docker: check for .dockerenv or cgroup evidence
        if os.path.exists("/.dockerenv"):
            ctx.environment_type = EnvironmentType.DOCKER
            ctx.container_id = self._extract_container_id()
            return

        cgroups = self._read_file("/proc/1/cgroup") or ""
        if "docker" in cgroups or "containerd" in cgroups:
            ctx.environment_type = EnvironmentType.DOCKER
            ctx.container_id = self._extract_container_id()
            return

        # Kubernetes: service account token is the canonical indicator
        if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token"):
            ctx.environment_type = EnvironmentType.KUBERNETES
            ctx.k8s_service_account = True
            return

        # VM detection via DMI data
        dmi = self._run("dmidecode -t system 2>/dev/null | grep -i product").lower()
        if any(v in dmi for v in ("vmware", "virtualbox", "kvm", "xen", "hyper-v", "qemu")):
            ctx.environment_type = EnvironmentType.VM
            return

        # Detect cloud via IMDS reachability (fast timeout)
        if self.config.imds_check or self.config.cloud_hint:
            for provider, url in self._IMDS_ENDPOINTS.items():
                if self._imds_reachable(url):
                    ctx.environment_type = EnvironmentType.CLOUD
                    ctx.cloud_provider = provider
                    ctx.imds_accessible = True
                    return

        ctx.environment_type = EnvironmentType.BARE_METAL

    def _extract_container_id(self) -> str:
        cgroup = self._read_file("/proc/1/cgroup") or ""
        match = re.search(r"([a-f0-9]{64})", cgroup)
        return match.group(1)[:12] if match else ""

    def _imds_reachable(self, url: str) -> bool:
        """Quick connectivity check to cloud IMDS endpoint (1s timeout)."""
        try:
            import urllib.request
            req = urllib.request.Request(url)
            if "google" in url:
                req.add_header("Metadata-Flavor", "Google")
            elif "azure" in url:
                req.add_header("Metadata", "true")
            with urllib.request.urlopen(req, timeout=1):
                return True
        except Exception:
            return False

    # ── Security controls detection ───────────────────────────────────────────

    def _detect_security_controls(self, ctx: SystemContext) -> None:
        """Detect all active MAC frameworks and security daemons."""
        import platform
        sc = ctx.security_controls

        # All MAC frameworks are Linux-only
        if platform.system() == "Windows":
            # Windows Defender check via tasklist
            tasklist = self._run("tasklist 2>nul").lower()
            sc.defender_running = "msmpeng.exe" in tasklist
            return

        # SELinux
        sestatus = self._run("sestatus 2>/dev/null").lower()
        sc.selinux_enabled   = "enabled" in sestatus
        sc.selinux_enforcing = "enforcing" in sestatus

        # AppArmor
        aa_status = self._run("aa-status 2>/dev/null || cat /sys/kernel/security/apparmor/profiles 2>/dev/null")
        sc.apparmor_enabled = bool(aa_status.strip())

        # Seccomp
        seccomp = self._read_file("/proc/self/status") or ""
        sc.seccomp_enabled = "Seccomp:\t2" in seccomp

        # Auditd
        sc.auditd_running = self._process_running("auditd")

        # Common EDR / endpoint agents
        sc.crowdstrike_running = self._process_running("falcon-sensor")
        sc.defender_running    = self._process_running("mdatp")

    def _process_running(self, name: str) -> bool:
        import platform
        if platform.system() == "Windows":
            out = self._run(f"tasklist /FI \"IMAGENAME eq {name}.exe\" 2>nul")
            return name.lower() in out.lower()
        out = self._run(f"pgrep -x {name} 2>/dev/null").strip()
        return bool(out)

    # ── Shell detection ───────────────────────────────────────────────────────

    def _detect_shell(self, ctx: SystemContext) -> None:
        import platform
        if platform.system() == "Windows":
            ctx.shell_type = ShellType.UNKNOWN
            return

        shell_path = os.environ.get("SHELL", "")
        if "bash" in shell_path:
            ctx.shell_type = ShellType.BASH
        elif "zsh" in shell_path:
            ctx.shell_type = ShellType.ZSH
        elif "sh" in shell_path:
            ctx.shell_type = ShellType.SH
        else:
            ctx.shell_type = ShellType.UNKNOWN

        # Detect restricted shell
        test = self._run("cd / 2>&1; echo $?").strip()
        if "restricted" in test.lower() or (test != "0" and test):
            ctx.shell_type = ShellType.RESTRICTED

    # ── Network & services ────────────────────────────────────────────────────

    def _detect_network(self, ctx: SystemContext) -> None:
        import platform
        if platform.system() == "Windows":
            iface_out = self._run("ipconfig 2>nul")
            ctx.network_interfaces = re.findall(r"adapter (.+?):", iface_out)
        else:
            iface_out = self._run("ip -o link show 2>/dev/null || ifconfig -a 2>/dev/null")
            ctx.network_interfaces = re.findall(r"^\d+:\s+(\S+):", iface_out, re.MULTILINE)

    def _detect_services(self, ctx: SystemContext) -> None:
        import platform
        if platform.system() == "Windows":
            svc_out = self._run('sc query type= all state= running 2>nul')
            ctx.running_services = re.findall(r"SERVICE_NAME:\s+(\S+)", svc_out)
            ctx.cron_jobs = []  # No cron on Windows
            return

        svc_out = self._run("systemctl list-units --type=service --state=running --no-pager 2>/dev/null | awk '{print $1}'")
        ctx.running_services = [s.strip() for s in svc_out.splitlines() if s.strip().endswith(".service")]

        cron_out = self._run("crontab -l 2>/dev/null; cat /etc/cron* /var/spool/cron/crontabs/* 2>/dev/null")
        ctx.cron_jobs = [l for l in cron_out.splitlines() if l.strip() and not l.startswith("#")]

    # ── Container specifics ───────────────────────────────────────────────────

    def _detect_container_specifics(self, ctx: SystemContext) -> None:
        """Check for privileged container and exposed Docker socket."""
        import platform
        if platform.system() == "Windows":
            return

        ctx.docker_socket_exposed = os.path.exists("/var/run/docker.sock")

        cap_out = self._run("cat /proc/self/status 2>/dev/null | grep CapEff")
        match = re.search(r"CapEff:\s+([0-9a-f]+)", cap_out)
        if match:
            cap_eff = int(match.group(1), 16)
            CAP_SYS_ADMIN = 1 << 21
            ctx.is_privileged_container = bool(cap_eff & CAP_SYS_ADMIN)

    # ── Cloud specifics ───────────────────────────────────────────────────────

    def _detect_cloud(self, ctx: SystemContext) -> None:
        """Attempt to identify cloud provider from IMDS or system hints."""
        if ctx.cloud_provider:
            return  # Already set during environment type detection
        hint = self.config.cloud_hint
        if hint and self._imds_reachable(self._IMDS_ENDPOINTS.get(hint, "")):
            ctx.cloud_provider = hint
            ctx.environment_type = EnvironmentType.CLOUD
            ctx.imds_accessible = True

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _run(self, cmd: str) -> str:
        """Run a shell command safely; return stdout or empty string on error."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            return result.stdout
        except Exception:
            return ""

    @staticmethod
    def _read_file(path: str) -> Optional[str]:
        try:
            with open(path, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return None