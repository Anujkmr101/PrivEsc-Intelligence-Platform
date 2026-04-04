"""
pip/models/context.py

Environment context model and scan configuration enums.
Populated by ContextEngine; consumed by all downstream modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


# ── Enums ────────────────────────────────────────────────────────────────────

class ScanMode(str, Enum):
    QUICK = "quick"
    DEEP = "deep"
    AUDIT = "audit"
    STEALTH = "stealth"


class StealthProfile(str, Enum):
    SILENT = "silent"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


class ReportType(str, Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    BLUE_TEAM = "blue-team"
    ALL = "all"


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class EnvironmentType(str, Enum):
    BARE_METAL = "bare_metal"
    VM = "vm"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    CLOUD = "cloud"
    UNKNOWN = "unknown"


class ShellType(str, Enum):
    BASH = "bash"
    SH = "sh"
    ZSH = "zsh"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


# ── Context model ─────────────────────────────────────────────────────────────

@dataclass
class SecurityControls:
    """Active security controls detected on the target."""
    selinux_enabled: bool = False
    selinux_enforcing: bool = False
    apparmor_enabled: bool = False
    seccomp_enabled: bool = False
    auditd_running: bool = False
    fail2ban_running: bool = False
    crowdstrike_running: bool = False
    defender_running: bool = False


@dataclass
class UserContext:
    """Information about the current user session."""
    username: str = ""
    uid: int = -1
    gid: int = -1
    groups: list[str] = field(default_factory=list)
    home_dir: str = ""
    shell: str = ""
    sudo_nopasswd: bool = False
    sudo_commands: list[str] = field(default_factory=list)
    is_service_account: bool = False


@dataclass
class SystemContext:
    """Detected system and environment properties."""
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    kernel_version: str = ""
    kernel_full: str = ""
    arch: str = ""
    environment_type: EnvironmentType = EnvironmentType.UNKNOWN
    cloud_provider: Optional[CloudProvider] = None
    container_id: str = ""
    is_privileged_container: bool = False
    docker_socket_exposed: bool = False
    k8s_service_account: bool = False
    imds_accessible: bool = False
    shell_type: ShellType = ShellType.UNKNOWN
    security_controls: SecurityControls = field(default_factory=SecurityControls)
    installed_packages: dict[str, str] = field(default_factory=dict)   # pkg -> version
    running_services: list[str] = field(default_factory=list)
    network_interfaces: list[str] = field(default_factory=list)
    cron_jobs: list[str] = field(default_factory=list)


@dataclass
class ScanConfig:
    """
    Immutable scan configuration passed to the orchestrator and all modules.
    Built from CLI arguments at startup.
    """
    mode: ScanMode = ScanMode.DEEP
    stealth: StealthProfile = StealthProfile.NORMAL
    report_types: list[ReportType] = field(default_factory=lambda: [ReportType.ALL])
    exploit_enabled: bool = False
    confirm_each: bool = False
    mitre_map: bool = True
    blue_team: bool = False
    cis_level: int = 1
    cloud_hint: Optional[CloudProvider] = None
    imds_check: bool = False
    output_dir: Path = field(default_factory=lambda: Path("./pip-output"))
    output_format: str = "json"
    no_disk: bool = False
    timeout: int = 300
    verbose: bool = False

    @property
    def is_audit_only(self) -> bool:
        return self.mode == ScanMode.AUDIT

    @property
    def generates_executive_report(self) -> bool:
        return ReportType.ALL in self.report_types or ReportType.EXECUTIVE in self.report_types

    @property
    def generates_blue_team_report(self) -> bool:
        return (
            self.blue_team
            or ReportType.ALL in self.report_types
            or ReportType.BLUE_TEAM in self.report_types
        )
