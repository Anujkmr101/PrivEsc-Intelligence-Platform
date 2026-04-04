"""
pip/core/stealth_engine.py

Stealth Profile Engine.

Controls the noise level of every command executed during a scan.
Modules call StealthEngine before executing commands to:
  - Check if a command is safe to run under the current profile
  - Get a throttle delay between commands
  - Decide whether to write any artifacts to disk
"""

from __future__ import annotations

import time
from typing import Optional

from pip.models.context import ScanConfig, StealthProfile, SystemContext


# Commands known to be logged by auditd, trigger Falco rules, or be
# flagged by common EDR signatures. Suppressed in SILENT mode.
_NOISY_COMMANDS = frozenset({
    "dmesg", "last", "lastlog", "find / -perm", "find / -writable",
    "lsof", "strace", "ltrace", "tcpdump", "wireshark",
    "nc -e", "ncat", "curl.*|sh", "wget.*|sh",
    "python3 -c.*socket", "perl.*socket", "ruby.*socket",
    "crontab -e", "at ", "batch ",
})


class StealthEngine:
    """
    Manages scan noise level.

    Profiles:
        SILENT     — memory-only, minimal commands, throttled execution.
                     Skips all commands in _NOISY_COMMANDS.
        NORMAL     — balanced. Throttles heavy commands only.
        AGGRESSIVE — maximum coverage. No suppression.
    """

    # Inter-command delay ranges (min, max) seconds per profile
    _DELAYS = {
        StealthProfile.SILENT:     (0.5, 2.0),
        StealthProfile.NORMAL:     (0.05, 0.3),
        StealthProfile.AGGRESSIVE: (0.0, 0.0),
    }

    def __init__(self, config: ScanConfig):
        self.config = config
        self.profile = config.stealth
        self._system_ctx: Optional[SystemContext] = None
        self._command_count = 0

    def configure(self, ctx: SystemContext) -> None:
        """
        Adjust stealth profile based on detected security controls.
        If auditd or an EDR agent is detected, automatically tighten the profile.
        """
        self._system_ctx = ctx
        sc = ctx.security_controls

        if sc.crowdstrike_running or sc.defender_running:
            if self.profile == StealthProfile.AGGRESSIVE:
                self.profile = StealthProfile.NORMAL  # Auto-downgrade

        if sc.auditd_running and self.profile == StealthProfile.AGGRESSIVE:
            self.profile = StealthProfile.NORMAL

    def is_command_allowed(self, cmd: str) -> bool:
        """Return False if this command should be suppressed under the current profile."""
        if self.profile == StealthProfile.AGGRESSIVE:
            return True
        if self.profile == StealthProfile.SILENT:
            return not any(noisy in cmd for noisy in _NOISY_COMMANDS)
        # NORMAL: allow most, suppress obviously dangerous commands
        return not any(noisy in cmd for noisy in {"tcpdump", "wireshark", "strace"})

    def throttle(self) -> None:
        """Sleep between commands according to the current stealth profile."""
        import random
        lo, hi = self._DELAYS[self.profile]
        if hi > 0:
            time.sleep(random.uniform(lo, hi))
        self._command_count += 1

    @property
    def no_disk(self) -> bool:
        """True if the scan should avoid writing anything to the target filesystem."""
        return self.config.no_disk or self.profile == StealthProfile.SILENT

    @property
    def max_find_depth(self) -> int:
        """Depth limit for filesystem searches to avoid triggering anomaly detection."""
        depths = {
            StealthProfile.SILENT:     3,
            StealthProfile.NORMAL:     5,
            StealthProfile.AGGRESSIVE: 10,
        }
        return depths[self.profile]
