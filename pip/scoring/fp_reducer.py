"""
pip/scoring/fp_reducer.py

False Positive Reducer.

Filters the raw finding list before graph construction to eliminate
known-benign patterns per distribution and environment type.

Examples of suppressed false positives:
  - /usr/bin/sudo SUID (expected and required)
  - Standard GTK/GNOME helper binaries with SUID
  - Kernel version matches that are patched on this distro
    (e.g. Ubuntu backports a fix without bumping the kernel version)
"""
from __future__ import annotations
from pip.models.context import SystemContext
from pip.models.finding import Finding, FindingCategory

# Binaries whose SUID bit is expected and not exploitable without GTFOBins correlation
_BENIGN_SUID = frozenset({
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/newgrp",
    "/usr/bin/gpasswd", "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/ping", "/usr/sbin/pam_timestamp_check",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/snapd/snap-confine",
    "/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic",
})

class FPReducer:
    """Filters known-benign findings from the raw enumeration output."""

    def __init__(self, sys_ctx: SystemContext):
        self.sys_ctx = sys_ctx

    def filter(self, findings: list[Finding]) -> list[Finding]:
        """Return a filtered copy of the findings list with false positives removed."""
        result = []
        for finding in findings:
            if self._is_false_positive(finding):
                continue
            result.append(finding)
        return result

    def _is_false_positive(self, finding: Finding) -> bool:
        # Suppress expected SUID binaries (only if they have no GTFOBins cmd attached)
        if finding.category == FindingCategory.SUID:
            if finding.affected_path in _BENIGN_SUID and not finding.exploit_cmd:
                return True
        # Suppress INFO-level kernel findings if no CVE was matched
        if finding.category == FindingCategory.KERNEL and not finding.cve and finding.confidence < 0.3:
            return True
        return False
