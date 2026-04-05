"""
pip/core/shell_compat.py

Shell Compatibility Layer.

Ensures commands work across bash, sh, zsh, and restricted shells.
Every enumeration module calls shell.run() rather than subprocess directly,
so stealth throttling and command filtering are automatically applied.
"""

from __future__ import annotations

import subprocess
import shlex
from typing import Optional

from pip.models.context import ScanConfig, SystemContext, ShellType
from pip.core.stealth_engine import StealthEngine


class ShellCompat:
    """
    Safe command execution wrapper.

    Handles:
      - Stealth throttling and noise filtering via StealthEngine.
      - Fallback command variants for restricted shells.
      - Timeout enforcement.
      - Capture of stdout, stderr, and exit code.
    """

    # Alternative commands for environments where the primary is unavailable.
    # Keys are canonical command names; values are fallback chains.
    _FALLBACKS: dict[str, list[str]] = {
        "find":     ["find", "/usr/bin/find"],
        "python3":  ["python3", "python", "/usr/bin/python3"],
        "curl":     ["curl", "wget -qO-"],
        "id":       ["id", "/usr/bin/id", "whoami"],
        "ss":       ["ss", "netstat", "cat /proc/net/tcp"],
        "ip":       ["ip", "ifconfig"],
        "systemctl":["systemctl", "service --status-all 2>/dev/null"],
    }

    def __init__(self, config: ScanConfig):
        self.config = config
        self.stealth: Optional[StealthEngine] = None
        self._shell_type: ShellType = ShellType.UNKNOWN
        self._restricted: bool = False

    def configure(self, ctx: SystemContext) -> None:
        self._shell_type = ctx.shell_type
        self._restricted = ctx.shell_type == ShellType.RESTRICTED

    def run(self, cmd: str, timeout: int = 15, allow_noisy: bool = False) -> CommandResult:
        """
        Execute a shell command safely and return a CommandResult.

        Args:
            cmd:          The shell command to run.
            timeout:      Per-command timeout in seconds.
            allow_noisy:  If True, bypasses stealth noise filtering (use sparingly).

        Returns:
            CommandResult with stdout, stderr, exit_code.
        """
        if self.stealth and not allow_noisy:
            if not self.stealth.is_command_allowed(cmd):
                return CommandResult(stdout="", stderr="suppressed by stealth profile", exit_code=-1, suppressed=True)
            self.stealth.throttle()

        try:
            import platform
            kwargs: dict = dict(shell=True, capture_output=True, text=True, timeout=timeout)
            if platform.system() != "Windows":
                kwargs["executable"] = (
                    "/bin/sh" if self._restricted else "/bin/bash"
                )
            result = subprocess.run(cmd, **kwargs)
            return CommandResult(
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(stdout="", stderr=f"command timed out after {timeout}s", exit_code=-1)
        except Exception as e:
            return CommandResult(stdout="", stderr=str(e), exit_code=-1)

    def read_file(self, path: str) -> Optional[str]:
        """Read a file directly if accessible; returns None on permission error."""
        try:
            with open(path, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    def which(self, binary: str) -> Optional[str]:
        """Locate a binary on PATH; returns full path or None."""
        result = self.run(f"which {shlex.quote(binary)} 2>/dev/null")
        path = result.stdout.strip()
        return path if path else None

    def binary_exists(self, binary: str) -> bool:
        return self.which(binary) is not None

    def resolve_command(self, canonical: str) -> str:
        """
        Return the first working variant from the fallback chain for a canonical command name.
        Falls back to the canonical name itself if no alternatives found.
        """
        for variant in self._FALLBACKS.get(canonical, [canonical]):
            base = variant.split()[0]
            if self.binary_exists(base):
                return variant
        return canonical


class CommandResult:
    """Result of a ShellCompat.run() call."""

    def __init__(self, stdout: str, stderr: str, exit_code: int, suppressed: bool = False):
        self.stdout    = stdout
        self.stderr    = stderr
        self.exit_code = exit_code
        self.suppressed = suppressed

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def output(self) -> str:
        """Convenience: return stdout stripped."""
        return self.stdout.strip()

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        return f"<CommandResult exit={self.exit_code} stdout={self.stdout[:60]!r}>"