"""
tests/test_core.py

Unit tests for the core engine components:
  - ShellCompat command execution and result handling
  - StealthEngine noise control and EDR-aware profile adjustment
"""

import pytest
from unittest.mock import patch, MagicMock

from pip.models.context import (
    ScanConfig, ScanMode, StealthProfile, SystemContext,
    SecurityControls, ShellType, EnvironmentType
)
from pip.core.shell_compat import ShellCompat, CommandResult
from pip.core.stealth_engine import StealthEngine


# ── CommandResult tests ───────────────────────────────────────────────────────

class TestCommandResult:
    def test_ok_true_when_exit_zero(self):
        r = CommandResult(stdout="hello", stderr="", exit_code=0)
        assert r.ok is True
        assert bool(r) is True

    def test_ok_false_when_nonzero(self):
        r = CommandResult(stdout="", stderr="error", exit_code=1)
        assert r.ok is False
        assert bool(r) is False

    def test_output_strips_whitespace(self):
        r = CommandResult(stdout="  hello world\n", stderr="", exit_code=0)
        assert r.output == "hello world"

    def test_suppressed_flag(self):
        r = CommandResult(stdout="", stderr="suppressed by stealth profile", exit_code=-1, suppressed=True)
        assert r.suppressed is True
        assert r.ok is False


# ── ShellCompat tests ─────────────────────────────────────────────────────────

class TestShellCompat:
    def _make_shell(self, stealth_profile: StealthProfile = StealthProfile.NORMAL) -> ShellCompat:
        config = ScanConfig(stealth=stealth_profile)
        shell = ShellCompat(config)
        ctx = SystemContext()
        ctx.shell_type = ShellType.BASH
        shell.configure(ctx)
        return shell

    def test_run_echo_returns_output(self):
        shell = self._make_shell()
        result = shell.run("echo hello")
        assert result.ok
        assert "hello" in result.output

    def test_run_failing_command(self):
        shell = self._make_shell()
        result = shell.run("false")
        assert not result.ok
        assert result.exit_code != 0

    def test_run_with_timeout(self):
        shell = self._make_shell()
        # Sleep for 5s with a 1s timeout should return a timeout error
        result = shell.run("sleep 5", timeout=1)
        assert not result.ok
        assert "timed out" in result.stderr

    def test_read_file_existing(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("file content")
        shell = self._make_shell()
        content = shell.read_file(str(f))
        assert content == "file content"

    def test_read_file_nonexistent_returns_none(self):
        shell = self._make_shell()
        result = shell.read_file("/nonexistent/path/file.txt")
        assert result is None

    def test_which_existing_binary(self):
        shell = self._make_shell()
        path = shell.which("bash")
        assert path is not None
        assert "bash" in path

    def test_which_nonexistent_binary(self):
        shell = self._make_shell()
        path = shell.which("definitely_not_a_real_binary_xyz123")
        assert path is None

    def test_binary_exists(self):
        shell = self._make_shell()
        assert shell.binary_exists("bash") is True
        assert shell.binary_exists("definitely_not_real_xyz123") is False


# ── StealthEngine tests ────────────────────────────────────────────────────────

class TestStealthEngine:
    def _make_engine(self, profile: StealthProfile, **security_kwargs) -> StealthEngine:
        config = ScanConfig(stealth=profile)
        engine = StealthEngine(config)
        ctx = SystemContext()
        for k, v in security_kwargs.items():
            setattr(ctx.security_controls, k, v)
        engine.configure(ctx)
        return engine

    def test_aggressive_allows_all_commands(self):
        engine = self._make_engine(StealthProfile.AGGRESSIVE)
        assert engine.is_command_allowed("tcpdump -i eth0") is True
        assert engine.is_command_allowed("strace -p 1234") is True
        assert engine.is_command_allowed("find / -perm -4000") is True

    def test_silent_blocks_noisy_commands(self):
        engine = self._make_engine(StealthProfile.SILENT)
        assert engine.is_command_allowed("tcpdump -i eth0") is False
        assert engine.is_command_allowed("strace -p 1234") is False
        assert engine.is_command_allowed("wireshark") is False

    def test_silent_allows_safe_commands(self):
        engine = self._make_engine(StealthProfile.SILENT)
        assert engine.is_command_allowed("id") is True
        assert engine.is_command_allowed("ls -la /etc") is True
        assert engine.is_command_allowed("cat /etc/passwd") is True

    def test_crowdstrike_downgrades_aggressive_to_normal(self):
        engine = self._make_engine(StealthProfile.AGGRESSIVE, crowdstrike_running=True)
        assert engine.profile == StealthProfile.NORMAL

    def test_crowdstrike_does_not_affect_silent(self):
        engine = self._make_engine(StealthProfile.SILENT, crowdstrike_running=True)
        assert engine.profile == StealthProfile.SILENT

    def test_no_disk_true_in_silent_mode(self):
        engine = self._make_engine(StealthProfile.SILENT)
        assert engine.no_disk is True

    def test_no_disk_false_in_normal_mode(self):
        config = ScanConfig(stealth=StealthProfile.NORMAL, no_disk=False)
        engine = StealthEngine(config)
        ctx = SystemContext()
        engine.configure(ctx)
        assert engine.no_disk is False

    def test_max_find_depth_by_profile(self):
        assert self._make_engine(StealthProfile.SILENT).max_find_depth == 3
        assert self._make_engine(StealthProfile.NORMAL).max_find_depth == 5
        assert self._make_engine(StealthProfile.AGGRESSIVE).max_find_depth == 10

    def test_throttle_increments_command_count(self):
        engine = self._make_engine(StealthProfile.AGGRESSIVE)
        engine.throttle()
        engine.throttle()
        assert engine._command_count == 2
