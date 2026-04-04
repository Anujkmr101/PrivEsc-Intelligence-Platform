"""
plugins/enum/example_custom_check.py

Example drop-in enumeration plugin.

Drop any Python file matching this interface into plugins/enum/ and it
will be auto-loaded by the Orchestrator at runtime — no code changes required.

To install your plugin:
    cp my_check.py plugins/enum/
    python pip.py plugins   # Verify it appears in the list
"""

from __future__ import annotations

from pip.models.context import ScanConfig, SystemContext, UserContext
from pip.models.finding import Finding, FindingCategory, Severity
from pip.core.shell_compat import ShellCompat


class ExampleCustomCheck:
    """
    Template for a custom enumeration plugin.

    Rename this class, change `name`, and implement `run()`.
    The Orchestrator calls run() concurrently with all other modules.
    """

    # Plugin identifier shown in `pip plugins` output
    name = "example_custom_check"

    def __init__(self, config: ScanConfig | None = None):
        self.config = config

    async def run(
        self,
        sys_ctx: SystemContext,
        user_ctx: UserContext,
        shell: ShellCompat,
    ) -> list[Finding]:
        """
        Execute your custom checks and return a list of Finding objects.

        Rules:
          - Never modify the target system (write, delete, execute payloads).
          - Use shell.run() for all command execution (stealth + throttling applied).
          - Use shell.read_file() for safe file reads.
          - Return an empty list if nothing was found — never return None.
          - Set source_module to self.name on every Finding.
        """
        findings: list[Finding] = []

        # Example: check for a world-readable /root directory
        result = shell.run("test -r /root && echo readable")
        if "readable" in result.stdout:
            findings.append(Finding(
                title="/root directory is world-readable",
                category=FindingCategory.WRITABLE,
                severity=Severity.HIGH,
                description=(
                    "The /root home directory is readable by the current user. "
                    "SSH keys, credentials, or sensitive scripts may be accessible."
                ),
                evidence="/root is readable",
                command="test -r /root",
                affected_path="/root",
                source_module=self.name,
            ))

        return findings
