"""
pip/core/plugin.py

Plugin Base Classes.

All drop-in modules in the plugins/ directory must subclass one of these
base classes and implement the required interface.

The Orchestrator uses duck-typing (checks for a .run() method) so
inheriting from these classes is strongly recommended but not strictly
enforced. Inheriting gives you type checking, IDE autocomplete, and
the default safety checks for free.

Plugin categories
─────────────────
  EnumPlugin        — discovers findings (read-only, no side effects)
  ExploitPlugin     — executes a specific exploit (requires --exploit flag)
  CloudPlugin       — cloud-provider-specific enumeration
  CorrelationPlugin — adds custom nodes/edges to the attack graph

Quick start
───────────
  1. Copy the relevant base class below into your plugin file.
  2. Set `name` to a unique snake_case identifier.
  3. Implement `run()` (and `can_run()` if your plugin has preconditions).
  4. Drop the file into the right plugins/ subdirectory.
  5. Run `python pip.py plugins` to confirm it loaded.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pip.models.context import ScanConfig, SystemContext, UserContext
    from pip.models.finding import Finding
    from pip.models.attack_path import AttackPath
    from pip.core.shell_compat import ShellCompat
    import networkx as nx


# ── Enumeration plugin ────────────────────────────────────────────────────────

class EnumPlugin(ABC):
    """
    Base class for read-only enumeration plugins.

    Plugins in this category discover findings — they never modify the
    target system, write files, or execute payloads.

    Example:
        class MySUIDCheck(EnumPlugin):
            name = "my_suid_check"

            async def run(self, sys_ctx, user_ctx, shell):
                result = shell.run("find /usr -perm -4000 -name 'myapp'")
                if result.ok:
                    return [Finding(title="Custom SUID: myapp", ...)]
                return []
    """

    #: Unique snake_case identifier shown in `pip plugins` output.
    name: str = "unnamed_enum_plugin"

    #: Human-readable description shown in verbose output.
    description: str = ""

    def can_run(self, sys_ctx: "SystemContext", user_ctx: "UserContext") -> bool:
        """
        Optional precondition check. Return False to skip this plugin entirely.

        Override this to gate your plugin on environment type, OS version,
        or any other context property detected by the ContextEngine.

        Default: always run.
        """
        return True

    @abstractmethod
    async def run(
        self,
        sys_ctx: "SystemContext",
        user_ctx: "UserContext",
        shell: "ShellCompat",
    ) -> list["Finding"]:
        """
        Execute enumeration checks. Must be async.

        Rules:
          - Never modify the target system.
          - Use shell.run() for all commands (stealth + throttling applied).
          - Use shell.read_file() for file access.
          - Return [] if nothing found. Never return None.
          - Set source_module = self.name on every Finding.

        Returns:
            List of Finding objects. Empty list if nothing found.
        """
        ...


# ── Exploit plugin ────────────────────────────────────────────────────────────

class ExploitPlugin(ABC):
    """
    Base class for exploit execution plugins.

    IMPORTANT: Exploit plugins only run when:
      1. The user passes --exploit on the CLI.
      2. The ExploitRunner's consent gate is passed.
      3. The finding was verified by the ExploitValidator.

    Exploit plugins must:
      - Be idempotent where possible.
      - Document their cleanup / rollback steps in `rollback()`.
      - Never exceed the scope of the specific exploit they implement.
      - Log every command to the audit trail (done automatically by ExploitRunner).
    """

    name: str = "unnamed_exploit_plugin"
    description: str = ""

    #: CVE or technique identifier this exploit implements (e.g. "CVE-2021-3156").
    cve_or_technique: str = ""

    #: FindingCategory this exploit applies to.
    target_category: str = ""

    def can_run(
        self,
        sys_ctx: "SystemContext",
        user_ctx: "UserContext",
        shell: "ShellCompat",
    ) -> bool:
        """
        Precondition check run before exploitation.
        Return False to abort cleanly.
        """
        return True

    @abstractmethod
    async def run(
        self,
        sys_ctx: "SystemContext",
        user_ctx: "UserContext",
        shell: "ShellCompat",
    ) -> bool:
        """
        Execute the exploit. Return True on success.

        Must only be called by ExploitRunner with an active consent gate.
        """
        ...

    async def rollback(self, shell: "ShellCompat") -> None:
        """
        Undo any changes made by run(). Called on failure or kill-switch.

        Implement this whenever run() modifies system state.
        Default: no-op.
        """
        pass


# ── Cloud plugin ──────────────────────────────────────────────────────────────

class CloudPlugin(EnumPlugin, ABC):
    """
    Base class for cloud-provider-specific enumeration plugins.

    Subclasses EnumPlugin with an additional `provider` attribute that
    gates execution to a specific cloud environment.

    The Orchestrator only activates CloudPlugins when the ContextEngine
    detects a matching cloud_provider in SystemContext.

    Example:
        class AWSSecretsManagerCheck(CloudPlugin):
            name = "aws_secrets_manager"
            provider = "aws"

            async def run(self, sys_ctx, user_ctx, shell):
                # Check for accessible Secrets Manager endpoints
                ...
    """

    #: Cloud provider this plugin targets: "aws" | "gcp" | "azure" | "any"
    provider: str = "any"

    def can_run(self, sys_ctx: "SystemContext", user_ctx: "UserContext") -> bool:
        if self.provider == "any":
            return True
        if sys_ctx.cloud_provider is None:
            return False
        return sys_ctx.cloud_provider.value == self.provider


# ── Correlation plugin ────────────────────────────────────────────────────────

class CorrelationPlugin(ABC):
    """
    Base class for custom attack graph extension plugins.

    Correlation plugins receive the partially-built NetworkX graph after
    standard enumeration and can add custom nodes, edges, or modify
    edge weights to encode organisation-specific attack paths.

    Use cases:
      - Custom application-specific privilege escalation chains
      - Organisation-specific service account abuse patterns
      - Non-standard SUID binaries unique to your environment

    Example:
        class CustomAppCorrelation(CorrelationPlugin):
            name = "custom_app_chain"

            def enrich(self, graph, findings, sys_ctx):
                # Add a custom edge for a proprietary service
                graph.add_edge("user_shell", "custom_service_root", weight=0.1)
    """

    name: str = "unnamed_correlation_plugin"
    description: str = ""

    @abstractmethod
    def enrich(
        self,
        graph: "nx.DiGraph",
        findings: "list[Finding]",
        sys_ctx: "SystemContext",
    ) -> None:
        """
        Mutate the attack graph in-place.

        Args:
            graph:    The NetworkX DiGraph being built by CorrelationGraphEngine.
            findings: All findings from enumeration (read-only).
            sys_ctx:  System context (read-only).
        """
        ...
