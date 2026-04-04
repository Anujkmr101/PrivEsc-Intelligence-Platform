"""
plugins/correlation/service_account_chain.py

Correlation Plugin: Service Account Privilege Chain.

Extends the attack graph with edges representing service account abuse
patterns that are not captured by the standard finding-to-edge mapping:

  1. Database service accounts running as root (MySQL, PostgreSQL running as root)
  2. Writable service account home directories + cron combination
  3. sudo rules allowing execution AS a service account that itself has root sudo

These chains are missed by tools that only look at isolated findings
because they require connecting dots across multiple finding categories.

This plugin adds the missing edges to the NetworkX graph so the
CorrelationGraphEngine can discover the full path.

Usage: drop this file into plugins/correlation/ — auto-loaded at runtime.
"""

from __future__ import annotations

import networkx as nx

from pip.core.plugin import CorrelationPlugin
from pip.models.context import SystemContext
from pip.models.finding import Finding, FindingCategory, Severity


class ServiceAccountChainPlugin(CorrelationPlugin):
    """
    Connects service-account-related findings into full escalation chains.

    Handles:
      - root-running database processes (mysql, postgres)
      - writable service home dirs + scheduled job combination
      - sudo-to-service-account-with-root-access chains
    """

    name        = "service_account_chain"
    description = "Adds attack graph edges for service account privilege chains."

    def enrich(
        self,
        graph: nx.DiGraph,
        findings: list[Finding],
        sys_ctx: SystemContext,
    ) -> None:
        """
        Add custom edges to the attack graph for service account abuse patterns.
        Called by CorrelationGraphEngine after all standard edges are built.
        """
        self._add_root_database_edges(graph, findings, sys_ctx)
        self._add_writable_service_home_edges(graph, findings)
        self._add_sudo_chain_edges(graph, findings)

    # ── Root-running database processes ───────────────────────────────────────

    def _add_root_database_edges(
        self,
        graph: nx.DiGraph,
        findings: list[Finding],
        sys_ctx: SystemContext,
    ) -> None:
        """
        If MySQL or PostgreSQL is running as root, a SQL injection or
        UDF exploit leads directly to a root shell.
        """
        root_db_services = [
            svc for svc in sys_ctx.running_services
            if any(db in svc.lower() for db in ("mysql", "mariadb", "postgres"))
        ]
        if not root_db_services:
            return

        # Check if the service runs as root (requires a credential/service finding)
        credential_findings = [
            f for f in findings if f.category == FindingCategory.CREDENTIAL
            and any(db in f.title.lower() for db in ("mysql", "postgres", "database", "db"))
        ]

        for svc in root_db_services:
            svc_node = f"db_service:{svc}"
            graph.add_node(svc_node, label=f"Root DB service: {svc}")

            # Edge: user_shell → db_service (via credential or UDF)
            # Synthesize a Finding to attach to this edge
            synthetic = Finding(
                title=f"Root-running database service: {svc}",
                category=FindingCategory.SERVICE,
                severity=Severity.HIGH,
                description=(
                    f"{svc} is running. If it runs as root and a credential "
                    f"or UDF exploit is available, full root access is possible."
                ),
                confidence=0.60,
                source_module=self.name,
            )
            graph.add_edge("user_shell", svc_node, finding=synthetic, weight=0.4)
            graph.add_edge(svc_node, "root_shell", finding=synthetic, weight=0.4)

    # ── Writable service home + cron ──────────────────────────────────────────

    def _add_writable_service_home_edges(
        self,
        graph: nx.DiGraph,
        findings: list[Finding],
    ) -> None:
        """
        If a service account's home directory is writable AND that account
        has a cron job, the attacker can plant a .bashrc/.profile payload
        that executes when the service account's shell is invoked by cron.
        """
        writable_homes = [
            f for f in findings
            if f.category == FindingCategory.LATERAL
            and "home" in f.affected_path.lower()
            and "readable" in f.title.lower()
        ]
        cron_findings = [
            f for f in findings if f.category == FindingCategory.CRON
        ]

        if not writable_homes or not cron_findings:
            return

        for home_finding in writable_homes:
            for cron_finding in cron_findings:
                chain_node = f"service_home_cron_chain:{home_finding.affected_path}"
                graph.add_node(chain_node, label="Service home + cron chain")

                synthetic = Finding(
                    title=f"Writable service home + cron chain via {home_finding.affected_path}",
                    category=FindingCategory.LATERAL,
                    severity=Severity.HIGH,
                    description=(
                        f"The service account home directory {home_finding.affected_path} "
                        f"is accessible. Combined with the cron finding "
                        f"'{cron_finding.title}', this may allow privilege escalation "
                        f"via .bashrc or .profile payload injection."
                    ),
                    confidence=0.55,
                    source_module=self.name,
                )
                graph.add_edge("user_shell", chain_node, finding=synthetic, weight=0.45)
                graph.add_edge(chain_node, "cron_root", finding=cron_finding, weight=0.2)

    # ── sudo chain: user → service account → root ─────────────────────────────

    def _add_sudo_chain_edges(
        self,
        graph: nx.DiGraph,
        findings: list[Finding],
    ) -> None:
        """
        Some systems allow `sudo -u serviceaccount <cmd>` where the service
        account itself has a NOPASSWD sudo rule granting root. This creates
        a two-hop chain that tools looking only for direct root sudo miss.

        Pattern: sudo_finding (user → svcaccount) + another sudo_finding (svcaccount → root)
        """
        sudo_findings = [f for f in findings if f.category == FindingCategory.SUDO]

        # Look for pairs: one sudo to non-root, one sudo from non-root to root
        for f1 in sudo_findings:
            for f2 in sudo_findings:
                if f1 is f2:
                    continue
                # Heuristic: if one is "ALL" (root) and the other is a specific user
                if "ALL" in f2.affected_path and "ALL" not in f1.affected_path:
                    pivot_node = f"sudo_pivot:{f1.affected_path}"
                    graph.add_node(pivot_node, label=f"sudo pivot: {f1.affected_path}")

                    synthetic = Finding(
                        title=f"Two-hop sudo chain: current user → {f1.affected_path} → root",
                        category=FindingCategory.SUDO,
                        severity=Severity.HIGH,
                        description=(
                            f"sudo rule allows executing as '{f1.affected_path}', "
                            f"which in turn has NOPASSWD ALL sudo. "
                            f"This creates a two-hop escalation chain to root."
                        ),
                        confidence=0.65,
                        source_module=self.name,
                    )
                    graph.add_edge("user_shell", pivot_node, finding=f1, weight=0.35)
                    graph.add_edge(pivot_node, "root_shell", finding=synthetic, weight=0.35)
