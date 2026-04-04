"""
pip/analysis/correlation_graph.py

Correlation Graph Engine — the intelligence core of PIP.

Converts a flat list of isolated Findings into a directed graph of
attack paths. Each node is a system state; each edge is an exploitable
action that transitions from one state to another.

Graph model:
    Nodes:   "user_shell", "writable_script", "cron_root", "root_shell", etc.
    Edges:   Finding objects (the action that traverses the edge)

The engine then finds all simple paths from "user_shell" to "root_shell"
using NetworkX, constructs AttackPath objects for each, and returns them
ranked by composite score (scoring happens in RiskScorer).
"""

from __future__ import annotations

from typing import Optional

import networkx as nx

from pip.models.context import ScanConfig, SystemContext
from pip.models.finding import Finding, FindingCategory
from pip.models.attack_path import AttackPath, AttackStep


class CorrelationGraphEngine:
    """
    Builds a directed attack graph from enumeration findings and extracts
    all viable paths from the current user context to root.
    """

    # Maximum path length to consider (prevents combinatorial explosion)
    MAX_PATH_LENGTH = 6
    # Maximum number of paths to return (sorted by score)
    MAX_PATHS = 10

    def __init__(self, config: ScanConfig):
        self.config = config
        self.graph = nx.DiGraph()
        self._path_counter = 0

    def build_paths(
        self,
        findings: list[Finding],
        sys_ctx: SystemContext,
    ) -> list[AttackPath]:
        """
        Main entry point. Build the attack graph and return all viable paths.

        Args:
            findings:   All Finding objects from enumeration modules.
            sys_ctx:    SystemContext for environment-aware edge building.

        Returns:
            List of AttackPath objects (unsorted; scoring done by RiskScorer).
        """
        self._build_graph(findings, sys_ctx)
        return self._extract_paths(findings)

    # ── Graph construction ────────────────────────────────────────────────────

    def _build_graph(self, findings: list[Finding], sys_ctx: SystemContext) -> None:
        """
        Populate the directed graph with nodes and edges derived from findings.

        Node naming convention:
            "user_shell"          — starting point (current user access)
            "file:<path>"         — a file or directory state
            "process:<name>"      — a running process state
            "cron_root"           — a root-owned cron job
            "root_shell"          — target (full root access)
            "service:<name>"      — a systemd service
            "container_escape"    — Docker/K8s escape intermediate node

        Edge attributes:
            finding:   The Finding that enables this transition.
            weight:    Inverse of confidence (for shortest-path queries).
        """
        self.graph.add_node("user_shell", label="Current user shell")
        self.graph.add_node("root_shell", label="Root shell")

        for finding in findings:
            self._add_edges_for_finding(finding, sys_ctx)

    def _add_edges_for_finding(self, finding: Finding, sys_ctx: SystemContext) -> None:
        """Map a single Finding to one or more edges in the attack graph."""
        cat = finding.category
        path = finding.affected_path

        if cat == FindingCategory.SUID:
            # SUID binary: user_shell → [binary execution] → root_shell
            node = f"suid:{path}"
            self.graph.add_node(node, label=f"SUID {path}")
            self._add_edge("user_shell", node, finding)
            self._add_edge(node, "root_shell", finding)

        elif cat == FindingCategory.SUDO:
            # Sudo rule: user_shell → [sudo execution] → root_shell
            node = f"sudo:{path}"
            self.graph.add_node(node, label=f"sudo {path}")
            self._add_edge("user_shell", node, finding)
            self._add_edge(node, "root_shell", finding)

        elif cat == FindingCategory.CAPABILITY:
            node = f"cap:{path}"
            self.graph.add_node(node, label=f"cap {path}")
            self._add_edge("user_shell", node, finding)
            self._add_edge(node, "root_shell", finding)

        elif cat == FindingCategory.CRON:
            # Multi-hop: user writes to script → cron executes as root
            script_node = f"file:{path}"
            self.graph.add_node(script_node, label=f"writable: {path}")
            self.graph.add_node("cron_root", label="Root cron execution")
            self._add_edge("user_shell", script_node, finding)
            self._add_edge(script_node, "cron_root", finding)
            self._add_edge("cron_root", "root_shell", finding)

        elif cat == FindingCategory.SERVICE:
            # Unit file write → service restart → root execution
            unit_node = f"service:{path}"
            self.graph.add_node(unit_node, label=f"unit file: {path}")
            self.graph.add_node("service_restart", label="Service restart trigger")
            self._add_edge("user_shell", unit_node, finding)
            self._add_edge(unit_node, "service_restart", finding)
            self._add_edge("service_restart", "root_shell", finding)

        elif cat == FindingCategory.WRITABLE:
            if "passwd" in path or "shadow" in path or "sudoers" in path:
                node = f"file:{path}"
                self.graph.add_node(node, label=f"writable: {path}")
                self._add_edge("user_shell", node, finding)
                self._add_edge(node, "root_shell", finding)

        elif cat == FindingCategory.NFS:
            node = f"nfs:{path}"
            self.graph.add_node(node, label=f"NFS: {path}")
            self._add_edge("user_shell", node, finding)
            self._add_edge(node, "root_shell", finding)

        elif cat == FindingCategory.CONTAINER:
            node = "container_escape"
            self.graph.add_node(node, label="Container escape vector")
            self._add_edge("user_shell", node, finding)
            self._add_edge(node, "root_shell", finding)

        elif cat == FindingCategory.KERNEL:
            node = "kernel_exploit"
            self.graph.add_node(node, label="Kernel exploit")
            self._add_edge("user_shell", node, finding)
            self._add_edge(node, "root_shell", finding)

        elif cat == FindingCategory.PATH:
            node = f"path_hijack:{path}"
            self.graph.add_node(node, label=f"PATH hijack: {path}")
            self._add_edge("user_shell", node, finding)
            self._add_edge(node, "root_shell", finding)

        elif cat == FindingCategory.CREDENTIAL:
            # Credentials can unlock lateral movement or direct root access
            node = f"cred:{path or finding.title[:20]}"
            self.graph.add_node(node, label="Credential found")
            self._add_edge("user_shell", node, finding)
            self._add_edge(node, "root_shell", finding)

    def _add_edge(self, src: str, dst: str, finding: Finding) -> None:
        """Add a directed edge with the Finding as its payload."""
        self.graph.add_edge(
            src, dst,
            finding=finding,
            weight=1.0 - finding.confidence,  # lower confidence → higher weight
        )

    # ── Path extraction ───────────────────────────────────────────────────────

    def _extract_paths(self, all_findings: list[Finding]) -> list[AttackPath]:
        """
        Find all simple paths from user_shell to root_shell in the graph,
        construct AttackPath objects, and return them.
        """
        attack_paths = []

        try:
            raw_paths = list(nx.all_simple_paths(
                self.graph,
                source="user_shell",
                target="root_shell",
                cutoff=self.MAX_PATH_LENGTH,
            ))
        except nx.NetworkXError:
            return []

        for node_sequence in raw_paths[:self.MAX_PATHS]:
            path = self._build_attack_path(node_sequence)
            if path:
                attack_paths.append(path)

        return attack_paths

    def _build_attack_path(self, node_sequence: list[str]) -> Optional[AttackPath]:
        """Convert a node sequence from nx into a structured AttackPath."""
        self._path_counter += 1
        steps = []
        mitre_ids = []

        for i in range(len(node_sequence) - 1):
            src, dst = node_sequence[i], node_sequence[i + 1]
            edge_data = self.graph.get_edge_data(src, dst)
            if not edge_data:
                continue
            finding: Finding = edge_data["finding"]

            step = AttackStep(
                order=len(steps) + 1,
                description=self._describe_step(src, dst, finding),
                command=finding.exploit_cmd or finding.command,
                finding=finding,
                expected=self._expected_outcome(dst),
            )
            steps.append(step)

            if finding.mitre_id and finding.mitre_id not in mitre_ids:
                mitre_ids.append(finding.mitre_id)

        if not steps:
            return None

        title = self._generate_title(steps)
        return AttackPath(
            path_id=f"path_{self._path_counter:03d}",
            title=title,
            steps=steps,
            mitre_ids=mitre_ids,
            narrative=self._generate_narrative(steps),
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _describe_step(src: str, dst: str, finding: Finding) -> str:
        templates = {
            FindingCategory.CRON:    "Inject payload into {path}, wait for root cron execution",
            FindingCategory.SUID:    "Abuse SUID binary {path} to spawn root shell",
            FindingCategory.SUDO:    "Execute {path} via sudo NOPASSWD rule",
            FindingCategory.CAPABILITY: "Abuse {cap} capability on {path}",
            FindingCategory.SERVICE: "Modify unit file {path}, trigger service restart",
            FindingCategory.WRITABLE:"Write root payload to {path}",
            FindingCategory.KERNEL:  "Exploit kernel vulnerability {cve}",
            FindingCategory.CONTAINER: "Escape container via {path}",
            FindingCategory.CREDENTIAL: "Use discovered credential to gain root access",
        }
        template = templates.get(finding.category, finding.description[:80])
        return template.format(
            path=finding.affected_path,
            cap=next((t for t in finding.tags if t.startswith("cap_")), "cap"),
            cve=finding.cve or finding.title,
        )

    @staticmethod
    def _expected_outcome(dst_node: str) -> str:
        if dst_node == "root_shell":
            return "Root shell obtained"
        if dst_node == "cron_root":
            return "Payload queued for root cron execution"
        if dst_node == "service_restart":
            return "Service will execute modified command as root on next restart"
        return f"Reach state: {dst_node.replace('_', ' ')}"

    @staticmethod
    def _generate_title(steps: list[AttackStep]) -> str:
        if not steps:
            return "Unknown path"
        primary = steps[0].finding
        return f"{primary.category.value.replace('_', ' ').title()} → Root via {primary.affected_path or primary.title}"

    @staticmethod
    def _generate_narrative(steps: list[AttackStep]) -> str:
        parts = [f"Step {s.order}: {s.description}." for s in steps]
        return " ".join(parts)
