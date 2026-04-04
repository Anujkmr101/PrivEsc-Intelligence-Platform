"""
pip/enum/cloud_container.py

Cloud and Container Enumeration Module.

Checks specific to Docker, Kubernetes, and cloud environments:
  - Docker socket exposure
  - Privileged container escape via CAP_SYS_ADMIN
  - Kubernetes RBAC misconfigurations and service account abuse
  - Cloud IMDS credential access (AWS/GCP/Azure)
  - Namespace escape vectors
"""
from __future__ import annotations
import os
from pip.models.context import ScanConfig, SystemContext, UserContext
from pip.models.finding import Finding, FindingCategory, Severity
from pip.core.shell_compat import ShellCompat

class CloudContainerModule:
    name = "cloud_container"

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, sys_ctx: SystemContext, user_ctx: UserContext, shell: ShellCompat) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_docker_socket(sys_ctx, shell))
        findings.extend(self._check_privileged_container(sys_ctx, shell))
        findings.extend(self._check_k8s_rbac(sys_ctx, shell))
        findings.extend(self._check_host_mounts(shell))
        return findings

    def _check_docker_socket(self, sys_ctx: SystemContext, shell: ShellCompat) -> list[Finding]:
        if not os.path.exists("/var/run/docker.sock"):
            return []
        result = shell.run("test -r /var/run/docker.sock && echo accessible")
        if "accessible" not in result.stdout:
            return []
        return [Finding(
            title="Docker socket exposed and accessible",
            category=FindingCategory.CONTAINER,
            severity=Severity.CRITICAL,
            description="The Docker socket at /var/run/docker.sock is accessible to the current user. "
                        "This allows spawning a privileged container with the host filesystem mounted, "
                        "effectively providing root access to the host.",
            evidence="/var/run/docker.sock accessible",
            exploit_cmd="docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
            command="test -r /var/run/docker.sock",
            affected_path="/var/run/docker.sock",
            source_module=self.name,
        )]

    def _check_privileged_container(self, sys_ctx: SystemContext, shell: ShellCompat) -> list[Finding]:
        if sys_ctx.is_privileged_container:
            return [Finding(
                title="Running inside a privileged container (CAP_SYS_ADMIN)",
                category=FindingCategory.CONTAINER,
                severity=Severity.CRITICAL,
                description="This container has CAP_SYS_ADMIN. The host can be escaped by mounting "
                            "the host filesystem via /dev/sda or cgroup release_agent techniques.",
                evidence="CapEff contains CAP_SYS_ADMIN",
                command="cat /proc/self/status | grep CapEff",
                source_module=self.name,
            )]
        return []

    def _check_k8s_rbac(self, sys_ctx: SystemContext, shell: ShellCompat) -> list[Finding]:
        findings = []
        if not sys_ctx.k8s_service_account:
            return findings
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        token = shell.read_file(token_path)
        if token:
            findings.append(Finding(
                title="Kubernetes service account token accessible",
                category=FindingCategory.CLOUD,
                severity=Severity.HIGH,
                description="A Kubernetes service account token is mounted and readable. "
                            "Depending on bound permissions, this may allow cluster-admin escalation.",
                evidence=f"Token path: {token_path}",
                command=f"cat {token_path}",
                affected_path=token_path,
                source_module=self.name,
            ))
        # Check for overly permissive RBAC
        rbac_result = shell.run(
            "kubectl auth can-i --list 2>/dev/null | grep -E '(\\*|create|get).*secrets'",
            timeout=5,
        )
        if rbac_result.output:
            findings.append(Finding(
                title="K8s service account can access secrets",
                category=FindingCategory.CLOUD,
                severity=Severity.CRITICAL,
                description="The current service account can list or get Secrets in Kubernetes. "
                            "This may expose credentials for other services or cluster-admin tokens.",
                evidence=rbac_result.output[:200],
                command="kubectl auth can-i --list",
                source_module=self.name,
            ))
        return findings

    def _check_host_mounts(self, shell: ShellCompat) -> list[Finding]:
        """Look for host filesystem mounts inside the container."""
        findings = []
        mounts = shell.read_file("/proc/mounts") or ""
        sensitive_mounts = ["/etc", "/root", "/home", "/var/lib", "/proc/sys"]
        for line in mounts.splitlines():
            for sensitive in sensitive_mounts:
                if f" {sensitive} " in line and "tmpfs" not in line and "overlay" not in line:
                    findings.append(Finding(
                        title=f"Host path mounted into container: {sensitive}",
                        category=FindingCategory.CONTAINER,
                        severity=Severity.HIGH,
                        description=f"The host path {sensitive} appears to be bind-mounted into this container. "
                                    f"Modifications here affect the host system.",
                        evidence=line.strip(),
                        command="cat /proc/mounts",
                        affected_path=sensitive,
                        source_module=self.name,
                    ))
        return findings
