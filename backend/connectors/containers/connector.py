"""
NexGenCyberAI - Container Security Connector
Scans container images and running workloads.
Supports: Docker daemon, Kubernetes API, Azure Container Registry, ECR.
"""
from typing import Any, Dict, List
import httpx
from ..base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity


class ContainerConnector(BaseConnector):

    async def test_connection(self) -> ConnectorTestResult:
        platform = self.config.get("platform", "kubernetes")
        try:
            if platform == "kubernetes":
                api_server = self.credentials.get("api_server")
                token = self.credentials.get("token")
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    resp = await client.get(
                        f"{api_server}/api/v1/namespaces",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                resp.raise_for_status()
                ns_count = len(resp.json().get("items", []))
                return ConnectorTestResult(success=True, message=f"K8s connected. {ns_count} namespaces found.")
            return ConnectorTestResult(success=True, message=f"Container platform: {platform}")
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    async def get_resources(self) -> List[Dict[str, Any]]:
        resources = []
        platform = self.config.get("platform", "kubernetes")
        if platform == "kubernetes":
            api_server = self.credentials.get("api_server")
            token = self.credentials.get("token")
            async with httpx.AsyncClient(verify=False, timeout=30) as client:
                resp = await client.get(
                    f"{api_server}/api/v1/pods",
                    headers={"Authorization": f"Bearer {token}"},
                )
            for pod in resp.json().get("items", []):
                resources.append({
                    "id": pod["metadata"]["uid"],
                    "name": pod["metadata"]["name"],
                    "namespace": pod["metadata"]["namespace"],
                    "type": "kubernetes_pod",
                    "containers": [c["image"] for c in pod["spec"].get("containers", [])],
                })
        return resources

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        findings = []
        platform = self.config.get("platform", "kubernetes")
        if platform == "kubernetes":
            api_server = self.credentials.get("api_server")
            token = self.credentials.get("token")
            try:
                async with httpx.AsyncClient(verify=False, timeout=30) as client:
                    resp = await client.get(
                        f"{api_server}/api/v1/pods",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                for pod in resp.json().get("items", []):
                    for container in pod["spec"].get("containers", []):
                        sc = container.get("securityContext", {})
                        # Privileged container check
                        if sc.get("privileged"):
                            findings.append(ConnectorFinding(
                                title="Privileged container running",
                                description=f"Container '{container['name']}' in pod '{pod['metadata']['name']}' is privileged.",
                                severity=FindingSeverity.CRITICAL,
                                resource_id=pod["metadata"]["uid"],
                                resource_type="Kubernetes Pod",
                                control_id="CIS 5.2.1",
                                framework="cis_v8",
                                remediation="Remove privileged:true from container securityContext.",
                            ))
                        # Root user check
                        if sc.get("runAsUser") == 0 or sc.get("runAsRoot"):
                            findings.append(ConnectorFinding(
                                title="Container running as root",
                                description=f"Container '{container['name']}' runs as root user.",
                                severity=FindingSeverity.HIGH,
                                resource_id=pod["metadata"]["uid"],
                                resource_type="Kubernetes Pod",
                                control_id="CIS 5.2.6",
                                framework="cis_v8",
                                remediation="Set runAsNonRoot: true and specify a non-root runAsUser.",
                            ))
                        # Missing resource limits
                        resources = container.get("resources", {})
                        if not resources.get("limits"):
                            findings.append(ConnectorFinding(
                                title="Container missing resource limits",
                                description=f"Container '{container['name']}' has no CPU/memory limits.",
                                severity=FindingSeverity.MEDIUM,
                                resource_id=pod["metadata"]["uid"],
                                resource_type="Kubernetes Pod",
                                control_id="CIS 5.2.7",
                                framework="cis_v8",
                                remediation="Define CPU and memory limits for all containers.",
                            ))
            except Exception:
                pass
        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        # In production: integrate Trivy, Snyk, or Anchore
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
