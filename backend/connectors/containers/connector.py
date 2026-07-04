"""
NexGenCyberAI - Container Security Connector
Scans container images and running workloads.
Supports: Docker daemon, Kubernetes API, Azure Container Registry, ECR.

Extended security checks:
  Docker: privileged containers, root containers, exposed ports, image age,
          sensitive environment variables.
  Kubernetes: privileged pods, root pods, cluster-admin RBAC over-grant,
              secrets in plain env vars, missing NetworkPolicies,
              unauthenticated API server access.
"""
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

import httpx
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

logger = logging.getLogger(__name__)

# Ports that are HIGH severity if bound to 0.0.0.0
_SENSITIVE_PORTS = {22, 3306, 5432, 6379, 27017}

# Env-var name fragments that indicate sensitive values
_SENSITIVE_ENV_FRAGMENTS = {"PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL", "API_KEY"}

# Ports that are considered admin/debug
_ADMIN_DEBUG_PORTS = {8080, 8443, 9090, 9000, 2375, 2376, 5000, 4243}


class ContainerConnector(BaseConnector):

    # ── Connection helpers ───────────────────────────────────────────────────────

    def _get_docker_client(self):
        """Return a docker.DockerClient or None (import-guarded)."""
        try:
            import docker
        except ImportError:
            logger.warning("docker SDK not installed; skipping Docker checks")
            return None
        docker_host = self.credentials.get("docker_host")
        try:
            if docker_host:
                return docker.DockerClient(base_url=docker_host, timeout=15)
            return docker.from_env(timeout=15)
        except Exception as exc:
            logger.warning("Docker client init failed: %s", exc)
            return None

    def _get_k8s_v1(self):
        """Return a kubernetes CoreV1Api client or None (import-guarded)."""
        try:
            from kubernetes import client as k8s_client, config as k8s_config
        except ImportError:
            logger.warning("kubernetes package not installed; skipping K8s checks")
            return None
        kubeconfig = self.credentials.get("kubeconfig_path") or os.environ.get("KUBECONFIG")
        try:
            if kubeconfig:
                k8s_config.load_kube_config(config_file=kubeconfig)
            else:
                k8s_config.load_incluster_config()
            return k8s_client.CoreV1Api()
        except Exception as exc:
            logger.warning("Kubernetes config load failed: %s", exc)
            return None

    def _get_k8s_rbac(self):
        """Return a kubernetes RbacAuthorizationV1Api client or None."""
        try:
            from kubernetes import client as k8s_client, config as k8s_config
        except ImportError:
            return None
        kubeconfig = self.credentials.get("kubeconfig_path") or os.environ.get("KUBECONFIG")
        try:
            if kubeconfig:
                k8s_config.load_kube_config(config_file=kubeconfig)
            else:
                k8s_config.load_incluster_config()
            return k8s_client.RbacAuthorizationV1Api()
        except Exception as exc:
            logger.warning("Kubernetes RBAC client init failed: %s", exc)
            return None

    def _get_k8s_networking(self):
        """Return a kubernetes NetworkingV1Api client or None."""
        try:
            from kubernetes import client as k8s_client, config as k8s_config
        except ImportError:
            return None
        kubeconfig = self.credentials.get("kubeconfig_path") or os.environ.get("KUBECONFIG")
        try:
            if kubeconfig:
                k8s_config.load_kube_config(config_file=kubeconfig)
            else:
                k8s_config.load_incluster_config()
            return k8s_client.NetworkingV1Api()
        except Exception as exc:
            logger.warning("Kubernetes Networking client init failed: %s", exc)
            return None

    # ── Base interface ───────────────────────────────────────────────────────────

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

    # ── Docker security checks ───────────────────────────────────────────────────

    def _check_privileged_containers(self) -> List[ConnectorFinding]:
        """List running containers and flag those with HostConfig.Privileged=True."""
        findings = []
        try:
            dc = self._get_docker_client()
            if dc is None:
                return findings
            for container in dc.containers.list():
                try:
                    attrs = container.attrs
                    privileged = attrs.get("HostConfig", {}).get("Privileged", False)
                    if privileged:
                        name = attrs.get("Name", container.short_id).lstrip("/")
                        findings.append(ConnectorFinding(
                            title=f"Container '{name}' is running in privileged mode — full host access",
                            description=(
                                f"Docker container '{name}' (ID: {container.short_id}) is running with "
                                "the --privileged flag. A privileged container has unrestricted access to "
                                "the host kernel and all devices, equivalent to running as root on the host."
                            ),
                            severity=FindingSeverity.CRITICAL,
                            resource_id=container.short_id,
                            resource_type="Docker Container",
                            control_id="NIST AC-6",
                            framework="nist_800_53",
                            remediation=(
                                "Remove the --privileged flag. If elevated capabilities are needed, "
                                "use --cap-add to grant only the specific Linux capabilities required."
                            ),
                            evidence={"container_name": name, "container_id": container.short_id},
                        ))
                except Exception as exc:
                    logger.warning("Error inspecting container %s: %s", container.short_id, exc)
        except Exception as exc:
            logger.warning("_check_privileged_containers failed: %s", exc)
        return findings

    def _check_root_containers(self) -> List[ConnectorFinding]:
        """Flag containers whose Config.User is empty, 'root', or '0'."""
        findings = []
        try:
            dc = self._get_docker_client()
            if dc is None:
                return findings
            for container in dc.containers.list():
                try:
                    attrs = container.attrs
                    user = attrs.get("Config", {}).get("User", "")
                    name = attrs.get("Name", container.short_id).lstrip("/")
                    if user in ("", "root", "0"):
                        findings.append(ConnectorFinding(
                            title=f"Container '{name}' runs as root user",
                            description=(
                                f"Docker container '{name}' (User: '{user or 'unset (defaults to root)'}') "
                                "is running as root. If the container is compromised, the attacker gains "
                                "root-level access to container processes and any mounted volumes."
                            ),
                            severity=FindingSeverity.HIGH,
                            resource_id=container.short_id,
                            resource_type="Docker Container",
                            control_id="NIST AC-6",
                            framework="nist_800_53",
                            remediation=(
                                "Add a USER instruction in the Dockerfile to run as a non-root user. "
                                "Example: 'USER 1001'. Ensure the application does not require root privileges."
                            ),
                            evidence={"container_name": name, "user": user or "unset"},
                        ))
                except Exception as exc:
                    logger.warning("Error inspecting container user %s: %s", container.short_id, exc)
        except Exception as exc:
            logger.warning("_check_root_containers failed: %s", exc)
        return findings

    def _check_exposed_ports(self) -> List[ConnectorFinding]:
        """Flag containers with dangerous ports bound to 0.0.0.0."""
        findings = []
        try:
            dc = self._get_docker_client()
            if dc is None:
                return findings
            for container in dc.containers.list():
                try:
                    attrs = container.attrs
                    name = attrs.get("Name", container.short_id).lstrip("/")
                    ports = attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
                    for port_proto, bindings in ports.items():
                        if not bindings:
                            continue
                        try:
                            port_num = int(port_proto.split("/")[0])
                        except ValueError:
                            continue
                        for binding in bindings:
                            host_ip = binding.get("HostIp", "")
                            host_port = binding.get("HostPort", "")
                            if host_ip == "0.0.0.0":
                                if port_num in _SENSITIVE_PORTS:
                                    findings.append(ConnectorFinding(
                                        title=(
                                            f"Container '{name}' exposes sensitive port {port_num} "
                                            f"on 0.0.0.0:{host_port}"
                                        ),
                                        description=(
                                            f"Container '{name}' binds port {port_num} to all interfaces "
                                            f"(0.0.0.0:{host_port}). Port {port_num} is a sensitive service "
                                            "port that should not be exposed publicly."
                                        ),
                                        severity=FindingSeverity.HIGH,
                                        resource_id=container.short_id,
                                        resource_type="Docker Container",
                                        control_id="NIST SC-7",
                                        framework="nist_800_53",
                                        remediation=(
                                            f"Bind port {port_num} to a specific interface (e.g., 127.0.0.1) "
                                            "or use Docker networks to restrict access."
                                        ),
                                        evidence={
                                            "container": name,
                                            "port": port_num,
                                            "host_binding": f"0.0.0.0:{host_port}",
                                        },
                                    ))
                                elif port_num in _ADMIN_DEBUG_PORTS:
                                    findings.append(ConnectorFinding(
                                        title=(
                                            f"Container '{name}' exposes admin/debug port {port_num} "
                                            f"on 0.0.0.0:{host_port}"
                                        ),
                                        description=(
                                            f"Container '{name}' exposes port {port_num} (common admin/debug port) "
                                            f"on all interfaces. This may allow unauthorized access to management "
                                            "interfaces."
                                        ),
                                        severity=FindingSeverity.MEDIUM,
                                        resource_id=container.short_id,
                                        resource_type="Docker Container",
                                        control_id="NIST SC-7",
                                        framework="nist_800_53",
                                        remediation=(
                                            "Restrict admin and debug ports to loopback (127.0.0.1) or "
                                            "remove them from production images entirely."
                                        ),
                                        evidence={
                                            "container": name,
                                            "port": port_num,
                                            "host_binding": f"0.0.0.0:{host_port}",
                                        },
                                    ))
                except Exception as exc:
                    logger.warning("Error inspecting ports for container %s: %s", container.short_id, exc)
        except Exception as exc:
            logger.warning("_check_exposed_ports failed: %s", exc)
        return findings

    def _check_container_image_age(self) -> List[ConnectorFinding]:
        """Flag containers using images older than 180 days."""
        findings = []
        try:
            dc = self._get_docker_client()
            if dc is None:
                return findings
            threshold = datetime.now(timezone.utc) - timedelta(days=180)
            for container in dc.containers.list():
                try:
                    attrs = container.attrs
                    name = attrs.get("Name", container.short_id).lstrip("/")
                    image_name = attrs.get("Config", {}).get("Image", "unknown")
                    # Get image creation date
                    image_id = attrs.get("Image", "")
                    try:
                        image = dc.images.get(image_id)
                        created_str = image.attrs.get("Created", "")
                        if created_str:
                            # Docker returns ISO 8601 with nanoseconds — truncate to microseconds
                            created_str_clean = created_str[:26] + "Z" if len(created_str) > 26 else created_str
                            try:
                                created_dt = datetime.fromisoformat(created_str_clean.replace("Z", "+00:00"))
                            except ValueError:
                                created_dt = datetime.fromisoformat(created_str[:19] + "+00:00")
                            if created_dt < threshold:
                                age_days = (datetime.now(timezone.utc) - created_dt).days
                                findings.append(ConnectorFinding(
                                    title=(
                                        f"Container '{name}' uses an image ({image_name}) "
                                        f"that is {age_days} days old — likely contains unpatched vulnerabilities"
                                    ),
                                    description=(
                                        f"The image '{image_name}' used by container '{name}' was created "
                                        f"{age_days} days ago (on {created_dt.date()}). Images older than 180 days "
                                        "are likely to contain known CVEs that have been patched in newer base images."
                                    ),
                                    severity=FindingSeverity.MEDIUM,
                                    resource_id=container.short_id,
                                    resource_type="Docker Container",
                                    control_id="NIST SI-2",
                                    framework="nist_800_53",
                                    remediation=(
                                        f"Rebuild or pull an updated version of '{image_name}'. "
                                        "Establish a regular image update cadence (at least every 90 days) "
                                        "and use automated vulnerability scanning in your CI/CD pipeline."
                                    ),
                                    evidence={
                                        "container": name,
                                        "image": image_name,
                                        "image_created": created_dt.date().isoformat(),
                                        "age_days": age_days,
                                    },
                                ))
                    except Exception as exc:
                        logger.warning("Failed to inspect image for container %s: %s", name, exc)
                except Exception as exc:
                    logger.warning("Error checking image age for container %s: %s", container.short_id, exc)
        except Exception as exc:
            logger.warning("_check_container_image_age failed: %s", exc)
        return findings

    def _check_sensitive_env_vars(self) -> List[ConnectorFinding]:
        """Flag containers with sensitive values in plain-text environment variables."""
        findings = []
        try:
            dc = self._get_docker_client()
            if dc is None:
                return findings
            for container in dc.containers.list():
                try:
                    attrs = container.attrs
                    name = attrs.get("Name", container.short_id).lstrip("/")
                    env_list = attrs.get("Config", {}).get("Env", []) or []
                    for env_entry in env_list:
                        if "=" not in env_entry:
                            continue
                        var_name = env_entry.split("=", 1)[0].upper()
                        for fragment in _SENSITIVE_ENV_FRAGMENTS:
                            if fragment in var_name:
                                findings.append(ConnectorFinding(
                                    title=(
                                        f"Container '{name}' has a sensitive value in "
                                        f"environment variable '{var_name}'"
                                    ),
                                    description=(
                                        f"Container '{name}' exposes the environment variable '{var_name}' "
                                        "which likely contains a secret, credential, or API key in plain text. "
                                        "Environment variables are visible via 'docker inspect' to anyone "
                                        "with Docker socket access."
                                    ),
                                    severity=FindingSeverity.HIGH,
                                    resource_id=container.short_id,
                                    resource_type="Docker Container",
                                    control_id="NIST IA-5",
                                    framework="nist_800_53",
                                    remediation=(
                                        "Use Docker secrets or a secrets manager (Vault, AWS Secrets Manager) "
                                        "to inject secrets at runtime. Mount secrets as files rather than "
                                        "exposing them as environment variables."
                                    ),
                                    evidence={"container": name, "env_var": var_name},
                                ))
                                break  # one finding per env var is sufficient
                except Exception as exc:
                    logger.warning("Error inspecting env vars for container %s: %s", container.short_id, exc)
        except Exception as exc:
            logger.warning("_check_sensitive_env_vars failed: %s", exc)
        return findings

    # ── Kubernetes security checks ───────────────────────────────────────────────

    def _check_pods_privileged(self) -> List[ConnectorFinding]:
        """Flag pods with containers running in privileged securityContext."""
        findings = []
        try:
            v1 = self._get_k8s_v1()
            if v1 is None:
                return findings
            pods = v1.list_pod_for_all_namespaces(watch=False)
            for pod in pods.items:
                ns = pod.metadata.namespace
                pod_name = pod.metadata.name
                for container in (pod.spec.containers or []):
                    sc = container.security_context
                    if sc and sc.privileged:
                        findings.append(ConnectorFinding(
                            title=f"Privileged pod container: {pod_name}/{container.name}",
                            description=(
                                f"Container '{container.name}' in pod '{pod_name}' (namespace: {ns}) "
                                "has securityContext.privileged=true. This grants the container full "
                                "access to the host kernel, equivalent to running as root on the node."
                            ),
                            severity=FindingSeverity.CRITICAL,
                            resource_id=f"{ns}/{pod_name}",
                            resource_type="Kubernetes Pod",
                            control_id="NIST AC-6",
                            framework="nist_800_53",
                            remediation=(
                                "Remove 'privileged: true' from the container securityContext. "
                                "Use specific capability grants (capabilities.add) only if necessary."
                            ),
                            evidence={
                                "namespace": ns,
                                "pod": pod_name,
                                "container": container.name,
                            },
                        ))
        except Exception as exc:
            logger.warning("_check_pods_privileged failed: %s", exc)
        return findings

    def _check_pods_root(self) -> List[ConnectorFinding]:
        """Flag pods where runAsNonRoot is False or runAsUser is 0."""
        findings = []
        try:
            v1 = self._get_k8s_v1()
            if v1 is None:
                return findings
            pods = v1.list_pod_for_all_namespaces(watch=False)
            for pod in pods.items:
                ns = pod.metadata.namespace
                pod_name = pod.metadata.name
                # Pod-level securityContext
                pod_sc = pod.spec.security_context
                pod_run_as_non_root = pod_sc.run_as_non_root if pod_sc else None
                pod_run_as_user = pod_sc.run_as_user if pod_sc else None
                for container in (pod.spec.containers or []):
                    c_sc = container.security_context
                    run_as_non_root = (
                        c_sc.run_as_non_root if (c_sc and c_sc.run_as_non_root is not None)
                        else pod_run_as_non_root
                    )
                    run_as_user = (
                        c_sc.run_as_user if (c_sc and c_sc.run_as_user is not None)
                        else pod_run_as_user
                    )
                    is_root = (
                        run_as_non_root is False
                        or run_as_user == 0
                        or (run_as_non_root is None and run_as_user is None)
                    )
                    if is_root:
                        findings.append(ConnectorFinding(
                            title=f"Pod container may run as root: {pod_name}/{container.name}",
                            description=(
                                f"Container '{container.name}' in pod '{pod_name}' (namespace: {ns}) "
                                f"does not enforce non-root execution "
                                f"(runAsNonRoot={run_as_non_root}, runAsUser={run_as_user}). "
                                "Running as root in a container increases the impact of a container escape."
                            ),
                            severity=FindingSeverity.HIGH,
                            resource_id=f"{ns}/{pod_name}",
                            resource_type="Kubernetes Pod",
                            control_id="NIST AC-6",
                            framework="nist_800_53",
                            remediation=(
                                "Set securityContext.runAsNonRoot: true and specify a non-zero "
                                "runAsUser in the pod or container securityContext."
                            ),
                            evidence={
                                "namespace": ns,
                                "pod": pod_name,
                                "container": container.name,
                                "runAsNonRoot": run_as_non_root,
                                "runAsUser": run_as_user,
                            },
                        ))
        except Exception as exc:
            logger.warning("_check_pods_root failed: %s", exc)
        return findings

    def _check_rbac_cluster_admin(self) -> List[ConnectorFinding]:
        """Flag ClusterRoleBindings to cluster-admin with more than 3 subjects."""
        findings = []
        try:
            rbac = self._get_k8s_rbac()
            if rbac is None:
                return findings
            bindings = rbac.list_cluster_role_binding(watch=False)
            for binding in bindings.items:
                role_ref = binding.role_ref
                if role_ref and role_ref.name == "cluster-admin":
                    subjects = binding.subjects or []
                    count = len(subjects)
                    if count > 3:
                        subject_names = [
                            f"{s.kind}/{s.name}" for s in subjects
                        ]
                        findings.append(ConnectorFinding(
                            title=(
                                f"cluster-admin ClusterRoleBinding '{binding.metadata.name}' "
                                f"has {count} subjects — excessive privilege"
                            ),
                            description=(
                                f"The ClusterRoleBinding '{binding.metadata.name}' grants cluster-admin "
                                f"to {count} subjects: {', '.join(subject_names[:10])}{'...' if count > 10 else ''}. "
                                "The cluster-admin role has unrestricted access to all Kubernetes resources. "
                                "It should be granted to as few subjects as possible."
                            ),
                            severity=FindingSeverity.HIGH,
                            resource_id=binding.metadata.name,
                            resource_type="Kubernetes ClusterRoleBinding",
                            control_id="NIST AC-6",
                            framework="nist_800_53",
                            remediation=(
                                "Review and reduce the subjects bound to the cluster-admin ClusterRoleBinding. "
                                "Use scoped ClusterRoles or Roles with minimal permissions instead."
                            ),
                            evidence={
                                "binding": binding.metadata.name,
                                "subject_count": count,
                                "subjects": subject_names,
                            },
                        ))
        except Exception as exc:
            logger.warning("_check_rbac_cluster_admin failed: %s", exc)
        return findings

    def _check_secrets_in_env(self) -> List[ConnectorFinding]:
        """Flag pods with raw secret values in env vars (not via secretKeyRef)."""
        findings = []
        try:
            v1 = self._get_k8s_v1()
            if v1 is None:
                return findings
            pods = v1.list_pod_for_all_namespaces(watch=False)
            for pod in pods.items:
                ns = pod.metadata.namespace
                pod_name = pod.metadata.name
                for container in (pod.spec.containers or []):
                    for env_var in (container.env or []):
                        var_name = (env_var.name or "").upper()
                        # Only flag plain 'value:' entries — not valueFrom: secretKeyRef
                        if env_var.value is not None and env_var.value_from is None:
                            for fragment in {"SECRET", "KEY", "PASSWORD", "TOKEN"}:
                                if fragment in var_name:
                                    findings.append(ConnectorFinding(
                                        title=(
                                            f"Pod '{pod_name}' container '{container.name}' "
                                            f"has plain-text secret in env var '{env_var.name}'"
                                        ),
                                        description=(
                                            f"Container '{container.name}' in pod '{pod_name}' "
                                            f"(namespace: {ns}) sets env var '{env_var.name}' as a "
                                            "raw plain-text value. Secrets should be injected via "
                                            "Kubernetes Secrets (valueFrom.secretKeyRef) to avoid "
                                            "exposure in pod specs and audit logs."
                                        ),
                                        severity=FindingSeverity.HIGH,
                                        resource_id=f"{ns}/{pod_name}",
                                        resource_type="Kubernetes Pod",
                                        control_id="NIST IA-5",
                                        framework="nist_800_53",
                                        remediation=(
                                            f"Move '{env_var.name}' to a Kubernetes Secret and reference it "
                                            "using 'valueFrom.secretKeyRef' in the pod spec."
                                        ),
                                        evidence={
                                            "namespace": ns,
                                            "pod": pod_name,
                                            "container": container.name,
                                            "env_var": env_var.name,
                                        },
                                    ))
                                    break
        except Exception as exc:
            logger.warning("_check_secrets_in_env failed: %s", exc)
        return findings

    def _check_network_policies(self) -> List[ConnectorFinding]:
        """Check if the default namespace has any NetworkPolicy. If none → MEDIUM."""
        findings = []
        try:
            net_api = self._get_k8s_networking()
            if net_api is None:
                return findings
            policies = net_api.list_namespaced_network_policy(namespace="default", watch=False)
            if not policies.items:
                findings.append(ConnectorFinding(
                    title="No NetworkPolicy in default namespace — all pods can communicate freely",
                    description=(
                        "The 'default' Kubernetes namespace has no NetworkPolicy resources. "
                        "Without a NetworkPolicy, all pods can communicate with all other pods "
                        "across all namespaces, violating the principle of least-privilege networking."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    resource_id="default",
                    resource_type="Kubernetes Namespace",
                    control_id="NIST SC-7",
                    framework="nist_800_53",
                    remediation=(
                        "Define a default-deny NetworkPolicy in the 'default' namespace and add "
                        "explicit allow rules for required communication paths. Example: "
                        "'podSelector: {}' with 'policyTypes: [Ingress, Egress]' and no rules "
                        "to deny all traffic by default."
                    ),
                ))
        except Exception as exc:
            logger.warning("_check_network_policies failed: %s", exc)
        return findings

    def _check_api_server_access(self) -> List[ConnectorFinding]:
        """Try to reach /api/v1/namespaces without auth. CRITICAL if 200."""
        findings = []
        try:
            import requests
            api_server = self.credentials.get("api_server")
            if not api_server:
                # Derive from kubeconfig if possible
                try:
                    from kubernetes import config as k8s_config
                    import yaml
                    kubeconfig = self.credentials.get("kubeconfig_path") or os.environ.get("KUBECONFIG")
                    if kubeconfig:
                        with open(kubeconfig) as f:
                            kc = yaml.safe_load(f)
                        cluster = kc.get("clusters", [{}])[0]
                        api_server = cluster.get("cluster", {}).get("server", "")
                except Exception:
                    pass
            if not api_server:
                return findings
            try:
                resp = requests.get(
                    f"{api_server}/api/v1/namespaces",
                    verify=False,
                    timeout=5,
                )
                if resp.status_code == 200:
                    findings.append(ConnectorFinding(
                        title="Kubernetes API server allows unauthenticated access",
                        description=(
                            f"The Kubernetes API server at '{api_server}' returned HTTP 200 to an "
                            "unauthenticated request to /api/v1/namespaces. This means anonymous access "
                            "is enabled, allowing any network actor to enumerate cluster resources."
                        ),
                        severity=FindingSeverity.CRITICAL,
                        resource_id=api_server,
                        resource_type="Kubernetes API Server",
                        control_id="NIST AC-17",
                        framework="nist_800_53",
                        remediation=(
                            "Disable anonymous authentication on the API server: "
                            "set '--anonymous-auth=false' in the kube-apiserver configuration. "
                            "Apply RBAC and ensure no ClusterRoleBinding grants cluster-admin to system:anonymous."
                        ),
                        evidence={"api_server": api_server, "status_code": resp.status_code},
                    ))
            except requests.exceptions.ConnectionError:
                pass  # API server unreachable — not a misconfiguration finding
        except ImportError:
            logger.warning("requests package not installed; skipping API server auth check")
        except Exception as exc:
            logger.warning("_check_api_server_access failed: %s", exc)
        return findings

    # ── Legacy Kubernetes checks (httpx-based, kept for backwards compat) ────────

    def _check_legacy_k8s_pods(
        self, api_server: str, token: str
    ) -> List[ConnectorFinding]:
        """Original httpx-based pod checks kept for environments without the SDK."""
        import asyncio
        findings = []
        try:
            import httpx as _httpx

            async def _fetch():
                async with _httpx.AsyncClient(verify=False, timeout=30) as client:
                    resp = await client.get(
                        f"{api_server}/api/v1/pods",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                return resp.json()

            data = asyncio.get_event_loop().run_until_complete(_fetch())
            for pod in data.get("items", []):
                for container in pod["spec"].get("containers", []):
                    sc = container.get("securityContext", {})
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
                    resources_cfg = container.get("resources", {})
                    if not resources_cfg.get("limits"):
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

    # ── Orchestration ────────────────────────────────────────────────────────────

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        findings: List[ConnectorFinding] = []
        platform = self.config.get("platform", "kubernetes")

        # Docker security checks
        findings.extend(self._check_privileged_containers())
        findings.extend(self._check_root_containers())
        findings.extend(self._check_exposed_ports())
        findings.extend(self._check_container_image_age())
        findings.extend(self._check_sensitive_env_vars())

        # Kubernetes security checks
        findings.extend(self._check_pods_privileged())
        findings.extend(self._check_pods_root())
        findings.extend(self._check_rbac_cluster_admin())
        findings.extend(self._check_secrets_in_env())
        findings.extend(self._check_network_policies())
        findings.extend(self._check_api_server_access())

        # Legacy httpx-based K8s checks (fallback)
        if platform == "kubernetes":
            api_server = self.credentials.get("api_server")
            token = self.credentials.get("token")
            if api_server and token:
                findings.extend(self._check_legacy_k8s_pods(api_server, token))

        return findings

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        # In production: integrate Trivy, Snyk, or Anchore
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
