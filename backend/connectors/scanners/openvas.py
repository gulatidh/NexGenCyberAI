"""OpenVAS / Greenbone vulnerability scanner.

Connector holds GVM daemon connection details + scan profile only.
Target and authenticated-scan credentials are supplied at scan-launch time.
"""
import asyncio
import shutil
from pathlib import Path

from connectors.base import ConnectorTestResult
from connectors.scanners.base import WorkflowConnector


class OpenVASConnector(WorkflowConnector):
    WORKFLOW_FILE = "openvas-scan.yml"
    REQUIRED_CONFIG = []   # target is per-scan, not per-connector
    RESOURCE_TYPE = "host"
    DEFAULT_DISPLAY_NAME = "OpenVAS / Greenbone"

    async def test_connection(self) -> ConnectorTestResult:
        """Verify the local GVM daemon is reachable by sending <get_version/>."""
        gvm_cli = shutil.which("gvm-cli")
        if not gvm_cli:
            return ConnectorTestResult(
                success=False,
                message="gvm-cli not found — run 'sudo gvm-setup' on Kali first.",
            )

        user     = self.credentials.get("gvm_user", "admin")
        password = self.credentials.get("gvm_password", "")

        _SOCKET_CANDIDATES = [
            "/run/gvmd/gvmd.sock",
            "/var/run/gvmd/gvmd.sock",
            "/run/gvmd.sock",
            "/tmp/gvm/gvmd.sock",
        ]
        socket_path = self.credentials.get("gvm_socket_path", "")
        if not socket_path:
            for _s in _SOCKET_CANDIDATES:
                if Path(_s).exists():
                    socket_path = _s
                    break

        cmd = [gvm_cli, "--gmp-username", user, "--gmp-password", password]
        if socket_path:
            cmd += ["socket", "--socketpath", socket_path, "--xml", "<get_version/>"]
        else:
            host = self.credentials.get("gvm_host", "127.0.0.1")
            port = str(self.credentials.get("gvm_port", 9390))
            cmd += ["tls", "--hostname", host, "--port", port, "--xml", "<get_version/>"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
            out = stdout.decode(errors="replace").strip()
            err = stderr.decode(errors="replace").strip()
            if not out:
                if "errno 13" in err.lower() or "permission denied" in err.lower():
                    return ConnectorTestResult(
                        success=False,
                        message="Permission denied — run: sudo chmod 666 /run/gvmd/gvmd.sock  (or restart WSL with: wsl --terminate kali-linux)",
                    )
                return ConnectorTestResult(
                    success=False,
                    message=f"GVM daemon not responding. Run 'sudo gvm-start'. Detail: {err[:200]}",
                )
            import xml.etree.ElementTree as ET
            root = ET.fromstring(out)
            version = root.findtext("version") or "unknown"
            conn_info = f"socket {socket_path}" if socket_path else f"TLS {self.credentials.get('gvm_host', '127.0.0.1')}:{self.credentials.get('gvm_port', 9390)}"
            return ConnectorTestResult(
                success=True,
                message=f"GVM daemon reachable (version {version}) via {conn_info}. Target and credentials are set at scan launch.",
                details={"version": version, "connection": conn_info},
            )
        except asyncio.TimeoutError:
            return ConnectorTestResult(
                success=False,
                message="GVM daemon timed out — is gvmd running? Try: sudo gvm-start",
            )
        except Exception as exc:
            return ConnectorTestResult(
                success=False,
                message=f"Connection failed: {exc}",
            )
