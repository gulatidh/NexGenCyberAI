"""Local scanner execution service.

Called by scans.py when a tool is configured to run locally instead of
dispatching to GitHub Actions. Each scanner runs as a subprocess, parses
output, and writes findings directly to the DB.
"""

import asyncio, json, os, shutil, subprocess, tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from db.database import SessionLocal
from api.models.models import Finding, Scan, ScanStatus, Severity

OWLET_BIN = Path.home() / ".owlet" / "bin"


def _env() -> dict:
    e = os.environ.copy()
    home_bin = str(Path.home() / ".local" / "bin")
    e["PATH"] = f"{OWLET_BIN}{os.pathsep}{home_bin}{os.pathsep}{e.get('PATH', '')}"
    return e


async def run_local_scan(scan_id: str, tool: str, config: dict) -> None:
    """BackgroundTask entry point — routes to the correct scanner implementation."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        scan.status = ScanStatus.RUNNING
        scan.progress_message = f"Running {tool} locally…"
        db.commit()

        try:
            if tool == "nmap":
                findings = await _nmap(config.get("target", ""))
            elif tool == "gitleaks":
                findings = await _gitleaks(config.get("repo_url") or config.get("target", ""))
            elif tool == "trivy":
                findings = await _trivy(config.get("image") or config.get("target", ""))
            elif tool == "trufflehog":
                findings = await _trufflehog(config.get("repo_url") or config.get("target", ""))
            elif tool == "semgrep":
                findings = await _semgrep(config.get("repo_url") or config.get("target", ""))
            elif tool == "openvas":
                findings = await _openvas(config.get("target", ""), config)
            elif tool == "checkov":
                findings = await _checkov(config.get("repo_url") or config.get("target", ""))
            elif tool == "sslyze":
                findings = await _sslyze(config.get("target", ""))
            elif tool == "codeql":
                findings = await _codeql(config.get("repo_url") or config.get("target", ""))
            elif tool == "owasp_dc":
                findings = await _owasp_dc(config.get("repo_url") or config.get("target", ""))
            elif tool == "zap":
                findings = await _zap(config.get("target", ""), config)
            else:
                findings = []

            _write_findings(db, scan, findings)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.progress_message = None
            db.commit()
        except Exception as exc:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:500]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def _write_findings(db, scan, findings: List[dict]) -> None:
    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    for f in findings:
        sev = sev_map.get((f.get("severity") or "info").lower(), Severity.INFO)
        db.add(Finding(
            scan_id=scan.id,
            title=(f.get("title") or "Finding")[:500],
            description=f.get("description") or "",
            severity=sev,
            resource_id=f.get("resource_id") or "",
            resource_type=f.get("resource_type") or "host",
            control_id=f.get("control_id") or "",
            framework=f.get("framework") or "nist_csf",
            remediation=f.get("remediation") or "",
            evidence=json.dumps(f.get("evidence") or {}),
            cve_id=f.get("cve_id") or "",
            cvss_score=float(f.get("cvss_score") or 0),
            status="open",
        ))
    scan.total_findings = len(findings)
    db.commit()


# ── Nmap ──────────────────────────────────────────────────────────────────────

async def _nmap(target: str) -> List[dict]:
    if not target:
        return []
    proc = await asyncio.create_subprocess_exec(
        "nmap", "-Pn", "-sV", "--top-ports", "1000",
        "--script=default,safe", "--script-timeout", "30s",
        "--host-timeout", "5m", "-oX", "-", target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_env(),
    )
    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=360)
    return _parse_nmap_xml(stdout.decode(errors="replace"), target)


def _parse_nmap_xml(xml: str, target: str) -> List[dict]:
    import xml.etree.ElementTree as ET
    HIGH_RISK_PORTS = {21, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 6379, 27017}
    MED_RISK_PORTS = {22, 80, 161, 389, 443, 8080, 8443}
    findings = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    for host in root.findall("host"):
        addr_el = host.find("address")
        ip = addr_el.get("addr", "") if addr_el is not None else ""
        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name", "") if hn_el is not None else ""
        resource = hostname or ip or target
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            pnum = int(port.get("portid", "0"))
            proto = port.get("protocol", "tcp")
            svc_el = port.find("service")
            svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            product = (svc_el.get("product", "") if svc_el is not None else "")
            version = (svc_el.get("version", "") if svc_el is not None else "")
            banner = " ".join(x for x in (product, version) if x)
            if pnum in HIGH_RISK_PORTS:
                sev = "high"
            elif pnum in MED_RISK_PORTS:
                sev = "medium"
            else:
                sev = "low"
            title = f"{svc_name.upper()} exposed on {pnum}/{proto}"
            if banner:
                title += f" ({banner})"
            findings.append({
                "title": title,
                "description": (
                    f"Nmap detected {svc_name} listening on {resource}:{pnum}/{proto}."
                    + (f" Service banner: {banner}." if banner else "")
                ),
                "severity": sev,
                "resource_id": f"{resource}:{pnum}/{proto}",
                "resource_type": "network/host",
                "control_id": "SC-7",
                "framework": "nist_csf",
                "remediation": (
                    "Verify this port must be externally reachable. "
                    "Restrict using firewall rules if not required."
                ),
                "evidence": {
                    "ip": ip, "hostname": hostname,
                    "port": pnum, "protocol": proto, "service": svc_name,
                },
                "cve_id": "",
                "cvss_score": 0,
            })
    return findings


# ── Gitleaks ──────────────────────────────────────────────────────────────────

async def _gitleaks(target: str) -> List[dict]:
    if not target:
        return []
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        report = tf.name
    try:
        proc = await asyncio.create_subprocess_exec(
            "gitleaks", "detect", "--source", target,
            "--report-format", "json", "--report-path", report,
            "--no-banner", "--exit-code", "0",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_env(),
        )
        await asyncio.wait_for(proc.communicate(), timeout=300)
        try:
            with open(report) as f:
                leaks = json.load(f) or []
        except Exception:
            leaks = []
    finally:
        try:
            os.unlink(report)
        except Exception:
            pass
    findings = []
    for leak in leaks:
        findings.append({
            "title": f"Secret detected — {leak.get('RuleID', 'unknown rule')}",
            "description": (
                f"Gitleaks found a secret in {leak.get('File', '?')} "
                f"at line {leak.get('StartLine', '?')}. "
                f"Rule: {leak.get('Description', '')}"
            ),
            "severity": "high",
            "resource_id": leak.get("File", ""),
            "resource_type": "code_file",
            "control_id": "SI-12",
            "framework": "nist_csf",
            "remediation": (
                "Rotate the exposed credential immediately. "
                "Remove from git history using git-filter-repo or BFG Repo Cleaner."
            ),
            "evidence": {
                "commit": leak.get("Commit", ""),
                "author": leak.get("Author", ""),
                "match": (leak.get("Match") or "")[:200],
            },
            "cve_id": "",
            "cvss_score": 0,
        })
    return findings


# ── Trivy ─────────────────────────────────────────────────────────────────────

async def _trivy(target: str) -> List[dict]:
    if not target:
        return []
    is_image = "/" in target or ":" in target
    cmd = ["trivy", "image" if is_image else "fs",
           "--format", "json", "--quiet", target]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_env(),
    )
    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
    try:
        data = json.loads(stdout)
    except Exception:
        return []
    SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    findings = []
    results = data if isinstance(data, list) else (data.get("Results") or [])
    for result in results:
        for vuln in (result.get("Vulnerabilities") or []):
            cvss_data = (vuln.get("CVSS") or {})
            nvd_v3 = (cvss_data.get("nvd") or {}).get("V3Score") or 0
            findings.append({
                "title": f"{vuln.get('VulnerabilityID', '')} in {vuln.get('PkgName', '')}",
                "description": vuln.get("Description") or vuln.get("Title") or "",
                "severity": SEV.get(vuln.get("Severity", ""), "info"),
                "resource_id": f"{result.get('Target', '')}/{vuln.get('PkgName', '')}",
                "resource_type": "package",
                "control_id": vuln.get("VulnerabilityID", ""),
                "framework": "nist_csf",
                "remediation": (
                    f"Update {vuln.get('PkgName', '')} "
                    f"to {vuln.get('FixedVersion', 'latest')}."
                ),
                "evidence": {
                    "installed": vuln.get("InstalledVersion", ""),
                    "fixed": vuln.get("FixedVersion", ""),
                    "target": result.get("Target", ""),
                },
                "cve_id": vuln.get("VulnerabilityID", ""),
                "cvss_score": nvd_v3,
            })
    return findings


# ── TruffleHog ────────────────────────────────────────────────────────────────

async def _trufflehog(target: str) -> List[dict]:
    if not target:
        return []
    proc = await asyncio.create_subprocess_exec(
        "trufflehog", "filesystem", "--json", "--no-update", target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_env(),
    )
    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
    findings = []
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        fs = (d.get("SourceMetadata") or {}).get("Data", {}).get("Filesystem", {})
        findings.append({
            "title": f"Secret found — {d.get('DetectorName', 'unknown')}",
            "description": (
                f"TruffleHog detected a {d.get('DetectorName', '')} secret "
                f"in {fs.get('file', '?')} at line {fs.get('line', '?')}."
            ),
            "severity": "high",
            "resource_id": fs.get("file", ""),
            "resource_type": "code_file",
            "control_id": "SI-12",
            "framework": "nist_csf",
            "remediation": "Rotate the exposed secret immediately.",
            "evidence": {
                "detector": d.get("DetectorName", ""),
                "verified": d.get("Verified", False),
            },
            "cve_id": "",
            "cvss_score": 0,
        })
    return findings


# ── Semgrep ───────────────────────────────────────────────────────────────────

async def _semgrep(target: str) -> List[dict]:
    if not target:
        return []
    proc = await asyncio.create_subprocess_exec(
        "semgrep", "scan", "--config=auto", "--json", "--quiet", target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_env(),
    )
    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
    try:
        data = json.loads(stdout)
    except Exception:
        return []
    SEV_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    findings = []
    for r in (data.get("results") or []):
        extra = r.get("extra") or {}
        check_id = r.get("check_id") or ""
        sev_label = (extra.get("severity") or "INFO").upper()
        findings.append({
            "title": check_id.split(".")[-1].replace("-", " ").title() or "Semgrep finding",
            "description": extra.get("message", ""),
            "severity": SEV_MAP.get(sev_label, "low"),
            "resource_id": f"{r.get('path', '')}:{(r.get('start') or {}).get('line', '')}",
            "resource_type": "code_file",
            "control_id": check_id,
            "framework": "nist_csf",
            "remediation": extra.get("fix") or "Review and remediate the finding.",
            "evidence": {
                "path": r.get("path", ""),
                "line": (r.get("start") or {}).get("line", ""),
                "rule": check_id,
            },
            "cve_id": "",
            "cvss_score": 0,
        })
    return findings


# ── OpenVAS / GVM ─────────────────────────────────────────────────────────────

async def _openvas(target: str, config: dict) -> List[dict]:
    """Connect to local GVM daemon and run a scan against target."""
    if not target:
        return []
    gvm_cli = shutil.which("gvm-cli", path=_env()["PATH"])
    if not gvm_cli:
        raise RuntimeError(
            "gvm-cli not found — install openvas and run 'sudo gvm-setup' first"
        )

    user     = config.get("gvm_user", "admin")
    password = config.get("gvm_password", "admin")

    # Authenticated scan credentials (optional)
    ssh_user        = config.get("ssh_user", "")
    ssh_password    = config.get("ssh_password", "")
    ssh_private_key = config.get("ssh_private_key", "")
    smb_user        = config.get("smb_user", "")
    smb_password    = config.get("smb_password", "")

    # Find the GVM Unix socket — gvmd puts it in one of these locations
    _SOCKET_CANDIDATES = [
        "/run/gvmd/gvmd.sock",
        "/var/run/gvmd/gvmd.sock",
        "/run/gvmd.sock",
        "/tmp/gvm/gvmd.sock",
    ]
    socket_path = config.get("gvm_socket_path", "")
    if not socket_path:
        for _s in _SOCKET_CANDIDATES:
            if Path(_s).exists():
                socket_path = _s
                break

    async def _gvm(xml: str) -> str:
        cmd = [gvm_cli, "--gmp-username", user, "--gmp-password", password]
        if socket_path:
            cmd += ["socket", "--socketpath", socket_path, "--xml", xml]
        else:
            # Fall back to TLS (older GVM installs)
            host = config.get("gvm_host", "127.0.0.1")
            port = str(config.get("gvm_port", 9390))
            cmd += ["tls", "--hostname", host, "--port", port, "--xml", xml]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=_env(),
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        out = stdout.decode(errors="replace").strip()
        if not out:
            err = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"gvm-cli returned no output. stderr: {err[:300]}")
        return out

    import xml.etree.ElementTree as ET

    # Verify connection before proceeding
    try:
        ver_resp = await _gvm("<get_version/>")
        ET.fromstring(ver_resp)  # parse check
    except RuntimeError:
        raise
    except Exception as _ve:
        raise RuntimeError(
            f"Cannot connect to GVM daemon. "
            f"Run 'sudo gvm-start' on Kali and check the socket exists. Detail: {_ve}"
        )

    # Create SSH credential if provided
    ssh_cred_id = ""
    if ssh_user and (ssh_password or ssh_private_key):
        if ssh_private_key:
            cred_xml = (
                f'<create_credential><name>owlet-ssh-{target}</name>'
                f'<type>usk</type>'
                f'<login>{ssh_user}</login>'
                f'<key><private>{ssh_private_key}</private></key>'
                f'</create_credential>'
            )
        else:
            cred_xml = (
                f'<create_credential><name>owlet-ssh-{target}</name>'
                f'<type>up</type>'
                f'<login>{ssh_user}</login>'
                f'<password>{ssh_password}</password>'
                f'</create_credential>'
            )
        resp = await _gvm(cred_xml)
        try:
            ssh_cred_id = ET.fromstring(resp).get("id", "")
        except Exception:
            pass

    # Create SMB credential if provided
    smb_cred_id = ""
    if smb_user and smb_password:
        cred_xml = (
            f'<create_credential><name>owlet-smb-{target}</name>'
            f'<type>up</type>'
            f'<login>{smb_user}</login>'
            f'<password>{smb_password}</password>'
            f'</create_credential>'
        )
        resp = await _gvm(cred_xml)
        try:
            smb_cred_id = ET.fromstring(resp).get("id", "")
        except Exception:
            pass

    # Create target — attach credentials if we have them
    ssh_cred_block = f'<ssh_credential id="{ssh_cred_id}"/>' if ssh_cred_id else ""
    smb_cred_block = f'<smb_credential id="{smb_cred_id}"/>' if smb_cred_id else ""
    create_target = (
        f'<create_target><name>owlet-{target}</name>'
        f'<hosts>{target}</hosts>'
        f'<port_range>T:1-65535</port_range>'
        f'{ssh_cred_block}{smb_cred_block}'
        f'</create_target>'
    )
    resp = await _gvm(create_target)
    try:
        target_id = ET.fromstring(resp).get("id", "")
    except Exception:
        raise RuntimeError(f"Failed to create GVM target: {resp[:200]}")

    # Create task with Full and Fast config
    create_task = (
        f'<create_task><name>owlet-scan-{target}</name>'
        f'<config id="daba56c8-73ec-11df-a475-002264764cea"/>'
        f'<target id="{target_id}"/></create_task>'
    )
    resp = await _gvm(create_task)
    try:
        task_id = ET.fromstring(resp).get("id", "")
    except Exception:
        raise RuntimeError(f"Failed to create GVM task: {resp[:200]}")

    # Start task
    await _gvm(f'<start_task task_id="{task_id}"/>')

    # Poll until done (max 2 hours)
    for _ in range(240):
        await asyncio.sleep(30)
        resp = await _gvm(f'<get_tasks task_id="{task_id}"/>')
        try:
            root = ET.fromstring(resp)
            status = root.findtext(".//status") or ""
            progress = root.findtext(".//progress") or "0"
            if status in ("Done", "Stopped", "Error", "Failed"):
                break
        except Exception:
            pass

    # Fetch report
    resp = await _gvm(f'<get_reports filter="task_id={task_id}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"/>')
    return _parse_openvas_report(resp, target)


def _parse_openvas_report(xml: str, target: str) -> List[dict]:
    import xml.etree.ElementTree as ET
    SEV = {"High": "high", "Medium": "medium", "Low": "low", "Log": "info"}
    findings = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    for result in root.findall(".//result"):
        name = result.findtext("name") or "OpenVAS finding"
        desc = result.findtext("description") or ""
        host = result.findtext("host") or target
        port = result.findtext("port") or ""
        threat = result.findtext("threat") or "Low"
        cvss = result.findtext(".//cvss_base") or "0"
        cve_el = result.find(".//cve")
        cve_id = cve_el.text.strip() if cve_el is not None and cve_el.text else ""
        findings.append({
            "title": name,
            "description": desc,
            "severity": SEV.get(threat, "info"),
            "resource_id": f"{host}:{port}" if port else host,
            "resource_type": "network/host",
            "control_id": cve_id or "SC-7",
            "framework": "nist_csf",
            "remediation": result.findtext("solution") or "Refer to vendor advisory.",
            "evidence": {"host": host, "port": port, "threat": threat},
            "cve_id": cve_id,
            "cvss_score": float(cvss) if cvss else 0,
        })
    return findings


# ── Checkov ───────────────────────────────────────────────────────────────────

async def _checkov(target: str) -> List[dict]:
    if not target:
        return []
    proc = await asyncio.create_subprocess_exec(
        "checkov", "-d", target, "--output", "json", "--quiet",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_env(),
    )
    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
    SEV_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    findings = []
    try:
        raw = json.loads(stdout.decode(errors="replace") or "[]")
    except Exception:
        return []
    results_list = raw if isinstance(raw, list) else [raw]
    for block in results_list:
        for check in (block.get("results", {}).get("failed_checks") or []):
            chk = check.get("check") or {}
            sev_label = (chk.get("severity") or "LOW").upper()
            file_path = check.get("file_path") or ""
            line = (check.get("file_line_range") or [0])[0]
            findings.append({
                "title": chk.get("name") or check.get("check_id") or "Checkov finding",
                "description": f"Checkov rule {check.get('check_id', '')} failed on {file_path}",
                "severity": SEV_MAP.get(sev_label, "info"),
                "resource_id": f"{file_path}:{line}",
                "resource_type": "code_file",
                "control_id": check.get("check_id") or "",
                "framework": "nist_csf",
                "remediation": "Refer to Checkov documentation for this rule.",
                "evidence": {"resource": check.get("resource", ""), "file": file_path, "line": line},
                "cve_id": "",
                "cvss_score": 0,
            })
    return findings


# ── SSLyze ────────────────────────────────────────────────────────────────────

async def _sslyze(target: str) -> List[dict]:
    if not target:
        return []
    proc = await asyncio.create_subprocess_exec(
        "sslyze", "--json_out=-", target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_env(),
    )
    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    try:
        data = json.loads(stdout.decode(errors="replace"))
    except Exception:
        return []
    findings = []
    results = (data.get("server_scan_results") or [])
    if not results:
        return []
    scan_result = results[0].get("scan_result") or {}

    def _ciphers(key: str) -> list:
        return (scan_result.get(key) or {}).get("result", {}).get("accepted_cipher_suites") or []

    checks = [
        ("ssl_2_0_cipher_suites", "critical", "SSLv2 Enabled", "Disable SSLv2 immediately — it is cryptographically broken."),
        ("ssl_3_0_cipher_suites", "critical", "SSLv3 Enabled", "Disable SSLv3 — vulnerable to POODLE attack."),
        ("tls_1_0_cipher_suites", "high", "TLS 1.0 Enabled", "Disable TLS 1.0 — deprecated, vulnerable to BEAST/POODLE."),
        ("tls_1_1_cipher_suites", "high", "TLS 1.1 Enabled", "Disable TLS 1.1 — deprecated by RFC 8996."),
    ]
    for key, sev, title, remediation in checks:
        if _ciphers(key):
            findings.append({
                "title": title,
                "description": f"{title} detected on {target}.",
                "severity": sev,
                "resource_id": target,
                "resource_type": "tls/ssl",
                "control_id": "SC-8",
                "framework": "nist_csf",
                "remediation": remediation,
                "evidence": {"target": target, "check": key},
                "cve_id": "",
                "cvss_score": 0,
            })

    heartbleed = (scan_result.get("heartbleed") or {}).get("result", {})
    if heartbleed.get("is_vulnerable_to_heartbleed"):
        findings.append({
            "title": "Heartbleed Vulnerability (CVE-2014-0160)",
            "severity": "critical",
            "description": f"Server at {target} is vulnerable to Heartbleed.",
            "resource_id": target, "resource_type": "tls/ssl", "control_id": "SC-8",
            "framework": "nist_csf",
            "remediation": "Upgrade OpenSSL to 1.0.1g or later. Reissue all TLS certificates.",
            "evidence": {"target": target}, "cve_id": "CVE-2014-0160", "cvss_score": 7.5,
        })

    robot = (scan_result.get("robot") or {}).get("result", {}).get("robot_result") or ""
    if robot in ("VULNERABLE_WEAK_ORACLE", "VULNERABLE_STRONG_ORACLE"):
        findings.append({
            "title": "ROBOT Attack Vulnerability",
            "severity": "high",
            "description": f"Server at {target} is vulnerable to ROBOT (Return Of Bleichenbacher's Oracle Threat).",
            "resource_id": target, "resource_type": "tls/ssl", "control_id": "SC-8",
            "framework": "nist_csf",
            "remediation": "Disable RSA key exchange cipher suites. Use ECDHE for forward secrecy.",
            "evidence": {"target": target, "robot_result": robot}, "cve_id": "", "cvss_score": 0,
        })

    return findings


# ── CodeQL ────────────────────────────────────────────────────────────────────

async def _codeql(repo_url: str, language: str = "") -> List[dict]:
    if not repo_url:
        return []
    # Prefer the explicit ~/.owlet/bin/codeql/codeql path (full bundle with query packs)
    _owlet_codeql = Path.home() / ".owlet" / "bin" / "codeql" / "codeql"
    codeql_bin = (
        str(_owlet_codeql) if _owlet_codeql.exists()
        else shutil.which("codeql", path=_env()["PATH"])
    )
    if not codeql_bin or not Path(codeql_bin).exists():
        raise RuntimeError(
            "CodeQL CLI not found — go to Settings → Local Runner and click Install next to CodeQL, "
            "or re-run setup.sh on Kali."
        )

    with tempfile.TemporaryDirectory() as base:
        src = os.path.join(base, "src")
        db = os.path.join(base, "db")
        sarif = os.path.join(base, "results.sarif")

        clone = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth=1", repo_url, src,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(clone.communicate(), timeout=300)

        if not language:
            src_path = Path(src)
            if list(src_path.rglob("*.py")):
                language = "python"
            elif list(src_path.rglob("*.js")) or list(src_path.rglob("*.ts")):
                language = "javascript"
            elif list(src_path.rglob("*.java")):
                language = "java"
            elif list(src_path.rglob("*.cs")):
                language = "csharp"
            elif list(src_path.rglob("*.go")):
                language = "go"
            elif list(src_path.rglob("*.rb")):
                language = "ruby"
            elif list(src_path.rglob("*.cpp")) or list(src_path.rglob("*.c")):
                language = "cpp"
            else:
                language = "python"

        create = await asyncio.create_subprocess_exec(
            codeql_bin, "database", "create", db,
            f"--language={language}", f"--source-root={src}", "--overwrite",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=_env(),
        )
        await asyncio.wait_for(create.communicate(), timeout=1800)

        suite = f"codeql/{language}-queries:codeql-suites/{language}-security-and-quality.qls"
        analyze = await asyncio.create_subprocess_exec(
            codeql_bin, "database", "analyze", db,
            "--format=sarif-latest", f"--output={sarif}", suite,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=_env(),
        )
        await asyncio.wait_for(analyze.communicate(), timeout=1800)

        try:
            with open(sarif) as f:
                data = json.load(f)
        except Exception:
            return []

    SEV_MAP = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
    findings = []
    for run in (data.get("runs") or []):
        for result in (run.get("results") or []):
            loc = ((result.get("locations") or [{}])[0]
                   .get("physicalLocation") or {})
            uri = (loc.get("artifactLocation") or {}).get("uri") or ""
            line = (loc.get("region") or {}).get("startLine") or 0
            level = result.get("level") or "warning"
            findings.append({
                "title": result.get("ruleId") or "CodeQL finding",
                "description": (result.get("message") or {}).get("text") or "",
                "severity": SEV_MAP.get(level, "medium"),
                "resource_id": f"{uri}:{line}",
                "resource_type": "code_file",
                "control_id": result.get("ruleId") or "",
                "framework": "nist_csf",
                "remediation": "Review CodeQL rule documentation for remediation guidance.",
                "evidence": {"uri": uri, "line": line, "rule": result.get("ruleId")},
                "cve_id": "",
                "cvss_score": 0,
            })
    return findings


# ── OWASP Dependency-Check ────────────────────────────────────────────────────

async def _owasp_dc(repo_url: str) -> List[dict]:
    if not repo_url:
        return []
    dc_sh = (
        str(Path.home() / ".owlet" / "bin" / "dependency-check.sh")
        or shutil.which("dependency-check.sh", path=_env()["PATH"])
    )
    if not dc_sh or not Path(dc_sh).exists():
        raise RuntimeError(
            "dependency-check.sh not found — download from https://github.com/jeremylong/DependencyCheck/releases"
        )

    with tempfile.TemporaryDirectory() as base:
        src = os.path.join(base, "src")
        out = os.path.join(base, "report")
        os.makedirs(out)

        clone = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth=1", repo_url, src,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(clone.communicate(), timeout=300)

        proc = await asyncio.create_subprocess_exec(
            dc_sh, "--scan", src, "--format", "JSON", "--out", out, "--noupdate",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=_env(),
        )
        await asyncio.wait_for(proc.communicate(), timeout=1800)

        report_path = os.path.join(out, "dependency-check-report.json")
        try:
            with open(report_path) as f:
                data = json.load(f)
        except Exception:
            return []

    SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    findings = []
    for dep in (data.get("dependencies") or []):
        fname = dep.get("fileName") or ""
        for vuln in (dep.get("vulnerabilities") or []):
            cve_id = vuln.get("name") or ""
            cvss3 = (vuln.get("cvssv3") or {})
            findings.append({
                "title": f"{cve_id} in {fname}" if cve_id else f"Vulnerability in {fname}",
                "description": vuln.get("description") or "",
                "severity": SEV_MAP.get((vuln.get("severity") or "").upper(), "info"),
                "resource_id": fname,
                "resource_type": "package",
                "control_id": cve_id or "RA-5",
                "framework": "nist_csf",
                "remediation": "Update the affected dependency to a patched version.",
                "evidence": {
                    "fileName": fname,
                    "cvssv3_score": cvss3.get("baseScore"),
                    "cvssv3_vector": cvss3.get("vectorString"),
                },
                "cve_id": cve_id,
                "cvss_score": float(cvss3.get("baseScore") or 0),
            })
    return findings


# ── OWASP ZAP (local daemon) ──────────────────────────────────────────────────

async def _zap(target: str, config: dict) -> List[dict]:
    if not target:
        return []
    zap_bin = (
        shutil.which("zap.sh", path=_env()["PATH"])
        or ("/usr/share/zaproxy/zap.sh" if Path("/usr/share/zaproxy/zap.sh").exists() else None)
        or str(Path.home() / ".owlet" / "bin" / "zap.sh")
    )
    if not zap_bin or not Path(zap_bin).exists():
        raise RuntimeError("zap.sh not found — install OWASP ZAP via 'sudo apt install zaproxy'")

    profile = config.get("profile") or "baseline"
    zap_port = 8090
    zap_base = f"http://127.0.0.1:{zap_port}"

    proc = await asyncio.create_subprocess_exec(
        zap_bin, "-daemon", f"-port={zap_port}", "-host", "127.0.0.1",
        "-config", "api.disablekey=true",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        env=_env(),
    )

    def _get(path: str) -> dict:
        import urllib.request as _ur
        with _ur.urlopen(f"{zap_base}{path}", timeout=10) as r:
            return json.loads(r.read())

    def _post(path: str, params: dict) -> dict:
        import urllib.request as _ur, urllib.parse as _up
        data = _up.urlencode(params).encode()
        req = _ur.Request(f"{zap_base}{path}", data=data)
        with _ur.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    try:
        for _ in range(60):
            await asyncio.sleep(2)
            try:
                _get("/JSON/core/view/version/")
                break
            except Exception:
                pass

        _post("/JSON/spider/action/scan/", {"url": target, "recurse": "true"})
        for _ in range(120):
            await asyncio.sleep(5)
            status = _get("/JSON/spider/view/status/").get("status") or "0"
            if status == "100":
                break

        if profile == "active":
            _post("/JSON/ascan/action/scan/", {"url": target, "recurse": "true"})
            for _ in range(360):
                await asyncio.sleep(10)
                status = _get("/JSON/ascan/view/status/").get("status") or "0"
                if status == "100":
                    break

        alerts_resp = _get(f"/JSON/core/view/alerts/?baseurl={target}&start=0&count=1000")
        alerts = alerts_resp.get("alerts") or []
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

    RISK_MAP = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
    findings = []
    for alert in alerts:
        cwe = alert.get("cweid") or "0"
        findings.append({
            "title": alert.get("name") or "ZAP alert",
            "description": alert.get("description") or "",
            "severity": RISK_MAP.get(alert.get("risk") or "Informational", "info"),
            "resource_id": alert.get("url") or target,
            "resource_type": "web/url",
            "control_id": f"CWE-{cwe}" if cwe != "0" else "SA-11",
            "framework": "nist_csf",
            "remediation": alert.get("solution") or "Review the ZAP alert for remediation guidance.",
            "evidence": {
                "url": alert.get("url"), "evidence": (alert.get("evidence") or "")[:500],
                "wasc_id": alert.get("wascid"),
            },
            "cve_id": "",
            "cvss_score": 0,
        })
    return findings
