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
            client_id=scan.client_id,
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

    host = config.get("gvm_host", "127.0.0.1")
    port = str(config.get("gvm_port", 9390))
    user = config.get("gvm_user", "admin")
    password = config.get("gvm_password", "admin")

    async def _gvm(xml: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            gvm_cli, "--gmp-username", user, "--gmp-password", password,
            "socket", "--xml", xml,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=_env(),
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        return stdout.decode(errors="replace")

    # Create target
    create_target = (
        f'<create_target><name>owlet-{target}</name>'
        f'<hosts>{target}</hosts>'
        f'<port_range>T:1-65535</port_range></create_target>'
    )
    resp = await _gvm(create_target)
    import xml.etree.ElementTree as ET
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
