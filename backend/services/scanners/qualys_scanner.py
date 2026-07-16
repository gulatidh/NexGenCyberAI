"""Qualys VMDR scanner integration."""
import asyncio
import httpx
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _norm_sev(score):
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 5:
        return "critical"
    if s == 4:
        return "high"
    if s == 3:
        return "medium"
    if s == 2:
        return "low"
    return "info"


async def run_qualys_scan(scan_id: str, db_url: str, creds: dict, config: dict) -> None:
    from db.database import SessionLocal
    from api.models.models import Scan, ScanStatus, Finding

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        api_url = creds.get("api_url", "https://qualysapi.qualys.com").rstrip("/")
        username = creds.get("username", "")
        password = creds.get("password", "")
        targets = config.get("targets") or config.get("target", "")
        option_id = config.get("option_profile_id", "")

        if not username or not password:
            raise ValueError("Qualys requires 'username' and 'password' in credentials")
        if not targets:
            raise ValueError("Qualys requires 'targets' in config (IPs or CIDR)")

        auth = (username, password)
        headers = {"X-Requested-With": "Monitara"}

        async with httpx.AsyncClient(timeout=120, verify=True) as client:
            # Launch scan
            launch_params = {
                "action": "launch",
                "scan_title": f"Monitara-{scan_id[:8]}",
                "ip": targets,
            }
            if option_id:
                launch_params["option_id"] = option_id
            launch_resp = await client.get(
                f"{api_url}/api/2.0/fo/scan/",
                auth=auth,
                headers=headers,
                params=launch_params,
            )
            launch_resp.raise_for_status()

            # Parse scan reference from XML
            root = ET.fromstring(launch_resp.text)
            scan_ref = ""
            for elem in root.iter("VALUE"):
                val = elem.text or ""
                if val.startswith("scan/"):
                    scan_ref = val
                    break

            if not scan_ref:
                raise ValueError(f"Could not parse scan reference from Qualys response")

            # Poll for completion (up to 2 hours)
            for _ in range(120):
                await asyncio.sleep(60)
                st_resp = await client.get(
                    f"{api_url}/api/2.0/fo/scan/",
                    auth=auth,
                    headers=headers,
                    params={"action": "status", "scan_ref": scan_ref},
                )
                st_root = ET.fromstring(st_resp.text)
                state_elem = st_root.find(".//STATE")
                if state_elem is not None and state_elem.text in ("Finished", "Cancelled", "Error"):
                    break

            # Fetch results
            fetch_resp = await client.get(
                f"{api_url}/api/2.0/fo/scan/",
                auth=auth,
                headers=headers,
                params={"action": "fetch", "scan_ref": scan_ref, "output_format": "CSV"},
            )
            fetch_resp.raise_for_status()
            raw_csv = fetch_resp.text

        findings_data = _parse_qualys_csv(raw_csv)

        for f in findings_data:
            db.add(Finding(scan_id=scan_id, **f))

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = {**(scan.summary or {}), "finding_count": len(findings_data)}
        db.commit()
        logger.info("Qualys scan %s completed — %d findings", scan_id, len(findings_data))

    except Exception as exc:
        logger.error("Qualys scan %s failed: %s", scan_id, exc, exc_info=True)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:500]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def _parse_qualys_csv(csv_text: str) -> list:
    findings = []
    lines = csv_text.splitlines()
    # Skip header lines (Qualys CSV starts with "---..." separators)
    data_lines = [l for l in lines if l and not l.startswith("-") and not l.startswith('"IP"') and not l.startswith("IP")]
    headers = []
    for line in lines:
        if line.startswith("IP") or line.startswith('"IP"'):
            headers = [h.strip().strip('"') for h in line.split(",")]
            break

    for line in data_lines:
        parts = line.split(",")
        if len(parts) < 5:
            continue
        row = dict(zip(headers, [p.strip().strip('"') for p in parts])) if headers else {}
        ip = row.get("IP", parts[0] if parts else "")
        title = row.get("Title", parts[3] if len(parts) > 3 else "Qualys Finding")
        severity = _norm_sev(row.get("Severity", 0))
        cve = row.get("CVE ID", "")
        cvss = float(row.get("CVSS Base", 0) or 0)
        findings.append({
            "title": title,
            "description": row.get("Diagnosis", ""),
            "severity": severity,
            "resource_id": ip,
            "resource_type": "host",
            "cve_id": cve,
            "cvss_score": cvss,
            "remediation": row.get("Solution", ""),
            "evidence": {"qualys_id": row.get("QID", ""), "port": row.get("Port", ""), "protocol": row.get("Protocol", "")},
            "status": "open",
        })
    return findings
