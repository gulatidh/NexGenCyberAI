"""Rapid7 InsightVM vulnerability scanner integration."""
import asyncio
import httpx
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SEV_MAP = {
    "critical": "critical", "severe": "high", "high": "high",
    "moderate": "medium", "medium": "medium",
    "low": "low", "minimal": "low",
    "informational": "info", "info": "info",
}


def _norm_sev(s):
    return SEV_MAP.get(str(s).lower(), "info")


async def run_rapid7_scan(scan_id: str, db_url: str, creds: dict, config: dict) -> None:
    from db.database import SessionLocal
    from api.models.models import Scan, ScanStatus, Finding

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        host = creds.get("host", "").rstrip("/")
        username = creds.get("username", "")
        password = creds.get("password", "")
        site_id = config.get("site_id", "")
        port = config.get("port", 3780)

        if not host or not username or not password:
            raise ValueError("Rapid7 InsightVM requires 'host', 'username', 'password' in credentials")
        if not site_id:
            raise ValueError("Rapid7 InsightVM requires 'site_id' in config")

        base = f"{host}:{port}/api/3"
        auth = (username, password)

        findings_data = []
        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            # Launch scan
            launch_resp = await client.post(
                f"{base}/sites/{site_id}/scans",
                auth=auth,
                json={},
            )
            launch_resp.raise_for_status()
            r7_scan_id = launch_resp.json().get("id")

            # Poll for completion (up to 2 hours)
            for _ in range(240):
                await asyncio.sleep(30)
                st_resp = await client.get(f"{base}/scans/{r7_scan_id}", auth=auth)
                st_resp.raise_for_status()
                status = st_resp.json().get("status", "")
                if status in ("finished", "stopped", "failed"):
                    break

            # Fetch vulnerabilities (paginated, cap 500)
            page = 0
            while len(findings_data) < 500:
                vresp = await client.get(
                    f"{base}/scans/{r7_scan_id}/vulnerabilities",
                    auth=auth,
                    params={"page": page, "size": 100},
                )
                if vresp.status_code != 200:
                    break
                data = vresp.json()
                resources = data.get("resources", [])
                if not resources:
                    break
                for v in resources:
                    severity_score = v.get("severity", 0) or 0
                    if severity_score >= 9:
                        sev = "critical"
                    elif severity_score >= 7:
                        sev = "high"
                    elif severity_score >= 4:
                        sev = "medium"
                    elif severity_score > 0:
                        sev = "low"
                    else:
                        sev = "info"
                    cves = v.get("cves", [])
                    findings_data.append({
                        "title": v.get("title") or v.get("id", "Vulnerability"),
                        "description": v.get("description", {}).get("text", "") if isinstance(v.get("description"), dict) else "",
                        "severity": sev,
                        "resource_id": str(v.get("id", "")),
                        "resource_type": "host",
                        "cve_id": cves[0] if cves else "",
                        "cvss_score": float(v.get("cvssV3", {}).get("score", 0) or v.get("cvssV2", {}).get("score", 0) or 0),
                        "remediation": v.get("solution", {}).get("text", "") if isinstance(v.get("solution"), dict) else "",
                        "evidence": {"rapid7_id": v.get("id"), "categories": v.get("categories", [])},
                        "status": "open",
                    })
                total = data.get("page", {}).get("totalResources", 0)
                if (page + 1) * 100 >= total:
                    break
                page += 1

        for f in findings_data:
            db.add(Finding(scan_id=scan_id, **f))

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = {**(scan.summary or {}), "finding_count": len(findings_data)}
        db.commit()
        logger.info("Rapid7 scan %s completed — %d findings", scan_id, len(findings_data))

    except Exception as exc:
        logger.error("Rapid7 scan %s failed: %s", scan_id, exc, exc_info=True)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:500]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
