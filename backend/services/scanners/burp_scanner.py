"""Burp Suite Enterprise Edition scanner integration."""
import asyncio
import httpx
import logging
import json
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SEV_MAP = {"high": "high", "medium": "medium", "low": "low", "info": "info", "information": "info"}


def _norm_sev(s):
    return SEV_MAP.get(str(s).lower(), "info")


async def run_burp_scan(scan_id: str, db_url: str, creds: dict, config: dict) -> None:
    from db.database import SessionLocal
    from api.models.models import Scan, ScanStatus, Finding

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        host = creds.get("host", "").rstrip("/")
        api_key = creds.get("api_key", "")
        target_url = config.get("target_url") or config.get("target", "")

        if not host or not api_key:
            raise ValueError("Burp Suite Enterprise requires 'host' and 'api_key' in credentials")
        if not target_url:
            raise ValueError("Burp Suite Enterprise requires 'target_url' in config")

        base = f"{host}/api/v1"
        headers = {"Authorization": api_key, "Content-Type": "application/json"}

        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            # Create scan
            resp = await client.post(f"{base}/scans", headers=headers, json={
                "urls": [target_url],
                "scope": {"include": [{"rule": target_url}]},
            })
            resp.raise_for_status()
            burp_scan_id = resp.json().get("id")

            # Poll for completion (up to 2 hours)
            for _ in range(240):
                await asyncio.sleep(30)
                st = await client.get(f"{base}/scans/{burp_scan_id}", headers=headers)
                st.raise_for_status()
                status = st.json().get("status", "")
                if status in ("succeeded", "failed", "cancelled"):
                    break

            # Fetch issues
            issues_resp = await client.get(f"{base}/scans/{burp_scan_id}/issues", headers=headers)
            issues_resp.raise_for_status()
            issues = issues_resp.json().get("issues", [])

        findings_data = []
        for issue in issues:
            findings_data.append({
                "title": issue.get("name", "Unknown issue"),
                "description": issue.get("description") or issue.get("issue_background") or "",
                "severity": _norm_sev(issue.get("severity", "info")),
                "resource_id": issue.get("origin") or target_url,
                "resource_type": "url",
                "cve_id": "",
                "cvss_score": 0.0,
                "remediation": issue.get("remediation_background") or issue.get("remediation_detail") or "",
                "evidence": {
                    "path": issue.get("path"),
                    "issue_type": issue.get("issue_type"),
                    "confidence": issue.get("confidence"),
                },
                "status": "open",
            })

        for f in findings_data:
            db.add(Finding(scan_id=scan_id, **f))

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = {**(scan.summary or {}), "finding_count": len(findings_data)}
        db.commit()
        logger.info("Burp scan %s completed — %d findings", scan_id, len(findings_data))

    except Exception as exc:
        logger.error("Burp scan %s failed: %s", scan_id, exc, exc_info=True)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:500]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
