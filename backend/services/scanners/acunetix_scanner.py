"""Acunetix Enterprise DAST scanner integration."""
import asyncio
import httpx
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info", "info": "info"}


def _norm_sev(s):
    return SEV_MAP.get(str(s).lower(), "info")


async def run_acunetix_scan(scan_id: str, db_url: str, creds: dict, config: dict) -> None:
    from db.database import SessionLocal
    from api.models.models import Scan, ScanStatus, Finding

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        host = creds.get("host", "").rstrip("/")
        api_key = creds.get("api_key", "")
        port = config.get("port", 3443)
        target_url = config.get("target_url") or config.get("target", "")
        profile_id = config.get("profile_id", "11111111-1111-1111-1111-111111111112")  # Full scan profile

        if not host or not api_key:
            raise ValueError("Acunetix requires 'host' and 'api_key' in credentials")
        if not target_url:
            raise ValueError("Acunetix requires 'target_url' in config")

        base = f"{host}:{port}/api/v1"
        headers = {"X-Auth": api_key, "Content-Type": "application/json"}

        findings_data = []
        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            # Create target
            target_resp = await client.post(
                f"{base}/targets",
                headers=headers,
                json={"address": target_url, "description": f"Aegis-{scan_id[:8]}", "type": "default"},
            )
            target_resp.raise_for_status()
            target_id = target_resp.json().get("target_id")

            # Create scan
            scan_resp = await client.post(
                f"{base}/scans",
                headers=headers,
                json={
                    "profile_id": profile_id,
                    "incremental": False,
                    "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
                    "target": {"target_id": target_id},
                },
            )
            scan_resp.raise_for_status()
            acx_scan_id = scan_resp.headers.get("location", "").split("/")[-1] or scan_resp.json().get("scan_id")

            # Poll for completion (up to 2 hours)
            result_id = None
            for _ in range(240):
                await asyncio.sleep(30)
                st_resp = await client.get(f"{base}/scans/{acx_scan_id}", headers=headers)
                st_resp.raise_for_status()
                scan_data = st_resp.json()
                current_session = scan_data.get("current_session", {}) or {}
                status = current_session.get("status", "")
                if status in ("completed", "aborted", "failed"):
                    result_id = current_session.get("scan_session_id")
                    break

            if result_id:
                # Fetch vulnerabilities
                page = 0
                while len(findings_data) < 500:
                    vresp = await client.get(
                        f"{base}/scans/{acx_scan_id}/results/{result_id}/vulnerabilities",
                        headers=headers,
                        params={"q": "status:open", "l": 100, "c": page * 100},
                    )
                    if vresp.status_code != 200:
                        break
                    data = vresp.json()
                    vulns = data.get("vulnerabilities", [])
                    if not vulns:
                        break
                    for v in vulns:
                        findings_data.append({
                            "title": v.get("vt_name", "Vulnerability"),
                            "description": v.get("description") or "",
                            "severity": _norm_sev(v.get("severity", "info")),
                            "resource_id": v.get("affects_url") or target_url,
                            "resource_type": "url",
                            "cve_id": v.get("vt_id", ""),
                            "cvss_score": float(v.get("cvss3_score") or v.get("cvss2_score") or 0),
                            "remediation": v.get("recommendation") or "",
                            "evidence": {
                                "request": (v.get("request") or "")[:500],
                                "parameter": v.get("affects_detail"),
                                "type": v.get("vuln_type"),
                            },
                            "status": "open",
                        })
                    if len(vulns) < 100:
                        break
                    page += 1

        for f in findings_data:
            db.add(Finding(scan_id=scan_id, **f))

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = {**(scan.summary or {}), "finding_count": len(findings_data)}
        db.commit()
        logger.info("Acunetix scan %s completed — %d findings", scan_id, len(findings_data))

    except Exception as exc:
        logger.error("Acunetix scan %s failed: %s", scan_id, exc, exc_info=True)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:500]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
