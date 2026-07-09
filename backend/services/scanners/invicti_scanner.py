"""Invicti (ex-Netsparker) DAST scanner integration."""
import asyncio
import httpx
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SEV_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "information": "info", "bestpractice": "info",
}


def _norm_sev(s):
    return SEV_MAP.get(str(s).lower().replace(" ", ""), "info")


async def run_invicti_scan(scan_id: str, db_url: str, creds: dict, config: dict) -> None:
    from db.database import SessionLocal
    from api.models.models import Scan, ScanStatus, Finding

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        api_url = creds.get("api_url", "https://www.invicti.com/api/1.0").rstrip("/")
        api_token = creds.get("api_token", "")
        username = creds.get("username", "")
        target_url = config.get("target_url") or config.get("target", "")
        profile_id = config.get("profile_id", "")

        if not api_token:
            raise ValueError("Invicti requires 'api_token' in credentials")
        if not target_url:
            raise ValueError("Invicti requires 'target_url' in config")

        import base64
        token_b64 = base64.b64encode(f"{username}:{api_token}".encode()).decode() if username else base64.b64encode(f":{api_token}".encode()).decode()
        headers = {"Authorization": f"Basic {token_b64}", "Content-Type": "application/json"}

        findings_data = []
        async with httpx.AsyncClient(timeout=60) as client:
            # Create and launch scan
            body = {"TargetUri": target_url, "IsScheduled": False}
            if profile_id:
                body["ProfileId"] = profile_id
            launch_resp = await client.post(f"{api_url}/scans/new-with-url", headers=headers, json=body)
            launch_resp.raise_for_status()
            invicti_scan_id = launch_resp.json().get("Id") or launch_resp.json().get("id")

            # Poll (up to 2 hours)
            for _ in range(240):
                await asyncio.sleep(30)
                st_resp = await client.get(f"{api_url}/scans/{invicti_scan_id}", headers=headers)
                st_resp.raise_for_status()
                state = st_resp.json().get("State", "")
                if state in ("Complete", "Failed", "Stopped", "Cancelled"):
                    break

            # Fetch vulnerabilities (paginated)
            page = 1
            while len(findings_data) < 500:
                vresp = await client.get(
                    f"{api_url}/scans/{invicti_scan_id}/issues",
                    headers=headers,
                    params={"page": page, "pageSize": 100},
                )
                if vresp.status_code != 200:
                    break
                data = vresp.json()
                issues = data.get("Items") or data.get("issues") or []
                if not issues:
                    break
                for issue in issues:
                    findings_data.append({
                        "title": issue.get("Name") or issue.get("Type", "Vulnerability"),
                        "description": issue.get("Description") or issue.get("Impact") or "",
                        "severity": _norm_sev(issue.get("Severity") or issue.get("severity", "info")),
                        "resource_id": issue.get("Url") or target_url,
                        "resource_type": "url",
                        "cve_id": issue.get("CvssVector", ""),
                        "cvss_score": float(issue.get("CvssScore") or 0),
                        "remediation": issue.get("RemedialProcedure") or issue.get("ActionsToTake") or "",
                        "evidence": {
                            "http_request": issue.get("HttpRequest"),
                            "http_response": (issue.get("HttpResponse") or "")[:500],
                            "classification": issue.get("Classification"),
                        },
                        "status": "open",
                    })
                if len(issues) < 100:
                    break
                page += 1

        for f in findings_data:
            db.add(Finding(scan_id=scan_id, **f))

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = {**(scan.summary or {}), "finding_count": len(findings_data)}
        db.commit()
        logger.info("Invicti scan %s completed — %d findings", scan_id, len(findings_data))

    except Exception as exc:
        logger.error("Invicti scan %s failed: %s", scan_id, exc, exc_info=True)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:500]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
