"""Snyk security scanner integration (SCA + Code)."""
import asyncio
import httpx
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def _norm_sev(s):
    return SEV_MAP.get(str(s).lower(), "info")


async def run_snyk_scan(scan_id: str, db_url: str, creds: dict, config: dict) -> None:
    from db.database import SessionLocal
    from api.models.models import Scan, ScanStatus, Finding

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        api_key = creds.get("api_key", "")
        org_id = creds.get("org_id") or config.get("org_id", "")

        if not api_key:
            raise ValueError("Snyk requires 'api_key' in credentials")
        if not org_id:
            raise ValueError("Snyk requires 'org_id' in credentials or config")

        headers = {"Authorization": f"token {api_key}", "Content-Type": "application/json"}
        base = "https://api.snyk.io/v1"

        findings_data = []
        async with httpx.AsyncClient(timeout=120) as client:
            # List all projects in the org
            projects_resp = await client.get(f"{base}/org/{org_id}/projects", headers=headers)
            projects_resp.raise_for_status()
            projects = projects_resp.json().get("projects", [])

            # For each project, fetch issues
            for project in projects[:50]:  # cap at 50 projects
                pid = project.get("id")
                pname = project.get("name", "unknown")
                ptype = project.get("type", "")

                issues_resp = await client.post(
                    f"{base}/org/{org_id}/project/{pid}/aggregated-issues",
                    headers=headers,
                    json={"includeDescription": True, "includeIntroducedThrough": False},
                )
                if issues_resp.status_code != 200:
                    continue

                issues = issues_resp.json().get("issues", {})
                vuln_list = issues.get("vulnerabilities", []) + issues.get("licenses", [])

                for v in vuln_list:
                    pkg = v.get("pkgName", "")
                    version = v.get("pkgVersions", [""])[0] if v.get("pkgVersions") else ""
                    identifiers = v.get("identifiers", {})
                    cves = identifiers.get("CVE", [])
                    cvss = v.get("cvssScore", 0) or 0

                    findings_data.append({
                        "title": f"{v.get('title', 'Vulnerability')} — {pkg}@{version}",
                        "description": v.get("description") or v.get("title") or "",
                        "severity": _norm_sev(v.get("severity", "low")),
                        "resource_id": f"{pname}/{pkg}@{version}",
                        "resource_type": "package",
                        "cve_id": cves[0] if cves else "",
                        "cvss_score": float(cvss),
                        "remediation": f"Upgrade {pkg} to version {v.get('fixedIn', ['latest'])[0] if v.get('fixedIn') else 'latest'}",
                        "evidence": {
                            "project": pname,
                            "project_type": ptype,
                            "snyk_id": v.get("id"),
                            "cves": cves,
                            "is_patchable": v.get("isPatchable"),
                        },
                        "status": "open",
                    })

        for f in findings_data:
            db.add(Finding(scan_id=scan_id, **f))

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = {**(scan.summary or {}), "finding_count": len(findings_data)}
        db.commit()
        logger.info("Snyk scan %s completed — %d findings", scan_id, len(findings_data))

    except Exception as exc:
        logger.error("Snyk scan %s failed: %s", scan_id, exc, exc_info=True)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:500]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
