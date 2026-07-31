"""Rapid7 InsightVM vulnerability scanner integration.

Two modes (auto-detected from host):
  Cloud   host contains 'insight.rapid7.com' → pulls asset findings via
          POST /vm/v4/integration/assets  +  per-asset vuln detail
  On-prem any other host                 → launches scan, polls, fetches vulns

Auth: api_key (X-Api-Key) preferred over username+password (avoids MFA).
"""
import asyncio
import httpx
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_CLOUD_BASE = "https://us.api.insight.rapid7.com"

SEV_MAP = {
    "critical": "critical", "severe": "high", "high": "high",
    "moderate": "medium", "medium": "medium",
    "low": "low", "minimal": "low",
    "informational": "info", "info": "info",
}


def _norm_sev(s):
    return SEV_MAP.get(str(s).lower(), "info")


def _is_cloud(host: str) -> bool:
    return "insight.rapid7.com" in host


def _auth_kwargs(creds: dict) -> dict:
    api_key = creds.get("api_key", "").strip()
    if api_key:
        return {"headers": {"X-Api-Key": api_key, "Content-Type": "application/json"}}
    return {"auth": (creds.get("username", ""), creds.get("password", ""))}


async def _run_cloud_scan(creds: dict, config: dict) -> list:
    """Pull asset findings from InsightVM Cloud integration API."""
    auth_kw = _auth_kwargs(creds)
    findings_data = []
    page = 0

    async with httpx.AsyncClient(verify=True, timeout=60) as client:
        # Fetch assets with their vulnerability counts (paginated)
        while True:
            resp = await client.post(
                f"{_CLOUD_BASE}/vm/v4/integration/assets",
                content=f'{{"size": 100, "page": {page}}}'.encode(),
                **auth_kw,
            )
            resp.raise_for_status()
            body = resp.json()
            assets = body.get("data", [])
            if not assets:
                break

            for asset in assets:
                asset_id = asset.get("id", "")
                hostname = (asset.get("host_name") or asset.get("ip") or asset_id)
                ip = asset.get("ip", "")
                os_name = asset.get("os_name", "")

                # Fetch vulnerabilities for this asset
                vresp = await client.post(
                    f"{_CLOUD_BASE}/vm/v4/integration/assets/{asset_id}/vulnerabilities",
                    content=b'{"size": 200}',
                    **auth_kw,
                )
                if vresp.status_code != 200:
                    continue

                for v in vresp.json().get("data", []):
                    sev = _norm_sev(v.get("severity", ""))
                    cve_raw = v.get("cves", "")
                    cve = cve_raw.split(",")[0].strip() if cve_raw else ""
                    cvss = float(v.get("cvss_v3_score") or v.get("cvss_v2_score") or 0)
                    findings_data.append({
                        "title": v.get("title", f"Rapid7 {v.get('id', 'Vulnerability')}"),
                        "description": v.get("description", ""),
                        "severity": sev,
                        "resource_id": hostname,
                        "resource_type": "host",
                        "cve_id": cve,
                        "cvss_score": cvss,
                        "remediation": "",
                        "evidence": {
                            "rapid7_id": v.get("id"),
                            "ip": ip,
                            "os": os_name,
                            "categories": v.get("categories", ""),
                            "risk_score": v.get("risk_score"),
                            "pci_status": v.get("pci_status"),
                        },
                        "status": "open",
                    })

            meta = body.get("metadata", {})
            if (page + 1) >= meta.get("totalPages", 1):
                break
            page += 1

    logger.info("Rapid7 Cloud: %d findings from %d pages of assets", len(findings_data), page + 1)
    return findings_data


async def run_rapid7_scan(scan_id: str, db_url: str, creds: dict, config: dict) -> None:
    from db.database import SessionLocal
    from api.models.models import Scan, ScanStatus, Finding

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        host = creds.get("host", "").rstrip("/")
        api_key = creds.get("api_key", "").strip()
        username = creds.get("username", "")
        password = creds.get("password", "")
        port = config.get("port", 3780)

        if not host:
            raise ValueError("Rapid7 InsightVM requires 'host' in credentials")
        if not api_key and not (username and password):
            raise ValueError("Rapid7 InsightVM requires 'api_key' or 'username'+'password' in credentials")

        auth_kwargs = _auth_kwargs(creds)
        logger.info("Rapid7 scan %s: mode=%s auth=%s", scan_id,
                    "cloud" if _is_cloud(host) else "on-prem",
                    "API Key" if api_key else "Basic Auth")

        if _is_cloud(host):
            findings_data = await _run_cloud_scan(creds, config)
        else:
            site_id = config.get("site_id", "")
            if not site_id:
                raise ValueError("Rapid7 on-prem requires 'site_id' in config")
            base = f"{host}:{port}/api/3"
            findings_data = []
            async with httpx.AsyncClient(verify=False, timeout=60) as client:
                # Launch scan
                launch_resp = await client.post(
                    f"{base}/sites/{site_id}/scans",
                    json={},
                    **auth_kwargs,
                )
                launch_resp.raise_for_status()
                r7_scan_id = launch_resp.json().get("id")

                # Poll for completion (up to 2 hours)
                for _ in range(240):
                    await asyncio.sleep(30)
                    st_resp = await client.get(f"{base}/scans/{r7_scan_id}", **auth_kwargs)
                    st_resp.raise_for_status()
                    status = st_resp.json().get("status", "")
                    if status in ("finished", "stopped", "failed"):
                        break

                # Fetch vulnerabilities (paginated, cap 500)
                page = 0
                while len(findings_data) < 500:
                    vresp = await client.get(
                        f"{base}/scans/{r7_scan_id}/vulnerabilities",
                        params={"page": page, "size": 100},
                        **auth_kwargs,
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
