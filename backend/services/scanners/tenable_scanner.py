"""Tenable.io vulnerability scanner integration."""
import asyncio
import logging
import json
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SEV_MAP = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


def _norm_sev(sev):
    if isinstance(sev, int):
        return SEV_MAP.get(sev, "info")
    s = str(sev).lower()
    for k in ("critical", "high", "medium", "low"):
        if k in s:
            return k
    return "info"


async def run_tenable_scan(scan_id: str, db_url: str, creds: dict, config: dict) -> None:
    from db.database import SessionLocal
    from api.models.models import Scan, ScanStatus, Finding

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        access_key = creds.get("access_key", "")
        secret_key = creds.get("secret_key", "")
        targets = config.get("targets") or config.get("target", "")
        policy_id = config.get("policy_id")  # optional — Tenable scan policy UUID

        if not access_key or not secret_key:
            raise ValueError("Tenable.io requires access_key and secret_key in credentials")
        if not targets:
            raise ValueError("Tenable.io requires 'targets' in config (IP, CIDR, or hostname)")

        # Run blocking Tenable SDK in thread pool
        findings_data = await asyncio.to_thread(
            _run_tenable_blocking, access_key, secret_key, targets, policy_id, scan_id
        )

        for f in findings_data:
            finding = Finding(scan_id=scan_id, **f)
            db.add(finding)

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = {**(scan.summary or {}), "finding_count": len(findings_data)}
        db.commit()
        logger.info("Tenable scan %s completed — %d findings", scan_id, len(findings_data))

    except Exception as exc:
        logger.error("Tenable scan %s failed: %s", scan_id, exc, exc_info=True)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:500]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def _run_tenable_blocking(access_key, secret_key, targets, policy_id, scan_id):
    from tenable.io import TenableIO
    import time

    tio = TenableIO(access_key, secret_key)

    # Build scan kwargs
    scan_kwargs = dict(
        name=f"Monitara-{scan_id[:8]}",
        targets=[t.strip() for t in str(targets).split(",") if t.strip()],
    )
    if policy_id:
        scan_kwargs["policy_id"] = policy_id

    scan_obj = tio.scans.create(**scan_kwargs)
    scan_id_tio = scan_obj["id"]
    tio.scans.launch(scan_id_tio)

    # Poll up to 2 hours
    for _ in range(240):
        time.sleep(30)
        details = tio.scans.details(scan_id_tio)
        status = details.get("info", {}).get("status", "")
        if status in ("completed", "stopped", "canceled", "aborted"):
            break

    # Fetch vulnerabilities
    results = tio.scans.results(scan_id_tio)
    vulns = results.get("vulnerabilities", [])
    findings = []
    for v in vulns:
        findings.append({
            "title": v.get("plugin_name", "Unknown vulnerability"),
            "description": v.get("plugin_name", ""),
            "severity": _norm_sev(v.get("severity", 0)),
            "resource_id": str(v.get("hostname", "")),
            "resource_type": "host",
            "cve_id": "",
            "cvss_score": float(v.get("score", 0) or 0),
            "remediation": "See Tenable vulnerability details for remediation guidance.",
            "evidence": {
                "plugin_id": v.get("plugin_id"),
                "count": v.get("count"),
                "vuln_index": v.get("vuln_index"),
            },
            "status": "open",
        })
    return findings
