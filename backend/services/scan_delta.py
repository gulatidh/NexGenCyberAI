"""Compute finding-level diff between two scans for the same client."""
import hashlib
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from api.models.models import Finding, Scan, ScanDelta


def _fingerprint(title: str, resource_id: Optional[str]) -> str:
    key = f"{(title or '').strip().lower()}|{(resource_id or '').strip().lower()}"
    return hashlib.md5(key.encode()).hexdigest()


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        "resource_id": f.resource_id,
        "resource_type": f.resource_type,
        "control_id": f.control_id,
    }


def compute_delta(scan_a_id: str, scan_b_id: str, client_id: str, db: Session) -> dict:
    raw_a = db.query(Finding).filter(Finding.scan_id == scan_a_id).all()
    raw_b = db.query(Finding).filter(Finding.scan_id == scan_b_id).all()

    map_a: Dict[str, Finding] = {_fingerprint(f.title, f.resource_id): f for f in raw_a}
    map_b: Dict[str, Finding] = {_fingerprint(f.title, f.resource_id): f for f in raw_b}

    fps_a, fps_b = set(map_a), set(map_b)
    new_fps = fps_b - fps_a
    resolved_fps = fps_a - fps_b
    common_fps = fps_a & fps_b

    new_findings = [_finding_to_dict(map_b[fp]) for fp in new_fps]
    resolved_findings = [_finding_to_dict(map_a[fp]) for fp in resolved_fps]

    changed_findings = []
    for fp in common_fps:
        fa, fb = map_a[fp], map_b[fp]
        sev_a = fa.severity.value if hasattr(fa.severity, "value") else str(fa.severity)
        sev_b = fb.severity.value if hasattr(fb.severity, "value") else str(fb.severity)
        if sev_a != sev_b:
            changed_findings.append({
                "id": fb.id,
                "title": fb.title,
                "resource_id": fb.resource_id,
                "severity_before": sev_a,
                "severity_after": sev_b,
            })

    n, r = len(new_findings), len(resolved_findings)
    trend = "improving" if r > n else ("declining" if n > r else "stable")

    return {
        "scan_a_id": scan_a_id,
        "scan_b_id": scan_b_id,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "changed_findings": changed_findings,
        "new_count": n,
        "resolved_count": r,
        "changed_count": len(changed_findings),
        "trend_direction": trend,
    }


def get_or_compute_delta(scan_b_id: str, client_id: str, db: Session,
                          scan_a_id: Optional[str] = None) -> Optional[dict]:
    from api.models.models import ScanStatus

    if not scan_a_id:
        prev = (
            db.query(Scan)
            .filter(
                Scan.client_id == client_id,
                Scan.id != scan_b_id,
                Scan.status == ScanStatus.COMPLETED,
            )
            .order_by(Scan.completed_at.desc())
            .first()
        )
        if not prev:
            return None
        scan_a_id = prev.id

    cached = db.query(ScanDelta).filter(
        ScanDelta.scan_a_id == scan_a_id,
        ScanDelta.scan_b_id == scan_b_id,
    ).first()
    if cached:
        return {
            "scan_a_id": scan_a_id,
            "scan_b_id": scan_b_id,
            "new_findings": cached.new_findings or [],
            "resolved_findings": cached.resolved_findings or [],
            "changed_findings": cached.changed_findings or [],
            "new_count": cached.new_count,
            "resolved_count": cached.resolved_count,
            "changed_count": cached.changed_count,
            "trend_direction": cached.trend_direction,
            "cached": True,
        }

    result = compute_delta(scan_a_id, scan_b_id, client_id, db)

    delta_row = ScanDelta(
        client_id=client_id,
        scan_a_id=scan_a_id,
        scan_b_id=scan_b_id,
        new_findings=result["new_findings"],
        resolved_findings=result["resolved_findings"],
        changed_findings=result["changed_findings"],
        new_count=result["new_count"],
        resolved_count=result["resolved_count"],
        changed_count=result["changed_count"],
        trend_direction=result["trend_direction"],
    )
    try:
        db.add(delta_row)
        db.commit()
    except Exception:
        db.rollback()

    return result
