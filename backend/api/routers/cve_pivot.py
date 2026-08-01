"""CVE Pivot — blast-radius view for a given CVE across all assets and scans."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional

from api.models.models import Finding, Scan, Asset, ThreatEntry
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/cve", tags=["cve-pivot"])

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _sev(f: Finding) -> str:
    return str(f.severity.value if hasattr(f.severity, "value") else f.severity).lower()


@router.get("/")
async def list_cves(
    client_id: str,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List all unique CVEs for a client, sorted by CVSS score descending."""
    query = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.cve_id.isnot(None),
            Finding.cve_id != "",
        )
    )
    if q:
        query = query.filter(Finding.cve_id.ilike(f"%{q}%"))

    findings = query.all()

    cve_map: dict = {}
    for f in findings:
        cid = f.cve_id
        if not cid:
            continue
        if cid not in cve_map:
            cve_map[cid] = {
                "cve_id": cid,
                "max_cvss": 0.0,
                "resources": set(),
                "finding_count": 0,
                "severities": set(),
                "first_seen": None,
                "last_seen": None,
            }
        e = cve_map[cid]
        e["max_cvss"] = max(e["max_cvss"], float(f.cvss_score or 0))
        e["resources"].add(f.resource_id or f.id)
        e["finding_count"] += 1
        e["severities"].add(_sev(f))
        if f.created_at:
            if e["first_seen"] is None or f.created_at < e["first_seen"]:
                e["first_seen"] = f.created_at
            if e["last_seen"] is None or f.created_at > e["last_seen"]:
                e["last_seen"] = f.created_at

    result = []
    for e in cve_map.values():
        sevs = e["severities"]
        max_sev = min(sevs, key=lambda s: _SEV_ORDER.get(s, 99)) if sevs else "info"
        result.append({
            "cve_id": e["cve_id"],
            "max_cvss": round(e["max_cvss"], 1),
            "affected_assets": len(e["resources"]),
            "finding_count": e["finding_count"],
            "max_severity": max_sev,
            "first_seen": e["first_seen"],
            "last_seen": e["last_seen"],
        })

    result.sort(key=lambda x: (-x["max_cvss"], -x["affected_assets"]))
    return result


@router.get("/{cve_id}")
async def get_cve_detail(
    client_id: str,
    cve_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Full blast-radius view for one CVE: affected assets, all findings, linked MITRE techniques."""
    findings = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.cve_id == cve_id,
        )
        .order_by(desc(Finding.created_at))
        .all()
    )

    if not findings:
        raise HTTPException(status_code=404, detail=f"No findings for {cve_id} in this client")

    # Unique resource_ids → look up Asset rows
    resource_ids = list({f.resource_id for f in findings if f.resource_id})
    assets_by_rid: dict = {}
    for rid in resource_ids:
        a = db.query(Asset).filter(Asset.client_id == client_id, Asset.external_id == rid).first()
        assets_by_rid[rid] = a

    # Linked MITRE techniques: ThreatEntry rows whose title/description mentions this CVE
    threat_entries = (
        db.query(ThreatEntry)
        .filter(
            ThreatEntry.client_id == client_id,
            ThreatEntry.description.ilike(f"%{cve_id}%")
            | ThreatEntry.title.ilike(f"%{cve_id}%"),
        )
        .all()
    )
    mitre_techniques = []
    seen = set()
    for te in threat_entries:
        key = te.technique_id or te.technique_name
        if key and key not in seen:
            seen.add(key)
            mitre_techniques.append({
                "technique_id": te.technique_id,
                "technique_name": te.technique_name,
                "tactic": te.tactic,
                "confidence": te.confidence,
            })

    sevs = [_sev(f) for f in findings]
    max_sev = min(set(sevs), key=lambda s: _SEV_ORDER.get(s, 99))
    max_cvss = max((float(f.cvss_score or 0) for f in findings), default=0.0)

    return {
        "cve_id": cve_id,
        "title": findings[0].title,
        "description": findings[0].description or "",
        "max_cvss": round(max_cvss, 1),
        "max_severity": max_sev,
        "affected_assets": len(resource_ids),
        "finding_count": len(findings),
        "mitre_techniques": mitre_techniques,
        "assets": [
            {
                "resource_id": rid,
                "asset_id": assets_by_rid[rid].id if assets_by_rid.get(rid) else None,
                "asset_name": assets_by_rid[rid].name if assets_by_rid.get(rid) else rid,
                "asset_class": assets_by_rid[rid].asset_class if assets_by_rid.get(rid) else None,
                "region": assets_by_rid[rid].region if assets_by_rid.get(rid) else None,
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": _sev(f),
                        "status": f.status,
                        "cvss_score": f.cvss_score,
                        "scan_id": f.scan_id,
                        "created_at": f.created_at,
                    }
                    for f in findings if f.resource_id == rid
                ],
            }
            for rid in resource_ids
        ],
    }
