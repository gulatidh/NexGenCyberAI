"""
Data Model / Ontology endpoints.

GET /clients/{cid}/data-model/stats
  — aggregate counts per entity type for Hub ontology badges.

GET /clients/{cid}/data-model/connections?entity_type=asset&entity_id=xxx
  — radial connection graph for a specific record.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from typing import Optional

from api.models.models import (
    Asset, Finding, Risk, Scan, RemediationAction,
    ControlDeficiency, ThreatEntry, VAPTReport, CustomFramework,
)
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/data-model", tags=["data-model"])


# ── helpers ──────────────────────────────────────────────────────────────────

def _sev(obj, attr="severity"):
    v = getattr(obj, attr, None)
    return v.value if hasattr(v, "value") else (v or "unknown")

def _status(obj, attr="status"):
    v = getattr(obj, attr, None)
    return v.value if hasattr(v, "value") else (v or "unknown")


# ── /stats ────────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_ontology_stats(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return counts + breakdowns for each ontology node for a given client."""

    # Assets
    total_assets = db.query(func.count(Asset.id)).filter(Asset.client_id == client_id).scalar() or 0
    asset_by_class = {}
    for cls, n in db.query(Asset.asset_class, func.count(Asset.id)).filter(
        Asset.client_id == client_id
    ).group_by(Asset.asset_class).all():
        asset_by_class[cls or "other"] = int(n or 0)

    # Findings (open only, via scan join)
    open_finding_rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(Scan.client_id == client_id, Finding.status == "open")
        .group_by(Finding.severity).all()
    )
    findings_by_sev = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    total_findings = 0
    for sev, n in open_finding_rows:
        k = sev.value if hasattr(sev, "value") else (sev or "info")
        findings_by_sev[k] = findings_by_sev.get(k, 0) + int(n or 0)
        total_findings += int(n or 0)

    finding_status_rows = (
        db.query(Finding.status, func.count(Finding.id))
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(Scan.client_id == client_id)
        .group_by(Finding.status).all()
    )
    findings_by_status = {}
    for st, n in finding_status_rows:
        k = st.value if hasattr(st, "value") else (st or "open")
        findings_by_status[k] = int(n or 0)

    # Risks
    risk_rows = (
        db.query(Risk.risk_level, func.count(Risk.id))
        .filter(Risk.client_id == client_id, Risk.status == "open")
        .group_by(Risk.risk_level).all()
    )
    risks_by_level = {}
    total_risks = 0
    for lvl, n in risk_rows:
        k = lvl.value if hasattr(lvl, "value") else (lvl or "medium")
        risks_by_level[k] = int(n or 0)
        total_risks += int(n or 0)

    # Remediations
    rem_rows = (
        db.query(RemediationAction.status, func.count(RemediationAction.id))
        .filter(RemediationAction.client_id == client_id)
        .group_by(RemediationAction.status).all()
    )
    rem_by_status = {}
    total_remediations = 0
    for st, n in rem_rows:
        k = st or "open"
        rem_by_status[k] = int(n or 0)
        total_remediations += int(n or 0)

    # Control deficiencies
    ctrl_rows = (
        db.query(ControlDeficiency.severity, func.count(ControlDeficiency.id))
        .filter(ControlDeficiency.client_id == client_id)
        .group_by(ControlDeficiency.severity).all()
    )
    ctrl_by_sev = {}
    total_controls = 0
    for sev, n in ctrl_rows:
        k = sev or "medium"
        ctrl_by_sev[k] = int(n or 0)
        total_controls += int(n or 0)

    # Threat entries
    threat_rows = (
        db.query(ThreatEntry.severity, func.count(ThreatEntry.id))
        .filter(ThreatEntry.client_id == client_id)
        .group_by(ThreatEntry.severity).all()
    )
    threats_by_sev = {}
    total_threats = 0
    for sev, n in threat_rows:
        k = sev or "medium"
        threats_by_sev[k] = int(n or 0)
        total_threats += int(n or 0)

    # VAPT Reports
    total_reports = db.query(func.count(VAPTReport.id)).filter(
        VAPTReport.client_id == client_id
    ).scalar() or 0

    return {
        "asset":       {"total": total_assets,      "breakdown": asset_by_class,    "key": "by_class"},
        "finding":     {"total": total_findings,     "breakdown": findings_by_sev,   "key": "by_severity",
                        "status": findings_by_status},
        "risk":        {"total": total_risks,        "breakdown": risks_by_level,    "key": "by_level"},
        "remediation": {"total": total_remediations, "breakdown": rem_by_status,     "key": "by_status"},
        "control":     {"total": total_controls,     "breakdown": ctrl_by_sev,       "key": "by_severity"},
        "technique":   {"total": total_threats,      "breakdown": threats_by_sev,    "key": "by_severity"},
        "report":      {"total": total_reports,      "breakdown": {},                "key": ""},
    }


# ── /connections ──────────────────────────────────────────────────────────────

@router.get("/connections")
async def get_entity_connections(
    client_id: str,
    entity_type: str = Query(...),
    entity_id: str = Query(...),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """
    Return the radial connection graph for a specific record.
    Always returns: { anchor, nodes: [...], edges: [...] }
    """
    nodes = []
    edges = []

    def _node(id_, entity, label, detail="", icon="", severity=None):
        return {"id": id_, "entity": entity, "label": label,
                "detail": detail, "icon": icon, "severity": severity}

    def _edge(src, tgt, label=""):
        return {"source": src, "target": tgt, "label": label}

    if entity_type == "asset":
        asset = db.query(Asset).filter(Asset.id == entity_id, Asset.client_id == client_id).first()
        if not asset:
            return {"anchor": None, "nodes": [], "edges": []}

        anchor = _node(asset.id, "asset", asset.name,
                       detail=asset.asset_class or asset.asset_type or "",
                       icon="computer")
        # Related findings (match by external_id / resource_id)
        findings = (
            db.query(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .filter(Scan.client_id == client_id,
                    Finding.resource_id == asset.external_id,
                    Finding.status == "open")
            .order_by(Finding.severity)
            .limit(12).all()
        )
        for f in findings:
            nid = f"f-{f.id}"
            nodes.append(_node(nid, "finding", f.title[:50], icon="bug_report", severity=_sev(f)))
            edges.append(_edge(asset.id, nid))

        # Related risks (via title keyword match on asset name — heuristic)
        risks = (
            db.query(Risk)
            .filter(Risk.client_id == client_id, Risk.status == "open")
            .limit(5).all()
        )
        for r in risks:
            nid = f"r-{r.id}"
            nodes.append(_node(nid, "risk", r.title[:50], icon="warning",
                               severity=_sev(r, "risk_level")))
            edges.append(_edge(asset.id, nid))

    elif entity_type == "finding":
        f = (
            db.query(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .filter(Finding.id == entity_id, Scan.client_id == client_id)
            .first()
        )
        if not f:
            return {"anchor": None, "nodes": [], "edges": []}

        anchor = _node(f.id, "finding", f.title[:60],
                       detail=f.resource_id or "", icon="bug_report",
                       severity=_sev(f))

        # Asset this finding belongs to
        if f.resource_id:
            asset = db.query(Asset).filter(
                Asset.client_id == client_id,
                Asset.external_id == f.resource_id
            ).first()
            if asset:
                nid = f"a-{asset.id}"
                nodes.append(_node(nid, "asset", asset.name, icon="computer"))
                edges.append(_edge(f.id, nid, "found on"))

        # Risks linked to this finding (heuristic: same client, open)
        risks = db.query(Risk).filter(
            Risk.client_id == client_id, Risk.status == "open"
        ).limit(4).all()
        for r in risks:
            nid = f"r-{r.id}"
            nodes.append(_node(nid, "risk", r.title[:50], icon="warning",
                               severity=_sev(r, "risk_level")))
            edges.append(_edge(f.id, nid, "contributes to"))

        # Control deficiencies sharing same control_id
        if f.control_id:
            cds = db.query(ControlDeficiency).filter(
                ControlDeficiency.client_id == client_id,
                ControlDeficiency.control_id == f.control_id
            ).limit(3).all()
            for cd in cds:
                nid = f"cd-{cd.id}"
                nodes.append(_node(nid, "control", cd.title[:50],
                                   detail=cd.framework or "", icon="policy"))
                edges.append(_edge(f.id, nid, "violates"))

    elif entity_type == "risk":
        r = db.query(Risk).filter(Risk.id == entity_id, Risk.client_id == client_id).first()
        if not r:
            return {"anchor": None, "nodes": [], "edges": []}

        anchor = _node(r.id, "risk", r.title[:60],
                       detail=r.category or "", icon="warning",
                       severity=_sev(r, "risk_level"))

        # Remediations for this client
        rems = db.query(RemediationAction).filter(
            RemediationAction.client_id == client_id,
            RemediationAction.status.in_(["open", "in_progress"])
        ).limit(5).all()
        for rm in rems:
            nid = f"rem-{rm.id}"
            nodes.append(_node(nid, "remediation", (rm.title or rm.action[:50]),
                               detail=rm.band or "", icon="build"))
            edges.append(_edge(r.id, nid, "mitigated by"))

        # Threat entries
        threats = db.query(ThreatEntry).filter(
            ThreatEntry.client_id == client_id,
            ThreatEntry.status == "active"
        ).limit(4).all()
        for t in threats:
            nid = f"t-{t.id}"
            nodes.append(_node(nid, "technique", t.title[:50],
                               detail=t.technique_id or "", icon="security",
                               severity=t.severity))
            edges.append(_edge(r.id, nid, "exposed by"))

    elif entity_type == "remediation":
        rm = db.query(RemediationAction).filter(
            RemediationAction.id == entity_id,
            RemediationAction.client_id == client_id
        ).first()
        if not rm:
            return {"anchor": None, "nodes": [], "edges": []}

        anchor = _node(rm.id, "remediation", (rm.title or rm.action[:60]),
                       detail=rm.band or "", icon="build")

        # Risks it resolves (client-level)
        risks = db.query(Risk).filter(
            Risk.client_id == client_id, Risk.status == "open"
        ).limit(5).all()
        for r in risks:
            nid = f"r-{r.id}"
            nodes.append(_node(nid, "risk", r.title[:50], icon="warning",
                               severity=_sev(r, "risk_level")))
            edges.append(_edge(rm.id, nid, "resolves"))

        # Evidence / VAPT reports
        reports = db.query(VAPTReport).filter(
            VAPTReport.client_id == client_id
        ).limit(3).all()
        for rp in reports:
            nid = f"rp-{rp.id}"
            nodes.append(_node(nid, "report", rp.title[:50], icon="description"))
            edges.append(_edge(rm.id, nid, "documented in"))

    else:
        return {"anchor": None, "nodes": [], "edges": []}

    return {"anchor": anchor, "nodes": nodes, "edges": edges}


# ── /list — quick record picker for the data-model explorer ───────────────────

@router.get("/list")
async def list_entity_records(
    client_id: str,
    entity_type: str = Query(...),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return top-20 records of the requested entity type for the search picker."""
    results = []

    if entity_type == "asset":
        q = db.query(Asset).filter(Asset.client_id == client_id)
        if search:
            q = q.filter(Asset.name.ilike(f"%{search}%"))
        for a in q.limit(20).all():
            results.append({"id": a.id, "label": a.name,
                            "detail": a.asset_class or a.asset_type or "",
                            "entity": "asset"})

    elif entity_type == "finding":
        q = (
            db.query(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .filter(Scan.client_id == client_id, Finding.status == "open")
        )
        if search:
            q = q.filter(Finding.title.ilike(f"%{search}%"))
        for f in q.order_by(Finding.severity).limit(20).all():
            sev = f.severity.value if hasattr(f.severity, "value") else (f.severity or "")
            results.append({"id": f.id, "label": f.title,
                            "detail": sev, "entity": "finding"})

    elif entity_type == "risk":
        q = db.query(Risk).filter(Risk.client_id == client_id, Risk.status == "open")
        if search:
            q = q.filter(Risk.title.ilike(f"%{search}%"))
        for r in q.limit(20).all():
            lvl = r.risk_level.value if hasattr(r.risk_level, "value") else (r.risk_level or "")
            results.append({"id": r.id, "label": r.title,
                            "detail": lvl, "entity": "risk"})

    elif entity_type == "remediation":
        q = db.query(RemediationAction).filter(RemediationAction.client_id == client_id)
        if search:
            q = q.filter(RemediationAction.action.ilike(f"%{search}%"))
        for rm in q.limit(20).all():
            results.append({"id": rm.id, "label": rm.title or rm.action[:60],
                            "detail": rm.band or "", "entity": "remediation"})

    return {"items": results}
