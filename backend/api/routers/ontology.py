"""Live per-client security ontology graph.

Derives nodes and edges from existing tables (Asset, Finding, ThreatEntry,
ControlDeficiency, RemediationAction) — no new LLM calls needed.
Returns a ReactFlow-compatible node/edge structure.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/ontology", tags=["ontology"])


@router.get("/")
async def get_client_ontology(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return live knowledge graph for a client derived from all security data."""
    from api.models.models import (
        Asset, Finding, Scan, ThreatEntry, ControlDeficiency, RemediationAction,
    )

    nodes = []
    edges = []
    node_ids: set = set()

    def _add_node(node_id, node_type, label, severity=None, meta=None):
        if node_id in node_ids:
            return
        node_ids.add(node_id)
        nodes.append({
            "id": node_id,
            "type": node_type,
            "label": (label or "(unnamed)")[:60],
            "severity": severity,
            "meta": meta or {},
        })

    def _add_edge(from_id, to_id, edge_type, weight=1.0):
        if from_id not in node_ids or to_id not in node_ids:
            return
        edges.append({
            "id": f"{from_id}-{edge_type}-{to_id}",
            "from": from_id,
            "to": to_id,
            "edge_type": edge_type,
            "weight": weight,
        })

    # Assets
    assets = db.query(Asset).filter(Asset.client_id == client_id).limit(80).all()
    asset_by_ext: dict = {}
    for a in assets:
        nid = f"asset-{a.id}"
        _add_node(nid, "asset", a.name or a.external_id,
                  meta={"asset_class": a.asset_class, "external_id": a.external_id})
        if a.external_id:
            asset_by_ext[a.external_id] = nid

    # Findings (open only)
    scan_ids = [s.id for s in db.query(Scan).filter(Scan.client_id == client_id).all()]
    findings = []
    if scan_ids:
        findings = (
            db.query(Finding)
            .filter(Finding.scan_id.in_(scan_ids), Finding.status == "open")
            .limit(120).all()
        )
    finding_node_ids: dict = {}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        nid = f"finding-{f.id}"
        _add_node(nid, "vulnerability", f.title, severity=sev,
                  meta={"resource_id": f.resource_id, "control_id": f.control_id})
        finding_node_ids[f.id] = nid
        if f.resource_id and f.resource_id in asset_by_ext:
            _add_edge(asset_by_ext[f.resource_id], nid, "exposes",
                      weight=0.9 if sev in ("critical", "high") else 0.5)

    # Threat entries
    threats = db.query(ThreatEntry).filter(ThreatEntry.client_id == client_id).limit(60).all()
    for t in threats:
        nid = f"threat-{t.id}"
        label = t.technique_id or t.title or "Unknown Threat"
        _add_node(nid, "threat", label, severity=t.severity,
                  meta={"technique_id": t.technique_id, "tactic": t.tactic})
        if t.finding_id and t.finding_id in finding_node_ids:
            _add_edge(nid, finding_node_ids[t.finding_id], "exploits", weight=0.8)

    # Control deficiencies
    gaps = db.query(ControlDeficiency).filter(ControlDeficiency.client_id == client_id).limit(60).all()
    gap_node_ids: dict = {}
    for g in gaps:
        nid = f"gap-{g.id}"
        _add_node(nid, "gap", g.title, severity=g.severity,
                  meta={"control_id": g.control_id, "framework": g.framework})
        gap_node_ids[g.id] = nid
        if g.finding_id and g.finding_id in finding_node_ids:
            _add_edge(nid, finding_node_ids[g.finding_id], "affects", weight=0.7)

    # Remediation actions
    actions = db.query(RemediationAction).filter(RemediationAction.client_id == client_id).limit(60).all()
    gap_nid_list = list(gap_node_ids.values())
    for ra in actions:
        nid = f"remediation-{ra.id}"
        label = ra.title or (ra.action[:60] if ra.action else "Remediation")
        _add_node(nid, "control", label,
                  meta={"band": ra.band, "effort": ra.effort, "impact": ra.impact})
        for g_nid in gap_nid_list[:5]:
            _add_edge(nid, g_nid, "mitigates", weight=0.6)

    type_counts: dict = {}
    for n in nodes:
        type_counts[n["type"]] = type_counts.get(n["type"], 0) + 1

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {"total_nodes": len(nodes), "total_edges": len(edges), "by_type": type_counts},
    }


@router.get("/stats")
async def get_ontology_stats(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    from api.models.models import Asset, Finding, Scan, ThreatEntry, ControlDeficiency, RemediationAction
    scan_ids = [s.id for s in db.query(Scan).filter(Scan.client_id == client_id).all()]
    open_findings = (
        db.query(Finding)
        .filter(Finding.scan_id.in_(scan_ids), Finding.status == "open")
        .count()
        if scan_ids else 0
    )
    return {
        "assets": db.query(Asset).filter(Asset.client_id == client_id).count(),
        "vulnerabilities": open_findings,
        "threats": db.query(ThreatEntry).filter(ThreatEntry.client_id == client_id).count(),
        "gaps": db.query(ControlDeficiency).filter(ControlDeficiency.client_id == client_id).count(),
        "controls": db.query(RemediationAction).filter(RemediationAction.client_id == client_id).count(),
    }
