"""Generate attack path graph from client findings using rule-based + LLM analysis."""
from typing import Dict, Any, List
from sqlalchemy.orm import Session


# Severity → numeric weight for edge ordering
_SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Keywords that suggest an attack step type
_STEP_RULES = [
    ("initial_access", ["exposed", "public", "internet", "open port", "unauthenticated", "external"]),
    ("credential_access", ["credential", "password", "secret", "key", "token", "auth", "login", "brute"]),
    ("privilege_escalation", ["privilege", "escalation", "admin", "root", "sudo", "iam role", "elevation"]),
    ("lateral_movement", ["lateral", "pivot", "spread", "cross", "vpc", "subnet", "network"]),
    ("data_access", ["data", "database", "storage", "s3", "blob", "bucket", "exfil", "leak", "pii", "sensitive"]),
    ("persistence", ["persistence", "backdoor", "scheduled", "cron", "startup", "service"]),
    ("impact", ["ransomware", "destroy", "delete", "corrupt", "dos", "denial"]),
]


def _classify_finding(f) -> str:
    text = ((f.title or "") + " " + (f.description or "")).lower()
    for step_type, keywords in _STEP_RULES:
        if any(kw in text for kw in keywords):
            return step_type
    return "vulnerability"


def get_attack_paths(db: Session, client_id: str, scan_id: str = None, project_id: str = None) -> Dict[str, Any]:
    """Return nodes and edges representing the attack path graph for a client."""
    from api.models.models import Finding, Scan, Asset

    q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id, Finding.status == "open")
    )
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    elif project_id:
        q = q.filter(Scan.project_id == project_id)

    findings = q.order_by(Finding.cvss_score.desc()).limit(100).all()

    if not findings:
        return {"nodes": [], "edges": [], "paths": []}

    # Build nodes (one per finding, plus resource nodes)
    nodes: List[Dict] = []
    seen_resources: Dict[str, str] = {}  # resource_id -> node_id
    finding_node_ids: Dict[str, str] = {}  # finding.id -> node_id

    # Add attacker origin node
    nodes.append({
        "id": "attacker",
        "label": "Attacker",
        "type": "attacker",
        "severity": None,
        "x": 0, "y": 0,
    })

    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        step_type = _classify_finding(f)
        nid = f"finding-{f.id[:8]}"
        finding_node_ids[f.id] = nid
        nodes.append({
            "id": nid,
            "label": (f.title or "Unknown")[:60],
            "type": step_type,
            "severity": sev,
            "resource": f.resource_id or "",
            "cvss": f.cvss_score or 0,
            "finding_id": f.id,
        })

        # Resource node
        if f.resource_id:
            rid = f"resource-{f.resource_id[:20]}"
            if rid not in seen_resources:
                seen_resources[f.resource_id] = rid
                nodes.append({
                    "id": rid,
                    "label": f.resource_id[:40],
                    "type": "resource",
                    "severity": None,
                    "resource": f.resource_id,
                })

    # Build edges — connect attacker → initial_access → other steps → impact
    PHASE_ORDER = ["initial_access", "credential_access", "privilege_escalation",
                   "lateral_movement", "data_access", "persistence", "impact", "vulnerability"]

    edges: List[Dict] = []
    # Group findings by step type
    by_phase: Dict[str, List[str]] = {}
    for f in findings:
        pt = _classify_finding(f)
        nid = finding_node_ids[f.id]
        by_phase.setdefault(pt, []).append(nid)

    # Attacker → initial access nodes
    for nid in by_phase.get("initial_access", [])[:3]:
        edges.append({"source": "attacker", "target": nid, "label": "exploits", "weight": 3})

    # Chain phases in order
    prev_phase_nodes = by_phase.get("initial_access", [])[:2]
    for phase in PHASE_ORDER[1:]:
        curr_nodes = by_phase.get(phase, [])[:2]
        if curr_nodes and prev_phase_nodes:
            for src in prev_phase_nodes[:1]:
                for tgt in curr_nodes[:1]:
                    edges.append({"source": src, "target": tgt, "label": "enables", "weight": 2})
        if curr_nodes:
            prev_phase_nodes = curr_nodes

    # Connect findings to their resource nodes
    for f in findings[:20]:
        if f.resource_id:
            rid = seen_resources.get(f.resource_id)
            nid = finding_node_ids[f.id]
            if rid:
                edges.append({"source": nid, "target": rid, "label": "affects", "weight": 1})

    # Identify critical path (highest severity chain)
    critical_findings = [f for f in findings if (f.severity.value if hasattr(f.severity, "value") else f.severity) == "critical"]
    critical_path = ["attacker"] + [finding_node_ids[f.id] for f in critical_findings[:5]]

    return {
        "nodes": nodes,
        "edges": edges,
        "paths": [{"label": "Critical Attack Path", "nodes": critical_path}],
        "stats": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if (f.severity.value if hasattr(f.severity, "value") else f.severity) == "critical"),
            "phases_present": list(by_phase.keys()),
        }
    }
