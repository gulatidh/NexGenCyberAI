"""Framework compliance endpoints — catalog, per-client status, override, recompute."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import List, Dict, Any

from api.models.models import (
    Client, ClientControlStatus, ControlStatus, Finding, FrameworkControl, FrameworkType, Scan,
)
from api.schemas.schemas import (
    ControlStatusResponse, ControlStatusUpdate, FrameworkCatalogEntry,
    FrameworkControlResponse, FrameworkSummaryResponse,
)
from db.database import get_db
from core.security import get_current_user
from services.compliance import (
    compute_summary, recompute_client_framework,
)

router = APIRouter(tags=["frameworks"])


_FRAMEWORK_NAMES = {
    "nist_csf": "NIST Cybersecurity Framework 2.0",
    "nist_800_53": "NIST SP 800-53 Rev 5",
    "cis_v8": "CIS Critical Security Controls v8.1",
    "gdpr": "GDPR",
    "iso_27001": "ISO/IEC 27001",
    "soc2": "SOC 2",
    "pci_dss": "PCI DSS",
}


def _coerce_framework(framework: str) -> FrameworkType:
    try:
        return FrameworkType(framework)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown framework: {framework}")


# ── Catalog (no client) ───────────────────────────────────────────────────────

@router.get("/frameworks/", response_model=List[FrameworkCatalogEntry])
async def list_frameworks(db: Session = Depends(get_db), _=Depends(get_current_user)):
    out: List[FrameworkCatalogEntry] = []
    # Group counts by framework value
    rows = db.query(FrameworkControl.framework, FrameworkControl.id).all()
    by_fw: Dict[str, int] = {}
    for fw, _id in rows:
        v = fw.value if hasattr(fw, "value") else str(fw)
        by_fw[v] = by_fw.get(v, 0) + 1
    for fw_value, count in sorted(by_fw.items()):
        out.append(FrameworkCatalogEntry(
            framework=FrameworkType(fw_value),
            name=_FRAMEWORK_NAMES.get(fw_value, fw_value),
            total_controls=count,
        ))
    return out


@router.get("/frameworks/{framework}/controls/", response_model=List[FrameworkControlResponse])
async def list_framework_controls(
    framework: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    fw = _coerce_framework(framework)
    return (
        db.query(FrameworkControl)
        .filter(FrameworkControl.framework == fw)
        .order_by(FrameworkControl.control_id.asc())
        .all()
    )


# ── Per-client ────────────────────────────────────────────────────────────────

@router.get("/clients/{client_id}/frameworks/", response_model=List[FrameworkSummaryResponse])
async def client_framework_summary(
    client_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Compliance summary for every framework — powers the dashboard tile."""
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    out: List[FrameworkSummaryResponse] = []
    available = (
        db.query(FrameworkControl.framework).distinct().all()
    )
    for (fw,) in available:
        counts = compute_summary(db, client_id, fw)
        out.append(FrameworkSummaryResponse(
            framework=fw,
            total=counts["total"],
            compliant=counts["compliant"],
            non_compliant=counts["non_compliant"],
            partial=counts["partial"],
            not_applicable=counts["not_applicable"],
            score=counts["score"],
            last_evaluated_at=counts["last_evaluated_at"],
        ))
    return out


@router.get("/clients/{client_id}/frameworks/{framework}/", response_model=Dict[str, Any])
async def client_framework_detail(
    client_id: str,
    framework: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Full controls-with-status payload for the Frameworks page."""
    fw = _coerce_framework(framework)
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    controls = (
        db.query(FrameworkControl)
        .filter(FrameworkControl.framework == fw)
        .order_by(FrameworkControl.control_id.asc())
        .all()
    )
    statuses = {
        s.framework_control_id: s
        for s in db.query(ClientControlStatus)
        .join(FrameworkControl, ClientControlStatus.framework_control_id == FrameworkControl.id)
        .filter(ClientControlStatus.client_id == client_id, FrameworkControl.framework == fw)
        .all()
    }

    items: List[Dict[str, Any]] = []
    for c in controls:
        st = statuses.get(c.id)
        items.append({
            "control": {
                "id": c.id,
                "framework": c.framework,
                "control_id": c.control_id,
                "parent_control_id": c.parent_control_id,
                "domain": c.domain,
                "title": c.title,
                "description": c.description,
                "weight": c.weight or 0,
            },
            "status": (st.status.value if st and hasattr(st.status, "value") else (st.status if st else "not_applicable")),
            "derived": (st.derived if st else True),
            "evidence": st.evidence if st else None,
            "last_evaluated_at": st.last_evaluated_at if st else None,
            "overridden_by": st.overridden_by if st else None,
            "overridden_at": st.overridden_at if st else None,
            "finding_ids": (st.derived_finding_ids if st and st.derived_finding_ids else []),
        })

    summary = compute_summary(db, client_id, fw)
    return {
        "framework": fw.value,
        "summary": {
            "total": summary["total"],
            "compliant": summary["compliant"],
            "non_compliant": summary["non_compliant"],
            "partial": summary["partial"],
            "not_applicable": summary["not_applicable"],
            "score": summary["score"],
            "last_evaluated_at": summary["last_evaluated_at"],
        },
        "controls": items,
    }


@router.get("/clients/{client_id}/frameworks/{framework}/controls/{control_id}", response_model=Dict[str, Any])
async def client_control_detail(
    client_id: str,
    framework: str,
    control_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    fw = _coerce_framework(framework)
    ctrl = (
        db.query(FrameworkControl)
        .filter(FrameworkControl.framework == fw, FrameworkControl.control_id == control_id)
        .first()
    )
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    st = (
        db.query(ClientControlStatus)
        .filter(
            ClientControlStatus.client_id == client_id,
            ClientControlStatus.framework_control_id == ctrl.id,
        )
        .first()
    )
    # Pull related findings (current state; matches by control_id case-insensitively)
    findings = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.client_id == client_id,
            Finding.framework == fw,
            Finding.control_id.ilike(control_id),
        )
        .all()
    )

    return {
        "control": {
            "id": ctrl.id,
            "framework": ctrl.framework,
            "control_id": ctrl.control_id,
            "parent_control_id": ctrl.parent_control_id,
            "domain": ctrl.domain,
            "title": ctrl.title,
            "description": ctrl.description,
            "weight": ctrl.weight or 0,
        },
        "status": (st.status.value if st and hasattr(st.status, "value") else (st.status if st else "not_applicable")),
        "derived": (st.derived if st else True),
        "evidence": st.evidence if st else None,
        "last_evaluated_at": st.last_evaluated_at if st else None,
        "overridden_by": st.overridden_by if st else None,
        "overridden_at": st.overridden_at if st else None,
        "findings": [
            {
                "id": f.id, "scan_id": f.scan_id, "title": f.title,
                "severity": f.severity, "status": f.status,
                "resource_id": f.resource_id, "cve_id": f.cve_id,
                "cvss_score": f.cvss_score, "created_at": f.created_at,
            }
            for f in findings
        ],
    }


@router.patch("/clients/{client_id}/frameworks/{framework}/controls/{control_id}", response_model=ControlStatusResponse)
async def override_control_status(
    client_id: str,
    framework: str,
    control_id: str,
    payload: ControlStatusUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    fw = _coerce_framework(framework)
    ctrl = (
        db.query(FrameworkControl)
        .filter(FrameworkControl.framework == fw, FrameworkControl.control_id == control_id)
        .first()
    )
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    st = (
        db.query(ClientControlStatus)
        .filter(
            ClientControlStatus.client_id == client_id,
            ClientControlStatus.framework_control_id == ctrl.id,
        )
        .first()
    )
    now = datetime.now(timezone.utc)
    upn = user.get("upn", user.get("preferred_username", "system"))
    if st is None:
        st = ClientControlStatus(
            client_id=client_id,
            framework_control_id=ctrl.id,
            status=payload.status,
            derived=False,
            evidence=payload.evidence,
            overridden_by=upn,
            overridden_at=now,
            last_evaluated_at=now,
        )
        db.add(st)
    else:
        st.status = payload.status
        st.derived = False
        st.evidence = payload.evidence if payload.evidence is not None else st.evidence
        st.overridden_by = upn
        st.overridden_at = now
        st.last_evaluated_at = now
    db.commit()
    db.refresh(st)
    return ControlStatusResponse(
        control=FrameworkControlResponse.model_validate(ctrl),
        status=st.status,
        derived=st.derived,
        evidence=st.evidence,
        last_evaluated_at=st.last_evaluated_at,
        overridden_by=st.overridden_by,
        overridden_at=st.overridden_at,
        finding_ids=st.derived_finding_ids or [],
    )


@router.delete("/clients/{client_id}/frameworks/{framework}/controls/{control_id}/override", status_code=204)
async def clear_override(
    client_id: str,
    framework: str,
    control_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    fw = _coerce_framework(framework)
    ctrl = (
        db.query(FrameworkControl)
        .filter(FrameworkControl.framework == fw, FrameworkControl.control_id == control_id)
        .first()
    )
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    st = (
        db.query(ClientControlStatus)
        .filter(
            ClientControlStatus.client_id == client_id,
            ClientControlStatus.framework_control_id == ctrl.id,
        )
        .first()
    )
    if st:
        st.derived = True
        st.overridden_by = None
        st.overridden_at = None
        # Re-derive immediately
        recompute_client_framework(db, client_id, fw)


@router.post("/clients/{client_id}/frameworks/{framework}/recompute/")
async def recompute_framework(
    client_id: str,
    framework: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    fw = _coerce_framework(framework)
    counts = recompute_client_framework(db, client_id, fw)
    return {"framework": fw.value, "counts": counts}
