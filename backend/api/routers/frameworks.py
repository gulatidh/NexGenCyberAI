"""Framework compliance endpoints — catalog, per-client status, override, recompute."""
import csv
import io
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from typing import Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

from api.models.models import (
    Asset, AssetStatus, Client, ClientControlStatus, ControlStatus, Finding, FrameworkControl, FrameworkType, Scan,
    CustomFramework,
)
from api.schemas.schemas import (
    ControlStatusResponse, ControlStatusUpdate, FrameworkCatalogEntry,
    FrameworkControlResponse, FrameworkSummaryResponse,
)
from db.database import get_db
from core.security import get_current_user
from services.compliance import (
    _normalize, compute_summary, derive_status_for_control, recompute_client_framework,
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
    "cis_azure": "CIS Microsoft Azure Foundations 5.0.0",
    "cis_aws": "CIS Amazon Web Services Foundations 7.0.0",
    "cis_aws_db": "CIS AWS Database Services 2.0.0",
    "cis_alibaba": "CIS Alibaba Cloud Foundation 2.0.0",
    "cis_gcp": "CIS Google Cloud Platform Foundation 4.0.0",
    "cis_gcp_workspace": "CIS Google Workspace Foundations 1.3.0",
    "cis_m365": "CIS Microsoft 365 Foundations 6.0.1",
    "cis_aks": "CIS Azure Kubernetes Service (AKS) 2.0.0",
    "cis_azure_compute": "CIS Microsoft Azure Compute Services 2.0.0",
    "cis_windows_server": "CIS Microsoft Windows Server 2025 2.0.0",
    "cis_ubuntu": "CIS Ubuntu Linux 22.04 LTS 3.0.0",
    "cis_esxi": "CIS VMware ESXi 8.0 1.3.0",
    "cis_f5": "CIS F5 Networks 1.0.0",
    "cis_palo_alto": "CIS Palo Alto Firewall 11 1.2.0",
    "cis_mssql": "CIS Microsoft SQL Server 2025 1.0.0",
}


def _coerce_framework(framework: str) -> FrameworkType:
    try:
        return FrameworkType(framework)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown framework: {framework}")


# ── Catalog (no client) ───────────────────────────────────────────────────────

@router.get("/frameworks/", response_model=List[FrameworkCatalogEntry])
async def list_frameworks(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Catalog returns every framework defined in `_FRAMEWORK_NAMES` even if
    no controls have been seeded yet — frameworks like GDPR/ISO/SOC2/PCI
    intentionally start empty so users can import controls via the CSV
    upload flow. Returning 0-count rows keeps them visible in the UI
    instead of dropping the whole Standards family.
    """
    try:
        rows = db.query(FrameworkControl.framework, FrameworkControl.id).all()
        by_fw: Dict[str, int] = {}
        for fw, _id in rows:
            v = fw.value if hasattr(fw, "value") else str(fw)
            by_fw[v] = by_fw.get(v, 0) + 1
        valid_values = {m.value for m in FrameworkType}
        out: List[FrameworkCatalogEntry] = []
        for fw_value, display_name in _FRAMEWORK_NAMES.items():
            if fw_value not in valid_values:
                continue
            out.append(FrameworkCatalogEntry(
                framework=FrameworkType(fw_value),
                name=display_name,
                total_controls=by_fw.get(fw_value, 0),
            ))
        out.sort(key=lambda e: e.name.lower())
        return out
    except Exception as exc:
        logger.exception("list_frameworks failed")
        raise HTTPException(status_code=500, detail=f"list_frameworks failed: {type(exc).__name__}: {exc}")


@router.get("/frameworks/all/")
async def list_frameworks_all(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Merged catalog: standard frameworks + user-created custom frameworks.
    Returns [{framework, name, is_custom, total_controls}] matching FrameworkCatalogEntry.
    """
    try:
        # Standard frameworks
        rows = db.query(FrameworkControl.framework, FrameworkControl.id).all()
        by_fw: Dict[str, int] = {}
        for fw, _id in rows:
            v = fw.value if hasattr(fw, "value") else str(fw)
            by_fw[v] = by_fw.get(v, 0) + 1
        valid_values = {m.value for m in FrameworkType}
        out = []
        for fw_value, display_name in _FRAMEWORK_NAMES.items():
            if fw_value not in valid_values:
                continue
            out.append({
                "framework": fw_value,
                "name": display_name,
                "is_custom": False,
                "total_controls": by_fw.get(fw_value, 0),
            })
        out.sort(key=lambda e: e["name"].lower())

        # Custom frameworks
        customs = db.query(CustomFramework).order_by(CustomFramework.name).all()
        for cf in customs:
            out.append({
                "framework": cf.slug,
                "name": cf.name,
                "is_custom": True,
                "total_controls": len(cf.controls) if cf.controls else 0,
            })

        return out
    except Exception as exc:
        logger.exception("list_frameworks_all failed")
        raise HTTPException(status_code=500, detail=f"list_frameworks_all failed: {exc}")


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
    try:
        client = db.query(Client).filter(Client.id == client_id, Client.deleted_at.is_(None)).first()
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        out: List[FrameworkSummaryResponse] = []
        valid_values = {m.value for m in FrameworkType}
        available = (
            db.query(FrameworkControl.framework).distinct().all()
        )
        for (fw,) in available:
            v = fw.value if hasattr(fw, "value") else str(fw)
            if v not in valid_values:
                logger.warning("Skipping unknown framework in client_framework_summary: %r", v)
                continue
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
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("client_framework_summary failed")
        raise HTTPException(status_code=500, detail=f"client_framework_summary failed: {type(exc).__name__}: {exc}")


@router.get("/clients/{client_id}/frameworks/{framework}/", response_model=Dict[str, Any])
async def client_framework_detail(
    client_id: str,
    framework: str,
    scan_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Full controls-with-status payload for the Frameworks page.
    Accepts both standard FrameworkType values and custom framework slugs.
    When scan_id is provided, statuses are derived live from that scan's findings
    rather than from the persisted ClientControlStatus rows.
    """
    from api.models.models import CustomFramework as CustomFW

    client = db.query(Client).filter(Client.id == client_id, Client.deleted_at.is_(None)).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    # Detect whether this is a standard or custom framework.
    custom_fw = None
    fw_enum = None
    try:
        fw_enum = FrameworkType(framework)
        fw_value: str = fw_enum.value
    except ValueError:
        custom_fw = db.query(CustomFW).filter(CustomFW.slug == framework).first()
        if not custom_fw:
            raise HTTPException(status_code=404, detail=f"Framework not found: {framework}")
        fw_value = framework

    if custom_fw:
        ctrl_ids = [link.framework_control_id for link in custom_fw.controls]
        controls = (
            db.query(FrameworkControl)
            .filter(FrameworkControl.id.in_(ctrl_ids))
            .order_by(FrameworkControl.control_id.asc())
            .all()
        ) if ctrl_ids else []
    else:
        controls = (
            db.query(FrameworkControl)
            .filter(FrameworkControl.framework == fw_value)
            .order_by(FrameworkControl.control_id.asc())
            .all()
        )

    # Build statuses: either scan-scoped (live derivation) or client-wide (persisted rows).
    if scan_id:
        # Verify scan belongs to this client.
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.client_id == client_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        finding_rows = (
            db.query(Finding.control_id, Finding.id, Finding.status, Finding.framework, Finding.control_mappings)
            .filter(Finding.scan_id == scan_id)
            .all()
        )
        open_by_ctrl: Dict[str, List[str]] = {}
        hist_by_ctrl: Dict[str, List[str]] = {}
        for ctrl_id, finding_id, fstatus, finding_framework, mappings in finding_rows:
            is_open = (fstatus or "open") == "open"
            keys: set = set()
            finding_fw_value = finding_framework.value if hasattr(finding_framework, "value") else (finding_framework or "")
            if finding_fw_value == fw_value and ctrl_id:
                keys.add(_normalize(ctrl_id))
            if mappings and isinstance(mappings, dict):
                for cid in mappings.get(fw_value, []) or []:
                    if cid:
                        keys.add(_normalize(cid))
            for key in keys:
                if key:
                    hist_by_ctrl.setdefault(key, []).append(finding_id)
                    if is_open:
                        open_by_ctrl.setdefault(key, []).append(finding_id)

        class _DS:
            """Lightweight proxy that looks like ClientControlStatus to the code below."""
            def __init__(self, ctrl_key: str) -> None:
                opens = open_by_ctrl.get(ctrl_key, [])
                hists = hist_by_ctrl.get(ctrl_key, [])
                self.status = derive_status_for_control(opens, hists)
                self.derived_finding_ids = hists
                self.derived = True
                self.evidence = None
                self.last_evaluated_at = None
                self.overridden_by = None
                self.overridden_at = None

        statuses = {
            c.id: _DS(_normalize(c.control_id))
            for c in controls
            if _normalize(c.control_id) in open_by_ctrl or _normalize(c.control_id) in hist_by_ctrl
        }
    elif custom_fw:
        statuses = {
            s.framework_control_id: s
            for s in db.query(ClientControlStatus)
            .filter(
                ClientControlStatus.client_id == client_id,
                ClientControlStatus.framework_control_id.in_([c.id for c in controls]),
            )
            .all()
        } if controls else {}
    else:
        statuses = {
            s.framework_control_id: s
            for s in db.query(ClientControlStatus)
            .join(FrameworkControl, ClientControlStatus.framework_control_id == FrameworkControl.id)
            .filter(ClientControlStatus.client_id == client_id, FrameworkControl.framework == fw_value)
            .all()
        }

    # Pre-load all referenced findings in one query so the drawer can show
    # title + resource_id + severity instead of just truncated IDs.
    all_finding_ids: set = set()
    for s in statuses.values():
        for fid in (s.derived_finding_ids or []):
            if fid:
                all_finding_ids.add(fid)
    findings_by_id: Dict[str, Any] = {}
    if all_finding_ids:
        for f in db.query(Finding).filter(Finding.id.in_(all_finding_ids)).all():
            findings_by_id[f.id] = f

    # Map resource_id (Asset.external_id) → asset row so the drawer can deep-link
    # each finding to its asset detail page in the SPA.
    referenced_resource_ids = {f.resource_id for f in findings_by_id.values() if f.resource_id}
    asset_by_ext_id: Dict[str, Any] = {}
    if referenced_resource_ids:
        for a in (
            db.query(Asset)
            .filter(
                Asset.client_id == client_id,
                Asset.external_id.in_(referenced_resource_ids),
                Asset.status == AssetStatus.ACTIVE.value,
            )
            .all()
        ):
            asset_by_ext_id[a.external_id] = a

    def _slim(f) -> Dict[str, Any]:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        asset = asset_by_ext_id.get(f.resource_id) if f.resource_id else None
        return {
            "id": f.id,
            "title": f.title,
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "severity": sev,
            "status": f.status,
            "scan_id": f.scan_id,
            "asset_id": asset.id if asset else None,
            "asset_name": asset.name if asset else None,
        }

    items: List[Dict[str, Any]] = []
    for c in controls:
        st = statuses.get(c.id)
        finding_ids = (st.derived_finding_ids if st and st.derived_finding_ids else []) or []
        rich_findings = [_slim(findings_by_id[fid]) for fid in finding_ids if fid in findings_by_id]
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
            "finding_ids": finding_ids,
            "findings": rich_findings,
        })

    # Custom frameworks and scan-scoped views: derive summary from items list
    # (compute_summary queries by FrameworkControl.framework which doesn't cover either case).
    if custom_fw or scan_id:
        cts: Dict[str, Any] = {"compliant": 0, "non_compliant": 0, "partial": 0, "not_applicable": 0, "total": 0, "last_evaluated_at": None}
        last_ev = None
        for item in items:
            if item["control"]["weight"] == 0:
                continue
            cts["total"] += 1
            s = item["status"]
            cts[s] = cts.get(s, 0) + 1
            lev = item["last_evaluated_at"]
            if lev and (last_ev is None or lev > last_ev):
                last_ev = lev
        cts["last_evaluated_at"] = last_ev
        denom = cts["total"] - cts["not_applicable"]
        cts["score"] = round((cts["compliant"] + 0.5 * cts["partial"]) / denom * 100, 1) if denom > 0 else 0.0
        summary_data = cts
    else:
        sd = compute_summary(db, client_id, fw_enum)
        summary_data = sd

    return {
        "framework": fw_value,
        "scan_id": scan_id,
        "scan_name": scan.name if scan_id and scan else None,
        "summary": {
            "total": summary_data["total"],
            "compliant": summary_data["compliant"],
            "non_compliant": summary_data["non_compliant"],
            "partial": summary_data["partial"],
            "not_applicable": summary_data["not_applicable"],
            "score": summary_data["score"],
            "last_evaluated_at": summary_data["last_evaluated_at"],
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
    try:
        counts = recompute_client_framework(db, client_id, fw)
    except Exception as exc:
        logger.exception("Recompute failed for client=%s framework=%s", client_id, fw.value)
        raise HTTPException(status_code=500, detail=f"Recompute failed: {type(exc).__name__}: {exc}")
    return {"framework": fw.value, "counts": counts}


# ── Bulk import (admin) ───────────────────────────────────────────────────────

def _parse_import_file(filename: str, raw: bytes) -> List[Dict[str, Any]]:
    """Accept either CSV or JSON. CSV columns: control_id, parent, domain, title, description, weight."""
    name = (filename or "").lower()
    text = raw.decode("utf-8-sig", errors="replace")
    if name.endswith(".json"):
        data = json.loads(text)
        rows = data["controls"] if isinstance(data, dict) and "controls" in data else data
        if not isinstance(rows, list):
            raise HTTPException(status_code=400, detail="JSON must be a list of control objects or {controls: [...]}")
        return rows
    # CSV (default)
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "control_id" not in [f.lower() for f in reader.fieldnames]:
        raise HTTPException(status_code=400, detail="CSV must have a 'control_id' column")
    rows = []
    for r in reader:
        rows.append({k.lower(): (v or None) for k, v in r.items()})
    return rows


@router.post("/frameworks/{framework}/import/")
async def import_controls(
    framework: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Bulk-upsert controls into a framework catalog.

    Accepts CSV (preferred) with columns: control_id, parent, domain, title, description, weight.
    Or JSON: list of control objects (same fields).
    Existing rows are updated by control_id; new rows are created.
    """
    fw = _coerce_framework(framework)
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty file")

    rows = _parse_import_file(file.filename or "", raw)
    created = updated = 0
    for r in rows:
        cid = (r.get("control_id") or r.get("controlid") or "").strip()
        if not cid:
            continue
        title = (r.get("title") or cid).strip()
        parent = (r.get("parent") or r.get("parent_control_id") or "").strip() or None
        domain = (r.get("domain") or "").strip() or None
        description = (r.get("description") or title).strip() or None
        weight_raw = r.get("weight")
        try:
            weight = int(weight_raw) if weight_raw not in (None, "") else (0 if not parent else 1)
        except (TypeError, ValueError):
            weight = 1

        existing = (
            db.query(FrameworkControl)
            .filter(FrameworkControl.framework == fw, FrameworkControl.control_id == cid)
            .first()
        )
        if existing:
            existing.parent_control_id = parent
            existing.domain = domain
            existing.title = title
            existing.description = description
            existing.weight = weight
            updated += 1
        else:
            db.add(FrameworkControl(
                framework=fw, control_id=cid, parent_control_id=parent,
                domain=domain, title=title, description=description, weight=weight,
            ))
            created += 1
    db.commit()
    logger.info("Imported %s: created=%d updated=%d", fw.value, created, updated)
    return {"framework": fw.value, "created": created, "updated": updated, "total_uploaded": len(rows)}
