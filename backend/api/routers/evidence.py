"""Compliance evidence collection — gather and package evidence for audit."""
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere

router = APIRouter(prefix="/clients/{client_id}/evidence", tags=["evidence"])


@router.get("/package")
async def generate_evidence_package(
    client_id: str,
    framework: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(require_editor_anywhere),
):
    """Generate a ZIP containing evidence for compliance audit."""
    from api.models.models import (
        Finding, Scan, AgentRun, ControlDeficiency, RemediationAction,
        FrameworkAssessment, Client,
    )

    client = db.query(Client).filter(Client.id == client_id).first()
    client_name = client.name if client else client_id

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Summary JSON
        findings_q = (
            db.query(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .filter(Scan.client_id == client_id)
        )
        open_findings = findings_q.filter(Finding.status == "open").count()
        remediated = findings_q.filter(Finding.status == "remediated").count()

        summary = {
            "client": client_name,
            "framework": framework or "All",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "open_findings": open_findings,
            "remediated_findings": remediated,
        }
        zf.writestr("00_summary.json", json.dumps(summary, indent=2))

        # 2. Open findings CSV
        import csv
        import io as _io
        csv_buf = _io.StringIO()
        w = csv.writer(csv_buf)
        w.writerow([
            "id", "title", "severity", "status", "resource_id",
            "cve_id", "cvss_score", "control_id", "framework", "created_at",
        ])
        q = findings_q
        if framework:
            q = q.filter(Finding.framework == framework)
        for f in q.order_by(Finding.cvss_score.desc()).limit(5000).all():
            w.writerow([
                f.id, f.title,
                f.severity.value if hasattr(f.severity, "value") else f.severity,
                f.status.value if hasattr(f.status, "value") else f.status,
                f.resource_id or "", f.cve_id or "", f.cvss_score or "",
                f.control_id or "",
                f.framework.value if hasattr(f.framework, "value") else (f.framework or ""),
                f.created_at.isoformat() if f.created_at else "",
            ])
        zf.writestr("01_findings.csv", csv_buf.getvalue())

        # 3. Control deficiencies
        deficiencies = db.query(ControlDeficiency).filter(ControlDeficiency.client_id == client_id)
        if framework:
            deficiencies = deficiencies.filter(ControlDeficiency.framework == framework)
        def_data = [
            {
                "control_id": d.control_id,
                "framework": d.framework,
                "severity": d.severity,
                "title": d.title,
                "gap": d.gap_description,
                "remediation": d.remediation,
            }
            for d in deficiencies.all()
        ]
        zf.writestr("02_control_deficiencies.json", json.dumps(def_data, indent=2))

        # 4. Remediation actions
        rem_data = [
            {
                "title": r.title,
                "status": r.status,
                "priority": r.priority,
                "band": r.band,
                "assigned_to": r.assigned_to,
                "due_date": str(r.due_date) if r.due_date else None,
            }
            for r in db.query(RemediationAction).filter(RemediationAction.client_id == client_id).all()
        ]
        zf.writestr("03_remediation_actions.json", json.dumps(rem_data, indent=2))

        # 5. Agent run log
        runs = (
            db.query(AgentRun)
            .filter(AgentRun.client_id == client_id, AgentRun.status == "completed")
            .order_by(AgentRun.started_at.desc())
            .limit(50)
            .all()
        )
        run_data = [
            {
                "agent_type": r.agent_type.value if hasattr(r.agent_type, "value") else str(r.agent_type),
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            }
            for r in runs
        ]
        zf.writestr("04_agent_runs.json", json.dumps(run_data, indent=2))

        # 6. Framework assessments
        assessments = (
            db.query(FrameworkAssessment)
            .filter(FrameworkAssessment.client_id == client_id)
            .order_by(FrameworkAssessment.assessed_at.desc())
            .limit(10)
            .all()
        )
        ass_data = [
            {
                "framework": a.framework.value if hasattr(a.framework, "value") else str(a.framework),
                "overall_score": a.overall_score,
                "assessed_at": a.assessed_at.isoformat() if a.assessed_at else None,
            }
            for a in assessments
        ]
        zf.writestr("05_framework_assessments.json", json.dumps(ass_data, indent=2))

    buf.seek(0)
    fname = (
        f"aegis-evidence-{client_name.replace(' ', '_')}"
        f"-{datetime.now(timezone.utc).strftime('%Y%m%d')}.zip"
    )
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )
