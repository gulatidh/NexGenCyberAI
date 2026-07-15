"""CTEM (Continuous Threat Exposure Management) program endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone

from api.models.models import CTEMProgram, CTEMPhaseNote
from api.schemas.schemas import CTEMProgramCreate, CTEMProgramResponse
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere

router = APIRouter(prefix="/clients/{client_id}/ctem", tags=["ctem"])

PHASES = ["scope", "discover", "prioritise", "validate", "mobilise"]


def _ensure_phases(db: Session, program: CTEMProgram):
    """Create missing CTEMPhaseNote rows for all 5 phases."""
    existing = {p.phase for p in program.phases}
    for phase in PHASES:
        if phase not in existing:
            db.add(CTEMPhaseNote(program_id=program.id, phase=phase))
    db.commit()
    db.refresh(program)


@router.get("/", response_model=List[CTEMProgramResponse])
async def list_programs(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(CTEMProgram).filter(CTEMProgram.client_id == client_id).order_by(CTEMProgram.created_at.desc()).all()


@router.post("/", response_model=CTEMProgramResponse, dependencies=[Depends(require_editor_anywhere)])
async def create_program(
    client_id: str,
    payload: CTEMProgramCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    program = CTEMProgram(
        client_id=client_id,
        name=payload.name,
        description=payload.description,
        created_by=user.get("email") or user.get("preferred_username") or "",
    )
    db.add(program)
    db.commit()
    db.refresh(program)
    _ensure_phases(db, program)
    return program


@router.get("/{program_id}", response_model=CTEMProgramResponse)
async def get_program(client_id: str, program_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    p = db.query(CTEMProgram).filter(CTEMProgram.id == program_id, CTEMProgram.client_id == client_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="CTEM program not found")
    return p


@router.patch("/{program_id}/phases/{phase}", dependencies=[Depends(require_editor_anywhere)])
async def update_phase(
    client_id: str,
    program_id: str,
    phase: str,
    notes: str = None,
    completed: bool = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    if phase not in PHASES:
        raise HTTPException(status_code=400, detail=f"Phase must be one of {PHASES}")
    pn = db.query(CTEMPhaseNote).join(CTEMProgram).filter(
        CTEMPhaseNote.program_id == program_id,
        CTEMPhaseNote.phase == phase,
        CTEMProgram.client_id == client_id,
    ).first()
    if not pn:
        raise HTTPException(status_code=404, detail="Phase note not found")
    if notes is not None:
        pn.notes = notes
    if completed is not None:
        pn.completed = completed
        if completed and not pn.completed_at:
            pn.completed_at = datetime.now(timezone.utc)
            pn.completed_by = user.get("email") or ""
        # Advance program to next phase if this one just completed
        if completed:
            program = pn.program
            current_idx = PHASES.index(phase)
            if current_idx + 1 < len(PHASES):
                program.current_phase = PHASES[current_idx + 1]
            else:
                program.status = "completed"
    db.commit()
    return {"updated": True, "phase": phase}


@router.delete("/{program_id}", dependencies=[Depends(require_editor_anywhere)])
async def delete_program(client_id: str, program_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    p = db.query(CTEMProgram).filter(CTEMProgram.id == program_id, CTEMProgram.client_id == client_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="CTEM program not found")
    db.delete(p)
    db.commit()
    return {"deleted": True}
