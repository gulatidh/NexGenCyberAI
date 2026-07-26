"""Project CRUD endpoints. A Project is the layer between Client and
Connector/Scan/Asset, e.g. a specific application or workload."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import List

from api.models.models import Asset, AssetStatus, Client, Connector, Project, Scan
from api.schemas.schemas import ProjectCreate, ProjectResponse, ProjectUpdate
from db.database import get_db
from core.security import get_current_user
from core.authz import require_scoped_role, AccessRole, AccessScope

router = APIRouter(prefix="/clients/{client_id}/projects", tags=["projects"])


@router.get("/", response_model=List[ProjectResponse])
async def list_projects(client_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    return db.query(Project).filter(Project.client_id == client_id).order_by(Project.name.asc()).all()


@router.post("/", response_model=ProjectResponse, status_code=201)
async def create_project(
    client_id: str,
    payload: ProjectCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    if not db.query(Client).filter(Client.id == client_id).first():
        raise HTTPException(status_code=404, detail="Client not found")
    project = Project(
        client_id=client_id,
        name=payload.name.strip(),
        description=payload.description,
        environment=payload.environment,
        cloud_provider=payload.cloud_provider,
        metadata_=payload.metadata_ or {},
    )
    db.add(project)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"Project '{payload.name}' already exists for this client")
    db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    client_id: str, project_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)
):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    p = db.query(Project).filter(Project.id == project_id, Project.client_id == client_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    return p


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    client_id: str,
    project_id: str,
    payload: ProjectUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    p = db.query(Project).filter(Project.id == project_id, Project.client_id == client_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        if k == "metadata_":
            p.metadata_ = v or {}
        else:
            setattr(p, k, v)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Project name already in use for this client")
    db.refresh(p)
    return p


@router.delete("/{project_id}", status_code=204)
async def delete_project(
    client_id: str, project_id: str, db: Session = Depends(get_db), user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.EDITOR, AccessScope.CLIENT, client_id, db, user)
    p = db.query(Project).filter(Project.id == project_id, Project.client_id == client_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    if p.name == "Default":
        raise HTTPException(status_code=400, detail="Cannot delete the Default project")
    if db.query(Connector).filter(Connector.project_id == project_id).count() > 0:
        raise HTTPException(status_code=409, detail="Project still has connectors. Move or delete them first.")
    db.delete(p)
    db.commit()


@router.get("/{project_id}/summary")
async def project_summary(
    client_id: str, project_id: str, db: Session = Depends(get_db), user=Depends(get_current_user),
):
    require_scoped_role(AccessRole.READER, AccessScope.CLIENT, client_id, db, user)
    p = db.query(Project).filter(Project.id == project_id, Project.client_id == client_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    return {
        "id": p.id,
        "name": p.name,
        "connector_count": db.query(Connector).filter(Connector.project_id == project_id).count(),
        "asset_count": db.query(Asset).filter(
            Asset.project_id == project_id, Asset.status == AssetStatus.ACTIVE.value,
        ).count(),
        "scan_count": db.query(Scan).filter(Scan.project_id == project_id).count(),
    }
