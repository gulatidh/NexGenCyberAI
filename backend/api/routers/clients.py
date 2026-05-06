"""Client profile CRUD endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ..models.models import Client
from ..schemas.schemas import ClientCreate, ClientUpdate, ClientResponse, DashboardSummary
from ...db.database import get_db
from ...core.security import get_current_user

router = APIRouter(prefix="/clients", tags=["clients"])


@router.get("/", response_model=List[ClientResponse])
async def list_clients(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(Client).filter(Client.is_active == True).all()


@router.post("/", response_model=ClientResponse, status_code=status.HTTP_201_CREATED)
async def create_client(payload: ClientCreate, db: Session = Depends(get_db), _=Depends(get_current_user)):
    if db.query(Client).filter(Client.slug == payload.slug).first():
        raise HTTPException(status_code=400, detail="Slug already exists")
    client = Client(**payload.model_dump())
    db.add(client)
    db.commit()
    db.refresh(client)
    return client


@router.get("/{client_id}", response_model=ClientResponse)
async def get_client(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@router.patch("/{client_id}", response_model=ClientResponse)
async def update_client(client_id: str, payload: ClientUpdate, db: Session = Depends(get_db), _=Depends(get_current_user)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(client, field, value)
    db.commit()
    db.refresh(client)
    return client


@router.delete("/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_client(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    client.is_active = False
    db.commit()
