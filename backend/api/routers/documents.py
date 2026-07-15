"""Security document upload and RAG querying."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.models.models import SecurityDocument
from api.schemas.schemas import SecurityDocumentResponse
from db.database import get_db
from core.security import get_current_user
from core.authz import require_editor_anywhere

router = APIRouter(prefix="/clients/{client_id}/documents", tags=["documents"])


class RAGQueryRequest(BaseModel):
    question: str


@router.get("/", response_model=List[SecurityDocumentResponse])
async def list_documents(client_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    return (
        db.query(SecurityDocument)
        .filter(SecurityDocument.client_id == client_id)
        .order_by(SecurityDocument.uploaded_at.desc())
        .all()
    )


@router.post("/", response_model=SecurityDocumentResponse, dependencies=[Depends(require_editor_anywhere)])
async def upload_document(
    client_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    content = await file.read()
    if len(content) > 20 * 1024 * 1024:  # 20 MB limit
        raise HTTPException(status_code=413, detail="File too large — 20MB maximum")

    from services.rag_service import extract_text, chunk_text
    text = extract_text(content, file.filename or "upload", file.content_type or "")
    chunks = chunk_text(text)

    doc = SecurityDocument(
        client_id=client_id,
        filename=file.filename or "upload",
        content_type=file.content_type or "application/octet-stream",
        size_bytes=len(content),
        extracted_text=text,
        chunk_count=len(chunks),
        uploaded_by=user.get("email") or user.get("preferred_username") or "",
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    return doc


@router.delete("/{doc_id}", dependencies=[Depends(require_editor_anywhere)])
async def delete_document(client_id: str, doc_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    doc = db.query(SecurityDocument).filter(
        SecurityDocument.id == doc_id,
        SecurityDocument.client_id == client_id,
    ).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    db.delete(doc)
    db.commit()
    return {"deleted": True}


@router.post("/query")
async def query_documents(
    client_id: str,
    payload: RAGQueryRequest,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    from services.rag_service import query_documents as _query
    return await _query(db, client_id, payload.question)
