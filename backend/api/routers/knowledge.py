"""Knowledge Base API — list (grouped by category), search, stats, detail.

Auth: read-only endpoints; any authenticated user can browse. Write/edit
endpoints will be added later when the file-upload UI lands.
"""
from __future__ import annotations
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from db.database import get_db
from core.security import get_current_user
from api.models.models import KnowledgeFile, KnowledgeFileSection

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


CATEGORY_LABELS = {
    "frameworks_and_standards": "Frameworks & Standards",
    "threat_intelligence": "Threat Intelligence",
    "compliance": "Compliance",
    "playbooks": "Playbooks",
}


def _section_to_dict(s: KnowledgeFileSection) -> Dict[str, Any]:
    return {
        "id": s.id,
        "position": s.position,
        "name": s.name,
        "section_type": s.section_type,
        "body": s.body or {},
    }


def _file_summary(f: KnowledgeFile) -> Dict[str, Any]:
    body = f.sections or []
    return {
        "id": f.id,
        "name": f.name,
        "category": f.category,
        "category_label": CATEGORY_LABELS.get(f.category, f.category.replace("_", " ").title()),
        "description": f.description,
        "version": f.version,
        "size_kb": f.size_kb,
        "used_by": f.used_by or [],
        "section_count": len(body),
        "sections": [_section_to_dict(s) for s in body],
    }


@router.get("/")
async def list_knowledge_files(
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return knowledge files grouped by category. If `category` is set,
    returns only that category. Each file includes its sections so the
    frontend doesn't need a second request to render the expanded view."""
    q = db.query(KnowledgeFile).options(joinedload(KnowledgeFile.sections))
    if category:
        q = q.filter(KnowledgeFile.category == category)
    files = q.order_by(KnowledgeFile.category, KnowledgeFile.name).all()

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in files:
        grouped[f.category].append(_file_summary(f))

    return {
        "categories": [
            {
                "key": cat,
                "label": CATEGORY_LABELS.get(cat, cat.replace("_", " ").title()),
                "count": len(items),
                "files": items,
            }
            for cat, items in grouped.items()
        ],
    }


@router.get("/search")
async def search_knowledge(
    q: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Full-text-ish search across name, description, section names, and
    section body keys/items. Returns flat list with match snippets."""
    if not q or len(q.strip()) < 2:
        return {"query": q, "results": []}

    needle = q.lower().strip()
    files = (
        db.query(KnowledgeFile)
        .options(joinedload(KnowledgeFile.sections))
        .all()
    )

    results = []
    for f in files:
        matches: List[str] = []
        if needle in (f.name or "").lower():
            matches.append(f"name: {f.name}")
        if needle in (f.description or "").lower():
            matches.append(f"description: {(f.description or '')[:120]}")
        for sec in f.sections:
            if needle in (sec.name or "").lower():
                matches.append(f"section: {sec.name}")
            body = sec.body or {}
            # Check items, keys, text
            for items_key in ("items", "keys"):
                v = body.get(items_key)
                if isinstance(v, list):
                    hits = [x for x in v if needle in str(x).lower()]
                    if hits:
                        matches.append(f"{sec.name} → {', '.join(str(h) for h in hits[:3])}")
                elif isinstance(v, dict):
                    hits = [k for k in v.keys() if needle in str(k).lower()]
                    if hits:
                        matches.append(f"{sec.name} → {', '.join(hits[:3])}")
            if "text" in body and needle in str(body["text"]).lower():
                matches.append(f"{sec.name} → text match")

        if matches:
            results.append({
                "file_id": f.id,
                "name": f.name,
                "category": f.category,
                "category_label": CATEGORY_LABELS.get(f.category, f.category.replace("_", " ").title()),
                "matches": matches[:6],
            })

    return {"query": q, "results": results}


@router.get("/stats")
async def knowledge_stats(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Header counts: total files, total size in KB, distinct agents using them."""
    files = db.query(KnowledgeFile).all()
    agents: Set[str] = set()
    total_size = 0
    for f in files:
        for a in (f.used_by or []):
            agents.add(a)
        total_size += int(f.size_kb or 0)
    return {
        "file_count": len(files),
        "agent_count": len(agents),
        "total_size_kb": total_size,
    }


@router.get("/{file_id}")
async def get_knowledge_file(
    file_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    f = (
        db.query(KnowledgeFile)
        .options(joinedload(KnowledgeFile.sections))
        .filter(KnowledgeFile.id == file_id)
        .first()
    )
    if not f:
        raise HTTPException(status_code=404, detail="Knowledge file not found")
    return _file_summary(f)
