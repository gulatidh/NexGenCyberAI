"""
Technology Registry — CRUD for TechnologyType taxonomy and AssetTypeMapping rules.
Also provides per-asset override endpoint.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional
from pydantic import BaseModel

from db.database import get_db
from core.auth import get_current_user
from api.models.models import TechnologyType, AssetTypeMapping, Asset

router = APIRouter(tags=["technology-registry"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class TechTypeCreate(BaseModel):
    name: str
    category: Optional[str] = None
    sub_category: Optional[str] = None
    color: Optional[str] = None
    description: Optional[str] = None


class TechTypeUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    sub_category: Optional[str] = None
    color: Optional[str] = None
    description: Optional[str] = None


class MappingCreate(BaseModel):
    provider_type: str
    technology_type_id: str


class OverrideClassBody(BaseModel):
    override_class: Optional[str] = None  # None clears the override


# ── Technology Types ──────────────────────────────────────────────────────────

@router.get("/technology-types/")
def list_technology_types(
    client_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    types = db.query(TechnologyType).order_by(TechnologyType.category, TechnologyType.name).all()
    result = []
    for t in types:
        row = {
            "id": t.id,
            "name": t.name,
            "category": t.category,
            "sub_category": t.sub_category,
            "color": t.color,
            "description": t.description,
            "is_builtin": t.is_builtin,
            "asset_count": 0,
        }
        if client_id:
            # Count assets using this type (via mapping or override)
            count = 0
            mappings = db.query(AssetTypeMapping).filter(
                AssetTypeMapping.technology_type_id == t.id
            ).all()
            provider_types = [m.provider_type.lower() for m in mappings]
            if provider_types:
                count += (
                    db.query(func.count(Asset.id))
                    .filter(
                        Asset.client_id == client_id,
                        func.lower(Asset.asset_type).in_(provider_types),
                        Asset.override_class.is_(None),
                    )
                    .scalar() or 0
                )
            # Count overridden assets
            count += (
                db.query(func.count(Asset.id))
                .filter(
                    Asset.client_id == client_id,
                    Asset.override_class == t.name,
                )
                .scalar() or 0
            )
            row["asset_count"] = count
        result.append(row)
    return result


@router.post("/technology-types/")
def create_technology_type(
    body: TechTypeCreate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    tt = TechnologyType(
        name=body.name,
        category=body.category,
        sub_category=body.sub_category,
        color=body.color,
        description=body.description,
        is_builtin=False,
    )
    db.add(tt)
    db.commit()
    db.refresh(tt)
    return {"id": tt.id, "name": tt.name, "category": tt.category,
            "sub_category": tt.sub_category, "color": tt.color,
            "description": tt.description, "is_builtin": tt.is_builtin}


@router.patch("/technology-types/{type_id}")
def update_technology_type(
    type_id: str,
    body: TechTypeUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    tt = db.query(TechnologyType).filter(TechnologyType.id == type_id).first()
    if not tt:
        raise HTTPException(status_code=404, detail="Technology type not found")
    if body.name is not None:
        tt.name = body.name
    if body.category is not None and not tt.is_builtin:
        tt.category = body.category
    if body.sub_category is not None and not tt.is_builtin:
        tt.sub_category = body.sub_category
    if body.color is not None:
        tt.color = body.color
    if body.description is not None:
        tt.description = body.description
    db.commit()
    return {"id": tt.id, "name": tt.name, "category": tt.category,
            "sub_category": tt.sub_category, "color": tt.color,
            "description": tt.description, "is_builtin": tt.is_builtin}


@router.delete("/technology-types/{type_id}")
def delete_technology_type(
    type_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    tt = db.query(TechnologyType).filter(TechnologyType.id == type_id).first()
    if not tt:
        raise HTTPException(status_code=404, detail="Technology type not found")
    if tt.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot delete built-in technology types")
    db.delete(tt)
    db.commit()
    return {"ok": True}


# ── Asset Type Mappings ───────────────────────────────────────────────────────

@router.get("/asset-type-mappings/")
def list_asset_type_mappings(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    mappings = db.query(AssetTypeMapping).order_by(AssetTypeMapping.provider_type).all()
    result = []
    for m in mappings:
        tt = db.query(TechnologyType).filter(TechnologyType.id == m.technology_type_id).first()
        result.append({
            "id": m.id,
            "provider_type": m.provider_type,
            "technology_type_id": m.technology_type_id,
            "technology_type_name": tt.name if tt else None,
            "technology_type_color": tt.color if tt else None,
        })
    return result


@router.post("/asset-type-mappings/")
def upsert_asset_type_mapping(
    body: MappingCreate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    tt = db.query(TechnologyType).filter(TechnologyType.id == body.technology_type_id).first()
    if not tt:
        raise HTTPException(status_code=404, detail="Technology type not found")
    # Upsert: update if provider_type already mapped
    existing = db.query(AssetTypeMapping).filter(
        func.lower(AssetTypeMapping.provider_type) == body.provider_type.lower()
    ).first()
    if existing:
        existing.technology_type_id = body.technology_type_id
        db.commit()
        return {"id": existing.id, "provider_type": existing.provider_type,
                "technology_type_id": existing.technology_type_id,
                "technology_type_name": tt.name}
    m = AssetTypeMapping(
        provider_type=body.provider_type.lower(),
        technology_type_id=body.technology_type_id,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return {"id": m.id, "provider_type": m.provider_type,
            "technology_type_id": m.technology_type_id,
            "technology_type_name": tt.name}


@router.delete("/asset-type-mappings/{mapping_id}")
def delete_asset_type_mapping(
    mapping_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    m = db.query(AssetTypeMapping).filter(AssetTypeMapping.id == mapping_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Mapping not found")
    db.delete(m)
    db.commit()
    return {"ok": True}


# ── Per-asset override ────────────────────────────────────────────────────────

@router.patch("/clients/{client_id}/assets/{asset_id}/override-class")
def override_asset_class(
    client_id: str,
    asset_id: str,
    body: OverrideClassBody,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    asset = db.query(Asset).filter(
        Asset.id == asset_id, Asset.client_id == client_id
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset.override_class = body.override_class  # None clears it
    db.commit()
    return {"id": asset.id, "override_class": asset.override_class}
