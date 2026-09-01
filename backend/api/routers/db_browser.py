"""Database Browser — admin-only read-only introspection of the live database."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import text, inspect as sa_inspect
from typing import Any

from db.database import get_db, engine
from core.security import get_current_user
from core.trial import is_admin

router = APIRouter(prefix="/admin/db", tags=["db-browser"])


def _require_admin(user=Depends(get_current_user)):
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin access required.")
    return user


@router.get("/tables")
def list_tables(
    db: Session = Depends(get_db),
    user=Depends(_require_admin),
):
    """List all tables with row counts."""
    try:
        insp = sa_inspect(engine)
        table_names = insp.get_table_names()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not inspect tables: {exc}")

    results = []
    for name in sorted(table_names):
        try:
            count = db.execute(text(f'SELECT COUNT(*) FROM "{name}"')).scalar() or 0
        except Exception:
            count = -1
        results.append({"table": name, "row_count": count})
    return results


@router.get("/tables/{table_name}/schema")
def table_schema(
    table_name: str,
    user=Depends(_require_admin),
):
    """Return column definitions for a table."""
    try:
        insp = sa_inspect(engine)
        valid_tables = insp.get_table_names()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if table_name not in valid_tables:
        raise HTTPException(status_code=404, detail=f"Table '{table_name}' not found.")

    try:
        columns = insp.get_columns(table_name)
        pk_constraint = insp.get_pk_constraint(table_name)
        pk_cols = set(pk_constraint.get("constrained_columns", []))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return [
        {
            "name": col["name"],
            "type": str(col["type"]),
            "nullable": col.get("nullable", True),
            "primary_key": col["name"] in pk_cols,
            "default": str(col.get("default") or "") or None,
        }
        for col in columns
    ]


@router.get("/tables/{table_name}/rows")
def table_rows(
    table_name: str,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user=Depends(_require_admin),
):
    """Return paginated rows from a table."""
    try:
        insp = sa_inspect(engine)
        valid_tables = insp.get_table_names()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if table_name not in valid_tables:
        raise HTTPException(status_code=404, detail=f"Table '{table_name}' not found.")

    offset = (page - 1) * limit
    try:
        dialect = engine.dialect.name
        if dialect == "mssql":
            sql = text(
                f'SELECT * FROM "{table_name}" ORDER BY (SELECT NULL) '
                f"OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY"
            )
        else:
            sql = text(f'SELECT * FROM "{table_name}" LIMIT {limit} OFFSET {offset}')
        result = db.execute(sql)
        columns = list(result.keys())
        rows = [[_serialize(v) for v in row] for row in result.fetchall()]
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Query failed: {exc}")

    return {"columns": columns, "rows": rows, "page": page, "limit": limit}


@router.get("/tables/{table_name}/columns/{column_name}/samples")
def column_samples(
    table_name: str,
    column_name: str,
    db: Session = Depends(get_db),
    user=Depends(_require_admin),
):
    """Return top 20 distinct values and their counts for a column."""
    try:
        insp = sa_inspect(engine)
        valid_tables = insp.get_table_names()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if table_name not in valid_tables:
        raise HTTPException(status_code=404, detail=f"Table '{table_name}' not found.")

    valid_cols = {c["name"] for c in insp.get_columns(table_name)}
    if column_name not in valid_cols:
        raise HTTPException(status_code=404, detail=f"Column '{column_name}' not found.")

    try:
        dialect = engine.dialect.name
        if dialect == "mssql":
            sql = text(
                f'SELECT TOP 20 "{column_name}", COUNT(*) as cnt '
                f'FROM "{table_name}" GROUP BY "{column_name}" ORDER BY cnt DESC'
            )
        else:
            sql = text(
                f'SELECT "{column_name}", COUNT(*) as cnt '
                f'FROM "{table_name}" GROUP BY "{column_name}" ORDER BY cnt DESC LIMIT 20'
            )
        result = db.execute(sql)
        return [{"value": _serialize(row[0]), "count": row[1]} for row in result.fetchall()]
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Sample query failed: {exc}")


def _serialize(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (int, float, bool, str)):
        return v
    try:
        return str(v)
    except Exception:
        return repr(v)
