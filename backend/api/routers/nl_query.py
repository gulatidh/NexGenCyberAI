"""Natural language query — converts plain English to SQL and executes it safely."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel
from typing import Optional, List, Any, Dict
import re

from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/query", tags=["nl-query"])

_SCHEMA_HINT = """
Available tables and key columns (SQLite):
- findings: id, title, severity (critical/high/medium/low/info), status (open/remediated/accepted/false_positive), resource_id, resource_type, cve_id, cvss_score, control_id, framework, description, remediation, created_at, assignee_email
- risks: id, title, description, risk_level (critical/high/medium/low), likelihood, impact, risk_score, category, status, assignee_email, created_at
- scans: id, scan_type, status (pending/running/completed/failed), created_at, client_id
- agent_runs: id, agent_type, status, started_at, completed_at, client_id
- threat_entries: id, technique_id, technique_name, tactic, confidence, severity, title, created_at
- control_deficiencies: id, control_id, framework, severity, title, gap_description, remediation, created_at
- remediation_actions: id, title, action, band, priority, effort, impact, status, assigned_to, due_date

Only write SELECT queries. Do NOT use INSERT, UPDATE, DELETE, DROP, CREATE, ALTER.
Join findings to scans on findings.scan_id = scans.id and filter scans.client_id = '{client_id}'.
For other tables filter directly on client_id = '{client_id}'.
Return at most 100 rows. Use LIMIT 100.
"""


class NLQueryRequest(BaseModel):
    question: str


class NLQueryResponse(BaseModel):
    question: str
    sql: str
    columns: List[str]
    rows: List[List[Any]]
    summary: str
    row_count: int


@router.post("/nl", response_model=NLQueryResponse)
async def natural_language_query(
    client_id: str,
    payload: NLQueryRequest,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    from core.ai_providers import get_llm
    from langchain_core.messages import HumanMessage, SystemMessage

    schema = _SCHEMA_HINT.replace("{client_id}", client_id)
    system_prompt = f"""You are a SQLite query generator for a security platform. Given a natural language question, output ONLY a valid SQLite SELECT query — no explanation, no markdown, no code fences. Just the raw SQL.

{schema}

Rules:
- Always add WHERE clause filtering by client_id = '{client_id}' (or via scans.client_id for findings)
- Use LIMIT 100 always
- Only SELECT — never mutate data
- Use proper SQLite syntax"""

    llm = get_llm()
    resp = await llm.ainvoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=payload.question),
    ])
    raw_sql = resp.content.strip() if hasattr(resp, "content") else str(resp).strip()

    # Strip markdown fences if present
    raw_sql = re.sub(r"^```sql\s*", "", raw_sql, flags=re.I)
    raw_sql = re.sub(r"^```\s*", "", raw_sql)
    raw_sql = re.sub(r"\s*```$", "", raw_sql).strip()

    # Safety check — only allow SELECT
    first_word = raw_sql.split()[0].upper() if raw_sql.split() else ""
    if first_word not in ("SELECT", "WITH"):
        raise HTTPException(status_code=400, detail="Generated query is not a SELECT statement — refusing to execute.")

    # Block dangerous keywords
    dangerous = re.compile(r'\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|REPLACE)\b', re.I)
    if dangerous.search(raw_sql):
        raise HTTPException(status_code=400, detail="Query contains disallowed keywords.")

    try:
        result = db.execute(text(raw_sql))
        columns = list(result.keys())
        rows = [list(row) for row in result.fetchall()]
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Query execution failed: {exc}")

    # Generate a brief summary
    summary = f"Found {len(rows)} result{'s' if len(rows) != 1 else ''}."

    return NLQueryResponse(
        question=payload.question,
        sql=raw_sql,
        columns=columns,
        rows=rows,
        summary=summary,
        row_count=len(rows),
    )
