"""Natural language query — converts plain English to SQL and executes it safely."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
import re

from db.database import get_db
from core.security import get_current_user

router = APIRouter(prefix="/clients/{client_id}/query", tags=["nl-query"])

_SCHEMA_HINT = """
Available tables and key columns (SQL Server / Azure SQL):
- findings: id, title, severity (critical/high/medium/low/info), status (open/remediated/accepted/false_positive), resource_id, resource_type, cve_id, cvss_score, control_id, framework, description, remediation, created_at, assignee_email, duplicate_of_id
- risks: id, title, description, risk_level (critical/high/medium/low), likelihood, impact, risk_score, category, status, assignee_email, created_at
- scans: id, scan_type, status (pending/running/completed/failed), created_at, client_id, is_live
- agent_runs: id, agent_type, status, started_at, completed_at, client_id
- threat_entries: id, technique_id, technique_name, tactic, confidence, severity, title, created_at
- control_deficiencies: id, control_id, framework, severity, title, gap_description, remediation, created_at
- remediation_actions: id, title, action, band, priority, effort, impact, status, assigned_to, due_date

Only write SELECT queries. Do NOT use INSERT, UPDATE, DELETE, DROP, CREATE, ALTER.
Join findings to scans on findings.scan_id = scans.id and filter scans.client_id = '{client_id}'.
For other tables filter directly on client_id = '{client_id}'.
Return at most 100 rows. Use TOP 100 in the SELECT clause (SQL Server syntax — NOT LIMIT).
"""


def _inject_top(sql: str, n: str) -> str:
    """Inject SELECT TOP n into the outer-most SELECT of a query (CTE-aware)."""
    # For WITH queries find the SELECT after all CTE parentheses close
    if re.match(r'\s*WITH\b', sql, re.I):
        depth = 0
        i = 0
        while i < len(sql):
            if sql[i] == '(':
                depth += 1
            elif sql[i] == ')':
                depth -= 1
            elif depth == 0:
                m = re.match(r'\bSELECT\b', sql[i:], re.I)
                if m:
                    return sql[:i] + f'SELECT TOP {n} ' + sql[i + len('SELECT'):].lstrip()
            i += 1
        return sql  # fallback — couldn't locate outer SELECT
    # Simple query: inject TOP after the first SELECT
    return re.sub(r'\bSELECT\b(?!\s+TOP\b)', f'SELECT TOP {n}', sql, count=1, flags=re.I)


def _rewrite_to_tsql(sql: str) -> str:
    """Convert common SQLite/MySQL patterns to T-SQL (Azure SQL Server)."""
    # LIMIT N  →  TOP N  (move into SELECT clause)
    limit_match = re.search(r'\bLIMIT\s+(\d+)\b', sql, re.I)
    if limit_match:
        n = limit_match.group(1)
        # Remove the LIMIT clause
        sql = re.sub(r'\bLIMIT\s+\d+\b', '', sql, flags=re.I).strip().rstrip(';')
        # Inject TOP into the outer SELECT (CTE-safe)
        if not re.search(r'\bSELECT\s+TOP\b', sql, re.I):
            sql = _inject_top(sql, n)

    # LIMIT N OFFSET M  →  already handled above (OFFSET kept if present for FETCH syntax)
    # OFFSET M ROWS FETCH NEXT N ROWS ONLY is valid T-SQL — leave as-is if present

    # Boolean literals: TRUE/FALSE → 1/0
    sql = re.sub(r'\bTRUE\b', '1', sql, flags=re.I)
    sql = re.sub(r'\bFALSE\b', '0', sql, flags=re.I)

    # ISNULL(a, b) is valid T-SQL; IFNULL(a,b) / COALESCE both work too — no change needed
    # DATE('now') / NOW() → GETDATE()
    sql = re.sub(r"\bDATE\s*\(\s*'now'\s*\)", 'GETDATE()', sql, flags=re.I)
    sql = re.sub(r'\bNOW\s*\(\s*\)', 'GETDATE()', sql, flags=re.I)

    # Ensure query ends without a trailing semicolon (pymssql handles it fine either way)
    sql = sql.strip().rstrip(';')

    return sql


class NLQueryRequest(BaseModel):
    question: str = Field(..., max_length=2000, description="Natural language question — max 2000 characters")


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
    system_prompt = f"""You are a T-SQL query generator for a security platform running on Azure SQL Server. Given a natural language question, output ONLY a valid T-SQL SELECT query — no explanation, no markdown, no code fences. Just the raw SQL.

{schema}

Rules:
- Always add WHERE clause filtering by client_id = '{client_id}' (or via scans.client_id for findings)
- Use TOP 100 in the SELECT clause — NEVER use LIMIT (this is SQL Server, not SQLite/MySQL)
- Only SELECT — never mutate data
- Use proper T-SQL / SQL Server syntax
- String concatenation uses + not ||
- Use GETDATE() not NOW() or DATE('now')
- Boolean values are 1/0 not TRUE/FALSE"""

    llm = get_llm()
    resp = await llm.ainvoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"<question>{payload.question}</question>"),
    ])
    raw_sql = resp.content.strip() if hasattr(resp, "content") else str(resp).strip()

    # Strip markdown fences if present
    raw_sql = re.sub(r"^```sql\s*", "", raw_sql, flags=re.I)
    raw_sql = re.sub(r"^```\s*", "", raw_sql)
    raw_sql = re.sub(r"\s*```$", "", raw_sql).strip()

    # Rewrite SQLite/MySQL patterns to T-SQL as a safety net
    raw_sql = _rewrite_to_tsql(raw_sql)

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
