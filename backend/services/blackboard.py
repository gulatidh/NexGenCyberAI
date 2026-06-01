"""Phase 5D — shared blackboard for cross-agent pollination.

When multiple catalog agents run against the same Scan, later agents
benefit from seeing what earlier agents already concluded. The
blackboard is a tiny scan-scoped buffer: each AgentRun, after producing
its output, posts a one-paragraph summary to `scan_blackboard`. The next
agent's run prepends the recent entries as "## Other agents on this
scan" context.

The summary is the first ~600 characters of the output, lightly cleaned
of markdown headers. Cheap; no LLM call needed. If the first paragraph
is too short or empty, we just take the first non-empty line.

Toggle: `AISettings.blackboard_enabled` (default ON — the cost is
negligible). Disabled → post/read become no-ops.
"""
from __future__ import annotations
import logging
import re
from typing import List, Optional

from sqlalchemy.orm import Session

from api.models.models import AISettings, ScanBlackboardEntry

logger = logging.getLogger(__name__)

_MAX_SUMMARY_CHARS = 600
_DEFAULT_RECENT = 6  # entries injected as context per agent run


def is_enabled(db: Session) -> bool:
    try:
        row = db.query(AISettings).first()
        # Default True if the toggle column exists but is null.
        if row is None:
            return True
        v = getattr(row, "blackboard_enabled", True)
        return bool(v) if v is not None else True
    except Exception as exc:
        logger.warning("blackboard_enabled lookup failed: %s", exc)
        return False


def _summarise(text: str) -> str:
    """First-paragraph extract, with markdown headers stripped. The intent
    is to give the next agent a one-paragraph executive synopsis without
    paying for another LLM call."""
    if not text:
        return ""
    # Drop level-3 / level-2 markdown headers — they're internal section
    # markers, not narrative.
    cleaned = re.sub(r"^#{1,6}\s+.*$", "", text, flags=re.MULTILINE)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    # First paragraph (anything before the first blank line). If too short,
    # fall back to the first 600 chars of the full text.
    first_para = cleaned.split("\n\n", 1)[0].strip()
    if len(first_para) < 80 and len(cleaned) > 80:
        first_para = cleaned[:_MAX_SUMMARY_CHARS]
    return first_para[:_MAX_SUMMARY_CHARS]


def post(
    db: Session,
    *,
    scan_id: str,
    agent_run_id: Optional[str],
    agent_name: Optional[str],
    agent_key: Optional[str],
    summary_text: str,
) -> Optional[ScanBlackboardEntry]:
    """Write a blackboard entry. Returns the row (or None if disabled / empty)."""
    summary = _summarise(summary_text)
    if not summary:
        return None
    row = ScanBlackboardEntry(
        scan_id=scan_id,
        agent_run_id=agent_run_id,
        agent_name=(agent_name or "")[:200],
        agent_key=(agent_key or "")[:128],
        summary=summary,
    )
    try:
        db.add(row)
        db.commit()
        db.refresh(row)
        return row
    except Exception as exc:
        logger.warning("blackboard post commit failed: %s", exc)
        db.rollback()
        return None


def recent_entries(db: Session, *, scan_id: str, k: int = _DEFAULT_RECENT) -> List[ScanBlackboardEntry]:
    if not is_enabled(db):
        return []
    return (
        db.query(ScanBlackboardEntry)
        .filter(ScanBlackboardEntry.scan_id == scan_id)
        .order_by(ScanBlackboardEntry.created_at.desc())
        .limit(k)
        .all()
    )


def render_blackboard_block(entries: List[ScanBlackboardEntry], *, exclude_agent_key: Optional[str] = None) -> str:
    """Markdown block to prepend to the next agent's instruction. Excludes
    entries from the same agent_key so an agent doesn't read its own past
    summary."""
    items = [e for e in entries if e.summary and e.agent_key != exclude_agent_key]
    if not items:
        return ""
    lines = [
        "## Other agents on this scan (their conclusions so far — build on these, do not contradict without cause)",
    ]
    for e in items:
        name = e.agent_name or e.agent_key or "agent"
        lines.append(f"### {name}")
        lines.append(e.summary)
        lines.append("")
    return "\n".join(lines)
