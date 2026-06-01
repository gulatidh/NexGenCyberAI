"""Phase 5 — semantic learning memory across engagements.

The story: every completed AgentRun (and every completed
ScheduledMissionRun) is post-processed by an LLM that extracts 3-7
atomic learnings — patterns observed, corrections made, recommendations
that landed well, pitfalls encountered. Each atom is embedded with the
configured embedding model (default OpenAI text-embedding-3-small,
1536-d) and stored in the `mission_learnings` table.

On the next agent run, `find_relevant(query, …)` embeds the new agent's
instruction + context, computes cosine similarity against the stored
embeddings, filters by recency / scope, and returns the top-k atoms.
The caller prepends them to the prompt as "## Prior learnings".

Storage choice: the embedding is a JSON-encoded list of floats kept on
the row itself. SQLite + Azure SQL both treat it as plain text. We
compute cosine similarity in Python — fast enough up to ~10k rows. When
we cross that threshold we promote to a real vector column on Azure SQL
(native VECTOR type) and pgvector / sqlite-vss on the other side.

The whole subsystem is opt-in (`AISettings.semantic_learning_enabled`).
Disabled → extract_learnings/find_relevant become no-ops.
"""
from __future__ import annotations
import json
import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session

from api.models.models import AISettings, MissionLearning

logger = logging.getLogger(__name__)


# Categories the extractor LLM is allowed to emit. Anything else gets
# coerced to "pattern" so the data stays clean for downstream filters.
_VALID_CATEGORIES = {"pattern", "correction", "recommendation", "pitfall"}

# Max atoms per source — keeps any single engagement from dominating the
# retrieval ranking. 7 is generous; LLMs tend to over-produce when asked.
_MAX_ATOMS_PER_SOURCE = 7

# Default recency window for retrieval. Older learnings still in the
# table but excluded from injection. Operator can adjust per-query.
_DEFAULT_RECENCY_DAYS = 180


_EXTRACTION_SYSTEM = """You are extracting durable lessons from a completed security engagement.

You will be given the engagement's output text (an agent briefing, a
report, etc.) along with brief metadata. Pull out 3-7 ATOMIC learnings
that would help a similar engagement in the future. Each atom must:

  • Be one or two sentences. No bullet sub-lists inside an atom.
  • State a concrete claim — a pattern observed, a correction the analyst
    made, a recommendation that landed, or a pitfall avoided.
  • Be transferable. Generic enough that a different client could apply
    it. Avoid client-specific names, IPs, or asset IDs.
  • NOT restate the engagement summary or executive overview — those are
    too coarse to retrieve against.

Output STRICT JSON only — no prose, no fences:

{
  "learnings": [
    {"category": "pattern" | "correction" | "recommendation" | "pitfall",
     "text": "<one or two sentences>"},
    ...
  ]
}
"""


def is_enabled(db: Session) -> bool:
    try:
        row = db.query(AISettings).first()
        return bool(row and getattr(row, "semantic_learning_enabled", False))
    except Exception as exc:
        logger.warning("semantic_learning_enabled lookup failed: %s", exc)
        return False


# ── Extraction ───────────────────────────────────────────────────────────────


async def extract_learnings(
    db: Session,
    *,
    text: str,
    source_kind: str,
    source_id: str,
    client_id: Optional[str] = None,
    agent_key: Optional[str] = None,
    domain: Optional[str] = None,
    extra_context: str = "",
) -> int:
    """Run the extractor LLM, embed each atom, persist to mission_learnings.

    Returns the number of learnings written. Returns 0 if the feature is
    disabled, the input is too short to bother with, or extraction fails."""
    if not is_enabled(db):
        return 0
    if not text or len(text.strip()) < 200:
        return 0

    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage
    except Exception as exc:
        logger.warning("LLM unavailable for learning extraction: %s", exc)
        return 0

    metadata_block = (
        f"## Engagement metadata\n"
        f"- source_kind: {source_kind}\n"
        f"- domain: {domain or 'unknown'}\n"
        f"- agent: {agent_key or 'n/a'}\n"
    )
    if extra_context:
        metadata_block += f"- extra_context: {extra_context}\n"
    user_body = metadata_block + "\n## Engagement output\n\n" + text.strip()[:8000]

    try:
        llm = get_llm(temperature=0.2, max_tokens=1024)
        result = await llm.ainvoke([
            SystemMessage(content=_EXTRACTION_SYSTEM),
            HumanMessage(content=user_body),
        ])
    except Exception as exc:
        logger.warning("learning extraction LLM call failed: %s", exc)
        return 0

    raw = result.content if hasattr(result, "content") else str(result)
    if isinstance(raw, list):
        raw = "\n".join(str(p) for p in raw)
    raw = (raw or "").strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1]
        if raw.endswith("```"):
            raw = raw[:-3]
    try:
        start = raw.find("{")
        end = raw.rfind("}")
        parsed = json.loads(raw[start:end + 1]) if start >= 0 and end > start else {}
    except Exception as exc:
        logger.warning("learning JSON parse failed: %s", exc)
        parsed = {}
    atoms_raw = parsed.get("learnings") or []

    atoms: List[Dict[str, str]] = []
    for a in atoms_raw[:_MAX_ATOMS_PER_SOURCE]:
        if not isinstance(a, dict):
            continue
        cat = str(a.get("category") or "").lower().strip()
        if cat not in _VALID_CATEGORIES:
            cat = "pattern"
        txt = str(a.get("text") or "").strip()
        if len(txt) < 30:
            continue
        atoms.append({"category": cat, "text": txt[:600]})
    if not atoms:
        return 0

    # Embed all atoms in one batch — cheaper than one-call-per-atom.
    embeddings: List[Optional[List[float]]] = [None] * len(atoms)
    try:
        from core.ai_providers import get_embeddings
        embedder = get_embeddings()
        vectors = embedder.embed_documents([a["text"] for a in atoms])
        if isinstance(vectors, list) and len(vectors) == len(atoms):
            embeddings = vectors  # type: ignore[assignment]
    except Exception as exc:
        # Embedding failure is non-fatal — we still keep the text so
        # future retrieval can fall back to keyword match.
        logger.warning("embedding failed (storing text-only): %s", exc)

    written = 0
    for atom, vec in zip(atoms, embeddings):
        row = MissionLearning(
            source_kind=source_kind,
            source_id=source_id,
            client_id=client_id,
            agent_key=agent_key,
            domain=domain,
            category=atom["category"],
            text=atom["text"],
            embedding_json=json.dumps(vec) if vec is not None else None,
        )
        db.add(row)
        written += 1
    try:
        db.commit()
    except Exception as exc:
        logger.warning("learning commit failed: %s", exc)
        db.rollback()
        return 0
    return written


# ── Retrieval ────────────────────────────────────────────────────────────────


def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b:
        return 0.0
    n = min(len(a), len(b))
    dot = 0.0
    na = 0.0
    nb = 0.0
    for i in range(n):
        x = a[i]
        y = b[i]
        dot += x * y
        na += x * x
        nb += y * y
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / math.sqrt(na * nb)


def find_relevant(
    db: Session,
    *,
    query_text: str,
    client_id: Optional[str] = None,
    agent_key: Optional[str] = None,
    domain: Optional[str] = None,
    k: int = 5,
    recency_days: int = _DEFAULT_RECENCY_DAYS,
) -> List[Dict[str, Any]]:
    """Return up to k learnings ranked by cosine similarity to `query_text`.

    Filters: prefers same agent_key, then same domain, then global. Drops
    rows older than `recency_days`. When semantic learning is disabled or
    no embeddings exist, falls back to most-recent text-only rows of the
    same agent/domain.
    """
    if not is_enabled(db):
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=recency_days)
    q = db.query(MissionLearning).filter(MissionLearning.created_at >= cutoff)
    # Soft-prefer matching agent/domain — pull a wider pool then re-rank.
    candidates = q.order_by(MissionLearning.created_at.desc()).limit(400).all()
    if not candidates:
        return []

    # Compute query embedding once.
    qvec: Optional[List[float]] = None
    try:
        from core.ai_providers import get_embeddings
        embedder = get_embeddings()
        result = embedder.embed_query(query_text[:4000])
        if isinstance(result, list):
            qvec = result
    except Exception as exc:
        logger.warning("query embedding failed (falling back to text-only): %s", exc)

    def relevance_boost(row: MissionLearning) -> float:
        boost = 0.0
        if agent_key and row.agent_key == agent_key:
            boost += 0.08
        if domain and row.domain == domain:
            boost += 0.05
        if client_id and row.client_id == client_id:
            boost += 0.04
        return boost

    scored: List[Tuple[float, MissionLearning]] = []
    for row in candidates:
        sim = 0.0
        if qvec and row.embedding_json:
            try:
                rvec = json.loads(row.embedding_json)
                if isinstance(rvec, list):
                    sim = _cosine(qvec, rvec)
            except Exception:
                pass
        sim += relevance_boost(row)
        if qvec is None and row.embedding_json is None:
            # No embeddings on either side — use recency as the sole signal.
            # Map "newer is better" into the same 0..1 scale by giving recent
            # rows a small synthetic score.
            sim = 0.05 + relevance_boost(row)
        scored.append((sim, row))

    scored.sort(key=lambda t: t[0], reverse=True)
    top = scored[:k]
    return [
        {
            "id": r.id,
            "category": r.category,
            "text": r.text,
            "agent_key": r.agent_key,
            "domain": r.domain,
            "score": round(sim, 4),
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for sim, r in top if r.text
    ]


def render_learnings_block(learnings: List[Dict[str, Any]]) -> str:
    """Format retrieved learnings into a markdown block that can be prepended
    to an agent's instruction. Empty input → empty string (caller can no-op)."""
    if not learnings:
        return ""
    lines = [
        "## Prior learnings (semantically similar from past engagements — apply where relevant)",
    ]
    for L in learnings:
        cat = (L.get("category") or "pattern").upper()
        lines.append(f"- [{cat}] {L['text']}")
    lines.append("")
    return "\n".join(lines)
