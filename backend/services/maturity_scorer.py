"""Phase 8E — per-STRIDE-category maturity scoring.

Each STRIDE (or methodology) category gets a 0-5 score reflecting how
well the customer's existing controls cover threats of that kind. The
score is driven by:

  - Threat status mix on this model: more `mitigated` / `compensated`
    statuses on this category → higher score.
  - Linked finding ratio: when each threat in a category points to a
    finding that's been closed, that's evidence the control works.
  - Mitigation coverage: threats with at least one mitigation that has
    a control_refs entry score higher than ungrounded threats.

The result is a dict `{category: score_0_to_5}` stored on
ThreatModel.maturity_scores and surfaced in the UI as a radar chart.

This is intentionally heuristic — not a CMMI assessment, just a useful
visual that says "Repudiation coverage is thin compared to Tampering."
"""
from __future__ import annotations
import logging
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def compute_maturity_scores(
    db: Session,
    client_id: Optional[str],
    methodology: str,
    threats: List[Dict[str, Any]],
) -> Dict[str, float]:
    """Compute one 0-5 score per category present in the threats list."""
    if not threats:
        return {}

    # Group threats by category, count each maturity signal.
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for t in threats:
        cat = (t.get("category") or "").lower().strip()
        if not cat:
            continue
        by_cat.setdefault(cat, []).append(t)

    # Closed-finding lookup — best-effort, single query keyed by id.
    closed_finding_ids: set = set()
    try:
        from api.models.models import Finding
        all_linked: set = set()
        for cat_threats in by_cat.values():
            for t in cat_threats:
                for fid in (t.get("linked_finding_ids") or []):
                    if isinstance(fid, str):
                        all_linked.add(fid)
        if all_linked:
            rows = db.query(Finding.id, Finding.status).filter(Finding.id.in_(list(all_linked))).all()
            for fid, status in rows:
                if (status or "").lower() in ("closed", "remediated", "accepted"):
                    closed_finding_ids.add(fid)
    except Exception:
        logger.exception("maturity: closed-finding lookup failed (continuing)")

    scores: Dict[str, float] = {}
    for cat, cat_threats in by_cat.items():
        n = len(cat_threats)
        if n == 0:
            continue
        # ── Signals ────────────────────────────────────────────────────────
        # status_mix: how many threats are in mitigated/compensated/n_a state
        mitigated = sum(1 for t in cat_threats if (t.get("status") or "").lower() in ("mitigated", "compensated", "not_applicable"))
        # detection_covered: detection_status == 'detected'
        detected = sum(1 for t in cat_threats if (t.get("detection_status") or "").lower() == "detected")
        # finding_evidence_closed: ≥1 linked_finding_id that's closed
        finding_closed = sum(
            1 for t in cat_threats
            if any(fid in closed_finding_ids for fid in (t.get("linked_finding_ids") or []))
        )
        # grounded ratio
        grounded = sum(1 for t in cat_threats if t.get("is_grounded"))
        # severity drag — high+critical threats lower the score
        critical_high = sum(1 for t in cat_threats if (t.get("severity") or "").lower() in ("critical", "high"))

        # Weights — tuned to land scores in a usable 1..5 range
        score = (
            (mitigated / n) * 2.0       # 0..2
            + (detected / n) * 1.2      # 0..1.2
            + (finding_closed / n) * 0.8  # 0..0.8
            + (grounded / n) * 0.5      # 0..0.5 — evidence quality
        )
        # Penalty: unmitigated critical/high drag the score down
        unmitigated_ch = sum(
            1 for t in cat_threats
            if (t.get("severity") or "").lower() in ("critical", "high")
            and (t.get("status") or "").lower() == "identified"
        )
        score -= (unmitigated_ch / n) * 1.0
        # Clamp to [0, 5]
        scores[cat] = round(max(0.0, min(5.0, score)), 2)

    return scores


def maturity_summary(scores: Dict[str, float]) -> Dict[str, Any]:
    """Return a small summary for the dashboard / detail page header."""
    if not scores:
        return {"avg": 0.0, "weakest": None, "strongest": None, "n_categories": 0}
    vals = list(scores.values())
    weakest = min(scores, key=lambda k: scores[k])
    strongest = max(scores, key=lambda k: scores[k])
    return {
        "avg": round(sum(vals) / len(vals), 2),
        "weakest": weakest,
        "weakest_score": scores[weakest],
        "strongest": strongest,
        "strongest_score": scores[strongest],
        "n_categories": len(scores),
    }
