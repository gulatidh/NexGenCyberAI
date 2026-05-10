"""Framework compliance derivation — translate findings into per-control statuses."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from sqlalchemy.orm import Session

from api.models.models import (
    ClientControlStatus, ControlStatus, Finding, FrameworkControl, FrameworkType, Scan,
)

logger = logging.getLogger(__name__)


_PREFIX_NOISE = ("nist ", "nist-", "nist_", "csf ", "csf-", "cis ", "cis-")


def _normalize(s: str) -> str:
    """Lowercase, strip, drop leading framework-prefix noise like 'NIST '.

    'NIST SC-8' → 'sc-8', 'CIS-3.10' → '3.10', 'PR.AA-04' → 'pr.aa-04'.
    Lets us match Finding.control_id against catalog control_id even when
    connectors emit prefixed forms.
    """
    out = (s or "").strip().lower()
    for noise in _PREFIX_NOISE:
        if out.startswith(noise):
            out = out[len(noise):]
            break
    return out


def derive_status_for_control(
    open_finding_ids: List[str],
    historical_finding_ids: List[str],
    is_covered_by_scan: bool = False,
) -> ControlStatus:
    """Pure function: classify a control given the findings that map to it.

    `is_covered_by_scan` says the connector ran a check that *would have*
    produced findings for this control if it failed. Absent findings on a
    covered control means it passed → COMPLIANT.
    """
    if open_finding_ids:
        # Open findings exist: non-compliant. If some are remediated/accepted too, partial.
        if len(historical_finding_ids) > len(open_finding_ids):
            return ControlStatus.PARTIAL
        return ControlStatus.NON_COMPLIANT
    if historical_finding_ids:
        # All findings cleared (remediated/accepted/false_positive)
        return ControlStatus.COMPLIANT
    if is_covered_by_scan:
        # Connector ran a check covering this control and emitted no failure → pass
        return ControlStatus.COMPLIANT
    # Never had a finding and not exercised by any scan — default to N/A
    return ControlStatus.NOT_APPLICABLE


def recompute_client_framework(
    db: Session, client_id: str, framework: FrameworkType,
) -> Dict[str, int]:
    """Re-derive every control's status for one client + framework.

    Respects user overrides (rows where derived=False) — those are not modified.
    Returns counts dict with `compliant`, `non_compliant`, `partial`, `not_applicable`,
    `overridden`, `total`.
    """
    fw_value = framework.value if hasattr(framework, "value") else str(framework)

    # Has the client run any successful scan? Used to decide whether checks
    # without findings should be treated as "passed" (compliant) or "untested" (N/A).
    has_completed_scan = db.query(Scan).filter(
        Scan.client_id == client_id,
        Scan.status == "completed",
    ).first() is not None

    # Build the universe of controls the connectors are *capable* of testing
    # for this framework. Controls in this set with no open findings are
    # COMPLIANT (the check ran and passed); controls outside it remain N/A
    # because we have no signal either way.
    covered_set: set = set()
    if has_completed_scan:
        try:
            from connectors.azure.control_mappings import all_covered_controls
            covered_set = {_normalize(c) for c in all_covered_controls(fw_value)}
        except Exception as exc:
            logger.warning("all_covered_controls failed for %s: %s", fw_value, exc)

    # 1. Pull every client finding (any framework). Two ways a finding can map to
    #    a control in this framework:
    #      (a) Finding.framework == fw_value AND normalized Finding.control_id == catalog id
    #      (b) Finding.control_mappings[fw_value] contains the catalog id
    #    (b) lets one Azure check satisfy CIS Azure + NIST 800-53 + CIS v8 simultaneously.
    finding_rows = (
        db.query(Finding.control_id, Finding.id, Finding.status, Finding.framework, Finding.control_mappings)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.client_id == client_id)
        .all()
    )
    open_by_ctrl: Dict[str, List[str]] = {}
    hist_by_ctrl: Dict[str, List[str]] = {}
    for ctrl_id, finding_id, status, finding_framework, mappings in finding_rows:
        is_open = (status or "open") == "open"
        keys: set = set()

        # Path (a): same framework, literal control_id match (after normalize)
        finding_fw_value = finding_framework.value if hasattr(finding_framework, "value") else (finding_framework or "")
        if finding_fw_value == fw_value and ctrl_id:
            keys.add(_normalize(ctrl_id))

        # Path (b): cross-framework mapping populated by the connector
        if mappings and isinstance(mappings, dict):
            for cid in mappings.get(fw_value, []) or []:
                if cid:
                    keys.add(_normalize(cid))

        for key in keys:
            if not key:
                continue
            hist_by_ctrl.setdefault(key, []).append(finding_id)
            if is_open:
                open_by_ctrl.setdefault(key, []).append(finding_id)

    # 2. Walk the catalog
    controls = (
        db.query(FrameworkControl).filter(FrameworkControl.framework == fw_value).all()
    )

    # 3. Pre-load existing status rows for this client
    existing = {
        s.framework_control_id: s
        for s in db.query(ClientControlStatus).filter(ClientControlStatus.client_id == client_id).all()
    }

    counts = {"compliant": 0, "non_compliant": 0, "partial": 0, "not_applicable": 0, "overridden": 0, "total": 0}
    now = datetime.now(timezone.utc)

    for ctrl in controls:
        counts["total"] += 1
        key = _normalize(ctrl.control_id)
        opens = open_by_ctrl.get(key, [])
        hists = hist_by_ctrl.get(key, [])
        derived_status = derive_status_for_control(opens, hists, is_covered_by_scan=key in covered_set)

        existing_row = existing.get(ctrl.id)
        if existing_row and not existing_row.derived:
            # User override — don't touch the status, but refresh derived_finding_ids for display
            existing_row.derived_finding_ids = hists
            counts["overridden"] += 1
            counts[existing_row.status.value if hasattr(existing_row.status, "value") else existing_row.status] = (
                counts.get(existing_row.status.value if hasattr(existing_row.status, "value") else existing_row.status, 0) + 1
            )
            continue

        if existing_row is None:
            existing_row = ClientControlStatus(
                client_id=client_id,
                framework_control_id=ctrl.id,
                status=derived_status,
                derived=True,
                derived_finding_ids=hists,
                last_evaluated_at=now,
            )
            db.add(existing_row)
        else:
            existing_row.status = derived_status
            existing_row.derived = True
            existing_row.derived_finding_ids = hists
            existing_row.last_evaluated_at = now

        # Skip categories/functions (weight=0) for counting; they're parents
        if ctrl.weight > 0:
            counts[derived_status.value] = counts.get(derived_status.value, 0) + 1

    db.commit()
    logger.info(
        "Recomputed %s for client %s: %s",
        fw_value, client_id, counts,
    )
    return counts


def compute_summary(
    db: Session, client_id: str, framework: FrameworkType,
) -> Dict[str, int]:
    """Cheap counts query (does not re-derive)."""
    fw_value = framework.value if hasattr(framework, "value") else str(framework)
    rows = (
        db.query(ClientControlStatus, FrameworkControl)
        .join(FrameworkControl, ClientControlStatus.framework_control_id == FrameworkControl.id)
        .filter(
            ClientControlStatus.client_id == client_id,
            FrameworkControl.framework == fw_value,
            FrameworkControl.weight > 0,
        )
        .all()
    )
    counts = {"compliant": 0, "non_compliant": 0, "partial": 0, "not_applicable": 0, "total": 0, "last_evaluated_at": None}
    last: datetime | None = None
    for st, _ctrl in rows:
        counts["total"] += 1
        sv = st.status.value if hasattr(st.status, "value") else st.status
        counts[sv] = counts.get(sv, 0) + 1
        if st.last_evaluated_at and (last is None or st.last_evaluated_at > last):
            last = st.last_evaluated_at
    counts["last_evaluated_at"] = last

    denom = counts["total"] - counts["not_applicable"]
    if denom > 0:
        counts["score"] = round((counts["compliant"] + 0.5 * counts["partial"]) / denom * 100, 1)
    else:
        counts["score"] = 0.0
    return counts


def recompute_all_frameworks_for_client(db: Session, client_id: str) -> Dict[str, Dict[str, int]]:
    """Run all three frameworks. Used after a `full` scan or finding update."""
    out: Dict[str, Dict[str, int]] = {}
    for fw in (FrameworkType.NIST_CSF, FrameworkType.NIST_800_53, FrameworkType.CIS_V8):
        try:
            out[fw.value] = recompute_client_framework(db, client_id, fw)
        except Exception as exc:
            logger.exception("Recompute failed for %s / %s: %s", client_id, fw, exc)
    return out


# ── Defender for Cloud direct-write path ────────────────────────────────────

_DEFENDER_STATE_TO_STATUS = {
    "Passed": ControlStatus.COMPLIANT,
    "Failed": ControlStatus.NON_COMPLIANT,
    "Skipped": ControlStatus.NOT_APPLICABLE,
    "Unsupported": ControlStatus.NOT_APPLICABLE,
}


def apply_defender_evaluations(
    db: Session,
    client_id: str,
    framework: FrameworkType,
    evaluations: list,
) -> Dict[str, int]:
    """Upsert ClientControlStatus rows directly from Defender results.

    Bypasses the finding-based recompute because Defender is already
    authoritative — every control in the framework has a Passed/Failed/Skipped
    state from Microsoft's own evaluation.

    Respects user overrides (rows with derived=False are not touched).

    Returns counts: {compliant, non_compliant, partial, not_applicable, total, overridden, unmatched}.
    """
    from datetime import datetime, timezone
    fw_value = framework.value if hasattr(framework, "value") else str(framework)
    now = datetime.now(timezone.utc)

    catalog = {
        c.control_id: c
        for c in db.query(FrameworkControl).filter(FrameworkControl.framework == fw_value).all()
    }
    existing = {
        s.framework_control_id: s
        for s in db.query(ClientControlStatus)
        .join(FrameworkControl, ClientControlStatus.framework_control_id == FrameworkControl.id)
        .filter(ClientControlStatus.client_id == client_id, FrameworkControl.framework == fw_value)
        .all()
    }

    counts = {"compliant": 0, "non_compliant": 0, "partial": 0, "not_applicable": 0,
              "total": 0, "overridden": 0, "unmatched": 0}
    seen_control_ids: set = set()

    for ev in evaluations:
        norm = _normalize(ev.control_id)
        ctrl = None
        for cid, c in catalog.items():
            if _normalize(cid) == norm:
                ctrl = c
                break
        if not ctrl:
            counts["unmatched"] += 1
            continue
        seen_control_ids.add(ctrl.id)

        new_status = _DEFENDER_STATE_TO_STATUS.get(ev.state, ControlStatus.NOT_APPLICABLE)
        evidence = f"Verified by Microsoft Defender for Cloud (state={ev.state}, standard={ev.standard_name})"
        if ev.failing_resources:
            evidence += f"\nFailing resources ({len(ev.failing_resources)}): " + ", ".join(
                (r.get("name") or r.get("id", "")[:80]) for r in ev.failing_resources[:5]
            )

        st = existing.get(ctrl.id)
        if st and not st.derived:
            counts["overridden"] += 1
            continue
        if st is None:
            st = ClientControlStatus(
                client_id=client_id,
                framework_control_id=ctrl.id,
                status=new_status,
                derived=True,
                evidence=evidence,
                derived_finding_ids=[],
                last_evaluated_at=now,
            )
            db.add(st)
        else:
            st.status = new_status
            st.evidence = evidence
            st.derived = True
            st.derived_finding_ids = []
            st.last_evaluated_at = now

        counts["total"] += 1
        if ctrl.weight > 0:
            counts[new_status.value] = counts.get(new_status.value, 0) + 1

    db.commit()
    logger.info(
        "Defender apply for %s / client %s: %s",
        fw_value, client_id, counts,
    )
    return counts
