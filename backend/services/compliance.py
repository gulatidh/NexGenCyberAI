"""Framework compliance derivation — translate findings into per-control statuses."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from sqlalchemy.orm import Session

from api.models.models import (
    Asset, ClientControlStatus, ControlStatus, Finding, FrameworkControl, FrameworkType, Scan,
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


def _auto_evidence(status_value: str, n_open: int, n_hist: int, covered: bool) -> str:
    """Human-readable rationale for an auto-derived control status, so the
    compliance report shows *why* every control is in its state — not a blank
    evidence cell for the compliant / not-applicable majority. Prefixed
    'Auto:' so a later manual/Defender edit is never clobbered."""
    if status_value == "non_compliant":
        return f"Auto: {n_open} open finding(s) mapped to this control require remediation."
    if status_value == "partial":
        return f"Auto: {n_open} open of {n_hist} mapped finding(s) — partially addressed."
    if status_value == "compliant":
        if n_hist:
            return f"Auto: {n_hist} mapped finding(s), none currently open — control satisfied."
        return "Auto: exercised by a scan with no failing findings mapped to this control."
    return "Auto: not evaluated — no scan or finding signal maps to this control yet."


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

    # Build the universe of controls the connectors *actually* tested for this
    # framework. Coverage is gated on which Azure resource types are present in
    # the Asset table — if no storage accounts were discovered, storage controls
    # are NOT marked covered (and therefore stay N/A rather than fake-Compliant).
    covered_set: set = set()
    if has_completed_scan:
        try:
            from connectors.azure.control_mappings import covered_controls_for_asset_types
            # Query which asset types we actually have records for (asset_type is
            # the provider-native type, e.g. "Microsoft.Compute/virtualMachines")
            asset_types_rows = (
                db.query(Asset.asset_type)
                .filter(Asset.client_id == client_id, Asset.asset_type.isnot(None))
                .distinct()
                .all()
            )
            present_resource_types = {r[0] for r in asset_types_rows if r[0]}
            covered_set = {
                _normalize(c)
                for c in covered_controls_for_asset_types(fw_value, present_resource_types)
            }
            logger.debug(
                "Coverage for %s client=%s: %d resource types → %d controls covered",
                fw_value, client_id, len(present_resource_types), len(covered_set),
            )
        except Exception as exc:
            logger.warning("covered_controls_for_asset_types failed for %s: %s", fw_value, exc)

    # ZAP frameworks: each completed scan of that framework type exercises
    # the entire catalog (every rule runs). So coverage = all catalog
    # control_ids when at least one completed scan exists for this framework.
    if fw_value in ("zap_unauth_passive", "zap_auth_active"):
        has_zap_scan = db.query(Scan).filter(
            Scan.client_id == client_id,
            Scan.framework == fw_value,
            Scan.status == "completed",
        ).first() is not None
        if has_zap_scan:
            zap_ctrls = (
                db.query(FrameworkControl.control_id)
                .filter(FrameworkControl.framework == fw_value)
                .all()
            )
            covered_set = {_normalize(c[0]) for c in zap_ctrls}

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

    ai_cutoff = now - timedelta(hours=24)

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

        # Check for a recent AI assessment that corrects the auto-derived status.
        # AI can see actual asset metadata and scan content; its verdict is more
        # accurate than the coverage-heuristic when they disagree.
        final_status = derived_status
        ev = _auto_evidence(derived_status.value, len(opens), len(hists), key in covered_set)
        if existing_row and existing_row.ai_assessment_json:
            try:
                ai = json.loads(existing_row.ai_assessment_json)
                assessed_at_raw = ai.get("assessed_at")
                ai_conf = (ai.get("confidence") or "").lower()
                ai_corrected = (ai.get("corrected_status") or "").lower().replace("-", "_")
                # Apply AI verdict when: recent assessment + high/medium confidence +
                # AI disagrees with auto-derive (prevents AI from silently locking in wrong answers)
                if (
                    assessed_at_raw
                    and ai_corrected
                    and ai_conf in ("high", "medium")
                    and ai_corrected != derived_status.value
                ):
                    assessed_at = datetime.fromisoformat(assessed_at_raw.replace("Z", "+00:00"))
                    if assessed_at > ai_cutoff:
                        try:
                            final_status = ControlStatus(ai_corrected)
                            gap = ai.get("gap_analysis", "")
                            ev = f"AI Assessment ({ai_conf} confidence): {gap}" if gap else f"AI Assessment ({ai_conf} confidence)."
                        except ValueError:
                            pass  # Unknown status string — keep derived
            except Exception:
                pass

        if existing_row is None:
            existing_row = ClientControlStatus(
                client_id=client_id,
                framework_control_id=ctrl.id,
                status=final_status,
                derived=True,
                derived_finding_ids=hists,
                evidence=ev,
                last_evaluated_at=now,
            )
            db.add(existing_row)
        else:
            existing_row.status = final_status
            existing_row.derived = True
            existing_row.derived_finding_ids = hists
            # Refresh auto-evidence, but never clobber a manual/Defender note.
            if not existing_row.evidence or str(existing_row.evidence).startswith(("Auto:", "AI Assessment")):
                existing_row.evidence = ev
            existing_row.last_evaluated_at = now

        # Skip categories/functions (weight=0) for counting; they're parents
        if ctrl.weight > 0:
            counts[final_status.value] = counts.get(final_status.value, 0) + 1

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


def recompute_all_frameworks_for_client_bg(client_id: str) -> None:
    """Background-task entry point: opens its own session, never raises out.

    Recomputing all three frameworks touches ~740 controls and is too heavy
    to run inline in the scan-ingest request — it blocked the scanner's POST
    past its client timeout and added memory pressure mid-request. Run it off
    the response path so findings (already committed before this) land fast
    and reliably regardless of recompute cost."""
    from db.database import SessionLocal
    db = SessionLocal()
    try:
        recompute_all_frameworks_for_client(db, client_id)
    except Exception:
        logger.exception("Background framework recompute failed for %s", client_id)
    finally:
        db.close()


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
