"""
Pull control-level compliance evaluations from Microsoft Defender for Cloud's
regulatoryCompliance API.

Defender already maps & evaluates the entire CIS Microsoft Azure Foundations
Benchmark (and NIST 800-53, ISO 27001, PCI DSS) against the customer's
subscription — far more comprehensive than the per-check logic in the Azure
connector. This module fetches those evaluations and feeds them into our
ClientControlStatus table.

Requires Defender for Cloud Standard tier on the subscription. On Free tier
the regulatoryCompliance API returns empty / 403; callers should treat the
return value of None as "Defender unavailable, fall back to per-check logic".
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from azure.identity import ClientSecretCredential, ManagedIdentityCredential

logger = logging.getLogger(__name__)


@dataclass
class ControlEvaluation:
    control_id: str               # Normalized, e.g. "1.1.1" or "AC-2"
    standard_name: str            # The Defender standard that produced this
    state: str                    # "Passed" | "Failed" | "Skipped" | "Unsupported"
    failing_resources: List[Dict[str, Any]] = field(default_factory=list)


# Map our framework value → list of substring patterns to match against Defender
# regulatory standard names (case-insensitive, punctuation-insensitive). Tries
# each in order; picks the highest-version match if multiple hits.
_FW_TO_DEFENDER_PATTERNS: Dict[str, List[str]] = {
    "cis_azure":      ["cismicrosoftazure", "azurecis"],
    "nist_800_53":    ["nistsp80053", "nist80053"],
    "iso_27001":      ["iso27001"],
    "pci_dss":        ["pcidss", "pcidssv4"],
}


def _slug(s: str) -> str:
    """Lowercase + drop punctuation/whitespace for fuzzy name matching."""
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _build_credential(credentials: Dict[str, Any]):
    if credentials.get("use_managed_identity"):
        return ManagedIdentityCredential()
    return ClientSecretCredential(
        tenant_id=credentials["tenant_id"],
        client_id=credentials["client_id"],
        client_secret=credentials["client_secret"],
    )


def _select_standard(standards: List[Any], framework: str) -> Optional[Any]:
    patterns = _FW_TO_DEFENDER_PATTERNS.get(framework)
    if not patterns:
        return None
    matches: List[Any] = []
    for std in standards:
        slug = _slug(std.name or "")
        for p in patterns:
            if p in slug:
                matches.append(std)
                break
    if not matches:
        return None
    # Prefer the one with the highest version-like suffix
    matches.sort(key=lambda s: (s.name or ""), reverse=True)
    return matches[0]


def _normalize_assessment_resources(assessment) -> List[Dict[str, Any]]:
    """Extract the failing-resource list from a regulatory compliance assessment."""
    out: List[Dict[str, Any]] = []
    rd = getattr(assessment, "resource_details", None)
    if rd is not None:
        rid = getattr(rd, "id", None) or getattr(rd, "source", None) or str(rd)
        if rid:
            out.append({
                "id": str(rid),
                "name": getattr(assessment, "display_name", "") or "",
                "category": getattr(assessment, "category", "") or "",
            })
    return out


async def get_regulatory_compliance(
    credentials: Dict[str, Any],
    framework: str,
) -> Optional[List[ControlEvaluation]]:
    """Fetch control-level evaluations from Defender for Cloud.

    Returns None when:
      - the framework isn't supported by Defender's built-in standards
      - Defender Standard tier isn't enabled on the subscription
      - the SDK call fails for any reason (logged as a warning)
    """
    try:
        from azure.mgmt.security import SecurityCenter
    except ImportError:
        logger.warning("azure-mgmt-security not installed; skipping Defender compliance pull")
        return None

    subscription_id = credentials.get("subscription_id")
    if not subscription_id:
        logger.warning("No subscription_id in credentials; cannot pull Defender compliance")
        return None

    cred = _build_credential(credentials)
    sc = SecurityCenter(cred, subscription_id)

    # 1. Find the matching standard
    try:
        standards = list(sc.regulatory_compliance_standards.list())
    except Exception as exc:
        logger.warning("Defender regulatoryCompliance unavailable (Standard tier required?): %s", exc)
        return None

    if not standards:
        logger.info("No Defender regulatory standards enabled on subscription %s", subscription_id)
        return None

    target = _select_standard(standards, framework)
    if not target:
        logger.info(
            "No Defender standard matches framework %s (available: %s)",
            framework, ", ".join(s.name for s in standards),
        )
        return None
    logger.info("Defender standard for %s: %s", framework, target.name)

    # 2. List controls in the standard
    try:
        controls = list(sc.regulatory_compliance_controls.list(target.name))
    except Exception as exc:
        logger.warning("Failed to list Defender controls for %s: %s", target.name, exc)
        return None

    out: List[ControlEvaluation] = []
    for ctrl in controls:
        ctrl_name = ctrl.name or ""
        state = getattr(ctrl, "state", None) or "Unsupported"

        failing: List[Dict[str, Any]] = []
        if state == "Failed":
            try:
                assessments = list(
                    sc.regulatory_compliance_assessments.list(target.name, ctrl_name)
                )
                for a in assessments:
                    a_state = getattr(a, "state", "")
                    if a_state in ("Failed", "Unhealthy"):
                        failing.extend(_normalize_assessment_resources(a))
            except Exception as exc:
                logger.debug("Could not list assessments for %s: %s", ctrl_name, exc)

        out.append(ControlEvaluation(
            control_id=ctrl_name,
            standard_name=target.name,
            state=state,
            failing_resources=failing,
        ))

    logger.info(
        "Defender compliance for %s/%s: %d controls (passed=%d, failed=%d, skipped=%d)",
        framework, target.name, len(out),
        sum(1 for c in out if c.state == "Passed"),
        sum(1 for c in out if c.state == "Failed"),
        sum(1 for c in out if c.state == "Skipped"),
    )
    return out
