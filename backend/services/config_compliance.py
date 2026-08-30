"""Config-based compliance evaluation.

Evaluates framework controls directly against asset configuration data collected
during discovery (Asset.provider_metadata). This is authoritative over finding-based
derivation: if a storage account exists and https_only=False, the control FAILS
regardless of whether a finding was ever emitted.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from api.models.models import Asset

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Control → config check catalogue
# Each key is (framework_value, normalized_control_id).
# Each value is a list of check dicts; multiple checks for one control means
# ALL are evaluated and results are merged across asset types.
# ---------------------------------------------------------------------------

# check dict shape:
# {
#   "resource_types": [...],   # list of lowercase asset_type values to match
#   "config_path": "config.key",  # dot-path into provider_metadata JSON
#   "expected": <value>,           # expected value for a PASS
#   "check_type": "equals"|"not_equals"|"truthy"|"falsy"|"contains",
#   "requirement": "human-readable description of what must be true",
# }

_CHECKS: Dict[Tuple[str, str], List[Dict]] = {

    # ── NIST 800-53 ─────────────────────────────────────────────────────────
    ("nist_800_53", "sc-8"): [
        {
            "resource_types": ["microsoft.storage/storageaccounts"],
            "config_path": "config.https_only",
            "expected": True, "check_type": "equals",
            "requirement": "Secure transfer required (HTTPS only) must be enabled on all storage accounts",
        },
        {
            "resource_types": ["microsoft.web/sites"],
            "config_path": "config.https_only",
            "expected": True, "check_type": "equals",
            "requirement": "HTTPS only must be enforced on all App Service web apps",
        },
    ],
    ("nist_800_53", "sc-13"): [
        {
            "resource_types": ["microsoft.storage/storageaccounts"],
            "config_path": "config.min_tls_version",
            "expected": "TLS1_2", "check_type": "equals",
            "requirement": "Minimum TLS version must be TLS 1.2 for all storage accounts",
        },
        {
            "resource_types": ["microsoft.sql/servers"],
            "config_path": "config.minimal_tls_version",
            "expected": "1.2", "check_type": "equals",
            "requirement": "Minimum TLS version must be 1.2 for all SQL servers",
        },
    ],
    ("nist_800_53", "sc-28"): [
        {
            "resource_types": ["microsoft.compute/virtualmachines"],
            "config_path": "config.disk_encryption_enabled",
            "expected": True, "check_type": "equals",
            "requirement": "OS disk encryption must be enabled on all virtual machines",
        },
    ],
    ("nist_800_53", "ac-3"): [
        {
            "resource_types": ["microsoft.storage/storageaccounts"],
            "config_path": "config.allow_blob_public_access",
            "expected": True, "check_type": "not_equals",
            "requirement": "Public blob access must be disabled on all storage accounts",
        },
    ],
    ("nist_800_53", "cp-9"): [
        {
            "resource_types": ["microsoft.keyvault/vaults"],
            "config_path": "config.soft_delete_enabled",
            "expected": True, "check_type": "equals",
            "requirement": "Soft delete must be enabled on all Key Vaults",
        },
    ],
    ("nist_800_53", "sc-12"): [
        {
            "resource_types": ["microsoft.keyvault/vaults"],
            "config_path": "config.purge_protection_enabled",
            "expected": True, "check_type": "equals",
            "requirement": "Purge protection must be enabled on all Key Vaults",
        },
    ],

    # ── CIS Azure ───────────────────────────────────────────────────────────
    ("cis_azure", "3.1"): [
        {
            "resource_types": ["microsoft.storage/storageaccounts"],
            "config_path": "config.https_only",
            "expected": True, "check_type": "equals",
            "requirement": "CIS Azure 3.1: Ensure 'Secure transfer required' is set to 'Enabled'",
        },
    ],
    ("cis_azure", "3.5"): [
        {
            "resource_types": ["microsoft.storage/storageaccounts"],
            "config_path": "config.allow_blob_public_access",
            "expected": True, "check_type": "not_equals",
            "requirement": "CIS Azure 3.5: Ensure that 'Public access level' is disabled for storage accounts with blob containers",
        },
    ],
    ("cis_azure", "3.13"): [
        {
            "resource_types": ["microsoft.storage/storageaccounts"],
            "config_path": "config.min_tls_version",
            "expected": "TLS1_2", "check_type": "equals",
            "requirement": "CIS Azure 3.13: Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'",
        },
    ],
    ("cis_azure", "8.5"): [
        {
            "resource_types": ["microsoft.keyvault/vaults"],
            "config_path": "config.soft_delete_enabled",
            "expected": True, "check_type": "equals",
            "requirement": "CIS Azure 8.5: Ensure that Azure Key Vault has soft delete enabled",
        },
        {
            "resource_types": ["microsoft.keyvault/vaults"],
            "config_path": "config.purge_protection_enabled",
            "expected": True, "check_type": "equals",
            "requirement": "CIS Azure 8.5: Ensure that Azure Key Vault has purge protection enabled",
        },
    ],
    ("cis_azure", "7.3"): [
        {
            "resource_types": ["microsoft.compute/virtualmachines"],
            "config_path": "config.disk_encryption_enabled",
            "expected": True, "check_type": "equals",
            "requirement": "CIS Azure 7.3: Ensure that 'OS disk' is encrypted with CMK or platform-managed key",
        },
    ],

    # ── CIS v8 ──────────────────────────────────────────────────────────────
    ("cis_v8", "3.10"): [
        {
            "resource_types": ["microsoft.storage/storageaccounts"],
            "config_path": "config.https_only",
            "expected": True, "check_type": "equals",
            "requirement": "CIS v8 3.10: Encrypt sensitive data in transit — enforce HTTPS on storage accounts",
        },
        {
            "resource_types": ["microsoft.web/sites"],
            "config_path": "config.https_only",
            "expected": True, "check_type": "equals",
            "requirement": "CIS v8 3.10: Encrypt sensitive data in transit — enforce HTTPS on App Service",
        },
    ],
    ("cis_v8", "3.11"): [
        {
            "resource_types": ["microsoft.compute/virtualmachines"],
            "config_path": "config.disk_encryption_enabled",
            "expected": True, "check_type": "equals",
            "requirement": "CIS v8 3.11: Encrypt sensitive data at rest — OS disk encryption required on VMs",
        },
    ],
    ("cis_v8", "3.3"): [
        {
            "resource_types": ["microsoft.storage/storageaccounts"],
            "config_path": "config.allow_blob_public_access",
            "expected": True, "check_type": "not_equals",
            "requirement": "CIS v8 3.3: Configure data access control lists — disable public blob access",
        },
    ],
    ("cis_v8", "11.1"): [
        {
            "resource_types": ["microsoft.keyvault/vaults"],
            "config_path": "config.soft_delete_enabled",
            "expected": True, "check_type": "equals",
            "requirement": "CIS v8 11.1: Establish and maintain a data recovery process — enable Key Vault soft delete",
        },
    ],
    ("cis_v8", "11.4"): [
        {
            "resource_types": ["microsoft.keyvault/vaults"],
            "config_path": "config.purge_protection_enabled",
            "expected": True, "check_type": "equals",
            "requirement": "CIS v8 11.4: Establish and maintain data backups — enable Key Vault purge protection",
        },
    ],

    # ── NIST CSF ────────────────────────────────────────────────────────────
    ("nist_csf", "pr.ds-02"): [
        {
            "resource_types": ["microsoft.storage/storageaccounts"],
            "config_path": "config.https_only",
            "expected": True, "check_type": "equals",
            "requirement": "PR.DS-02: Data-in-transit protection — enforce HTTPS on storage accounts",
        },
        {
            "resource_types": ["microsoft.web/sites"],
            "config_path": "config.https_only",
            "expected": True, "check_type": "equals",
            "requirement": "PR.DS-02: Data-in-transit protection — enforce HTTPS on App Service",
        },
    ],
    ("nist_csf", "pr.ds-01"): [
        {
            "resource_types": ["microsoft.compute/virtualmachines"],
            "config_path": "config.disk_encryption_enabled",
            "expected": True, "check_type": "equals",
            "requirement": "PR.DS-01: Data-at-rest protection — enable OS disk encryption on VMs",
        },
    ],
    ("nist_csf", "pr.ds-11"): [
        {
            "resource_types": ["microsoft.keyvault/vaults"],
            "config_path": "config.purge_protection_enabled",
            "expected": True, "check_type": "equals",
            "requirement": "PR.DS-11: Data backups protection — enable Key Vault purge protection",
        },
    ],
    ("nist_csf", "pr.aa-05"): [
        {
            "resource_types": ["microsoft.storage/storageaccounts"],
            "config_path": "config.allow_blob_public_access",
            "expected": True, "check_type": "not_equals",
            "requirement": "PR.AA-05: Access permissions managed — disable public blob access on storage accounts",
        },
    ],
}


def _get_nested(data: Any, path: str) -> Any:
    """Navigate 'config.https_only' in {'config': {'https_only': True}}."""
    parts = path.split(".")
    cur = data
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _check_passes(found: Any, expected: Any, check_type: str) -> bool:
    if check_type == "equals":
        return found == expected
    if check_type == "not_equals":
        return found != expected
    if check_type == "truthy":
        return bool(found)
    if check_type == "falsy":
        return not bool(found)
    if check_type == "contains":
        return expected in str(found or "")
    return False


def evaluate_control_from_config(
    db: Session,
    client_id: str,
    framework_value: str,
    normalized_control_id: str,
) -> Optional[Dict]:
    """Return config-based compliance result or None if no checks defined.

    Returns dict with:
    - status: compliant | non_compliant | partial | not_applicable
    - evidence_text: human-readable string for the evidence column
    - config_evidence: structured evidence for the UI
    """
    checks = _CHECKS.get((framework_value, normalized_control_id))
    if not checks:
        return None

    all_asset_results: List[Dict] = []
    requirements: List[Dict] = []

    for chk in checks:
        resource_types = [rt.lower() for rt in chk["resource_types"]]
        requirements.append({
            "resource_type": resource_types[0],
            "requirement": chk["requirement"],
            "expected": str(chk["expected"]),
        })

        assets = (
            db.query(Asset)
            .filter(
                Asset.client_id == client_id,
                func.lower(Asset.asset_type).in_(resource_types),
            )
            .all()
        )

        for asset in assets:
            # provider_metadata may be a dict (JSON column) or serialized string
            if isinstance(asset.provider_metadata, dict):
                meta = asset.provider_metadata
            elif isinstance(asset.provider_metadata, str):
                try:
                    meta = json.loads(asset.provider_metadata)
                except Exception:
                    meta = {}
            else:
                meta = {}

            found = _get_nested(meta, chk["config_path"])
            config_key = chk["config_path"].split(".")[-1]

            if found is None:
                result = "no_data"
                passes = False
            else:
                passes = _check_passes(found, chk["expected"], chk["check_type"])
                result = "pass" if passes else "fail"

            all_asset_results.append({
                "name": asset.name,
                "type": asset.asset_type or resource_types[0],
                "config_key": config_key,
                "found": found,
                "expected": chk["expected"],
                "result": result,
                "requirement": chk["requirement"],
            })

    if not all_asset_results:
        return {
            "status": "not_applicable",
            "evidence_text": "Config: No assets of the relevant resource type discovered for this client — control is not applicable.",
            "config_evidence": {
                "requirements": requirements,
                "assets": [],
                "summary": "No applicable assets found.",
            },
        }

    total = len(all_asset_results)
    passed = sum(1 for r in all_asset_results if r["result"] == "pass")
    failed = sum(1 for r in all_asset_results if r["result"] == "fail")
    no_data = sum(1 for r in all_asset_results if r["result"] == "no_data")

    if failed == 0 and no_data == 0:
        status = "compliant"
    elif passed == 0:
        status = "non_compliant"
    else:
        status = "partial"

    if status == "compliant":
        evidence_text = f"Config: {passed}/{total} asset(s) pass the required configuration — control satisfied."
    elif status == "partial":
        evidence_text = f"Config: {passed}/{total} asset(s) compliant, {failed} failing — partial compliance."
    else:
        evidence_text = f"Config: {failed}/{total} asset(s) failing required configuration — control not met."

    if no_data and status != "compliant":
        evidence_text += f" ({no_data} asset(s) had no configuration data.)"

    summary = (
        f"{passed}/{total} asset(s) compliant"
        + (f", {failed} failing" if failed else "")
        + (f", {no_data} missing data" if no_data else "")
    )

    return {
        "status": status,
        "evidence_text": evidence_text,
        "config_evidence": {
            "requirements": requirements,
            "assets": all_asset_results,
            "summary": summary,
        },
    }
