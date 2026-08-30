"""
Cross-framework control mappings for Azure connector checks.

Each connector check has a stable `check_id` key. _CHECK_MAP[check_id] returns
{framework_value: [control_ids]} so one finding can contribute compliance
status to all of NIST 800-53, NIST CSF 2.0, CIS v8.1, and CIS Azure 5.0.

Adding a new Azure check: pick a stable check_id, add a row, call
mappings_for(check_id) when constructing the ConnectorFinding.
"""
from typing import Dict, List, Set

# Per-port mapping for NSG inbound 0.0.0.0/0 findings
_PORT_TO_CIS_AZURE: Dict[int, List[str]] = {
    22:    ["6.2"],          # SSH
    3389:  ["6.1"],          # RDP
    23:    ["6.4"],           # Telnet (HTTP/UDP/other unrestricted) → broad networking ctrl
    21:    ["6.4"],           # FTP
    5900:  ["6.4"],           # VNC
    1433:  ["4.1.2", "6.4"],  # MSSQL
    3306:  ["4.1.2", "6.4"],  # MySQL
    5432:  ["4.1.2", "6.4"],  # PostgreSQL
    6379:  ["6.4"],          # Redis
    27017: ["6.4"],          # MongoDB
    9200:  ["6.4"],          # Elasticsearch
}


def nsg_port_mappings(port: int) -> Dict[str, List[str]]:
    """Mapping for NSG-allows-port-from-internet finding."""
    return {
        "cis_azure": _PORT_TO_CIS_AZURE.get(port, ["6.4"]),
        "nist_800_53": ["AC-17", "SC-7"],
        "nist_csf": ["PR.AA-04", "PR.IR-01"],
        "cis_v8": ["CIS-4.4", "CIS-12.2"],
    }


_CHECK_MAP: Dict[str, Dict[str, List[str]]] = {
    # Storage accounts
    "storage-https-only": {
        "cis_azure": ["3.1"],
        "nist_800_53": ["SC-8"],
        "nist_csf": ["PR.DS-02"],
        "cis_v8": ["CIS-3.10"],
    },
    "storage-public-blob": {
        "cis_azure": ["3.5"],
        "nist_800_53": ["AC-3"],
        "nist_csf": ["PR.AA-05"],
        "cis_v8": ["CIS-3.3"],
    },
    "storage-tls-version": {
        "cis_azure": ["3.13"],
        "nist_800_53": ["SC-8", "SC-13"],
        "nist_csf": ["PR.DS-02"],
        "cis_v8": ["CIS-3.10"],
    },

    # Key Vault
    "keyvault-soft-delete": {
        "cis_azure": ["8.5"],
        "nist_800_53": ["CP-9", "SC-12"],
        "nist_csf": ["PR.DS-11"],
        "cis_v8": ["CIS-11.1"],
    },
    "keyvault-purge-protection": {
        "cis_azure": ["8.5"],
        "nist_800_53": ["CP-9", "SC-12"],
        "nist_csf": ["PR.DS-11"],
        "cis_v8": ["CIS-11.4"],
    },

    # RBAC
    "rbac-excess-owners": {
        "cis_azure": ["1.23"],
        "nist_800_53": ["AC-6"],
        "nist_csf": ["PR.AA-05"],
        "cis_v8": ["CIS-5.4", "CIS-6.8"],
    },

    # Logging
    "activity-log-no-diag-settings": {
        "cis_azure": ["5.1.1"],
        "nist_800_53": ["AU-2", "AU-12"],
        "nist_csf": ["DE.CM-01"],
        "cis_v8": ["CIS-8.2"],
    },

    # VM security
    "vm-os-disk-not-encrypted": {
        "cis_azure": ["7.3"],
        "nist_800_53": ["SC-28", "SC-13"],
        "nist_csf": ["PR.DS-01"],
        "cis_v8": ["CIS-3.11"],
    },
    "vm-no-endpoint-protection": {
        "cis_azure": ["7.6"],
        "nist_800_53": ["SI-3"],
        "nist_csf": ["DE.CM-01"],
        "cis_v8": ["CIS-10.1"],
    },

    # Defender for Cloud assessment titles (well-known ones)
    "defender-mfa-owners": {
        "cis_azure": ["1.1.2"],
        "nist_800_53": ["AC-2", "IA-2"],
        "nist_csf": ["PR.AA-01"],
        "cis_v8": ["CIS-6.5"],
    },
    "defender-secure-transfer-storage": {
        "cis_azure": ["3.1"],
        "nist_800_53": ["SC-8"],
        "nist_csf": ["PR.DS-02"],
        "cis_v8": ["CIS-3.10"],
    },
    "defender-nsg-on-subnets": {
        "cis_azure": ["6.7"],
        "nist_800_53": ["SC-7"],
        "nist_csf": ["PR.IR-01"],
        "cis_v8": ["CIS-12.2"],
    },
    "defender-jit-vm-access": {
        "cis_azure": ["6.1", "6.2"],
        "nist_800_53": ["AC-17"],
        "nist_csf": ["PR.AA-04"],
        "cis_v8": ["CIS-6.4"],
    },
    "defender-endpoint-protection": {
        "cis_azure": ["7.6"],
        "nist_800_53": ["SI-3"],
        "nist_csf": ["DE.CM-01"],
        "cis_v8": ["CIS-10.1"],
    },
}


_DEFENDER_TITLE_TO_CHECK = {
    "MFA should be enabled on accounts with owner permissions": "defender-mfa-owners",
    "Secure transfer to storage accounts should be enabled": "defender-secure-transfer-storage",
    "Network security groups should be applied on subnets": "defender-nsg-on-subnets",
    "Just-In-Time network access control should be applied on virtual machines": "defender-jit-vm-access",
    "Endpoint protection should be installed on machines": "defender-endpoint-protection",
}


# Maps each check_id to the Azure resource_type it actually inspects.
# Coverage for a control is only claimed when the client has Asset records
# of that resource_type — i.e., the scan actually ran against those resources.
_CHECK_RESOURCE_TYPE: Dict[str, str] = {
    "storage-https-only":             "microsoft.storage/storageaccounts",
    "storage-public-blob":            "microsoft.storage/storageaccounts",
    "storage-tls-version":            "microsoft.storage/storageaccounts",
    "keyvault-soft-delete":           "microsoft.keyvault/vaults",
    "keyvault-purge-protection":      "microsoft.keyvault/vaults",
    "rbac-excess-owners":             "microsoft.authorization/roleassignments",
    "activity-log-no-diag-settings":  "microsoft.insights/diagnosticsettings",
    "vm-os-disk-not-encrypted":       "microsoft.compute/virtualmachines",
    "vm-no-endpoint-protection":      "microsoft.compute/virtualmachines",
    "defender-mfa-owners":            "microsoft.authorization/roleassignments",
    "defender-secure-transfer-storage": "microsoft.storage/storageaccounts",
    "defender-nsg-on-subnets":        "microsoft.network/networksecuritygroups",
    "defender-jit-vm-access":         "microsoft.compute/virtualmachines",
    "defender-endpoint-protection":   "microsoft.compute/virtualmachines",
}


def mappings_for(check_id: str) -> Dict[str, List[str]]:
    """Return cross-framework control mapping dict; empty if check_id unknown."""
    return dict(_CHECK_MAP.get(check_id, {}))


def defender_mappings(title: str) -> Dict[str, List[str]]:
    """Map a Defender-for-Cloud assessment title to control_mappings."""
    check = _DEFENDER_TITLE_TO_CHECK.get(title)
    return mappings_for(check) if check else {}


def covered_controls_for_asset_types(
    framework_value: str,
    present_resource_types: Set[str],
) -> List[str]:
    """Controls that the Azure connector can validate given the resource types
    actually present (from the Asset table). A control is only marked as covered
    — and therefore COMPLIANT when no findings are emitted — when the relevant
    resource type actually exists in the scanned environment.

    Controls that map to resource types not present stay N/A (no evidence either way).
    Controls from NSG port rules are included only when NSG assets are present.
    """
    present_lower = {t.lower() for t in present_resource_types}
    out: set = set()

    for check_id, mappings in _CHECK_MAP.items():
        rtype = _CHECK_RESOURCE_TYPE.get(check_id, "").lower()
        # If we don't know the resource type, or no assets of that type exist, skip
        if not rtype or rtype not in present_lower:
            continue
        for cid in mappings.get(framework_value, []) or []:
            if cid:
                out.add(cid)

    # NSG port rules covered when NSG assets exist
    if "microsoft.network/networksecuritygroups" in present_lower:
        for port_mappings in _PORT_TO_CIS_AZURE.values():
            for cid in port_mappings:
                if framework_value == "cis_azure":
                    out.add(cid)

    return sorted(out)


def all_covered_controls(framework_value: str) -> List[str]:
    """DEPRECATED: returns the static universe of controls the connector *can* check
    regardless of what was actually scanned. Prefer covered_controls_for_asset_types()
    which gates coverage on actual Asset records."""
    out: set = set()
    for mappings in _CHECK_MAP.values():
        for cid in mappings.get(framework_value, []) or []:
            if cid:
                out.add(cid)
    for mappings_for_port in _PORT_TO_CIS_AZURE.values():
        for cid in mappings_for_port:
            if framework_value == "cis_azure":
                out.add(cid)
    return sorted(out)
