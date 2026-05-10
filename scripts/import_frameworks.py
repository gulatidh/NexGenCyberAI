"""
Build the framework control catalogs.

Outputs three JSON files into backend/data/frameworks/:
  - nist_csf.json       (NIST CSF 2.0)         — 6 functions, 22 categories, 108 subcategories
  - nist_800_53.json    (NIST SP 800-53 Rev 5) — 20 families, ~322 base controls (enhancements excluded)
  - cis_v8.json         (CIS Controls v8.1)    — 18 controls, 153 safeguards

NIST data sources fetched from the official OSCAL content GitHub repo (USNISTGOV/oscal-content).
CIS data is hand-encoded inline (CIS v8 reference is freely published on cisecurity.org).
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA_DIR = Path(__file__).resolve().parent.parent / "backend" / "data" / "frameworks"
NIST_CSF_URL = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json"
NIST_800_53_URL = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"


def _fetch(url: str) -> Dict[str, Any]:
    print(f"  fetching {url}")
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _statement_prose(parts: List[Dict[str, Any]]) -> str:
    """Concatenate every 'statement' part (recursively) into a single string."""
    chunks: List[str] = []
    for p in parts or []:
        if p.get("name") == "statement" and p.get("prose"):
            chunks.append(p["prose"])
        # OSCAL nests statement parts (e.g., 800-53 has a.,b.,c. items); collect those too
        for sub in p.get("parts", []) or []:
            if sub.get("name") == "item" and sub.get("prose"):
                chunks.append(f"  {sub.get('props', [{}])[0].get('value', '')} {sub['prose']}".strip())
    return "\n".join(chunks).strip()


# ── NIST CSF 2.0 ──────────────────────────────────────────────────────────────

def build_nist_csf() -> Dict[str, Any]:
    cat = _fetch(NIST_CSF_URL)["catalog"]
    controls: List[Dict[str, Any]] = []
    for func in cat.get("groups", []):
        func_id = func["id"].upper()
        func_title = func["title"]
        controls.append({
            "control_id": func_id,
            "parent": None,
            "domain": func_title,
            "title": func_title,
            "description": "",
            "weight": 0,
        })
        for cat_ctrl in func.get("controls", []):
            cat_id = cat_ctrl["id"].upper()
            cat_title = cat_ctrl["title"]
            controls.append({
                "control_id": cat_id,
                "parent": func_id,
                "domain": func_title,
                "title": cat_title,
                "description": _statement_prose(cat_ctrl.get("parts", [])),
                "weight": 0,
            })
            for sub in cat_ctrl.get("controls", []):
                sub_id = sub["id"].upper()
                # CSF subcategory titles are useless ("GV.OC-01") — use the statement prose as title
                statement = _statement_prose(sub.get("parts", []))
                title = statement.split(".")[0][:240] if statement else sub["title"]
                controls.append({
                    "control_id": sub_id,
                    "parent": cat_id,
                    "domain": func_title,
                    "title": title,
                    "description": statement,
                    "weight": 1,
                })
    return {
        "framework": "nist_csf",
        "version": "2.0",
        "source": NIST_CSF_URL,
        "controls": controls,
    }


# ── NIST SP 800-53 Rev 5 ──────────────────────────────────────────────────────

def build_nist_800_53() -> Dict[str, Any]:
    cat = _fetch(NIST_800_53_URL)["catalog"]
    controls: List[Dict[str, Any]] = []
    for fam in cat.get("groups", []):
        fam_id = fam["id"].upper()
        fam_title = fam["title"]
        controls.append({
            "control_id": fam_id,
            "parent": None,
            "domain": fam_title,
            "title": fam_title,
            "description": "",
            "weight": 0,
        })
        for ctrl in fam.get("controls", []):
            # Skip control enhancements — base controls only (e.g. AC-2, not AC-2(1))
            if "(" in ctrl["id"]:
                continue
            ctrl_id = ctrl["id"].upper().replace("AC-2.01", "AC-2")  # safety
            controls.append({
                "control_id": ctrl_id,
                "parent": fam_id,
                "domain": fam_title,
                "title": ctrl["title"],
                "description": _statement_prose(ctrl.get("parts", [])),
                "weight": 1,
            })
    return {
        "framework": "nist_800_53",
        "version": "Rev 5.1.1",
        "source": NIST_800_53_URL,
        "controls": controls,
    }


# ── CIS Critical Security Controls v8.1 ───────────────────────────────────────
# Hand-encoded from the CIS-published v8.1 reference (cisecurity.org/controls/v8).
# 18 Controls × 153 Safeguards.

CIS_V8 = [
    ("CIS-1", "Inventory and Control of Enterprise Assets", [
        ("CIS-1.1", "Establish and Maintain Detailed Enterprise Asset Inventory"),
        ("CIS-1.2", "Address Unauthorized Assets"),
        ("CIS-1.3", "Utilize an Active Discovery Tool"),
        ("CIS-1.4", "Use Dynamic Host Configuration Protocol (DHCP) Logging to Update Enterprise Asset Inventory"),
        ("CIS-1.5", "Use a Passive Asset Discovery Tool"),
    ]),
    ("CIS-2", "Inventory and Control of Software Assets", [
        ("CIS-2.1", "Establish and Maintain a Software Inventory"),
        ("CIS-2.2", "Ensure Authorized Software is Currently Supported"),
        ("CIS-2.3", "Address Unauthorized Software"),
        ("CIS-2.4", "Utilize Automated Software Inventory Tools"),
        ("CIS-2.5", "Allowlist Authorized Software"),
        ("CIS-2.6", "Allowlist Authorized Libraries"),
        ("CIS-2.7", "Allowlist Authorized Scripts"),
    ]),
    ("CIS-3", "Data Protection", [
        ("CIS-3.1", "Establish and Maintain a Data Management Process"),
        ("CIS-3.2", "Establish and Maintain a Data Inventory"),
        ("CIS-3.3", "Configure Data Access Control Lists"),
        ("CIS-3.4", "Enforce Data Retention"),
        ("CIS-3.5", "Securely Dispose of Data"),
        ("CIS-3.6", "Encrypt Data on End-User Devices"),
        ("CIS-3.7", "Establish and Maintain a Data Classification Scheme"),
        ("CIS-3.8", "Document Data Flows"),
        ("CIS-3.9", "Encrypt Data on Removable Media"),
        ("CIS-3.10", "Encrypt Sensitive Data in Transit"),
        ("CIS-3.11", "Encrypt Sensitive Data at Rest"),
        ("CIS-3.12", "Segment Data Processing and Storage Based on Sensitivity"),
        ("CIS-3.13", "Deploy a Data Loss Prevention Solution"),
        ("CIS-3.14", "Log Sensitive Data Access"),
    ]),
    ("CIS-4", "Secure Configuration of Enterprise Assets and Software", [
        ("CIS-4.1", "Establish and Maintain a Secure Configuration Process"),
        ("CIS-4.2", "Establish and Maintain a Secure Configuration Process for Network Infrastructure"),
        ("CIS-4.3", "Configure Automatic Session Locking on Enterprise Assets"),
        ("CIS-4.4", "Implement and Manage a Firewall on Servers"),
        ("CIS-4.5", "Implement and Manage a Firewall on End-User Devices"),
        ("CIS-4.6", "Securely Manage Enterprise Assets and Software"),
        ("CIS-4.7", "Manage Default Accounts on Enterprise Assets and Software"),
        ("CIS-4.8", "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software"),
        ("CIS-4.9", "Configure Trusted DNS Servers on Enterprise Assets"),
        ("CIS-4.10", "Enforce Automatic Device Lockout on Portable End-User Devices"),
        ("CIS-4.11", "Enforce Remote Wipe Capability on Portable End-User Devices"),
        ("CIS-4.12", "Separate Enterprise Workspaces on Mobile End-User Devices"),
    ]),
    ("CIS-5", "Account Management", [
        ("CIS-5.1", "Establish and Maintain an Inventory of Accounts"),
        ("CIS-5.2", "Use Unique Passwords"),
        ("CIS-5.3", "Disable Dormant Accounts"),
        ("CIS-5.4", "Restrict Administrator Privileges to Dedicated Administrator Accounts"),
        ("CIS-5.5", "Establish and Maintain an Inventory of Service Accounts"),
        ("CIS-5.6", "Centralize Account Management"),
    ]),
    ("CIS-6", "Access Control Management", [
        ("CIS-6.1", "Establish an Access Granting Process"),
        ("CIS-6.2", "Establish an Access Revoking Process"),
        ("CIS-6.3", "Require MFA for Externally-Exposed Applications"),
        ("CIS-6.4", "Require MFA for Remote Network Access"),
        ("CIS-6.5", "Require MFA for Administrative Access"),
        ("CIS-6.6", "Establish and Maintain an Inventory of Authentication and Authorization Systems"),
        ("CIS-6.7", "Centralize Access Control"),
        ("CIS-6.8", "Define and Maintain Role-Based Access Control"),
    ]),
    ("CIS-7", "Continuous Vulnerability Management", [
        ("CIS-7.1", "Establish and Maintain a Vulnerability Management Process"),
        ("CIS-7.2", "Establish and Maintain a Remediation Process"),
        ("CIS-7.3", "Perform Automated Operating System Patch Management"),
        ("CIS-7.4", "Perform Automated Application Patch Management"),
        ("CIS-7.5", "Perform Automated Vulnerability Scans of Internal Enterprise Assets"),
        ("CIS-7.6", "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets"),
        ("CIS-7.7", "Remediate Detected Vulnerabilities"),
    ]),
    ("CIS-8", "Audit Log Management", [
        ("CIS-8.1", "Establish and Maintain an Audit Log Management Process"),
        ("CIS-8.2", "Collect Audit Logs"),
        ("CIS-8.3", "Ensure Adequate Audit Log Storage"),
        ("CIS-8.4", "Standardize Time Synchronization"),
        ("CIS-8.5", "Collect Detailed Audit Logs"),
        ("CIS-8.6", "Collect DNS Query Audit Logs"),
        ("CIS-8.7", "Collect URL Request Audit Logs"),
        ("CIS-8.8", "Collect Command-Line Audit Logs"),
        ("CIS-8.9", "Centralize Audit Logs"),
        ("CIS-8.10", "Retain Audit Logs"),
        ("CIS-8.11", "Conduct Audit Log Reviews"),
        ("CIS-8.12", "Collect Service Provider Logs"),
    ]),
    ("CIS-9", "Email and Web Browser Protections", [
        ("CIS-9.1", "Ensure Use of Only Fully Supported Browsers and Email Clients"),
        ("CIS-9.2", "Use DNS Filtering Services"),
        ("CIS-9.3", "Maintain and Enforce Network-Based URL Filters"),
        ("CIS-9.4", "Restrict Unnecessary or Unauthorized Browser and Email Client Extensions"),
        ("CIS-9.5", "Implement DMARC"),
        ("CIS-9.6", "Block Unnecessary File Types"),
        ("CIS-9.7", "Deploy and Maintain Email Server Anti-Malware Protections"),
    ]),
    ("CIS-10", "Malware Defenses", [
        ("CIS-10.1", "Deploy and Maintain Anti-Malware Software"),
        ("CIS-10.2", "Configure Automatic Anti-Malware Signature Updates"),
        ("CIS-10.3", "Disable Autorun and Autoplay for Removable Media"),
        ("CIS-10.4", "Configure Automatic Anti-Malware Scanning of Removable Media"),
        ("CIS-10.5", "Enable Anti-Exploitation Features"),
        ("CIS-10.6", "Centrally Manage Anti-Malware Software"),
        ("CIS-10.7", "Use Behavior-Based Anti-Malware Software"),
    ]),
    ("CIS-11", "Data Recovery", [
        ("CIS-11.1", "Establish and Maintain a Data Recovery Process"),
        ("CIS-11.2", "Perform Automated Backups"),
        ("CIS-11.3", "Protect Recovery Data"),
        ("CIS-11.4", "Establish and Maintain an Isolated Instance of Recovery Data"),
        ("CIS-11.5", "Test Data Recovery"),
    ]),
    ("CIS-12", "Network Infrastructure Management", [
        ("CIS-12.1", "Ensure Network Infrastructure is Up-to-Date"),
        ("CIS-12.2", "Establish and Maintain a Secure Network Architecture"),
        ("CIS-12.3", "Securely Manage Network Infrastructure"),
        ("CIS-12.4", "Establish and Maintain Architecture Diagrams"),
        ("CIS-12.5", "Centralize Network Authentication, Authorization, and Auditing (AAA)"),
        ("CIS-12.6", "Use of Secure Network Management and Communication Protocols"),
        ("CIS-12.7", "Ensure Remote Devices Utilize a VPN and are Connecting to an Enterprise's AAA Infrastructure"),
        ("CIS-12.8", "Establish and Maintain Dedicated Computing Resources for All Administrative Work"),
    ]),
    ("CIS-13", "Network Monitoring and Defense", [
        ("CIS-13.1", "Centralize Security Event Alerting"),
        ("CIS-13.2", "Deploy a Host-Based Intrusion Detection Solution"),
        ("CIS-13.3", "Deploy a Network Intrusion Detection Solution"),
        ("CIS-13.4", "Perform Traffic Filtering Between Network Segments"),
        ("CIS-13.5", "Manage Access Control for Remote Assets"),
        ("CIS-13.6", "Collect Network Traffic Flow Logs"),
        ("CIS-13.7", "Deploy a Host-Based Intrusion Prevention Solution"),
        ("CIS-13.8", "Deploy a Network Intrusion Prevention Solution"),
        ("CIS-13.9", "Deploy Port-Level Access Control"),
        ("CIS-13.10", "Perform Application Layer Filtering"),
        ("CIS-13.11", "Tune Security Event Alerting Thresholds"),
    ]),
    ("CIS-14", "Security Awareness and Skills Training", [
        ("CIS-14.1", "Establish and Maintain a Security Awareness Program"),
        ("CIS-14.2", "Train Workforce Members to Recognize Social Engineering Attacks"),
        ("CIS-14.3", "Train Workforce Members on Authentication Best Practices"),
        ("CIS-14.4", "Train Workforce on Data Handling Best Practices"),
        ("CIS-14.5", "Train Workforce Members on Causes of Unintentional Data Exposure"),
        ("CIS-14.6", "Train Workforce Members on Recognizing and Reporting Security Incidents"),
        ("CIS-14.7", "Train Workforce on How to Identify and Report if Their Enterprise Assets are Missing Security Updates"),
        ("CIS-14.8", "Train Workforce on the Dangers of Connecting to and Transmitting Enterprise Data Over Insecure Networks"),
        ("CIS-14.9", "Conduct Role-Specific Security Awareness and Skills Training"),
    ]),
    ("CIS-15", "Service Provider Management", [
        ("CIS-15.1", "Establish and Maintain an Inventory of Service Providers"),
        ("CIS-15.2", "Establish and Maintain a Service Provider Management Policy"),
        ("CIS-15.3", "Classify Service Providers"),
        ("CIS-15.4", "Ensure Service Provider Contracts Include Security Requirements"),
        ("CIS-15.5", "Assess Service Providers"),
        ("CIS-15.6", "Monitor Service Providers"),
        ("CIS-15.7", "Securely Decommission Service Providers"),
    ]),
    ("CIS-16", "Application Software Security", [
        ("CIS-16.1", "Establish and Maintain a Secure Application Development Process"),
        ("CIS-16.2", "Establish and Maintain a Process to Accept and Address Software Vulnerabilities"),
        ("CIS-16.3", "Perform Root Cause Analysis on Security Vulnerabilities"),
        ("CIS-16.4", "Establish and Manage an Inventory of Third-Party Software Components"),
        ("CIS-16.5", "Use Up-to-Date and Trusted Third-Party Software Components"),
        ("CIS-16.6", "Establish and Maintain a Severity Rating System and Process for Application Vulnerabilities"),
        ("CIS-16.7", "Use Standard Hardening Configuration Templates for Application Infrastructure"),
        ("CIS-16.8", "Separate Production and Non-Production Systems"),
        ("CIS-16.9", "Train Developers in Application Security Concepts and Secure Coding"),
        ("CIS-16.10", "Apply Secure Design Principles in Application Architectures"),
        ("CIS-16.11", "Leverage Vetted Modules or Services for Application Security Components"),
        ("CIS-16.12", "Implement Code-Level Security Checks"),
        ("CIS-16.13", "Conduct Application Penetration Testing"),
        ("CIS-16.14", "Conduct Threat Modeling"),
    ]),
    ("CIS-17", "Incident Response Management", [
        ("CIS-17.1", "Designate Personnel to Manage Incident Handling"),
        ("CIS-17.2", "Establish and Maintain Contact Information for Reporting Security Incidents"),
        ("CIS-17.3", "Establish and Maintain an Enterprise Process for Reporting Incidents"),
        ("CIS-17.4", "Establish and Maintain an Incident Response Process"),
        ("CIS-17.5", "Assign Key Roles and Responsibilities"),
        ("CIS-17.6", "Define Mechanisms for Communicating During Incident Response"),
        ("CIS-17.7", "Conduct Routine Incident Response Exercises"),
        ("CIS-17.8", "Conduct Post-Incident Reviews"),
        ("CIS-17.9", "Establish and Maintain Security Incident Thresholds"),
    ]),
    ("CIS-18", "Penetration Testing", [
        ("CIS-18.1", "Establish and Maintain a Penetration Testing Program"),
        ("CIS-18.2", "Perform Periodic External Penetration Tests"),
        ("CIS-18.3", "Remediate Penetration Test Findings"),
        ("CIS-18.4", "Validate Security Measures"),
        ("CIS-18.5", "Perform Periodic Internal Penetration Tests"),
    ]),
]


def build_cis_v8() -> Dict[str, Any]:
    controls: List[Dict[str, Any]] = []
    for ctrl_id, ctrl_title, safeguards in CIS_V8:
        controls.append({
            "control_id": ctrl_id,
            "parent": None,
            "domain": ctrl_title,
            "title": ctrl_title,
            "description": "",
            "weight": 0,
        })
        for sg_id, sg_title in safeguards:
            controls.append({
                "control_id": sg_id,
                "parent": ctrl_id,
                "domain": ctrl_title,
                "title": sg_title,
                "description": sg_title,
                "weight": 1,
            })
    return {
        "framework": "cis_v8",
        "version": "8.1",
        "source": "https://www.cisecurity.org/controls/v8",
        "controls": controls,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print("Generating NIST CSF 2.0 …")
    csf = build_nist_csf()
    (DATA_DIR / "nist_csf.json").write_text(json.dumps(csf, indent=2))
    print(f"  → {len(csf['controls'])} controls")

    print("Generating NIST 800-53 Rev 5 …")
    sp = build_nist_800_53()
    (DATA_DIR / "nist_800_53.json").write_text(json.dumps(sp, indent=2))
    print(f"  → {len(sp['controls'])} controls (base only)")

    print("Generating CIS Controls v8.1 …")
    cis = build_cis_v8()
    (DATA_DIR / "cis_v8.json").write_text(json.dumps(cis, indent=2))
    print(f"  → {len(cis['controls'])} controls + safeguards")

    # CIS Benchmarks (15 platform-specific catalogs)
    from cis_benchmarks import ALL_BENCHMARKS, to_json_payload
    for bm in ALL_BENCHMARKS:
        payload = to_json_payload(bm)
        out = DATA_DIR / f"{bm['framework']}.json"
        out.write_text(json.dumps(payload, indent=2))
        leaves = sum(1 for c in payload["controls"] if c["weight"] > 0)
        sections = len(payload["controls"]) - leaves
        print(f"  → {bm['framework']:24s} {sections:3d} sections + {leaves:4d} leaves ({bm['version']})")

    print(f"\nDone. Files written to {DATA_DIR}")


if __name__ == "__main__":
    main()
