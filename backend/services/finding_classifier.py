"""
Classify a Finding into the modern CNAPP taxonomy used by the Findings page.

Sections (top-level tabs in the SPA):
  - security_posture   — issues from cloud / host / config / data scans
  - threat_detection   — runtime detections / alerts
  - secure_development — code / build / IaC / admission

Categories within Security Posture:
  vulnerability, cloud_configuration, host_configuration, attack_surface,
  data, secret, end_of_life, sast, network_exposure, excessive_access,
  identity_access, ai_security

Heuristics use whatever signal we have today (control_id, resource_type, title,
cve_id, framework). Connectors that produce findings can also pre-tag the
category by setting `evidence["category"]` — when set, that wins over the
heuristic. As more dedicated scanners/connectors land (SAST, IaC, runtime),
they should pre-tag instead of relying on heuristics.
"""
from __future__ import annotations
import re
from typing import Tuple

# Section → list of (category_key, label, icon_name)
SECTIONS = {
    "security_posture": [
        ("vulnerability",       "Vulnerability Findings",       "BugReport"),
        ("cloud_configuration", "Cloud Configuration Findings", "CloudQueue"),
        ("host_configuration",  "Host Configuration Findings",  "Computer"),
        ("attack_surface",      "Attack Surface Findings",      "Public"),
        ("data",                "Data Findings",                "Storage"),
        ("secret",              "Secret Findings",              "VpnKey"),
        ("end_of_life",         "End of Life Findings",         "EventBusy"),
        ("sast",                "SAST Findings",                "Code"),
        ("network_exposure",    "Network Exposure",             "Lan"),
        ("excessive_access",    "Excessive Access Findings",    "GroupAdd"),
        ("identity_access",     "Identity Access Findings",     "Person"),
        ("ai_security",         "AI Security Findings",         "Psychology"),
    ],
    "threat_detection": [
        ("detections", "Detections", "Notifications"),
    ],
    "secure_development": [
        ("code_build_scans",       "Code & Build Scans",           "Build"),
        ("kubernetes_admission",   "Kubernetes Admission Reviews", "AllInbox"),
    ],
}

ALL_CATEGORIES = [(s, c[0], c[1], c[2]) for s, cats in SECTIONS.items() for c in cats]
CATEGORY_TO_SECTION = {c[0]: s for s, cats in SECTIONS.items() for c in cats}


def _norm_ctrl(s: str) -> str:
    return (s or "").upper().strip().lstrip("NIST ").lstrip("CIS-")


def classify(finding) -> Tuple[str, str]:
    """Return (section, category) for a Finding. Defaults to security_posture/cloud_configuration."""
    # Connector pre-tag wins
    ev = finding.evidence or {}
    if isinstance(ev, dict) and ev.get("category"):
        cat = ev["category"]
        return CATEGORY_TO_SECTION.get(cat, "security_posture"), cat

    title = (finding.title or "").lower()
    desc = (finding.description or "").lower()
    rt = (finding.resource_type or "").lower()
    ctrl = _norm_ctrl(finding.control_id or "")
    cve = finding.cve_id or ""

    # Vulnerabilities — anything with a CVE or non-trivial CVSS
    if cve or (finding.cvss_score and finding.cvss_score > 0):
        return "security_posture", "vulnerability"

    # Secrets
    if any(k in title for k in ("secret", "credential leaked", "api key exposed", "private key")):
        return "security_posture", "secret"

    # End of life
    if any(k in title or k in desc for k in ("end of life", "end-of-life", "eol", "deprecated", "out of support", "unsupported version")):
        return "security_posture", "end_of_life"

    # SAST — title contains code-scan markers
    if any(k in title for k in ("sast", "code scan", "source code", "sql injection in code")):
        return "security_posture", "sast"

    # AI security
    if any(k in title for k in ("prompt injection", "ai model", "llm", "model jailbreak")):
        return "security_posture", "ai_security"

    # Threat detection — runtime alerts
    if any(k in title for k in ("alert", "detection", "anomalous", "suspicious activity", "runtime threat")):
        return "threat_detection", "detections"

    # Kubernetes admission
    if any(k in title for k in ("admission webhook", "podsecuritypolicy", "k8s admission")):
        return "secure_development", "kubernetes_admission"

    # Code & build
    if any(k in title for k in ("ci pipeline", "build artifact", "container image scan", "image scan")):
        return "secure_development", "code_build_scans"

    # Network exposure — NSGs, ports, internet-facing
    if any(k in title for k in ("nsg", "port ", "internet", "public ip", "0.0.0.0/0", "exposed")):
        return "security_posture", "network_exposure"
    if ctrl in ("SC-7", "AC-17") or "networksecuritygroups" in rt or "securitygroup" in rt:
        return "security_posture", "network_exposure"

    # Attack surface — overlaps with network exposure but more about DNS/CDN/edge
    if any(k in title for k in ("public dns", "exposed endpoint", "publicly accessible", "front door")):
        return "security_posture", "attack_surface"

    # Identity access — MFA, password policy
    if any(k in title for k in ("mfa", "multi-factor", "password policy", "authentication", "sign-in")):
        return "security_posture", "identity_access"
    if ctrl in ("AC-2", "IA-2"):
        return "security_posture", "identity_access"

    # Excessive access — RBAC, owner roles
    if any(k in title for k in ("owner role", "admin", "privilege", "rbac")):
        return "security_posture", "excessive_access"
    if ctrl == "AC-6":
        return "security_posture", "excessive_access"

    # Data — storage, encryption, public blob
    if any(k in title for k in ("storage", "blob", "bucket", "encryption", "tls", "https-only", "encrypt")):
        return "security_posture", "data"
    if "storageaccounts" in rt or "::s3::" in rt or "buckets" in rt:
        return "security_posture", "data"

    # Host configuration — VM-level
    if "virtualmachines" in rt or "ec2" in rt or "googleapis.com/instance" in rt:
        return "security_posture", "host_configuration"

    # Default — Cloud Configuration
    return "security_posture", "cloud_configuration"
