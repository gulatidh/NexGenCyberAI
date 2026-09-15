"""Per-agent typed input field definitions.

Each entry in AGENT_INPUTS maps an AgentType value to a list of InputField dicts.
The frontend reads these from GET /agents/catalog and renders a dynamic form per agent.
"""
from typing import Any, Dict, List, Optional


def _field(
    name: str,
    label: str,
    type_: str,
    required: bool = False,
    options: Optional[List[str]] = None,
    placeholder: str = "",
    hint: str = "",
) -> Dict[str, Any]:
    f: Dict[str, Any] = {
        "name": name,
        "label": label,
        "type": type_,
        "required": required,
        "placeholder": placeholder,
        "hint": hint,
    }
    if options:
        f["options"] = options
    return f


AGENT_INPUTS: Dict[str, List[Dict[str, Any]]] = {
    "threat_intel": [
        _field("industry_sector", "Industry Sector", "select", required=True,
               options=["Financial Services", "Healthcare", "Government",
                        "Critical Infrastructure", "Technology", "Retail",
                        "Energy", "Manufacturing", "Other"]),
        _field("geography", "Primary Geography", "select", required=True,
               options=["Singapore / SEA", "United States", "European Union",
                        "United Kingdom", "Australia / NZ", "Middle East", "Global"]),
        _field("threat_focus", "Threat Focus", "multiselect",
               options=["Ransomware", "APT / Nation-State", "Insider Threat",
                        "Supply Chain", "Phishing / Social Engineering",
                        "Zero-Day Exploitation", "All"]),
        _field("existing_detections", "Existing Detection Tools", "textarea",
               placeholder="e.g. Microsoft Sentinel, CrowdStrike, Splunk SIEM",
               hint="List your current SIEM / EDR / NDR tools so the agent avoids recommending duplicates"),
    ],
    "compliance_monitor": [
        _field("primary_framework", "Primary Framework", "select", required=True,
               options=["nist_csf", "iso_27001", "pci_dss", "gdpr", "hipaa",
                        "cis_v8", "gcc_im8", "soc2", "nist_800_53"]),
        _field("org_type", "Organisation Type", "select", required=True,
               options=["Government / Public Sector", "Financial Services", "Healthcare",
                        "Technology", "Retail / E-commerce", "Critical Infrastructure", "Other"]),
        _field("audit_target_date", "Next Audit / Assessment Date", "text",
               placeholder="e.g. Q1 2026",
               hint="Helps the agent prioritise near-term control gaps"),
        _field("known_gaps", "Known Existing Gaps", "textarea",
               placeholder="Briefly describe any gaps you already know about",
               hint="The agent will acknowledge and factor these in rather than rediscovering them"),
    ],
    "risk_manager": [
        _field("risk_appetite", "Risk Appetite", "select", required=True,
               options=["Low (risk-averse, maximum controls)", "Medium (balanced)",
                        "High (growth-focused)"]),
        _field("business_criticality", "Business Criticality of Affected Systems", "select",
               options=["Mission Critical", "Business Critical", "Standard",
                        "Development / Test"]),
        _field("existing_controls", "Key Existing Controls", "textarea",
               placeholder="e.g. MFA enabled, WAF deployed, endpoint AV",
               hint="List controls already in place — the agent won't recommend duplicates"),
    ],
    "remediation": [
        _field("implementation_team", "Implementation Team Size", "select",
               options=["Solo / 1 person", "Small team (2-5)", "Medium team (6-20)",
                        "Large team (20+)"]),
        _field("budget_band", "Remediation Budget Band", "select",
               options=["< $10k", "$10k – $100k", "$100k – $500k", "$500k+", "Not defined"]),
        _field("priority_constraint", "Priority Constraint", "select",
               options=["Minimise cost", "Minimise effort", "Maximise security impact",
                        "Meet compliance deadline"]),
        _field("timeline", "Target Completion Timeline", "text",
               placeholder="e.g. 90 days, Q2 2026"),
    ],
    "orchestrator": [
        _field("engagement_type", "Engagement Type", "select", required=True,
               options=["Full Assessment", "Compliance-Focused", "Threat-Focused",
                        "Executive Briefing"]),
        _field("audience", "Report Audience", "select",
               options=["CISO / Security Leadership", "Technical Team",
                        "Board / Executives", "Auditors"]),
        _field("industry_sector", "Industry Sector", "select",
               options=["Financial Services", "Healthcare", "Government", "Technology",
                        "Retail", "Energy", "Critical Infrastructure", "Other"]),
        _field("geography", "Primary Geography", "select",
               options=["Singapore / SEA", "United States", "European Union", "Other"]),
    ],
    "va_scanner": [
        _field("asset_scope", "Asset Scope", "multiselect",
               options=["Web Applications", "APIs", "Cloud Infrastructure",
                        "Network Devices", "Endpoints", "Containers", "Source Code"]),
        _field("severity_threshold", "Minimum Severity to Report", "select",
               options=["All (Info+)", "Low+", "Medium+", "High+", "Critical only"]),
    ],
    "framework_analyst": [
        _field("target_certification", "Target Certification", "select",
               options=["NIST CSF 2.0", "ISO 27001:2022", "PCI DSS v4.0",
                        "SOC 2 Type II", "GDPR Article 32", "GCC IM8",
                        "CIS Controls v8"]),
        _field("current_maturity", "Current Maturity Estimate", "select",
               options=["Ad-hoc (Tier 0)", "Partial (Tier 1)", "Risk-Informed (Tier 2)",
                        "Repeatable (Tier 3)", "Adaptive (Tier 4)"]),
    ],
    "configuration_review": [
        _field("cloud_provider", "Cloud Provider", "select",
               options=["Azure", "AWS", "Google Cloud", "Multi-cloud", "On-premise"]),
        _field("compliance_baseline", "Compliance Baseline", "select",
               options=["CIS Benchmark", "NIST 800-53", "CSP Security Baseline", "Custom"]),
    ],
}


def get_agent_inputs(agent_type_value: str) -> List[Dict[str, Any]]:
    """Return the input field definitions for the given agent type value string."""
    return AGENT_INPUTS.get(agent_type_value, [])
