"""Knowledge injection service.

Loads CISA KEV catalog and curated MITRE ATT&CK technique summaries.
Injected into ThreatIntelAgent system prompts at runtime.
CISA KEV is fetched on first access and cached in-memory for the process lifetime.
On disk: backend/data/knowledge/cisa_kev_cache.json (refreshed on startup).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_KEV_CACHE: Optional[List[Dict]] = None
_KEV_PATH = Path(__file__).parent.parent / "data" / "knowledge" / "cisa_kev_cache.json"

# Curated top-50 MITRE ATT&CK techniques most relevant to cloud/web/enterprise.
# ATT&CK v15 — format: {id, name, tactic, desc}
MITRE_TECHNIQUES: List[Dict[str, str]] = [
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access / Persistence / Privilege Escalation / Defense Evasion", "desc": "Adversaries use legitimate credentials (compromised, default, or created) to access systems."},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "desc": "Adversaries exploit vulnerabilities in internet-facing applications such as web servers, APIs, or VPNs."},
    {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access / Persistence", "desc": "Adversaries leverage external remote services (VPN, RDP, Citrix, SSH) to gain or maintain access."},
    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "desc": "Adversaries send malicious emails or messages to gain code execution or credential access."},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "desc": "Adversaries abuse command-line interfaces and scripting engines (PowerShell, bash, Python) to execute code."},
    {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Execution / Persistence / Privilege Escalation", "desc": "Adversaries abuse task scheduling to execute malicious code at a specified time or interval."},
    {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion / Privilege Escalation", "desc": "Adversaries inject malicious code into legitimate processes to evade defences and elevate privileges."},
    {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence / Privilege Escalation", "desc": "Adversaries configure malicious programs to execute automatically on system start-up."},
    {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence / Privilege Escalation", "desc": "Adversaries manipulate accounts to maintain or elevate access (adding MFA bypass, modifying group membership)."},
    {"id": "T1136", "name": "Create Account", "tactic": "Persistence", "desc": "Adversaries create accounts to maintain access after initial exploitation."},
    {"id": "T1484", "name": "Domain/Tenant Policy Modification", "tactic": "Defense Evasion / Privilege Escalation", "desc": "Adversaries modify domain/tenant policies (e.g. Azure AD Conditional Access) to weaken defences."},
    {"id": "T1134", "name": "Access Token Manipulation", "tactic": "Defense Evasion / Privilege Escalation", "desc": "Adversaries manipulate access tokens to operate under different security contexts."},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "desc": "Adversaries obfuscate code, scripts, or payloads to evade detection."},
    {"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion", "desc": "Adversaries disable or tamper with security tools, logging, and monitoring."},
    {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion", "desc": "Adversaries delete or modify logs and artefacts to remove evidence of compromise."},
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "desc": "Adversaries attempt to gain access through password guessing, spraying, or credential stuffing."},
    {"id": "T1555", "name": "Credentials from Password Stores", "tactic": "Credential Access", "desc": "Adversaries extract credentials from browsers, password managers, and credential stores."},
    {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access", "desc": "Adversaries search for credentials stored insecurely in files, environment variables, or code repositories."},
    {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access / Discovery", "desc": "Adversaries capture network traffic to obtain credentials or sensitive data."},
    {"id": "T1057", "name": "Process Discovery", "tactic": "Discovery", "desc": "Adversaries enumerate running processes to understand the environment and identify targets."},
    {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "desc": "Adversaries collect OS, hardware, and configuration details to plan further exploitation."},
    {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "desc": "Adversaries enumerate files and directories to find sensitive data or configuration files."},
    {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery", "desc": "Adversaries enumerate local and domain accounts to plan credential attacks or lateral movement."},
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "desc": "Adversaries scan the network to discover hosts and services for lateral movement."},
    {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "desc": "Adversaries use legitimate remote service protocols (RDP, SMB, SSH, WinRM) to move laterally."},
    {"id": "T1550", "name": "Use Alternate Authentication Material", "tactic": "Lateral Movement / Defense Evasion", "desc": "Adversaries use pass-the-hash, pass-the-ticket, or stolen tokens to authenticate without credentials."},
    {"id": "T1534", "name": "Internal Spearphishing", "tactic": "Lateral Movement", "desc": "Adversaries use compromised accounts to send phishing messages internally to expand access."},
    {"id": "T1074", "name": "Data Staged", "tactic": "Collection", "desc": "Adversaries stage collected data in a central location prior to exfiltration."},
    {"id": "T1005", "name": "Data from Local System", "tactic": "Collection", "desc": "Adversaries search and collect data stored on local filesystems."},
    {"id": "T1530", "name": "Data from Cloud Storage", "tactic": "Collection", "desc": "Adversaries access and exfiltrate data from cloud storage (S3, Azure Blob, GCS)."},
    {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "desc": "Adversaries use non-standard protocols (DNS, ICMP, HTTPS) to exfiltrate data."},
    {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "desc": "Adversaries exfiltrate data using legitimate web services (OneDrive, GitHub, Slack)."},
    {"id": "T1485", "name": "Data Destruction", "tactic": "Impact", "desc": "Adversaries destroy data to cause operational impact or cover tracks."},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "desc": "Adversaries encrypt data to extort victims (ransomware)."},
    {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact", "desc": "Adversaries disable or destroy backup and recovery capabilities."},
    {"id": "T1195", "name": "Supply Chain Compromise", "tactic": "Initial Access", "desc": "Adversaries compromise software, hardware, or service supply chains before delivery."},
    {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access", "desc": "Adversaries exploit vulnerable browsers or plugins when users visit malicious websites."},
    {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution", "desc": "Adversaries exploit vulnerabilities in client-side software to achieve code execution."},
    {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "desc": "Adversaries exploit vulnerabilities to gain elevated privileges."},
    {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement", "desc": "Adversaries exploit vulnerabilities in network services to move laterally."},
    {"id": "T1525", "name": "Implant Internal Image", "tactic": "Persistence", "desc": "Adversaries modify container or VM images to maintain persistence in cloud environments."},
    {"id": "T1537", "name": "Transfer Data to Cloud Account", "tactic": "Exfiltration", "desc": "Adversaries exfiltrate data to an attacker-controlled cloud account."},
    {"id": "T1580", "name": "Cloud Infrastructure Discovery", "tactic": "Discovery", "desc": "Adversaries enumerate cloud infrastructure (VMs, storage, IAM, functions) to plan attacks."},
    {"id": "T1538", "name": "Cloud Service Dashboard", "tactic": "Discovery", "desc": "Adversaries use cloud management consoles to discover resources and configurations."},
    {"id": "T1528", "name": "Steal Application Access Token", "tactic": "Credential Access", "desc": "Adversaries steal OAuth tokens, API keys, or service account credentials."},
    {"id": "T1556", "name": "Modify Authentication Process", "tactic": "Credential Access / Defense Evasion / Persistence", "desc": "Adversaries modify authentication mechanisms to bypass or capture credentials."},
    {"id": "T1600", "name": "Weaken Encryption", "tactic": "Defense Evasion", "desc": "Adversaries reduce the strength of encryption in use to facilitate decryption of communications."},
    {"id": "T1619", "name": "Cloud Storage Object Discovery", "tactic": "Discovery", "desc": "Adversaries enumerate objects in cloud storage buckets to find sensitive data."},
    {"id": "T1613", "name": "Container and Resource Discovery", "tactic": "Discovery", "desc": "Adversaries enumerate containers and orchestration services (Kubernetes, ECS) to find targets."},
    {"id": "T1611", "name": "Escape to Host", "tactic": "Privilege Escalation", "desc": "Adversaries escape container isolation to gain access to the underlying host."},
]


def get_mitre_context() -> str:
    """Concise MITRE ATT&CK reference block for injection into agent system prompts."""
    lines = [f"## MITRE ATT&CK Technique Reference (v15 — {len(MITRE_TECHNIQUES)} Cloud/Enterprise techniques)", ""]
    for t in MITRE_TECHNIQUES:
        lines.append(f"- **{t['id']}** {t['name']} [{t['tactic']}]: {t['desc']}")
    return "\n".join(lines)


def _load_kev_from_disk() -> Optional[List[Dict]]:
    if _KEV_PATH.exists():
        try:
            with open(_KEV_PATH) as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            return data.get("vulnerabilities", [])
        except Exception as exc:
            logger.warning("KEV disk load failed: %s", exc)
    return None


def _fetch_kev_from_cisa() -> Optional[List[Dict]]:
    try:
        import urllib.request
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read())
        vulns = data.get("vulnerabilities", [])
        _KEV_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_KEV_PATH, "w") as f:
            json.dump(vulns, f)
        logger.info("CISA KEV: fetched %d entries", len(vulns))
        return vulns
    except Exception as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return None


def get_kev_catalog(max_entries: int = 100) -> List[Dict]:
    """Return KEV entries sorted by dateAdded descending, loading/caching as needed."""
    global _KEV_CACHE
    if _KEV_CACHE is None:
        _KEV_CACHE = _load_kev_from_disk() or _fetch_kev_from_cisa() or []
    sorted_kev = sorted(_KEV_CACHE, key=lambda x: x.get("dateAdded", ""), reverse=True)
    return sorted_kev[:max_entries]


def get_kev_context(max_entries: int = 50) -> str:
    """CISA KEV reference block for injection into threat agent system prompts."""
    entries = get_kev_catalog(max_entries)
    if not entries:
        return "## CISA KEV\nCISA KEV catalog unavailable — agent will rely on training knowledge only."
    lines = [
        f"## CISA Known Exploited Vulnerabilities (KEV) — {len(entries)} most recent entries",
        "",
        "CVE ID | Vendor | Product | Date Added | Description",
        "---|---|---|---|---",
    ]
    for e in entries:
        cve = e.get("cveID", "")
        vendor = (e.get("vendorProject") or "")[:30]
        product = (e.get("product") or "")[:30]
        date = e.get("dateAdded", "")
        desc = (e.get("shortDescription") or e.get("vulnerabilityName") or "")[:80]
        lines.append(f"{cve} | {vendor} | {product} | {date} | {desc}")
    return "\n".join(lines)


def refresh_kev_cache() -> int:
    """Force-refresh the KEV cache from CISA. Returns new entry count."""
    global _KEV_CACHE
    _KEV_CACHE = _fetch_kev_from_cisa() or []
    return len(_KEV_CACHE)
