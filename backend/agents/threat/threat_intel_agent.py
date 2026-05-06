"""
NexGenCyberAI - Threat Intelligence Agent
Queries open-source threat intelligence feeds (AlienVault OTX, MITRE ATT&CK).
Identifies TTPs, threat actors, and indicators of compromise.
"""
from langchain.tools import Tool
from typing import Any, Dict, List
import httpx
from ..base_agent import BaseAgent


async def _fetch_otx_pulse(indicator: str) -> str:
    """Query AlienVault OTX for threat indicators."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general",
                headers={"X-OTX-API-KEY": ""},
            )
        if resp.status_code == 200:
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return f"OTX: {indicator} found in {pulse_count} threat pulses"
        return f"OTX: No results for {indicator}"
    except Exception as exc:
        return f"OTX query failed: {exc}"


def _map_to_mitre_attack(finding_title: str) -> str:
    """Map a finding title to MITRE ATT&CK technique (local lookup)."""
    MITRE_MAP = {
        "MFA": "T1078 — Valid Accounts",
        "privilege": "T1078.003 — Local Accounts",
        "lateral": "T1021 — Remote Services",
        "phishing": "T1566 — Phishing",
        "ransomware": "T1486 — Data Encrypted for Impact",
        "credential": "T1003 — OS Credential Dumping",
        "exfiltration": "T1041 — Exfiltration Over C2 Channel",
        "persistence": "T1053 — Scheduled Task/Job",
        "discovery": "T1082 — System Information Discovery",
        "injection": "T1055 — Process Injection",
    }
    title_lower = finding_title.lower()
    for keyword, technique in MITRE_MAP.items():
        if keyword in title_lower:
            return technique
    return "Unknown technique"


def _mitre_lookup_tool(finding_title: str) -> str:
    return f"ATT&CK: {_map_to_mitre_attack(finding_title)}"


class ThreatIntelAgent(BaseAgent):
    agent_name = "ThreatIntelAgent"
    domain = "threat intelligence and MITRE ATT&CK"
    objective = (
        "Correlate security findings with threat actor TTPs using MITRE ATT&CK. "
        "Query threat intelligence feeds to identify known IOCs and active threats."
    )

    def _default_tools(self) -> List[Tool]:
        return [
            Tool(
                name="mitre_attack_lookup",
                func=_mitre_lookup_tool,
                description="Map a finding title to a MITRE ATT&CK technique. Input: finding title string.",
            ),
        ]

    async def enrich_findings(self, findings: List[Dict], client_name: str) -> Dict[str, Any]:
        import json
        enriched = []
        for f in findings:
            technique = _map_to_mitre_attack(f.get("title", ""))
            enriched.append({**f, "mitre_technique": technique})
        technique_counts: Dict[str, int] = {}
        for f in enriched:
            t = f.get("mitre_technique", "")
            if t != "Unknown technique":
                technique_counts[t] = technique_counts.get(t, 0) + 1
        result = await self.run({
            "input": json.dumps({
                "task": "threat_intel",
                "client": client_name,
                "top_techniques": sorted(technique_counts.items(), key=lambda x: -x[1])[:5],
                "instructions": (
                    "1. Identify which threat actors use these TTPs. "
                    "2. Assess whether this pattern matches a known campaign. "
                    "3. Recommend detection rules (Sigma/YARA)."
                ),
            })
        })
        result["technique_mapping"] = technique_counts
        result["enriched_findings"] = enriched
        return result
