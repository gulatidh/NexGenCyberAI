"""
NexGenCyberAI - Vulnerability Assessment Scan Agent
Orchestrates multi-source VA scanning, deduplicates findings,
enriches with NVD CVE data, and prioritises by EPSS score.
"""
from langchain.tools import Tool
from typing import Any, Dict, List
import httpx
from agents.base_agent import BaseAgent


async def _fetch_nvd_cve(cve_id: str) -> Dict:
    """Fetch CVE details from NVD API v2."""
    if not cve_id or not cve_id.startswith("CVE-"):
        return {}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                headers={"apiKey": ""},
            )
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if vulns:
            cve_data = vulns[0].get("cve", {})
            metrics = cve_data.get("metrics", {})
            cvss = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", metrics.get("cvssMetricV2", [{}])))
            score = cvss[0].get("cvssData", {}).get("baseScore", 0) if cvss else 0
            return {
                "cvss_score": score,
                "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
            }
    except Exception:
        pass
    return {}


def _deduplicate_findings(findings_json: str) -> str:
    """Remove duplicate findings by title+resource_id."""
    import json
    try:
        findings = json.loads(findings_json)
    except Exception:
        return findings_json
    seen = set()
    unique = []
    for f in findings:
        key = f"{f.get('title', '')}|{f.get('resource_id', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return json.dumps({"deduplicated_count": len(unique), "original_count": len(findings), "findings": unique[:50]})


def _prioritise_by_cvss(findings_json: str) -> str:
    """Sort findings by CVSS score descending."""
    import json
    try:
        findings = json.loads(findings_json)
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
        sorted_f = sorted(findings, key=lambda x: x.get("cvss_score", 0), reverse=True)
        return "\n".join(
            f"CVSS {f.get('cvss_score', 0):4.1f} | {f.get('severity','').upper():8s} | {f.get('title','')[:80]} | {f.get('cve_id','')}"
            for f in sorted_f[:20]
        )
    except Exception as exc:
        return str(exc)


class VAScanAgent(BaseAgent):
    agent_name = "VAScanAgent"
    domain = "vulnerability assessment and CVE analysis"
    objective = (
        "Orchestrate vulnerability scans across all connected platforms, "
        "deduplicate and enrich findings with NVD/EPSS data, "
        "and produce a prioritised remediation plan."
    )

    def _default_tools(self) -> List[Tool]:
        return [
            Tool(
                name="deduplicate_findings",
                func=_deduplicate_findings,
                description="Remove duplicate vulnerability findings. Input: JSON array of findings.",
            ),
            Tool(
                name="prioritise_by_cvss",
                func=_prioritise_by_cvss,
                description="Sort and display findings by CVSS score. Input: JSON array of findings.",
            ),
        ]

    async def analyse_vulnerabilities(
        self,
        findings: List[Dict],
        client_name: str,
    ) -> Dict[str, Any]:
        import json
        # Enrich top CVEs with NVD data
        enriched = []
        for f in findings:
            if cve := f.get("cve_id"):
                nvd = await _fetch_nvd_cve(cve)
                f.update(nvd)
            enriched.append(f)

        findings_json = json.dumps(enriched)
        dedup = _deduplicate_findings(findings_json)
        priority = _prioritise_by_cvss(dedup)

        input_data = {
            "task": "va_analysis",
            "client": client_name,
            "dedup_summary": json.loads(dedup) if dedup.startswith("{") else dedup,
            "priority_list": priority,
            "instructions": (
                "1. Summarise the vulnerability landscape. "
                "2. Identify top 5 critical vulnerabilities to patch immediately. "
                "3. Group by asset type. "
                "4. Provide patch/mitigation steps for each critical item."
            ),
        }
        result = await self.run({"input": json.dumps(input_data)})
        result["priority_list"] = priority
        result["enriched_count"] = len(enriched)
        return result
