"""
AI Review — stateless scan advisory endpoint.

Takes a completed scan_id and returns LLM-generated agent recommendations
with match scores and reasoning. Returns ALL relevant agents (score >= 40),
not limited to 3.
"""
import json
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.models.models import Finding, Scan, AIAgent
from core.security import get_current_user
from db.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ai-review"])


class ScanAdvisoryRequest(BaseModel):
    scan_id: str


class AgentRecommendation(BaseModel):
    agent_key: str
    match_score: int
    reasoning: str
    bring: List[str]


class ScanAdvisoryResponse(BaseModel):
    banner: str
    recommendations: List[AgentRecommendation]


_CLOUD_TYPES = {"azure", "aws", "gcp"}
_SAST_TYPES = {"semgrep", "codeql", "ai_code_review", "sonarqube", "gitleaks", "trufflehog"}
_NETWORK_TYPES = {"nmap", "openvas", "trivy", "tenable", "qualys", "rapid7", "burp_enterprise", "web"}


def _get_fallback(connector_type: str) -> dict:
    ct = (connector_type or "").lower()
    if ct in _CLOUD_TYPES:
        return {
            "banner": "Your cloud scan identified configuration and posture risks. The following agents are ranked by relevance to help you quantify impact, map compliance gaps, and assess IAM exposure.",
            "recommendations": [
                {"agent_key": "risk_manager", "match_score": 94, "reasoning": "Translates cloud misconfigurations into financial ALE exposure.", "bring": ["FAIR risk scores", "ALE calculations", "Risk heatmap"]},
                {"agent_key": "iam_posture_advisor", "match_score": 88, "reasoning": "Reviews IAM policies and privilege chains — critical for cloud scans.", "bring": ["IAM posture assessment", "Privilege escalation paths", "Least-privilege recommendations"]},
                {"agent_key": "compliance_monitor", "match_score": 82, "reasoning": "Maps cloud findings to CIS and NIST benchmarks.", "bring": ["Control gap report", "Framework compliance %", "Audit evidence"]},
                {"agent_key": "threat_intel", "match_score": 76, "reasoning": "Correlates cloud misconfigs with known threat actor TTPs.", "bring": ["Threat actor profiles", "MITRE techniques", "CVE enrichment"]},
                {"agent_key": "remediation", "match_score": 70, "reasoning": "Generates a prioritised remediation plan with SLA targets.", "bring": ["Prioritised actions", "SLA targets", "Owner assignments"]},
            ],
        }
    if ct in _SAST_TYPES:
        return {
            "banner": "Your code scan found security vulnerabilities. Agents are ranked by relevance to enrich with CVE data, map to MITRE ATT&CK, and produce developer-ready remediation guidance.",
            "recommendations": [
                {"agent_key": "appsec_advisor", "match_score": 95, "reasoning": "Purpose-built for application security findings.", "bring": ["AppSec risk findings", "Secure design recommendations", "OWASP mapping"]},
                {"agent_key": "threat_intel", "match_score": 88, "reasoning": "Maps code vulnerabilities to CVEs and adversary techniques.", "bring": ["CVE enrichment", "MITRE ATT&CK techniques", "Exploit likelihood"]},
                {"agent_key": "remediation", "match_score": 83, "reasoning": "Generates fix instructions and playbooks for code issues.", "bring": ["Prioritised remediation actions", "Developer fix guidance", "SLA targets"]},
                {"agent_key": "risk_manager", "match_score": 72, "reasoning": "Quantifies business risk from code vulnerabilities.", "bring": ["FAIR risk scores", "Risk heatmap", "ALE calculations"]},
                {"agent_key": "compliance_monitor", "match_score": 65, "reasoning": "Maps code findings to OWASP ASVS and PCI DSS controls.", "bring": ["Control gap report", "Compliance %", "Audit evidence"]},
            ],
        }
    if ct in _NETWORK_TYPES:
        return {
            "banner": "Your network or vulnerability scan has results. Agents are ranked by relevance to prioritise remediation, map threat actor activity, and assess compliance posture.",
            "recommendations": [
                {"agent_key": "vuln_commander", "match_score": 93, "reasoning": "Purpose-built for vulnerability triage with exploitability weighting.", "bring": ["Exploitability-ranked findings", "Top-10 actionable vulns", "Asset criticality context"]},
                {"agent_key": "threat_intel", "match_score": 87, "reasoning": "Correlates network findings with active threat actor TTPs.", "bring": ["CVE enrichment", "Threat actor profiles", "MITRE techniques"]},
                {"agent_key": "nist_assessment_advisor", "match_score": 80, "reasoning": "Maps network findings to NIST SP 800-53 controls.", "bring": ["NIST control mapping", "Compliance gap report", "Audit-ready findings"]},
                {"agent_key": "remediation", "match_score": 74, "reasoning": "Generates a prioritised remediation plan with SLA targets.", "bring": ["Prioritised actions", "SLA targets", "Owner assignments"]},
                {"agent_key": "risk_manager", "match_score": 68, "reasoning": "Converts network findings into risk-scored entries.", "bring": ["FAIR risk scores", "ALE calculations", "Risk heatmap"]},
            ],
        }
    return {
        "banner": "Your scan has completed. Agents are ranked by relevance for enrichment, risk quantification, and remediation planning.",
        "recommendations": [
            {"agent_key": "threat_intel", "match_score": 88, "reasoning": "Enriches findings with CVE details and MITRE ATT&CK technique mapping.", "bring": ["CVE enrichment", "MITRE techniques", "Threat actor profiles"]},
            {"agent_key": "risk_manager", "match_score": 84, "reasoning": "Converts findings into risk-scored entries using FAIR methodology.", "bring": ["FAIR risk scores", "ALE calculations", "Risk heatmap"]},
            {"agent_key": "remediation", "match_score": 79, "reasoning": "Generates a prioritised remediation plan with SLA targets.", "bring": ["Prioritised actions", "SLA targets", "Owner assignments"]},
            {"agent_key": "compliance_monitor", "match_score": 72, "reasoning": "Maps findings to common compliance frameworks.", "bring": ["Control gap report", "Framework compliance %", "Audit evidence"]},
        ],
    }


@router.post("/clients/{client_id}/ai-review/scan-advisory", response_model=ScanAdvisoryResponse)
async def scan_advisory(
    client_id: str,
    payload: ScanAdvisoryRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == payload.scan_id, Scan.client_id == client_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Gather finding context
    findings = db.query(Finding).filter(
        Finding.scan_id == payload.scan_id
    ).limit(50).all()

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    resource_types: set = set()
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        if f.resource_type:
            resource_types.add(f.resource_type)

    total = sum(sev_counts.values())
    top_findings = sorted(findings, key=lambda f: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            f.severity.value if hasattr(f.severity, "value") else str(f.severity), 5
        )
    ))[:5]
    top_titles = [
        f"{f.severity.value if hasattr(f.severity,'value') else f.severity}: {f.title}"
        for f in top_findings
    ]

    scan_summary = scan.summary or {}
    connector_type = ""
    if scan.connector:
        connector_type = scan.connector.connector_type.value if hasattr(scan.connector.connector_type, "value") else str(scan.connector.connector_type)
    elif "connector_type" in scan_summary:
        connector_type = scan_summary["connector_type"]

    # Load full live agent catalog from DB — only enabled agents
    all_agents = (
        db.query(AIAgent)
        .filter(AIAgent.is_enabled == True)
        .order_by(AIAgent.group_key, AIAgent.name)
        .all()
    )
    agent_lines = []
    for a in all_agents:
        desc = (a.description or a.objective or "AI security agent")[:120]
        agent_lines.append(f'- {a.key} ({a.group_label}): {desc}')
    agent_list = "\n".join(agent_lines) if agent_lines else "- orchestrator: Full pipeline\n- threat_intel: CVE enrichment\n- risk_manager: Risk scoring"

    prompt = f"""You are a security AI orchestration advisor inside Monitara. Analyze this completed scan and score ALL agents for relevance.

Scan: {scan.name}
Connector type: {connector_type or "unknown"}
Findings: {total} total — {sev_counts['critical']} critical, {sev_counts['high']} high, {sev_counts['medium']} medium, {sev_counts['low']} low
Top findings: {', '.join(top_titles) if top_titles else 'none'}
Resource types: {', '.join(sorted(resource_types)) if resource_types else 'various'}

Full agent catalog (agent_key · group · description):
{agent_list}

Your job: score EVERY agent for relevance to THIS specific scan data. Score 0-100 where:
- 80-100: highly relevant, directly addresses the dominant findings
- 60-79: relevant, provides useful context
- 40-59: somewhat useful, secondary value
- 0-39: not relevant to this scan (EXCLUDE from output)

Rules:
- Score based on the actual scan data — severity distribution, connector type, resource types, finding titles
- A cloud scan (azure/aws/gcp) → cloud posture, IAM, compliance agents score higher
- A code scan (sast/ai_code_review) → appsec, threat intel, remediation agents score higher
- A network/vuln scan → vuln triage, compliance, threat intel score higher
- Be specific and diverse — score EVERY agent independently, don't cluster scores
- Include ALL agents scoring >= 40, sort by score descending

Return ONLY valid JSON (no markdown, no explanation):
{{"banner": "2-sentence analysis of what this scan found", "recommendations": [{{"agent_key": "exact key from catalog", "match_score": 0-100, "reasoning": "one sentence why this agent fits this scan", "bring": ["2-3 concise benefit bullets"]}}]}}

Include every agent with score >= 40, sorted descending by match_score."""

    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage
        llm = get_llm()
        resp = await llm.ainvoke([HumanMessage(content=prompt)])
        raw = resp.content.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
        if raw.endswith("```"):
            raw = raw.rsplit("```", 1)[0]
        raw = raw.strip()
        data = json.loads(raw)
        banner = data.get("banner", "")
        recs_raw = data.get("recommendations", [])
        # Filter to score >= 40 and sort descending (LLM should already do this, but enforce)
        recs_raw = [r for r in recs_raw if int(r.get("match_score", 0)) >= 40]
        recs_raw.sort(key=lambda r: int(r.get("match_score", 0)), reverse=True)
        recommendations = [
            AgentRecommendation(
                agent_key=r.get("agent_key", "orchestrator"),
                match_score=int(r.get("match_score", 80)),
                reasoning=r.get("reasoning", ""),
                bring=r.get("bring", ["Analysis complete"]),
            )
            for r in recs_raw
        ]
        return ScanAdvisoryResponse(banner=banner, recommendations=recommendations)
    except Exception as exc:
        logger.warning("scan_advisory LLM call failed: %s", exc)
        fb = _get_fallback(connector_type)
        return ScanAdvisoryResponse(
            banner=fb["banner"],
            recommendations=[AgentRecommendation(**r) for r in fb["recommendations"]],
        )
