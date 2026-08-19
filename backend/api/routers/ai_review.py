"""
AI Review — stateless scan advisory endpoint.

Takes a completed scan_id and returns LLM-generated agent recommendations
with match scores and reasoning. No DB writes — purely advisory.
"""
import json
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.models.models import Finding, Scan
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


# Fallback recommendations by connector category
_FALLBACK: dict = {
    "sast": {
        "banner": "Your code scan found security issues. Threat Intelligence will map these to known vulnerabilities and MITRE ATT&CK techniques, while Remediation Planner will provide developer-ready fix guidance.",
        "recommendations": [
            {"agent_key": "threat_intel", "match_score": 92, "reasoning": "Maps code vulnerabilities to CVE database and adversary exploitation patterns.", "bring": ["Completed scan"]},
            {"agent_key": "remediation", "match_score": 88, "reasoning": "Generates step-by-step fix instructions and code snippets tailored to the specific issues found.", "bring": ["Completed scan"]},
        ],
    },
    "cloud": {
        "banner": "Your cloud posture scan identified configuration risks. Risk Manager will quantify business impact using FAIR methodology, and Compliance Monitor will check against CIS and NIST benchmarks.",
        "recommendations": [
            {"agent_key": "risk_manager", "match_score": 94, "reasoning": "Translates cloud misconfigurations into financial exposure estimates using FAIR-lite ALE model.", "bring": ["Completed scan", "Asset criticality context"]},
            {"agent_key": "compliance_monitor", "match_score": 89, "reasoning": "Maps cloud findings to CIS, NIST CSF, and ISO 27001 controls to identify compliance gaps.", "bring": ["Completed scan", "Target framework"]},
        ],
    },
    "default": {
        "banner": "Your scan has completed. Run Threat Intelligence to enrich findings with CVE data and MITRE ATT&CK mapping, then use Remediation Planner to generate prioritised fix guidance.",
        "recommendations": [
            {"agent_key": "threat_intel", "match_score": 90, "reasoning": "Enriches findings with CVE details, threat actor profiles, and MITRE ATT&CK technique mapping.", "bring": ["Completed scan"]},
            {"agent_key": "remediation", "match_score": 85, "reasoning": "Converts findings into a prioritised remediation plan with SLA targets and suggested owners.", "bring": ["Completed scan"]},
        ],
    },
}

_CLOUD_TYPES = {"azure", "aws", "gcp"}
_SAST_TYPES = {"semgrep", "codeql", "ai_code_review", "sonarqube", "gitleaks", "trufflehog"}


def _get_fallback(connector_type: str) -> dict:
    ct = (connector_type or "").lower()
    if ct in _CLOUD_TYPES:
        return _FALLBACK["cloud"]
    if ct in _SAST_TYPES:
        return _FALLBACK["sast"]
    return _FALLBACK["default"]


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

    prompt = f"""You are a security AI orchestration advisor inside Monitara. Analyze this completed scan and recommend which AI agents to run next.

Scan: {scan.name}
Connector type: {connector_type or "unknown"}
Findings: {total} total — {sev_counts['critical']} critical, {sev_counts['high']} high, {sev_counts['medium']} medium, {sev_counts['low']} low
Top findings: {', '.join(top_titles) if top_titles else 'none'}
Resource types: {', '.join(sorted(resource_types)) if resource_types else 'various'}

Available agents (use these exact keys):
- orchestrator: Full pipeline — runs threat intel, compliance analysis, and remediation planning together
- risk_manager: FAIR-based risk quantification and ALE scoring
- threat_intel: CVE enrichment, threat actor correlation, MITRE ATT&CK mapping
- compliance_monitor: Framework compliance gap analysis (NIST, ISO 27001, PCI DSS, CIS, GCC IM8, MAS TRM)
- remediation: Prioritized remediation planning with SLA targets
- ai_code_review: Source code security review (only relevant for SAST scans)

Return ONLY valid JSON (no markdown, no explanation):
{{"banner": "1-2 sentence analysis of this scan and why the recommended agents fit", "recommendations": [{{"agent_key": "one of the keys above", "match_score": 0-100, "reasoning": "one sentence why this agent is the best fit for this specific scan", "bring": ["list", "of", "what is available or needed"]}}]}}

Return 2-3 recommendations ranked by fit. For vulnerability scans recommend threat_intel first. For compliance/config scans recommend compliance_monitor. For cloud scans recommend risk_manager. Always include remediation unless it is already the top pick. Never recommend ai_code_review unless connector_type is sast or ai_code_review."""

    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage
        llm = get_llm()
        resp = await llm.ainvoke([HumanMessage(content=prompt)])
        raw = resp.content.strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
        if raw.endswith("```"):
            raw = raw.rsplit("```", 1)[0]
        raw = raw.strip()
        data = json.loads(raw)
        banner = data.get("banner", "")
        recs_raw = data.get("recommendations", [])
        recommendations = [
            AgentRecommendation(
                agent_key=r.get("agent_key", "orchestrator"),
                match_score=int(r.get("match_score", 80)),
                reasoning=r.get("reasoning", ""),
                bring=r.get("bring", ["Completed scan"]),
            )
            for r in recs_raw[:3]
        ]
        return ScanAdvisoryResponse(banner=banner, recommendations=recommendations)
    except Exception as exc:
        logger.warning("scan_advisory LLM call failed: %s", exc)
        fb = _get_fallback(connector_type)
        return ScanAdvisoryResponse(
            banner=fb["banner"],
            recommendations=[AgentRecommendation(**r) for r in fb["recommendations"]],
        )
