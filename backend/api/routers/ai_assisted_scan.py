"""
AI Assisted Scan — conversational wizard that guides a user from intent to scan launch.

Design:
- Stateless: full conversation history sent on every call.
- LLM uses live environment profile (connectors, recent scans, assets) injected
  into system prompt — no fine-tuning needed.
- LLM keeps asking questions until all required fields are collected.
- Every LLM response ends with a SCAN_STATE: JSON block the backend parses.
- Launch endpoint creates a Scan record and dispatches _execute_scan as a
  BackgroundTask — reuses existing scan infrastructure, touches nothing else.
- Post-scan next-steps endpoint reads only finding summary (counts + top titles),
  not full finding dump, to stay lightweight.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.models.models import Connector, Finding, Scan, ScanStatus
from core.security import get_current_user
from db.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ai-assisted-scan"])

# ── Connector display names for the system prompt ─────────────────────────────

_CONNECTOR_DESCRIPTIONS = {
    "azure":          "Azure cloud — misconfigurations, IAM risks, exposed resources, Defender alerts",
    "aws":            "AWS cloud — S3 exposure, IAM, security groups, GuardDuty findings",
    "gcp":            "Google Cloud Platform — IAM, storage, compute misconfigurations",
    "nmap":           "Network hosts / IP ranges — open ports, services, OS detection",
    "web":            "Web applications — OWASP Top 10, injections, XSS, broken auth",
    "semgrep":        "Source code (static analysis) — bugs, injections, insecure patterns",
    "codeql":         "Source code (deep analysis) — data flow vulnerabilities",
    "sonarqube":      "Source code quality + security — connected SonarQube instance",
    "trivy":          "Container images / Kubernetes — CVEs in Docker images",
    "gitleaks":       "Git repositories — leaked secrets, API keys, credentials",
    "trufflehog":     "Git history deep scan — high-entropy secret detection",
    "openvas":        "Network vulnerability scan — CVEs across hosts (OpenVAS)",
    "owasp_dc":       "Dependency check — known CVEs in project dependencies",
    "ai_code_review": "AI code review — LLM-driven security review of source code",
    "tenable":        "Enterprise vulnerability management — Tenable.io",
    "burp_enterprise":"Web app scanning at scale — Burp Suite Enterprise",
    "snyk":           "Developer-first — code, containers, IaC, open-source dependencies",
    "rapid7":         "InsightVM — network vulnerability management",
    "qualys":         "VMDR — vulnerability management, detection, response",
    "invicti":        "Web application security — Invicti (Netsparker)",
    "acunetix":       "Web vulnerability scanner — Acunetix Enterprise",
    "nuclei":         "Template-based web/network scanner — Nuclei",
    "checkov":        "Infrastructure-as-Code — Terraform, CloudFormation, K8s misconfigs",
    "sslyze":         "TLS/SSL configuration audit — certificate issues, weak ciphers",
}

_SYSTEM_PROMPT = """\
You are the Aegis AI Scan Guide — a friendly, expert security assistant inside the Monitara security platform. Your job is to help the user launch the right security scan for their goal.

## Rules
- Ask EXACTLY ONE question at a time. Never combine two questions.
- Keep language simple and jargon-free — the user may not be technical.
- If the user's answer is vague or incomplete, ask again with a concrete example.
- Never ask for passwords or credentials in the chat — if a connector is already configured its credentials are stored securely; if not configured, tell the user to add it via the Connections page first.
- Be encouraging and concise. Acknowledge what the user said before asking the next question.
- When you have all required information, set ready_to_launch: true and summarise what will happen.

## Conversation Phases (follow in order)
1. INTENT — Understand what the user wants to assess (cloud environment, web app, network, code repo, container, etc.)
2. CONNECTOR — Suggest the best matching connector from those available. Explain in one sentence what it will scan. Confirm with user.
3. TARGET — Collect the specific target details required for that connector type:
   - azure/aws/gcp: subscription/account ID or region scope
   - web/burp_enterprise/invicti/acunetix/nuclei: target URL(s)
   - nmap/openvas/sslyze: IP address, CIDR range, or hostname
   - semgrep/codeql/ai_code_review: repository URL (GitHub/GitLab/Azure DevOps)
   - trivy: container image name (e.g. nginx:latest)
   - gitleaks/trufflehog: repository URL
   - tenable/rapid7/qualys/snyk: target scope or project name
   - checkov: repository URL or IaC directory
   - sonarqube: project key in SonarQube
   For already-configured cloud connectors, target is optional (default: full environment).
4. FRAMEWORK (optional) — Ask if they want compliance scoring against a framework (CIS Azure, NIST CSF, ISO 27001, etc.) or "None / skip".
5. CONFIRM — Summarise: connector, target, framework. Ask "Ready to launch?"

## Available Environment (live data injected below)
{env_profile}

## CRITICAL: End EVERY response with this exact marker and JSON (no code fences):
SCAN_STATE:{{"phase":"intent|connector|target|framework|confirm|ready","connector_type":"{connector_type_or_null}","connector_id":"{connector_id_or_null}","scan_name":"{descriptive_name_or_null}","target":"{target_or_null}","framework":"{framework_value_or_null}","ready_to_launch":false}}
"""

_AGENT_DESCRIPTIONS = {
    "threat_intel":        ("Threat Intel Agent",       "Maps your findings to MITRE ATT&CK tactics and adversary profiles"),
    "risk_manager":        ("Risk Manager Agent",        "Quantifies financial exposure (FAIR model) and prioritises risks"),
    "compliance_monitor":  ("Compliance Monitor Agent",  "Checks which framework controls are failing based on scan findings"),
    "remediation":         ("Remediation Agent",         "Generates step-by-step fix instructions and executable scripts"),
    "orchestrator":        ("Full Orchestrator",         "Runs all four agents in sequence — comprehensive analysis in one go"),
}


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str   # "user" | "assistant"
    content: str

class ChatRequest(BaseModel):
    message: str
    history: List[ChatMessage] = []

class OptionItem(BaseModel):
    label: str          # display text on the chip
    value: str          # sent back as the user's answer when clicked
    sub: Optional[str] = None  # optional subtitle (e.g. connector type)

class ChatResponse(BaseModel):
    message: str
    state: Dict[str, Any]
    options: List[OptionItem] = []   # quick-select chips shown below the AI message

class LaunchRequest(BaseModel):
    connector_id: str
    scan_name: str
    target: Optional[str] = None
    framework: Optional[str] = None

class LaunchResponse(BaseModel):
    scan_id: str
    scan_name: str

class AgentRecommendation(BaseModel):
    agent_type: str
    display_name: str
    reason: str
    priority: int

class NextStepsResponse(BaseModel):
    recommendations: List[AgentRecommendation]
    summary: str


# ── Environment profile builder ───────────────────────────────────────────────

def _build_env_profile(db: Session, client_id: str) -> str:
    lines = []

    # Configured connectors (with IDs so LLM can reference them)
    connectors = db.query(Connector).filter(
        Connector.client_id == client_id,
        Connector.is_active == True,
    ).all() if hasattr(Connector, "is_active") else db.query(Connector).filter(
        Connector.client_id == client_id,
    ).all()

    if connectors:
        lines.append("### Configured connectors (use these IDs when suggesting):")
        for c in connectors:
            ct = c.connector_type.value if hasattr(c.connector_type, "value") else str(c.connector_type)
            desc = _CONNECTOR_DESCRIPTIONS.get(ct, ct)
            lines.append(f"  - name='{c.name}' | type={ct} | id={c.id} | scans: {desc}")
    else:
        lines.append("### Configured connectors: NONE — tell the user to add connectors via the Connections page first.")

    # Recent scans
    recent = db.query(Scan).filter(
        Scan.client_id == client_id
    ).order_by(Scan.created_at.desc()).limit(5).all()
    if recent:
        lines.append("### Recent scans:")
        for s in recent:
            dt = s.created_at.strftime("%Y-%m-%d") if s.created_at else "unknown date"
            summary = s.summary or {}
            total = summary.get("total", "?")
            lines.append(f"  - '{s.name}' ({dt}) status={s.status.value if hasattr(s.status,'value') else s.status} findings={total}")

    # Asset + finding counts
    try:
        from api.models.models import Asset
        asset_count = db.query(Asset).filter(Asset.client_id == client_id).count()
        open_findings = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(
            Scan.client_id == client_id,
            Finding.status == "open",
        ).count()
        lines.append(f"### Environment size: {asset_count} assets, {open_findings} open findings")
    except Exception:
        pass

    return "\n".join(lines) if lines else "No environment data available yet."


# ── LLM call + state parser ────────────────────────────────────────────────────

_DEFAULT_STATE: Dict[str, Any] = {
    "phase": "intent",
    "connector_type": None,
    "connector_id": None,
    "scan_name": None,
    "target": None,
    "framework": None,
    "ready_to_launch": False,
}

def _parse_state(raw: str) -> tuple[str, Dict[str, Any]]:
    """Split message from SCAN_STATE JSON block. Returns (display_message, state_dict)."""
    marker = "SCAN_STATE:"
    idx = raw.rfind(marker)
    if idx == -1:
        return raw.strip(), dict(_DEFAULT_STATE)

    display = raw[:idx].strip()
    json_str = raw[idx + len(marker):].strip()
    try:
        state = json.loads(json_str)
    except Exception:
        # Try to extract JSON between { }
        try:
            start = json_str.index("{")
            end = json_str.rindex("}") + 1
            state = json.loads(json_str[start:end])
        except Exception:
            state = dict(_DEFAULT_STATE)

    # Normalise
    for k, v in _DEFAULT_STATE.items():
        if k not in state:
            state[k] = v
    # null strings → None
    for k in ("connector_type", "connector_id", "scan_name", "target", "framework"):
        if state.get(k) in ("null", "None", "", "{connector_type_or_null}",
                             "{connector_id_or_null}", "{descriptive_name_or_null}",
                             "{target_or_null}", "{framework_value_or_null}"):
            state[k] = None

    return display, state


async def _call_llm(system: str, messages: List[Dict]) -> str:
    from core.ai_providers import get_llm
    from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

    llm = get_llm()
    lc_messages = [SystemMessage(content=system)]
    for m in messages:
        if m["role"] == "user":
            lc_messages.append(HumanMessage(content=m["content"]))
        else:
            lc_messages.append(AIMessage(content=m["content"]))

    response = await llm.ainvoke(lc_messages)
    return response.content


# ── Options builder (server-side, not LLM) ────────────────────────────────────

_FRAMEWORK_OPTIONS = [
    ("NIST CSF 2.0",         "nist_csf"),
    ("CIS Controls v8",      "cis_v8"),
    ("CIS Azure",            "cis_azure"),
    ("CIS AWS",              "cis_aws"),
    ("ISO/IEC 27001",        "iso_27001"),
    ("PCI DSS v4",           "pci_dss"),
    ("GDPR",                 "gdpr"),
    ("Skip / No framework",  "none"),
]

def _build_options(phase: str, db: Session, client_id: str) -> List[OptionItem]:
    """Return quick-select chip options for the current phase.
    These are built from live DB data — not generated by the LLM."""
    if phase == "connector":
        connectors = db.query(Connector).filter(
            Connector.client_id == client_id
        ).all()
        return [
            OptionItem(
                label=c.name,
                value=f"Use {c.name}",
                sub=c.connector_type.value if hasattr(c.connector_type, "value") else str(c.connector_type),
            )
            for c in connectors
        ]
    if phase == "framework":
        return [OptionItem(label=label, value=label) for label, _ in _FRAMEWORK_OPTIONS]
    return []


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/clients/{client_id}/ai-assisted-scan/chat", response_model=ChatResponse)
async def ai_scan_chat(
    client_id: str,
    payload: ChatRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    env_profile = _build_env_profile(db, client_id)
    system = _SYSTEM_PROMPT.format(env_profile=env_profile)

    history = [{"role": m.role, "content": m.content} for m in payload.history]
    history.append({"role": "user", "content": payload.message})

    try:
        raw = await _call_llm(system, history)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"AI provider unavailable: {exc}")

    display, state = _parse_state(raw)
    options = _build_options(state.get("phase", "intent"), db, client_id)
    return ChatResponse(message=display, state=state, options=options)


@router.post("/clients/{client_id}/ai-assisted-scan/launch", response_model=LaunchResponse)
async def ai_scan_launch(
    client_id: str,
    payload: LaunchRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    from api.routers.scans import _execute_scan
    from core.config import get_settings
    from api.models.models import FrameworkType

    connector = db.query(Connector).filter(
        Connector.id == payload.connector_id,
        Connector.client_id == client_id,
    ).first()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    framework = None
    if payload.framework:
        try:
            framework = FrameworkType(payload.framework)
        except ValueError:
            pass

    initial_summary: Optional[Dict] = None
    if payload.target:
        initial_summary = {"ai_guided_target": payload.target}

    scan = Scan(
        client_id=client_id,
        connector_id=payload.connector_id,
        name=payload.scan_name or f"AI Guided Scan — {connector.name}",
        scan_type=connector.connector_type,
        framework=framework,
        initiated_by=user.get("upn", user.get("preferred_username", "ai-guided")),
        status=ScanStatus.PENDING,
        summary=initial_summary,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(
        _execute_scan, scan.id, get_settings().DATABASE_URL, None, None,
    )

    return LaunchResponse(scan_id=scan.id, scan_name=scan.name)


@router.get("/clients/{client_id}/ai-assisted-scan/{scan_id}/next-steps", response_model=NextStepsResponse)
async def ai_scan_next_steps(
    client_id: str,
    scan_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.client_id == client_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Build compact finding summary — no full dump, just counts + top titles
    summary = scan.summary or {}
    sev_counts = {s: summary.get(s, 0) for s in ["critical", "high", "medium", "low", "info"]}
    total = summary.get("total", sum(sev_counts.values()))

    top_findings = db.query(Finding.title, Finding.severity).filter(
        Finding.scan_id == scan_id,
        Finding.status == "open",
    ).order_by(Finding.severity).limit(5).all()

    top_titles = [f"{f.severity.value if hasattr(f.severity,'value') else f.severity}: {f.title}" for f in top_findings]

    prompt = f"""A security scan just completed. Based on the results, recommend which AI analysis agents to run next.

Scan: {scan.name}
Findings: {total} total — critical={sev_counts['critical']}, high={sev_counts['high']}, medium={sev_counts['medium']}, low={sev_counts['low']}
Top findings: {', '.join(top_titles) if top_titles else 'none'}

Available agents:
- threat_intel: maps findings to MITRE ATT&CK, identifies adversary profiles
- risk_manager: FAIR-model financial risk quantification, risk prioritisation
- compliance_monitor: checks framework controls (CIS, NIST, ISO 27001, etc.)
- remediation: generates step-by-step fix scripts and playbooks
- orchestrator: runs all four agents in one go

Respond ONLY with JSON:
{{"summary": "one sentence about the scan results and what needs attention", "recommendations": [{{"agent_type": "...", "priority": 1, "reason": "one sentence why"}}]}}

Order by priority (1 = most urgent). Include only agents that make sense for these results."""

    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage
        llm = get_llm()
        resp = await llm.ainvoke([HumanMessage(content=prompt)])
        raw = resp.content.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        data = json.loads(raw)
    except Exception as exc:
        logger.warning("next-steps LLM call failed: %s", exc)
        # Fallback: sensible defaults
        data = {
            "summary": f"Scan completed with {total} findings ({sev_counts['critical']} critical, {sev_counts['high']} high).",
            "recommendations": [
                {"agent_type": "orchestrator", "priority": 1, "reason": "Run a full analysis to get threat intelligence, risk scores, compliance gaps, and remediation scripts in one go."},
            ]
        }

    recs = []
    for r in data.get("recommendations", []):
        agent_type = r.get("agent_type", "orchestrator")
        display_name, default_reason = _AGENT_DESCRIPTIONS.get(agent_type, (agent_type, ""))
        recs.append(AgentRecommendation(
            agent_type=agent_type,
            display_name=display_name,
            reason=r.get("reason", default_reason),
            priority=r.get("priority", 99),
        ))

    recs.sort(key=lambda x: x.priority)
    return NextStepsResponse(summary=data.get("summary", ""), recommendations=recs)
