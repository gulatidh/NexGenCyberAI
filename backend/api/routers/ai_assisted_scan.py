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
import os
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


def _load_portal_context() -> str:
    """Load the Monitara platform knowledge base used by the portal assistant."""
    try:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(here, "data", "portal_assistant_context.md")
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""

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
You are the Aegis AI Scan Guide — a friendly, expert security assistant embedded inside the Monitara AI cybersecurity platform. Your sole job is to help the user launch the right security scan for their goal.

## Platform: Monitara AI (also called Aegis AI)
This is NOT a generic platform. Use only the navigation paths and workflows described below.

### How to add a connector (if one is missing)
Left nav → **Connections** → click **Add Connection** → select the connector type → fill credentials → Save.
Do NOT say "look in Settings → Integrations" or "click Add Connector" — those paths don't exist. The page is called **Connections**.

### How to run a scan (for your reference — you will launch it via the button in this wizard)
Left nav → **Assessments** → **New Scan** → choose client + connector → set scan type → (optional) pick a framework → Start.
Users launching through this AI wizard do NOT need to go to Assessments — the Launch button here will create and start the scan automatically.

### Key navigation
- **Connections**: where all connectors (cloud, scanners, enterprise tools) are added and managed
- **Assessments**: scan history — shows progress after a scan is launched
- **AI Buddies**: run AI agents (Risk Manager, Threat Intel, Compliance Monitor, Remediation, Orchestrator) against completed scans
- **Threat Register / Control Deficiencies / Remediation Tracker**: registers populated by AI agents
- **AI Settings**: configure LLM providers (Azure OpenAI, OpenAI, Anthropic, etc.)

## Rules
- Ask EXACTLY ONE question at a time. Never combine two questions.
- Keep language simple and jargon-free — the user may not be technical.
- If the user's answer is vague or incomplete, ask again with a concrete example.
- Never ask for passwords or credentials in the chat — if a connector is already configured its credentials are stored securely; if not configured, tell the user to add it via the **Connections** page first.
- Be encouraging and concise. Acknowledge what the user said before asking the next question.
- When you have all required information, set ready_to_launch: true and summarise what will happen.

## Conversation Phases (follow in order)
1. INTENT — Understand what the user wants to assess (cloud environment, web app, network, code repo, container, etc.)
2. CONNECTOR — Suggest the best matching connector from those available in the environment. Explain in one sentence what it will scan. Confirm with user.
3. TARGET — Collect the specific target details required for that connector type:
   - azure/aws/gcp: subscription/account ID or region scope (optional for configured cloud connectors — default scans full environment)
   - web/burp_enterprise/invicti/acunetix/nuclei: target URL(s)
   - nmap/openvas/sslyze: IP address, CIDR range, or hostname
   - semgrep/codeql/ai_code_review: repository URL (GitHub/GitLab/Azure DevOps)
   - trivy: container image name (e.g. nginx:latest)
   - gitleaks/trufflehog: repository URL
   - tenable/rapid7/qualys/snyk: target scope or project name
   - checkov: repository URL or IaC directory
   - sonarqube: project key in SonarQube
4. FRAMEWORK (optional) — Ask if they want compliance scoring against a framework (CIS Azure, NIST CSF, ISO 27001, etc.) or "None / skip".
5. CONFIRM — Summarise: connector, target, framework. Ask "Shall I launch the scan?"

## Available Environment (live data injected below)
{env_profile}

## CRITICAL: End EVERY response with the SCAN_STATE marker below (no code fences, no backticks).
You MUST advance the phase field as the conversation progresses — do NOT keep it at "intent" once you have moved on:
- phase = "intent"    → while you are still understanding what the user wants to assess
- phase = "connector" → once you know the goal and are suggesting / confirming which scanner to use
- phase = "target"    → once the connector is confirmed and you are asking for target details
- phase = "framework" → once the target is confirmed and you are asking about compliance framework
- phase = "confirm"   → once all details are collected; summarise and ask the user to confirm
- phase = "ready"     → user confirmed launch; set ready_to_launch: true

Also fill in the other fields as you collect them (null until known):
- connector_type: the lowercase connector type key (e.g. "azure", "web", "semgrep")
- connector_id: the exact ID from the Available Environment list
- scan_name: a short descriptive name for the scan
- target: the target string (URL, IP, repo URL, image name, or null for full-environment cloud scans)
- framework: framework key (e.g. "nist_csf", "iso_27001") or null

SCAN_STATE:{{"phase":"CURRENT_PHASE","connector_type":"TYPE_OR_NULL","connector_id":"ID_OR_NULL","scan_name":"NAME_OR_NULL","target":"TARGET_OR_NULL","framework":"FRAMEWORK_OR_NULL","ready_to_launch":false}}
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
    # null strings → None (covers old and new placeholder values)
    _NULL_VALUES = {
        "null", "None", "", "TYPE_OR_NULL", "ID_OR_NULL", "NAME_OR_NULL",
        "TARGET_OR_NULL", "FRAMEWORK_OR_NULL", "CURRENT_PHASE",
        "{connector_type_or_null}", "{connector_id_or_null}",
        "{descriptive_name_or_null}", "{target_or_null}", "{framework_value_or_null}",
    }
    for k in ("connector_type", "connector_id", "scan_name", "target", "framework"):
        if state.get(k) in _NULL_VALUES:
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
    ("NIST CSF 2.0",        "nist_csf"),
    ("CIS Controls v8",     "cis_v8"),
    ("CIS Azure",           "cis_azure"),
    ("CIS AWS",             "cis_aws"),
    ("ISO/IEC 27001",       "iso_27001"),
    ("PCI DSS v4",          "pci_dss"),
    ("GDPR",                "gdpr"),
    ("Skip / No framework", ""),
]

# Map label → enum key so chip values are always the correct DB key
_FRAMEWORK_LABEL_TO_KEY = {label: key for label, key in _FRAMEWORK_OPTIONS}

_OTHER_OPTION = OptionItem(label="Other / Not listed", value="__other__", sub="Type your own answer below")

_INTENT_OPTIONS = [
    OptionItem(label="Azure / Cloud posture",    value="I want to scan my Azure cloud environment for misconfigurations and security risks",         sub="Cloud security"),
    OptionItem(label="Web application",           value="I want to scan a web application for OWASP vulnerabilities",                               sub="DAST / web"),
    OptionItem(label="Source code review",        value="I want to review source code for security vulnerabilities",                                sub="SAST / code"),
    OptionItem(label="Network / IP range",        value="I want to scan my network or IP address range for open ports and vulnerabilities",          sub="Network"),
    OptionItem(label="Container / Docker image",  value="I want to scan a container image for known CVEs",                                          sub="Container"),
    OptionItem(label="Find leaked secrets",       value="I want to scan a code repository for leaked secrets, API keys, and credentials",           sub="Secrets detection"),
]

_CONFIRM_OPTIONS = [
    OptionItem(label="Yes, launch the scan!",    value="Yes, everything looks correct. Please launch the scan."),
    OptionItem(label="Change the connector",     value="I'd like to use a different connector or scanner."),
    OptionItem(label="Change the target",        value="I'd like to change the target."),
    OptionItem(label="Change the framework",     value="I'd like to use a different compliance framework."),
]


_CLOUD_CONNECTOR_TYPES = {"azure", "aws", "gcp"}


def _infer_options_phase(state: Dict[str, Any]) -> str:
    """Infer which option set to display from collected state fields.
    The LLM often keeps phase='intent' even when further along — we override
    based on what fields are actually filled in."""
    if state.get("ready_to_launch"):
        return "ready"
    llm_phase = state.get("phase", "intent")
    if llm_phase in ("confirm", "ready"):
        return "confirm"
    if state.get("connector_id"):
        # Connector confirmed — in target, framework, or confirm
        if llm_phase == "framework":
            return "framework"
        return "target"
    if state.get("connector_type") or llm_phase == "connector":
        return "connector"
    return "intent"


def _build_options(state: Dict[str, Any], db: Session, client_id: str) -> List[OptionItem]:
    """Return quick-select chip options inferred from conversation state.
    Built from live DB data — not generated by the LLM."""
    phase = _infer_options_phase(state)
    connector_type = (state.get("connector_type") or "").lower()

    if phase == "intent":
        return _INTENT_OPTIONS + [_OTHER_OPTION]

    if phase == "connector":
        connectors = db.query(Connector).filter(
            Connector.client_id == client_id,
        ).all()
        items = [
            OptionItem(
                label=c.name,
                value=f"Use {c.name}",
                sub=c.connector_type.value if hasattr(c.connector_type, "value") else str(c.connector_type),
            )
            for c in connectors
        ]
        return items + [_OTHER_OPTION]

    if phase == "target":
        if connector_type in _CLOUD_CONNECTOR_TYPES:
            return [
                OptionItem(label="Full environment (default)", value="Scan my full environment — no specific scope needed"),
                OptionItem(label="Specific subscription / account", value="I want to specify a subscription or account ID"),
                _OTHER_OPTION,
            ]
        return [_OTHER_OPTION]

    if phase == "framework":
        items = [OptionItem(label=label, value=key or label) for label, key in _FRAMEWORK_OPTIONS]
        return items + [_OTHER_OPTION]

    if phase in ("confirm", "ready"):
        return _CONFIRM_OPTIONS

    return [_OTHER_OPTION]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/clients/{client_id}/ai-assisted-scan/chat", response_model=ChatResponse)
async def ai_scan_chat(
    client_id: str,
    payload: ChatRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    try:
        env_profile = _build_env_profile(db, client_id)
    except Exception as exc:
        logger.warning("ai_scan_chat: env profile build failed: %s", exc)
        env_profile = "No environment data available yet."

    portal_ctx = _load_portal_context()
    system = (
        (portal_ctx + "\n\n---\n\n") if portal_ctx else ""
    ) + _SYSTEM_PROMPT.replace("{env_profile}", env_profile)

    history = [{"role": m.role, "content": m.content} for m in payload.history]
    history.append({"role": "user", "content": payload.message})

    try:
        raw = await _call_llm(system, history)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"AI provider unavailable: {exc}")

    display, state = _parse_state(raw)
    options = _build_options(state, db, client_id)
    return ChatResponse(message=display, state=state, options=options)


class LaunchRequest(BaseModel):
    connector_id: Optional[str] = None
    connector_type: Optional[str] = None  # fallback if connector_id is null
    scan_name: str = "AI Guided Scan"
    target: Optional[str] = None
    framework: Optional[str] = None


@router.post("/clients/{client_id}/ai-assisted-scan/launch", response_model=LaunchResponse)
async def ai_scan_launch(
    client_id: str,
    payload: LaunchRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    try:
        from api.routers.scans import _execute_scan
        from core.config import get_settings
        from api.models.models import FrameworkType

        # Resolve connector — prefer explicit ID, fall back to first matching type
        connector = None
        if payload.connector_id:
            connector = db.query(Connector).filter(
                Connector.id == payload.connector_id,
                Connector.client_id == client_id,
            ).first()
        if not connector and payload.connector_type:
            # Find first connector of that type for this client
            from api.models.models import ConnectorType
            try:
                ct = ConnectorType(payload.connector_type.lower())
                connector = db.query(Connector).filter(
                    Connector.client_id == client_id,
                    Connector.connector_type == ct,
                ).first()
            except (ValueError, Exception):
                connector = None
        if not connector:
            raise HTTPException(
                status_code=404,
                detail=f"Connector not found — no connector_id provided and no connector of type '{payload.connector_type}' configured for this client. Add a connector via the Connections page first.",
            )

        # Resolve framework key — handle label strings ("CIS Azure" → "cis_azure")
        framework_key = payload.framework or ""
        if framework_key in _FRAMEWORK_LABEL_TO_KEY:
            framework_key = _FRAMEWORK_LABEL_TO_KEY[framework_key]
        framework = None
        if framework_key:
            try:
                framework = FrameworkType(framework_key)
            except ValueError:
                pass

        initial_summary: Optional[Dict] = None
        if payload.target:
            initial_summary = {"ai_guided_target": payload.target}

        scan = Scan(
            client_id=client_id,
            connector_id=connector.id,
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

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("ai_scan_launch failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to launch scan: {exc}")


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
