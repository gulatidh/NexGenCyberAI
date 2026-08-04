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
- Frontend handles all wizard UI and option selection; backend only provides
  AI guidance text and state parsing.
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


_MONITARA_NAV = """\
## Monitara AI — Quick Navigation Reference
- Add / manage connectors: left nav → **Connections** → **Add Connection** (NOT "Settings → Integrations")
- Launch a scan manually: left nav → **Assessments** → **New Scan**
- Run AI analysis after a scan: left nav → **AI Buddies** → select scan → choose agent → Run
- View threats/compliance gaps/remediations: **Threat Register** / **Control Deficiencies** / **Remediation Tracker** in left nav
- Configure LLM providers: left nav → **Connections** → **AI Settings**
- Connector credentials are stored securely — never ask the user for passwords in chat
"""

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
You are the Aegis AI Scan Guide inside Monitara AI. The user is configuring a security scan through a structured wizard UI — your role is to provide helpful guidance text that appears in a blue strip at the top of the wizard. You do NOT drive navigation — the UI handles that. Respond with concise, encouraging guidance (1-3 sentences) based on what the user has selected or asked.

{nav_reference}

═══ RULES ═══

R1 — Keep responses SHORT and helpful. The UI already shows the wizard options — just acknowledge the selection and hint at what's next.

R2 — NEVER ask the user to name a connector or choose options — the UI provides those. Only comment on what they've chosen or asked.

R3 — If the user sends free text with a question, answer it helpfully based on the environment profile below.

R4 — NEVER ASK IF A CONNECTOR EXISTS. The Available Environment below shows every configured connector.

═══ AVAILABLE ENVIRONMENT (live data) ═══
{env_profile}

═══ MANDATORY: End EVERY response with this marker + JSON (no code fences, no backticks) ═══
SCAN_STATE:{{"phase":"PHASE","category":"CATEGORY_OR_NULL","connector_type":"TYPE_OR_NULL","connector_id":"ID_OR_NULL","scan_name":"NAME_OR_NULL","target":"TARGET_OR_NULL","framework":"KEY_OR_NULL","ready_to_launch":false}}
Allowed PHASE values: intent | connector | target | framework | confirm | ready
Use the literal word null (no quotes) for unknown fields.
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
    label: str
    value: str
    sub: Optional[str] = None

class ChatResponse(BaseModel):
    message: str
    state: Dict[str, Any]
    options: List[OptionItem] = []

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

    # Group connectors by security use-case so LLM can instantly match user intent
    _CATEGORY_TYPES = {
        "Web / DAST":        {"web", "burp_enterprise", "invicti", "acunetix", "nuclei"},
        "Cloud posture":     {"azure", "aws", "gcp"},
        "SAST / Code":       {"semgrep", "codeql", "sonarqube", "ai_code_review"},
        "Network":           {"nmap", "openvas", "sslyze"},
        "Containers":        {"trivy"},
        "Secrets detection": {"gitleaks", "trufflehog"},
        "Dependencies":      {"owasp_dc", "snyk", "checkov"},
        "Enterprise VM":     {"tenable", "rapid7", "qualys"},
    }

    if connectors:
        # Build category → connector list map
        by_category: Dict[str, list] = {cat: [] for cat in _CATEGORY_TYPES}
        by_category["Other"] = []
        for c in connectors:
            ct = c.connector_type.value if hasattr(c.connector_type, "value") else str(c.connector_type)
            placed = False
            for cat, types in _CATEGORY_TYPES.items():
                if ct in types:
                    by_category[cat].append((c.name, ct, c.id))
                    placed = True
                    break
            if not placed:
                by_category["Other"].append((c.name, ct, c.id))

        lines.append("### Configured connectors grouped by use-case:")
        for cat, items in by_category.items():
            if items:
                item_strs = [f"'{name}' (type={ct}, id={cid})" for name, ct, cid in items]
                lines.append(f"  {cat}: {', '.join(item_strs)}")
            else:
                lines.append(f"  {cat}: [none configured]")
    else:
        lines.append("### Configured connectors: NONE — tell the user they need to add connectors via the Connections page before scanning.")

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

    # Asset inventory — grouped by class, each entry shows asset name + connector source
    try:
        from api.models.models import Asset as AssetModel

        # Build connector_id → (name, type) lookup from already-queried connectors
        conn_map = {}
        for c in connectors:
            ct = c.connector_type.value if hasattr(c.connector_type, "value") else str(c.connector_type)
            conn_map[c.id] = (c.name, ct)

        # Fetch assets (cap at 150 most recent to stay compact)
        assets = (
            db.query(AssetModel)
            .filter(AssetModel.client_id == client_id)
            .order_by(AssetModel.last_synced_at.desc())
            .limit(150)
            .all()
        )

        # Friendly class labels
        _CLASS_LABEL = {
            "vm":       "VMs / Compute",
            "storage":  "Storage",
            "network":  "Network",
            "database": "Databases",
            "identity": "Identity / IAM",
            "keyvault": "Key Vaults / Secrets",
            "other":    "Other cloud resources",
        }
        _WEB_CLASSES  = {"url", "web", "webapp", "application"}
        _CODE_CLASSES = {"repo", "repository", "code", "codebase"}
        _CONT_CLASSES = {"container", "image", "docker"}

        by_class: Dict[str, list] = {}
        for a in assets:
            ac = (a.asset_class or "other").lower()
            if ac in _WEB_CLASSES:
                bucket = "Web apps / URLs"
            elif ac in _CODE_CLASSES:
                bucket = "Code repositories"
            elif ac in _CONT_CLASSES:
                bucket = "Container images"
            else:
                bucket = _CLASS_LABEL.get(ac, f"{ac}")
            by_class.setdefault(bucket, []).append(a)

        if assets:
            open_findings = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(
                Scan.client_id == client_id, Finding.status == "open",
            ).count()
            lines.append(
                f"\n### Asset inventory ({len(assets)} assets, {open_findings} open findings):"
            )
            for bucket, items in by_class.items():
                shown = items[:12]
                asset_strs = []
                for a in shown:
                    cname, ctype = conn_map.get(a.connector_id, ("unknown connector", "?"))
                    synced = a.last_synced_at.strftime("%Y-%m-%d") if a.last_synced_at else "?"
                    asset_strs.append(f"'{a.name}' [via '{cname}' ({ctype}), last seen {synced}]")
                overflow = f" (+{len(items)-12} more)" if len(items) > 12 else ""
                lines.append(f"  {bucket}: {', '.join(asset_strs)}{overflow}")
        else:
            lines.append("\n### Asset inventory: empty (no assets discovered yet — run a scan first to populate)")
    except Exception as _ae:
        logger.debug("asset map build failed: %s", _ae)

    return "\n".join(lines) if lines else "No environment data available yet."


# ── LLM call + state parser ────────────────────────────────────────────────────

_DEFAULT_STATE: Dict[str, Any] = {
    "phase": "intent",
    "category": None,
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
        "TARGET_OR_NULL", "FRAMEWORK_OR_NULL", "CURRENT_PHASE", "CATEGORY_OR_NULL",
        "{connector_type_or_null}", "{connector_id_or_null}",
        "{descriptive_name_or_null}", "{target_or_null}", "{framework_value_or_null}",
    }
    for k in ("category", "connector_type", "connector_id", "scan_name", "target", "framework"):
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


# ── Options builder — frontend handles all selections, always return empty ─────

def _build_options(state: Dict[str, Any], db: Session, client_id: str, history_len: int = 0) -> List[OptionItem]:
    """Frontend handles all wizard selections. Always return empty list."""
    return []


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

    system = (
        _SYSTEM_PROMPT
        .replace("{nav_reference}", _MONITARA_NAV)
        .replace("{env_profile}", env_profile)
    )

    history = [{"role": m.role, "content": m.content} for m in payload.history]
    history.append({"role": "user", "content": payload.message})

    try:
        raw = await _call_llm(system, history)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"AI provider unavailable: {exc}")

    display, state = _parse_state(raw)
    options = _build_options(state, db, client_id, history_len=len(history))
    return ChatResponse(message=display, state=state, options=options)


class LaunchRequest(BaseModel):
    connector_id: Optional[str] = None
    connector_type: Optional[str] = None  # fallback if connector_id is null
    scan_name: str = "AI Guided Scan"
    target: Optional[str] = None
    framework: Optional[str] = None


# Framework label → key mapping for launch endpoint
_FRAMEWORK_LABEL_TO_KEY = {
    "NIST CSF 2.0":      "nist_csf",
    "CIS Controls v8":   "cis_v8",
    "CIS Azure":         "cis_azure",
    "CIS AWS":           "cis_aws",
    "ISO/IEC 27001":     "iso_27001",
    "PCI DSS v4":        "pci_dss",
    "GDPR":              "gdpr",
    "Skip / No framework": "",
}


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
        from api.models.models import FrameworkType, ScanType

        # Map connector category → appropriate ScanType
        _CT_TO_SCAN_TYPE = {
            "azure": ScanType.CONFIGURATION, "aws": ScanType.CONFIGURATION,
            "gcp": ScanType.CONFIGURATION,
        }
        _DEFAULT_SCAN_TYPE = ScanType.FULL

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

        ct_key = connector.connector_type.value if hasattr(connector.connector_type, "value") else str(connector.connector_type)
        resolved_scan_type = _CT_TO_SCAN_TYPE.get(ct_key, _DEFAULT_SCAN_TYPE)

        # Build initial_summary with the right key for each scanner type.
        # Code-review scanners read "repo_url"; web scanners read "target_url".
        _CODE_REVIEW_TYPES = {"ai_code_review", "semgrep", "codeql", "gitleaks", "trufflehog"}
        _WEB_SCAN_TYPES    = {"web", "burp_enterprise", "invicti", "acunetix", "nuclei", "nmap", "openvas", "sslyze"}
        initial_summary: Optional[Dict] = None
        if payload.target:
            if ct_key in _CODE_REVIEW_TYPES:
                initial_summary = {"repo_url": payload.target, "ai_guided_target": payload.target}
            elif ct_key in _WEB_SCAN_TYPES:
                initial_summary = {"target_url": payload.target, "ai_guided_target": payload.target}
            else:
                initial_summary = {"ai_guided_target": payload.target}

        scan = Scan(
            client_id=client_id,
            connector_id=connector.id,
            name=payload.scan_name or f"AI Guided Scan — {connector.name}",
            scan_type=resolved_scan_type,
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
