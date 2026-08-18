"""AI Guardrails status endpoint — returns live evidence for each security control."""
from typing import Optional
from fastapi import APIRouter, Depends
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func

from core.security import get_current_user
from db.database import get_db

router = APIRouter(prefix="/ai-guardrails", tags=["guardrails"])


@router.get("/status")
async def get_guardrails_status(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Return the status and evidence for every AI guardrail control (live DB-backed)."""
    from api.models.models import PromptAuditLog

    total_audit_logs = db.query(func.count(PromptAuditLog.id)).scalar() or 0
    nl_query_logs    = db.query(func.count(PromptAuditLog.id)).filter(PromptAuditLog.endpoint == "nl_query").scalar() or 0
    assistant_logs   = db.query(func.count(PromptAuditLog.id)).filter(PromptAuditLog.endpoint == "assistant_chat").scalar() or 0
    agent_logs       = db.query(func.count(PromptAuditLog.id)).filter(PromptAuditLog.endpoint == "agent_run").scalar() or 0

    audit_covered = []
    audit_pending = []
    if agent_logs > 0:
        audit_covered.append({"label": "Agent run logging", "detail": f"{agent_logs} agent runs logged — routers/agent_catalog.py"})
    else:
        audit_pending.append("Agent run audit logging (no entries yet)")
    if nl_query_logs > 0:
        audit_covered.append({"label": "NL Query logging", "detail": f"{nl_query_logs} NL queries logged — routers/nl_query.py"})
    else:
        audit_pending.append("NL Query endpoint audit logging (no entries yet)")
    if assistant_logs > 0:
        audit_covered.append({"label": "Assistant chat logging", "detail": f"{assistant_logs} assistant messages logged — routers/assistant.py"})
    else:
        audit_pending.append("Assistant chat endpoint audit logging (no entries yet)")
    audit_pending.append("Retention policy and automated export for compliance audits")

    endpoints_covered = sum([agent_logs > 0, nl_query_logs > 0, assistant_logs > 0])
    audit_status = "active" if endpoints_covered == 3 else "partial"

    rate_limit_evidence = [
        {"label": "Global user limit",         "detail": "120 requests/min per user (JWT sub, falls back to IP) — _RateLimitMiddleware in main.py"},
        {"label": "Expensive endpoint limit",  "detail": "5 req/min per user for POST /scans/, /agents/run, /assistant/chat, /findings/, /playbook — main.py"},
        {"label": "HTTP 429 + Retry-After",    "detail": "Returns {'detail': 'Rate limit exceeded'} + Retry-After: 60 header"},
    ]
    rate_limit_pending = [
        "Monthly AI token budget cap per client/tenant",
        "Rate limit state persistence across server restarts (currently in-memory only)",
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "controls": [
            {
                "id": "input_validation",
                "name": "Input Length & Format Validation",
                "category": "Input Safety",
                "status": "active",
                "description": "Pydantic request models enforce maximum character limits on all user-controlled text fields sent to LLMs. FastAPI automatically returns HTTP 422 Unprocessable Entity on violation — the LLM is never called.",
                "evidence": [
                    {"label": "NL Query limit",        "detail": "NLQueryRequest.question: Field(max_length=2000) — routers/nl_query.py"},
                    {"label": "Assistant message limit","detail": "ChatRequest.message: Field(max_length=4000) — routers/assistant.py"},
                    {"label": "Automatic enforcement", "detail": "FastAPI + Pydantic v2 enforce limits before the endpoint body runs — HTTP 422 returned, LLM never called"},
                ],
                "pending": [
                    "AgentRunRequest.additional_context field length limit",
                    "File upload size validation for AI Code Review archive uploads",
                ],
            },
            {
                "id": "prompt_isolation",
                "name": "Prompt Injection Isolation",
                "category": "Input Safety",
                "status": "active",
                "description": "User-controlled data is wrapped in XML boundary markers before insertion into LLM system prompts. HTML entities are escaped in finding titles. Follows OWASP LLM01 indirect prompt injection guidance.",
                "evidence": [
                    {"label": "Finding title HTML-escaping", "detail": "title_safe = title.replace('<','&lt;').replace('>','&gt;') — routers/agent_catalog.py"},
                    {"label": "Findings XML wrapper",        "detail": "<findings>…</findings> block isolates all finding data from LLM instructions — routers/agent_catalog.py"},
                    {"label": "NL Query isolation",          "detail": "HumanMessage(content='<question>{payload.question}</question>') — routers/nl_query.py"},
                    {"label": "Assistant message isolation", "detail": "HumanMessage(content='<user_message>{payload.message}</user_message>') — routers/assistant.py"},
                ],
                "pending": [
                    "Asset name / description escaping (passed to threat modeler prompts)",
                    "Automated red-team testing with OWASP LLM test suite in CI/CD pipeline",
                ],
            },
            {
                "id": "sql_injection",
                "name": "NL Query SQL Injection Prevention",
                "category": "Input Safety",
                "status": "active",
                "description": "Natural language queries are LLM-converted to SQL and then safety-validated before execution. Only SELECT/WITH statements execute. Dangerous DML/DDL keywords are blocked by regex. A hard TOP 100 row limit is injected.",
                "evidence": [
                    {"label": "SELECT/WITH allowlist", "detail": "first_word check — non-SELECT returns HTTP 400 before DB is touched — routers/nl_query.py"},
                    {"label": "Keyword blocklist",     "detail": r"re.compile(r'\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|REPLACE)\b', re.I) — routers/nl_query.py"},
                    {"label": "Hard row limit",        "detail": "SELECT TOP 100 injected into every generated query via _inject_top() — routers/nl_query.py"},
                    {"label": "Client scoping",        "detail": "Schema hint instructs LLM: filter client_id = '{client_id}' — user can only see their own records"},
                ],
                "pending": [],
            },
            {
                "id": "rate_limiting",
                "name": "API Rate Limiting",
                "category": "Abuse Prevention",
                "status": "active",
                "description": "In-memory per-user rate limiting on all endpoints. JWT sub claim used as bucket key (falls back to IP for unauthenticated requests). General limit: 120 req/min. Expensive AI endpoints: 5 req/min. Returns HTTP 429 with Retry-After header.",
                "evidence": rate_limit_evidence,
                "pending": rate_limit_pending,
            },
            {
                "id": "token_budget",
                "name": "LLM Token Budget Enforcement",
                "category": "Abuse Prevention",
                "status": "partial",
                "description": "All LLM calls are capped at max_tokens=4096 output by default. AI Code Review has an explicit configurable token budget. No cross-request cumulative spend cap yet.",
                "evidence": [
                    {"label": "Default output cap",     "detail": "max_tokens=4096 default in get_llm() — core/ai_providers.py"},
                    {"label": "Code review budget",     "detail": "CODE_REVIEW_MAX_TOKENS env var controls reviewer token budget — services/code_review/runner.py"},
                    {"label": "Provider failover safety","detail": "Automatic failover across 6 providers prevents single-provider over-spending"},
                ],
                "pending": [
                    "Cumulative token budget across all agents per client (monthly cap)",
                    "Cost-aware throttling: route expensive tasks to cheaper models when budget is low",
                    "Per-tenant spend alerts and hard cutoff",
                ],
            },
            {
                "id": "output_validation",
                "name": "LLM Output Schema Validation",
                "category": "Output Safety",
                "status": "partial",
                "description": "Agent outputs are parsed through per-kind JSON schema validation. Artifacts are capped at 25 per response. Enum fields are coerced to known values. Malformed JSON falls back to raw text extraction.",
                "evidence": [
                    {"label": "Per-kind schema validation","detail": "parse_response() validates risk_drafts, jira_drafts, control_mappings, runbook schemas — services/agent_artifacts.py"},
                    {"label": "Artifact cap",              "detail": "artifacts[:25] hard limit prevents oversized response sets"},
                    {"label": "Defensive JSON parsing",    "detail": "Markdown fence stripping, JSON extraction from prose, summary fallback on parse failure"},
                ],
                "pending": [
                    "Strict JSON Schema engine validation (currently loose coercion, not $schema-validated)",
                    "Secret and credential pattern detection in agent outputs before storage",
                    "PII detection before persisting LLM responses to the database",
                ],
            },
            {
                "id": "access_control",
                "name": "Authentication & Role-Based Access Control",
                "category": "Access Control",
                "status": "active",
                "description": "All endpoints require Azure Entra ID JWT. Three roles (READER, EDITOR, ADMIN) at three scopes. AI agent endpoints require EDITOR or above. Same-tenant users auto-granted ADMIN. Token validated on every request.",
                "evidence": [
                    {"label": "JWT validation",          "detail": "Azure Entra ID RS256 token verified on every request — core/security.py get_current_user()"},
                    {"label": "RBAC on agent/scan endpoints","detail": "require_editor_anywhere() dependency on all write endpoints — core/authz.py"},
                    {"label": "Client-ID tenant isolation","detail": "All DB queries filter by client_id scoped to authenticated user — prevents cross-tenant data access"},
                    {"label": "Admin detection",         "detail": "NexGenAdmin JWT role OR same-tenant tid claim = admin — core/trial.py is_admin()"},
                ],
                "pending": [
                    "Time-based session revocation (currently relies solely on Azure token TTL)",
                ],
            },
            {
                "id": "provider_failover",
                "name": "AI Provider Resilience & Automatic Failover",
                "category": "Availability",
                "status": "active",
                "description": "get_llm() automatically tries all configured providers in priority order when the primary fails. Each failover is logged at WARNING. Fast-skip for unconfigured providers avoids network timeouts.",
                "evidence": [
                    {"label": "Fallback order",        "detail": "azure_openai → openai → google_gemini → aws_bedrock → anthropic → custom_openai — core/ai_providers.py _FALLBACK_ORDER"},
                    {"label": "Fast credential check", "detail": "_is_configured() skips providers with missing credentials — no network call, no timeout"},
                    {"label": "Warning log on failover","detail": "logger.warning() on every failover — visible in Azure Monitor / App Service Log Stream"},
                    {"label": "ProviderUnavailableError","detail": "Carries primary provider + full attempts list — callers receive HTTP 503 when all fail"},
                ],
                "pending": [
                    "Per-provider circuit breaker (skip a provider that failed 3+ times in 5 min)",
                    "Rate-limit cooldown between failover retries",
                ],
            },
            {
                "id": "prompt_audit_log",
                "name": "Prompt Audit Logging",
                "category": "Compliance",
                "status": audit_status,
                "description": "Every LLM call records metadata to prompt_audit_logs: user, endpoint, provider, character counts (not prompt text), token usage, latency, status. Full prompt text is never stored.",
                "evidence": [
                    {"label": "PromptAuditLog model",  "detail": "prompt_audit_logs table — api/models/models.py (user_id, endpoint, provider, input_chars, output_chars, tokens_used, latency_ms, status, block_reason)"},
                    {"label": "log_llm_call() helper", "detail": "Best-effort async helper — swallows all DB errors so audit never interrupts LLM responses — core/ai_providers.py"},
                    {"label": "Total audit entries",   "detail": f"{total_audit_logs} LLM calls logged across all endpoints"},
                ] + audit_covered,
                "pending": audit_pending,
            },
            {
                "id": "pii_scrubbing",
                "name": "PII / Sensitive Data Scrubbing",
                "category": "Data Privacy",
                "status": "pending",
                "description": "No automatic PII detection or redaction before sending data to external LLM providers. Customer asset names, IPs, resource identifiers, and finding descriptions are sent verbatim.",
                "evidence": [],
                "pending": [
                    "PII detection regex patterns (email, IPv4/IPv6, phone, SSN) on finding titles before LLM calls",
                    "Option to pin sensitive clients to Azure OpenAI only (data residency / sovereignty boundary)",
                    "EU data residency controls — ensure EU client data only routes to EU-region endpoints",
                    "PII masking tokens that get re-hydrated in the response",
                ],
            },
            {
                "id": "jailbreak_detection",
                "name": "Jailbreak & Adversarial Input Detection",
                "category": "Input Safety",
                "status": "pending",
                "description": "No runtime detection of jailbreak patterns or adversarial prompts beyond XML isolation markers.",
                "evidence": [],
                "pending": [
                    "Semantic jailbreak detection (Azure Content Safety, Lakera Guard, or Llama Guard)",
                    "Automated red-teaming with Garak or Microsoft PyRIT in CI/CD pipeline",
                    "Blocked-call alerting when jailbreak detection threshold is exceeded",
                    "Canary tokens in system prompts to detect exfiltration attempts",
                ],
            },
            {
                "id": "content_filtering",
                "name": "Output Content Filtering",
                "category": "Output Safety",
                "status": "pending",
                "description": "No harmful content detection or credential scanning in LLM responses before they are stored or returned.",
                "evidence": [],
                "pending": [
                    "High-entropy string detection to catch accidentally generated secrets/credentials in agent outputs",
                    "Azure Content Safety API integration for harmful content categories",
                    "PII regex scan on agent output before DB persistence",
                    "Per-finding hallucination confidence scoring",
                ],
            },
        ],
    }


@router.get("/audit-logs")
async def get_audit_logs(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
    limit: int = 100,
    offset: int = 0,
    endpoint: Optional[str] = None,
):
    """Return paginated prompt audit log entries for the admin UI."""
    from api.models.models import PromptAuditLog
    q = db.query(PromptAuditLog).order_by(PromptAuditLog.created_at.desc())
    if endpoint:
        q = q.filter(PromptAuditLog.endpoint == endpoint)
    total = q.count()
    rows = q.offset(offset).limit(limit).all()
    return {
        "total": total,
        "rows": [
            {
                "id": r.id,
                "user_id": r.user_id,
                "endpoint": r.endpoint,
                "provider": r.provider,
                "model": r.model,
                "input_chars": r.input_chars,
                "output_chars": r.output_chars,
                "tokens_used": r.tokens_used,
                "latency_ms": r.latency_ms,
                "status": r.status,
                "block_reason": r.block_reason,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }
