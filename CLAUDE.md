# NexGenCyberAI — Claude Code Context

AI-Powered Cybersecurity Posture Management Platform (branded **Aegis AI** — tagline "See your risk. Model your threats. Fix what matters." Repo/Azure resources/Entra scope keep the internal `NexGenCyberAI` name). Multi-tenant SaaS connecting to Azure, AWS, GCP, Entra ID, Okta and running AI security agents (Azure OpenAI / Claude / OpenAI / Gemini / Bedrock). Frontend uses a Google-vibrant dark theme (primary `#4285F4`, secondary `#34A853`, accent `#FBBC04`, danger `#EA4335`, surface `#1E1E1E`).

---

## Project Structure

```
/opt/NexGenCyberAI/
├── backend/                  FastAPI Python 3.12 API
│   ├── main.py               App entry, startup provisioning, router registration,
│   │                         on-disk column migrations (ai_verdict, report, etc.)
│   ├── requirements.txt
│   ├── data/                 Local caches — threat_intel_cache.json,
│   │                         nvd_cve_cache.json, sync_feed_stats.json (gitignored)
│   ├── api/
│   │   ├── models/models.py  SQLAlchemy ORM — all tables + enums.
│   │   │                     Notable: ConnectorType, ScannerCategory,
│   │   │                     CONNECTOR_CATEGORY dict, MissionType,
│   │   │                     ScheduledMission, ScheduledMissionRun (with `report` JSON),
│   │   │                     KnowledgeFile, AIAgent, Scan.ai_verdict (JSON),
│   │   │                     AISettings + EmailSettings (single-row config tables).
│   │   ├── schemas/schemas.py Pydantic request/response schemas
│   │   └── routers/          One file per resource:
│   │                          clients, scans, scans_overview, scans_runner,
│   │                          findings, risks, risk_portfolio, agents,
│   │                          agent_catalog, frameworks, missions, knowledge,
│   │                          threat_models, admin, ai_settings, email, technologies, …
│   ├── connectors/           Cloud + scanner connectors
│   │   ├── base.py           BaseConnector, ConnectorFinding, FindingSeverity
│   │   ├── factory.py        get_connector(type, creds, config) dispatcher
│   │   ├── sync.py           sync_connector_assets — refresh inventory pre-scan
│   │   ├── web/              ZAP (DAST). connector.py + auth.py + trigger_zap_scan
│   │   ├── scanners/         GitHub-Actions-driven scanners (WorkflowConnector)
│   │   │     ├── base.py     WorkflowConnector — shared base
│   │   │     ├── nmap.py, openvas.py, trivy.py
│   │   │     ├── semgrep.py, codeql.py, sonarqube.py
│   │   │     ├── owasp_dc.py, gitleaks.py, trufflehog.py
│   │   ├── azure/connector.py  Direct ARM scanning (NSG, Storage, Key Vault, RBAC, VMs)
│   │   ├── aws/, gcp/, entraid/, containers/, onprem/, …
│   ├── agents/               AI agent implementations (LangChain ReAct)
│   │   ├── base_agent.py     Provider-agnostic LLM wrapper
│   │   ├── orchestrator/     Runs all agents in sequence
│   │   ├── risk/             Risk scoring (NIST SP 800-30) — structured prompt
│   │   ├── framework/        NIST CSF / CIS v8 / GDPR mapping
│   │   ├── vascan/           Vulnerability analysis
│   │   ├── threat/           MITRE ATT&CK correlation
│   │   ├── remediation/      Playbook generation
│   │   └── compliance/       Audit report generation
│   ├── services/             Business logic that's not a router handler
│   │   ├── verdict.py        Per-scan structured AI verdict (the Assessments
│   │   │                     detail page model) + compute_rps()
│   │   ├── threat_intel.py   EPSS + CISA KEV cache (in-memory + on-disk)
│   │   ├── reachability.py   Wiz GraphQL / CrowdStrike Spotlight live lookups
│   │   ├── sync_feeds.py     Registry of on-demand external feeds — surfaces
│   │   │                     to /admin/sync/feeds endpoints + Sync page
│   │   ├── scan_runtime.py   Per-scan transient state (auth headers, target)
│   │   ├── scan_binaries.py  Local filesystem store for CodeQL --build-mode=none
│   │   │                     uploads (/home/data/uploads/<scan_id>/...). 30-day
│   │   │                     cleanup loop, scheduled in main.py.
│   │   ├── threat_modeler.py On-demand AI threat-model generator. Pulls scope
│   │   │                     (assets/findings/connectors), samples up to 25
│   │   │                     diversified CAPEC/ATT&CK library entries, calls
│   │   │                     the LLM with a methodology-specific prompt
│   │   │                     (STRIDE / PASTA / LINDDUN / MITRE ATT&CK / Kill Chain),
│   │   │                     enforces a fixed JSON output schema, persists to
│   │   │                     ThreatModel. Falls back to deterministic skeleton
│   │   │                     when no LLM is configured.
│   │   ├── mission_scheduler.py APScheduler in-process cron for workflows
│   │   ├── mission_executor.py Dispatches a ScheduledMission to its handler
│   │   ├── mission_reports.py  Standardised AI report (7 fixed sections) per run
│   │   ├── compliance.py     Per-framework recompute
│   │   ├── email_settings.py Single-row SMTP config (get_config_safe / update_config /
│   │   │                     get_resolved); password encrypted, never echoed back
│   │   ├── email_sender.py   smtplib sender (STARTTLS/SSL), multipart + attachments
│   │   └── …
│   └── core/
│       ├── config.py         Settings from env vars (pydantic-settings)
│       ├── ai_providers.py   Multi-provider LLM factory (get_llm())
│       ├── encryption.py     Fernet credential encryption
│       ├── scan_tokens.py    Per-scan HMAC mint/verify for workflow callbacks
│       ├── github_dispatch.py POST /actions/workflows/{file}/dispatches
│       ├── security.py       Entra ID JWT validation, get_current_user
│       └── authz.py          RBAC grants — admin/editor/reader × global/client/project
├── frontend/                 React 18 + TypeScript + MUI v6
│   └── src/
│       ├── pages/            Dashboard, RiskOverview, Clients, Scans (Assessments),
│       │                     ScanDetail, Findings, Risks (Risk Register),
│       │                     ThreatModels, ThreatModelDetail, Assets,
│       │                     Technologies, AssetDetail, Frameworks, Agents,
│       │                     Missions (Workflows), KnowledgeBase, Reports,
│       │                     AISettings, EmailSettings, Admin, Sync, Account, …
│       ├── services/api.ts   Axios client — all API calls, auto-attaches Entra ID JWT
│       ├── types/index.ts    TypeScript interfaces matching backend schemas
│       ├── auth/             MSAL Azure Entra ID authentication
│       └── components/
│           ├── layout/        AppLayout, NotificationBell
│           ├── RichOutput.tsx Markdown renderer for agent output (dark theme +
│           │                  conversational-tail stripping + risk_register table)
│           ├── AgentInsightCard.tsx Tile-style expandable agent run card
│           ├── DfdDiagram.tsx Lazy-loaded Mermaid renderer for threat-model DFDs
│           ├── ThreatLibraryChip.tsx Hover-to-fetch CAPEC/ATT&CK chip tooltip
│           ├── technologies/, risk-overview/  Tokens + presentational pieces
└── infrastructure/terraform/ Azure infrastructure as code
    ├── main.tf, variables.tf, outputs.tf
    └── terraform.tfvars      Secret values — NOT in Git
.github/workflows/            CI/CD + scanner runners
    deploy.yml                Single-env deploy to *-dev App Services on push to main
    zap-scan.yml, trivy-scan.yml, gitleaks-scan.yml, trufflehog-scan.yml,
    semgrep-scan.yml, nmap-scan.yml      Workflow-driven scanners
```

---

## Live Azure Environment

Single environment (cost-optimised — prod App Services are provisioned on demand per customer; no separate prod gate today).

| Resource | URL |
|---|---|
| Frontend (React SPA) | https://nexgencyberai-dev-okxksu-web.azurewebsites.net |
| Backend (FastAPI) | https://nexgencyberai-dev-okxksu-api.azurewebsites.net |
| API Docs | https://nexgencyberai-dev-okxksu-api.azurewebsites.net/api/docs |
| Health Check | https://nexgencyberai-dev-okxksu-api.azurewebsites.net/api/health |
| Resource Group | nexgencyberai-dev-rg |
| Frontend App | nexgencyberai-dev-okxksu-web (Node 22 LTS) |
| Backend App | nexgencyberai-dev-okxksu-api (Python 3.12) |

---

## Git & CI/CD

- **Repo**: github.com/gulatidh/NexGenCyberAI (private)
- **Branch**: single `main` — no `develop`. Push directly or via PR.
- **CI/CD**: `.github/workflows/deploy.yml` triggers on push to `main`.
  - Backend: `pip install -r requirements.txt` + deploy zip to Azure App Service via OIDC
  - Frontend: `npm ci` + `react-scripts build` (CI=true) + deploy zip
  - Terraform: plan only (apply is manual)
- **Scanner workflows** (zap-, trivy-, gitleaks-, trufflehog-, semgrep-, nmap-) are NOT auto-triggered — they fire on `workflow_dispatch` from the backend when a scan starts, authenticated via per-scan HMAC token.
- **Deploy rule**: Always `git push origin main` — CI/CD handles deployment automatically. Never deploy manually via Kudu unless Git is also updated immediately after.

---

## Database

- **Dev**: SQLite (`backend/nexgencyberai.db`) — file-based, no setup needed
- **Prod (Azure)**: **SQLite on persistent `/home`** — `DATABASE_URL=sqlite:////home/nexgencyberai.db` (survives restarts, shared across workers). The mssql/`pymssql` path still exists in code for an Azure SQL deployment but is **not** what dev-okxksu runs today — see "Prod DB is SQLite on App Service `/home`" in Known Issues for how to pull/inspect it.
- **ORM**: SQLAlchemy 2.0
- **Critical**: All `SAEnum` columns use `values_callable=_ev` (see `models.py`) so SQLAlchemy stores lowercase enum values. Never remove this or DB reads break with `KeyError`.
- **Startup migrations**: `main.py::_ensure_added_columns()` runs idempotent `ALTER TABLE ... ADD COLUMN` for new JSON columns (`ai_verdict`, `ai_verdict_generated_at`, `scheduled_mission_runs.report`). Safe on SQLite + MSSQL.
- **Other startup work**: `_normalize_enum_case()`, `_provision_entraid_connector()`, `_provision_azure_connector()`, agent + knowledge base seeding, threat-intel cache warm.

---

## Authentication & Authorization

- **Provider**: Microsoft Entra ID (Azure AD) via MSAL
- **Frontend**: `@azure/msal-react` — `MsalAuthenticationTemplate` wraps entire app, auto-redirects to Entra ID login
- **Backend**: JWT bearer token validation — every API endpoint requires `Depends(get_current_user)`
- **Token flow**: Frontend acquires token silently → attaches as `Authorization: Bearer <token>` → backend validates against JWKS URI
- **RBAC** (`core/authz.py`): three roles (`reader`/`editor`/`admin`) × three scopes (`global`/`client`/`project`). Admin-only pages (Sync, Administration) gated client-side via `useQuery(adminApi.me)`. `is_editor_anywhere(grants)` + the `require_editor_anywhere` FastAPI dependency (403 if not editor/admin anywhere) gate every **mutating** endpoint — threat-model POSTs, mission create/run, scan create/rescan/upload-binary, agent run, admin sync/refresh. `/admin/me` returns `is_editor_anywhere` for the frontend.
- **Executive vs Analyst view mode** (`frontend/src/theme/ViewModeContext.tsx`, toggle top-right in `AppLayout`): `mode: "executive" | "analyst"` (default analyst, persisted in `localStorage["ui-view-mode"]`). Executive = read-only (`canAct = false`) — action buttons (New Assessment, Run, Re-model, …) disable. **Wired to RBAC**: `AppLayout` calls `setReadOnly(!me.is_editor_anywhere)`, and `effectiveExecutive = mode === "executive" || readOnly`, so a reader-only user is *locked* into executive mode (the Analyst toggle disables) regardless of the localStorage preference. Components read `const { canAct } = useViewMode()` to gate UI.
- **Workflow runners** authenticate to `/scans/config/` and `/scans/ingest/` using a per-scan HMAC token minted by `core/scan_tokens.py` — NOT a user JWT.

---

## Frontend Pages & Navigation

`AppLayout.tsx` defines two nav groups:

**Main workflow**: Dashboard · Risk Overview · Clients · Assessments (Scans) · Findings · Risk Register (Risks) · Threat Models · Asset Inventory · Technologies · Frameworks · AI Buddies (the operational + advisory agents catalog) · Workflows (Missions) · Knowledge Base · Reports

**Settings** (some admin-only): AI Settings · Email Settings · Sync · Administration · Help

Routes live in `App.tsx`. Connectors and Projects no longer have top-level nav — they're tabs inside the Client Detail page.

### Key pages and what they do

- **Assessments** (`/scans`) — tile grid of every scan across all clients (access-filtered). Tiles collapse by version group: only the newest run per target renders, older versions live in the History dialog. Each tile has top-right icons (delete, replay/rescan, history badge with run count), status chip, category dot, "Category · Client" header. Click anywhere on the tile (not the icons) to drill into ScanDetail. When the user leaves the scan name blank, `scans.py` auto-names it `<scan_type>_<YYYYMMDD>_<HHMM>` (UTC) instead of a bare "full".
- **ScanDetail** (`/scans/:scanId`) — top tabs: Verdict / Findings / one per agent run. Verdict tab renders the structured AI verdict (The Verdict, What We Found, Why It Matters, Executive Summary, Capability Gaps, Signal Coverage, Attack Paths, Vendor Scorecard, RPS factor breakdown with evidenced/estimated/unknown tags, Data Completeness, Automation Opportunities). Per-finding delete in the Findings table. Print/PDF button at top expands every tab + applies the print stylesheet (see "Report PDF / print colours" below — keeps brand/severity colours on a white page).
- **Findings** (`/findings`) — section tabs + category tiles + sortable table. Per-row delete + "Delete blank findings" toolbar button.
- **Risk Register** (`/risks`) — KPI strip + severity donut + Top 5 + slicer chips + table + **AI Agent Risk Analysis** tile grid. Each agent run is a tile with heading/status/summary; click to expand; only one open at a time.
- **Threat Models** (`/threat-models`) — On-demand AI threat modelling. List page tile grid (one tile per model, collapsed by version chain) + **two entry points**: (a) Create dialog with methodology picker; (b) **Upload Diagram** dialog accepting `.drawio` / `.xml` / `.pdf` / `.jpg` / `.png` — components and data flows are extracted (drawio = deterministic XML parse; pdf = text + LLM; image = vision LLM), the user reviews on the detail page, then clicks *Start AI threat modelling*. Detail page has 4 tabs: Diagram / Components / Threats (with hoverable CAPEC + ATT&CK chips citing real library IDs) / Mitigations. **Diagram tab** has a Mermaid ↔ draw.io toggle plus a *Download .drawio* button — the draw.io view embeds diagrams.net in an iframe and loads server-rendered mxGraph XML (`services/drawio_renderer.py` lays components into swimlanes by trust_zone). Threats tab has per-row "Add to Risk Register" and bulk "Convert N to Risk Register" buttons — dedupe via `risks.source_threat_model_id` + `source_threat_id`. Diagram-derived models live in `status="extracted_review"` with a purple banner until the user starts modelling; the threat_modeler then treats those components as authoritative (LLM emits threats keyed to the user-reviewed IDs, never inventing new ones). Print/PDF expands all four tabs into one paginated document (`beforeprint`/`afterprint`; SVG colors preserved). Polls every 4s during `generating`.
- **Risk Overview** (`/risk-overview`) — Risk Portfolio dashboard. FAIR-lite ALE: Total/Net Exposure, Open Critical/High, 30-Day Breach Probability. Risk-by-domain bar chart, full risk table with ALE range, Remediation status, Source link.
- **Workflows** (`/missions`) — scheduled missions (cron picker + presets). History drawer per row; "View Report" opens the standardised PDF-ready report dialog (KPI strip + 7 fixed sections).
- **Knowledge Base** (`/knowledge`) — two tabs. **Knowledge Files**: pre-seeded files in categories, expandable cards, search, stats endpoint. **Threat Intelligence** (`ThreatIntelBrowser`): browse synced feed data — source picker (ATT&CK / CAPEC / KEV / NVD recent / EPSS) with per-source filters (search, category facets, CWE, min CVSS, min EPSS, ransomware-only) and a dynamic table. Each row is clickable → opens the authoritative external reference (`r.ref`, built by `sync_feeds._ref_url`: ATT&CK→attack.mitre.org, CAPEC→capec.mitre.org, CVE→nvd.nist.gov). Backed by `GET /admin/sync/feeds/{feed_id}/entries` (params `limit,q,category,cwe,min_cvss,min_score,ransomware`) via `api.syncFeedEntries`.
- **AI Buddies** (`/agents`, formerly "AI Agents") — Catalog of operational + ~43 advisory buddies in 7 groups. Admin-only CRUD with current config shown. When a Client + Scan are selected on this page, catalog agents consume the scan findings as context, persist their output as an `AgentRun` tied to the scan (`agent_type=ORCHESTRATOR`, real identity in `input_data.agent_key`/`agent_name`), and appear as tabs on the ScanDetail page. Phase 7C personality (signature line / avatar / accent colour, from `_BUDDY_PERSONALITY` in `services/agent_seed.py`) renders on each tile. **Personality + trigger keys must match the real catalog keys** (`appsec_advisor`, `vuln_commander`, `soc_strategist`, `partner_advisor`, `iam_posture_advisor`, …) — earlier they pointed at non-existent slugs and silently did nothing. Phase 7B proactive triggers (`services/buddy_triggers.py::fire_event`) are gated by `PROACTIVE_BUDDIES_ENABLED` (default OFF — see Known Issues).
- **Stale Assets** (`/stale-assets`) — assets not seen in the latest connector sync (`AssetStatus.STALE`/`DELETED`). Kept for audit but **excluded from all analysis** — Asset Inventory defaults to `status=active`, and threat-model scope, technology inventory, project counts, and framework control evidence all filter to `Asset.status == ACTIVE` (single-asset threat-model scope is the one exception). The assets list endpoint accepts `status=active` (default) `| stale | deleted | archived` (stale+deleted, used by this page) `| all`. Stale assets auto-reactivate when a future sync sees them again.
- **Sync** (`/sync`, admin-only) — manual on-demand sync of external feeds (EPSS, CISA KEV, NVD recent CVEs, framework recompute). Per-tile sync button + "Sync all".
- **Reports** (`/reports`) — five report types (Executive / Compliance / Findings / Risk Register / Asset Inventory) over existing data. Per report: **Export CSV**, **Email Report** (dialog with To/Cc + pre-filled subject + editable body + "attach report as HTML" — POSTs to `/email/send/`, editor-gated), and **Print / PDF** (`window.print()`).
- **Email Settings** (`/email-settings`) — admin configures outbound SMTP. Provider preset (**Office 365** → `smtp.office365.com:587` STARTTLS / Gmail / Custom SMTP), host/port/security/username/password/from, an enable toggle, and a **Send test email** box. Password is write-only (shows "configured", never echoed). Non-admins see read-only. See "Outbound Email" below.

---

## Adding a New Page (Frontend Pattern)

Follow `frontend/src/pages/Findings.tsx` as the template:
1. Create `frontend/src/pages/NewPage.tsx`
2. Add API function to `frontend/src/services/api.ts`
3. Add TypeScript interface to `frontend/src/types/index.ts`
4. Register route in `frontend/src/App.tsx`
5. Add nav item in `frontend/src/components/layout/AppLayout.tsx`

**ESLint rule**: CI runs with `CI=true` which promotes unused import warnings to errors. Always remove unused imports before committing.

**Icon names**: MUI v6 exports the `*Outlined` form (`DeleteOutlined`, `CheckCircleOutlined`, `ErrorOutlined`) — NOT `*Outline`. The `replace_all` Edit option will chain through related strings — avoid `replace_all "Outline" → "Outlined"` because it'll then re-edit the same names. Targeted import-line edits only.

---

## Adding a New API Endpoint (Backend Pattern)

Follow `backend/api/routers/findings.py` as the template:
1. Create `backend/api/routers/newresource.py` with `APIRouter(prefix="/clients/{client_id}/newresource")`
2. Add Pydantic schemas to `backend/api/schemas/schemas.py`
3. Add SQLAlchemy model to `backend/api/models/models.py` if new table needed
4. Register router in `backend/main.py`: `app.include_router(newresource.router, prefix="/api/v1")`
5. Trailing slash matters — FastAPI runs with `redirect_slashes=False`

---

## Adding a New Connector

### Direct (in-process) connectors (Azure, AWS, GCP, Entra ID, …)

Follow `backend/connectors/azure/connector.py`:
1. Create `backend/connectors/newcloud/connector.py` extending `BaseConnector`
2. Implement `test_connection`, `get_resources`, `run_configuration_review`, `run_vulnerability_scan`, `get_compliance_status`
3. Return `ConnectorFinding` objects
4. Register in `backend/connectors/factory.py`
5. Add `ConnectorType.NEWCLOUD` enum + `CONNECTOR_CATEGORY` entry in `models.py`

### Workflow-driven scanners (Nmap, Trivy, Gitleaks, Semgrep, CodeQL, …)

These defer execution to GitHub Actions. Backend just stores config + mints the HMAC scan token + fires `workflow_dispatch`.

1. Create `backend/connectors/scanners/newscanner.py` extending `WorkflowConnector` — set `WORKFLOW_FILE`, `REQUIRED_CONFIG`, `RESOURCE_TYPE`, `DEFAULT_DISPLAY_NAME`
2. Create `.github/workflows/newscanner-scan.yml` with inputs `scan_id`, `scan_token`, `api_base`. Fetch config via `GET /api/v1/scans/config/`, run the scanner, POST findings to `POST /api/v1/scans/ingest/`
3. `scans.py` already has a generic `WorkflowConnector` dispatch path — any new scanner inherits it automatically
4. The `_get(key)` helper on `WorkflowConnector` reads from both `config` and `credentials` because the Connectors UI saves everything under `credentials`

### CodeQL binary-upload mode (special-case workflow scanner)

CodeQL also accepts a compiled artifact instead of a source repo:
- Frontend toggle in the New Assessment dialog (Source repo / Upload binary)
- Binary path: `POST /clients/{cid}/scans/` with `defer_dispatch=true` → multipart `POST /clients/{cid}/scans/{sid}/upload-binary` (500 MB cap)
- Backend stores under `/home/data/uploads/<scan_id>/<filename>` + `.meta.json` sidecar (size, sha256). `services/scan_binaries.py` owns the layout + the 30-day cleanup loop scheduled in `main.py`.
- Workflow fetches via `GET /scans/binary/<id>?scan_token=...` (HMAC-gated), extracts by archive type, autodetects Java vs C#, runs `codeql database create --build-mode=none`
- `/scans/config/` surfaces `binary_filename` / `binary_size` / `binary_sha256` so the workflow YAML can branch on `mode == 'binary'`
- Generic dispatch in `scans.py` allows the connector's `repo_url` to be empty when `scan.summary.binary` is set

---

## AI Agents

- All agents extend `BaseAgent` in `backend/agents/base_agent.py`
- Uses LangChain ReAct (`create_react_agent`) with provider-agnostic `get_llm()`
- **Fallback**: If no AI API key is configured, returns rule-based analysis only — every consumer should expect both shapes
- **Lazy imports**: `AgentOrchestrator` is imported lazily inside `_get_orchestrator()` in routers — never import at module level (crashes workers at startup)
- Supported providers: `azure_openai`, `openai`, `anthropic`, `google_gemini`, `aws_bedrock`
- Configure via the AI Settings page or `DEFAULT_AI_PROVIDER` env var
- **Conversational tails**: System prompts ask for executive tone and no closing offers; `RichOutput.tsx` also scrubs them on render (`"If you want, I can also..."`, `"Would you like me to..."`, `"Shall I..."`)

### Standardised workflow reports (`services/mission_reports.py`)

Every `ScheduledMissionRun` (scheduled or manual) auto-generates a JSON report with a **fixed 7-section schema** (Executive Summary, Scope & Inputs, Key Findings, Risk Picture, Recommendations, Next Steps, Data Completeness). `_normalise_sections()` enforces this even if the LLM hallucinates extra sections or skips one. A deterministic skeleton renders when no LLM is configured.

### Per-scan AI verdict (`services/verdict.py`)

Auto-generated on scan completion via the `BackgroundTasks` queue in `/scans/ingest/`. Falls back to deterministic text if no LLM is available. Persisted to `Scan.ai_verdict` (JSON column) and rendered by ScanDetail.

### Phase 5 — agent quality loop (`services/agent_critique.py`, `services/learning_memory.py`, `services/blackboard.py`)

Three opt-in capabilities that improve agent output without changing any individual agent's prompt:

1. **Self-critique** (`self_critique_enabled`, default OFF — doubles per-agent LLM cost). After an agent emits its output, a second LLM call audits it against a rubric (severity calls, evidence grounding, vagueness, contradiction) and either confirms or returns a revised version. Original + revised + critique notes are stored in `AgentRun.output_data` so the UI can show "self-reviewed".

2. **Semantic learning + retrieval** (`semantic_learning_enabled`, default OFF — adds embedding cost per atom). Every completed `AgentRun` and `ScheduledMissionRun` is post-processed by an LLM that extracts 3-7 atomic learnings (categories: pattern / correction / recommendation / pitfall). Each is embedded with `text-embedding-3-small` (1536-d) via `core.ai_providers.get_embeddings()` and stored in `mission_learnings` with `embedding_json` as a JSON list of floats (works on SQLite + Azure SQL without pgvector — cosine computed in Python; fine to ~10k rows). Before each agent runs, `find_relevant(query, agent_key, domain, ...)` retrieves the top-5 cosine-similar atoms (90-day recency window) and prepends them as a "## Prior learnings" block to the prompt.

3. **Scan blackboard** (`blackboard_enabled`, default ON — negligible cost). When multiple agents run on the same `Scan`, each writes a one-paragraph synopsis to `scan_blackboard` after completion; subsequent agents read recent peer synopses as "## Other agents on this scan" context. Cross-pollination without forcing the orchestrator to centrally aggregate.

All three are surfaced on the **AI Settings** page with a stats strip (learnings stored / embedded / blackboard entries / self-critique runs in 30d) and toggles. Stats endpoint: `GET /ai/learning-stats/`. Embedding provider/model are configurable from the same page.

---

## Threat Modelling

On-demand threat models scoped to a client (and optionally a project / asset). Five methodologies supported in one engine:

| Methodology | Categories used for `threats[].category` |
|---|---|
| STRIDE | spoofing · tampering · repudiation · information_disclosure · denial_of_service · elevation_of_privilege |
| PASTA | technical_attack · business_impact · application_threat · attack_vector · countermeasure |
| LINDDUN | linking · identifying · non_repudiation · detecting · data_disclosure · unawareness · non_compliance |
| MITRE ATT&CK | initial_access · execution · persistence · privilege_escalation · defense_evasion · credential_access · discovery · lateral_movement · collection · exfiltration · impact |
| Lockheed Kill Chain | reconnaissance · weaponization · delivery · exploitation · installation · command_and_control · actions_on_objectives |

**Generation flow** (`services/threat_modeler.py::generate_threat_model`) — a **visible, asset-first multi-step pipeline**. Threat modelling is **architecture-driven, not findings-driven**: components come from the asset inventory, threats from the structure (methodology + CAPEC/ATT&CK library); findings/risks are corroborating evidence, not a prerequisite. Each step writes `ThreatModel.progress_json` and commits, so the 4s detail poll renders a live checklist (`{"current","pct","steps":[{key,label,status,detail}]}`; statuses `pending|active|done|skipped|error`):
1. **Discover assets** (`_ensure_assets`) — if the scope has no assets but the client has connectors, sync them **one connector at a time** via `connectors.sync.sync_connector_assets` (best-effort, each surfaced as progress); else `skipped` → model from architecture. Diagram-upload models skip this (their components are authoritative).
2. **Gather context** (`_collect_scope`) — assets + recent findings + **Risk Register (top 25 by score)** + connector topology. Risk rows feed a `## Risk assessment` block in the prompt so threats align with tracked risk.
3. **Load threat library** (`_library_sample`) — up to 25 diversified `ThreatLibrary` entries (≤4 per category), preferring ATT&CK for `mitre_attack` and CAPEC otherwise (falls back to ATT&CK when CAPEC isn't synced).
4. **Run analysis** — `_build_system_prompt()` + `_build_user_prompt()` inject methodology guidance + a "cite from THIS list only" library block; `_invoke_llm` is bounded by `asyncio.wait_for(LLM_TIMEOUT_SECONDS=180)`. `_normalise()` enforces the fixed schema (`executive_summary`, `components`, `data_flows`, `threats`, `mitigations`, `dfd_mermaid`, `trust_boundaries`, `entry_points`, `coverage_decisions`).
5. **Finalize** — persist output + maturity scores; `status="completed"`, `pct=100`.

`progress_json` is a JSON column (idempotent ALTER TABLE in `main.py::_ensure_added_columns`), surfaced on `ThreatModelSummary`/`_summary_from` as `progress`. `_set_step()` uses `flag_modified` so in-place dict mutations are tracked. Orphaned `generating` rows (worker died mid-run) are self-healed by `main.py::_fail_stale_threat_models()` on startup (>20 min → `failed`).

**Scope**: a model is scoped to `client` (default), `project`, `asset`, or **`scans`**. When `scope_type='scans'`, `scope_scan_ids` (JSON column) holds the chosen scan IDs — `_collect_scope` pulls findings from exactly those scans and narrows assets to the connectors those scans ran against, so one model = one environment (avoids messy client-wide aggregates). The create dialog has a multi-scan picker. Stale/deleted assets are excluded from all scopes (except an explicit single-asset scope). DFD: `_build_mermaid` prepends service-type icons to nodes; `DfdDiagram.tsx` colours trust-zone subgraphs at render (Internet=red/DMZ=amber/Private=green/data=purple/mgmt=blue). Coverage matrix supports selective gap-fill (pick cells → "Fill selected") and clicking a threat cell opens the threat.

**Versioning**: `parent_threat_model_id` mirrors the `Scan.parent_scan_id` flat-sibling chain — first ancestor with `parent_threat_model_id IS NULL` is the root. Rescan creates a new row linked to the root; list endpoint collapses to newest sibling per root.

**Library tooltip**: Frontend `ThreatLibraryChip.tsx` lazy-fetches `GET /threat-models/library/{source}/{source_id}` on hover and shows `source_id · name · category · description · CWEs`. Returns 404 with a "run Sync" hint when the entry isn't cached yet.

**Endpoints**:
- `GET /threat-models/methodologies` — public catalog for the create-dialog picker (returns labels + descriptions + default)
- `GET /threat-models/library/{source}/{source_id}` — chip tooltip lookup
- `POST /clients/{cid}/threat-models/` — create + kick off background generation
- `GET /clients/{cid}/threat-models/` — list, collapsed by version chain
- `GET /clients/{cid}/threat-models/{id}` — full detail (poll for status)
- `GET /clients/{cid}/threat-models/{id}/versions` — every sibling in the chain
- `POST /clients/{cid}/threat-models/{id}/rescan` — new version with same scope + methodology
- `POST /clients/{cid}/threat-models/{id}/threats/{tid}/convert-to-risk` — create one Risk from a single threat (idempotent: returns existing risk_id if already converted)
- `POST /clients/{cid}/threat-models/{id}/convert-all-to-risks` — bulk-create risks for every unconverted threat. Returns `{created, skipped, risk_ids}`
- `GET /clients/{cid}/threat-models/{id}/drawio` — render the DFD as mxGraph XML for the embedded diagrams.net viewer. `?download=1` returns the file as a `.drawio` attachment
- `POST /clients/{cid}/threat-models/from-diagram` — multipart upload (`.drawio`/`.xml`/`.pdf`/`.jpg`/`.png`); extracts components + data_flows via `services/diagram_extractor.py` and persists a `ThreatModel` row in `status="extracted_review"`
- `POST /clients/{cid}/threat-models/{id}/start-modeling` — after the user reviews/edits the extracted DFD, kicks off the existing threat-modeler pipeline with those components treated as authoritative architecture
- `POST /clients/{cid}/threat-models/{id}/remodel` — (editor-gated) regenerate as a new version with a **user-curated component set** + analyst notes pinned. Body `{components, data_flows, analyst_notes}`
- `DELETE /clients/{cid}/threat-models/{id}` — delete one row

**Component curation + analyst notes** — users can correct the auto-derived architecture (components the modeler shouldn't include, or missing ones) and add free-text guidance:
- **Create dialog** (`ThreatModels.tsx`) has an "Analyst notes" textarea; create can also pass a curated `components` list.
- **Detail page** (`ThreatModelDetail.tsx`) Components tab renders a `ComponentsEditor` (add/remove components with type/zone/criticality, analyst-notes box, "Re-model with these" → `remodel`) when `!printing && canAct && status !== "extracted_review"`.
- `ThreatModel` gained `analyst_notes` (Text) + `components_pinned` (Boolean) columns (idempotent ALTER in `main.py`). When `components_pinned` is set (or scope is a diagram), `threat_modeler.generate_threat_model` treats the stored components as **authoritative** — it skips asset-derivation and the LLM emits threats keyed only to those component ids. `analyst_notes` is injected into the prompt as a "## Analyst guidance (AUTHORITATIVE)" block. Rescan/remodel carry `analyst_notes` + `components_pinned` + the pinned `components_json` forward.

---

## Rescan + version history

Every Assessment tile has a Replay icon (`POST /clients/{cid}/scans/{sid}/rescan`). Rescan creates a fresh `Scan` row reusing the original's connector / scan_type / framework / name, then dispatches as a normal scan. The new row sets `parent_scan_id` to the **root** of the chain (first ancestor whose `parent_scan_id` is NULL) so siblings stay flat — not a deep parent → parent chain.

- Tile grid shows only the newest sibling per `(parent_scan_id ?? id)` group.
- `GET /clients/{cid}/scans/{sid}/versions` returns every sibling sharing the same root, newest-first — powers the History dialog.
- `/scans/all` exposes `parent_scan_id` on each tile so the frontend groups without an extra round-trip.
- Schema: `scans.parent_scan_id VARCHAR(36) NULL` — idempotent ALTER TABLE in `main.py::_ensure_added_columns()`.

---

## Risk Priority Score (RPS)

`services/verdict.py::compute_rps()` returns multi-factor scoring per finding:

```
RPS = CVSS × EPSS × KEV_multiplier × reachability × exploitability
      × asset_criticality × business_context
```

Every factor has a `source` tag — `evidenced` / `estimated` / `unknown`. Unknown factors are **dropped** from the multiplication so missing data integrations don't penalise scores.

| Factor | Evidenced source | Estimated fallback |
|---|---|---|
| CVSS | scanner / NVD | severity-mapped |
| EPSS | `services/threat_intel.py` cache (FIRST.org) | severity-mapped |
| KEV multiplier | `services/threat_intel.py` cache (CISA KEV) — 2× normal, 3× ransomware | 1.0 |
| Reachability | `services/reachability.py` — Wiz GraphQL or CrowdStrike Spotlight when configured | 1.0 (unknown) |
| Exploitability | CVSS bucket proxy | — |
| Asset criticality | crown-jewel ontology (not wired) | 5.0 |
| Business context | mission inputs (not wired) | 1.0 |

When the threat-intel cache is empty (never synced), EPSS/KEV report `unknown` rather than falsely claiming `evidenced not-found`.

---

## External Feeds (Sync page)

Auto-scheduled in the background via APScheduler (the same scheduler the missions service uses — `services/mission_scheduler.get_scheduler()`), with a manual "Sync" button on each tile for immediate refresh. Cadences are defined in `sync_feeds.SCHEDULES`:

| Feed | Cadence |
|---|---|
| EPSS | Daily 03:15 UTC |
| KEV | Daily 03:30 UTC |
| NVD recent | Every 6 hours (NVD 2.0 REST API) |
| MITRE ATT&CK | Weekly Sun 04:00 UTC |
| MITRE CAPEC | Weekly Sun 04:15 UTC |
| Frameworks recompute | Not scheduled — manual only (DB recompute, not an external feed) |

Each scheduled run records `last_scheduled_at` / `last_scheduled_ok` / `last_scheduled_error` in `sync_feed_stats.json` so admins can see whether the background fetcher is healthy. The Sync UI shows `next_run_at` per tile.

Feed registry lives in `backend/services/sync_feeds.py`; admin endpoints under `/admin/sync/feeds/...`.

| Feed | Source | What it does |
|---|---|---|
| EPSS | https://epss.cyentia.com/epss_scores-current.csv.gz | Per-CVE exploit probability |
| CISA KEV | https://www.cisa.gov/.../known_exploited_vulnerabilities.json | CVEs confirmed exploited in the wild |
| NVD Recent | https://services.nvd.nist.gov/rest/json/cves/2.0 (NVD **2.0 REST API**, paginated `lastModStartDate`/`lastModEndDate`) | 8-day rolling window — CVSS v3, CWE list, descriptions for finding enrichment. Uses the platform `NVD_API_KEY` (delay 0.7s keyed / 6.5s keyless). The old 1.1 `.json.gz` feed was retired by NIST — do not reinstate it |
| MITRE ATT&CK | https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json | ~600 Enterprise techniques, written into `threat_library` (source=`attack`). Cited by the Threat Modeler when methodology is `mitre_attack` (and as a fallback for others) |
| MITRE CAPEC | https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json | ~550 attack patterns, mapped to STRIDE buckets via `x_capec_consequences` heuristic. Cited by the Threat Modeler for STRIDE / PASTA / LINDDUN / Kill Chain methodologies |
| Frameworks | bundled (no network) | Recompute compliance for every client using bundled catalogs |

Caches persist to a **durable, worker-shared dir** resolved by `core.paths.data_dir()` — `$SYNC_DATA_DIR`, else `/home/data` on Azure (persistent + shared across gunicorn workers), else `backend/data` (dev):
- `threat_intel_cache.json` — EPSS + KEV combined
- `nvd_cve_cache.json`
- `sync_feed_stats.json` — per-feed last-sync timestamps for non-threat-intel feeds

`threat_intel.py` re-reads the cache when the file's mtime changes, so a sync run by one worker is picked up by the others (and by `verdict.py`'s RPS EPSS/KEV factors). **Why this matters**: the caches used to live in the ephemeral, per-worker `backend/data/` (wwwroot) — after a sync, a reload hitting a different worker showed "never synced / 0 entries", and `verdict.py` often saw empty EPSS/KEV. ATT&CK/CAPEC never had this bug (they're in the `threat_library` DB table on `/home`). `main.py` warms the cache from disk at startup; admins can force a sync via the Sync page.

---

## Outbound Email (SMTP / Office 365)

On-demand email sending — no email infra existed before (the `ScheduledMission.send_summary_email` flag is still unwired). All config is **DB-stored, not env vars**.

- **Model**: `EmailSettings` (single-row table, like `AISettings`). SMTP password stored encrypted via `core.encryption.encrypt`; auto-created at startup by `Base.metadata.create_all` (brand-new table — no ALTER needed).
- **Service**: `services/email_settings.py` — `get_config_safe` (UI; password masked to a `smtp_password_configured` bool), `update_config` (upsert; send `""` to clear the password, omit to keep), `get_resolved` (full config + decrypted password for sending), `PROVIDER_PRESETS` (`office365` / `gmail` / `smtp`).
- **Sender**: `services/email_sender.py` — `smtplib` (STARTTLS 587 / SSL 465 / none), multipart text+HTML, optional base64 attachments. Raises `EmailError` with actionable messages (e.g. O365 SMTP-AUTH / app-password guidance).
- **Router** `api/routers/email.py` (registered `prefix="/api/v1"` → `/api/v1/email/...`):
  - `GET /email/config/` — current config (password never echoed) + presets
  - `PATCH /email/config/` — **admin-only** (`require_role(ADMIN)`) upsert
  - `POST /email/test/` — **admin-only** test send
  - `POST /email/send/` — **editor-gated** (`require_editor_anywhere`); analysts send a report email (to/cc/subject/body_html/body_text + attachments)
- **Frontend**: `pages/EmailSettings.tsx` (route `/email-settings`, nav under Settings) + `emailApi` in `api.ts`. The **Reports page "Email Report" dialog** builds a self-contained HTML snapshot of the rendered report (`printRef.innerHTML` wrapped in a light stylesheet, base64) as the attachment.
- **Operational caveat**: Office 365 over SMTP requires **SMTP AUTH enabled** on the mailbox and an **app password** if MFA is on. Microsoft is deprecating Basic Auth/SMTP AUTH — if it's disabled tenant-wide, switch to a Microsoft Graph `sendMail` transport (not built today; the sender is structured to add one).

---

## Report PDF / print colours

"Download to PDF" everywhere is the **browser's native `window.print()`** ("Save as PDF") — there is no jsPDF/html2canvas. Output is controlled by `@media print` CSS blocks per page (`Reports`, `ScanDetail`, `Missions`, and the `ThreatModelDetail` fallback). The portal is dark-themed, so print forces a **white, paper-friendly page** but now **keeps brand/severity colours**:
- Each block sets `print-color-adjust: exact` so the browser stops dropping coloured backgrounds.
- Surfaces (Card/Paper/Table) → white; body text (`.MuiTypography-root` / `.MuiTableCell-root`) → dark `#1a1a1a` for legibility.
- **Chips, charts, progress bars keep their colours** automatically — they aren't targeted by the dark-text rule (a child's inline `sx` colour beats an ancestor's inherited `!important`). Coloured KPI numbers are tagged `className="keep-color"` and excluded via `:not(.keep-color)`.
- The threat-model **server-rendered deliverable** (`services/threat_model_pdf.py`, opened by ThreatModelDetail's Download PDF) is a separate purpose-built document — not governed by these blocks.

---

## Key Environment Variables (backend)

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLite (dev) or mssql+pymssql://... (prod) |
| `AZURE_TENANT_ID` | Entra ID tenant for JWT validation |
| `AZURE_CLIENT_ID` | Backend app registration client ID |
| `DEFAULT_AI_PROVIDER` | `azure_openai` \| `openai` \| `anthropic` \| `google_gemini` \| `aws_bedrock` |
| `PROACTIVE_BUDDIES_ENABLED` | Phase 7B proactive buddy auto-runs on scan ingest. **Default `false`** — firing real buddy LLM runs inline during ingest OOM-kills small App Service workers and loses findings. Only flip on once runs are moved off the web worker / the plan has headroom |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `AZURE_OPENAI_API_KEY` | Provider keys |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL |
| `ENCRYPTION_KEY` | Fernet key for connector credential encryption |
| `ENTRAID_CONNECTOR_TENANT_ID` / `_CLIENT_ID` / `_CLIENT_SECRET` / `_DB_CLIENT_ID` | Auto-provision Entra ID connector |
| `AZURE_SUBSCRIPTION_ID` | Auto-provision Azure ARM connector |
| `PUBLIC_API_BASE` | Public URL the workflow runners call back to (for `/scans/config/` + `/scans/ingest/`) |
| `GITHUB_DISPATCH_TOKEN` | PAT or App token with `actions:write` on the repo |
| `GITHUB_REPO_OWNER` / `GITHUB_REPO_NAME` / `GITHUB_WORKFLOW_REF` | Where to fire workflow_dispatch (default ref: `main`) |
| `NVD_API_KEY` | Platform-wide NVD API key. **KV-backed in prod** (`@Microsoft.KeyVault(VaultName=ngcai-dev-okxksu;SecretName=NvdApiKey)` — Terraform `azurerm_key_vault_secret.nvd_api_key` with `ignore_changes=[value]`; secret set out-of-band via `az keyvault secret set`). Used by the NVD-recent feed sync AND surfaced to OWASP Dependency-Check via `/scans/config/` when the connector has no own `nvd_api_key`. Without it, DC's NVD download throttles to hours — see Known Issues |
| `WIZ_API_TOKEN` / `WIZ_TENANT_URL` | (Optional) enable Wiz reachability — GraphQL endpoint |
| `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` / `FALCON_BASE_URL` | (Optional) enable CrowdStrike Spotlight reachability |
| `INITIAL_ADMIN_UPN` | UPN that the bootstrap will always grant global admin (per-UPN check, not "any admin exists"). Use this to recover when grants get wiped. |
| `SCAN_BINARIES_DIR` | (Optional) override CodeQL binary upload path. Default `/home/data/uploads`. |

---

## Infrastructure (Terraform)

- **State**: Local (`terraform.tfstate`) — not remote backend yet
- **tfvars**: `/opt/NexGenCyberAI/infrastructure/terraform/terraform.tfvars` — **NOT in Git**, store securely
- **Node version**: `22-lts`
- **Python version**: `3.12`
- **To apply**: `cd infrastructure/terraform && terraform apply`
- **Drift warning**: Direct Azure CLI / Portal config changes must be reflected in `main.tf` to avoid being reverted on next `terraform apply`

---

## Known Issues / Historical Fixes

- **SAEnum KeyError** — Always use `values_callable=_ev` on every `SAEnum()`; without it SQLAlchemy uses uppercase member names but the DB stores lowercase
- **Agent import crash** — Never import `AgentOrchestrator` at module level; LangGraph chain crashes uvicorn workers at startup. Use the lazy `_get_orchestrator()` pattern
- **Trailing slash 404** — FastAPI has `redirect_slashes=False`; all POST endpoints and frontend API calls must include trailing slash
- **CI ESLint failures** — `CI=true` makes unused imports hard errors. Always clean imports before committing
- **MUI v6 icon names** — Use `DeleteOutlined`, `CheckCircleOutlined`, `ErrorOutlined` (with the `d`). The `Outline` variants don't exist
- **`replace_all` chaining** — When renaming a token where the new name is a superset of the old one (e.g. `Outline` → `Outlined`), `replace_all` will re-apply on the same line in a follow-up call. Use targeted edits on the import line only
- **Workflow scanner dispatch** — Used to be ZAP-only. Now `scans.py` has a generic `WorkflowConnector` branch that any scanner with `WORKFLOW_FILE` set inherits. Bad config (missing `target` / `repo_url` / `image`) marks the scan `FAILED` with a clear message instead of completing silently with 0 findings
- **Private repo cloning** — Workflow YAMLs construct an authenticated clone URL by injecting `git_username:git_token` into the `https://` URL. The `_get(key)` helper on `WorkflowConnector` reads from both `config` and `credentials` because the UI saves everything under `credentials`
- **MissionRunResponse datetime fields** — Use `Optional[datetime]`, not `Optional[str]`, so Pydantic v2 auto-serialises. Wrong type caused 500s on `/missions/{id}/run`
- **Connector PATCH 404 after "Add"** — The Add button must reset `editing` state + form fields, otherwise the save fires PATCH against a stale ID
- **Conversational AI output** — Filter conversational tails server-side via prompt engineering AND client-side in `RichOutput.tsx`. Belt-and-braces — the LLM ignores prompt instructions occasionally
- **MSAL redirect loop** — `services/api.ts` only calls `acquireTokenRedirect` on `InteractionRequiredAuthError`. Other silent-token failures log + let the request 401 instead of looping. `_redirectInFlight` flag prevents concurrent redirects causing `interaction_in_progress` errors
- **Tz-mixing crash on `/scans/all`** — Some DB rows have naive `started_at` (SQLite default), others tz-aware (MSSQL). Always coerce to UTC via the `_aware()` helper before subtracting from `datetime.now(timezone.utc)`. The bug 500'd the endpoint and made every tile disappear
- **GITHUB_WORKFLOW_REF on App Service** — Must point at an existing branch (we're on `main`). Stale value (`develop` after that branch was deleted) caused `workflow_dispatch` to fail with HTTP 422 and made Nmap/CodeQL scans fail in ~1 second with no GitHub Actions run
- **`INITIAL_ADMIN_UPN` bootstrap** — `main.py::_bootstrap_initial_admin()` checks per-UPN, not "any global admin exists". If you wipe the user_access table or a different admin grant lingers, the configured UPN still gets re-granted on startup
- **CodeQL pack:suite syntax** — CLI rejects `codeql/javascript-security-and-quality.qls`. Must be `<pack-name>:<path-in-pack>` e.g. `codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls`
- **Binary uploads (`scan_binaries.py`)** — Created scan has `defer_dispatch=true` so the workflow only fires AFTER the multipart upload completes. Otherwise the runner would 404 on `/scans/binary/<id>` because the binary isn't on disk yet
- **Proactive buddies OOM → "no findings"** — Phase 7B `buddy_triggers.fire_event` (fired from `/scans/ingest/`) ran real buddy LLM runs inline in the web worker. On the B1 plan (1.75 GB, `uvicorn --workers 4`) that OOM-killed the worker mid-ingest, the scanner's POST got HTTP 500, and findings failed to land. Gated behind `PROACTIVE_BUDDIES_ENABLED` (default OFF) in `core/config.py` — `fire_event` returns `0` immediately unless the flag is set, restoring the lightweight known-good ingest path. Buddies still run on demand from the AI Buddies page. Root weakness is the over-subscribed B1 plan; re-enable proactive runs only after right-sizing or moving runs off the web worker
- **CI Node version** — `deploy.yml` `NODE_VERSION` is `22` to match the App Service runtime (`node_version = "22-lts"` in `main.tf`). A mismatch surfaces a setup-node warning; keep these in lock-step
- **Scans stuck "running" forever** — a workflow-driven scan that's cancelled / times out / fails to dispatch never calls `/scans/ingest`, so the scan never reaches a terminal state. `main.py::_fail_stale_scans()` fails any scan in `pending`/`running` older than 90 min (> the slowest job, OWASP DC ~60m) — runs at startup and every 20 min via the `_start_stuck_scan_watchdog` loop. Same self-heal pattern as the threat-model watchdog. **Direct (in-process) connector scans (Azure/AWS/GCP/Entra) are also vulnerable** — they run inside the web worker, so a gunicorn `--max-requests` recycle or OOM mid-scan orphans them at `running` (empty summary, 0 findings). The same 90-min watchdog reaps them; rescan from the tile afterward.
- **OWASP Dependency-Check hung forever (keyless NVD)** — DC's NVD CVE download is throttled to *hours* without an API key, so keyless scans never finished. Fixes: (1) `NVD_API_KEY` stored in Key Vault + surfaced to the workflow via `/scans/config/` (connector's own `nvd_api_key` wins, else platform fallback in `scans_runner.py`); (2) `owasp-dc-scan.yml` gates the DC step on a key being present (`steps.cfg.outputs.has_nvd_key == '1'`), `timeout-minutes: 45`, `actions/cache` for the `dc-data` NVD DB, `--nvdApiDelay 2000`; (3) a keyless run now posts a clear "needs NVD API key" ingest error so the scan **ends `failed`** instead of hanging. OWASP DC is now `status: "live"` in the Scans type picker (was "Coming soon").
- **Threat-model rescan stuck on "generating"** — `threat_models.py::rescan` queues `generate_threat_model_bg` as a FastAPI BackgroundTask in the web worker. If the worker is OOM-killed mid-run, the `except` that sets `status='failed'` never executes, so the row is orphaned at `generating`/`pending` and the detail page polls forever. Two guards: (a) `main.py::_fail_stale_threat_models()` runs at startup and flips any `generating`/`pending` row older than 20 min to `failed` (age-gated so a genuinely in-flight run isn't killed); (b) the LLM call in `threat_modeler.py::_invoke_llm` is wrapped in `asyncio.wait_for(..., LLM_TIMEOUT_SECONDS=180)` so a stalled provider socket resolves to a skeleton/failed instead of hanging
- **Light theme / hardcoded colors** — the UI was built dark-only with ~1,800 hardcoded colors (`bgcolor: "#1E1E1E"`, `color: "white"`, `color: "rgba(255,255,255,…)"`), so light mode only flipped the page background while tiles/text stayed dark-on-dark. Fixed by migrating those literals to **theme tokens** in `sx`: `#1E1E1E`→`"background.paper"`, `color:"white"`→`"text.primary"`, `color:"rgba(255,255,255,a)"`→`"text.secondary"`, white `borderColor`→`"divider"`. The dark palette is anchored (`background.paper #141B2B`, `text.primary #E6EBF3`) so dark mode is unchanged. **Light mode is the default** (`ThemeModeContext` initial mode). **Rules when adding UI: use theme tokens, never hardcoded dark hex/white.** Ternary colors (`color: active ? X : "rgba(255,255,255,…)"`) are the easy miss — the false/unselected branch must be a token (`text.secondary`) or it goes invisible in light mode. `ListItemText slotProps.style` is plain CSS (no palette paths) — use `mode === "light" ? … : …`. The sidebar follows the app theme (light in light mode); only chart `fill`/`stroke` + Recharts `wrapperStyle`/`labelStyle` need `useTheme().palette.*`. Gotchas: (1) the migration must skip React inline `style={{}}` and Recharts plain-object props (`wrapperStyle`/`labelStyle`/`contentStyle`) — those don't resolve MUI palette paths; use `useTheme().palette.*` there. (2) The **sidebar chrome stays dark in both modes**, so `AppLayout`'s drawer is wrapped in a fixed dark `<ThemeProvider theme={buildTheme("dark")}>` so its tokens resolve light-on-dark. (3) `theme/index.ts` and `*/tokens.ts` hold intentional literal colors — don't tokenize theme/styleOverride definitions. Tiles get depth via `MuiCard` `boxShadow`+hairline border in `buildComponents()`.
- **Empty threat models ("0 components, 0 threats" but status=completed)** — the threat-modeler LLM call capped `max_tokens=4096`, but the deliverable JSON schema (components + data_flows + threats + mitigations + trust_boundaries + entry_points + coverage_decisions) exceeds that for any real scope, so the response truncated mid-JSON (`finish_reason=length`), `json.loads` failed, `_normalise({})` emptied everything, and it saved as `completed` with no error. Fixes in `services/threat_modeler.py`: raised the cap to `THREAT_MODEL_MAX_TOKENS=16000` (gpt-4.1-mini allows ~32k output); `_invoke_llm` now detects parse failure / `finish_reason=length` and returns a `meta["error"]`; `generate_threat_model` raises (→ status `failed` + visible reason) instead of silently saving an empty model when a non-diagram run yields 0 components and 0 threats. Diagnosis came from the prod SQLite DB (`sqlite:////home/nexgencyberai.db`) pulled via Kudu VFS — see note below.
- **Mermaid DFD parse errors / LLM JSON truncation (whole family)** — LLM-authored Mermaid had invalid syntax (e.g. `-->|https (pii, encrypted)|` — unquoted parens read as a node-shape start), and LLM JSON calls truncated at `max_tokens=4096`. Fixes: (1) `_normalise` now ALWAYS rebuilds `dfd_mermaid` deterministically from the structured `components`+`data_flows` via `_build_mermaid()` (`_mm_id`/`_mm_label` sanitise ids + quote labels) — the LLM's raw Mermaid is ignored; (2) every threat-model LLM call uses `THREAT_MODEL_MAX_TOKENS=16000`; (3) `coverage/fill-gaps` (`threat_modeler_gapfill.py`) also raised to 16000 AND batches `_MAX_CELLS_PER_CALL=40` per call so the response JSON can't truncate (was 502 `gap-fill JSON parse failed`). **Existing broken models need a rescan** to regenerate a valid DFD.
- **Prod DB is SQLite on App Service `/home`** — `DATABASE_URL=sqlite:////home/nexgencyberai.db` (persistent storage, survives restarts; NOT Azure SQL despite CLAUDE.md's earlier prod note). To inspect prod data: `TOK=$(az account get-access-token --resource https://management.core.windows.net/ --query accessToken -o tsv)` then `curl -H "Authorization: Bearer $TOK" https://<app>.scm.azurewebsites.net/api/vfs/nexgencyberai.db -o prod.db` (SCM basic auth is disabled; the AAD bearer token works). Query locally with sqlite3/python.
- **GDPR / ISO 27001 / SOC 2 / PCI DSS show "0 controls" — by design, not a sync bug** — framework control catalogs are seeded at startup from `backend/data/frameworks/*.json` (`main.py::_seed_framework_controls()`, destructive-sync: rows absent from the JSON are deleted). Only NIST CSF/800-53, CIS v8 + ~17 CIS benchmarks, and the two ZAP sets have JSON files. GDPR/ISO27001/SOC2/PCI ship with **no JSON** (legal/process frameworks with no canonical machine-readable control list), so `frameworks.py::list_frameworks` intentionally returns them as 0-count placeholders to keep them visible. Populate via the UI/API import (`POST /api/v1/frameworks/{fw}/import/`, CSV or JSON) **or** by adding a `{fw}.json` seed file — but not both (the seed sync would prune the imported rows).
- **App Service worker tuning (RAM/OOM)** — startup command in `deploy.yml` runs **gunicorn managing uvicorn workers** (`gunicorn main:app -k uvicorn.workers.UvicornWorker --workers 2 --timeout 300 --graceful-timeout 60 --max-requests 600 --max-requests-jitter 150`), was plain `uvicorn --workers 4`. On the B1 plan (1.75 GB) 4 workers over-subscribed memory and any heavy LLM run (verdict / buddies / threat model) OOM-killed a worker. The fix has two parts: (a) `--workers 2` halves peak memory pressure (the lever for acute per-request spikes); (b) `--max-requests` recycles each worker periodically to reclaim memory that creeps up between LLM runs (the lever for gradual growth). `gunicorn==23.0.0` is pinned in `requirements.txt`. No `--preload` (avoids sharing the SQLAlchemy engine across fork). Staying on B1 — the fix is worker tuning, not a plan upgrade; if RAM gets tight under heavier load, tune further (lower `--max-requests`, or drop to `--workers 1`) before considering a larger plan
