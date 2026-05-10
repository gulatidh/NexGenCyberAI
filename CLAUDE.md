# NexGenCyberAI — Claude Code Context

AI-Powered Cybersecurity Posture Management Platform. Multi-tenant SaaS connecting to Azure, AWS, GCP, Entra ID, Okta and running AI security agents (Claude / OpenAI / Gemini / Bedrock).

---

## Project Structure

```
/opt/NexGenCyberAI/
├── backend/                  FastAPI Python 3.12 API
│   ├── main.py               App entry point, startup provisioning, router registration
│   ├── requirements.txt      Python dependencies
│   ├── api/
│   │   ├── models/models.py  SQLAlchemy ORM — all DB tables and enums
│   │   ├── schemas/schemas.py Pydantic request/response schemas
│   │   └── routers/          One file per resource (clients, scans, findings, risks, agents, etc.)
│   ├── connectors/           Cloud connector implementations
│   │   ├── base.py           BaseConnector, ConnectorFinding, FindingSeverity
│   │   ├── azure/connector.py  Direct ARM scanning (NSG, storage, Key Vault, RBAC, VMs)
│   │   ├── aws/connector.py
│   │   ├── gcp/connector.py
│   │   └── entraid/connector.py
│   ├── agents/               AI agent implementations (LangChain ReAct)
│   │   ├── base_agent.py     BaseAgent — provider-agnostic LLM wrapper
│   │   ├── orchestrator/     Runs all agents in sequence
│   │   ├── risk/             Risk scoring (NIST SP 800-30)
│   │   ├── framework/        NIST CSF / CIS v8 / GDPR mapping
│   │   ├── vascan/           Vulnerability analysis
│   │   ├── threat/           MITRE ATT&CK correlation
│   │   ├── remediation/      Playbook generation
│   │   └── compliance/       Audit report generation
│   └── core/
│       ├── config.py         Settings from env vars (pydantic-settings)
│       ├── ai_providers.py   Multi-provider LLM factory (get_llm())
│       └── encryption.py     Credential encryption for connectors
├── frontend/                 React 18 + TypeScript + MUI v6
│   └── src/
│       ├── pages/            One file per route (Dashboard, Clients, Findings, Risks, etc.)
│       ├── services/api.ts   Axios client — all API calls, auto-attaches Entra ID bearer token
│       ├── types/index.ts    TypeScript interfaces matching backend schemas
│       ├── auth/             MSAL Azure Entra ID authentication
│       └── components/layout/ AppLayout, NotificationBell
└── infrastructure/terraform/ Azure infrastructure as code
    ├── main.tf               All Azure resources
    ├── variables.tf          Input variable definitions
    ├── terraform.tfvars      Secret values — NOT in Git, keep safe locally
    └── outputs.tf            Resource URLs and connection strings
```

---

## Live Azure Environment

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
- **Branches**: `develop` (active dev) → `main` (stable, production-ready)
- **CI/CD**: GitHub Actions triggers on push to `develop` or `main`
  - Backend: pip install + pytest + deploy to Azure App Service
  - Frontend: npm ci + tsc + react-scripts build + deploy to Azure App Service
  - Terraform: plan (apply is manual)
- **Deploy rule**: Always `git push origin develop` — CI/CD handles deployment automatically. Never deploy manually via Kudu unless Git is also updated immediately after.
- **Merge to main**: Via PR only (`gh pr create` → `gh pr merge`)

---

## Database

- **Dev**: SQLite (`backend/nexgencyberai.db`) — file-based, no setup needed
- **Prod**: Azure SQL Server (mssql) via `pymssql`
- **ORM**: SQLAlchemy 2.0
- **Critical**: All `SAEnum` columns use `values_callable=_ev` (see `models.py`) so SQLAlchemy stores lowercase enum values. Never remove this or DB reads will break with `KeyError`.
- **Startup**: `main.py` runs `_normalize_enum_case()` + `_provision_entraid_connector()` + `_provision_azure_connector()` on every startup

---

## Authentication

- **Provider**: Microsoft Entra ID (Azure AD) via MSAL
- **Frontend**: `@azure/msal-react` — `MsalAuthenticationTemplate` wraps entire app, auto-redirects to Entra ID login
- **Backend**: JWT bearer token validation — every API endpoint requires `Depends(get_current_user)`
- **Token flow**: Frontend acquires token silently → attaches as `Authorization: Bearer <token>` → backend validates against JWKS URI

---

## Adding a New Page (Frontend Pattern)

Follow `frontend/src/pages/Findings.tsx` as the template:
1. Create `frontend/src/pages/NewPage.tsx` with client selector + table + detail dialog
2. Add API function to `frontend/src/services/api.ts`
3. Add TypeScript interface to `frontend/src/types/index.ts`
4. Register route in `frontend/src/App.tsx`
5. Add nav item in `frontend/src/components/layout/AppLayout.tsx`

**ESLint rule**: CI runs with `CI=true` which promotes unused import warnings to errors. Always remove unused imports before committing.

---

## Adding a New API Endpoint (Backend Pattern)

Follow `backend/api/routers/findings.py` as the template:
1. Create `backend/api/routers/newresource.py` with `APIRouter(prefix="/clients/{client_id}/newresource")`
2. Add Pydantic schemas to `backend/api/schemas/schemas.py`
3. Add SQLAlchemy model to `backend/api/models/models.py` if new table needed
4. Register router in `backend/main.py`: `app.include_router(newresource.router, prefix="/api/v1")`

---

## Adding a New Connector

Follow `backend/connectors/azure/connector.py` as the template:
1. Create `backend/connectors/newcloud/connector.py` extending `BaseConnector`
2. Implement: `test_connection()`, `get_resources()`, `run_configuration_review()`, `run_vulnerability_scan()`, `get_compliance_status()`
3. Return `ConnectorFinding` objects with `title`, `description`, `severity`, `resource_id`, `control_id`, `remediation`
4. Register in `backend/connectors/factory.py`
5. Add `ConnectorType.NEWCLOUD` enum value in `models.py`

---

## AI Agents

- All agents extend `BaseAgent` in `backend/agents/base_agent.py`
- Uses LangChain ReAct (`create_react_agent`) with provider-agnostic `get_llm()`
- **Fallback**: If no AI API key is configured, returns rule-based analysis only
- **Lazy imports**: `AgentOrchestrator` is imported lazily inside `_get_orchestrator()` in routers — never import at module level (crashes workers at startup)
- Supported providers: `azure_openai`, `openai`, `anthropic`, `google_gemini`, `aws_bedrock`
- Configure via AI Settings page or `DEFAULT_AI_PROVIDER` env var

---

## Key Environment Variables (backend)

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLite (dev) or mssql+pymssql://... (prod) |
| `AZURE_TENANT_ID` | Entra ID tenant for JWT validation |
| `AZURE_CLIENT_ID` | Backend app registration client ID |
| `DEFAULT_AI_PROVIDER` | `azure_openai` \| `openai` \| `anthropic` \| `google_gemini` \| `aws_bedrock` |
| `ANTHROPIC_API_KEY` | Claude API key |
| `OPENAI_API_KEY` | OpenAI API key |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI key |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL |
| `ENCRYPTION_KEY` | Fernet key for connector credential encryption |
| `ENTRAID_CONNECTOR_TENANT_ID` | Auto-provision Entra ID connector on startup |
| `ENTRAID_CONNECTOR_CLIENT_ID` | Auto-provision Entra ID connector on startup |
| `ENTRAID_CONNECTOR_CLIENT_SECRET` | Auto-provision Entra ID connector on startup |
| `ENTRAID_CONNECTOR_DB_CLIENT_ID` | Client UUID to attach provisioned connector to |
| `AZURE_SUBSCRIPTION_ID` | Auto-provision Azure ARM connector on startup |

---

## Infrastructure (Terraform)

- **State**: Local (`terraform.tfstate`) — not remote backend yet
- **tfvars**: `/opt/NexGenCyberAI/infrastructure/terraform/terraform.tfvars` — **NOT in Git**, store securely
- **Node version**: `22-lts` (updated from 20)
- **Python version**: `3.12`
- **To apply**: `cd infrastructure/terraform && terraform apply`
- **Drift warning**: Any direct Azure CLI / Portal config changes must be reflected in `main.tf` to avoid being reverted on next `terraform apply`

---

## Known Issues / Historical Fixes

- **SAEnum KeyError**: Always use `values_callable=_ev` on every `SAEnum()` — without it SQLAlchemy uses uppercase member names but DB stores lowercase values
- **Agent import crash**: Never import `AgentOrchestrator` at module level — LangGraph chain crashes uvicorn workers at startup
- **Trailing slash 404**: FastAPI has `redirect_slashes=False` — all POST endpoints and frontend API calls must include trailing slash
- **CI ESLint failures**: `CI=true` makes unused imports hard errors — always clean imports before committing
