# NexGenCyberAI — Monitara Security Platform

AI-powered security operations platform. FastAPI backend + React/TypeScript frontend, deployed to Azure App Service via GitHub Actions.

---

## Table of Contents

1. [Architecture overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Azure setup (one-time)](#azure-setup-one-time)
4. [Entra ID app registrations](#entra-id-app-registrations)
5. [GitHub secrets](#github-secrets)
6. [First deployment](#first-deployment)
7. [Local development](#local-development)
8. [Environment variables reference](#environment-variables-reference)
9. [Adding a new environment (staging / prod)](#adding-a-new-environment)
10. [Troubleshooting](#troubleshooting)

---

## Architecture overview

```
GitHub Actions CI/CD
  ├── backend-test     → pytest
  ├── frontend-test    → tsc + npm run build (uploads artifact)
  ├── deploy-backend   → pre-bundled deps zip → Kudu → Azure App Service (API)
  └── deploy-frontend  → build artifact zip  → Kudu → Azure App Service (Web)

Azure Resources
  ├── App Service Plan (Linux P2v3)
  ├── App Service — backend  (Python 3.12, FastAPI + gunicorn/uvicorn)
  ├── App Service — frontend (Node 22, serve -s)
  ├── SQLite (embedded, file on App Service disk — no separate DB service)
  ├── Azure Key Vault (optional — for secrets at rest)
  └── Application Insights (optional — logging)

Auth: Azure Entra ID (MSAL) — two App Registrations (backend API + frontend SPA)
```

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Azure CLI | 2.60+ | `az --version` |
| Terraform | 1.7+ | Only needed if provisioning infra from scratch |
| Node.js | 22 | Frontend builds |
| Python | 3.12 | Backend |
| Git | any | |

You need an Azure subscription and a GitHub account with Actions enabled.

---

## Azure setup (one-time)

### Option A — Terraform (recommended for new environments)

```bash
cd infrastructure/terraform

# Copy and fill in your values
cp terraform.tfvars.example terraform.tfvars   # edit this file

# Create the Terraform state storage account first (one-time, manual)
az group create -n nexgencyberai-tfstate-rg -l eastus
az storage account create -n nexgencyberaitfstate -g nexgencyberai-tfstate-rg --sku Standard_LRS
az storage container create -n tfstate --account-name nexgencyberaitfstate

# Initialise and apply
terraform init
terraform plan -var="subscription_id=<YOUR_SUBSCRIPTION_ID>"
terraform apply -var="subscription_id=<YOUR_SUBSCRIPTION_ID>"
```

After `apply` completes, Terraform outputs the backend and frontend App Service URLs — note these down.

### Option B — Manual Azure CLI

```bash
# Variables — change these for your environment
RG="nexgencyberai-dev-rg"
LOCATION="eastus"
PLAN="nexgencyberai-plan"
BACKEND_APP="nexgencyberai-api"
FRONTEND_APP="nexgencyberai-web"

# Resource group + App Service plan
az group create -n $RG -l $LOCATION
az appservice plan create -n $PLAN -g $RG --is-linux --sku P2v3

# Backend (Python 3.12)
az webapp create -n $BACKEND_APP -g $RG --plan $PLAN --runtime "PYTHON:3.12"

# Frontend (Node 22)
az webapp create -n $FRONTEND_APP -g $RG --plan $PLAN --runtime "NODE:22-lts"

# CORS: allow frontend to call backend
az webapp cors add -n $BACKEND_APP -g $RG \
  --allowed-origins "https://${FRONTEND_APP}.azurewebsites.net"
```

---

## Entra ID app registrations

You need **two** App Registrations in your Azure Entra ID tenant.

### 1. Backend API registration

```bash
# Create the registration
az ad app create --display-name "NexGenCyberAI-API" \
  --sign-in-audience AzureADMyOrg

# Note the appId from the output — this is AZURE_CLIENT_ID / REACT_APP_BACKEND_CLIENT_ID

# Create a client secret
az ad app credential reset --id <APP_ID> --append
# Note the "password" value — this is AZURE_CLIENT_SECRET
```

In the Azure portal for this registration:
- **Expose an API** → set Application ID URI (e.g. `api://<APP_ID>`)
- **Expose an API** → add a scope named `access_as_user`
- **App roles** → add role `NexGenAdmin` (value: `NexGenAdmin`) for admin users

### 2. Frontend SPA registration

```bash
az ad app create --display-name "NexGenCyberAI-Web" \
  --sign-in-audience AzureADMyOrg \
  --spa-redirect-uris "https://<FRONTEND_APP>.azurewebsites.net" \
                      "http://localhost:3000"

# Note the appId — this is REACT_APP_AZURE_CLIENT_ID
```

In the Azure portal for this registration:
- **API permissions** → Add permission → My APIs → NexGenCyberAI-API → `access_as_user`
- Grant admin consent

---

## GitHub secrets

Go to your GitHub repo → **Settings → Secrets and variables → Actions** and add:

| Secret | Description |
|--------|-------------|
| `AZURE_CREDENTIALS` | Output of `az ad sp create-for-rbac --sdk-auth --role contributor --scopes /subscriptions/<ID>/resourceGroups/<RG>` |
| `REACT_APP_AZURE_CLIENT_ID` | Frontend App Registration client ID |
| `REACT_APP_AZURE_TENANT_ID` | Your Entra tenant ID (`az account show --query tenantId -o tsv`) |
| `REACT_APP_BACKEND_CLIENT_ID` | Backend App Registration client ID |
| `REACT_APP_API_URL` | `https://<BACKEND_APP>.azurewebsites.net/api/v1` |
| `REACT_APP_REDIRECT_URI` | `https://<FRONTEND_APP>.azurewebsites.net` |

Generate `AZURE_CREDENTIALS`:
```bash
az ad sp create-for-rbac \
  --name "nexgencyberai-github-actions" \
  --role contributor \
  --scopes /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG> \
  --sdk-auth
```

---

## First deployment

### 1. Update workflow env vars

Edit `.github/workflows/deploy.yml` and set the three hardcoded names to match your Azure resources:

```yaml
env:
  AZ_RESOURCE_GROUP: "your-resource-group"
  AZ_BACKEND_APP:    "your-backend-app-name"
  AZ_FRONTEND_APP:   "your-frontend-app-name"
```

### 2. Set backend App Service environment variables

```bash
az webapp config appsettings set \
  -n <BACKEND_APP> -g <RG> \
  --settings \
    AZURE_TENANT_ID="<tenant-id>" \
    AZURE_CLIENT_ID="<backend-app-registration-client-id>" \
    AZURE_CLIENT_SECRET="<client-secret>" \
    AZURE_JWKS_URI="https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys" \
    SECRET_KEY="$(openssl rand -hex 32)" \
    ALLOWED_ORIGINS="https://<FRONTEND_APP>.azurewebsites.net" \
    DEFAULT_AI_PROVIDER="azure_openai" \
    AZURE_OPENAI_API_KEY="<your-key>" \
    AZURE_OPENAI_ENDPOINT="https://<your-resource>.openai.azure.com/" \
    AZURE_OPENAI_DEPLOYMENT="gpt-4o" \
    ENCRYPTION_KEY="$(openssl rand -hex 32)"
```

> **Tip:** You can also set these in the Azure portal under App Service → Configuration → Application settings.

### 3. Push to main

```bash
git push origin main
```

GitHub Actions runs automatically. Watch progress under the **Actions** tab. The first run takes longer because the Python vendor cache is cold (~12–15 min). Subsequent pushes take 5–10 min.

### 4. Seed initial data (optional)

```bash
# Run against the live backend via SSH or Kudu console
cd /home/site/wwwroot
PYTHONPATH=/home/site/wwwroot/vendor python3 seed_data.py
```

---

## Local development

### Backend only

```bash
cd backend
pip install -r requirements.txt

# Create .env (see Environment variables reference below)
cp .env.example .env   # edit with your credentials

PYTHONPATH=. uvicorn main:app --reload --port 8000
```

### Frontend only

```bash
cd frontend
npm install

# Set env vars (or create .env.local)
REACT_APP_API_URL=http://localhost:8000/api/v1 \
REACT_APP_AZURE_CLIENT_ID=<client-id> \
REACT_APP_AZURE_TENANT_ID=<tenant-id> \
REACT_APP_BACKEND_CLIENT_ID=<backend-client-id> \
npm start
```

### Full stack with Docker Compose

```bash
cp .env.example .env   # fill in AI provider keys and Entra IDs
docker-compose up --build
```

- Backend API: http://localhost:8000
- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs

> Docker Compose uses PostgreSQL + Redis locally. Azure deployment uses SQLite (no external DB needed).

---

## Environment variables reference

Create `backend/.env` for local development. All values are optional unless marked **required**.

### Authentication (required for login to work)

| Variable | Description |
|----------|-------------|
| `AZURE_TENANT_ID` | Entra ID tenant ID |
| `AZURE_CLIENT_ID` | Backend App Registration client ID |
| `AZURE_CLIENT_SECRET` | Backend App Registration secret |
| `AZURE_JWKS_URI` | `https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys` |

### App

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me-in-production` | JWT signing key — generate with `openssl rand -hex 32` |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated CORS origins |
| `DATABASE_URL` | `sqlite:///./nexgencyberai.db` | SQLite path or PostgreSQL DSN |
| `ENCRYPTION_KEY` | `` | Key for encrypting stored connector credentials |

### AI providers (at least one required for agents to work)

| Variable | Description |
|----------|-------------|
| `DEFAULT_AI_PROVIDER` | `azure_openai` \| `openai` \| `anthropic` \| `google_gemini` \| `aws_bedrock` |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI key |
| `AZURE_OPENAI_ENDPOINT` | `https://<resource>.openai.azure.com/` |
| `AZURE_OPENAI_DEPLOYMENT` | Deployment name (default: `gpt-4o`) |
| `OPENAI_API_KEY` | Direct OpenAI key |
| `ANTHROPIC_API_KEY` | Anthropic Claude key |
| `GOOGLE_API_KEY` | Google Gemini key |
| `AWS_BEDROCK_ACCESS_KEY` / `AWS_BEDROCK_SECRET_KEY` | AWS credentials for Bedrock |
| `CUSTOM_OPENAI_BASE_URL` | Any OpenAI-compatible endpoint (Ollama, Together AI, etc.) |

> The platform auto-fails-over across providers in the order: Azure OpenAI → OpenAI → Gemini → Bedrock → Anthropic. Configure at least two for resilience.

### Optional integrations

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | For GitHub Actions workflow dispatch (ZAP/Semgrep/etc. scans) |
| `NVD_API_KEY` | NIST NVD API key for OWASP Dependency-Check scans |
| `ARM_SUBSCRIPTION_ID` | Azure subscription for Azure connector scans |
| `GCP_PROJECT_ID` | GCP project for GCP connector scans |
| `SCAN_INGEST_SECRET` | Shared secret for GitHub Actions scan result callbacks |

---

## Adding a new environment

To deploy a staging or production environment alongside dev:

1. **Provision Azure resources** — run Terraform with `environment=staging` or `environment=prod`, or create manually with different names.

2. **Add a new workflow file** (e.g. `.github/workflows/deploy-staging.yml`) — copy `deploy.yml` and change:
   - The `on.push.branches` trigger to your staging branch
   - The `AZ_RESOURCE_GROUP`, `AZ_BACKEND_APP`, `AZ_FRONTEND_APP` env vars
   - The `concurrency.group` key so it doesn't block the dev pipeline

3. **Add environment-specific secrets** in GitHub under **Settings → Environments** (create a `staging` environment) and scope the secrets to that environment.

4. **Update ALLOWED_ORIGINS** on the backend App Service to include the new frontend URL.

---

## Troubleshooting

### Backend returns 500 / "uvicorn not found"

The startup command uses the pre-bundled vendor directory. Check:
```bash
# In Kudu console (App Service → Advanced Tools → Bash)
ls /home/site/wwwroot/vendor/gunicorn
PYTHONPATH=/home/site/wwwroot/vendor python3 -c "import gunicorn; print(gunicorn.__version__)"
```

If vendor is missing, the deploy job may have failed before packaging. Re-run the workflow.

### Login loop / 401 on API calls

- Check `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` are set on the backend App Service.
- Check `REACT_APP_AZURE_CLIENT_ID`, `REACT_APP_BACKEND_CLIENT_ID` were correct when the frontend was **built** (they're baked into the JS bundle at build time).
- Ensure the frontend redirect URI is registered in the SPA App Registration.

### Frontend shows old version after deploy

The frontend is a static SPA served by `serve -s .`. Hard-refresh the browser (Ctrl+Shift+R) or clear the cache. Azure App Service does not add cache-control headers automatically — consider adding a startup script that sets them via `serve`'s `-C` flag if needed.

### GitHub Actions stuck at "Kudu busy" (HTTP 409)

Another deploy is already running on that App Service. The workflow retries automatically with 60 s backoff (up to 5 attempts). If it keeps failing, cancel the stuck deployment in the Azure portal under App Service → Deployment Center → Logs.

### First backend deploy is slow (~12 min)

The Python vendor cache is cold on the first run — pip installs ~40 packages into the cache. Every subsequent deploy with the same `requirements.txt` restores the cache in ~30 s and skips pip entirely.

### Terraform state storage doesn't exist

Create it before `terraform init`:
```bash
az group create -n nexgencyberai-tfstate-rg -l eastus
az storage account create -n nexgencyberaitfstate -g nexgencyberai-tfstate-rg --sku Standard_LRS --allow-blob-public-access false
az storage container create -n tfstate --account-name nexgencyberaitfstate
```
