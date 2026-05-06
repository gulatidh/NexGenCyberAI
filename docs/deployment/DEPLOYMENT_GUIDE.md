# NexGenCyberAI — Complete Deployment Guide

## Table of Contents
1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Step 1 — Entra ID App Registrations](#3-step-1--entra-id-app-registrations)
4. [Step 2 — Azure Infrastructure (Terraform)](#4-step-2--azure-infrastructure-terraform)
5. [Step 3 — Configure AI Providers](#5-step-3--configure-ai-providers)
6. [Step 4 — Configure Connectors](#6-step-4--configure-connectors)
7. [Step 5 — GitHub Repository Setup](#7-step-5--github-repository-setup)
8. [Step 6 — GitHub Actions CI/CD](#8-step-6--github-actions-cicd)
9. [Step 7 — Local Development](#9-step-7--local-development)
10. [Step 8 — Post-Deployment Verification](#10-step-8--post-deployment-verification)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        USERS (Browser)                          │
│                 Authenticated via Entra ID OIDC                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTPS
                ┌───────────▼──────────┐
                │  Azure App Service   │
                │  Frontend (React)    │
                │  nexgencyberai-web   │
                └───────────┬──────────┘
                            │ REST + Bearer Token
                ┌───────────▼──────────┐
                │  Azure App Service   │
                │  Backend (FastAPI)   │
                │  nexgencyberai-api   │
                └──┬───┬───┬───┬──────┘
                   │   │   │   │
       ┌───────────┘   │   │   └────────────────┐
       │               │   │                    │
  ┌────▼────┐    ┌─────▼──┐  ┌───▼───┐  ┌──────▼───────┐
  │Azure SQL│    │  Redis  │  │Key    │  │ AI Providers  │
  │Database │    │  Cache  │  │Vault  │  │ Claude/OpenAI │
  └─────────┘    └─────────┘  └───────┘  │ Gemini/Bedrock│
                                         └──────────────┘
                     │
       ┌─────────────┼──────────────┐
       │             │              │
  ┌────▼────┐  ┌─────▼───┐  ┌──────▼──┐
  │ Azure   │  │  AWS    │  │  GCP    │  ← Cloud Connectors
  │Defender │  │Security │  │Security │
  └─────────┘  │  Hub    │  │ Center  │
               └─────────┘  └─────────┘
```

---

## 2. Prerequisites

Install the following tools on your deployment machine:

```bash
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login

# Terraform
wget https://releases.hashicorp.com/terraform/1.7.0/terraform_1.7.0_linux_amd64.zip
unzip terraform_1.7.0_linux_amd64.zip && sudo mv terraform /usr/local/bin/

# GitHub CLI
type -p curl >/dev/null || sudo apt install curl -y
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | \
  sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | \
  sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install gh -y
gh auth login

# Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt-get install -y nodejs

# Python 3.12
sudo apt install python3.12 python3.12-pip -y

# Docker
sudo apt install docker.io docker-compose -y
```

---

## 3. Step 1 — Entra ID App Registrations

You need **two** App Registrations: one for the backend API and one for the frontend SPA.

### 3a. Backend API App Registration

```bash
# Login
az login

TENANT_ID=$(az account show --query tenantId -o tsv)

# Create backend app registration
BACKEND_APP=$(az ad app create \
  --display-name "NexGenCyberAI-Backend" \
  --sign-in-audience "AzureADMyOrg" \
  --query appId -o tsv)

echo "Backend Client ID: $BACKEND_APP"

# Create service principal
az ad sp create --id $BACKEND_APP

# Create client secret
BACKEND_SECRET=$(az ad app credential reset \
  --id $BACKEND_APP \
  --years 2 \
  --query password -o tsv)

echo "Backend Client Secret: $BACKEND_SECRET"  # Save this securely!

# Expose the API — add a scope
az ad app update --id $BACKEND_APP \
  --identifier-uris "api://$BACKEND_APP"

az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications(appId='$BACKEND_APP')" \
  --headers "Content-Type=application/json" \
  --body "{
    \"api\": {
      \"oauth2PermissionScopes\": [{
        \"id\": \"$(uuidgen)\",
        \"adminConsentDescription\": \"Access NexGenCyberAI\",
        \"adminConsentDisplayName\": \"NexGenCyberAI.Read\",
        \"isEnabled\": true,
        \"type\": \"User\",
        \"value\": \"NexGenCyberAI.Read\"
      }]
    }
  }"

# Add app roles (NexGenAdmin, NexGenAnalyst)
az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications(appId='$BACKEND_APP')" \
  --headers "Content-Type=application/json" \
  --body '{
    "appRoles": [
      {
        "allowedMemberTypes": ["User"],
        "displayName": "NexGen Admin",
        "id": "'"$(uuidgen)"'",
        "isEnabled": true,
        "description": "Full access to NexGenCyberAI",
        "value": "NexGenAdmin"
      },
      {
        "allowedMemberTypes": ["User"],
        "displayName": "NexGen Analyst",
        "id": "'"$(uuidgen)"'",
        "isEnabled": true,
        "description": "Read and analyse security data",
        "value": "NexGenAnalyst"
      }
    ]
  }'
```

### 3b. Frontend SPA App Registration

```bash
FRONTEND_APP=$(az ad app create \
  --display-name "NexGenCyberAI-Frontend" \
  --sign-in-audience "AzureADMyOrg" \
  --query appId -o tsv)

echo "Frontend Client ID: $FRONTEND_APP"

az ad sp create --id $FRONTEND_APP

# Configure as SPA with redirect URI
az ad app update --id $FRONTEND_APP \
  --web-redirect-uris "http://localhost:3000" \
  "https://nexgencyberai-prod-web.azurewebsites.net"

# Grant the frontend access to the backend API scope
az ad app permission add \
  --id $FRONTEND_APP \
  --api $BACKEND_APP \
  --api-permissions "NexGenCyberAI.Read=Scope"

az ad app permission grant \
  --id $FRONTEND_APP \
  --api $BACKEND_APP \
  --scope "NexGenCyberAI.Read"

# Admin consent
az ad app permission admin-consent --id $FRONTEND_APP
```

---

## 4. Step 2 — Azure Infrastructure (Terraform)

### 4a. Create Terraform State Storage

```bash
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
LOCATION="eastus"

# Create storage account for Terraform state
az group create --name nexgencyberai-tfstate-rg --location $LOCATION

az storage account create \
  --name nexgencyberaitfstate \
  --resource-group nexgencyberai-tfstate-rg \
  --location $LOCATION \
  --sku Standard_LRS \
  --encryption-services blob

az storage container create \
  --name tfstate \
  --account-name nexgencyberaitfstate
```

### 4b. Create terraform.tfvars

```bash
cd infrastructure/terraform
cat > terraform.tfvars <<EOF
subscription_id          = "$SUBSCRIPTION_ID"
location                 = "$LOCATION"
environment              = "dev"
entra_tenant_id          = "$TENANT_ID"
entra_backend_client_id  = "$BACKEND_APP"
entra_frontend_client_id = "$FRONTEND_APP"
entra_admin_group        = "NexGenCyberAI-Admins"
entra_admin_group_id     = "$(az ad group show --group 'NexGenCyberAI-Admins' --query id -o tsv 2>/dev/null || echo 'YOUR_GROUP_OBJECT_ID')"
sql_admin_password       = "NexGenCyber@2025!"
default_ai_provider      = "azure_openai"
EOF
```

### 4c. Deploy Infrastructure

```bash
cd infrastructure/terraform
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

**Save the outputs:**
```bash
terraform output
# backend_url     = "https://nexgencyberai-dev-XXXXXX-api.azurewebsites.net"
# frontend_url    = "https://nexgencyberai-dev-XXXXXX-web.azurewebsites.net"
# sql_server_fqdn = "nexgencyberai-dev-XXXXXX-sql.database.windows.net"
```

---

## 5. Step 3 — Configure AI Providers

Configure secrets in Azure Key Vault or App Service settings:

### Option A — Azure OpenAI (recommended for Azure deployments)
```bash
APP_NAME="nexgencyberai-dev-XXXXXX-api"  # from terraform output

az webapp config appsettings set \
  --name $APP_NAME \
  --resource-group nexgencyberai-dev-rg \
  --settings \
    AZURE_OPENAI_API_KEY="your-azure-openai-key" \
    AZURE_OPENAI_ENDPOINT="https://your-openai-resource.openai.azure.com" \
    AZURE_OPENAI_DEPLOYMENT="gpt-4o" \
    DEFAULT_AI_PROVIDER="azure_openai"
```

### Option B — Anthropic Claude
```bash
az webapp config appsettings set \
  --name $APP_NAME --resource-group nexgencyberai-dev-rg \
  --settings \
    ANTHROPIC_API_KEY="sk-ant-..." \
    DEFAULT_AI_PROVIDER="anthropic"
```

### Option C — OpenAI
```bash
az webapp config appsettings set \
  --name $APP_NAME --resource-group nexgencyberai-dev-rg \
  --settings \
    OPENAI_API_KEY="sk-..." \
    DEFAULT_AI_PROVIDER="openai"
```

### Option D — Google Gemini
```bash
az webapp config appsettings set \
  --name $APP_NAME --resource-group nexgencyberai-dev-rg \
  --settings \
    GOOGLE_API_KEY="AIza..." \
    DEFAULT_AI_PROVIDER="google_gemini"
```

### Option E — AWS Bedrock
```bash
az webapp config appsettings set \
  --name $APP_NAME --resource-group nexgencyberai-dev-rg \
  --settings \
    AWS_BEDROCK_ACCESS_KEY="AKIA..." \
    AWS_BEDROCK_SECRET_KEY="..." \
    AWS_BEDROCK_REGION="us-east-1" \
    DEFAULT_AI_PROVIDER="aws_bedrock"
```

> **Note:** All five providers can be configured simultaneously. Users can switch providers from the **AI Settings** page in the web UI. The `DEFAULT_AI_PROVIDER` controls which is used by default.

---

## 6. Step 4 — Configure Connectors

After deployment, add connectors via the UI or API. Below are the required credentials per connector type.

### Azure Connector
```json
{
  "tenant_id": "YOUR_TENANT_ID",
  "client_id": "SERVICE_PRINCIPAL_CLIENT_ID",
  "client_secret": "SERVICE_PRINCIPAL_SECRET",
  "subscription_id": "TARGET_SUBSCRIPTION_ID"
}
```
**Required permissions:** `Security Reader`, `Reader` on the subscription.

### AWS Connector
```json
{
  "access_key_id": "AKIAXXXXXXXXXXXXXXXX",
  "secret_access_key": "your-secret-key",
  "role_arn": "arn:aws:iam::123456789:role/NexGenCyberAI-ReadOnly"
}
```
**Required IAM policies:** `SecurityAudit`, `SecurityHub:GetFindings`, `Inspector2:ListFindings`.

### GCP Connector
```json
{
  "project_id": "my-gcp-project",
  "service_account_json": "{\"type\":\"service_account\",...}",
  "org_id": "123456789"
}
```
**Required roles:** `roles/securitycenter.findingsViewer`, `roles/cloudasset.viewer`.

### Entra ID Connector
```json
{
  "tenant_id": "YOUR_TENANT_ID",
  "client_id": "APP_CLIENT_ID",
  "client_secret": "APP_SECRET"
}
```
**Required Graph API permissions:** `IdentityRiskyUser.Read.All`, `Policy.Read.All`, `UserAuthenticationMethod.Read.All`.

### Okta Connector
```json
{
  "domain": "yourorg.okta.com",
  "api_token": "YOUR_OKTA_API_TOKEN"
}
```

### ServiceNow Connector
```json
{
  "instance_url": "https://yourinstance.service-now.com",
  "username": "admin",
  "password": "your-password"
}
```

### Kubernetes / Containers
```json
{
  "api_server": "https://your-k8s-api.example.com:6443",
  "token": "eyJhbGciOiJSUzI1NiIs..."
}
```

### On-Premises (Nessus)
```json
{
  "nessus_url": "https://your-nessus-server:8834",
  "nessus_api_key": "ACCESS_KEY",
  "nessus_secret_key": "SECRET_KEY"
}
```

---

## 7. Step 5 — GitHub Repository Setup

```bash
cd /opt/NexGenCyberAI

# Authenticate GitHub CLI
gh auth login

# Create private repository
gh repo create NexGenCyberAI \
  --private \
  --description "AI-Powered Cybersecurity Posture Management Platform" \
  --clone=false

# Initialize git and push
git init
git config user.email "dheeraj.a.gulati@accenture.com"
git config user.name "Dheeraj Gulati"
git add .
git commit -m "feat: initial NexGenCyberAI platform

- Multi-tenant client profile management
- Connectors: Azure, AWS, GCP, On-Prem, Entra ID, Okta, ServiceNow, Containers
- Frameworks: NIST CSF, NIST 800-53, CIS v8, GDPR, ISO 27001, SOC 2, PCI DSS
- AI Agents: Risk Manager, VA Scanner, Framework Analyst, Threat Intel, Remediation, Compliance
- AI Providers: Claude (Anthropic), OpenAI GPT, Google Gemini, AWS Bedrock, Azure OpenAI
- Authentication: Azure Entra ID (MSAL)
- Infrastructure: Terraform (Azure App Service, SQL, Redis, Key Vault)
- CI/CD: GitHub Actions → Azure App Service

Co-Authored-By: NexGenCyberAI Build System"

git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/NexGenCyberAI.git
git push -u origin main

# Create develop branch
git checkout -b develop
git push -u origin develop
```

---

## 8. Step 6 — GitHub Actions CI/CD

Configure the following **GitHub Secrets** (Settings → Secrets → Actions):

```bash
# Create Azure Service Principal for CI/CD
SP_JSON=$(az ad sp create-for-rbac \
  --name "NexGenCyberAI-GitHub-Actions" \
  --role "Contributor" \
  --scopes "/subscriptions/$SUBSCRIPTION_ID" \
  --sdk-auth)

# Set secrets via GitHub CLI
gh secret set AZURE_CREDENTIALS --body "$SP_JSON"
gh secret set AZURE_SUBSCRIPTION_ID --body "$SUBSCRIPTION_ID"
gh secret set AZURE_BACKEND_APP_NAME_DEV --body "nexgencyberai-dev-XXXXXX-api"
gh secret set AZURE_FRONTEND_APP_NAME_DEV --body "nexgencyberai-dev-XXXXXX-web"
gh secret set AZURE_BACKEND_APP_NAME_PROD --body "nexgencyberai-prod-XXXXXX-api"
gh secret set AZURE_FRONTEND_APP_NAME_PROD --body "nexgencyberai-prod-XXXXXX-web"
gh secret set TF_VAR_sql_admin_password --body "NexGenCyber@2025!"
gh secret set TF_VAR_entra_tenant_id --body "$TENANT_ID"
gh secret set TF_VAR_entra_backend_client_id --body "$BACKEND_APP"
gh secret set TF_VAR_entra_frontend_client_id --body "$FRONTEND_APP"
gh secret set TF_VAR_entra_admin_group_id --body "YOUR_GROUP_OBJECT_ID"
gh secret set REACT_APP_AZURE_CLIENT_ID --body "$FRONTEND_APP"
gh secret set REACT_APP_AZURE_TENANT_ID --body "$TENANT_ID"
```

**Trigger first deployment:**
```bash
git push origin main
# Monitor: https://github.com/YOUR_USERNAME/NexGenCyberAI/actions
```

---

## 9. Step 7 — Local Development

```bash
cd /opt/NexGenCyberAI

# Copy and fill environment variables
cp .env.example .env
# Edit .env with your credentials

# Start all services
docker-compose up --build

# Or run without Docker:
# Backend
cd backend && pip install -r requirements.txt && uvicorn main:app --reload --port 8000

# Frontend
cd frontend && npm install && npm start
```

Access at:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/api/docs

---

## 10. Step 8 — Post-Deployment Verification

```bash
# 1. Health check
curl https://nexgencyberai-dev-api.azurewebsites.net/api/health

# Expected:
# {"status":"healthy","version":"1.0.0","db":"ok","app":"NexGenCyberAI"}

# 2. Open API docs
open https://nexgencyberai-dev-api.azurewebsites.net/api/docs

# 3. Check frontend loads
open https://nexgencyberai-dev-web.azurewebsites.net

# 4. Verify AI providers
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://nexgencyberai-dev-api.azurewebsites.net/api/v1/ai/providers

# 5. Check App Service logs
az webapp log tail \
  --name nexgencyberai-dev-api \
  --resource-group nexgencyberai-dev-rg
```

---

## 11. Troubleshooting

| Issue | Resolution |
|-------|-----------|
| Entra ID login loop | Verify redirect URI matches exactly in App Registration |
| 401 on API calls | Check `AZURE_CLIENT_ID` and `AZURE_TENANT_ID` in App Service settings |
| AI agents returning "Configure AI provider" | Set `DEFAULT_AI_PROVIDER` and at least one API key in App Service settings |
| Connector test fails | Verify service principal has required permissions (see Step 4) |
| Database connection error | Check `DatabaseUrl` secret in Key Vault, verify firewall allows Azure services |
| Frontend blank page | Check browser console for MSAL config errors; verify tenant ID and client ID |
| Terraform state lock | `terraform force-unlock LOCK_ID` |

---

*Generated by NexGenCyberAI Build System — 2026-05-06*
