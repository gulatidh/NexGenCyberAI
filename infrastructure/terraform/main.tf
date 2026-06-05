/**
 * NexGenCyberAI - Azure Infrastructure (Terraform)
 * Provisions all resources required to run the platform on Azure.
 *
 * Resources created:
 *  - Resource Group
 *  - App Service Plan (Linux P2v3)
 *  - App Service (backend API) + App Service (frontend SPA)
 *  - Azure SQL Database (Basic/Standard depending on env)
 *  - Azure Cache for Redis (C0 Basic)
 *  - Azure Key Vault (secrets storage)
 *  - Log Analytics Workspace + Application Insights
 *  - Azure Container Registry (if container deployment used)
 */

terraform {
  required_version = ">= 1.7"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
  # Remote state — update storage account details before use
  backend "azurerm" {
    resource_group_name  = "nexgencyberai-tfstate-rg"
    storage_account_name = "nexgencyberaitfstate"
    container_name       = "tfstate"
    key                  = "nexgencyberai.terraform.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
  subscription_id = var.subscription_id
}

provider "azuread" {}

data "azurerm_client_config" "current" {}

# ── Random suffix for globally unique names ──────────────────────────────────

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "random_string" "sql_suffix" {
  length  = 4
  special = false
  upper   = false
}

locals {
  suffix   = random_string.suffix.result
  app_name = "nexgencyberai-${var.environment}-${local.suffix}"
  kv_name  = "ngcai-${var.environment}-${local.suffix}"
  tags = {
    project     = "NexGenCyberAI"
    environment = var.environment
    managed_by  = "terraform"
  }
}

# ── Resource Group ────────────────────────────────────────────────────────────

resource "azurerm_resource_group" "main" {
  name     = "nexgencyberai-${var.environment}-rg"
  location = var.location
  tags     = local.tags
}

# ── Log Analytics + App Insights ──────────────────────────────────────────────

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${local.app_name}-law"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

resource "azurerm_application_insights" "main" {
  name                = "${local.app_name}-ai"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  tags                = local.tags
}

# ── Azure SQL ─────────────────────────────────────────────────────────────────

resource "azurerm_mssql_server" "main" {
  name                         = "ncai-${var.environment}-${random_string.sql_suffix.result}-sql"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = var.sql_location
  version                      = "12.0"
  administrator_login          = var.sql_admin_login
  administrator_login_password = var.sql_admin_password
  minimum_tls_version          = "1.2"
  tags                         = local.tags

  azuread_administrator {
    login_username = var.entra_admin_group
    object_id      = var.entra_admin_group_id
  }
}

resource "azurerm_mssql_database" "main" {
  name           = "nexgencyberai"
  server_id      = azurerm_mssql_server.main.id
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  sku_name       = var.environment == "prod" ? "S2" : "Basic"
  max_size_gb    = var.environment == "prod" ? 50 : 2
  zone_redundant = var.environment == "prod"
  tags           = local.tags
}

resource "azurerm_mssql_firewall_rule" "azure_services" {
  name             = "AllowAzureServices"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# ── Redis Cache ───────────────────────────────────────────────────────────────

resource "azurerm_redis_cache" "main" {
  name                          = "${local.app_name}-redis"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  capacity                      = var.environment == "prod" ? 1 : 0
  family                        = "C"
  sku_name                      = var.environment == "prod" ? "Standard" : "Basic"
  non_ssl_port_enabled          = false
  minimum_tls_version           = "1.2"
  public_network_access_enabled = var.environment == "prod" ? false : true
  tags                          = local.tags
}

# ── Key Vault ─────────────────────────────────────────────────────────────────

resource "azurerm_key_vault" "main" {
  name                        = local.kv_name
  resource_group_name         = azurerm_resource_group.main.name
  location                    = azurerm_resource_group.main.location
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  purge_protection_enabled    = var.environment == "prod"
  soft_delete_retention_days  = 7
  rbac_authorization_enabled  = true
  tags                        = local.tags
}

# Grant Terraform deployer access to write secrets
resource "azurerm_role_assignment" "deployer_kv" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Key Vault secrets
resource "azurerm_key_vault_secret" "db_connection" {
  name         = "DatabaseUrl"
  value        = "mssql+pymssql://${var.sql_admin_login}:${var.sql_admin_password}@${azurerm_mssql_server.main.fully_qualified_domain_name}/nexgencyberai"
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_role_assignment.deployer_kv]
}

resource "azurerm_key_vault_secret" "redis_connection" {
  name         = "RedisUrl"
  value        = "rediss://:${azurerm_redis_cache.main.primary_access_key}@${azurerm_redis_cache.main.hostname}:6380"
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_role_assignment.deployer_kv]
}

# Platform-wide NVD API key for OWASP Dependency-Check scans. Value from
# TF_VAR_nvd_api_key (or set out-of-band via `az keyvault secret set`); the
# ignore_changes keeps Terraform from clobbering an az-managed value.
resource "azurerm_key_vault_secret" "nvd_api_key" {
  name         = "NvdApiKey"
  value        = var.nvd_api_key
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_role_assignment.deployer_kv]
  lifecycle {
    ignore_changes = [value]
  }
}

# ── App Service Plan ──────────────────────────────────────────────────────────

resource "azurerm_service_plan" "main" {
  name                = "${local.app_name}-asp"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = var.environment == "prod" ? "P2v3" : "B1"
  tags                = local.tags
}

# ── Backend App Service ───────────────────────────────────────────────────────

resource "azurerm_linux_web_app" "backend" {
  name                = "${local.app_name}-api"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.main.id
  https_only          = true
  tags                = local.tags

  identity {
    type = "SystemAssigned"
  }

  site_config {
    always_on        = true
    http2_enabled    = true
    ftps_state       = "Disabled"
    minimum_tls_version = "1.2"

    application_stack {
      python_version = "3.12"
    }

    cors {
      allowed_origins     = ["https://${local.app_name}-web.azurewebsites.net"]
      support_credentials = true
    }
  }

  app_settings = {
    "APPINSIGHTS_INSTRUMENTATIONKEY"        = azurerm_application_insights.main.instrumentation_key
    "APPLICATIONINSIGHTS_CONNECTION_STRING" = azurerm_application_insights.main.connection_string
    "SCM_DO_BUILD_DURING_DEPLOYMENT"        = "true"
    "AZURE_TENANT_ID"                       = var.entra_tenant_id
    "AZURE_CLIENT_ID"                       = var.entra_backend_client_id
    "DEFAULT_AI_PROVIDER"                   = var.default_ai_provider
    "DATABASE_URL"                          = "@Microsoft.KeyVault(VaultName=${azurerm_key_vault.main.name};SecretName=DatabaseUrl)"
    "REDIS_URL"                             = "@Microsoft.KeyVault(VaultName=${azurerm_key_vault.main.name};SecretName=RedisUrl)"
    "CELERY_BROKER_URL"                     = "@Microsoft.KeyVault(VaultName=${azurerm_key_vault.main.name};SecretName=RedisUrl)"
    "NVD_API_KEY"                           = "@Microsoft.KeyVault(VaultName=${azurerm_key_vault.main.name};SecretName=NvdApiKey)"
  }

  logs {
    http_logs {
      file_system {
        retention_in_days = 7
        retention_in_mb   = 35
      }
    }
    application_logs {
      file_system_level = "Information"
    }
  }
}

# ── Frontend App Service ──────────────────────────────────────────────────────

resource "azurerm_linux_web_app" "frontend" {
  name                = "${local.app_name}-web"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.main.id
  https_only          = true
  tags                = local.tags

  site_config {
    always_on           = true
    http2_enabled       = true
    ftps_state          = "Disabled"
    minimum_tls_version = "1.2"

    application_stack {
      node_version = "22-lts"
    }
  }

  app_settings = {
    "REACT_APP_API_URL"          = "https://${local.app_name}-api.azurewebsites.net/api/v1"
    "REACT_APP_AZURE_CLIENT_ID"  = var.entra_frontend_client_id
    "REACT_APP_AZURE_TENANT_ID"  = var.entra_tenant_id
    "REACT_APP_REDIRECT_URI"     = "https://${local.app_name}-web.azurewebsites.net"
  }
}

# ── RBAC: App Service → Key Vault ─────────────────────────────────────────────

resource "azurerm_role_assignment" "backend_kv" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_web_app.backend.identity[0].principal_id
}

# ── Container Registry (optional) ────────────────────────────────────────────

resource "azurerm_container_registry" "main" {
  count               = var.use_containers ? 1 : 0
  name                = replace("${local.app_name}acr", "-", "")
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
}
