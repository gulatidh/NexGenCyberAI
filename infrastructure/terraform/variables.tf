variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "environment" {
  description = "Environment: dev | staging | prod"
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging, or prod"
  }
}

variable "sql_admin_login" {
  description = "Azure SQL administrator username"
  type        = string
  default     = "nexgenadmin"
}

variable "sql_admin_password" {
  description = "Azure SQL administrator password"
  type        = string
  sensitive   = true
}

variable "entra_tenant_id" {
  description = "Azure Entra ID tenant ID"
  type        = string
}

variable "entra_backend_client_id" {
  description = "Entra ID App Registration client_id for the backend API"
  type        = string
}

variable "entra_frontend_client_id" {
  description = "Entra ID App Registration client_id for the frontend SPA"
  type        = string
}

variable "entra_admin_group" {
  description = "Entra ID group name for SQL Entra admin"
  type        = string
  default     = "NexGenCyberAI-Admins"
}

variable "entra_admin_group_id" {
  description = "Object ID of the Entra ID admin group"
  type        = string
}

variable "default_ai_provider" {
  description = "Default AI provider: azure_openai | openai | anthropic | google_gemini | aws_bedrock"
  type        = string
  default     = "azure_openai"
}

variable "use_containers" {
  description = "Create Azure Container Registry"
  type        = bool
  default     = false
}
