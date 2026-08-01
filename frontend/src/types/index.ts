export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type RiskLevel = "critical" | "high" | "medium" | "low";
export type ConnectorType =
  | "azure" | "aws" | "gcp" | "onprem" | "servicenow" | "okta" | "cyberark" | "entraid"
  | "containers" | "github" | "jira" | "web"
  // SAST
  | "semgrep" | "codeql" | "sonarqube"
  // Network & Infrastructure
  | "nmap" | "openvas" | "trivy"
  // Dependency & Secret
  | "owasp_dc" | "gitleaks" | "trufflehog"
  // AI-powered local code review
  | "ai_code_review"
  // Enterprise professional scanners
  | "tenable" | "burp_enterprise" | "snyk" | "rapid7" | "qualys" | "invicti" | "acunetix"
  // Import / offline upload
  | "upload";
export type ConnectorStatus = "active" | "inactive" | "error" | "pending";
export type ScanType = "vulnerability" | "configuration" | "compliance" | "full";
export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type FrameworkType =
  | "nist_csf" | "nist_800_53" | "cis_v8"
  | "gdpr" | "iso_27001" | "soc2" | "pci_dss"
  | "cis_azure" | "cis_aws" | "cis_aws_db" | "cis_alibaba"
  | "cis_gcp" | "cis_gcp_workspace" | "cis_m365" | "cis_aks" | "cis_azure_compute"
  | "cis_windows_server" | "cis_ubuntu" | "cis_esxi"
  | "cis_f5" | "cis_palo_alto" | "cis_mssql"
  | "zap_unauth_passive" | "zap_auth_active";
export type AgentType = "risk_manager" | "va_scanner" | "framework_analyst" | "compliance_monitor" | "threat_intel" | "remediation" | "orchestrator";

export interface Client {
  id: string;
  name: string;
  slug: string;
  industry?: string;
  country?: string;
  contact_name?: string;
  contact_email?: string;
  logo_url?: string;
  is_active: boolean;
  created_at?: string;
}

export interface Project {
  id: string;
  client_id: string;
  name: string;
  description?: string;
  environment?: string;
  cloud_provider?: string;
  created_at?: string;
}

export interface ProjectSummary {
  id: string;
  name: string;
  connector_count: number;
  asset_count: number;
  scan_count: number;
}

export interface Connector {
  id: string;
  client_id: string;
  project_id?: string;
  name: string;
  connector_type: ConnectorType;
  status: ConnectorStatus;
  config?: Record<string, any>;
  last_synced_at?: string;
  error_message?: string;
  created_at?: string;
}

export interface Scan {
  id: string;
  client_id: string;
  project_id?: string;
  connector_id?: string;
  name?: string;
  scan_type: ScanType;
  status: ScanStatus;
  framework?: FrameworkType;
  initiated_by?: string;
  started_at?: string;
  completed_at?: string;
  summary?: {
    total?: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
  };
  error_message?: string;
  created_at?: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  description?: string;
  severity: Severity;
  resource_id?: string;
  resource_type?: string;
  control_id?: string;
  framework?: FrameworkType;
  status: string;
  remediation?: string;
  cve_id?: string;
  cvss_score?: number;
  created_at?: string;
  seen_count?: number;
  first_seen_at?: string;
  occurrence_count?: number;
  last_seen_at?: string;
  duplicate_of_id?: string;
  playbook?: string;
  control_mappings?: any;
  evidence?: any;
  assignee_email?: string;
  due_date?: string;
  remediated_at?: string;
  suppressed_at?: string;
  suppression_reason?: string;
  acceptance_justification?: string;
  accepted_by?: string;
  acceptance_expires_at?: string;
}

export interface Risk {
  id: string;
  client_id: string;
  title: string;
  description?: string;
  risk_level: RiskLevel;
  likelihood: number;
  impact: number;
  risk_score?: number;
  category?: string;
  owner?: string;
  due_date?: string;
  status: string;
  mitigation_plan?: string;
  created_at?: string;
}

export interface AgentRun {
  id: string;
  client_id?: string;
  agent_type: AgentType;
  status: string;
  input_data?: Record<string, any>;
  output_data?: Record<string, any>;
  tokens_used?: number;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
}

export interface AIProvider {
  provider: string;
  available: boolean;
  models: string[];
}

export type ControlStatus = "compliant" | "non_compliant" | "partial" | "not_applicable";

export interface FrameworkControl {
  id: string;
  framework: FrameworkType;
  control_id: string;
  parent_control_id?: string;
  domain?: string;
  title: string;
  description?: string;
  weight: number;
}

export interface LinkedFinding {
  id: string;
  title: string;
  resource_id?: string;
  resource_type?: string;
  severity: Severity;
  status: string;
  scan_id?: string;
  asset_id?: string | null;
  asset_name?: string | null;
}

export interface ControlStatusEntry {
  control: FrameworkControl;
  status: ControlStatus;
  derived: boolean;
  evidence?: string;
  last_evaluated_at?: string;
  overridden_by?: string;
  overridden_at?: string;
  finding_ids: string[];
  findings?: LinkedFinding[];
}

export interface FrameworkSummary {
  framework: FrameworkType;
  total: number;
  compliant: number;
  non_compliant: number;
  partial: number;
  not_applicable: number;
  score: number;
  last_evaluated_at?: string;
}

export interface FrameworkCatalogEntry {
  framework: FrameworkType;
  name: string;
  version?: string;
  total_controls: number;
}

export interface FrameworkDetail {
  framework: FrameworkType;
  summary: {
    total: number;
    compliant: number;
    non_compliant: number;
    partial: number;
    not_applicable: number;
    score: number;
    last_evaluated_at?: string;
  };
  controls: ControlStatusEntry[];
}

export type AssetStatus = "active" | "stale" | "deleted" | "new" | "reappeared";
export type AssetClass = "vm" | "storage" | "network" | "database" | "identity" | "keyvault" | "other";

export interface Asset {
  id: string;
  client_id: string;
  connector_id: string;
  external_id: string;
  name: string;
  asset_type?: string;
  asset_class?: AssetClass | string;
  region?: string;
  subscription_id?: string;
  resource_group?: string;
  account_id?: string;
  project_id?: string;
  tags?: Record<string, string>;
  status: AssetStatus;
  first_seen_at?: string;
  last_synced_at?: string;
  reappeared_at?: string;
  open_findings_count: number;
  risks_count: number;
  severity_breakdown?: { critical: number; high: number; medium: number; low: number; info: number };
  cve_count?: number;
  last_scan_date?: string;
}

export interface AssetDetail extends Asset {
  provider_metadata?: Record<string, any>;
  findings: Finding[];
  risks: Risk[];
  cves?: string[];
  cve_count?: number;
  last_scan_date?: string;
}

// ── Risk Overview ──────────────────────────────────────────────────────────

export interface RiskOverviewCompliance {
  framework: string;
  score: number;
  total: number;
  compliant: number;
  non_compliant: number;
  partial: number;
  not_applicable: number;
}

export interface RiskOverviewOpenIssues {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  deltas: { critical: number; high: number; medium: number; low: number };
}

export interface RiskSeverityTrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface RiskAvgAge {
  critical: number;
  high: number;
  medium: number;
  low: number;
  sla: { critical: number; high: number; medium: number; low: number };
}

export interface RiskSecurityScore {
  current: number;
  prev_7d: number;
  delta: number;
  history: { date: string; score: number }[];
}

export interface RiskTopIssue {
  title: string;
  severity: Severity;
  framework?: string | null;
  count: number;
  affected_resources: number;
}

export interface RiskIssuesFlowPoint {
  date: string;
  opened: number;
  resolved: number;
}

export interface RiskProjectRow {
  name: string;
  asset_count: number;
  issues: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  environment: string;
}

export interface RiskServiceRow {
  name: string;
  owner: string;
  asset_count: number;
  issues: number;
  critical: number;
  high: number;
  risk_level: "critical" | "high" | "medium" | "low";
}

export interface RiskOverviewFilters {
  projects: string[];
  environments: string[];
  cloud_providers: string[];
  frameworks: string[];
  statuses: string[];
}

export interface RiskOverview {
  compliance: RiskOverviewCompliance[];
  open_issues: RiskOverviewOpenIssues;
  severity_trend: RiskSeverityTrendPoint[];
  avg_age: RiskAvgAge;
  security_score: RiskSecurityScore;
  top_issues: RiskTopIssue[];
  issues_flow: RiskIssuesFlowPoint[];
  projects: RiskProjectRow[];
  services: RiskServiceRow[];
  filter_options: RiskOverviewFilters;
  as_of: string;
}

// ── Technology Inventory ───────────────────────────────────────────────────

export type TechStatus = "healthy" | "warning" | "critical" | "ignored";
export type RiskLevelLow = "critical" | "high" | "medium" | "low";

export interface TechnologyRow {
  id: string;
  name: string;
  resources_count: number;
  type: string;
  category: string;
  category_icon: string;
  category_color: string;
  subcategory: string;
  subcategory_icon: string;
  organization_usage_pct: number;
  status: TechStatus;
  risk_level: RiskLevelLow;
  open_findings: number;
  cve_count: number;
  versions_detected: number;
  owner: string;
  environments: string[];
  last_seen?: string;
  regions: string[];
  subscriptions: string[];
}

export interface CategoryBreakdown {
  name: string;
  icon: string;
  color: string;
  count: number;
}

export interface SubcategoryBreakdown {
  name: string;
  icon: string;
  count: number;
}

export interface TypeBreakdown {
  name: string;
  count: number;
}

export interface TechnologyFilters {
  categories: string[];
  types: string[];
  environments: string[];
  regions: string[];
  subscriptions: string[];
  owners: string[];
  statuses: string[];
  cloud_providers: string[];
}

export interface TechnologyInventory {
  summary: {
    total: number;
    by_status: Record<TechStatus, number>;
  };
  categories: CategoryBreakdown[];
  subcategories: SubcategoryBreakdown[];
  types: TypeBreakdown[];
  technologies: TechnologyRow[];
  filter_options: TechnologyFilters;
  as_of: string;
}

export interface TechnologyDetail {
  name: string;
  category: string;
  subcategory: string;
  type: string;
  resources_count: number;
  versions_detected: { version: string; asset_count: number }[];
  regions: string[];
  subscriptions: string[];
  open_findings: {
    id: string; title: string; severity: Severity; status: string;
    resource_id?: string; cve_id?: string; cvss_score?: number;
  }[];
  assets: {
    id: string; name: string; external_id: string; region?: string;
    subscription_id?: string; resource_group?: string; status: string;
  }[];
  stale_count?: number;
  stale_assets?: {
    id: string; name: string; external_id: string; region?: string;
    subscription_id?: string; resource_group?: string; status: string;
  }[];
  owner: string;
  exposure_level: string;
  policies: { name: string; framework: string; control_id: string; status: string }[];
}

export interface FindingCategory {
  key: string;
  label: string;
  icon: string;
  count: number;
}

export interface FindingSection {
  key: string;
  label: string;
  total: number;
  categories: FindingCategory[];
}

export interface FindingCategoriesResponse {
  sections: FindingSection[];
  grand_total: number;
}

// ── RBAC ───────────────────────────────────────────────────────────────────

export type AccessRole = "reader" | "editor" | "admin";
export type AccessScope = "global" | "client" | "project";

export interface AccessGrant {
  id: string;
  email: string;
  role: AccessRole;
  scope_type: AccessScope;
  scope_id?: string | null;
  scope_label?: string | null;
  granted_by?: string | null;
  granted_at?: string;
}

export interface UserAccessSummary {
  email: string;
  grants: AccessGrant[];
  effective_global_role?: AccessRole | null;
}

export interface ManageableScopes {
  global: boolean;
  client_ids: string[];
  project_ids: string[];
}

export interface MyAccess {
  email: string;
  grants: AccessGrant[];
  is_admin: boolean;                 // global admin
  is_admin_anywhere?: boolean;       // admin at any scope (gates Admin nav)
  is_editor_anywhere: boolean;
  manageable_scopes?: ManageableScopes;
}

export interface TicketSync {
  id: string;
  client_id: string;
  connector_type: string;
  source_type: string;
  source_id: string;
  ticket_id: string;
  ticket_url: string;
  ticket_status: string;
  created_at: string;
  updated_at?: string;
}

export interface DashboardSummary {
  total_clients: number;
  active_connectors: number;
  open_findings: number;
  critical_findings: number;
  findings_by_severity?: Record<string, number>;
  risks_open: number;
  scans_last_30d: number;
  compliance_scores: Record<string, number>;
  posture_health: Record<string, number>;
  recent_scans: any[];
  recent_risks: any[];
  recent_findings: any[];
  agent_runs_total: number;
}

// ── Phase 9 Threat Modeling types ─────────────────────────────────────────────

export interface AttackTreeStep {
  step: number;
  threat_id: string;
  title: string;
  severity: string;
  likelihood: number;
}

export interface AttackTree {
  id: string;
  root_goal: string;
  root_threat_id: string;
  steps: AttackTreeStep[];
  combined_probability: number;
  impact: string;
  mitre_chain: string[];
}

export interface AdversaryProfile {
  id: string;
  name: string;
  type: string;
  motivation: string;
  sophistication: string;
  targeted_assets: string[];
  likely_techniques: string[];
  threat_ids: string[];
  likelihood: number;
  rationale: string;
}

export interface SigmaRule {
  threat_id: string;
  threat_title: string;
  platform: string;
  rule_id: string;
  severity: string;
  status: string;
  sigma_yaml: string;
}

export interface ThreatModel {
  id: string;
  client_id: string;
  name?: string | null;
  scope_type: string;
  framework?: string | null;
  methodology: string;
  status: string;
  attack_trees_json?: AttackTree[];
  adversary_profiles_json?: AdversaryProfile[];
  sigma_rules_json?: SigmaRule[];
  auto_remodel?: boolean;
}

// ── AI Remediation Jobs ────────────────────────────────────────────────────

export type RemediationJobStatus =
  | 'pending'
  | 'analyzing'
  | 'ready'
  | 'verifying'
  | 'verified'
  | 'partial'
  | 'unresolved'
  | 'failed';

export interface FindingRemediationPlan {
  finding_id: string;
  confidence_score: number;
  automatable: 'yes' | 'partial' | 'no';
  estimated_downtime: 'none' | 'minimal' | 'maintenance_window';
  risk_level: 'low' | 'medium' | 'high';
  step_by_step_plan: string[];
  artifact_type: 'bash' | 'powershell' | 'aws_cli' | 'azure_cli' | 'terraform' | 'code_patch' | 'manual';
  artifact_content: string;
  what_could_go_wrong: string;
  rollback_steps: string[];
  verification_status?: 'resolved' | 'unresolved' | null;
}

export interface RemediationJob {
  id: string;
  client_id: string;
  scan_id?: string | null;
  finding_ids: string[];
  status: RemediationJobStatus;
  plans?: FindingRemediationPlan[] | null;
  overall_summary?: string | null;
  overall_confidence?: number | null;
  overall_risk_level?: string | null;
  recommended_order?: string[] | null;
  verification_scan_id?: string | null;
  verification_results?: Record<string, 'resolved' | 'unresolved'> | null;
  error_message?: string | null;
  created_by?: string | null;
  created_at: string;
  updated_at?: string | null;
}
