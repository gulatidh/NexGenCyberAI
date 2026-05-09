export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type RiskLevel = "critical" | "high" | "medium" | "low";
export type ConnectorType = "azure" | "aws" | "gcp" | "onprem" | "servicenow" | "okta" | "entraid" | "containers" | "github" | "jira";
export type ConnectorStatus = "active" | "inactive" | "error" | "pending";
export type ScanType = "vulnerability" | "configuration" | "compliance" | "full";
export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type FrameworkType = "nist_csf" | "nist_800_53" | "cis_v8" | "gdpr" | "iso_27001" | "soc2" | "pci_dss";
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

export interface Connector {
  id: string;
  client_id: string;
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
  connector_id?: string;
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

export interface ControlStatusEntry {
  control: FrameworkControl;
  status: ControlStatus;
  derived: boolean;
  evidence?: string;
  last_evaluated_at?: string;
  overridden_by?: string;
  overridden_at?: string;
  finding_ids: string[];
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

export type AssetStatus = "active" | "stale" | "deleted";
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
  open_findings_count: number;
  risks_count: number;
}

export interface AssetDetail extends Asset {
  provider_metadata?: Record<string, any>;
  findings: Finding[];
  risks: Risk[];
}

export interface DashboardSummary {
  total_clients: number;
  active_connectors: number;
  open_findings: number;
  critical_findings: number;
  risks_open: number;
  scans_last_30d: number;
  compliance_scores: Record<string, number>;
  posture_health: Record<string, number>;
  recent_scans: any[];
  recent_risks: any[];
  recent_findings: any[];
  agent_runs_total: number;
}
