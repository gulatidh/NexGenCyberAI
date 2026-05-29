// Shared color/style tokens for the Risk Overview dashboard.
// Centralized so a future light-mode theme can override one place.

export const SEV_COLOR: Record<string, string> = {
  critical: "#f44336",
  high: "#ff9800",
  medium: "#ffeb3b",
  low: "#4caf50",
  info: "#4285F4",
};

export const SEV_BG: Record<string, string> = {
  critical: "rgba(244,67,54,0.10)",
  high: "rgba(255,152,0,0.10)",
  medium: "rgba(255,235,59,0.10)",
  low: "rgba(76,175,80,0.10)",
  info: "rgba(66,133,244,0.10)",
};

export const RISK_COLOR: Record<string, string> = {
  critical: "#f44336",
  high: "#ff9800",
  medium: "#ffeb3b",
  low: "#4caf50",
};

export const SCORE_COLOR = (score: number): string => {
  if (score >= 85) return "#00e676";
  if (score >= 70) return "#ff9800";
  return "#f44336";
};

export const cardSx = {
  bgcolor: "#1E1E1E",
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: 2,
};

export const FRAMEWORK_LABEL: Record<string, string> = {
  nist_csf: "NIST CSF 2.0",
  nist_800_53: "NIST 800-53",
  cis_v8: "CIS v8.1",
  cis_azure: "CIS Azure",
  cis_aws: "CIS AWS",
  cis_aws_db: "CIS AWS DB",
  cis_alibaba: "CIS Alibaba",
  cis_gcp: "CIS GCP",
  cis_gcp_workspace: "CIS Workspace",
  cis_m365: "CIS M365",
  cis_aks: "CIS AKS",
  cis_azure_compute: "CIS Azure Compute",
  cis_windows_server: "CIS Windows Server",
  cis_ubuntu: "CIS Ubuntu",
  cis_esxi: "CIS ESXi",
  cis_f5: "CIS F5",
  cis_palo_alto: "CIS Palo Alto",
  cis_mssql: "CIS SQL Server",
  gdpr: "GDPR",
  iso_27001: "ISO 27001",
  soc2: "SOC 2",
  pci_dss: "PCI DSS",
};
