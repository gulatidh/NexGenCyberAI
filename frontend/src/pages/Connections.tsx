/**
 * Connections — unified hub for AI providers, platform connectors, and scanners.
 * Section 1: AI Providers (read-only status, links to /ai-settings)
 * Section 2: Platform Connectors (cloud / identity — full CRUD)
 * Section 3: Scanners (DAST / SAST / Network / Dependency — full CRUD)
 */
import React, { useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Button, Card, CardContent, Grid, Chip,
  Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, Select, MenuItem, FormControl, InputLabel,
  CircularProgress, Alert,
} from "@mui/material";
import {
  Add, PlayArrow, CheckCircle, Error, HourglassEmpty, Cable, Edit, Delete,
  OpenInNew, Psychology, Hub, Cloud,
} from "@mui/icons-material";
import { Cancel } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { connectorsApi, projectsApi, aiApi } from "../services/api";
import { Connector, ConnectorType, Project, AIProvider } from "../types";
import { toast } from "react-toastify";
// ── AI provider display map ───────────────────────────────────────────────────

const PROVIDER_LOGOS: Record<string, string> = {
  anthropic: "🟣 Anthropic Claude",
  openai: "🟢 OpenAI GPT",
  azure_openai: "🔵 Azure OpenAI",
  google_gemini: "🟡 Google Gemini",
  aws_bedrock: "🟠 AWS Bedrock",
  custom_openai: "⚫ Custom / Ollama",
};

// ── Connector maps ────────────────────────────────────────────────────────────

const PLATFORM_TYPES = new Set<ConnectorType>([
  "azure", "aws", "gcp", "onprem", "servicenow", "okta", "cyberark", "entraid",
  "containers", "github", "jira",
]);

const CONNECTOR_CATEGORY: Record<ConnectorType, string> = {
  azure: "cloud", aws: "cloud", gcp: "cloud", onprem: "cloud",
  servicenow: "cloud", okta: "cloud", cyberark: "cloud", entraid: "cloud",
  containers: "cloud", github: "cloud", jira: "cloud",
  web: "dast",
  semgrep: "sast", codeql: "sast", sonarqube: "sast",
  nmap: "network", openvas: "network", trivy: "network",
  owasp_dc: "dependency", gitleaks: "dependency", trufflehog: "dependency",
  ai_code_review: "sast",
  tenable: "enterprise", burp_enterprise: "enterprise", snyk: "enterprise",
  rapid7: "enterprise", qualys: "enterprise", invicti: "enterprise", acunetix: "enterprise",
};

const CONNECTOR_ICONS: Record<ConnectorType, string> = {
  azure: "☁️ Azure", aws: "🟠 AWS", gcp: "🔵 GCP",
  onprem: "🖥️ On-Premises", servicenow: "🟣 ServiceNow",
  okta: "🔑 Okta", cyberark: "🔐 CyberArk", entraid: "🆔 Entra ID",
  containers: "🐳 Containers", github: "🐙 GitHub", jira: "📋 Jira",
  web: "🌐 Web App (ZAP)",
  semgrep: "🔍 Semgrep", codeql: "🧬 CodeQL", sonarqube: "📊 SonarQube",
  nmap: "📡 NMAP", openvas: "🛰️ OpenVAS", trivy: "🏷️ Trivy",
  owasp_dc: "📦 OWASP Dep-Check", gitleaks: "💧 Gitleaks", trufflehog: "🐷 TruffleHog",
  ai_code_review: "🤖 AI Code Review",
  tenable: "🔴 Tenable.io", burp_enterprise: "🟠 Burp Enterprise", snyk: "💜 Snyk",
  rapid7: "🔵 Rapid7 InsightVM", qualys: "🟢 Qualys VMDR",
  invicti: "⚪ Invicti", acunetix: "🔺 Acunetix Enterprise",
};

const DISABLED_CONNECTOR_TYPES = new Set<string>(["sonarqube", "openvas"]);

const SCANNER_CATEGORIES = ["dast", "sast", "network", "dependency", "enterprise"] as const;

const CATEGORY_LABEL: Record<string, string> = {
  cloud: "Cloud & Identity",
  dast: "DAST — Dynamic AppSec",
  sast: "SAST — Static AppSec",
  network: "Network & Infrastructure",
  dependency: "Dependency & Secret",
  enterprise: "Enterprise Scanners",
};

// ── Status display ────────────────────────────────────────────────────────────

const STATUS_PROPS: Record<string, any> = {
  active:   { icon: <CheckCircle sx={{ fontSize: 16 }} />, color: "#00e676",       label: "Active"  },
  error:    { icon: <Error       sx={{ fontSize: 16 }} />, color: "#f44336",       label: "Error"   },
  pending:  { icon: <HourglassEmpty sx={{ fontSize: 16 }} />, color: "#ff9800",   label: "Pending" },
  inactive: { icon: <Cable      sx={{ fontSize: 16 }} />, color: "text.secondary", label: "Inactive"},
};

// ── Credential field definitions ─────────────────────────────────────────────

type CredField = { key: string; label: string; secret?: boolean; placeholder?: string; help?: string };

const CREDENTIAL_FIELDS: Record<ConnectorType, CredField[]> = {
  azure: [
    { key: "tenant_id",       label: "Tenant ID" },
    { key: "client_id",       label: "Client ID" },
    { key: "client_secret",   label: "Client Secret",   secret: true },
    { key: "subscription_id", label: "Subscription ID" },
  ],
  aws: [
    { key: "access_key_id",     label: "Access Key ID" },
    { key: "secret_access_key", label: "Secret Access Key", secret: true },
    { key: "role_arn",          label: "Role ARN (optional)" },
  ],
  gcp: [
    { key: "project_id",           label: "Project ID" },
    { key: "service_account_json", label: "Service Account JSON", secret: true },
  ],
  onprem: [
    { key: "nessus_url",        label: "Nessus URL" },
    { key: "nessus_api_key",    label: "API Key",    secret: true },
    { key: "nessus_secret_key", label: "Secret Key", secret: true },
  ],
  servicenow: [
    { key: "instance_url", label: "Instance URL (https://xxx.service-now.com)" },
    { key: "username",     label: "Username" },
    { key: "password",     label: "Password", secret: true },
  ],
  okta: [
    { key: "domain",    label: "Okta Domain (xxx.okta.com)" },
    { key: "api_token", label: "API Token", secret: true },
  ],
  cyberark: [
    { key: "base_url",  label: "PVWA URL (https://cyberark.company.com)" },
    { key: "username",  label: "Username" },
    { key: "password",  label: "Password", secret: true },
    { key: "auth_type", label: "Auth Type (CyberArk / LDAP / Windows)", placeholder: "CyberArk" },
  ],
  entraid: [
    { key: "tenant_id",     label: "Tenant ID" },
    { key: "client_id",     label: "App Registration Client ID" },
    { key: "client_secret", label: "Client Secret", secret: true },
  ],
  containers: [
    { key: "api_server", label: "Kubernetes API Server URL" },
    { key: "token",      label: "Bearer Token", secret: true },
  ],
  github: [
    { key: "token", label: "Personal Access Token", secret: true },
    { key: "org",   label: "Organisation" },
  ],
  jira: [
    { key: "url",       label: "Jira URL" },
    { key: "email",     label: "Email" },
    { key: "api_token", label: "API Token", secret: true },
  ],
  web: [],
  semgrep: [
    { key: "repo_url",     label: "Git Repo URL", placeholder: "https://github.com/org/repo",
      help: "HTTPS clone URL. Public repos work as-is; private repos also need the token below." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token",
      help: "For GitHub PATs use 'x-access-token'. For Azure DevOps use any non-empty string." },
    { key: "git_token",    label: "Git Personal Access Token", secret: true, placeholder: "ghp_…",
      help: "Required for private repos. GitHub: scope 'repo' (read). Azure DevOps: 'Code (Read)'." },
  ],
  codeql: [
    { key: "repo_url",     label: "Git Repo URL", placeholder: "https://github.com/org/repo",
      help: "HTTPS clone URL. CodeQL works best on GitHub-hosted repos." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token" },
    { key: "git_token",    label: "Git Personal Access Token", secret: true, placeholder: "ghp_…",
      help: "Required for private repos. Scope 'repo' for code-read; 'security_events' if writing back SARIF." },
  ],
  sonarqube: [
    { key: "repo_url",          label: "Git Repo URL (optional)", placeholder: "https://github.com/org/repo" },
    { key: "sonar_host_url",    label: "SonarQube Host URL",      placeholder: "https://sonar.example.com" },
    { key: "sonar_project_key", label: "SonarQube Project Key",   placeholder: "org_repo" },
    { key: "sonar_token",       label: "Sonar Token",             secret: true, placeholder: "sqp_…" },
    { key: "git_username",      label: "Git Username",            placeholder: "x-access-token" },
    { key: "git_token",         label: "Git Personal Access Token", secret: true },
  ],
  nmap: [
    { key: "target", label: "Target host / IP / CIDR", placeholder: "10.0.0.0/24  or  scanme.nmap.org",
      help: "Single host, IP, or CIDR range. Authorisation required — never scan systems you don't own." },
  ],
  openvas: [
    { key: "target", label: "Target host / IP / CIDR", placeholder: "10.0.1.5  or  192.168.1.0/24",
      help: "Greenbone/OpenVAS scans this target with the default vulnerability profile." },
  ],
  trivy: [
    { key: "image",        label: "Container image (optional)", placeholder: "ghcr.io/org/app:1.2.3",
      help: "Provide an image to scan a container; or use repo_url below for IaC/filesystem scans." },
    { key: "repo_url",     label: "Git Repo URL (alternative to image)", placeholder: "https://github.com/org/repo" },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token" },
    { key: "git_token",    label: "Git Personal Access Token", secret: true },
  ],
  owasp_dc: [
    { key: "repo_url",     label: "Git Repo URL", placeholder: "https://github.com/org/repo",
      help: "OWASP Dependency-Check runs against the cloned repo's manifests (pom.xml, package.json, etc.)." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token" },
    { key: "git_token",    label: "Git Personal Access Token", secret: true },
    { key: "nvd_api_key",  label: "NVD API Key (optional)", secret: true,
      help: "Free key: https://nvd.nist.gov/developers/request-an-api-key" },
  ],
  gitleaks: [
    { key: "repo_url",     label: "Git Repo URL", placeholder: "https://github.com/org/repo",
      help: "Full git history is scanned for committed secrets — clone is non-shallow." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token" },
    { key: "git_token",    label: "Git Personal Access Token", secret: true, placeholder: "ghp_…",
      help: "Required for private repos. Scope 'repo' (read)." },
  ],
  trufflehog: [
    { key: "repo_url",     label: "Git Repo URL", placeholder: "https://github.com/org/repo",
      help: "TruffleHog walks git history; verified secrets are flagged critical." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token" },
    { key: "git_token",    label: "Git Personal Access Token", secret: true, placeholder: "ghp_…" },
  ],
  ai_code_review: [
    { key: "repo_url",     label: "Git Repo URL (optional if uploading archive)",
      placeholder: "https://github.com/org/repo",
      help: "HTTPS clone URL. Leave blank if you will upload a zip archive when starting the scan." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token",
      help: "For GitHub PATs use 'x-access-token'. Leave blank for public repos." },
    { key: "git_token",    label: "Git Personal Access Token", secret: true, placeholder: "ghp_…",
      help: "Required for private repos. Scope 'repo' (read)." },
  ],
  tenable: [
    { key: "access_key", label: "Access Key", secret: true, placeholder: "a0b1c2d3-...", help: "Tenable.io Settings → My Account → API Keys" },
    { key: "secret_key", label: "Secret Key", secret: true, placeholder: "e4f5g6h7-..." },
  ],
  burp_enterprise: [
    { key: "host", label: "Burp Enterprise Host URL", placeholder: "https://burp.company.com", help: "Your Burp Suite Enterprise server URL" },
    { key: "api_key", label: "API Key", secret: true, placeholder: "burp_api_...", help: "Enterprise Settings → API" },
  ],
  snyk: [
    { key: "api_key", label: "API Token", secret: true, placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", help: "Snyk Account Settings → Auth Token" },
    { key: "org_id", label: "Organisation ID", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", help: "Snyk Settings → Organisation → General" },
  ],
  rapid7: [
    { key: "host", label: "InsightVM Host URL", placeholder: "https://insightvm.company.com", help: "Your InsightVM console URL" },
    { key: "username", label: "Username" },
    { key: "password", label: "Password", secret: true },
  ],
  qualys: [
    { key: "api_url", label: "Qualys API URL", placeholder: "https://qualysapi.qualys.com", help: "Your Qualys platform API URL (varies by pod)" },
    { key: "username", label: "Username" },
    { key: "password", label: "Password", secret: true },
  ],
  invicti: [
    { key: "api_url", label: "Invicti API URL", placeholder: "https://www.invicti.com/api/1.0", help: "Cloud: https://www.invicti.com/api/1.0 · On-prem: https://your-server/api/1.0" },
    { key: "api_token", label: "API Token", secret: true, placeholder: "invicti_token_...", help: "Invicti Settings → API Tokens" },
    { key: "username", label: "Username (for Basic auth)", placeholder: "user@company.com" },
  ],
  acunetix: [
    { key: "host", label: "Acunetix Host URL", placeholder: "https://acunetix.company.com", help: "Your Acunetix Enterprise server (port 3443 is used automatically)" },
    { key: "api_key", label: "API Key", secret: true, placeholder: "1/xxxx...", help: "Acunetix → Profile → API Key" },
  ],
};

// ── Type help banners ─────────────────────────────────────────────────────────

const TYPE_HELP: Partial<Record<ConnectorType, string>> = {
  semgrep:    "Point at a Git repo URL. For private repos, paste a PAT below. Semgrep runs --config auto (curated security rules) inside GitHub Actions.",
  codeql:     "Point at a Git repo URL (public or PAT-accessible). The workflow auto-detects the language and runs CodeQL's security-and-quality query suite.",
  sonarqube:  "Either point at a self-hosted SonarQube server, or use SonarCloud (host=https://sonarcloud.io). Workflow coming soon.",
  nmap:       "Scan a single host, IP, or CIDR. Requires written authorisation from the network owner. Runs nmap -Pn -sS -sV --top-ports 1000 --script=default,safe,vuln.",
  openvas:    "Greenbone/OpenVAS scans the target IP/CIDR with the default profile. Workflow coming soon.",
  trivy:      "Provide either a container image OR a Git repo URL. Image scans hit the registry; repo scans pull manifests + IaC for misconfigs and CVEs.",
  owasp_dc:   "Scans dependency manifests (pom.xml, package.json, …) in the cloned repo against known CVEs. Add an nvd_api_key to avoid NVD rate-limits.",
  gitleaks:   "Walks the full git history for committed secrets. Public repos work without auth; private repos need a PAT.",
  trufflehog: "Walks the full git history with high-fidelity verification. Verified secrets are flagged critical.",
  ai_code_review: "LLM-powered code security review — no GitHub Actions required. Point at a Git repo or upload a zip archive when starting a scan. The AI triages files by risk, reviews each function for vulnerabilities, runs a self-critique pass to remove false positives, and traces cross-file taint flows.",
  tenable:        "Connects to Tenable.io's REST API to launch network/host vulnerability scans. Scans the target IPs/CIDRs you configure and ingests all found vulnerabilities with CVSS scores.",
  burp_enterprise:"Connects to your Burp Suite Enterprise server to launch DAST scans against web applications. Uses Burp's industry-standard crawler and active attack engine.",
  snyk:           "Connects to your Snyk organisation and ingests issues from all projects — open-source vulnerabilities, license issues, and Snyk Code findings.",
  rapid7:         "Connects to your Rapid7 InsightVM console to launch a site scan and ingest discovered vulnerabilities with severity, CVSS scores, and remediation guidance.",
  qualys:         "Connects to your Qualys VMDR subscription to launch authenticated scans against the specified IP/CIDR ranges and ingest QID-based vulnerabilities.",
  invicti:        "Connects to Invicti's cloud or on-prem API to launch proof-based DAST scans. Low false-positive rate due to evidence-based vulnerability confirmation.",
  acunetix:       "Connects to your Acunetix Enterprise instance to create a scan target and launch a full vulnerability scan. Ingests web application vulnerabilities, misconfigurations, and OWASP Top 10 issues.",
};

// ── Component ─────────────────────────────────────────────────────────────────

export default function Connections() {
  const navigate = useNavigate();
  const qc = useQueryClient();

  // ── Client / project selection ──────────────────────────────────────────────
  const { clientId: selectedClientId } = useActiveClient();
  const [selectedProjectId, setSelectedProjectId] = useState("");

  // ── Dialog state ────────────────────────────────────────────────────────────
  const [open, setOpen] = useState(false);
  const [addMode, setAddMode] = useState<"platform" | "scanner" | null>(null);
  const [editing, setEditing] = useState<Connector | null>(null);

  // Form fields
  const [connectorType, setConnectorType] = useState<ConnectorType>("azure");
  const [connName, setConnName] = useState("");
  const [connProjectId, setConnProjectId] = useState("");
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [testResults, setTestResults] = useState<Record<string, any>>({});

  // Web (ZAP) connector fields
  const [webTargetUrl, setWebTargetUrl] = useState("");
  const [webProfile, setWebProfile] = useState<"baseline" | "active">("baseline");
  const [webAuthMethod, setWebAuthMethod] = useState<
    "none" | "bearer" | "cookie" | "form" | "oauth_client_credentials"
  >("none");
  const [webAuth, setWebAuth] = useState<Record<string, string>>({});
  const [webExcludes, setWebExcludes] = useState("");

  // ── Queries ─────────────────────────────────────────────────────────────────
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", selectedClientId],
    queryFn: () => projectsApi.list(selectedClientId),
    enabled: !!selectedClientId,
  });

  const { data: connectors = [], isLoading: connectorsLoading } = useQuery<Connector[]>({
    queryKey: ["connectors", selectedClientId, selectedProjectId],
    queryFn: () => connectorsApi.list(selectedClientId, selectedProjectId || undefined),
    enabled: !!selectedClientId,
  });

  const { data: aiData } = useQuery({
    queryKey: ["ai-providers"],
    queryFn: aiApi.listProviders,
  });
  const aiProviders: AIProvider[] = (aiData as any)?.providers || [];

  const { data: aiConfig } = useQuery({
    queryKey: ["ai-config"],
    queryFn: aiApi.getConfig,
    retry: 0,
  });

  // ── Derived lists ────────────────────────────────────────────────────────────
  const platformConnectors = connectors.filter((c) => PLATFORM_TYPES.has(c.connector_type));
  const scannerConnectors  = connectors.filter((c) => !PLATFORM_TYPES.has(c.connector_type));

  // ── Mutations ────────────────────────────────────────────────────────────────
  const createMutation = useMutation({
    mutationFn: (data: any) =>
      editing
        ? connectorsApi.update(selectedClientId, editing.id, data)
        : connectorsApi.create(selectedClientId, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["connectors"] });
      closeDialog();
      toast.success(editing ? "Connector updated" : "Connector added");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error"),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => connectorsApi.delete(selectedClientId, id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["connectors"] });
      toast.success("Connector deleted");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error"),
  });

  const testMutation = useMutation({
    mutationFn: ({ clientId, connId }: { clientId: string; connId: string }) =>
      connectorsApi.test(clientId, connId),
    onSuccess: (data, vars) => {
      setTestResults((prev) => ({ ...prev, [vars.connId]: data }));
      qc.invalidateQueries({ queryKey: ["connectors"] });
    },
    onError: (e: any, vars) =>
      setTestResults((prev) => ({ ...prev, [vars.connId]: { success: false, message: e.message } })),
  });

  // ── Dialog helpers ───────────────────────────────────────────────────────────
  const closeDialog = () => {
    setOpen(false);
    setEditing(null);
    setAddMode(null);
    setConnName("");
    setCredentials({});
    setWebTargetUrl("");
    setWebProfile("baseline");
    setWebAuthMethod("none");
    setWebAuth({});
    setWebExcludes("");
  };

  const openAdd = (mode: "platform" | "scanner") => {
    setEditing(null);
    setAddMode(mode);
    setConnName("");
    setConnectorType(mode === "platform" ? "azure" : "web");
    setCredentials({});
    setTestResults({});
    setWebTargetUrl("");
    setWebProfile("baseline");
    setWebAuthMethod("none");
    setWebAuth({});
    setWebExcludes("");
    setConnProjectId(selectedProjectId || projects[0]?.id || "");
    setOpen(true);
  };

  const openEdit = (c: Connector) => {
    setEditing(c);
    setAddMode(null);
    setConnName(c.name);
    setConnectorType(c.connector_type);
    setConnProjectId(c.project_id || "");
    setCredentials({});
    setWebTargetUrl("");
    setWebProfile("baseline");
    setWebAuthMethod("none");
    setWebAuth({});
    setWebExcludes("");
    setOpen(true);
  };

  // Filtered type options for the dialog's type picker
  const dialogTypeOptions = Object.entries(CONNECTOR_ICONS).filter(([k]) => {
    if (DISABLED_CONNECTOR_TYPES.has(k)) return false;
    if (editing) return true; // show all when editing
    if (addMode === "platform") return PLATFORM_TYPES.has(k as ConnectorType);
    if (addMode === "scanner")  return !PLATFORM_TYPES.has(k as ConnectorType);
    return true;
  });

  const credFields = CREDENTIAL_FIELDS[connectorType] || [];

  // ── Save handler ─────────────────────────────────────────────────────────────
  const handleSave = () => {
    if (connectorType === "web") {
      const exclude_paths = webExcludes.split("\n").map((s) => s.trim()).filter(Boolean);
      const config = {
        target_url: webTargetUrl.trim(),
        default_profile: webProfile,
        ...(exclude_paths.length ? { exclude_paths } : {}),
      };
      const creds = { auth: { method: webAuthMethod, ...webAuth } };
      createMutation.mutate(
        editing
          ? { name: connName, project_id: connProjectId, credentials: creds, config }
          : { name: connName, connector_type: connectorType, project_id: connProjectId, credentials: creds, config }
      );
    } else {
      createMutation.mutate(
        editing
          ? { name: connName, project_id: connProjectId, ...(Object.keys(credentials).length ? { credentials } : {}) }
          : { name: connName, connector_type: connectorType, project_id: connProjectId, credentials }
      );
    }
  };

  // ── Sub-components ────────────────────────────────────────────────────────────

  const ConnectorCard = ({ conn }: { conn: Connector }) => {
    const sp = STATUS_PROPS[conn.status] || STATUS_PROPS.inactive;
    const tr = testResults[conn.id];
    return (
      <Card
        sx={{
          bgcolor: "background.paper",
          border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 2,
          height: "100%",
        }}
      >
        <CardContent>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
            <Typography sx={{ color: "text.primary", fontWeight: 600, fontSize: 14, lineHeight: 1.4 }}>
              {conn.name}
            </Typography>
            <Chip
              size="small"
              icon={sp.icon}
              label={sp.label}
              sx={{ bgcolor: `${sp.color === "text.secondary" ? "rgba(255,255,255,0.08)" : sp.color + "20"}`, color: sp.color, fontSize: 11, flexShrink: 0, ml: 1 }}
            />
          </Box>
          <Typography variant="body2" sx={{ color: "text.secondary", mb: 1.5, fontSize: 13 }}>
            {CONNECTOR_ICONS[conn.connector_type] || conn.connector_type}
          </Typography>
          {conn.error_message && (
            <Typography variant="caption" sx={{ color: "#f44336", display: "block", mb: 1 }}>
              {conn.error_message}
            </Typography>
          )}
          {tr && (
            <Alert
              severity={tr.success ? "success" : "error"}
              sx={{ py: 0, mb: 1, fontSize: 11 }}
            >
              {tr.message}
            </Alert>
          )}
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, flexWrap: "wrap", mt: 1 }}>
            <Button
              size="small" variant="outlined" startIcon={<PlayArrow />}
              onClick={() => testMutation.mutate({ clientId: selectedClientId, connId: conn.id })}
              disabled={testMutation.isPending}
              sx={{ borderColor: "#4285F4", color: "#4285F4", fontSize: 11 }}
            >
              Test
            </Button>
            <Button
              size="small" variant="outlined" startIcon={<Edit sx={{ fontSize: 14 }} />}
              onClick={() => openEdit(conn)}
              sx={{
                borderColor: "divider", color: "text.secondary", fontSize: 11,
                "&:hover": { borderColor: "#4285F4", color: "#4285F4", bgcolor: "rgba(66,133,244,0.08)" },
              }}
            >
              Edit
            </Button>
            <Button
              size="small" variant="outlined" startIcon={<Delete sx={{ fontSize: 14 }} />}
              onClick={() => {
                if (window.confirm(`Delete connector "${conn.name}"? Linked assets stay but won't be re-synced.`)) {
                  deleteMutation.mutate(conn.id);
                }
              }}
              disabled={deleteMutation.isPending}
              sx={{
                borderColor: "rgba(244,67,54,0.4)", color: "#EA4335", fontSize: 11,
                "&:hover": { borderColor: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" },
              }}
            >
              Delete
            </Button>
          </Box>
        </CardContent>
      </Card>
    );
  };

  const SectionHeader = ({
    icon,
    title,
    subtitle,
    count,
    onAdd,
    addLabel,
    disabled,
  }: {
    icon: React.ReactNode;
    title: string;
    subtitle: string;
    count: number;
    onAdd: () => void;
    addLabel: string;
    disabled: boolean;
  }) => (
    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
        <Box sx={{
          width: 40, height: 40, borderRadius: 2,
          bgcolor: "rgba(66,133,244,0.12)", display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          {icon}
        </Box>
        <Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 16 }}>{title}</Typography>
            {count > 0 && (
              <Chip
                label={count}
                size="small"
                sx={{ height: 20, fontSize: 11, fontWeight: 700, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4" }}
              />
            )}
          </Box>
          <Typography variant="body2" sx={{ color: "text.secondary", fontSize: 12 }}>{subtitle}</Typography>
        </Box>
      </Box>
      <Button
        variant="outlined" size="small" startIcon={<Add />}
        onClick={onAdd}
        disabled={disabled}
        sx={{
          borderColor: "#4285F4", color: "#4285F4", fontSize: 12,
          "&:hover": { bgcolor: "rgba(66,133,244,0.08)" },
          "&.Mui-disabled": { borderColor: "rgba(255,255,255,0.12)", color: "text.disabled" },
        }}
      >
        {addLabel}
      </Button>
    </Box>
  );

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <Box>
      {/* ── Page header ── */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>
            Connections
          </Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            All integrations in one place — AI providers, cloud platforms, and security scanners
          </Typography>
        </Box>
        {/* Project selector */}
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 180 }} disabled={!selectedClientId}>
            <InputLabel sx={{ color: "text.secondary" }}>Project</InputLabel>
            <Select
              value={selectedProjectId}
              onChange={(e) => setSelectedProjectId(e.target.value)}
              label="Project"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
            >
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => (
                <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>
      </Box>

      {/* ══════════════════════════════════════════════════════════════════════
          SECTION 1 — AI Providers
      ══════════════════════════════════════════════════════════════════════ */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            <Box sx={{
              width: 40, height: 40, borderRadius: 2,
              bgcolor: "rgba(66,133,244,0.12)", display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <Psychology sx={{ color: "#4285F4", fontSize: 22 }} />
            </Box>
            <Box>
              <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 16 }}>AI Providers</Typography>
              <Typography variant="body2" sx={{ color: "text.secondary", fontSize: 12 }}>
                Language models powering Monitara AI agents
              </Typography>
            </Box>
          </Box>
          <Button
            variant="outlined" size="small" endIcon={<OpenInNew sx={{ fontSize: 14 }} />}
            onClick={() => navigate("/ai-settings")}
            sx={{
              borderColor: "#4285F4", color: "#4285F4", fontSize: 12,
              "&:hover": { bgcolor: "rgba(66,133,244,0.08)" },
            }}
          >
            Configure
          </Button>
        </Box>

        {/* Horizontal scrollable row of provider cards */}
        <Box sx={{ display: "flex", gap: 2, overflowX: "auto", pb: 1, "&::-webkit-scrollbar": { height: 4 }, "&::-webkit-scrollbar-thumb": { bgcolor: "rgba(255,255,255,0.15)", borderRadius: 2 } }}>
          {aiProviders.length === 0 ? (
            <Typography variant="body2" sx={{ color: "text.secondary", py: 2 }}>
              Loading AI providers…
            </Typography>
          ) : (
            aiProviders.map((provider) => {
              const isDefault = aiConfig?.default_provider === provider.provider;
              const label = PROVIDER_LOGOS[provider.provider] || provider.provider;
              return (
                <Card
                  key={provider.provider}
                  sx={{
                    bgcolor: "background.paper",
                    border: `1px solid ${provider.available ? "rgba(52,168,83,0.3)" : "rgba(255,255,255,0.08)"}`,
                    borderRadius: 2,
                    minWidth: 200,
                    flexShrink: 0,
                  }}
                >
                  <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography sx={{ color: "text.primary", fontWeight: 600, fontSize: 13 }}>
                        {label}
                      </Typography>
                      {provider.available
                        ? <CheckCircle sx={{ fontSize: 18, color: "#00e676" }} />
                        : <Cancel     sx={{ fontSize: 18, color: "#f44336" }} />
                      }
                    </Box>
                    {isDefault && (
                      <Chip
                        label="Active"
                        size="small"
                        sx={{
                          mb: 1, height: 18, fontSize: 10, fontWeight: 700,
                          bgcolor: "rgba(0,230,118,0.12)", color: "#00e676",
                        }}
                      />
                    )}
                    <Button
                      size="small" variant="text" endIcon={<OpenInNew sx={{ fontSize: 12 }} />}
                      onClick={() => navigate("/ai-settings")}
                      sx={{ color: "#4285F4", fontSize: 11, p: 0, minWidth: 0, mt: isDefault ? 0 : 1 }}
                    >
                      Configure →
                    </Button>
                  </CardContent>
                </Card>
              );
            })
          )}
        </Box>
      </Box>

      {/* ══════════════════════════════════════════════════════════════════════
          SECTION 2 — Platform Connectors
      ══════════════════════════════════════════════════════════════════════ */}
      <Box
        sx={{
          mb: 4, p: 3, borderRadius: 2,
          bgcolor: "background.paper",
          border: "1px solid",
          borderColor: "divider",
        }}
      >
        <SectionHeader
          icon={<Cloud sx={{ color: "#4285F4", fontSize: 22 }} />}
          title="Platform Connectors"
          subtitle="Cloud platforms, identity providers, and SaaS integrations"
          count={platformConnectors.length}
          onAdd={() => openAdd("platform")}
          addLabel="Add Platform Connector"
          disabled={!selectedClientId || projects.length === 0}
        />

        {!selectedClientId ? (
          <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "text.primary" }}>
            Select a client to view connectors.
          </Alert>
        ) : connectorsLoading ? (
          <CircularProgress size={24} sx={{ color: "#4285F4" }} />
        ) : platformConnectors.length === 0 ? (
          <Card
            sx={{
              bgcolor: "transparent", border: "1px dashed rgba(255,255,255,0.2)",
              borderRadius: 2, p: 4, textAlign: "center",
            }}
          >
            <Cable sx={{ fontSize: 40, color: "text.secondary", mb: 1 }} />
            <Typography sx={{ color: "text.secondary", fontSize: 14 }}>
              No platform connectors yet. Add one to start importing assets.
            </Typography>
          </Card>
        ) : (
          <Grid container spacing={2}>
            {platformConnectors.map((conn) => (
              <Grid size={{ xs: 12, sm: 6, md: 4 }} key={conn.id}>
                <ConnectorCard conn={conn} />
              </Grid>
            ))}
          </Grid>
        )}
      </Box>

      {/* ══════════════════════════════════════════════════════════════════════
          SECTION 3 — Scanners
      ══════════════════════════════════════════════════════════════════════ */}
      <Box
        sx={{
          mb: 4, p: 3, borderRadius: 2,
          bgcolor: "background.paper",
          border: "1px solid",
          borderColor: "divider",
        }}
      >
        <SectionHeader
          icon={<Hub sx={{ color: "#4285F4", fontSize: 22 }} />}
          title="Scanners"
          subtitle="Security scanners use Platform Connector credentials to find vulnerabilities"
          count={scannerConnectors.length}
          onAdd={() => openAdd("scanner")}
          addLabel="Add Scanner"
          disabled={!selectedClientId || projects.length === 0}
        />

        {!selectedClientId ? (
          <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "text.primary" }}>
            Select a client to view scanners.
          </Alert>
        ) : connectorsLoading ? (
          <CircularProgress size={24} sx={{ color: "#4285F4" }} />
        ) : scannerConnectors.length === 0 ? (
          <Card
            sx={{
              bgcolor: "transparent", border: "1px dashed rgba(255,255,255,0.2)",
              borderRadius: 2, p: 4, textAlign: "center",
            }}
          >
            <Hub sx={{ fontSize: 40, color: "text.secondary", mb: 1 }} />
            <Typography sx={{ color: "text.secondary", fontSize: 14 }}>
              No scanners yet. Add one to start running security scans.
            </Typography>
          </Card>
        ) : (
          <Box>
            {SCANNER_CATEGORIES.map((cat) => {
              const group = scannerConnectors.filter((c) => CONNECTOR_CATEGORY[c.connector_type] === cat);
              if (group.length === 0) return null;
              return (
                <Box key={cat} sx={{ mb: 3 }}>
                  {/* Category sub-header */}
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                    <Typography sx={{
                      color: "text.secondary", fontWeight: 700, fontSize: 12,
                      textTransform: "uppercase", letterSpacing: 1,
                    }}>
                      {CATEGORY_LABEL[cat]}
                    </Typography>
                    <Chip
                      label={group.length}
                      size="small"
                      sx={{ height: 18, fontSize: 10, fontWeight: 700, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4" }}
                    />
                    <Box sx={{ flex: 1, height: 1, bgcolor: "rgba(255,255,255,0.08)" }} />
                  </Box>
                  <Grid container spacing={2}>
                    {group.map((conn) => (
                      <Grid size={{ xs: 12, sm: 6, md: 4 }} key={conn.id}>
                        <ConnectorCard conn={conn} />
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              );
            })}
          </Box>
        )}
      </Box>

      {/* ══════════════════════════════════════════════════════════════════════
          CRUD Dialog (shared for platform + scanner)
      ══════════════════════════════════════════════════════════════════════ */}
      <Dialog
        open={open}
        onClose={closeDialog}
        slotProps={{
          paper: {
            sx: { bgcolor: "background.paper", color: "text.primary", minWidth: 520, maxWidth: 640 },
          },
        }}
      >
        <DialogTitle>
          {editing
            ? `Edit Connector — ${editing.name}`
            : addMode === "platform"
              ? "Add Platform Connector"
              : "Add Scanner"}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 0.5 }}>
            {/* Type picker */}
            <Grid size={{ xs: 12, sm: 6 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "text.secondary" }}>Type</InputLabel>
                <Select
                  value={connectorType}
                  onChange={(e) => {
                    setConnectorType(e.target.value as ConnectorType);
                    setCredentials({});
                    setWebTargetUrl(""); setWebAuthMethod("none"); setWebAuth({}); setWebExcludes("");
                  }}
                  label="Type"
                  sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                >
                  {dialogTypeOptions.map(([k, v]) => (
                    <MenuItem key={k} value={k}>{v}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            {/* Name */}
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField
                fullWidth size="small" label="Connector Name"
                value={connName} onChange={(e) => setConnName(e.target.value)}
                slotProps={{
                  inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } },
                  htmlInput:  { style: { color: "white" } },
                }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
              />
            </Grid>

            {/* Project */}
            <Grid size={{ xs: 12 }}>
              <FormControl fullWidth size="small" required>
                <InputLabel sx={{ color: "text.secondary" }}>Project</InputLabel>
                <Select
                  value={connProjectId}
                  onChange={(e) => setConnProjectId(e.target.value)}
                  label="Project"
                  sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                >
                  {projects.map((p) => (
                    <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>

            {/* Type help banner */}
            {connectorType !== "web" && TYPE_HELP[connectorType] && (
              <Grid size={{ xs: 12 }}>
                <Alert
                  severity="info"
                  sx={{
                    bgcolor: "rgba(66,133,244,0.08)", color: "text.secondary",
                    border: "1px solid rgba(66,133,244,0.25)",
                    "& .MuiAlert-icon": { color: "#4285F4" },
                  }}
                >
                  {TYPE_HELP[connectorType]}
                </Alert>
              </Grid>
            )}

            {/* Standard credential fields */}
            {connectorType !== "web" &&
              credFields.map(({ key, label, secret, placeholder, help }) => (
                <Grid size={{ xs: 12 }} key={key}>
                  <TextField
                    fullWidth size="small" label={label}
                    type={secret ? "password" : "text"}
                    placeholder={placeholder}
                    helperText={help}
                    value={credentials[key] || ""}
                    onChange={(e) => setCredentials({ ...credentials, [key]: e.target.value })}
                    slotProps={{
                      inputLabel:    { sx: { color: "rgba(255,255,255,0.5)" } },
                      htmlInput:     { style: { color: "white" } },
                      formHelperText:{ sx: { color: "text.secondary", fontSize: 11 } },
                    }}
                    sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                  />
                </Grid>
              ))
            }

            {/* Web (ZAP) connector — special form */}
            {connectorType === "web" && (
              <>
                <Grid size={{ xs: 12 }}>
                  <TextField
                    fullWidth size="small" label="Target URL"
                    placeholder="https://app.example.com"
                    value={webTargetUrl} onChange={(e) => setWebTargetUrl(e.target.value)}
                    slotProps={{
                      inputLabel: { sx: { color: "text.secondary" } },
                      htmlInput:  { style: { color: "white" } },
                    }}
                    sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                  />
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <FormControl fullWidth size="small">
                    <InputLabel sx={{ color: "text.secondary" }}>Default scan profile</InputLabel>
                    <Select
                      value={webProfile} label="Default scan profile"
                      onChange={(e) => setWebProfile(e.target.value as "baseline" | "active")}
                      sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                    >
                      <MenuItem value="baseline">Baseline — passive crawl (~5 min, safe)</MenuItem>
                      <MenuItem value="active">Active — attack scan (~30 min, intrusive)</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <FormControl fullWidth size="small">
                    <InputLabel sx={{ color: "text.secondary" }}>Authentication</InputLabel>
                    <Select
                      value={webAuthMethod} label="Authentication"
                      onChange={(e) => { setWebAuthMethod(e.target.value as any); setWebAuth({}); }}
                      sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                    >
                      <MenuItem value="none">None — unauthenticated scan</MenuItem>
                      <MenuItem value="bearer">Bearer token (API)</MenuItem>
                      <MenuItem value="cookie">Cookie</MenuItem>
                      <MenuItem value="form">Form login</MenuItem>
                      <MenuItem value="oauth_client_credentials">OAuth (client_credentials)</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>

                {webAuthMethod === "bearer" && (
                  <Grid size={{ xs: 12 }}>
                    <TextField
                      fullWidth size="small" type="password" label="Bearer token"
                      value={webAuth.token || ""} onChange={(e) => setWebAuth({ ...webAuth, token: e.target.value })}
                      slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                      sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                    />
                  </Grid>
                )}

                {webAuthMethod === "cookie" && (
                  <>
                    <Grid size={{ xs: 12, sm: 5 }}>
                      <TextField
                        fullWidth size="small" label="Cookie name" placeholder="sessionid"
                        value={webAuth.cookie_name || ""} onChange={(e) => setWebAuth({ ...webAuth, cookie_name: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 7 }}>
                      <TextField
                        fullWidth size="small" type="password" label="Cookie value"
                        value={webAuth.cookie_value || ""} onChange={(e) => setWebAuth({ ...webAuth, cookie_value: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    </Grid>
                  </>
                )}

                {webAuthMethod === "form" && (
                  <>
                    <Grid size={{ xs: 12 }}>
                      <TextField
                        fullWidth size="small" label="Login URL" placeholder="https://app.example.com/login"
                        value={webAuth.login_url || ""} onChange={(e) => setWebAuth({ ...webAuth, login_url: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField
                        fullWidth size="small" label="Username"
                        value={webAuth.username || ""} onChange={(e) => setWebAuth({ ...webAuth, username: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField
                        fullWidth size="small" type="password" label="Password"
                        value={webAuth.password || ""} onChange={(e) => setWebAuth({ ...webAuth, password: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField
                        fullWidth size="small" label="Username field name" placeholder="username"
                        value={webAuth.username_field || ""} onChange={(e) => setWebAuth({ ...webAuth, username_field: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField
                        fullWidth size="small" label="Password field name" placeholder="password"
                        value={webAuth.password_field || ""} onChange={(e) => setWebAuth({ ...webAuth, password_field: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    </Grid>
                  </>
                )}

                {webAuthMethod === "oauth_client_credentials" && (
                  <>
                    <Grid size={{ xs: 12 }}>
                      <TextField
                        fullWidth size="small" label="Token endpoint URL"
                        placeholder="https://login.example.com/oauth/token"
                        value={webAuth.token_url || ""} onChange={(e) => setWebAuth({ ...webAuth, token_url: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField
                        fullWidth size="small" label="Client ID"
                        value={webAuth.client_id || ""} onChange={(e) => setWebAuth({ ...webAuth, client_id: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField
                        fullWidth size="small" type="password" label="Client secret"
                        value={webAuth.client_secret || ""} onChange={(e) => setWebAuth({ ...webAuth, client_secret: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    </Grid>
                    <Grid size={{ xs: 12 }}>
                      <TextField
                        fullWidth size="small" label="Scope (optional)" placeholder="api:read"
                        value={webAuth.scope || ""} onChange={(e) => setWebAuth({ ...webAuth, scope: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      />
                    </Grid>
                  </>
                )}

                <Grid size={{ xs: 12 }}>
                  <TextField
                    fullWidth size="small" multiline minRows={2}
                    label="Exclude paths (one per line, optional)"
                    placeholder={"/logout\n/payment"}
                    value={webExcludes} onChange={(e) => setWebExcludes(e.target.value)}
                    slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "white" } } }}
                    sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                  />
                </Grid>
              </>
            )}
          </Grid>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={closeDialog} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button
            variant="contained"
            disabled={
              !connName || !connProjectId || createMutation.isPending ||
              (connectorType === "web" && !webTargetUrl.trim())
            }
            onClick={handleSave}
            sx={{ bgcolor: "#4285F4", color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}
          >
            {createMutation.isPending ? <CircularProgress size={18} /> : "Save"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
