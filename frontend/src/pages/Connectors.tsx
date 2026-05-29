import React, { useState } from "react";
import {
  Box, Typography, Button, Card, CardContent, Grid, Chip,
  Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, Select, MenuItem, FormControl, InputLabel,
  CircularProgress, Alert,
} from "@mui/material";
import { Add, PlayArrow, CheckCircle, Error, HourglassEmpty, Cable, Edit, Delete } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { connectorsApi, clientsApi, projectsApi } from "../services/api";
import { Connector, ConnectorType, Client, Project } from "../types";
import { toast } from "react-toastify";

const CONNECTOR_ICONS: Record<ConnectorType, string> = {
  azure: "☁️ Azure", aws: "🟠 AWS", gcp: "🔵 GCP",
  onprem: "🖥️ On-Premises", servicenow: "🟣 ServiceNow",
  okta: "🔑 Okta", entraid: "🆔 Entra ID",
  containers: "🐳 Containers", github: "🐙 GitHub", jira: "📋 Jira",
  web: "🌐 Web App (ZAP)",
  // SAST
  semgrep: "🔍 Semgrep", codeql: "🧬 CodeQL", sonarqube: "📊 SonarQube",
  // Network
  nmap: "📡 NMAP", openvas: "🛰️ OpenVAS", trivy: "🏷️ Trivy",
  // Dependency & Secret
  owasp_dc: "📦 OWASP Dep-Check", gitleaks: "💧 Gitleaks", trufflehog: "🐷 TruffleHog",
};

type CredField = {
  key: string; label: string; secret?: boolean;
  placeholder?: string; help?: string;
};
const CREDENTIAL_FIELDS: Record<ConnectorType, CredField[]> = {
  azure: [
    { key: "tenant_id", label: "Tenant ID" },
    { key: "client_id", label: "Client ID" },
    { key: "client_secret", label: "Client Secret", secret: true },
    { key: "subscription_id", label: "Subscription ID" },
  ],
  aws: [
    { key: "access_key_id", label: "Access Key ID" },
    { key: "secret_access_key", label: "Secret Access Key", secret: true },
    { key: "role_arn", label: "Role ARN (optional)" },
  ],
  gcp: [
    { key: "project_id", label: "Project ID" },
    { key: "service_account_json", label: "Service Account JSON", secret: true },
  ],
  onprem: [
    { key: "nessus_url", label: "Nessus URL" },
    { key: "nessus_api_key", label: "API Key", secret: true },
    { key: "nessus_secret_key", label: "Secret Key", secret: true },
  ],
  servicenow: [
    { key: "instance_url", label: "Instance URL (https://xxx.service-now.com)" },
    { key: "username", label: "Username" },
    { key: "password", label: "Password", secret: true },
  ],
  okta: [
    { key: "domain", label: "Okta Domain (xxx.okta.com)" },
    { key: "api_token", label: "API Token", secret: true },
  ],
  entraid: [
    { key: "tenant_id", label: "Tenant ID" },
    { key: "client_id", label: "App Registration Client ID" },
    { key: "client_secret", label: "Client Secret", secret: true },
  ],
  containers: [
    { key: "api_server", label: "Kubernetes API Server URL" },
    { key: "token", label: "Bearer Token", secret: true },
  ],
  github: [
    { key: "token", label: "Personal Access Token", secret: true },
    { key: "org", label: "Organisation" },
  ],
  jira: [
    { key: "url", label: "Jira URL" },
    { key: "email", label: "Email" },
    { key: "api_token", label: "API Token", secret: true },
  ],
  // Web connector handles its own form (target URL + auth method picker
  // with conditional fields), so no static credential fields here.
  web: [],
  // SAST — most just need a repo URL. Add git_username + git_token for
  // private repos. The clone URL will be rewritten with the PAT at runtime.
  semgrep: [
    { key: "repo_url", label: "Git Repo URL", placeholder: "https://github.com/org/repo",
      help: "HTTPS clone URL. Public repos work as-is; private repos also need the token below." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token",
      help: "For GitHub PATs use 'x-access-token' (default). For Azure DevOps use any non-empty string." },
    { key: "git_token", label: "Git Personal Access Token", secret: true,
      placeholder: "ghp_…",
      help: "Required for private repos. GitHub: scope 'repo' (read). Azure DevOps: 'Code (Read)'." },
  ],
  codeql: [
    { key: "repo_url", label: "Git Repo URL", placeholder: "https://github.com/org/repo",
      help: "HTTPS clone URL. CodeQL works best on GitHub-hosted repos." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token" },
    { key: "git_token", label: "Git Personal Access Token", secret: true,
      placeholder: "ghp_…",
      help: "Required for private repos. Scope 'repo' for code-read; 'security_events' if writing back SARIF." },
  ],
  sonarqube: [
    { key: "repo_url", label: "Git Repo URL (optional for SonarCloud)",
      placeholder: "https://github.com/org/repo",
      help: "Leave blank if SonarCloud will pull from its own integration." },
    { key: "sonar_host_url", label: "SonarQube Host URL",
      placeholder: "https://sonar.example.com",
      help: "Use https://sonarcloud.io for SonarCloud Enterprise." },
    { key: "sonar_project_key", label: "SonarQube Project Key",
      placeholder: "org_repo",
      help: "The unique projectKey from your SonarQube/SonarCloud project settings." },
    { key: "sonar_token", label: "Sonar Token", secret: true,
      placeholder: "sqp_… or squ_…",
      help: "User token from My Account → Security in Sonar." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token" },
    { key: "git_token", label: "Git Personal Access Token", secret: true },
  ],
  // Network
  nmap: [
    { key: "target", label: "Target host / IP / CIDR",
      placeholder: "10.0.0.0/24  or  scanme.nmap.org",
      help: "Single host, IP, or CIDR range. Authorisation required — never scan systems you don't own." },
  ],
  openvas: [
    { key: "target", label: "Target host / IP / CIDR",
      placeholder: "10.0.1.5  or  192.168.1.0/24",
      help: "Greenbone/OpenVAS scans this target with the default vulnerability profile." },
  ],
  trivy: [
    { key: "image", label: "Container image (optional)",
      placeholder: "ghcr.io/org/app:1.2.3  or  ubuntu:22.04",
      help: "Provide an image to scan a container; or use repo_url below for IaC/filesystem scans." },
    { key: "repo_url", label: "Git Repo URL (alternative to image)",
      placeholder: "https://github.com/org/repo" },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token" },
    { key: "git_token", label: "Git Personal Access Token", secret: true },
  ],
  // Dependency & Secret
  owasp_dc: [
    { key: "repo_url", label: "Git Repo URL",
      placeholder: "https://github.com/org/repo",
      help: "OWASP Dependency-Check runs against the cloned repo's manifests (pom.xml, package.json, etc.)." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token" },
    { key: "git_token", label: "Git Personal Access Token", secret: true },
  ],
  gitleaks: [
    { key: "repo_url", label: "Git Repo URL",
      placeholder: "https://github.com/org/repo",
      help: "Full git history is scanned for committed secrets — clone is non-shallow." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token" },
    { key: "git_token", label: "Git Personal Access Token", secret: true,
      placeholder: "ghp_…",
      help: "Required for private repos. Scope 'repo' (read) — Gitleaks doesn't push anything back." },
  ],
  trufflehog: [
    { key: "repo_url", label: "Git Repo URL",
      placeholder: "https://github.com/org/repo",
      help: "TruffleHog walks git history; verified secrets (where it can ping the issuer) are flagged critical." },
    { key: "git_username", label: "Git Username", placeholder: "x-access-token" },
    { key: "git_token", label: "Git Personal Access Token", secret: true,
      placeholder: "ghp_…" },
  ],
};

// Top-of-dialog quick-setup guidance per connector type. Shown above the form.
const TYPE_HELP: Partial<Record<ConnectorType, string>> = {
  semgrep: "Point at a Git repo URL. For private repos, paste a PAT below. Semgrep runs `--config auto` (curated security rules) inside GitHub Actions.",
  codeql: "GitHub-hosted repos work best. CodeQL workflow is not yet wired — the connector saves and tests, but Run will be enabled in a future release.",
  sonarqube: "Either point at a self-hosted SonarQube server, or use SonarCloud (host=https://sonarcloud.io). Workflow coming soon.",
  nmap: "Scan a single host, IP, or CIDR. Requires explicit written authorisation from the network owner. Workflow coming soon.",
  openvas: "Greenbone/OpenVAS scans the target IP/CIDR with the default profile. Workflow coming soon.",
  trivy: "Provide either a container image OR a Git repo URL. Image scans hit the registry; repo scans pull manifests + IaC for misconfigs and CVEs.",
  owasp_dc: "Scans dependency manifests in the cloned repo. Workflow coming soon.",
  gitleaks: "Walks the full git history for committed secrets. Public repos work without auth; private repos need a PAT.",
  trufflehog: "Walks the full git history with high-fidelity verification. Verified secrets (where TruffleHog can ping the issuer) are flagged critical.",
};

// Connector → category mapping (mirrors backend CONNECTOR_CATEGORY).
// Drives the section grouping on the Connectors page.
const CONNECTOR_CATEGORY: Record<ConnectorType, string> = {
  azure: "cloud", aws: "cloud", gcp: "cloud", onprem: "cloud",
  servicenow: "cloud", okta: "cloud", entraid: "cloud",
  containers: "cloud", github: "cloud", jira: "cloud",
  web: "dast",
  semgrep: "sast", codeql: "sast", sonarqube: "sast",
  nmap: "network", openvas: "network", trivy: "network",
  owasp_dc: "dependency", gitleaks: "dependency", trufflehog: "dependency",
};

const CATEGORY_LABEL: Record<string, string> = {
  cloud: "Cloud & Identity",
  dast: "DAST — Dynamic AppSec",
  sast: "SAST — Static AppSec",
  network: "Network & Infrastructure",
  dependency: "Dependency & Secret",
};

const CATEGORY_ORDER = ["cloud", "dast", "sast", "network", "dependency"] as const;

const STATUS_PROPS: Record<string, any> = {
  active: { icon: <CheckCircle sx={{ fontSize: 16 }} />, color: "#00e676", label: "Active" },
  error: { icon: <Error sx={{ fontSize: 16 }} />, color: "#f44336", label: "Error" },
  pending: { icon: <HourglassEmpty sx={{ fontSize: 16 }} />, color: "#ff9800", label: "Pending" },
  inactive: { icon: <Cable sx={{ fontSize: 16 }} />, color: "rgba(255,255,255,0.3)", label: "Inactive" },
};

export default function Connectors() {
  const qc = useQueryClient();
  const [selectedClientId, setSelectedClientId] = useState("");
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [open, setOpen] = useState(false);
  const [connectorType, setConnectorType] = useState<ConnectorType>("azure");
  const [connName, setConnName] = useState("");
  const [connProjectId, setConnProjectId] = useState("");
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [testResults, setTestResults] = useState<Record<string, any>>({});
  // Web (ZAP) connector — kept separate because its shape doesn't fit the
  // flat credentials map: target_url + default_profile go in `config`, and
  // auth lives under `credentials.auth = { method, ...method-specific }`.
  const [webTargetUrl, setWebTargetUrl] = useState("");
  const [webProfile, setWebProfile] = useState<"baseline" | "active">("baseline");
  const [webAuthMethod, setWebAuthMethod] = useState<"none" | "bearer" | "cookie" | "form" | "oauth_client_credentials">("none");
  const [webAuth, setWebAuth] = useState<Record<string, string>>({});
  const [webExcludes, setWebExcludes] = useState("");  // newline-separated

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", selectedClientId],
    queryFn: () => projectsApi.list(selectedClientId),
    enabled: !!selectedClientId,
  });
  const { data: connectors = [], isLoading } = useQuery<Connector[]>({
    queryKey: ["connectors", selectedClientId, selectedProjectId],
    queryFn: () => connectorsApi.list(selectedClientId, selectedProjectId || undefined),
    enabled: !!selectedClientId,
  });

  const [editing, setEditing] = useState<Connector | null>(null);

  const createMutation = useMutation({
    mutationFn: (data: any) => editing
      ? connectorsApi.update(selectedClientId, editing.id, data)
      : connectorsApi.create(selectedClientId, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["connectors"] });
      setOpen(false);
      setEditing(null);
      setConnName("");
      setCredentials({});
      toast.success(editing ? "Connector updated" : "Connector added");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error"),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => connectorsApi.delete(selectedClientId, id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["connectors"] }); toast.success("Connector deleted"); },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error"),
  });

  const openEdit = (c: Connector) => {
    setEditing(c);
    setConnName(c.name);
    setConnectorType(c.connector_type);
    setConnProjectId(c.project_id || "");
    setCredentials({});  // don't pre-fill credentials; user enters new ones if rotating
    setOpen(true);
  };

  const testMutation = useMutation({
    mutationFn: ({ clientId, connId }: any) => connectorsApi.test(clientId, connId),
    onSuccess: (data, vars) => { setTestResults(prev => ({ ...prev, [vars.connId]: data })); qc.invalidateQueries({ queryKey: ["connectors"] }); },
    onError: (e: any, vars) => setTestResults(prev => ({ ...prev, [vars.connId]: { success: false, message: e.message } })),
  });

  const credFields = CREDENTIAL_FIELDS[connectorType] || [];

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Connectors</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>Connect cloud platforms, identity providers, and SaaS tools</Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1 }}>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Select Client</InputLabel>
            <Select value={selectedClientId} onChange={(e) => setSelectedClientId(e.target.value)} label="Select Client"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 180 }} disabled={!selectedClientId}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Project</InputLabel>
            <Select value={selectedProjectId} onChange={(e) => setSelectedProjectId(e.target.value)} label="Project"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
            </Select>
          </FormControl>
          <Button variant="contained" startIcon={<Add />} disabled={!selectedClientId || projects.length === 0}
            onClick={() => {
              // Important: reset editing state so the dialog runs in "create"
              // mode. Without this, a previous edit leaves `editing` set and
              // the next Save fires a PATCH against the stale connector ID
              // — produces a 404 if that connector was since deleted or
              // belonged to a different client.
              setEditing(null);
              setConnName("");
              setConnectorType("azure");
              setCredentials({});
              setTestResults({});
              setWebTargetUrl("");
              setWebProfile("baseline");
              setWebAuthMethod("none");
              setWebAuth({});
              setWebExcludes("");
              setConnProjectId(selectedProjectId || projects[0]?.id || "");
              setOpen(true);
            }}
            sx={{ bgcolor: "#4285F4", color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}>
            Add Connector
          </Button>
        </Box>
      </Box>

      {!selectedClientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "white" }}>Select a client to view and manage its connectors.</Alert>
      ) : isLoading ? (
        <CircularProgress sx={{ color: "#4285F4" }} />
      ) : connectors.length === 0 ? (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
          <Cable sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
          <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>No connectors. Add one to start scanning.</Typography>
        </Card>
      ) : (
        <Box>
          {CATEGORY_ORDER.map((cat) => {
            const group = connectors.filter((c) => CONNECTOR_CATEGORY[c.connector_type] === cat);
            if (group.length === 0) return null;
            return (
              <Box key={cat} sx={{ mb: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                  <Typography sx={{ color: "rgba(255,255,255,0.85)", fontWeight: 700, fontSize: 13, textTransform: "uppercase", letterSpacing: 1 }}>
                    {CATEGORY_LABEL[cat]}
                  </Typography>
                  <Chip
                    label={group.length}
                    size="small"
                    sx={{
                      height: 20, fontSize: 11, fontWeight: 700,
                      bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4",
                    }}
                  />
                  <Box sx={{ flex: 1, height: 1, bgcolor: "rgba(255,255,255,0.08)" }} />
                </Box>
                <Grid container spacing={2}>
                  {group.map((conn) => {
                    const sp = STATUS_PROPS[conn.status] || STATUS_PROPS.inactive;
                    const tr = testResults[conn.id];
                    return (
                      <Grid size={{ xs: 12, sm: 6, md: 4 }} key={conn.id}>
                        <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
                          <CardContent>
                            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
                              <Typography sx={{ color: "white", fontWeight: 600 }}>{conn.name}</Typography>
                              <Chip size="small" icon={sp.icon} label={sp.label}
                                sx={{ bgcolor: `${sp.color}20`, color: sp.color, fontSize: 11 }} />
                            </Box>
                            <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)", mb: 1.5 }}>
                              {CONNECTOR_ICONS[conn.connector_type] || conn.connector_type}
                            </Typography>
                            {conn.error_message && (
                              <Typography variant="caption" sx={{ color: "#f44336", display: "block", mb: 1 }}>{conn.error_message}</Typography>
                            )}
                            {tr && (
                              <Alert severity={tr.success ? "success" : "error"} sx={{ py: 0, mb: 1, fontSize: 11 }}>{tr.message}</Alert>
                            )}
                            <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, flexWrap: "wrap" }}>
                              <Button size="small" variant="outlined" startIcon={<PlayArrow />}
                                onClick={() => testMutation.mutate({ clientId: selectedClientId, connId: conn.id })}
                                disabled={testMutation.isPending}
                                sx={{ borderColor: "#4285F4", color: "#4285F4", fontSize: 11 }}>
                                Test
                              </Button>
                              <Button size="small" variant="outlined" startIcon={<Edit sx={{ fontSize: 14 }} />}
                                onClick={() => openEdit(conn)}
                                sx={{ borderColor: "rgba(255,255,255,0.2)", color: "rgba(255,255,255,0.85)", fontSize: 11,
                                  "&:hover": { borderColor: "#4285F4", color: "#4285F4", bgcolor: "rgba(66,133,244,0.08)" } }}>
                                Edit
                              </Button>
                              <Button size="small" variant="outlined" startIcon={<Delete sx={{ fontSize: 14 }} />}
                                onClick={() => {
                                  if (window.confirm(`Delete connector "${conn.name}"? Linked assets stay but won't be re-synced.`)) {
                                    deleteMutation.mutate(conn.id);
                                  }
                                }}
                                disabled={deleteMutation.isPending}
                                sx={{ borderColor: "rgba(244,67,54,0.4)", color: "#EA4335", fontSize: 11,
                                  "&:hover": { borderColor: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" } }}>
                                Delete
                              </Button>
                            </Box>
                          </CardContent>
                        </Card>
                      </Grid>
                    );
                  })}
                </Grid>
              </Box>
            );
          })}
        </Box>
      )}

      {/* Add Connector Dialog */}
      <Dialog open={open} onClose={() => { setOpen(false); setEditing(null); }} slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white", minWidth: 520 } } }}>
        <DialogTitle>{editing ? `Edit Connector — ${editing.name}` : "Add Connector"}</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 0.5 }}>
            <Grid size={{ xs: 12, sm: 6 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Type</InputLabel>
                <Select value={connectorType} onChange={(e) => {
                    setConnectorType(e.target.value as ConnectorType);
                    setCredentials({});
                    setWebTargetUrl(""); setWebAuthMethod("none"); setWebAuth({}); setWebExcludes("");
                  }}
                  label="Type" sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                  {Object.entries(CONNECTOR_ICONS).map(([k, v]) => <MenuItem key={k} value={k}>{v}</MenuItem>)}
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="Connector Name" value={connName} onChange={(e) => setConnName(e.target.value)}
                slotProps={{ inputLabel: { sx: { color: 'rgba(255,255,255,0.5)' } }, htmlInput: { style: { color: 'white' } } }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <FormControl fullWidth size="small" required>
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Project</InputLabel>
                <Select value={connProjectId} onChange={(e) => setConnProjectId(e.target.value)} label="Project"
                  sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                  {projects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
                </Select>
              </FormControl>
            </Grid>
            {connectorType !== "web" && TYPE_HELP[connectorType] && (
              <Grid size={{ xs: 12 }}>
                <Alert severity="info"
                  sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "rgba(255,255,255,0.85)",
                    border: "1px solid rgba(66,133,244,0.25)",
                    "& .MuiAlert-icon": { color: "#4285F4" } }}>
                  {TYPE_HELP[connectorType]}
                </Alert>
              </Grid>
            )}
            {connectorType !== "web" && credFields.map(({ key, label, secret, placeholder, help }) => (
              <Grid size={{ xs: 12 }} key={key}>
                <TextField fullWidth size="small" label={label} type={secret ? "password" : "text"}
                  placeholder={placeholder}
                  helperText={help}
                  value={credentials[key] || ""} onChange={(e) => setCredentials({ ...credentials, [key]: e.target.value })}
                  slotProps={{
                    inputLabel: { sx: { color: 'rgba(255,255,255,0.5)' } },
                    htmlInput: { style: { color: 'white' } },
                    formHelperText: { sx: { color: "rgba(255,255,255,0.45)", fontSize: 11 } },
                  }}
                  sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
              </Grid>
            ))}

            {connectorType === "web" && (
              <>
                <Grid size={{ xs: 12 }}>
                  <TextField fullWidth size="small" label="Target URL"
                    placeholder="https://app.example.com"
                    value={webTargetUrl} onChange={(e) => setWebTargetUrl(e.target.value)}
                    slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                    sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <FormControl fullWidth size="small">
                    <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Default scan profile</InputLabel>
                    <Select value={webProfile} label="Default scan profile"
                      onChange={(e) => setWebProfile(e.target.value as "baseline" | "active")}
                      sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                      <MenuItem value="baseline">Baseline — passive crawl (~5 min, safe)</MenuItem>
                      <MenuItem value="active">Active — attack scan (~30 min, intrusive)</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }}>
                  <FormControl fullWidth size="small">
                    <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Authentication</InputLabel>
                    <Select value={webAuthMethod} label="Authentication"
                      onChange={(e) => { setWebAuthMethod(e.target.value as any); setWebAuth({}); }}
                      sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
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
                    <TextField fullWidth size="small" type="password" label="Bearer token"
                      value={webAuth.token || ""} onChange={(e) => setWebAuth({ ...webAuth, token: e.target.value })}
                      slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                      sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                  </Grid>
                )}

                {webAuthMethod === "cookie" && (
                  <>
                    <Grid size={{ xs: 12, sm: 5 }}>
                      <TextField fullWidth size="small" label="Cookie name" placeholder="sessionid"
                        value={webAuth.cookie_name || ""} onChange={(e) => setWebAuth({ ...webAuth, cookie_name: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 7 }}>
                      <TextField fullWidth size="small" type="password" label="Cookie value"
                        value={webAuth.cookie_value || ""} onChange={(e) => setWebAuth({ ...webAuth, cookie_value: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                    </Grid>
                  </>
                )}

                {webAuthMethod === "form" && (
                  <>
                    <Grid size={{ xs: 12 }}>
                      <TextField fullWidth size="small" label="Login URL" placeholder="https://app.example.com/login"
                        value={webAuth.login_url || ""} onChange={(e) => setWebAuth({ ...webAuth, login_url: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField fullWidth size="small" label="Username"
                        value={webAuth.username || ""} onChange={(e) => setWebAuth({ ...webAuth, username: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField fullWidth size="small" type="password" label="Password"
                        value={webAuth.password || ""} onChange={(e) => setWebAuth({ ...webAuth, password: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField fullWidth size="small" label="Username field name" placeholder="username"
                        value={webAuth.username_field || ""} onChange={(e) => setWebAuth({ ...webAuth, username_field: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField fullWidth size="small" label="Password field name" placeholder="password"
                        value={webAuth.password_field || ""} onChange={(e) => setWebAuth({ ...webAuth, password_field: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                    </Grid>
                  </>
                )}

                {webAuthMethod === "oauth_client_credentials" && (
                  <>
                    <Grid size={{ xs: 12 }}>
                      <TextField fullWidth size="small" label="Token endpoint URL"
                        placeholder="https://login.example.com/oauth/token"
                        value={webAuth.token_url || ""} onChange={(e) => setWebAuth({ ...webAuth, token_url: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField fullWidth size="small" label="Client ID"
                        value={webAuth.client_id || ""} onChange={(e) => setWebAuth({ ...webAuth, client_id: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                    </Grid>
                    <Grid size={{ xs: 12, sm: 6 }}>
                      <TextField fullWidth size="small" type="password" label="Client secret"
                        value={webAuth.client_secret || ""} onChange={(e) => setWebAuth({ ...webAuth, client_secret: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                    </Grid>
                    <Grid size={{ xs: 12 }}>
                      <TextField fullWidth size="small" label="Scope (optional)" placeholder="api:read"
                        value={webAuth.scope || ""} onChange={(e) => setWebAuth({ ...webAuth, scope: e.target.value })}
                        slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                        sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                    </Grid>
                  </>
                )}

                <Grid size={{ xs: 12 }}>
                  <TextField fullWidth size="small" multiline minRows={2}
                    label="Exclude paths (one per line, optional)"
                    placeholder={"/logout\n/payment"}
                    value={webExcludes} onChange={(e) => setWebExcludes(e.target.value)}
                    slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                    sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                </Grid>
              </>
            )}
          </Grid>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setOpen(false)} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
          <Button variant="contained"
            disabled={!connName || !connProjectId || createMutation.isPending
              || (connectorType === "web" && !webTargetUrl.trim())}
            onClick={() => {
              if (connectorType === "web") {
                const exclude_paths = webExcludes.split("\n").map((s) => s.trim()).filter(Boolean);
                const config = {
                  target_url: webTargetUrl.trim(),
                  default_profile: webProfile,
                  ...(exclude_paths.length ? { exclude_paths } : {}),
                };
                const creds = { auth: { method: webAuthMethod, ...webAuth } };
                createMutation.mutate(editing
                  ? { name: connName, project_id: connProjectId, credentials: creds, config }
                  : { name: connName, connector_type: connectorType, project_id: connProjectId, credentials: creds, config });
              } else {
                createMutation.mutate(editing
                  ? { name: connName, project_id: connProjectId, ...(Object.keys(credentials).length ? { credentials } : {}) }
                  : { name: connName, connector_type: connectorType, project_id: connProjectId, credentials });
              }
            }}
            sx={{ bgcolor: "#4285F4", color: "#000" }}>
            {createMutation.isPending ? <CircularProgress size={18} /> : "Save"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
