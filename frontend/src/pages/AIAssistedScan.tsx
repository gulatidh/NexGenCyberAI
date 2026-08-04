import React, { useEffect, useRef, useState } from "react";
import {
  Accordion, AccordionDetails, AccordionSummary,
  Alert, Box, Button, Card, CardActionArea, CardContent,
  Chip, CircularProgress, Collapse, FormControl, IconButton,
  InputLabel, List, ListItem, ListItemIcon, ListItemText,
  MenuItem, Paper, Radio, Select, TextField, Tooltip, Typography,
} from "@mui/material";
import {
  AccountTree, ArrowBack, Business, CheckCircle, Cloud, Code,
  Edit, ExpandMore, HourglassEmpty, Inventory2, Key,
  Language, Psychology, RadioButtonUnchecked, RocketLaunch,
  Router, Send, SmartToy,
} from "@mui/icons-material";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useActiveClient } from "../contexts/ClientContext";
import { apiClient, assetsApi, connectorsApi } from "../services/api";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface ScanState {
  phase: string;
  connector_type: string | null;
  connector_id: string | null;
  scan_name: string | null;
  target: string | null;
  framework: string | null;
  ready_to_launch: boolean;
}

interface AgentRec {
  agent_type: string;
  display_name: string;
  reason: string;
  priority: number;
}

type WizardPhase = "category" | "scanner" | "target" | "framework" | "confirm" | "launched";

interface WizardState {
  phase: WizardPhase;
  categoryId: string | null;
  connector: any | null;
  target: string | null;
  targetIsCustom: boolean;
  framework: string | null;
  scanName: string | null;
}

// ── Credential schema ─────────────────────────────────────────────────────────

interface CredField { k: string; l: string; pw?: boolean; req?: boolean; hint?: string; multiline?: boolean }

const CREDENTIAL_SCHEMA: Record<string, CredField[]> = {
  azure: [{k:"subscription_id",l:"Subscription ID",req:true},{k:"tenant_id",l:"Tenant ID",req:true},{k:"client_id",l:"Client ID (App ID)",req:true},{k:"client_secret",l:"Client Secret",pw:true,req:true}],
  aws: [{k:"access_key_id",l:"Access Key ID",req:true},{k:"secret_access_key",l:"Secret Access Key",pw:true,req:true},{k:"region",l:"Region",hint:"e.g. us-east-1"}],
  gcp: [{k:"project_id",l:"Project ID",req:true},{k:"service_account_json",l:"Service Account JSON",pw:true,multiline:true,hint:"Paste JSON key file content"}],
  web: [{k:"target_url",l:"Target URL",hint:"https://example.com",req:true}],
  nmap: [],
  openvas: [{k:"host",l:"Host",req:true},{k:"username",l:"Username",req:true},{k:"password",l:"Password",pw:true,req:true}],
  semgrep: [{k:"github_token",l:"GitHub Token (optional)",pw:true,hint:"Required for private repos"}],
  codeql: [{k:"repo_url",l:"Repository URL",req:true},{k:"github_token",l:"GitHub Token",pw:true}],
  ai_code_review: [{k:"repo_url",l:"Repository URL",hint:"Leave blank to upload code archive"}],
  sonarqube: [{k:"url",l:"SonarQube URL",req:true},{k:"token",l:"Token",pw:true,req:true},{k:"project_key",l:"Project Key"}],
  trivy: [],
  gitleaks: [{k:"github_token",l:"GitHub Token (optional)",pw:true,hint:"Required for private repos"}],
  trufflehog: [{k:"github_token",l:"GitHub Token (optional)",pw:true,hint:"Required for private repos"}],
  owasp_dc: [{k:"project_path",l:"Project Path",hint:"/path/to/project"}],
  snyk: [{k:"api_token",l:"Snyk API Token",pw:true,req:true},{k:"org_id",l:"Org ID"}],
  checkov: [],
  tenable: [{k:"access_key",l:"Access Key",req:true},{k:"secret_key",l:"Secret Key",pw:true,req:true}],
  rapid7: [{k:"url",l:"API URL",req:true,hint:"https://us.api.insight.rapid7.com"},{k:"api_key",l:"API Key",pw:true,req:true}],
  qualys: [{k:"username",l:"Username",req:true},{k:"password",l:"Password",pw:true,req:true},{k:"api_url",l:"API URL",hint:"https://qualysapi.qualys.com"}],
  burp_enterprise: [{k:"url",l:"Enterprise URL",req:true},{k:"api_key",l:"API Key",pw:true,req:true}],
  invicti: [{k:"url",l:"API URL",req:true},{k:"username",l:"Username",req:true},{k:"api_token",l:"API Token",pw:true,req:true}],
  acunetix: [{k:"url",l:"URL",req:true},{k:"api_key",l:"API Key",pw:true,req:true}],
  nuclei: [{k:"target_url",l:"Target URL",hint:"https://example.com"}],
  sslyze: [],
};

// ── Category definitions ──────────────────────────────────────────────────────

interface ScanCategory {
  id: string;
  label: string;
  description: string;
  connectorTypes: string[];
  color: string;
  Icon: React.ElementType;
}

const SCAN_CATEGORIES: ScanCategory[] = [
  { id: "cloud",      label: "Cloud Posture",       description: "Azure, AWS, GCP — IAM & misconfigurations",      connectorTypes: ["azure","aws","gcp"],                                    color: "#4285F4", Icon: Cloud },
  { id: "web",        label: "Web Application",     description: "OWASP Top 10, injections, XSS, broken auth",     connectorTypes: ["web","burp_enterprise","invicti","acunetix","nuclei"],  color: "#34A853", Icon: Language },
  { id: "code",       label: "Source Code / SAST",  description: "Static analysis, AI code review",                connectorTypes: ["semgrep","codeql","sonarqube","ai_code_review"],         color: "#FBBC04", Icon: Code },
  { id: "network",    label: "Network / OS Scan",   description: "Open ports, CVEs, OS fingerprinting",            connectorTypes: ["nmap","openvas","sslyze"],                               color: "#EA4335", Icon: Router },
  { id: "container",  label: "Container / Docker",  description: "Docker image CVEs, Kubernetes misconfigs",       connectorTypes: ["trivy"],                                                color: "#00BCD4", Icon: Inventory2 },
  { id: "secrets",    label: "Secrets Detection",   description: "Leaked API keys, credentials in Git history",    connectorTypes: ["gitleaks","trufflehog"],                                color: "#FF9800", Icon: Key },
  { id: "dependency", label: "Dependencies",        description: "Open-source CVEs, IaC misconfigs",               connectorTypes: ["owasp_dc","snyk","checkov"],                            color: "#9C27B0", Icon: AccountTree },
  { id: "enterprise", label: "Enterprise Scanner",  description: "Tenable, Rapid7, Qualys VMDR",                  connectorTypes: ["tenable","rapid7","qualys"],                            color: "#607D8B", Icon: Business },
];

const CLOUD_CONNECTOR_TYPES = new Set(["azure", "aws", "gcp"]);

const FRAMEWORK_OPTIONS = [
  { key: "nist_csf",  label: "NIST CSF 2.0" },
  { key: "cis_v8",    label: "CIS Controls v8" },
  { key: "iso_27001", label: "ISO/IEC 27001" },
  { key: "pci_dss",   label: "PCI DSS v4" },
  { key: "gdpr",      label: "GDPR" },
  { key: "cis_azure", label: "CIS Azure" },
  { key: "cis_aws",   label: "CIS AWS" },
  { key: "",          label: "Skip / None" },
];

const WIZARD_STEPS = [
  { id: "category",   label: "Category" },
  { id: "scanner",    label: "Scanner" },
  { id: "target",     label: "Target" },
  { id: "framework",  label: "Framework" },
  { id: "confirm",    label: "Confirm" },
];

function wizardStepIndex(phase: WizardPhase): number {
  const idx = WIZARD_STEPS.findIndex(s => s.id === phase);
  return idx === -1 ? 0 : idx;
}

// ── Static fallback guidance per phase ───────────────────────────────────────

function staticGuidance(phase: WizardPhase): string {
  switch (phase) {
    case "category":   return "Choose the type of security assessment you'd like to run.";
    case "scanner":    return "Select the scanner or connector to use for this assessment.";
    case "target":     return "Specify the target you want to scan.";
    case "framework":  return "Pick a compliance framework to score your findings against, or skip.";
    case "confirm":    return "Review your scan configuration before launching.";
    case "launched":   return "Your scan has been launched! Check the Scans page for progress.";
    default:           return "Follow the steps on the left to configure and launch your scan.";
  }
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function chatApi(clientId: string, message: string, history: Message[]) {
  const r = await apiClient.post(`/clients/${clientId}/ai-assisted-scan/chat`, { message, history });
  return r.data as { message: string; state: ScanState; options: any[] };
}

async function launchApi(clientId: string, state: { connector_id: string | null; connector_type: string | null; scan_name: string | null; target: string | null; framework: string | null }) {
  const r = await apiClient.post(`/clients/${clientId}/ai-assisted-scan/launch`, {
    connector_id: state.connector_id,
    connector_type: state.connector_type,
    scan_name: state.scan_name || "AI Guided Scan",
    target: state.target,
    framework: state.framework,
  });
  return r.data as { scan_id: string; scan_name: string };
}

function extractErrorDetail(e: any): string {
  const detail = e?.response?.data?.detail;
  if (!detail) return "Failed to launch scan.";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d: any) => d?.msg || JSON.stringify(d)).join(", ");
  return JSON.stringify(detail);
}

async function nextStepsApi(clientId: string, scanId: string) {
  const r = await apiClient.get(`/clients/${clientId}/ai-assisted-scan/${scanId}/next-steps`);
  return r.data as { recommendations: AgentRec[]; summary: string };
}

// ── Right panel stepper ───────────────────────────────────────────────────────

function RightPanel({
  wizardState, launching, scanId, nextSteps, nextStepsLoading, clientId, onLaunch, onNavigate,
}: {
  wizardState: WizardState;
  launching: boolean;
  scanId: string | null;
  nextSteps: { recommendations: AgentRec[]; summary: string } | null;
  nextStepsLoading: boolean;
  clientId: string;
  onLaunch: () => void;
  onNavigate: (path: string) => void;
}) {
  const currentIdx = wizardStepIndex(wizardState.phase);

  const catDef = SCAN_CATEGORIES.find(c => c.id === wizardState.categoryId);

  const chips: { label: string; value: string }[] = [];
  if (wizardState.categoryId && catDef) chips.push({ label: "Category", value: catDef.label });
  if (wizardState.connector) chips.push({ label: "Scanner", value: wizardState.connector.name });
  if (wizardState.target) chips.push({ label: "Target", value: wizardState.target });
  if (wizardState.framework !== null) chips.push({ label: "Framework", value: FRAMEWORK_OPTIONS.find(f => f.key === wizardState.framework)?.label ?? (wizardState.framework || "None") });

  const canLaunch = wizardState.phase === "confirm";

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 2, height: "100%" }}>

      {/* Phase stepper */}
      <Card variant="outlined">
        <CardContent sx={{ pb: "12px !important" }}>
          <Typography variant="caption" sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "text.secondary" }}>
            Progress
          </Typography>
          <List dense disablePadding sx={{ mt: 1 }}>
            {WIZARD_STEPS.map((step, i) => {
              const done = i < currentIdx;
              const active = i === currentIdx;
              return (
                <ListItem key={step.id} disablePadding sx={{ py: 0.25 }}>
                  <ListItemIcon sx={{ minWidth: 28 }}>
                    {done
                      ? <CheckCircle sx={{ fontSize: 16, color: "#34A853" }} />
                      : active
                        ? <HourglassEmpty sx={{ fontSize: 16, color: "#4285F4" }} />
                        : <RadioButtonUnchecked sx={{ fontSize: 16, color: "action.disabled" }} />
                    }
                  </ListItemIcon>
                  <ListItemText
                    primary={step.label}
                    slotProps={{ primary: { sx: { fontSize: 13, color: done ? "#34A853" : active ? "text.primary" : "text.disabled" } } }}
                  />
                </ListItem>
              );
            })}
          </List>
        </CardContent>
      </Card>

      {/* Collected config summary */}
      {chips.length > 0 && (
        <Card variant="outlined">
          <CardContent sx={{ pb: "12px !important" }}>
            <Typography variant="caption" sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "text.secondary" }}>
              Scan Configuration
            </Typography>
            <Box sx={{ mt: 1.5, display: "flex", flexDirection: "column", gap: 1 }}>
              {chips.map(chip => (
                <Box key={chip.label} sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 1 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ flexShrink: 0 }}>{chip.label}</Typography>
                  <Chip
                    label={chip.value}
                    size="small"
                    sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontSize: 11, maxWidth: 160, overflow: "hidden" }}
                  />
                </Box>
              ))}
            </Box>
          </CardContent>
        </Card>
      )}

      {/* Launch button */}
      {canLaunch && !scanId && (
        <Button
          variant="contained"
          size="large"
          startIcon={launching ? <CircularProgress size={16} color="inherit" /> : <RocketLaunch />}
          disabled={launching}
          onClick={onLaunch}
          sx={{ bgcolor: "#34A853", "&:hover": { bgcolor: "#2D9248" }, fontWeight: 700, py: 1.5 }}
          fullWidth
        >
          {launching ? "Launching…" : "Launch Scan"}
        </Button>
      )}

      {/* Post-launch */}
      {wizardState.phase === "launched" && scanId && (
        <Card variant="outlined" sx={{ bgcolor: "rgba(52,168,83,0.06)", borderColor: "rgba(52,168,83,0.3)" }}>
          <CardContent sx={{ pb: "12px !important" }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
              <CheckCircle sx={{ color: "#34A853", fontSize: 18 }} />
              <Typography variant="body2" sx={{ fontWeight: 700, color: "#34A853" }}>Scan launched!</Typography>
            </Box>
            <Button size="small" variant="outlined" fullWidth
              sx={{ borderColor: "rgba(52,168,83,0.4)", color: "#34A853", mb: 1 }}
              onClick={() => onNavigate(`/vulnerability/scans/${scanId}`)}>
              View Scan Progress
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Next steps */}
      {nextStepsLoading && (
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, px: 1 }}>
          <CircularProgress size={14} />
          <Typography variant="caption" color="text.secondary">Getting AI recommendations…</Typography>
        </Box>
      )}
      {nextSteps && (
        <Card variant="outlined">
          <CardContent sx={{ pb: "12px !important" }}>
            <Typography variant="caption" sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "text.secondary" }}>
              Recommended Next Steps
            </Typography>
            {nextSteps.summary && (
              <Typography variant="caption" sx={{ display: "block", color: "text.secondary", mt: 0.5, mb: 1 }}>
                {nextSteps.summary}
              </Typography>
            )}
            <List dense disablePadding>
              {nextSteps.recommendations.map((rec, i) => (
                <ListItem key={rec.agent_type} disablePadding sx={{ py: 0.5 }}>
                  <ListItemIcon sx={{ minWidth: 28 }}>
                    <Psychology sx={{ fontSize: 16, color: "#9C27B0" }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={`${i + 1}. ${rec.display_name}`}
                    secondary={rec.reason}
                    slotProps={{ primary: { sx: { fontSize: 13, fontWeight: 600 } }, secondary: { sx: { fontSize: 11 } } }}
                  />
                </ListItem>
              ))}
            </List>
            <Button size="small" variant="outlined" fullWidth sx={{ mt: 1 }}
              onClick={() => onNavigate("/ai-advisor/agents")}>
              Open AI Agents →
            </Button>
          </CardContent>
        </Card>
      )}
    </Box>
  );
}

// ── Inline connector creation accordion ──────────────────────────────────────

function AddConnectorAccordion({
  categoryId,
  clientId,
  onCreated,
  defaultExpanded,
}: {
  categoryId: string;
  clientId: string;
  onCreated: (connector: any) => void;
  defaultExpanded?: boolean;
}) {
  const queryClient = useQueryClient();
  const cat = SCAN_CATEGORIES.find(c => c.id === categoryId);
  const typesForCat = cat?.connectorTypes ?? [];

  const [connName, setConnName] = useState("");
  const [connType, setConnType] = useState(typesForCat[0] ?? "");
  const [creds, setCreds] = useState<Record<string, string>>({});
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);

  const fields: CredField[] = CREDENTIAL_SCHEMA[connType] ?? [];

  const handleTypeChange = (t: string) => {
    setConnType(t);
    setCreds({});
    setTestError(null);
  };

  const handleCred = (k: string, v: string) => setCreds(prev => ({ ...prev, [k]: v }));

  const handleTestAndConnect = async () => {
    if (!connName.trim() || !connType) return;
    setTesting(true);
    setTestError(null);
    try {
      const created = await connectorsApi.create(clientId, {
        name: connName.trim(),
        connector_type: connType,
        credentials: creds,
      });
      queryClient.invalidateQueries({ queryKey: ["connectors-list", clientId] });
      queryClient.invalidateQueries({ queryKey: ["connectors-health", clientId] });
      onCreated(created);
    } catch (e: any) {
      const detail = e?.response?.data?.detail;
      setTestError(typeof detail === "string" ? detail : "Failed to create connector.");
    } finally {
      setTesting(false);
    }
  };

  const missingRequired = fields.some(f => f.req && !creds[f.k]?.trim());
  const disabled = !connName.trim() || !connType || missingRequired || testing;

  return (
    <Accordion defaultExpanded={defaultExpanded} variant="outlined" sx={{ mt: 1, "&:before": { display: "none" } }}>
      <AccordionSummary expandIcon={<ExpandMore />}>
        <Typography variant="body2" sx={{ fontWeight: 600 }}>＋ Add new connector</Typography>
      </AccordionSummary>
      <AccordionDetails sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
        <TextField
          label="Connector name"
          size="small"
          fullWidth
          value={connName}
          onChange={e => setConnName(e.target.value)}
        />
        <FormControl size="small" fullWidth>
          <InputLabel>Connector type</InputLabel>
          <Select value={connType} label="Connector type" onChange={e => handleTypeChange(e.target.value)}>
            {typesForCat.map(t => (
              <MenuItem key={t} value={t}>{t}</MenuItem>
            ))}
          </Select>
        </FormControl>
        {fields.map(f => (
          <TextField
            key={f.k}
            label={f.l}
            size="small"
            fullWidth
            required={!!f.req}
            type={f.pw ? "password" : "text"}
            multiline={!!f.multiline}
            minRows={f.multiline ? 3 : undefined}
            placeholder={f.hint}
            value={creds[f.k] ?? ""}
            onChange={e => handleCred(f.k, e.target.value)}
          />
        ))}
        {testError && <Alert severity="error" sx={{ py: 0.5, fontSize: 12 }}>{testError}</Alert>}
        <Button
          variant="contained"
          disabled={disabled}
          onClick={handleTestAndConnect}
          startIcon={testing ? <CircularProgress size={14} color="inherit" /> : undefined}
          sx={{ bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" } }}
        >
          {testing ? "Connecting…" : "Test & Connect"}
        </Button>
      </AccordionDetails>
    </Accordion>
  );
}

// ── Wizard step cards ─────────────────────────────────────────────────────────

function CategoryStep({ connectors, onSelect }: {
  connectors: any[] | undefined;
  onSelect: (catId: string) => void;
}) {
  return (
    <Box>
      <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
        What type of security assessment would you like to run?
      </Typography>
      <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1.5 }}>
        {SCAN_CATEGORIES.map(cat => {
          const count = connectors
            ? connectors.filter((c: any) => {
                const ct = c.connector_type?.value ?? c.connector_type ?? "";
                return cat.connectorTypes.includes(ct);
              }).length
            : null;
          const CatIcon = cat.Icon;
          return (
            <Card
              key={cat.id}
              variant="outlined"
              sx={{
                cursor: "pointer",
                border: "1.5px solid",
                borderColor: "divider",
                transition: "border-color 0.15s, box-shadow 0.15s",
                "&:hover": { borderColor: cat.color, boxShadow: `0 0 0 2px ${cat.color}22` },
              }}
            >
              <CardActionArea onClick={() => onSelect(cat.id)} sx={{ p: 1.5 }}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.25 }}>
                  <Box sx={{ bgcolor: `${cat.color}18`, borderRadius: 1.5, p: 0.75, display: "flex", flexShrink: 0 }}>
                    <CatIcon sx={{ fontSize: 22, color: cat.color }} />
                  </Box>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, flexWrap: "wrap" }}>
                      <Typography variant="body2" sx={{ fontWeight: 700, lineHeight: 1.3 }}>{cat.label}</Typography>
                      {count !== null && (
                        <Chip
                          label={`${count} connected`}
                          size="small"
                          sx={{
                            height: 16, fontSize: 10,
                            bgcolor: count > 0 ? "rgba(52,168,83,0.12)" : "rgba(0,0,0,0.06)",
                            color: count > 0 ? "#34A853" : "text.secondary",
                          }}
                        />
                      )}
                    </Box>
                    <Typography variant="caption" color="text.secondary" sx={{ lineHeight: 1.4, display: "block", mt: 0.25 }}>
                      {cat.description}
                    </Typography>
                  </Box>
                </Box>
              </CardActionArea>
            </Card>
          );
        })}
      </Box>
    </Box>
  );
}

function ScannerStep({ categoryId, clientId, selected, onSelect, onBack }: {
  categoryId: string;
  clientId: string;
  selected: any | null;
  onSelect: (connector: any) => void;
  onBack: () => void;
}) {
  const { data: connectors } = useQuery({
    queryKey: ["connectors-list", clientId],
    queryFn: () => connectorsApi.list(clientId),
    enabled: !!clientId,
    staleTime: 30_000,
  });
  const { data: health } = useQuery({
    queryKey: ["connectors-health", clientId],
    queryFn: () => connectorsApi.health(clientId),
    enabled: !!clientId,
    staleTime: 60_000,
  });

  const cat = SCAN_CATEGORIES.find(c => c.id === categoryId);
  const catTypes = cat?.connectorTypes ?? [];

  const filtered = (connectors ?? []).filter((c: any) => {
    const ct = c.connector_type?.value ?? c.connector_type ?? "";
    return catTypes.includes(ct);
  });

  const getLastScan = (connectorId: string): string => {
    if (!health) return "Never";
    const h = (health as any[]).find((x: any) => x.connector_id === connectorId || x.id === connectorId);
    if (!h || !h.last_scan_at) return "Never";
    const days = Math.floor((Date.now() - new Date(h.last_scan_at).getTime()) / 86_400_000);
    return days === 0 ? "Today" : `${days}d ago`;
  };

  const noConnectors = filtered.length === 0;

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
        <IconButton size="small" onClick={onBack}><ArrowBack fontSize="small" /></IconButton>
        <Typography variant="body2" color="text.secondary">
          {noConnectors
            ? `No ${cat?.label ?? "matching"} connectors configured yet.`
            : `Select a scanner for ${cat?.label ?? "this category"}:`}
        </Typography>
      </Box>

      {noConnectors ? (
        <Alert severity="warning" sx={{ mb: 1, fontSize: 13 }}>
          No connector configured for <strong>{cat?.label}</strong>. Use the form below to add one.
        </Alert>
      ) : (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75, mb: 1 }}>
          {filtered.map((c: any) => {
            const ct = c.connector_type?.value ?? c.connector_type ?? "";
            const isSelected = selected?.id === c.id;
            return (
              <Paper
                key={c.id}
                variant="outlined"
                onClick={() => onSelect(c)}
                sx={{
                  display: "flex", alignItems: "center", gap: 1.5,
                  p: 1.5, cursor: "pointer",
                  borderColor: isSelected ? "#4285F4" : "divider",
                  bgcolor: isSelected ? "rgba(66,133,244,0.06)" : "transparent",
                  transition: "all 0.15s",
                  "&:hover": { borderColor: "#4285F4", bgcolor: "rgba(66,133,244,0.04)" },
                }}
              >
                <Radio checked={isSelected} size="small" sx={{ p: 0, color: "#4285F4" }} />
                <Box sx={{ flex: 1 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>{c.name}</Typography>
                    <Chip label={ct} size="small" sx={{ fontSize: 10, height: 18 }} />
                  </Box>
                  <Typography variant="caption" color="text.secondary">Last scan: {getLastScan(c.id)}</Typography>
                </Box>
              </Paper>
            );
          })}
        </Box>
      )}

      <AddConnectorAccordion
        categoryId={categoryId}
        clientId={clientId}
        defaultExpanded={noConnectors}
        onCreated={(newConn) => onSelect(newConn)}
      />
    </Box>
  );
}

function TargetStep({ connector, clientId, target, onSelect, onBack }: {
  connector: any;
  clientId: string;
  target: string | null;
  onSelect: (target: string, isCustom: boolean) => void;
  onBack: () => void;
}) {
  const ct = connector?.connector_type?.value ?? connector?.connector_type ?? "";
  const isCloud = CLOUD_CONNECTOR_TYPES.has(ct);

  const { data: assets } = useQuery({
    queryKey: ["assets-for-target", clientId, ct],
    queryFn: () => assetsApi.list(clientId, { connector_type: ct }),
    enabled: !!clientId && !!ct,
    staleTime: 60_000,
    select: (data: any[]) => data.slice(0, 20),
  });

  const FULL_ENV_VALUE = "__full_env__";
  const CUSTOM_VALUE = "__custom__";

  const [selected, setSelected] = useState<string>(
    target ? (target === "full" ? FULL_ENV_VALUE : target) : (isCloud ? FULL_ENV_VALUE : "")
  );
  const [customText, setCustomText] = useState(target && target !== "full" && !assets?.some((a: any) => a.name === target || a.external_id === target) ? target : "");
  const showCustomInput = selected === CUSTOM_VALUE;

  const handleSelect = (val: string) => {
    setSelected(val);
    if (val === FULL_ENV_VALUE) {
      onSelect("full", false);
    } else if (val !== CUSTOM_VALUE) {
      onSelect(val, false);
    }
  };

  const handleCustomConfirm = () => {
    if (customText.trim()) onSelect(customText.trim(), true);
  };

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
        <IconButton size="small" onClick={onBack}><ArrowBack fontSize="small" /></IconButton>
        <Typography variant="body2" color="text.secondary">Select a target to scan:</Typography>
      </Box>

      <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
        {isCloud && (
          <Paper
            variant="outlined"
            onClick={() => handleSelect(FULL_ENV_VALUE)}
            sx={{
              display: "flex", alignItems: "center", gap: 1.5, p: 1.5, cursor: "pointer",
              borderColor: selected === FULL_ENV_VALUE ? "#4285F4" : "divider",
              bgcolor: selected === FULL_ENV_VALUE ? "rgba(66,133,244,0.06)" : "transparent",
              transition: "all 0.15s", "&:hover": { borderColor: "#4285F4" },
            }}
          >
            <Radio checked={selected === FULL_ENV_VALUE} size="small" sx={{ p: 0, color: "#4285F4" }} />
            <Box>
              <Typography variant="body2" sx={{ fontWeight: 600 }}>Full environment (default)</Typography>
              <Typography variant="caption" color="text.secondary">Scan all resources in the configured account</Typography>
            </Box>
          </Paper>
        )}

        {(assets ?? []).map((a: any) => {
          const val = a.name ?? a.external_id ?? String(a.id);
          const isSelected = selected === val;
          return (
            <Paper
              key={a.id}
              variant="outlined"
              onClick={() => handleSelect(val)}
              sx={{
                display: "flex", alignItems: "center", gap: 1.5, p: 1.5, cursor: "pointer",
                borderColor: isSelected ? "#4285F4" : "divider",
                bgcolor: isSelected ? "rgba(66,133,244,0.06)" : "transparent",
                transition: "all 0.15s", "&:hover": { borderColor: "#4285F4" },
              }}
            >
              <Radio checked={isSelected} size="small" sx={{ p: 0, color: "#4285F4" }} />
              <Box sx={{ flex: 1 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>{a.name ?? a.external_id}</Typography>
                  {a.asset_class && <Chip label={a.asset_class} size="small" sx={{ fontSize: 10, height: 18 }} />}
                </Box>
                {a.last_synced_at && (
                  <Typography variant="caption" color="text.secondary">
                    Last synced: {new Date(a.last_synced_at).toLocaleDateString()}
                  </Typography>
                )}
              </Box>
            </Paper>
          );
        })}

        <Paper
          variant="outlined"
          onClick={() => setSelected(CUSTOM_VALUE)}
          sx={{
            display: "flex", alignItems: "center", gap: 1.5, p: 1.5, cursor: "pointer",
            borderColor: selected === CUSTOM_VALUE ? "#4285F4" : "divider",
            bgcolor: selected === CUSTOM_VALUE ? "rgba(66,133,244,0.06)" : "transparent",
            transition: "all 0.15s", "&:hover": { borderColor: "#4285F4" },
          }}
        >
          <Radio checked={selected === CUSTOM_VALUE} size="small" sx={{ p: 0, color: "#4285F4" }} />
          <Typography variant="body2" sx={{ fontWeight: 600 }}>Custom target…</Typography>
        </Paper>

        <Collapse in={showCustomInput}>
          <Box sx={{ display: "flex", gap: 1, mt: 0.5 }}>
            <TextField
              size="small"
              fullWidth
              placeholder="URL, IP, hostname, repo URL…"
              value={customText}
              onChange={e => setCustomText(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter") handleCustomConfirm(); }}
            />
            <Button variant="contained" size="small" disabled={!customText.trim()} onClick={handleCustomConfirm}
              sx={{ bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" }, whiteSpace: "nowrap" }}>
              Confirm
            </Button>
          </Box>
        </Collapse>
      </Box>
    </Box>
  );
}

function FrameworkStep({ selected, onSelect, onBack }: {
  selected: string | null;
  onSelect: (key: string) => void;
  onBack: () => void;
}) {
  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
        <IconButton size="small" onClick={onBack}><ArrowBack fontSize="small" /></IconButton>
        <Typography variant="body2" color="text.secondary">
          Score findings against a compliance framework (optional):
        </Typography>
      </Box>
      <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1 }}>
        {FRAMEWORK_OPTIONS.map(fw => {
          const isSelected = selected === fw.key;
          return (
            <Paper
              key={fw.key || "none"}
              variant="outlined"
              onClick={() => onSelect(fw.key)}
              sx={{
                display: "flex", alignItems: "center", gap: 1, p: 1.25, cursor: "pointer",
                borderColor: isSelected ? "#4285F4" : "divider",
                bgcolor: isSelected ? "rgba(66,133,244,0.06)" : "transparent",
                transition: "all 0.15s", "&:hover": { borderColor: "#4285F4" },
              }}
            >
              <Radio checked={isSelected} size="small" sx={{ p: 0, flexShrink: 0, color: "#4285F4" }} />
              <Typography variant="body2" sx={{ fontWeight: isSelected ? 700 : 400, fontSize: 12, lineHeight: 1.3 }}>
                {fw.label}
              </Typography>
            </Paper>
          );
        })}
      </Box>
    </Box>
  );
}

function ConfirmStep({ wizardState, onEdit, onBack }: {
  wizardState: WizardState;
  onEdit: (phase: WizardPhase) => void;
  onBack: () => void;
}) {
  const cat = SCAN_CATEGORIES.find(c => c.id === wizardState.categoryId);
  const fwLabel = FRAMEWORK_OPTIONS.find(f => f.key === wizardState.framework)?.label ?? (wizardState.framework || "None");

  const rows: { label: string; value: string; phase: WizardPhase }[] = [
    { label: "Category",   value: cat?.label ?? "—",                        phase: "category" },
    { label: "Scanner",    value: wizardState.connector?.name ?? "—",        phase: "scanner" },
    { label: "Target",     value: wizardState.target === "full" ? "Full environment" : (wizardState.target ?? "—"), phase: "target" },
    { label: "Framework",  value: fwLabel,                                   phase: "framework" },
    { label: "Scan name",  value: wizardState.scanName ?? "—",               phase: "category" },
  ];

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
        <IconButton size="small" onClick={onBack}><ArrowBack fontSize="small" /></IconButton>
        <Typography variant="body2" color="text.secondary">Review your scan configuration:</Typography>
      </Box>
      <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
        {rows.map(row => (
          <Paper key={row.label} variant="outlined" sx={{ display: "flex", alignItems: "center", px: 2, py: 1.25, gap: 1 }}>
            <Typography variant="caption" color="text.secondary" sx={{ width: 80, flexShrink: 0 }}>{row.label}</Typography>
            <Typography variant="body2" sx={{ fontWeight: 600, flex: 1 }}>{row.value}</Typography>
            <Tooltip title={`Edit ${row.label.toLowerCase()}`}>
              <IconButton size="small" onClick={() => onEdit(row.phase)} sx={{ ml: "auto" }}>
                <Edit sx={{ fontSize: 15 }} />
              </IconButton>
            </Tooltip>
          </Paper>
        ))}
      </Box>
    </Box>
  );
}

function LaunchedStep({ scanId, onNavigate }: { scanId: string | null; onNavigate: (path: string) => void }) {
  return (
    <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2, py: 4 }}>
      <CheckCircle sx={{ fontSize: 56, color: "#34A853" }} />
      <Typography variant="h6" sx={{ fontWeight: 700, color: "#34A853" }}>Scan Launched!</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center" }}>
        Your scan is running in the background. You can monitor its progress on the Scans page.
      </Typography>
      {scanId && (
        <Button variant="outlined" onClick={() => onNavigate(`/vulnerability/scans/${scanId}`)}
          sx={{ borderColor: "#34A853", color: "#34A853" }}>
          View Scan Progress
        </Button>
      )}
    </Box>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AIAssistedScan() {
  const { clientId } = useActiveClient();
  const navigate = useNavigate();

  // Guidance strip state
  const [guidanceMsg, setGuidanceMsg] = useState<string>("Welcome! Choose a category to start your security assessment.");
  const [guidanceLoading, setGuidanceLoading] = useState(false);

  // Internal history for chatApi (not displayed)
  const [chatHistory, setChatHistory] = useState<Message[]>([]);

  // Free-text override
  const [freeText, setFreeText] = useState("");
  const [freeTextLoading, setFreeTextLoading] = useState(false);

  // Wizard state
  const [wizardState, setWizardState] = useState<WizardState>({
    phase: "category",
    categoryId: null,
    connector: null,
    target: null,
    targetIsCustom: false,
    framework: null,
    scanName: null,
  });

  // Launch state
  const [launching, setLaunching] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [nextSteps, setNextSteps] = useState<{ recommendations: AgentRec[]; summary: string } | null>(null);
  const [nextStepsLoading, setNextStepsLoading] = useState(false);

  const inputRef = useRef<HTMLInputElement>(null);
  const greeted = useRef(false);

  const { data: connectors } = useQuery({
    queryKey: ["connectors-list", clientId],
    queryFn: () => connectorsApi.list(clientId ?? ""),
    enabled: !!clientId,
    staleTime: 30_000,
  });

  // Initial greeting
  useEffect(() => {
    if (!clientId || greeted.current) return;
    greeted.current = true;
    setGuidanceLoading(true);
    chatApi(clientId, "Hello", [])
      .then(res => {
        setGuidanceMsg(res.message);
        setChatHistory([{ role: "assistant", content: res.message }]);
      })
      .catch(() => {
        setGuidanceMsg(staticGuidance("category"));
      })
      .finally(() => setGuidanceLoading(false));
  }, [clientId]);

  // Send a selection to AI for acknowledgment and update guidance strip
  const sendSelectionToAI = async (userMsg: string, nextPhase: WizardPhase) => {
    if (!clientId) return;
    setGuidanceLoading(true);
    const newHistory: Message[] = [...chatHistory, { role: "user", content: userMsg }];
    try {
      const res = await chatApi(clientId, userMsg, chatHistory);
      setGuidanceMsg(res.message);
      setChatHistory([...newHistory, { role: "assistant", content: res.message }]);
    } catch {
      setGuidanceMsg(staticGuidance(nextPhase));
      setChatHistory(newHistory);
    } finally {
      setGuidanceLoading(false);
    }
  };

  const handleCategorySelect = (catId: string) => {
    const cat = SCAN_CATEGORIES.find(c => c.id === catId)!;
    const newScanName = `${cat.label} — Assessment`;
    setWizardState(prev => ({
      ...prev,
      phase: "scanner",
      categoryId: catId,
      connector: null,
      target: null,
      targetIsCustom: false,
      framework: null,
      scanName: newScanName,
    }));
    sendSelectionToAI(`I want to run a ${cat.label} assessment`, "scanner");
  };

  const handleScannerSelect = (connector: any) => {
    const ct = connector.connector_type?.value ?? connector.connector_type ?? "";
    const scanName = `${SCAN_CATEGORIES.find(c => c.id === wizardState.categoryId)?.label ?? "AI"} — ${connector.name}`;
    setWizardState(prev => ({
      ...prev,
      phase: "target",
      connector,
      target: CLOUD_CONNECTOR_TYPES.has(ct) ? "full" : null,
      targetIsCustom: false,
      scanName,
    }));
    sendSelectionToAI(`Use connector: ${connector.name} (${ct})`, "target");
  };

  const handleTargetSelect = (target: string, isCustom: boolean) => {
    setWizardState(prev => ({ ...prev, phase: "framework", target, targetIsCustom: isCustom }));
    sendSelectionToAI(`Target: ${target === "full" ? "full environment" : target}`, "framework");
  };

  const handleFrameworkSelect = (key: string) => {
    const fwLabel = FRAMEWORK_OPTIONS.find(f => f.key === key)?.label ?? (key || "None");
    setWizardState(prev => ({ ...prev, phase: "confirm", framework: key }));
    sendSelectionToAI(`Framework: ${fwLabel}`, "confirm");
  };

  const handleEdit = (phase: WizardPhase) => {
    setWizardState(prev => ({ ...prev, phase }));
  };

  const handleBack = () => {
    const currentIdx = wizardStepIndex(wizardState.phase);
    if (currentIdx <= 0) return;
    const prevStep = WIZARD_STEPS[currentIdx - 1];
    setWizardState(prev => ({ ...prev, phase: prevStep.id as WizardPhase }));
  };

  const handleLaunch = async () => {
    if (!clientId || !wizardState.connector) return;
    setLaunching(true);
    setLaunchError(null);
    try {
      const ct = wizardState.connector.connector_type?.value ?? wizardState.connector.connector_type ?? null;
      const result = await launchApi(clientId, {
        connector_id: wizardState.connector.id ?? null,
        connector_type: ct,
        scan_name: wizardState.scanName || "AI Guided Scan",
        target: wizardState.target === "full" ? null : wizardState.target,
        framework: wizardState.framework || null,
      });
      setScanId(result.scan_id);
      setWizardState(prev => ({ ...prev, phase: "launched" }));
      setGuidanceMsg(`Scan "${result.scan_name}" launched! I'm analysing the best next steps for you.`);
      // Fetch next steps
      setNextStepsLoading(true);
      setTimeout(async () => {
        try {
          const ns = await nextStepsApi(clientId, result.scan_id);
          setNextSteps(ns);
        } catch { /* non-fatal */ } finally {
          setNextStepsLoading(false);
        }
      }, 3000);
    } catch (e: any) {
      setLaunchError(extractErrorDetail(e));
    } finally {
      setLaunching(false);
    }
  };

  const handleFreeTextSend = async () => {
    const text = freeText.trim();
    if (!text || freeTextLoading || !clientId) return;
    setFreeText("");
    setFreeTextLoading(true);
    const newHistory: Message[] = [...chatHistory, { role: "user", content: text }];
    try {
      const res = await chatApi(clientId, text, chatHistory);
      setGuidanceMsg(res.message);
      setChatHistory([...newHistory, { role: "assistant", content: res.message }]);
    } catch {
      setGuidanceMsg("AI unavailable — check AI provider settings.");
      setChatHistory(newHistory);
    } finally {
      setFreeTextLoading(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  };

  // Render wizard step card content
  const renderWizardContent = () => {
    if (!clientId) return <Alert severity="warning">Select a client in the top toolbar to begin.</Alert>;

    switch (wizardState.phase) {
      case "category":
        return <CategoryStep connectors={connectors} onSelect={handleCategorySelect} />;

      case "scanner":
        return (
          <ScannerStep
            categoryId={wizardState.categoryId!}
            clientId={clientId}
            selected={wizardState.connector}
            onSelect={handleScannerSelect}
            onBack={handleBack}
          />
        );

      case "target":
        return (
          <TargetStep
            connector={wizardState.connector}
            clientId={clientId}
            target={wizardState.target}
            onSelect={handleTargetSelect}
            onBack={handleBack}
          />
        );

      case "framework":
        return (
          <FrameworkStep
            selected={wizardState.framework}
            onSelect={handleFrameworkSelect}
            onBack={handleBack}
          />
        );

      case "confirm":
        return (
          <ConfirmStep
            wizardState={wizardState}
            onEdit={handleEdit}
            onBack={handleBack}
          />
        );

      case "launched":
        return <LaunchedStep scanId={scanId} onNavigate={navigate} />;

      default:
        return null;
    }
  };

  return (
    <Box sx={{ height: "calc(100vh - 64px)", display: "flex", flexDirection: "column", overflow: "hidden" }}>

      {/* Page header */}
      <Box sx={{ px: 3, py: 2, borderBottom: "1px solid", borderColor: "divider", flexShrink: 0 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
          <SmartToy sx={{ color: "#4285F4", fontSize: 28 }} />
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.2 }}>AI Assisted Scan</Typography>
            <Typography variant="caption" color="text.secondary">
              Follow the guided wizard to configure and launch a security assessment
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* Body: wizard left, config right */}
      <Box sx={{ flex: 1, display: "flex", overflow: "hidden" }}>

        {/* Left panel */}
        <Box sx={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", borderRight: "1px solid", borderColor: "divider" }}>

          {/* AI guidance strip */}
          <Box sx={{ bgcolor: "#4285F4", px: 2.5, py: 1.25, flexShrink: 0, display: "flex", alignItems: "flex-start", gap: 1.25 }}>
            <SmartToy sx={{ color: "#fff", fontSize: 20, mt: 0.25, flexShrink: 0 }} />
            <Box sx={{ flex: 1 }}>
              {guidanceLoading ? (
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  {[0, 1, 2].map(d => (
                    <Box key={d} sx={{
                      width: 5, height: 5, borderRadius: "50%", bgcolor: "#ffffffaa",
                      animation: "bounce 1.2s ease-in-out infinite",
                      animationDelay: `${d * 0.2}s`,
                      "@keyframes bounce": {
                        "0%, 80%, 100%": { transform: "scale(0.6)", opacity: 0.4 },
                        "40%": { transform: "scale(1)", opacity: 1 },
                      },
                    }} />
                  ))}
                </Box>
              ) : (
                <Typography variant="body2" sx={{ color: "#fff", lineHeight: 1.5 }}>
                  {guidanceMsg}
                </Typography>
              )}
            </Box>
          </Box>

          {/* Wizard step card */}
          <Box sx={{ flex: 1, overflowY: "auto", p: 2.5 }}>
            <Card variant="outlined" sx={{ bgcolor: "background.paper" }}>
              <CardContent>
                {renderWizardContent()}
              </CardContent>
            </Card>

            {/* Launch error */}
            {launchError && (
              <Alert severity="error" onClose={() => setLaunchError(null)} sx={{ mt: 1.5 }}>
                {launchError}
              </Alert>
            )}
          </Box>

          {/* Free-text override */}
          <Box sx={{ p: 2, borderTop: "1px solid", borderColor: "divider", flexShrink: 0 }}>
            <Box sx={{ display: "flex", gap: 1 }}>
              <TextField
                inputRef={inputRef}
                fullWidth
                size="small"
                placeholder="Override — type anything to the AI guide…"
                value={freeText}
                onChange={e => setFreeText(e.target.value)}
                disabled={freeTextLoading || wizardState.phase === "launched"}
                onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleFreeTextSend(); } }}
                multiline
                maxRows={3}
              />
              <Button
                variant="contained"
                onClick={handleFreeTextSend}
                disabled={!freeText.trim() || freeTextLoading || wizardState.phase === "launched"}
                sx={{ bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" }, minWidth: 44, px: 1.5 }}
              >
                {freeTextLoading ? <CircularProgress size={16} color="inherit" /> : <Send fontSize="small" />}
              </Button>
            </Box>
            <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
              Press Enter to send · Shift+Enter for new line
            </Typography>
          </Box>
        </Box>

        {/* Right panel */}
        <Box sx={{ width: 320, flexShrink: 0, p: 2, overflowY: "auto" }}>
          {clientId ? (
            <RightPanel
              wizardState={wizardState}
              launching={launching}
              scanId={scanId}
              nextSteps={nextSteps}
              nextStepsLoading={nextStepsLoading}
              clientId={clientId}
              onLaunch={handleLaunch}
              onNavigate={navigate}
            />
          ) : (
            <Alert severity="warning">Select a client in the top toolbar to begin.</Alert>
          )}
        </Box>
      </Box>
    </Box>
  );
}
