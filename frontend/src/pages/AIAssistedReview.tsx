import React, { useState } from "react";
import {
  Box, Typography, Grid, Card, CardContent, Chip, Stepper, Step, StepLabel,
  Tabs, Tab, Button, CircularProgress, Dialog, DialogTitle, DialogContent,
  DialogActions, Divider, Alert, TextField, MenuItem, Select, FormControl,
  InputLabel, LinearProgress, Tooltip, Skeleton,
} from "@mui/material";
import {
  AutoAwesome, RocketLaunch, Architecture, CheckCircle, PendingOutlined,
  UploadFile, ArrowForward, SmartToy, BugReport, Security, Gavel, Memory,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";

import { useActiveClient } from "../contexts/ClientContext";
import { scansApi, agentsApi, aiReviewApi } from "../services/api";

// ── Types ──────────────────────────────────────────────────────────────────────

interface Scan {
  id: string;
  name: string;
  status: string;
  connector_type?: string;
  created_at?: string;
  completed_at?: string;
  summary?: Record<string, number>;
  connector?: { connector_type?: string; name?: string };
}

interface AgentRecommendation {
  agent_key: string;
  match_score: number;
  reasoning: string;
  bring: string[];
}

interface ScanAdvisory {
  banner: string;
  recommendations: AgentRecommendation[];
}

// ── Constants ──────────────────────────────────────────────────────────────────

const WIZARD_STEPS = ["Select assessment", "AI recommendation", "Choose agent", "Run"];

interface AgentDef {
  key: string;
  name: string;
  category: string;
  catLabel: string;
  desc: string;
  inputs: string[];
  wizard: boolean;
}

const AGENT_CATALOG: AgentDef[] = [
  {
    key: "orchestrator", name: "Full Orchestrator", category: "all", catLabel: "Full Pipeline",
    desc: "Runs threat intel, compliance analysis, and remediation planning in one pass.",
    inputs: ["Completed scan"], wizard: false,
  },
  {
    key: "risk_manager", name: "Risk Manager", category: "vuln", catLabel: "Vulnerability & Exposure",
    desc: "Quantifies risk using FAIR methodology — translates findings into ALE scores and business impact.",
    inputs: ["Completed scan", "Asset criticality context"], wizard: false,
  },
  {
    key: "threat_intel", name: "Threat Intelligence", category: "vuln", catLabel: "Vulnerability & Exposure",
    desc: "Enriches findings with CVE data, threat actor profiles, and MITRE ATT&CK technique mapping.",
    inputs: ["Completed scan"], wizard: false,
  },
  {
    key: "compliance_monitor", name: "Compliance Monitor", category: "compliance", catLabel: "Compliance & Governance",
    desc: "Maps findings to NIST CSF, ISO 27001, PCI DSS, CIS Controls, GCC IM8, or MAS TRM and highlights gaps.",
    inputs: ["Completed scan", "Target framework selection"], wizard: false,
  },
  {
    key: "remediation", name: "Remediation Planner", category: "compliance", catLabel: "Compliance & Governance",
    desc: "Turns findings into a prioritized remediation plan with suggested owners and SLA targets.",
    inputs: ["Completed scan"], wizard: false,
  },
  {
    key: "arch_review", name: "Architecture Review", category: "ae", catLabel: "Architecture & Engineering",
    desc: "Reviews a system design against security architecture patterns and flags deviations from best practice.",
    inputs: ["Network/data-flow diagram", "Cloud environment details", "Existing controls (optional)"], wizard: true,
  },
  {
    key: "iac_hardening", name: "IaC Hardening Advisor", category: "ae", catLabel: "Architecture & Engineering",
    desc: "Reviews Terraform, ARM, or Bicep templates against CIS or NIST benchmarks before deployment.",
    inputs: ["IaC templates", "Target benchmark selection"], wizard: true,
  },
  {
    key: "zt_advisor", name: "Zero Trust Advisor", category: "ae", catLabel: "Architecture & Engineering",
    desc: "Evaluates network segmentation and proposes a zero-trust model for the environment.",
    inputs: ["Network topology / VLAN map", "Firewall rule export"], wizard: true,
  },
];

const CATEGORY_TABS = [
  { value: "all", label: "All" },
  { value: "vuln", label: "Vulnerability & Exposure" },
  { value: "compliance", label: "Compliance & Governance" },
  { value: "triage", label: "Triage & Detection" },
  { value: "ae", label: "Architecture & Engineering" },
];

const CONNECTOR_TYPE_CHIP: Record<string, { label: string; color: string }> = {
  azure: { label: "Cloud", color: "#0ea5e9" },
  aws: { label: "Cloud", color: "#f59e0b" },
  gcp: { label: "Cloud", color: "#10b981" },
  semgrep: { label: "SAST", color: "#8b5cf6" },
  codeql: { label: "SAST", color: "#8b5cf6" },
  ai_code_review: { label: "Code AI", color: "#6366f1" },
  sonarqube: { label: "SAST", color: "#8b5cf6" },
  web: { label: "DAST", color: "#ef4444" },
  nmap: { label: "Network", color: "#f97316" },
  openvas: { label: "Network", color: "#f97316" },
  trivy: { label: "Container", color: "#0284c7" },
  tenable: { label: "Enterprise", color: "#dc2626" },
  qualys: { label: "Enterprise", color: "#dc2626" },
  rapid7: { label: "Enterprise", color: "#dc2626" },
  burp_enterprise: { label: "Enterprise", color: "#dc2626" },
  snyk: { label: "Dependency", color: "#7c3aed" },
};

function getConnectorChip(ct: string) {
  return CONNECTOR_TYPE_CHIP[ct] || { label: ct?.toUpperCase() || "SCAN", color: "#6b7280" };
}

function getConnectorType(scan: Scan): string {
  return scan.connector?.connector_type || scan.connector_type || "";
}

// ── Match bars ─────────────────────────────────────────────────────────────────

function MatchBars({ score }: { score: number }) {
  const filled = Math.round((score / 100) * 5);
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mt: 0.5 }}>
      {[1, 2, 3, 4, 5].map((i) => (
        <Box key={i} sx={{
          width: 6, height: 14, borderRadius: 1,
          bgcolor: i <= filled ? "primary.main" : "rgba(255,255,255,0.12)",
        }} />
      ))}
      <Typography sx={{ ml: 0.5, fontSize: 12, color: "primary.main", fontWeight: 700 }}>
        {score}%
      </Typography>
    </Box>
  );
}

// ── Scan card ─────────────────────────────────────────────────────────────────

function ScanCard({ scan, selected, onClick }: { scan: Scan; selected: boolean; onClick: () => void }) {
  const ct = getConnectorType(scan);
  const chip = getConnectorChip(ct);
  const summary = scan.summary || {};
  const crit = summary.critical || 0;
  const high = summary.high || 0;
  const med = summary.medium || 0;
  const low = summary.low || 0;
  const dateStr = scan.completed_at || scan.created_at || "";
  const date = dateStr ? new Date(dateStr).toLocaleDateString() : "";

  return (
    <Card
      onClick={onClick}
      sx={{
        cursor: "pointer",
        border: selected ? "2px solid" : "1px solid rgba(255,255,255,0.1)",
        borderColor: selected ? "primary.main" : undefined,
        bgcolor: selected ? "rgba(99,102,241,0.08)" : "background.paper",
        transition: "all 0.15s",
        "&:hover": { borderColor: "primary.main", boxShadow: "0 0 0 1px rgba(99,102,241,0.3)" },
        position: "relative",
      }}
    >
      {selected && (
        <Box sx={{
          position: "absolute", top: 8, right: 8,
          width: 22, height: 22, borderRadius: "50%",
          bgcolor: "primary.main", display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <CheckCircle sx={{ fontSize: 14, color: "#fff" }} />
        </Box>
      )}
      <CardContent sx={{ pb: "12px !important" }}>
        <Chip
          label={chip.label}
          size="small"
          sx={{ bgcolor: `${chip.color}22`, color: chip.color, fontSize: 10, height: 18, mb: 1, fontWeight: 700 }}
        />
        <Typography sx={{ fontSize: 13, fontWeight: 600, mb: 0.5, pr: selected ? 3 : 0 }}
          noWrap title={scan.name}>
          {scan.name}
        </Typography>
        {date && (
          <Typography sx={{ fontSize: 11, color: "text.secondary", mb: 1 }}>{date}</Typography>
        )}
        <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
          {crit > 0 && <Chip label={`${crit}C`} size="small" sx={{ height: 16, fontSize: 10, bgcolor: "#ef444422", color: "#ef4444" }} />}
          {high > 0 && <Chip label={`${high}H`} size="small" sx={{ height: 16, fontSize: 10, bgcolor: "#f9731622", color: "#f97316" }} />}
          {med > 0 && <Chip label={`${med}M`} size="small" sx={{ height: 16, fontSize: 10, bgcolor: "#eab30822", color: "#eab308" }} />}
          {low > 0 && <Chip label={`${low}L`} size="small" sx={{ height: 16, fontSize: 10, bgcolor: "#22c55e22", color: "#22c55e" }} />}
          {(crit + high + med + low) === 0 && (
            <Chip label="No findings" size="small" sx={{ height: 16, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
          )}
        </Box>
      </CardContent>
    </Card>
  );
}

// ── Recommendation card ────────────────────────────────────────────────────────

function RecCard({ rec, onRun, onWizard }: {
  rec: AgentRecommendation;
  onRun: () => void;
  onWizard?: () => void;
}) {
  const def = AGENT_CATALOG.find(a => a.key === rec.agent_key);
  const name = def?.name || rec.agent_key;
  const catLabel = def?.catLabel || "";

  return (
    <Card sx={{
      borderLeft: "3px solid",
      borderColor: "primary.main",
      bgcolor: "rgba(99,102,241,0.04)",
      height: "100%",
      display: "flex",
      flexDirection: "column",
    }}>
      <Box sx={{
        height: 4,
        background: `linear-gradient(90deg, rgba(99,102,241,0.6) 0%, rgba(99,102,241,0.1) 100%)`,
        borderTopRightRadius: 4,
      }} />
      <CardContent sx={{ flex: 1, display: "flex", flexDirection: "column" }}>
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
          <Chip label={catLabel} size="small" sx={{ fontSize: 10, height: 18, bgcolor: "rgba(99,102,241,0.15)", color: "primary.main" }} />
        </Box>
        <Typography sx={{ fontSize: 15, fontWeight: 700, mt: 0.5 }}>{name}</Typography>
        <MatchBars score={rec.match_score} />
        <Typography sx={{ fontSize: 12, color: "text.secondary", mt: 1 }}>
          <strong style={{ color: "inherit" }}>Why: </strong>{rec.reasoning}
        </Typography>
        {rec.bring?.length > 0 && (
          <Box sx={{ mt: 1 }}>
            <Typography sx={{ fontSize: 11, color: "text.secondary", mb: 0.5 }}>Bring:</Typography>
            {rec.bring.map((b, i) => (
              <Chip key={i} label={b} size="small" variant="outlined"
                sx={{ mr: 0.5, mb: 0.5, fontSize: 10, height: 18, borderColor: "rgba(255,255,255,0.12)", color: "text.secondary" }} />
            ))}
          </Box>
        )}
        <Box sx={{ mt: "auto", pt: 1.5 }}>
          {def?.wizard ? (
            <Button size="small" variant="outlined" fullWidth startIcon={<Architecture />} onClick={onWizard}
              sx={{ fontSize: 12 }}>
              Start wizard
            </Button>
          ) : (
            <Button size="small" variant="contained" fullWidth startIcon={<RocketLaunch />} onClick={onRun}
              sx={{ fontSize: 12 }}>
              Run agent
            </Button>
          )}
        </Box>
      </CardContent>
    </Card>
  );
}

// ── Catalog card ──────────────────────────────────────────────────────────────

function CatalogCard({ agent, onRun, onWizard, scanId }: {
  agent: AgentDef;
  onRun: (key: string) => void;
  onWizard: (agent: AgentDef) => void;
  scanId?: string;
}) {
  const Icon = agent.category === "ae" ? Architecture
    : agent.key === "threat_intel" ? Security
    : agent.key === "compliance_monitor" ? Gavel
    : agent.key === "risk_manager" ? Memory
    : SmartToy;

  return (
    <Card sx={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <CardContent sx={{ flex: 1, display: "flex", flexDirection: "column" }}>
        <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5, mb: 1 }}>
          <Box sx={{ width: 36, height: 36, borderRadius: 1.5, bgcolor: "rgba(99,102,241,0.12)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
            <Icon sx={{ fontSize: 18, color: "primary.main" }} />
          </Box>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography sx={{ fontSize: 13, fontWeight: 700 }}>{agent.name}</Typography>
            <Chip label={agent.catLabel} size="small"
              sx={{ fontSize: 9, height: 16, mt: 0.3, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
          </Box>
        </Box>
        <Typography sx={{ fontSize: 12, color: "text.secondary", flex: 1 }}>{agent.desc}</Typography>
        <Box sx={{ mt: 1 }}>
          <Typography sx={{ fontSize: 11, color: "text.secondary", mb: 0.3 }}>Needs:</Typography>
          {agent.inputs.map((inp, i) => (
            <Chip key={i} label={inp} size="small" variant="outlined"
              sx={{ mr: 0.5, mb: 0.3, fontSize: 10, height: 16, borderColor: "rgba(255,255,255,0.1)", color: "text.secondary" }} />
          ))}
        </Box>
        <Box sx={{ mt: 1.5 }}>
          {agent.wizard ? (
            <Button size="small" variant="outlined" fullWidth startIcon={<Architecture />}
              onClick={() => onWizard(agent)} sx={{ fontSize: 11 }}>
              Start wizard
            </Button>
          ) : (
            <Tooltip title={!scanId ? "Select an assessment first" : ""} placement="top">
              <span style={{ display: "block" }}>
                <Button size="small" variant="contained" fullWidth startIcon={<RocketLaunch />}
                  onClick={() => onRun(agent.key)}
                  disabled={!scanId}
                  sx={{ fontSize: 11 }}>
                  Run agent
                </Button>
              </span>
            </Tooltip>
          )}
        </Box>
      </CardContent>
    </Card>
  );
}

// ── Wizard modal ──────────────────────────────────────────────────────────────

interface WizardState {
  environment: string;
  system: string;
  framework: string;
  hasDiagram: boolean;
  hasCloudDetails: boolean;
}

function WizardModal({ agent, open, onClose, onLaunch }: {
  agent: AgentDef | null;
  open: boolean;
  onClose: () => void;
  onLaunch: (state: WizardState) => void;
}) {
  const [step, setStep] = useState(0);
  const [state, setState] = useState<WizardState>({
    environment: "", system: "", framework: "", hasDiagram: false, hasCloudDetails: false,
  });

  const canLaunch = state.environment && state.system && state.hasDiagram;

  const handleClose = () => { setStep(0); setState({ environment: "", system: "", framework: "", hasDiagram: false, hasCloudDetails: false }); onClose(); };

  const preflight = [
    { label: "Environment defined", pass: !!state.environment },
    { label: "System/workload described", pass: !!state.system },
    { label: "Architecture diagram uploaded", pass: state.hasDiagram },
    { label: "Cloud infrastructure details", pass: state.hasCloudDetails, optional: true },
    { label: "Compliance framework selected", pass: !!state.framework, optional: true },
  ];

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ pb: 1 }}>
        <Typography sx={{ fontWeight: 700, fontSize: 16 }}>{agent?.name || ""} Wizard</Typography>
        <Stepper activeStep={step} sx={{ mt: 1.5 }} alternativeLabel>
          {["Define scope", "Bring inputs", "Readiness check"].map(l => (
            <Step key={l}><StepLabel sx={{ "& .MuiStepLabel-label": { fontSize: 11 } }}>{l}</StepLabel></Step>
          ))}
        </Stepper>
      </DialogTitle>
      <Divider />
      <DialogContent>
        {step === 0 && (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2, pt: 1 }}>
            <FormControl size="small" fullWidth>
              <InputLabel>Environment *</InputLabel>
              <Select label="Environment *" value={state.environment} onChange={e => setState(s => ({ ...s, environment: e.target.value }))}>
                {["Azure", "AWS", "GCP", "On-premises", "Hybrid", "Multi-cloud"].map(v => <MenuItem key={v} value={v}>{v}</MenuItem>)}
              </Select>
            </FormControl>
            <TextField size="small" label="System / workload *" multiline rows={2} value={state.system}
              onChange={e => setState(s => ({ ...s, system: e.target.value }))}
              placeholder="Describe the system being reviewed, e.g. 'Customer-facing API on Azure AKS with SQL backend'" />
            <FormControl size="small" fullWidth>
              <InputLabel>Target framework (optional)</InputLabel>
              <Select label="Target framework (optional)" value={state.framework} onChange={e => setState(s => ({ ...s, framework: e.target.value }))}>
                <MenuItem value="">None</MenuItem>
                {["NIST CSF 2.0", "ISO 27001:2022", "CIS Controls v8", "PCI DSS v4.0", "GDPR"].map(v => <MenuItem key={v} value={v}>{v}</MenuItem>)}
              </Select>
            </FormControl>
          </Box>
        )}

        {step === 1 && (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5, pt: 1 }}>
            <Typography variant="body2" sx={{ color: "text.secondary", mb: 1 }}>
              Upload or confirm the inputs needed for this analysis. Required items are marked with *.
            </Typography>
            {[
              { label: "Architecture / data-flow diagram *", key: "hasDiagram" as const, required: true },
              { label: "Cloud infrastructure details (export or description)", key: "hasCloudDetails" as const, required: false },
            ].map(item => (
              <Box key={item.key} sx={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                p: 1.5, border: "1px solid", borderColor: state[item.key] ? "primary.main" : "rgba(255,255,255,0.1)",
                borderRadius: 1, bgcolor: state[item.key] ? "rgba(99,102,241,0.06)" : "transparent",
              }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  {state[item.key]
                    ? <CheckCircle sx={{ fontSize: 18, color: "primary.main" }} />
                    : <UploadFile sx={{ fontSize: 18, color: "text.secondary" }} />}
                  <Typography sx={{ fontSize: 13 }}>{item.label}</Typography>
                </Box>
                <Button size="small" variant={state[item.key] ? "outlined" : "contained"} sx={{ fontSize: 11, minWidth: 80 }}
                  onClick={() => setState(s => ({ ...s, [item.key]: !s[item.key] }))}>
                  {state[item.key] ? "Uploaded" : "Upload"}
                </Button>
              </Box>
            ))}
            <Typography variant="caption" sx={{ color: "text.secondary", mt: 0.5 }}>
              Note: In a future release, files will be uploaded directly. For now, confirming availability is sufficient to proceed.
            </Typography>
          </Box>
        )}

        {step === 2 && (
          <Box sx={{ pt: 1 }}>
            <Typography variant="body2" sx={{ color: "text.secondary", mb: 1.5 }}>
              Preflight check — ensure all required inputs are ready before launching.
            </Typography>
            <Box sx={{ display: "flex", flexDirection: "column", gap: 1, fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 1.5, borderRadius: 1 }}>
              {preflight.map((item, i) => (
                <Box key={i} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  {item.pass
                    ? <CheckCircle sx={{ fontSize: 15, color: "#22c55e" }} />
                    : <PendingOutlined sx={{ fontSize: 15, color: item.optional ? "#f59e0b" : "#ef4444" }} />}
                  <Typography sx={{ fontSize: 12, color: item.pass ? "#22c55e" : item.optional ? "#f59e0b" : "#ef4444" }}>
                    {item.pass ? "PASS" : item.optional ? "SKIP"  : "FAIL"}
                  </Typography>
                  <Typography sx={{ fontSize: 12, color: "text.secondary" }}>{item.label}{item.optional ? " (optional)" : ""}</Typography>
                </Box>
              ))}
            </Box>
            {!canLaunch && (
              <Alert severity="warning" sx={{ mt: 2, fontSize: 12 }}>
                Complete required items before launching.
              </Alert>
            )}
          </Box>
        )}
      </DialogContent>
      <DialogActions sx={{ p: 2, pt: 0 }}>
        <Button onClick={handleClose} color="inherit" size="small">Cancel</Button>
        {step > 0 && <Button onClick={() => setStep(s => s - 1)} size="small">Back</Button>}
        {step < 2
          ? <Button variant="contained" size="small" onClick={() => setStep(s => s + 1)}
              disabled={step === 0 && (!state.environment || !state.system)}
              endIcon={<ArrowForward />}>Next</Button>
          : <Button variant="contained" size="small" disabled={!canLaunch}
              startIcon={<RocketLaunch />}
              onClick={() => { onLaunch(state); handleClose(); }}>
              Launch
            </Button>
        }
      </DialogActions>
    </Dialog>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AIAssistedReview() {
  const { clientId } = useActiveClient();
  const qc = useQueryClient();

  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [catalogTab, setCatalogTab] = useState("all");
  const [wizardAgent, setWizardAgent] = useState<AgentDef | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [activeStep, setActiveStep] = useState(0);

  // Load scans
  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ["scans", clientId],
    queryFn: () => scansApi.list(clientId),
    enabled: !!clientId,
  });

  const completedScans: Scan[] = (scansData || []).filter(
    (s: Scan) => s.status === "completed"
  );

  // Advisory call
  const advisoryMutation = useMutation({
    mutationFn: (scanId: string) => aiReviewApi.scanAdvisory(clientId, scanId),
  });

  // Agent run
  const runMutation = useMutation({
    mutationFn: ({ agentKey, scanId }: { agentKey: string; scanId: string }) =>
      agentsApi.run(clientId, { agent_type: agentKey, scan_id: scanId, input_data: {} }),
    onSuccess: () => {
      toast.success("Agent queued — check AI Buddies for results");
      qc.invalidateQueries({ queryKey: ["agent-runs"] });
      setActiveStep(3);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to start agent"),
  });

  const handleSelectScan = (scan: Scan) => {
    setSelectedScan(scan);
    setActiveStep(1);
    advisoryMutation.mutate(scan.id);
  };

  const handleRunAgent = (agentKey: string) => {
    if (!selectedScan) return;
    runMutation.mutate({ agentKey, scanId: selectedScan.id });
    setActiveStep(3);
  };

  const handleWizardLaunch = (state: WizardState) => {
    if (!selectedScan) return;
    const context = `Architecture Review Request\nEnvironment: ${state.environment}\nSystem: ${state.system}\nFramework: ${state.framework || "none"}\nDiagram available: ${state.hasDiagram ? "yes" : "no"}\nCloud details available: ${state.hasCloudDetails ? "yes" : "no"}`;
    agentsApi.run(clientId, {
      agent_type: "orchestrator",
      scan_id: selectedScan.id,
      input_data: { extra_context: context },
    }).then(() => {
      toast.success("Input brief collected — Orchestrator will run with your architecture context");
      qc.invalidateQueries({ queryKey: ["agent-runs"] });
      setActiveStep(3);
    }).catch((e: any) => toast.error(e?.response?.data?.detail || "Launch failed"));
  };

  const advisory: ScanAdvisory | undefined = advisoryMutation.data;
  const filteredCatalog = catalogTab === "all"
    ? AGENT_CATALOG
    : AGENT_CATALOG.filter(a => a.category === catalogTab);

  return (
    <Box sx={{ p: 3, maxWidth: 1200, mx: "auto" }}>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
          <AutoAwesome sx={{ color: "primary.main", fontSize: 22 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>AI Assisted Review</Typography>
        </Box>
        <Typography variant="body2" sx={{ color: "text.secondary", mb: 2.5 }}>
          Select a completed assessment and let AI recommend which agents to run next, or browse the full agent catalog.
        </Typography>

        {/* Stepper */}
        <Stepper activeStep={activeStep} alternativeLabel sx={{ maxWidth: 600 }}>
          {WIZARD_STEPS.map(label => (
            <Step key={label}>
              <StepLabel sx={{ "& .MuiStepLabel-label": { fontSize: 12 } }}>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>
      </Box>

      <Divider sx={{ mb: 3 }} />

      {/* Section 1 — Assessment selection */}
      <Box sx={{ mb: 4 }}>
        <Typography sx={{ fontWeight: 700, fontSize: 14, mb: 1.5, display: "flex", alignItems: "center", gap: 0.5 }}>
          <BugReport sx={{ fontSize: 16 }} />
          01 · SELECT ASSESSMENT
        </Typography>

        {scansLoading ? (
          <Grid container spacing={2}>
            {[1, 2, 3].map(i => (
              <Grid key={i} size={{ xs: 12, sm: 6, md: 3 }}>
                <Skeleton variant="rectangular" height={120} sx={{ borderRadius: 1 }} />
              </Grid>
            ))}
          </Grid>
        ) : completedScans.length === 0 ? (
          <Alert severity="info" sx={{ maxWidth: 500 }}>
            No completed assessments found for this project. Run a scan first to use AI Assisted Review.
          </Alert>
        ) : (
          <Grid container spacing={2}>
            {completedScans.map(scan => (
              <Grid key={scan.id} size={{ xs: 12, sm: 6, md: 3 }}>
                <ScanCard
                  scan={scan}
                  selected={selectedScan?.id === scan.id}
                  onClick={() => handleSelectScan(scan)}
                />
              </Grid>
            ))}
          </Grid>
        )}
      </Box>

      {/* Section 2 — AI recommendation (after scan selected) */}
      {selectedScan && (
        <Box sx={{ mb: 4 }}>
          <Typography sx={{ fontWeight: 700, fontSize: 14, mb: 1.5, display: "flex", alignItems: "center", gap: 0.5 }}>
            <AutoAwesome sx={{ fontSize: 16 }} />
            02 · AI RECOMMENDATION
          </Typography>

          {advisoryMutation.isPending ? (
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, p: 2, border: "1px solid rgba(255,255,255,0.1)", borderRadius: 1 }}>
              <CircularProgress size={18} />
              <Typography sx={{ fontSize: 13, color: "text.secondary" }}>
                AI is analysing your scan…
              </Typography>
            </Box>
          ) : advisoryMutation.isError ? (
            <Alert severity="warning" sx={{ mb: 2 }}>
              Could not fetch AI recommendations. You can still browse the full agent catalog below.
            </Alert>
          ) : advisory ? (
            <>
              {/* AI banner */}
              <Box sx={{
                display: "flex", alignItems: "flex-start", gap: 1.5, p: 2, mb: 2.5,
                borderLeft: "3px solid", borderColor: "primary.main",
                bgcolor: "rgba(99,102,241,0.06)", borderRadius: "0 4px 4px 0",
              }}>
                <AutoAwesome sx={{ color: "primary.main", fontSize: 18, mt: 0.2, flexShrink: 0 }} />
                <Typography sx={{ fontSize: 13, color: "text.primary", lineHeight: 1.6 }}>
                  {advisory.banner}
                </Typography>
              </Box>

              {/* Recommendation cards */}
              <Grid container spacing={2}>
                {advisory.recommendations.map((rec, i) => (
                  <Grid key={i} size={{ xs: 12, sm: 6, md: 4 }}>
                    <RecCard
                      rec={rec}
                      onRun={() => { handleRunAgent(rec.agent_key); setActiveStep(2); }}
                      onWizard={() => {
                        const def = AGENT_CATALOG.find(a => a.key === rec.agent_key);
                        if (def) { setWizardAgent(def); setWizardOpen(true); setActiveStep(2); }
                      }}
                    />
                  </Grid>
                ))}
              </Grid>
            </>
          ) : null}
        </Box>
      )}

      {/* Section 3 — Full agent catalog (after scan selected) */}
      {selectedScan && (
        <Box>
          <Typography sx={{ fontWeight: 700, fontSize: 14, mb: 1.5, display: "flex", alignItems: "center", gap: 0.5 }}>
            <SmartToy sx={{ fontSize: 16 }} />
            03 · FULL AGENT CATALOG
          </Typography>

          {/* A&E callout */}
          <Box sx={{
            display: "flex", alignItems: "flex-start", gap: 1.5, p: 2, mb: 2.5,
            bgcolor: "rgba(3,105,161,0.08)", border: "1px solid rgba(3,105,161,0.2)", borderRadius: 1,
          }}>
            <Architecture sx={{ color: "#0284c7", fontSize: 20, mt: 0.2, flexShrink: 0 }} />
            <Box>
              <Typography sx={{ fontWeight: 700, fontSize: 13, color: "#0284c7", mb: 0.3 }}>
                Architecture & Engineering agents
              </Typography>
              <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
                These agents analyse system designs, IaC templates, and network topology — not scan findings.
                Use the guided wizard to provide the right inputs before running.
              </Typography>
            </Box>
          </Box>

          {/* Category tabs */}
          <Tabs value={catalogTab} onChange={(_, v) => setCatalogTab(v)} sx={{ mb: 2, borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
            {CATEGORY_TABS.map(t => (
              <Tab key={t.value} value={t.value} label={t.label} sx={{ fontSize: 12, textTransform: "none", minWidth: "auto" }} />
            ))}
          </Tabs>

          <Grid container spacing={2}>
            {filteredCatalog.map(agent => (
              <Grid key={agent.key} size={{ xs: 12, sm: 6, md: 4 }}>
                <CatalogCard
                  agent={agent}
                  scanId={selectedScan?.id}
                  onRun={(key) => { handleRunAgent(key); setActiveStep(2); }}
                  onWizard={(a) => { setWizardAgent(a); setWizardOpen(true); setActiveStep(2); }}
                />
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Show a hint when no scan is selected */}
      {!selectedScan && !scansLoading && completedScans.length > 0 && (
        <Box sx={{ mt: 2, p: 3, border: "1px dashed rgba(255,255,255,0.1)", borderRadius: 2, textAlign: "center" }}>
          <SmartToy sx={{ fontSize: 36, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary", fontSize: 13 }}>
            Select an assessment above to see AI-powered agent recommendations and the full agent catalog.
          </Typography>
        </Box>
      )}

      {/* Running indicator */}
      {runMutation.isPending && (
        <Box sx={{ position: "fixed", bottom: 80, right: 24, p: 2, bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 2, display: "flex", alignItems: "center", gap: 1, boxShadow: 4 }}>
          <CircularProgress size={16} />
          <Typography sx={{ fontSize: 13 }}>Starting agent…</Typography>
        </Box>
      )}

      {/* Wizard modal */}
      <WizardModal
        agent={wizardAgent}
        open={wizardOpen}
        onClose={() => setWizardOpen(false)}
        onLaunch={handleWizardLaunch}
      />
    </Box>
  );
}
