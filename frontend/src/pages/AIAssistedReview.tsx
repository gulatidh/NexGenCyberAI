import React, { useState, useMemo } from "react";
import {
  Box, Typography, Grid, Card, CardContent, Chip, Stepper, Step, StepLabel,
  Tabs, Tab, Button, CircularProgress, Dialog, DialogTitle, DialogContent,
  DialogActions, Divider, Alert, TextField, MenuItem, Select, FormControl,
  InputLabel, Tooltip, Skeleton, Checkbox, Avatar,
} from "@mui/material";
import {
  AutoAwesome, RocketLaunch, Architecture, CheckCircle, PendingOutlined,
  UploadFile, ArrowForward, SmartToy, BugReport, PlaylistAddCheck,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";

import { useActiveClient } from "../contexts/ClientContext";
import { scansApi, agentsApi, aiReviewApi, agentCatalogApi } from "../services/api";
import { AgentType } from "../types";

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

interface CatalogAgent {
  id: string;
  key: string;
  name: string;
  group_key: string;
  group_label: string;
  description?: string;
  domain?: string;
  legacy_orchestrator: boolean;
  is_enabled: boolean;
  accent_color?: string;
  avatar_url?: string;
}

interface AgentGroup {
  key: string;
  label: string;
  agents: CatalogAgent[];
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

// ── Helpers ────────────────────────────────────────────────────────────────────

const CONNECTOR_CHIP: Record<string, { label: string; color: string }> = {
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

function getChip(ct: string) {
  return CONNECTOR_CHIP[ct] || { label: ct?.toUpperCase() || "SCAN", color: "#6b7280" };
}

function getScanConnectorType(scan: Scan): string {
  return scan.connector?.connector_type || scan.connector_type || "";
}

// Whether this agent requires a scan to be selected
function requiresScan(agent: CatalogAgent): boolean {
  return agent.legacy_orchestrator || agent.group_key === "operational";
}

// A&E agents get a wizard
function isWizardAgent(agent: CatalogAgent): boolean {
  return agent.group_key === "architecture_engineering";
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
      <Typography sx={{ ml: 0.5, fontSize: 12, color: "primary.main", fontWeight: 700 }}>{score}%</Typography>
    </Box>
  );
}

// ── Scan card ─────────────────────────────────────────────────────────────────

function ScanCard({ scan, selected, onClick }: { scan: Scan; selected: boolean; onClick: () => void }) {
  const ct = getScanConnectorType(scan);
  const chip = getChip(ct);
  const s = scan.summary || {};
  const date = scan.completed_at || scan.created_at || "";
  const dateStr = date ? new Date(date).toLocaleDateString() : "";

  return (
    <Card onClick={onClick} sx={{
      cursor: "pointer", position: "relative",
      border: selected ? "2px solid" : "1px solid rgba(255,255,255,0.1)",
      borderColor: selected ? "primary.main" : undefined,
      bgcolor: selected ? "rgba(99,102,241,0.08)" : "background.paper",
      transition: "all 0.15s",
      "&:hover": { borderColor: "primary.main", boxShadow: "0 0 0 1px rgba(99,102,241,0.3)" },
    }}>
      {selected && (
        <Box sx={{ position: "absolute", top: 8, right: 8, width: 20, height: 20, borderRadius: "50%", bgcolor: "primary.main", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <CheckCircle sx={{ fontSize: 13, color: "#fff" }} />
        </Box>
      )}
      <CardContent sx={{ pb: "12px !important" }}>
        <Chip label={chip.label} size="small"
          sx={{ bgcolor: `${chip.color}22`, color: chip.color, fontSize: 10, height: 18, mb: 1, fontWeight: 700 }} />
        <Typography sx={{ fontSize: 13, fontWeight: 600, mb: 0.5, pr: selected ? 3 : 0 }} noWrap title={scan.name}>{scan.name}</Typography>
        {dateStr && <Typography sx={{ fontSize: 11, color: "text.secondary", mb: 1 }}>{dateStr}</Typography>}
        <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
          {(s.critical || 0) > 0 && <Chip label={`${s.critical}C`} size="small" sx={{ height: 16, fontSize: 10, bgcolor: "#ef444422", color: "#ef4444" }} />}
          {(s.high || 0) > 0 && <Chip label={`${s.high}H`} size="small" sx={{ height: 16, fontSize: 10, bgcolor: "#f9731622", color: "#f97316" }} />}
          {(s.medium || 0) > 0 && <Chip label={`${s.medium}M`} size="small" sx={{ height: 16, fontSize: 10, bgcolor: "#eab30822", color: "#eab308" }} />}
          {(s.low || 0) > 0 && <Chip label={`${s.low}L`} size="small" sx={{ height: 16, fontSize: 10, bgcolor: "#22c55e22", color: "#22c55e" }} />}
          {((s.critical || 0) + (s.high || 0) + (s.medium || 0) + (s.low || 0)) === 0 && (
            <Chip label="No findings" size="small" sx={{ height: 16, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
          )}
        </Box>
      </CardContent>
    </Card>
  );
}

// ── Recommendation card ────────────────────────────────────────────────────────

function RecCard({ rec, allAgents, onRun, onWizard, alreadyRan }: {
  rec: AgentRecommendation;
  allAgents: CatalogAgent[];
  onRun: () => void;
  onWizard?: () => void;
  alreadyRan: boolean;
}) {
  const agent = allAgents.find(a => a.key === rec.agent_key);
  const name = agent?.name || rec.agent_key;
  const catLabel = agent?.group_label || "";
  const brings = rec.bring || [];
  const wizard = agent ? isWizardAgent(agent) : false;
  const accentColor = agent?.accent_color || "primary.main";

  return (
    <Card sx={{
      borderLeft: "3px solid", borderColor: accentColor,
      bgcolor: "rgba(99,102,241,0.04)", height: "100%", display: "flex", flexDirection: "column",
      position: "relative",
    }}>
      {alreadyRan && (
        <Chip label="Already ran on this scan" size="small"
          sx={{ position: "absolute", top: 8, right: 8, fontSize: 9, height: 16, bgcolor: "rgba(234,179,8,0.12)", color: "#eab308" }} />
      )}
      <Box sx={{ height: 4, background: `linear-gradient(90deg, ${accentColor}99 0%, ${accentColor}11 100%)`, borderTopRightRadius: 4 }} />
      <CardContent sx={{ flex: 1, display: "flex", flexDirection: "column" }}>
        <Chip label={catLabel} size="small"
          sx={{ fontSize: 10, height: 18, bgcolor: "rgba(99,102,241,0.15)", color: "primary.main", alignSelf: "flex-start" }} />
        <Typography sx={{ fontSize: 15, fontWeight: 700, mt: 0.5 }}>{name}</Typography>
        <MatchBars score={rec.match_score} />
        <Typography sx={{ fontSize: 12, color: "text.secondary", mt: 1 }}>
          <strong>Why: </strong>{rec.reasoning}
        </Typography>
        {brings.length > 0 && (
          <Box sx={{ mt: 1 }}>
            <Typography sx={{ fontSize: 11, color: "text.secondary", mb: 0.5 }}>What you get:</Typography>
            {brings.map((b, i) => (
              <Chip key={i} label={b} size="small" variant="outlined"
                sx={{ mr: 0.5, mb: 0.5, fontSize: 10, height: 18, borderColor: "rgba(255,255,255,0.12)", color: "text.secondary" }} />
            ))}
          </Box>
        )}
        <Box sx={{ mt: "auto", pt: 1.5 }}>
          {wizard
            ? <Button size="small" variant="outlined" fullWidth startIcon={<Architecture />} onClick={onWizard} sx={{ fontSize: 12 }}>Start wizard</Button>
            : <Button size="small" variant="contained" fullWidth startIcon={<RocketLaunch />} onClick={onRun} sx={{ fontSize: 12 }}>Run agent</Button>
          }
        </Box>
      </CardContent>
    </Card>
  );
}

// ── Catalog card ──────────────────────────────────────────────────────────────

function CatalogCard({ agent, onRun, onWizard, scanId, alreadyRan, selectMode, selected, onToggle }: {
  agent: CatalogAgent;
  onRun: (agent: CatalogAgent) => void;
  onWizard: (agent: CatalogAgent) => void;
  scanId?: string;
  alreadyRan: boolean;
  selectMode: boolean;
  selected: boolean;
  onToggle: (key: string) => void;
}) {
  const needsScan = requiresScan(agent);
  const isWizard = isWizardAgent(agent);
  const canRun = !needsScan || !!scanId;
  const accentColor = agent.accent_color || "#6366f1";

  return (
    <Card onClick={selectMode ? () => onToggle(agent.key) : undefined} sx={{
      height: "100%", display: "flex", flexDirection: "column", position: "relative",
      cursor: selectMode ? "pointer" : "default",
      border: selected ? "2px solid" : "1px solid rgba(255,255,255,0.08)",
      borderColor: selected ? "primary.main" : undefined,
      bgcolor: selected ? "rgba(99,102,241,0.06)" : "background.paper",
      transition: "all 0.12s",
      ...(selectMode ? { "&:hover": { borderColor: "primary.main" } } : {}),
    }}>
      {selectMode && (
        <Checkbox checked={selected} size="small"
          sx={{ position: "absolute", top: 4, right: 4, zIndex: 1, p: 0.5 }}
          onClick={(e) => { e.stopPropagation(); onToggle(agent.key); }} />
      )}
      {alreadyRan && !selectMode && (
        <Chip label="Ran before" size="small"
          sx={{ position: "absolute", top: 8, right: 8, fontSize: 9, height: 16, bgcolor: "rgba(34,197,94,0.12)", color: "#22c55e" }} />
      )}
      <Box sx={{ height: 3, bgcolor: accentColor, opacity: 0.5 }} />
      <CardContent sx={{ flex: 1, display: "flex", flexDirection: "column" }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
          <Avatar sx={{ width: 34, height: 34, bgcolor: `${accentColor}22`, fontSize: 14, color: accentColor, fontWeight: 700, flexShrink: 0 }}>
            {agent.name.charAt(0)}
          </Avatar>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography sx={{ fontSize: 13, fontWeight: 700 }}>{agent.name}</Typography>
            {agent.domain && (
              <Chip label={agent.domain} size="small"
                sx={{ fontSize: 9, height: 16, mt: 0.3, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
            )}
          </Box>
        </Box>
        <Typography sx={{ fontSize: 12, color: "text.secondary", flex: 1, lineHeight: 1.5 }}>
          {agent.description || "AI security analysis agent."}
        </Typography>
        {!selectMode && (
          <Box sx={{ mt: 1.5 }}>
            {isWizard
              ? <Button size="small" variant="outlined" fullWidth startIcon={<Architecture />}
                  onClick={() => onWizard(agent)} sx={{ fontSize: 11 }}>Start wizard</Button>
              : (
                <Tooltip title={!canRun ? "Select an assessment first" : ""} placement="top">
                  <span style={{ display: "block" }}>
                    <Button size="small" variant="contained" fullWidth startIcon={<RocketLaunch />}
                      disabled={!canRun} onClick={() => onRun(agent)} sx={{ fontSize: 11 }}>
                      Run agent
                    </Button>
                  </span>
                </Tooltip>
              )
            }
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

// ── Wizard modal ──────────────────────────────────────────────────────────────

interface WizardState {
  environment: string;
  system: string;
  framework: string;
  diagramFile: File | null;
  cloudDetailsFile: File | null;
}

function WizardModal({ agent, open, onClose, onLaunch }: {
  agent: CatalogAgent | null;
  open: boolean;
  onClose: () => void;
  onLaunch: (state: WizardState) => void;
}) {
  const [step, setStep] = useState(0);
  const [state, setState] = useState<WizardState>({ environment: "", system: "", framework: "", diagramFile: null, cloudDetailsFile: null });

  const canLaunch = !!state.environment && !!state.system && !!state.diagramFile;

  const handleClose = () => {
    setStep(0);
    setState({ environment: "", system: "", framework: "", diagramFile: null, cloudDetailsFile: null });
    onClose();
  };

  const preflight = [
    { label: "Environment defined", pass: !!state.environment },
    { label: "System/workload described", pass: !!state.system },
    { label: "Architecture diagram uploaded", pass: !!state.diagramFile },
    { label: "Cloud infrastructure details", pass: !!state.cloudDetailsFile, optional: true },
    { label: "Compliance framework selected", pass: !!state.framework, optional: true },
  ];

  const uploadRows = [
    { label: "Architecture / data-flow diagram *", key: "diagramFile" as const, accept: ".png,.jpg,.jpeg,.pdf,.svg,.drawio,.vsdx" },
    { label: "Cloud infrastructure details (optional)", key: "cloudDetailsFile" as const, accept: ".json,.csv,.txt,.pdf" },
  ];

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ pb: 1 }}>
        <Typography sx={{ fontWeight: 700, fontSize: 16 }}>{agent?.name || ""} — Input Wizard</Typography>
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
              <Select label="Environment *" value={state.environment}
                onChange={e => setState(s => ({ ...s, environment: e.target.value }))}>
                {["Azure", "AWS", "GCP", "On-premises", "Hybrid", "Multi-cloud"].map(v => <MenuItem key={v} value={v}>{v}</MenuItem>)}
              </Select>
            </FormControl>
            <TextField size="small" label="System / workload *" multiline rows={2}
              value={state.system} onChange={e => setState(s => ({ ...s, system: e.target.value }))}
              placeholder="e.g. 'Customer-facing API on Azure AKS with SQL backend'" />
            <FormControl size="small" fullWidth>
              <InputLabel>Target framework (optional)</InputLabel>
              <Select label="Target framework (optional)" value={state.framework}
                onChange={e => setState(s => ({ ...s, framework: e.target.value }))}>
                <MenuItem value="">None</MenuItem>
                {["NIST CSF 2.0", "ISO 27001:2022", "CIS Controls v8", "PCI DSS v4.0", "GDPR"].map(v => <MenuItem key={v} value={v}>{v}</MenuItem>)}
              </Select>
            </FormControl>
          </Box>
        )}
        {step === 1 && (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5, pt: 1 }}>
            <Typography variant="body2" sx={{ color: "text.secondary", mb: 1 }}>Upload the inputs needed for this analysis.</Typography>
            {uploadRows.map(item => {
              const file = state[item.key];
              return (
                <Box key={item.key} sx={{
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                  p: 1.5, border: "1px solid", borderColor: file ? "primary.main" : "rgba(255,255,255,0.1)",
                  borderRadius: 1, bgcolor: file ? "rgba(99,102,241,0.06)" : "transparent",
                }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    {file ? <CheckCircle sx={{ fontSize: 18, color: "primary.main" }} /> : <UploadFile sx={{ fontSize: 18, color: "text.secondary" }} />}
                    <Box>
                      <Typography sx={{ fontSize: 13 }}>{item.label}</Typography>
                      {file && <Typography sx={{ fontSize: 11, color: "text.secondary" }}>{(file as File).name}</Typography>}
                    </Box>
                  </Box>
                  <Button size="small" variant={file ? "outlined" : "contained"} component="label" sx={{ fontSize: 11, minWidth: 80 }}>
                    {file ? "Change" : "Upload"}
                    <input type="file" hidden accept={item.accept} onChange={(e) => {
                      const f = e.target.files?.[0] || null;
                      setState(s => ({ ...s, [item.key]: f }));
                    }} />
                  </Button>
                </Box>
              );
            })}
          </Box>
        )}
        {step === 2 && (
          <Box sx={{ pt: 1 }}>
            <Typography variant="body2" sx={{ color: "text.secondary", mb: 1.5 }}>Preflight check before launch.</Typography>
            <Box sx={{ display: "flex", flexDirection: "column", gap: 1, bgcolor: "rgba(0,0,0,0.2)", p: 1.5, borderRadius: 1 }}>
              {preflight.map((item, i) => (
                <Box key={i} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  {item.pass
                    ? <CheckCircle sx={{ fontSize: 15, color: "#22c55e" }} />
                    : <PendingOutlined sx={{ fontSize: 15, color: item.optional ? "#f59e0b" : "#ef4444" }} />}
                  <Typography sx={{ fontSize: 12, color: item.pass ? "#22c55e" : item.optional ? "#f59e0b" : "#ef4444" }}>
                    {item.pass ? "PASS" : item.optional ? "SKIP" : "FAIL"}
                  </Typography>
                  <Typography sx={{ fontSize: 12, color: "text.secondary" }}>{item.label}{item.optional ? " (optional)" : ""}</Typography>
                </Box>
              ))}
            </Box>
            {!canLaunch && <Alert severity="warning" sx={{ mt: 2, fontSize: 12 }}>Complete required items before launching.</Alert>}
          </Box>
        )}
      </DialogContent>
      <DialogActions sx={{ p: 2, pt: 0 }}>
        <Button onClick={handleClose} color="inherit" size="small">Cancel</Button>
        {step > 0 && <Button onClick={() => setStep(s => s - 1)} size="small">Back</Button>}
        {step < 2
          ? <Button variant="contained" size="small"
              disabled={step === 0 && (!state.environment || !state.system)}
              onClick={() => setStep(s => s + 1)} endIcon={<ArrowForward />}>Next</Button>
          : <Button variant="contained" size="small" disabled={!canLaunch}
              startIcon={<RocketLaunch />} onClick={() => { onLaunch(state); handleClose(); }}>Launch</Button>
        }
      </DialogActions>
    </Dialog>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

const WIZARD_STEPS = ["Select assessment", "AI recommendation", "Choose agent", "Run"];

export default function AIAssistedReview() {
  const { clientId } = useActiveClient();
  const qc = useQueryClient();

  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [catalogTab, setCatalogTab] = useState("all");
  const [wizardAgent, setWizardAgent] = useState<CatalogAgent | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const [selectMode, setSelectMode] = useState(false);
  const [selectedAgents, setSelectedAgents] = useState<Set<string>>(new Set());

  // Load completed scans
  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ["scans", clientId],
    queryFn: () => scansApi.list(clientId),
    enabled: !!clientId,
  });
  const completedScans: Scan[] = useMemo(
    () => (scansData || []).filter((s: Scan) => s.status === "completed"),
    [scansData]
  );

  // Load full agent catalog from backend (same as AI Buddies)
  const { data: catalogData, isLoading: catalogLoading } = useQuery<{ groups: AgentGroup[] }>({
    queryKey: ["agent-catalog-review"],
    queryFn: () => agentCatalogApi.list(false),
  });

  const allGroups: AgentGroup[] = useMemo(() => catalogData?.groups || [], [catalogData]);
  const allAgents: CatalogAgent[] = useMemo(() => allGroups.flatMap(g => g.agents), [allGroups]);

  // Category tabs = "All" + each group that has enabled agents
  const catTabs = useMemo(() => [
    { value: "all", label: "All" },
    ...allGroups
      .filter(g => g.agents.some(a => a.is_enabled))
      .map(g => ({ value: g.key, label: g.label })),
  ], [allGroups]);

  const filteredAgents: CatalogAgent[] = useMemo(() => {
    const enabled = allAgents.filter(a => a.is_enabled);
    return catalogTab === "all" ? enabled : enabled.filter(a => a.group_key === catalogTab);
  }, [allAgents, catalogTab]);

  // Load agent runs for duplicate detection
  const { data: agentRuns } = useQuery({
    queryKey: ["agent-runs-all", clientId],
    queryFn: () => agentsApi.listRuns(clientId),
    enabled: !!clientId,
  });

  const alreadyRan = useMemo(() => new Set<string>(
    (agentRuns || [])
      .filter((r: any) => r.status === "completed" && (!selectedScan || r.scan_id === selectedScan.id))
      .map((r: any) => r.agent_type)
  ), [agentRuns, selectedScan]);

  // Advisory call
  const advisoryMutation = useMutation({
    mutationFn: (scanId: string) => aiReviewApi.scanAdvisory(clientId, scanId),
  });

  const advisory: ScanAdvisory | undefined = advisoryMutation.data;

  // Run legacy agent (orchestrator, risk_manager, etc.)
  const legacyRunMutation = useMutation({
    mutationFn: ({ agentKey, scanId }: { agentKey: string; scanId?: string }) =>
      agentsApi.run(clientId, { agent_type: agentKey, scan_id: scanId, input_data: {} }),
    onSuccess: () => {
      toast.success("Agent queued — check AI Buddies for results");
      qc.invalidateQueries({ queryKey: ["agent-runs-all"] });
      setActiveStep(3);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to start agent"),
  });

  // Run AI buddy agent (non-legacy)
  const buddyRunMutation = useMutation({
    mutationFn: ({ agentId, scanId }: { agentId: string; scanId?: string }) =>
      agentCatalogApi.run(agentId, undefined, clientId, scanId, undefined),
    onSuccess: () => {
      toast.success("Agent queued — check AI Buddies for results");
      qc.invalidateQueries({ queryKey: ["agent-runs-all"] });
      setActiveStep(3);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to start agent"),
  });

  const isPending = legacyRunMutation.isPending || buddyRunMutation.isPending;

  const handleSelectScan = (scan: Scan) => {
    setSelectedScan(scan);
    setActiveStep(1);
    advisoryMutation.mutate(scan.id);
  };

  const handleRunAgent = (agent: CatalogAgent) => {
    if (agent.legacy_orchestrator || agent.group_key === "operational") {
      legacyRunMutation.mutate({ agentKey: agent.key, scanId: selectedScan?.id });
    } else {
      buddyRunMutation.mutate({ agentId: agent.id, scanId: selectedScan?.id });
    }
    setActiveStep(3);
  };

  const handleRunByKey = (agentKey: string) => {
    const agent = allAgents.find(a => a.key === agentKey);
    if (agent) handleRunAgent(agent);
  };

  const handleBatchRun = async () => {
    const toRun = Array.from(selectedAgents);
    let successCount = 0;
    for (const agentKey of toRun) {
      const agent = allAgents.find(a => a.key === agentKey);
      if (!agent) continue;
      if (isWizardAgent(agent)) {
        setWizardAgent(agent);
        setWizardOpen(true);
        break;
      }
      if (requiresScan(agent) && !selectedScan) continue;
      try {
        if (agent.legacy_orchestrator || agent.group_key === "operational") {
          await agentsApi.run(clientId, { agent_type: agentKey, scan_id: selectedScan?.id, input_data: {} });
        } else {
          await agentCatalogApi.run(agent.id, undefined, clientId, selectedScan?.id, undefined);
        }
        successCount++;
      } catch (e: any) {
        toast.error(`${agent.name}: ${e?.response?.data?.detail || "failed"}`);
      }
    }
    if (successCount > 0) {
      toast.success(`${successCount} agent${successCount > 1 ? "s" : ""} queued — check AI Buddies for results`);
      qc.invalidateQueries({ queryKey: ["agent-runs-all"] });
      setSelectedAgents(new Set());
      setSelectMode(false);
      setActiveStep(3);
    }
  };

  const handleWizardLaunch = (state: WizardState) => {
    const context = [
      `Architecture Review: ${wizardAgent?.name || ""}`,
      `Environment: ${state.environment}`,
      `System: ${state.system}`,
      `Framework: ${state.framework || "none"}`,
      `Diagram: ${state.diagramFile?.name || "none"}`,
      `Cloud details: ${state.cloudDetailsFile?.name || "none"}`,
    ].join("\n");
    if (wizardAgent) {
      buddyRunMutation.mutate({ agentId: wizardAgent.id, scanId: selectedScan?.id });
    }
  };

  const toggleAgentSelect = (key: string) => {
    setSelectedAgents(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };

  const sectionPrefix = selectedScan ? "03 · " : "02 · ";

  return (
    <Box sx={{ p: 3, maxWidth: 1280, mx: "auto", pb: selectedAgents.size > 0 ? 12 : 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
          <AutoAwesome sx={{ color: "primary.main", fontSize: 22 }} />
          <Typography variant="h5" sx={{ fontWeight: 700 }}>AI Assisted Review</Typography>
        </Box>
        <Typography variant="body2" sx={{ color: "text.secondary", mb: 2.5 }}>
          Select a completed assessment and let AI recommend agents, or browse the full catalog. Strategic and advisory agents run without a scan.
        </Typography>
        <Stepper activeStep={activeStep} alternativeLabel sx={{ maxWidth: 600 }}>
          {WIZARD_STEPS.map(label => (
            <Step key={label}><StepLabel sx={{ "& .MuiStepLabel-label": { fontSize: 12 } }}>{label}</StepLabel></Step>
          ))}
        </Stepper>
      </Box>

      <Divider sx={{ mb: 3 }} />

      {/* Section 1 — Assessment selection */}
      <Box sx={{ mb: 4 }}>
        <Typography sx={{ fontWeight: 700, fontSize: 14, mb: 1.5, display: "flex", alignItems: "center", gap: 0.5 }}>
          <BugReport sx={{ fontSize: 16 }} />
          01 · SELECT ASSESSMENT
          <Typography component="span" sx={{ ml: 1, fontSize: 12, color: "text.secondary", fontWeight: 400 }}>
            (optional — advisory, A&E, and strategic agents work without one)
          </Typography>
        </Typography>
        {scansLoading ? (
          <Grid container spacing={2}>
            {[1, 2, 3].map(i => <Grid key={i} size={{ xs: 12, sm: 6, md: 3 }}><Skeleton variant="rectangular" height={120} sx={{ borderRadius: 1 }} /></Grid>)}
          </Grid>
        ) : completedScans.length === 0 ? (
          <Alert severity="info" sx={{ maxWidth: 500 }}>No completed assessments found. You can still run advisory and A&E agents below.</Alert>
        ) : (
          <Grid container spacing={2}>
            {completedScans.map(scan => (
              <Grid key={scan.id} size={{ xs: 12, sm: 6, md: 3 }}>
                <ScanCard scan={scan} selected={selectedScan?.id === scan.id} onClick={() => handleSelectScan(scan)} />
              </Grid>
            ))}
          </Grid>
        )}
      </Box>

      {/* Section 2 — AI recommendation (after scan selected) */}
      {selectedScan && (
        <Box sx={{ mb: 4 }}>
          <Typography sx={{ fontWeight: 700, fontSize: 14, mb: 1.5, display: "flex", alignItems: "center", gap: 0.5 }}>
            <AutoAwesome sx={{ fontSize: 16 }} />02 · AI RECOMMENDATION
          </Typography>
          {advisoryMutation.isPending ? (
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, p: 2, border: "1px solid rgba(255,255,255,0.1)", borderRadius: 1 }}>
              <CircularProgress size={18} />
              <Typography sx={{ fontSize: 13, color: "text.secondary" }}>AI is analysing your scan…</Typography>
            </Box>
          ) : advisoryMutation.isError ? (
            <Alert severity="warning" sx={{ mb: 2 }}>Could not fetch AI recommendations. Browse the full agent catalog below.</Alert>
          ) : advisory ? (
            <>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5, p: 2, mb: 2.5, borderLeft: "3px solid", borderColor: "primary.main", bgcolor: "rgba(99,102,241,0.06)", borderRadius: "0 4px 4px 0" }}>
                <AutoAwesome sx={{ color: "primary.main", fontSize: 18, mt: 0.2, flexShrink: 0 }} />
                <Typography sx={{ fontSize: 13, lineHeight: 1.6 }}>{advisory.banner}</Typography>
              </Box>
              <Grid container spacing={2}>
                {advisory.recommendations.map((rec, i) => (
                  <Grid key={i} size={{ xs: 12, sm: 6, md: 4 }}>
                    <RecCard rec={rec} allAgents={allAgents} alreadyRan={alreadyRan.has(rec.agent_key)}
                      onRun={() => handleRunByKey(rec.agent_key)}
                      onWizard={() => {
                        const a = allAgents.find(x => x.key === rec.agent_key);
                        if (a) { setWizardAgent(a); setWizardOpen(true); setActiveStep(2); }
                      }} />
                  </Grid>
                ))}
              </Grid>
            </>
          ) : null}
        </Box>
      )}

      {/* Section 3 — Full agent catalog (always visible) */}
      <Box>
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1.5 }}>
          <Typography sx={{ fontWeight: 700, fontSize: 14, display: "flex", alignItems: "center", gap: 0.5 }}>
            <SmartToy sx={{ fontSize: 16 }} />
            {sectionPrefix}FULL AGENT CATALOG
            {!catalogLoading && (
              <Typography component="span" sx={{ ml: 1, fontSize: 12, color: "text.secondary", fontWeight: 400 }}>
                ({allAgents.filter(a => a.is_enabled).length} agents)
              </Typography>
            )}
          </Typography>
          <Button size="small" variant={selectMode ? "contained" : "outlined"}
            startIcon={<PlaylistAddCheck />}
            onClick={() => { setSelectMode(v => !v); if (selectMode) setSelectedAgents(new Set()); }}
            sx={{ fontSize: 11 }}>
            {selectMode ? "Done selecting" : "Select agents"}
          </Button>
        </Box>

        {/* A&E callout */}
        <Box sx={{
          display: "flex", alignItems: "flex-start", gap: 1.5, p: 2, mb: 2.5,
          bgcolor: "rgba(3,105,161,0.08)", border: "1px solid rgba(3,105,161,0.2)", borderRadius: 1,
        }}>
          <Architecture sx={{ color: "#0284c7", fontSize: 20, mt: 0.2, flexShrink: 0 }} />
          <Box>
            <Typography sx={{ fontWeight: 700, fontSize: 13, color: "#0284c7", mb: 0.3 }}>
              Architecture & Engineering agents work without an assessment
            </Typography>
            <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
              These agents review system designs, IaC templates, and network topology — not scan findings. Use the guided wizard to upload inputs before running.
            </Typography>
          </Box>
        </Box>

        {catalogLoading ? (
          <Grid container spacing={2}>
            {[1, 2, 3, 4, 5, 6].map(i => <Grid key={i} size={{ xs: 12, sm: 6, md: 3 }}><Skeleton variant="rectangular" height={180} sx={{ borderRadius: 1 }} /></Grid>)}
          </Grid>
        ) : (
          <>
            <Tabs value={catalogTab} onChange={(_, v) => setCatalogTab(v)}
              variant="scrollable" scrollButtons="auto"
              sx={{ mb: 2, borderBottom: "1px solid rgba(255,255,255,0.08)", minHeight: 38 }}>
              {catTabs.map(t => (
                <Tab key={t.value} value={t.value} label={t.label}
                  sx={{ fontSize: 12, textTransform: "none", minWidth: "auto", minHeight: 38, py: 0.5 }} />
              ))}
            </Tabs>
            <Grid container spacing={2}>
              {filteredAgents.map(agent => (
                <Grid key={agent.id} size={{ xs: 12, sm: 6, md: 3 }}>
                  <CatalogCard agent={agent} scanId={selectedScan?.id}
                    alreadyRan={alreadyRan.has(agent.key)}
                    selectMode={selectMode} selected={selectedAgents.has(agent.key)}
                    onToggle={toggleAgentSelect}
                    onRun={handleRunAgent}
                    onWizard={(a) => { setWizardAgent(a); setWizardOpen(true); setActiveStep(2); }} />
                </Grid>
              ))}
            </Grid>
          </>
        )}
      </Box>

      {/* Running indicator */}
      {isPending && (
        <Box sx={{ position: "fixed", bottom: 80, right: 24, p: 2, bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 2, display: "flex", alignItems: "center", gap: 1, boxShadow: 4, zIndex: 1300 }}>
          <CircularProgress size={16} />
          <Typography sx={{ fontSize: 13 }}>Starting agent…</Typography>
        </Box>
      )}

      {/* Batch run floating bar */}
      {selectedAgents.size > 0 && (
        <Box sx={{
          position: "fixed", bottom: 24, left: "50%", transform: "translateX(-50%)",
          bgcolor: "background.paper", border: "1px solid", borderColor: "primary.main",
          borderRadius: 3, p: 1.5, display: "flex", alignItems: "center", gap: 2,
          boxShadow: "0 8px 32px rgba(0,0,0,0.4)", zIndex: 1200,
        }}>
          <Typography sx={{ fontSize: 13 }}>
            {selectedAgents.size} agent{selectedAgents.size > 1 ? "s" : ""} selected
            {selectedScan ? ` · ${selectedScan.name}` : ""}
          </Typography>
          <Button variant="outlined" size="small" onClick={() => setSelectedAgents(new Set())}>Clear</Button>
          <Button variant="contained" size="small" startIcon={<RocketLaunch />}
            onClick={handleBatchRun} disabled={isPending}>
            Run selected
          </Button>
        </Box>
      )}

      {/* Wizard modal */}
      <WizardModal agent={wizardAgent} open={wizardOpen} onClose={() => setWizardOpen(false)} onLaunch={handleWizardLaunch} />
    </Box>
  );
}
