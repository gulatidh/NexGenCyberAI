import React, { useMemo, useState } from "react";
import {
  Box, Typography, Card, Chip, Button, IconButton, Switch, Tooltip,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Select, MenuItem, FormControl, InputLabel, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, Alert,
  ToggleButton, ToggleButtonGroup, FormControlLabel, Checkbox, Grid,
  Drawer, Divider,
} from "@mui/material";
import { Add, PlayArrow, Edit, Delete, Schedule, History, Print, Article, Close as CloseIcon } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";
import { missionsApi, clientsApi } from "../services/api";
import { Client } from "../types";
import { fromNow } from "../utils/datetime";
import RichOutput from "../components/RichOutput";

// ── Mission types (mirrors backend MissionType enum) ─────────────────────────
const MISSION_TYPES: { value: string; label: string }[] = [
  { value: "soc_design", label: "SOC Design" },
  { value: "vulnerability_response", label: "Vulnerability Response" },
  { value: "grc_advisory", label: "GRC Advisory" },
  { value: "cloud_security_assessment", label: "Cloud Security Assessment" },
  { value: "zero_trust_design", label: "Zero Trust Design" },
  { value: "incident_response_program", label: "Incident Response Program" },
  { value: "threat_intel_program", label: "Threat Intel Program" },
  { value: "data_protection_assessment", label: "Data Protection Assessment" },
  { value: "iga_deployment", label: "IGA Deployment" },
  { value: "phishing_triage", label: "Phishing Triage" },
  { value: "portfolio_rationalization", label: "Portfolio Rationalization" },
  { value: "security_architecture_review", label: "Security Architecture Review" },
];

// ── Schedule presets ─────────────────────────────────────────────────────────
const PRESETS = [
  { id: "daily", label: "Daily 6 AM", cron: "0 6 * * *", text: "Every day at 6:00 AM UTC" },
  { id: "weekly", label: "Weekly Monday", cron: "0 6 * * 1", text: "Every Monday at 6:00 AM UTC" },
  { id: "monthly", label: "Monthly 1st", cron: "0 6 1 * *", text: "1st of every month at 6:00 AM UTC" },
] as const;

// Minimal cron → human-readable converter. Covers the 3 presets exactly and
// gives a best-effort label for arbitrary 5-field expressions.
function cronToHuman(expr: string): string {
  const trimmed = expr.trim();
  const preset = PRESETS.find((p) => p.cron === trimmed);
  if (preset) return preset.text;
  const parts = trimmed.split(/\s+/);
  if (parts.length !== 5) return "Custom schedule";
  const [m, h, dom, mon, dow] = parts;
  const time = `${h === "*" ? "every hour" : `${h.padStart(2, "0")}:${m.padStart(2, "0")}`}`;
  const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  if (dom !== "*" && dow === "*") return `Day ${dom} of each month at ${time} UTC`;
  if (dow !== "*" && dom === "*") {
    const d = Number(dow);
    return `Every ${isNaN(d) ? dow : dayNames[d % 7]} at ${time} UTC`;
  }
  if (dom === "*" && dow === "*" && mon === "*") return `Every day at ${time} UTC`;
  return `${trimmed} (UTC)`;
}

interface Mission {
  id: string;
  name: string;
  client_id: string;
  client_name?: string;
  mission_type: string;
  cron_expression: string;
  cron_label?: string;
  timezone: string;
  send_summary_email: boolean;
  update_risk_quantification: boolean;
  is_active: boolean;
  last_run_at?: string | null;
  next_run_at?: string | null;
}

export default function Missions() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Mission | null>(null);

  const [historyMission, setHistoryMission] = useState<Mission | null>(null);
  const [reportRun, setReportRun] = useState<any | null>(null);

  // Form state
  const [name, setName] = useState("New Scheduled Mission");
  const [clientId, setClientId] = useState("");
  const [missionType, setMissionType] = useState("cloud_security_assessment");
  const [cron, setCron] = useState("0 6 * * *");
  const [sendEmail, setSendEmail] = useState(false);
  const [updateRisk, setUpdateRisk] = useState(false);

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: missions = [], isLoading } = useQuery<Mission[]>({
    queryKey: ["missions"], queryFn: () => missionsApi.list(),
  });

  const { data: historyRuns = [], isLoading: historyLoading } = useQuery<any[]>({
    queryKey: ["mission-runs", historyMission?.id],
    queryFn: () => missionsApi.runs(historyMission!.id),
    enabled: !!historyMission,
  });

  const cronLabel = useMemo(() => cronToHuman(cron), [cron]);

  const resetForm = () => {
    setEditing(null);
    setName("New Scheduled Mission");
    setClientId("");
    setMissionType("cloud_security_assessment");
    setCron("0 6 * * *");
    setSendEmail(false);
    setUpdateRisk(false);
  };

  const openEdit = (m: Mission) => {
    setEditing(m);
    setName(m.name);
    setClientId(m.client_id);
    setMissionType(m.mission_type);
    setCron(m.cron_expression);
    setSendEmail(m.send_summary_email);
    setUpdateRisk(m.update_risk_quantification);
    setOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: (payload: any) => editing
      ? missionsApi.update(editing.id, payload)
      : missionsApi.create(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["missions"] });
      toast.success(editing ? "Mission updated" : "Mission scheduled");
      setOpen(false); resetForm();
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Failed to save mission"),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => missionsApi.delete(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["missions"] }); toast.success("Mission deleted"); },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      missionsApi.update(id, { is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["missions"] }),
  });

  const runNowMutation = useMutation({
    mutationFn: (id: string) => missionsApi.runNow(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["missions"] }); toast.success("Mission triggered"); },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Run failed"),
  });

  const submit = () => {
    if (!clientId) { toast.error("Pick a client first"); return; }
    saveMutation.mutate({
      name, client_id: clientId, mission_type: missionType,
      cron_expression: cron, cron_label: cronLabel,
      send_summary_email: sendEmail, update_risk_quantification: updateRisk,
      is_active: true,
    });
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Workflows</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            Pre-configured security workflows that run on a recurring schedule
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<Add />}
          onClick={() => { resetForm(); setOpen(true); }}>
          Schedule Workflow
        </Button>
      </Box>

      {isLoading ? (
        <CircularProgress sx={{ color: "#4285F4" }} />
      ) : missions.length === 0 ? (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
          <Schedule sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
          <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>
            No workflows yet. Click "Schedule Workflow" to set one up.
          </Typography>
        </Card>
      ) : (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, overflow: "hidden" }}>
          <Table>
            <TableHead>
              <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 12, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
                <TableCell>Active</TableCell>
                <TableCell>Name</TableCell>
                <TableCell>Client</TableCell>
                <TableCell>Workflow Type</TableCell>
                <TableCell>Schedule</TableCell>
                <TableCell>Next Run</TableCell>
                <TableCell>Last Run</TableCell>
                <TableCell>Post-Actions</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {missions.map((m) => {
                const mt = MISSION_TYPES.find((t) => t.value === m.mission_type);
                return (
                  <TableRow key={m.id} hover sx={{ "& td": { color: "white", borderColor: "rgba(255,255,255,0.05)" } }}>
                    <TableCell>
                      <Switch
                        size="small"
                        checked={m.is_active}
                        onChange={(e) => toggleMutation.mutate({ id: m.id, is_active: e.target.checked })}
                      />
                    </TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>{m.name}</TableCell>
                    <TableCell sx={{ color: "rgba(255,255,255,0.7)" }}>{m.client_name || m.client_id.slice(0, 8)}</TableCell>
                    <TableCell>
                      <Chip label={mt?.label || m.mission_type} size="small"
                        sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 11 }} />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" sx={{ display: "block", color: "white" }}>
                        {m.cron_label || cronToHuman(m.cron_expression)}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", fontFamily: "monospace", fontSize: 10 }}>
                        {m.cron_expression}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ color: "rgba(255,255,255,0.7)", fontSize: 12 }}>
                      {m.next_run_at ? fromNow(m.next_run_at) : "—"}
                    </TableCell>
                    <TableCell sx={{ color: "rgba(255,255,255,0.7)", fontSize: 12 }}>
                      {m.last_run_at ? fromNow(m.last_run_at) : "Never"}
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                        {m.send_summary_email && <Chip label="Email" size="small" sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontSize: 10, height: 18 }} />}
                        {m.update_risk_quantification && <Chip label="Risk Quant" size="small" sx={{ bgcolor: "rgba(251,188,4,0.12)", color: "#FBBC04", fontSize: 10, height: 18 }} />}
                        {!m.send_summary_email && !m.update_risk_quantification && (
                          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.3)" }}>—</Typography>
                        )}
                      </Box>
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Run now">
                        <IconButton size="small" disabled={runNowMutation.isPending}
                          onClick={() => runNowMutation.mutate(m.id)}
                          sx={{ color: "#34A853" }}>
                          <PlayArrow sx={{ fontSize: 18 }} />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Run history & outputs">
                        <IconButton size="small" onClick={() => setHistoryMission(m)}
                          sx={{ color: "rgba(255,255,255,0.6)", "&:hover": { color: "#4285F4" } }}>
                          <History sx={{ fontSize: 16 }} />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit">
                        <IconButton size="small" onClick={() => openEdit(m)}
                          sx={{ color: "rgba(255,255,255,0.6)", "&:hover": { color: "#4285F4" } }}>
                          <Edit sx={{ fontSize: 16 }} />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete">
                        <IconButton size="small"
                          onClick={() => {
                            if (window.confirm(`Delete mission "${m.name}"?`)) deleteMutation.mutate(m.id);
                          }}
                          sx={{ color: "rgba(255,255,255,0.6)", "&:hover": { color: "#EA4335" } }}>
                          <Delete sx={{ fontSize: 16 }} />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Schedule dialog */}
      <Dialog open={open} onClose={() => { setOpen(false); resetForm(); }} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
        <DialogTitle>{editing ? `Edit Workflow — ${editing.name}` : "Schedule a Workflow"}</DialogTitle>
        <DialogContent dividers sx={{ borderColor: "rgba(255,255,255,0.08)" }}>
          <Grid container spacing={2} sx={{ mt: 0.5 }}>
            <Grid size={{ xs: 12 }}>
              <TextField fullWidth size="small" label="Name"
                value={name} onChange={(e) => setName(e.target.value)}
                slotProps={{ inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } }, htmlInput: { style: { color: "white" } } }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
                <Select value={clientId} onChange={(e) => setClientId(e.target.value)} label="Client"
                  sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                  {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Workflow Type</InputLabel>
                <Select value={missionType} onChange={(e) => setMissionType(e.target.value)} label="Workflow Type"
                  sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                  {MISSION_TYPES.map((mt) => <MenuItem key={mt.value} value={mt.value}>{mt.label}</MenuItem>)}
                </Select>
              </FormControl>
            </Grid>

            <Grid size={{ xs: 12 }}>
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 1 }}>
                Schedule
              </Typography>
              <ToggleButtonGroup
                exclusive size="small"
                value={PRESETS.find((p) => p.cron === cron)?.id || ""}
                onChange={(_, v) => { if (v) setCron(PRESETS.find((p) => p.id === v)!.cron); }}
                sx={{
                  "& .MuiToggleButton-root": {
                    color: "rgba(255,255,255,0.7)", borderColor: "rgba(255,255,255,0.15)", textTransform: "none",
                  },
                  "& .Mui-selected": { color: "#4285F4 !important", bgcolor: "rgba(66,133,244,0.1) !important" },
                }}
              >
                {PRESETS.map((p) => <ToggleButton key={p.id} value={p.id}>{p.label}</ToggleButton>)}
              </ToggleButtonGroup>
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField fullWidth size="small" label="Custom cron expression (5 fields, UTC)"
                value={cron} onChange={(e) => setCron(e.target.value)}
                helperText={cronLabel}
                slotProps={{
                  inputLabel: { sx: { color: "rgba(255,255,255,0.5)" } },
                  htmlInput: { style: { color: "white", fontFamily: "monospace" } },
                  formHelperText: { sx: { color: "#4285F4", fontStyle: "italic" } },
                }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
            </Grid>

            <Grid size={{ xs: 12 }}>
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 0.5 }}>
                Post-run actions
              </Typography>
              <FormControlLabel
                sx={{ display: "block", color: "white" }}
                control={<Checkbox checked={sendEmail} onChange={(e) => setSendEmail(e.target.checked)}
                  sx={{ color: "rgba(255,255,255,0.5)", "&.Mui-checked": { color: "#34A853" } }} />}
                label="Send summary email" />
              <FormControlLabel
                sx={{ display: "block", color: "white" }}
                control={<Checkbox checked={updateRisk} onChange={(e) => setUpdateRisk(e.target.checked)}
                  sx={{ color: "rgba(255,255,255,0.5)", "&.Mui-checked": { color: "#FBBC04" } }} />}
                label="Update risk quantification" />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => { setOpen(false); resetForm(); }} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
          <Button variant="contained" onClick={submit} disabled={saveMutation.isPending || !clientId}>
            {saveMutation.isPending ? <CircularProgress size={18} /> : (editing ? "Save" : "Schedule")}
          </Button>
        </DialogActions>
      </Dialog>

      <Alert severity="info" sx={{ mt: 2, bgcolor: "rgba(66,133,244,0.08)", color: "rgba(255,255,255,0.7)" }}>
        Cron expressions are evaluated in <b>UTC</b>. Workflow handlers run inside the backend process via APScheduler — no external broker required.
      </Alert>

      {/* Run history + output drawer */}
      <Drawer anchor="right" open={!!historyMission} onClose={() => setHistoryMission(null)}
        slotProps={{ paper: { sx: { width: { xs: "100%", md: 640 }, bgcolor: "#1E1E1E", color: "white" } } }}>
        {historyMission && (
          <Box sx={{ p: 2.5, display: "flex", flexDirection: "column", height: "100%" }}>
            <Typography variant="h6" sx={{ fontWeight: 700 }}>{historyMission.name}</Typography>
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", mb: 2 }}>
              Run history & outputs · {historyMission.client_name || historyMission.client_id.slice(0, 8)}
            </Typography>
            <Divider sx={{ borderColor: "rgba(255,255,255,0.08)", mb: 2 }} />
            <Box sx={{ flex: 1, overflow: "auto" }}>
              {historyLoading ? (
                <CircularProgress sx={{ color: "#4285F4" }} />
              ) : historyRuns.length === 0 ? (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>
                  No runs yet. Click the Run Now button on the row, or wait for the schedule to fire.
                </Typography>
              ) : (
                historyRuns.map((run) => (
                  <Card key={run.id} sx={{ bgcolor: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 2, p: 1.5, mb: 1.5 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Chip label={run.status} size="small"
                        sx={{ height: 20, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                          bgcolor: run.status === "success" ? "rgba(52,168,83,0.15)" : run.status === "failed" ? "rgba(234,67,53,0.15)" : "rgba(251,188,4,0.15)",
                          color: run.status === "success" ? "#34A853" : run.status === "failed" ? "#EA4335" : "#FBBC04" }} />
                      <Chip label={run.triggered_by} size="small"
                        sx={{ height: 20, fontSize: 10, bgcolor: "rgba(255,255,255,0.05)", color: "rgba(255,255,255,0.7)" }} />
                      {run.report && (
                        <Chip label="Report" size="small" icon={<Article sx={{ fontSize: 14 }} />}
                          sx={{ height: 20, fontSize: 10, bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontWeight: 700,
                            "& .MuiChip-icon": { color: "#4285F4" } }} />
                      )}
                      <Box sx={{ flex: 1 }} />
                      <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                        {run.started_at ? fromNow(run.started_at) : ""}
                      </Typography>
                    </Box>
                    {run.output && (
                      <Typography variant="caption" sx={{
                        color: "rgba(255,255,255,0.65)", fontSize: 11.5, display: "block", lineHeight: 1.5,
                      }}>
                        {run.output}
                      </Typography>
                    )}
                    {run.error && (
                      <Alert severity="error" sx={{ mt: 1, fontSize: 11 }}>{run.error}</Alert>
                    )}
                    {run.report && (
                      <Box sx={{ mt: 1.25, display: "flex", justifyContent: "flex-end" }}>
                        <Button size="small" variant="outlined" startIcon={<Article sx={{ fontSize: 14 }} />}
                          onClick={() => setReportRun(run)}
                          sx={{ borderColor: "rgba(66,133,244,0.4)", color: "#4285F4", fontSize: 11,
                            "&:hover": { borderColor: "#4285F4", bgcolor: "rgba(66,133,244,0.08)" } }}>
                          View Report
                        </Button>
                      </Box>
                    )}
                  </Card>
                ))
              )}
            </Box>
          </Box>
        )}
      </Drawer>

      {/* Standardised workflow report viewer — opens for any run with a
          generated report. Same theme + layout every time so PDF exports
          look identical across mission types and runs. */}
      <MissionReportDialog run={reportRun} mission={historyMission} onClose={() => setReportRun(null)} />
    </Box>
  );
}

// ── Mission report viewer ─────────────────────────────────────────────────────

interface ReportMetric { label: string; value: string; tone?: string; }
interface ReportSection { id: string; title: string; body: string; }
interface MissionReport {
  generated_at: string;
  model: string;
  mission_type_label: string;
  client_name: string;
  title: string;
  subtitle?: string;
  metrics: ReportMetric[];
  sections: ReportSection[];
}

const METRIC_TONE_COLOR: Record<string, string> = {
  good: "#34A853", warn: "#FBBC04", bad: "#EA4335", neutral: "#4285F4",
};

function MissionReportDialog({ run, mission, onClose }: {
  run: any | null; mission: Mission | null; onClose: () => void;
}) {
  const open = !!run && !!run.report;
  if (!open) return null;
  const report = run.report as MissionReport;
  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth
      slotProps={{ paper: { sx: { bgcolor: "#0F0F0F", color: "white" } } }}>
      {/* Print stylesheet — flatten to a paper-friendly single document.
          Same template every time so every PDF reads the same. */}
      <style>{`
        @media print {
          @page { size: A4; margin: 14mm; }
          body { background: white !important; color: black !important; }
          .MuiDialog-root, .MuiDialog-container, .MuiPaper-root {
            position: static !important; max-width: 100% !important;
            box-shadow: none !important;
          }
          .no-print { display: none !important; }
          .mission-report-print, .mission-report-print * {
            color: #1a1a1a !important;
            background: white !important;
            border-color: rgba(0,0,0,0.15) !important;
            box-shadow: none !important;
          }
          .mission-report-print .report-section { page-break-inside: avoid; }
          .mission-report-print h1, .mission-report-print h2, .mission-report-print h3 {
            page-break-after: avoid;
          }
        }
      `}</style>

      {/* Header bar (hidden on print) */}
      <Box className="no-print" sx={{
        display: "flex", alignItems: "center", gap: 1, p: 1.5,
        borderBottom: "1px solid rgba(255,255,255,0.08)", bgcolor: "#1A1A1A",
      }}>
        <Article sx={{ color: "#4285F4" }} />
        <Typography sx={{ color: "white", fontWeight: 700 }}>Workflow Report</Typography>
        <Chip label={run.status} size="small"
          sx={{ height: 20, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
            bgcolor: run.status === "success" ? "rgba(52,168,83,0.15)" : "rgba(234,67,53,0.15)",
            color: run.status === "success" ? "#34A853" : "#EA4335" }} />
        <Box sx={{ flex: 1 }} />
        <Button size="small" variant="outlined" startIcon={<Print />} onClick={() => window.print()}
          sx={{ borderColor: "rgba(255,255,255,0.2)", color: "rgba(255,255,255,0.85)",
            "&:hover": { borderColor: "#4285F4", color: "#4285F4" } }}>
          Download PDF
        </Button>
        <IconButton size="small" onClick={onClose} sx={{ color: "rgba(255,255,255,0.6)" }}>
          <CloseIcon />
        </IconButton>
      </Box>

      {/* Report body — same template every run */}
      <DialogContent className="mission-report-print" sx={{ p: 4, bgcolor: "#0F0F0F" }}>
        {/* Title block */}
        <Box sx={{ mb: 3, pb: 2, borderBottom: "2px solid #4285F4" }}>
          <Typography variant="caption" sx={{
            color: "#4285F4", letterSpacing: 2, textTransform: "uppercase",
            fontWeight: 700, fontSize: 11,
          }}>
            {report.mission_type_label || mission?.mission_type || "Workflow"} · Standardised Report
          </Typography>
          <Typography variant="h4" sx={{ color: "white", fontWeight: 700, lineHeight: 1.2, mt: 0.5 }}>
            {report.title}
          </Typography>
          {report.subtitle && (
            <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.65)", mt: 0.75 }}>
              {report.subtitle}
            </Typography>
          )}
          <Box sx={{ display: "flex", gap: 2, mt: 1.5, flexWrap: "wrap" }}>
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
              <strong>Client:</strong> {report.client_name}
            </Typography>
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
              <strong>Generated:</strong> {report.generated_at ? new Date(report.generated_at).toLocaleString() : "—"}
            </Typography>
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
              <strong>Model:</strong> {report.model || "—"}
            </Typography>
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
              <strong>Trigger:</strong> {run.triggered_by}
            </Typography>
          </Box>
        </Box>

        {/* KPI metrics row — always 4 cards, same template */}
        {report.metrics?.length > 0 && (
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {report.metrics.map((m, i) => {
              const color = METRIC_TONE_COLOR[m.tone || "neutral"] || "#4285F4";
              return (
                <Grid size={{ xs: 6, md: 3 }} key={i}>
                  <Box sx={{
                    bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)",
                    borderRadius: 2, p: 1.75, height: "100%",
                  }}>
                    <Typography variant="caption" sx={{
                      color: "rgba(255,255,255,0.5)", textTransform: "uppercase",
                      letterSpacing: 1, fontSize: 10, fontWeight: 700,
                    }}>
                      {m.label}
                    </Typography>
                    <Typography sx={{ color, fontSize: 26, fontWeight: 700, lineHeight: 1.15, mt: 0.5 }}>
                      {m.value}
                    </Typography>
                  </Box>
                </Grid>
              );
            })}
          </Grid>
        )}

        {/* Sections — fixed 7-section order */}
        {(report.sections || []).map((s) => (
          <Box key={s.id} className="report-section" sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{
              color: "#4285F4", fontWeight: 700, mb: 1.5,
              pb: 0.5, borderBottom: "1px solid rgba(66,133,244,0.3)",
              fontSize: 16, letterSpacing: -0.2,
            }}>
              {s.title}
            </Typography>
            <RichOutput value={s.body} />
          </Box>
        ))}

        {/* Footer */}
        <Box sx={{ mt: 4, pt: 2, borderTop: "1px solid rgba(255,255,255,0.06)", textAlign: "center" }}>
          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.35)", fontSize: 10 }}>
            NexGenCyberAI — Generated by AI on standardised template v{1}. This report is advisory and
            should be reviewed by a qualified security professional before acting on recommendations.
          </Typography>
        </Box>
      </DialogContent>
    </Dialog>
  );
}
