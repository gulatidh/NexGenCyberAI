import React, { useMemo, useState } from "react";
import {
  Box, Typography, Card, Chip, Button, IconButton, Switch, Tooltip,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Select, MenuItem, FormControl, InputLabel, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, Alert,
  ToggleButton, ToggleButtonGroup, FormControlLabel, Checkbox, Grid,
} from "@mui/material";
import { Add, PlayArrow, Edit, Delete, Schedule } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";
import { missionsApi, clientsApi } from "../services/api";
import { Client } from "../types";
import { fromNow } from "../utils/datetime";

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
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Scheduled Missions</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            Pre-configured security missions that run on a recurring schedule
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<Add />}
          onClick={() => { resetForm(); setOpen(true); }}>
          Schedule Mission
        </Button>
      </Box>

      {isLoading ? (
        <CircularProgress sx={{ color: "#4285F4" }} />
      ) : missions.length === 0 ? (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
          <Schedule sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
          <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>
            No scheduled missions yet. Click "Schedule Mission" to set one up.
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
                <TableCell>Mission Type</TableCell>
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
        <DialogTitle>{editing ? `Edit Mission — ${editing.name}` : "Schedule a Mission"}</DialogTitle>
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
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Mission Type</InputLabel>
                <Select value={missionType} onChange={(e) => setMissionType(e.target.value)} label="Mission Type"
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
        Cron expressions are evaluated in <b>UTC</b>. Mission handlers run inside the backend process via APScheduler — no external broker required.
      </Alert>
    </Box>
  );
}
