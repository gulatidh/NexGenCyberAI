import React, { useMemo, useState } from "react";
import { useViewMode } from "../theme/ViewModeContext";
import {
  Box, Typography, Button, Card, CardContent, Grid, Chip,
  Select, MenuItem, FormControl, InputLabel, CircularProgress, Alert,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Switch, IconButton, Tooltip, Drawer, Divider,
} from "@mui/material";
import {
  SmartToy, PlayArrow, Add, Edit, Delete, AutoFixHigh,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { agentsApi, clientsApi, scansApi, agentCatalogApi, adminApi } from "../services/api";
import { Client, Scan, AgentType, MyAccess } from "../types";
import { toast } from "react-toastify";
import RichOutput from "../components/RichOutput";

// ── Types ────────────────────────────────────────────────────────────────────

interface Agent {
  id: string;
  key: string;
  name: string;
  group_key: string;
  group_label: string;
  description?: string;
  objective?: string;
  domain?: string;
  system_prompt?: string;
  provider?: string;
  model?: string;
  temperature: number;
  max_tokens: number;
  tools_enabled: string[];
  knowledge_file_ids: string[];
  is_builtin: boolean;
  is_enabled: boolean;
  legacy_orchestrator: boolean;
  updated_at?: string;
  updated_by?: string;
  // Phase 7A/7C — artifact + personality
  output_kind?: string;
  output_schema_json?: string;
  avatar_url?: string;
  signature_opening?: string;
  accent_color?: string;
}

interface AgentGroup { key: string; label: string; agents: Agent[]; }

// Per-group accent (Google palette)
const GROUP_COLOR: Record<string, string> = {
  core_advisory: "#4285F4",
  architecture_engineering: "#34A853",
  threat_incident_response: "#EA4335",
  risk_compliance_governance: "#FBBC04",
  vulnerability_management: "#FF7043",
  agentic_ai_security: "#9C27B0",
  business_reporting: "#00ACC1",
  specialized_readiness: "#7CB342",
  operational: "#4285F4",
};

// ── Configuration dialog ─────────────────────────────────────────────────────

function ConfigureDialog({ open, agent, onClose, onSave, isAdmin }: {
  open: boolean; agent: Agent | null; onClose: () => void;
  onSave: (patch: any) => void; isAdmin: boolean;
}) {
  const [form, setForm] = useState<Partial<Agent>>({});
  React.useEffect(() => { setForm(agent || {}); }, [agent]);

  if (!agent) return null;
  const set = <K extends keyof Agent>(k: K, v: Agent[K]) => setForm((f) => ({ ...f, [k]: v }));
  const readOnly = !isAdmin;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth
      slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
      <DialogTitle>
        {readOnly ? "Agent Configuration" : "Edit Agent Configuration"}
        <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>
          {agent.name} · {agent.group_label}{agent.is_builtin && " · Built-in"}
        </Typography>
      </DialogTitle>
      <DialogContent dividers sx={{ borderColor: "divider" }}>
        <Grid container spacing={2} sx={{ mt: 0.5 }}>
          <Grid size={{ xs: 12, sm: 6 }}>
            <TextField fullWidth size="small" label="Name" disabled={readOnly}
              value={form.name || ""} onChange={(e) => set("name", e.target.value)}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 12, sm: 6 }}>
            <TextField fullWidth size="small" label="Domain" disabled={readOnly}
              value={form.domain || ""} onChange={(e) => set("domain", e.target.value)}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField fullWidth size="small" label="Description" disabled={readOnly}
              value={form.description || ""} onChange={(e) => set("description", e.target.value)}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField fullWidth size="small" label="Objective" disabled={readOnly}
              value={form.objective || ""} onChange={(e) => set("objective", e.target.value)}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField fullWidth size="small" label="System Prompt" multiline minRows={6} disabled={readOnly}
              value={form.system_prompt || ""} onChange={(e) => set("system_prompt", e.target.value)}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary", fontFamily: "monospace", fontSize: 12 } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <TextField fullWidth size="small" label="Provider" disabled={readOnly}
              placeholder="inherit"
              value={form.provider || ""} onChange={(e) => set("provider", e.target.value)}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <TextField fullWidth size="small" label="Model" disabled={readOnly}
              placeholder="inherit"
              value={form.model || ""} onChange={(e) => set("model", e.target.value)}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <TextField fullWidth size="small" type="number" label="Temperature" disabled={readOnly}
              value={form.temperature ?? 0.1} onChange={(e) => set("temperature", parseFloat(e.target.value))}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { step: 0.1, min: 0, max: 2, style: { color: "text.primary" } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 6, sm: 3 }}>
            <TextField fullWidth size="small" type="number" label="Max Tokens" disabled={readOnly}
              value={form.max_tokens ?? 4096} onChange={(e) => set("max_tokens", parseInt(e.target.value, 10))}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <Switch checked={!!form.is_enabled} disabled={readOnly}
                onChange={(e) => set("is_enabled", e.target.checked)} />
              <Typography variant="body2">Enabled — agent appears in active pickers and orchestration</Typography>
            </Box>
          </Grid>
          {readOnly && (
            <Grid size={{ xs: 12 }}>
              <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "text.primary" }}>
                Read-only view. Only administrators can edit the agent catalog.
              </Alert>
            </Grid>
          )}
        </Grid>
      </DialogContent>
      <DialogActions sx={{ p: 2 }}>
        <Button onClick={onClose} sx={{ color: "text.secondary" }}>Close</Button>
        {!readOnly && (
          <Button variant="contained" onClick={() => onSave(form)}>Save</Button>
        )}
      </DialogActions>
    </Dialog>
  );
}

// ── New Agent dialog ────────────────────────────────────────────────────────

function NewAgentDialog({ open, onClose, onCreate, existingGroups }: {
  open: boolean; onClose: () => void; onCreate: (data: any) => void;
  existingGroups: { key: string; label: string }[];
}) {
  const [data, setData] = useState<any>({
    key: "", name: "", group_key: existingGroups[0]?.key || "core_advisory",
    group_label: existingGroups[0]?.label || "Core Advisory",
    description: "", system_prompt: "", temperature: 0.1, max_tokens: 4096, is_enabled: true,
  });
  React.useEffect(() => {
    if (open) setData({
      key: "", name: "", group_key: existingGroups[0]?.key || "core_advisory",
      group_label: existingGroups[0]?.label || "Core Advisory",
      description: "", system_prompt: "", temperature: 0.1, max_tokens: 4096, is_enabled: true,
    });
  }, [open, existingGroups]);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth
      slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
      <DialogTitle>New Agent</DialogTitle>
      <DialogContent dividers sx={{ borderColor: "divider" }}>
        <Grid container spacing={2} sx={{ mt: 0.5 }}>
          <Grid size={{ xs: 12, sm: 6 }}>
            <TextField fullWidth size="small" label="Key (slug, unique)" required
              value={data.key} onChange={(e) => setData({ ...data, key: e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, "_") })}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary", fontFamily: "monospace" } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 12, sm: 6 }}>
            <TextField fullWidth size="small" label="Display Name" required
              value={data.name} onChange={(e) => setData({ ...data, name: e.target.value })}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <FormControl fullWidth size="small">
              <InputLabel sx={{ color: "text.secondary" }}>Group</InputLabel>
              <Select value={data.group_key} label="Group"
                onChange={(e) => {
                  const g = existingGroups.find((x) => x.key === e.target.value);
                  setData({ ...data, group_key: e.target.value, group_label: g?.label || e.target.value });
                }}
                sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                {existingGroups.map((g) => <MenuItem key={g.key} value={g.key}>{g.label}</MenuItem>)}
              </Select>
            </FormControl>
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField fullWidth size="small" label="Description"
              value={data.description} onChange={(e) => setData({ ...data, description: e.target.value })}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField fullWidth size="small" label="System Prompt" multiline minRows={4}
              value={data.system_prompt} onChange={(e) => setData({ ...data, system_prompt: e.target.value })}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary", fontFamily: "monospace", fontSize: 12 } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
          </Grid>
        </Grid>
      </DialogContent>
      <DialogActions sx={{ p: 2 }}>
        <Button onClick={onClose} sx={{ color: "text.secondary" }}>Cancel</Button>
        <Button variant="contained" disabled={!data.key || !data.name}
          onClick={() => onCreate(data)}>Create</Button>
      </DialogActions>
    </Dialog>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function Agents() {
  const qc = useQueryClient();
  const { canAct } = useViewMode();
  const [selectedClientId, setSelectedClientId] = useState("");
  const [selectedScanId, setSelectedScanId] = useState("");
  const [configuring, setConfiguring] = useState<Agent | null>(null);
  const [newOpen, setNewOpen] = useState(false);
  const [briefingAgent, setBriefingAgent] = useState<Agent | null>(null);
  const [briefingPrompt, setBriefingPrompt] = useState("");
  const [briefingOutput, setBriefingOutput] = useState<{ output: string; provider: string; model?: string; tokens_used: number; duration_ms: number } | null>(null);
  const [briefingError, setBriefingError] = useState<string>("");

  const { data: me } = useQuery<MyAccess>({ queryKey: ["my-access"], queryFn: adminApi.me, retry: 0 });
  const isAdmin = !!(me?.is_admin || me?.is_admin_anywhere);

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: scans = [] } = useQuery<Scan[]>({
    queryKey: ["scans-for-agents", selectedClientId],
    queryFn: () => scansApi.list(selectedClientId),
    enabled: !!selectedClientId,
  });

  const { data: catalogData, isLoading } = useQuery<{ groups: AgentGroup[] }>({
    queryKey: ["agent-catalog"], queryFn: agentCatalogApi.list,
  });

  const groups = useMemo(() => catalogData?.groups || [], [catalogData]);
  const groupOptions = useMemo(() => groups.map((g) => ({ key: g.key, label: g.label })), [groups]);

  const runMutation = useMutation({
    mutationFn: (agentType: AgentType) =>
      agentsApi.run(selectedClientId, { agent_type: agentType, scan_id: selectedScanId || undefined }),
    onSuccess: (_, agentType) => { qc.invalidateQueries({ queryKey: ["agent-runs"] }); toast.success(`${agentType} started`); },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Agent run failed"),
  });

  const briefingMutation = useMutation({
    mutationFn: ({ agentId, prompt }: { agentId: string; prompt?: string }) =>
      agentCatalogApi.run(agentId, prompt, selectedClientId || undefined, selectedScanId || undefined),
    onSuccess: (data) => { setBriefingOutput(data); setBriefingError(""); },
    onError: (e: any) => {
      setBriefingError(e.response?.data?.detail || e.message || "Briefing failed");
      setBriefingOutput(null);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: any }) => agentCatalogApi.update(id, patch),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["agent-catalog"] }); toast.success("Agent updated"); setConfiguring(null); },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Update failed"),
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => agentCatalogApi.create(data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["agent-catalog"] }); toast.success("Agent created"); setNewOpen(false); },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Create failed"),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => agentCatalogApi.delete(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["agent-catalog"] }); toast.success("Agent deleted"); },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Delete failed"),
  });

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>AI Buddies</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            {groups.length > 0
              ? `${groups.reduce((s, g) => s + g.agents.length, 0)} specialist agents across ${groups.length} groups${isAdmin ? "" : " — admin role required to modify"}`
              : "Loading…"}
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Client (for run)</InputLabel>
            <Select value={selectedClientId} onChange={(e) => { setSelectedClientId(e.target.value); setSelectedScanId(""); }} label="Client (for run)"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">None</MenuItem>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 180 }} disabled={!selectedClientId}>
            <InputLabel sx={{ color: "text.secondary" }}>Scan (optional)</InputLabel>
            <Select value={selectedScanId} onChange={(e) => setSelectedScanId(e.target.value)} label="Scan (optional)"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">No scan</MenuItem>
              {scans.map((s) => <MenuItem key={s.id} value={s.id}>{s.name || s.id.slice(0, 8)}</MenuItem>)}
            </Select>
          </FormControl>
          {isAdmin && (
            <Button variant="contained" startIcon={<Add />} onClick={() => setNewOpen(true)}>
              New Agent
            </Button>
          )}
        </Box>
      </Box>

      {isLoading ? (
        <CircularProgress sx={{ color: "#4285F4" }} />
      ) : (
        groups.map((group) => {
          const color = GROUP_COLOR[group.key] || "#4285F4";
          return (
            <Box key={group.key} sx={{ mb: 4 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                <Box sx={{ width: 4, height: 18, bgcolor: color, borderRadius: 1 }} />
                <Typography sx={{ color: "text.secondary", fontWeight: 700, fontSize: 13, textTransform: "uppercase", letterSpacing: 1.5 }}>
                  {group.label}
                </Typography>
                <Chip label={group.agents.length} size="small"
                  sx={{ height: 20, bgcolor: `${color}1F`, color, fontSize: 11, fontWeight: 700 }} />
                <Box sx={{ flex: 1, height: 1, bgcolor: "rgba(255,255,255,0.08)" }} />
              </Box>
              <Grid container spacing={2}>
                {group.agents.map((agent) => (
                  <Grid size={{ xs: 12, sm: 6, md: 4 }} key={agent.id}>
                    <Card sx={{
                      bgcolor: "background.paper",
                      border: `1px solid ${agent.is_enabled ? "rgba(255,255,255,0.08)" : "rgba(255,255,255,0.04)"}`,
                      borderRadius: 2, opacity: agent.is_enabled ? 1 : 0.5, height: "100%",
                    }}>
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1 }}>
                          <Box sx={{ width: 32, height: 32, borderRadius: 1, bgcolor: `${color}1F`,
                            display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                            <SmartToy sx={{ color, fontSize: 18 }} />
                          </Box>
                          <Box sx={{ flex: 1, minWidth: 0 }}>
                            <Typography sx={{ color: "text.primary", fontWeight: 600, fontSize: 14, lineHeight: 1.2 }}>
                              {agent.name}
                            </Typography>
                            <Typography variant="caption" sx={{ color: "text.secondary" }}>
                              {agent.domain || agent.group_label}
                            </Typography>
                          </Box>
                          {agent.is_builtin && (
                            <Chip label="Built-in" size="small"
                              sx={{ height: 18, fontSize: 9, fontWeight: 700, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
                          )}
                        </Box>
                        {agent.signature_opening && (
                          <Typography variant="caption" sx={{
                            color: agent.accent_color || color, fontStyle: "italic",
                            fontWeight: 600, display: "block", mb: 0.5,
                          }}>
                            “{agent.signature_opening}”
                          </Typography>
                        )}
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5, minHeight: 36 }}>
                          {agent.description}
                        </Typography>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, flexWrap: "wrap" }}>
                          {agent.legacy_orchestrator ? (
                            <Button size="small" variant="outlined" startIcon={<PlayArrow sx={{ fontSize: 14 }} />}
                              disabled={!selectedClientId || runMutation.isPending || !canAct}
                              onClick={() => runMutation.mutate(agent.key as AgentType)}
                              sx={{ borderColor: color, color, fontSize: 11, "&:hover": { bgcolor: `${color}1A` } }}>
                              Run
                            </Button>
                          ) : (
                            <Button size="small" variant="outlined" startIcon={<PlayArrow sx={{ fontSize: 14 }} />}
                              disabled={!agent.is_enabled || !canAct}
                              onClick={() => {
                                setBriefingAgent(agent);
                                setBriefingPrompt("");
                                setBriefingOutput(null);
                                setBriefingError("");
                              }}
                              sx={{ borderColor: color, color, fontSize: 11, "&:hover": { bgcolor: `${color}1A` } }}>
                              Run
                            </Button>
                          )}
                          <Box sx={{ flex: 1 }} />
                          <Tooltip title={isAdmin ? "Configure" : "View configuration"}>
                            <IconButton size="small" onClick={() => setConfiguring(agent)}
                              sx={{ color: "text.secondary", "&:hover": { color } }}>
                              {isAdmin ? <Edit sx={{ fontSize: 16 }} /> : <AutoFixHigh sx={{ fontSize: 16 }} />}
                            </IconButton>
                          </Tooltip>
                          {isAdmin && !agent.is_builtin && (
                            <Tooltip title="Delete">
                              <IconButton size="small"
                                onClick={() => {
                                  if (window.confirm(`Delete agent "${agent.name}"?`)) deleteMutation.mutate(agent.id);
                                }}
                                sx={{ color: "text.secondary", "&:hover": { color: "#EA4335" } }}>
                                <Delete sx={{ fontSize: 16 }} />
                              </IconButton>
                            </Tooltip>
                          )}
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          );
        })
      )}

      <ConfigureDialog
        open={!!configuring}
        agent={configuring}
        onClose={() => setConfiguring(null)}
        onSave={(patch) => updateMutation.mutate({ id: configuring!.id, patch })}
        isAdmin={isAdmin}
      />
      <NewAgentDialog
        open={newOpen}
        onClose={() => setNewOpen(false)}
        onCreate={(data) => createMutation.mutate(data)}
        existingGroups={groupOptions}
      />

      {/* Briefing drawer — invoke a catalog agent and view its LLM-generated output */}
      <Drawer anchor="right" open={!!briefingAgent} onClose={() => setBriefingAgent(null)}
        slotProps={{ paper: { sx: { width: { xs: "100%", sm: 540 }, bgcolor: "background.paper", color: "text.primary" } } }}>
        {briefingAgent && (
          <Box sx={{ p: 2.5, display: "flex", flexDirection: "column", height: "100%" }}>
            <Typography variant="h6" sx={{ fontWeight: 700 }}>{briefingAgent.name}</Typography>
            <Typography variant="caption" sx={{ color: "text.secondary", mb: 2 }}>
              {briefingAgent.group_label} · {briefingAgent.domain || briefingAgent.description}
            </Typography>
            <Divider sx={{ borderColor: "divider", mb: 2 }} />
            <TextField
              fullWidth size="small" multiline minRows={3} label="Your instruction (optional)"
              placeholder="Leave blank for a standard briefing on this agent's domain."
              value={briefingPrompt} onChange={(e) => setBriefingPrompt(e.target.value)}
              slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
              sx={{ mb: 2, "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
            <Button variant="contained" startIcon={<PlayArrow />}
              disabled={briefingMutation.isPending}
              onClick={() => briefingMutation.mutate({ agentId: briefingAgent.id, prompt: briefingPrompt || undefined })}
              sx={{ mb: 2 }}>
              {briefingMutation.isPending ? <CircularProgress size={18} /> : "Generate Briefing"}
            </Button>
            <Box sx={{ flex: 1, overflow: "auto", borderTop: "1px solid rgba(255,255,255,0.06)", pt: 2 }}>
              {briefingMutation.isPending && (
                <Box sx={{ textAlign: "center", py: 4 }}>
                  <CircularProgress size={28} sx={{ color: "#4285F4" }} />
                  <Typography variant="caption" sx={{ display: "block", color: "text.secondary", mt: 1 }}>
                    Calling the AI engine…
                  </Typography>
                </Box>
              )}
              {briefingError && (
                <Alert severity="error" sx={{ mb: 1 }}>{briefingError}</Alert>
              )}
              {briefingOutput && (
                <>
                  <Box sx={{ display: "flex", gap: 1, mb: 1.5, flexWrap: "wrap" }}>
                    <Chip size="small" label={`Provider: ${briefingOutput.provider}`}
                      sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 10, height: 20 }} />
                    {briefingOutput.model && (
                      <Chip size="small" label={`Model: ${briefingOutput.model}`}
                        sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontSize: 10, height: 20 }} />
                    )}
                    {briefingOutput.tokens_used > 0 && (
                      <Chip size="small" label={`${briefingOutput.tokens_used} tokens`}
                        sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", fontSize: 10, height: 20 }} />
                    )}
                    <Chip size="small" label={`${briefingOutput.duration_ms} ms`}
                      sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", fontSize: 10, height: 20 }} />
                  </Box>
                  <RichOutput value={briefingOutput.output} />
                </>
              )}
              {!briefingMutation.isPending && !briefingOutput && !briefingError && (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  Click "Generate Briefing" to invoke this agent.
                </Typography>
              )}
            </Box>
          </Box>
        )}
      </Drawer>
    </Box>
  );
}
