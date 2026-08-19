import React, { useMemo, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useViewMode } from "../theme/ViewModeContext";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Button, Card, CardContent, Grid, Chip,
  Select, MenuItem, FormControl, InputLabel, CircularProgress, Alert,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Switch, IconButton, Tooltip, Drawer, Divider, LinearProgress, Collapse,
  Avatar, RadioGroup, FormControlLabel, Radio, FormLabel, Stepper, Step, StepLabel,
  Paper,
} from "@mui/material";
import {
  SmartToy, PlayArrow, Add, Edit, Delete, AutoFixHigh, ExpandMore, ExpandLess,
  CloudUpload, OpenInNew, ArrowBack, ArrowForward, DragIndicator,
  AddCircle, DoNotDisturb,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { agentsApi, scansApi, agentCatalogApi, adminApi, customFrameworksApi, assetsApi, connectorsApi } from "../services/api";
import { Scan, AgentType, MyAccess } from "../types";
import { toast } from "react-toastify";
import RichOutput from "../components/RichOutput";
import { AgentRunWizard, InputField, SelectOption, DEFAULT_SCHEMA, GROUP_COLOR } from "../components/AgentRunWizard";
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
  // Input wizard schema
  input_schema?: InputField[];
}

interface AgentGroup { key: string; label: string; agents: Agent[]; }

// ── Configuration dialog ─────────────────────────────────────────────────────

function ConfigureDialog({ open, agent, onClose, onSave, isAdmin, hideSensitive }: {
  open: boolean; agent: Agent | null; onClose: () => void;
  onSave: (patch: any) => void; isAdmin: boolean; hideSensitive?: boolean;
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
          {!hideSensitive && (
            <Grid size={{ xs: 12 }}>
              <TextField fullWidth size="small" label="System Prompt" multiline minRows={6} disabled={readOnly}
                value={form.system_prompt || ""} onChange={(e) => set("system_prompt", e.target.value)}
                slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary", fontFamily: "monospace", fontSize: 12 } } }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
            </Grid>
          )}
          {hideSensitive && (
            <Grid size={{ xs: 12 }}>
              <Alert severity="warning" sx={{ fontSize: 13 }}>
                AI instructions are not visible on the trial plan. Upgrade for full access.
              </Alert>
            </Grid>
          )}
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

// ── Schema field types available in the builder ───────────────────────────────
const FIELD_TYPE_OPTIONS = [
  { value: "scan",          label: "Scan Selector",      description: "Dropdown to pick a completed scan" },
  { value: "framework",     label: "Framework Selector", description: "Dropdown to pick a compliance framework" },
  { value: "select",        label: "Choice (Select)",    description: "Radio cards — user picks one option from a list" },
  { value: "text_context",  label: "Paste / Data",       description: "Multi-line paste area for raw data (logs, configs, metrics)" },
  { value: "custom_prompt", label: "Instructions",       description: "Free-text instructions or focus area" },
  { value: "file_upload",   label: "File Upload",        description: "Upload a file — PDF, DOCX, CSV, JSON, TXT (text extracted automatically)" },
  { value: "asset_select",  label: "Asset Selection",    description: "Multi-select from the client asset inventory" },
  { value: "platform_data", label: "Platform Data",      description: "Select a connected platform and pull its latest scan data" },
];

interface SchemaFieldDraft {
  id: number; // local key for React
  type: string;
  label: string;
  required: boolean;
  description: string;
  options: { value: string; label: string; description: string }[];
}

let _fieldId = 0;
const mkField = (type = "custom_prompt"): SchemaFieldDraft => ({
  id: ++_fieldId, type, label: "", required: false, description: "", options: [],
});

function SchemaFieldEditor({ field, onChange, onDelete, accentColor }: {
  field: SchemaFieldDraft;
  onChange: (f: SchemaFieldDraft) => void;
  onDelete: () => void;
  accentColor: string;
}) {
  const [expanded, setExpanded] = useState(true);
  const set = (patch: Partial<SchemaFieldDraft>) => onChange({ ...field, ...patch });

  const addOption = () => set({ options: [...field.options, { value: "", label: "", description: "" }] });
  const setOption = (i: number, patch: Partial<typeof field.options[0]>) => {
    const opts = field.options.map((o, idx) => idx === i ? { ...o, ...patch } : o);
    set({ options: opts });
  };
  const removeOption = (i: number) => set({ options: field.options.filter((_, idx) => idx !== i) });

  return (
    <Paper variant="outlined" sx={{ p: 1.5, mb: 1.5, borderColor: "divider", position: "relative" }}>
      {/* Header row */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: expanded ? 1.5 : 0 }}>
        <DragIndicator sx={{ color: "text.disabled", fontSize: 18, cursor: "grab" }} />
        <FormControl size="small" sx={{ minWidth: 160 }}>
          <Select value={field.type} onChange={(e) => set({ type: e.target.value })}
            sx={{ fontSize: 13 }}>
            {FIELD_TYPE_OPTIONS.map((o) => (
              <MenuItem key={o.value} value={o.value}>
                <Box>
                  <Typography sx={{ fontSize: 13, fontWeight: 600 }}>{o.label}</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>{o.description}</Typography>
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <TextField size="small" placeholder="Field label *" value={field.label}
          onChange={(e) => set({ label: e.target.value })}
          sx={{ flex: 1, "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
        <Tooltip title={field.required ? "Required" : "Optional"}>
          <Switch size="small" checked={field.required}
            onChange={(e) => set({ required: e.target.checked })}
            sx={{ "& .MuiSwitch-switchBase.Mui-checked": { color: accentColor } }} />
        </Tooltip>
        <IconButton size="small" onClick={() => setExpanded((v) => !v)} sx={{ color: "text.secondary" }}>
          {expanded ? <ExpandLess fontSize="small" /> : <ExpandMore fontSize="small" />}
        </IconButton>
        <IconButton size="small" onClick={onDelete} sx={{ color: "error.main" }}>
          <Delete fontSize="small" />
        </IconButton>
      </Box>

      {/* Expanded detail */}
      {expanded && (
        <Box sx={{ pl: 4 }}>
          <TextField fullWidth size="small" placeholder="Helper text shown below the field (optional)"
            value={field.description} onChange={(e) => set({ description: e.target.value })}
            sx={{ mb: field.type === "select" ? 1.5 : 0, "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />

          {field.type === "select" && (
            <Box>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, mb: 0.5, display: "block" }}>
                OPTIONS — users see these as clickable radio cards
              </Typography>
              {field.options.map((opt, i) => (
                <Box key={i} sx={{ display: "flex", gap: 1, mb: 1, alignItems: "flex-start" }}>
                  <TextField size="small" placeholder="value (slug)" value={opt.value}
                    onChange={(e) => setOption(i, { value: e.target.value.toLowerCase().replace(/\s+/g, "_") })}
                    sx={{ width: 130, "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
                  <TextField size="small" placeholder="Label" value={opt.label}
                    onChange={(e) => setOption(i, { label: e.target.value })}
                    sx={{ width: 150, "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
                  <TextField size="small" placeholder="Description (shown under label)" value={opt.description}
                    onChange={(e) => setOption(i, { description: e.target.value })}
                    sx={{ flex: 1, "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
                  <IconButton size="small" onClick={() => removeOption(i)} sx={{ color: "error.main", mt: 0.25 }}>
                    <DoNotDisturb fontSize="small" />
                  </IconButton>
                </Box>
              ))}
              <Button size="small" startIcon={<AddCircle />} onClick={addOption}
                sx={{ color: accentColor, fontSize: 12 }}>
                Add option
              </Button>
            </Box>
          )}
        </Box>
      )}
    </Paper>
  );
}

function NewAgentDialog({ open, onClose, onCreate, existingGroups }: {
  open: boolean; onClose: () => void; onCreate: (data: any) => void;
  existingGroups: { key: string; label: string }[];
}) {
  const [step, setStep] = useState(0);
  const [data, setData] = useState<any>({
    key: "", name: "", group_key: existingGroups[0]?.key || "core_advisory",
    group_label: existingGroups[0]?.label || "Core Advisory",
    description: "", objective: "", domain: "", system_prompt: "",
    temperature: 0.1, max_tokens: 4096, is_enabled: true,
  });
  const [fields, setFields] = useState<SchemaFieldDraft[]>([
    mkField("custom_prompt"),
  ]);

  React.useEffect(() => {
    if (open) {
      setStep(0);
      setData({
        key: "", name: "", group_key: existingGroups[0]?.key || "core_advisory",
        group_label: existingGroups[0]?.label || "Core Advisory",
        description: "", objective: "", domain: "", system_prompt: "",
        temperature: 0.1, max_tokens: 4096, is_enabled: true,
      });
      setFields([mkField("custom_prompt")]);
    }
  }, [open, existingGroups]);

  const accentColor = "#4285F4";
  const step1Valid = !!data.key && !!data.name;
  const step2Valid = fields.every((f) => !!f.label.trim());

  const handleCreate = () => {
    const input_schema = fields.map(({ type, label, required, description, options }) => {
      const field: any = { type, label, required };
      if (description.trim()) field.description = description.trim();
      if (type === "select" && options.length) {
        field.options = options.map(({ value, label: l, description: d }) => {
          const o: any = { value: value || l.toLowerCase().replace(/\s+/g, "_"), label: l };
          if (d.trim()) o.description = d.trim();
          return o;
        });
      }
      return field;
    });
    onCreate({ ...data, input_schema });
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth
      slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
      <DialogTitle sx={{ pb: 0 }}>
        <Typography sx={{ fontWeight: 700, fontSize: 18 }}>New Agent</Typography>
        <Stepper activeStep={step} sx={{ mt: 2, mb: 0 }}>
          <Step><StepLabel>Agent Details</StepLabel></Step>
          <Step><StepLabel>Input Schema</StepLabel></Step>
        </Stepper>
      </DialogTitle>

      <DialogContent dividers sx={{ borderColor: "divider", minHeight: 380 }}>

        {/* ── Step 1: Agent Details ────────────────────────────────────── */}
        {step === 0 && (
          <Grid container spacing={2} sx={{ mt: 0.5 }}>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="Key (slug, unique)" required
                value={data.key}
                onChange={(e) => setData({ ...data, key: e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, "_") })}
                helperText="snake_case, used internally"
                slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary", fontFamily: "monospace" } } }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="Display Name" required
                value={data.name} onChange={(e) => setData({ ...data, name: e.target.value })}
                slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
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
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="Domain / Specialty"
                placeholder="e.g. Cloud Security, IAM, Threat Intel"
                value={data.domain} onChange={(e) => setData({ ...data, domain: e.target.value })}
                slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField fullWidth size="small" label="Description"
                placeholder="One-line summary shown on the agent card"
                value={data.description} onChange={(e) => setData({ ...data, description: e.target.value })}
                slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField fullWidth size="small" label="Objective"
                placeholder="What does this agent produce? (shown in detail panel)"
                value={data.objective} onChange={(e) => setData({ ...data, objective: e.target.value })}
                slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary" } } }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField fullWidth size="small" label="System Prompt" multiline minRows={5}
                placeholder="The AI instructions — role, expertise, methodology, conduct rules…"
                value={data.system_prompt} onChange={(e) => setData({ ...data, system_prompt: e.target.value })}
                slotProps={{ inputLabel: { sx: { color: "text.secondary" } }, htmlInput: { style: { color: "text.primary", fontFamily: "monospace", fontSize: 12 } } }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
            </Grid>
          </Grid>
        )}

        {/* ── Step 2: Input Schema Builder ─────────────────────────────── */}
        {step === 1 && (
          <Box>
            <Alert severity="info" sx={{ mb: 2, fontSize: 13 }}>
              Define what information the wizard will collect when someone runs this agent.
              Fields appear in order — drag to reorder. Leave empty to skip the wizard entirely.
            </Alert>

            {fields.map((field, i) => (
              <SchemaFieldEditor
                key={field.id}
                field={field}
                accentColor={accentColor}
                onChange={(updated) => setFields((fs) => fs.map((f) => f.id === field.id ? updated : f))}
                onDelete={() => setFields((fs) => fs.filter((f) => f.id !== field.id))}
              />
            ))}

            {/* Quick-add buttons */}
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 1 }}>
              {FIELD_TYPE_OPTIONS.map((opt) => (
                <Button key={opt.value} size="small" variant="outlined"
                  startIcon={<Add sx={{ fontSize: 14 }} />}
                  onClick={() => setFields((fs) => [...fs, mkField(opt.value)])}
                  sx={{ fontSize: 11, borderColor: "divider", color: "text.secondary",
                    "&:hover": { borderColor: accentColor, color: accentColor } }}>
                  {opt.label}
                </Button>
              ))}
            </Box>

            {fields.length === 0 && (
              <Typography variant="body2" sx={{ color: "text.disabled", mt: 2, textAlign: "center" }}>
                No fields — the wizard will not appear when running this agent.
              </Typography>
            )}
          </Box>
        )}
      </DialogContent>

      <DialogActions sx={{ p: 2, gap: 1 }}>
        <Button onClick={onClose} sx={{ color: "text.secondary" }}>Cancel</Button>
        <Box sx={{ flex: 1 }} />
        {step > 0 && (
          <Button startIcon={<ArrowBack />} onClick={() => setStep(0)} sx={{ color: "text.secondary" }}>
            Back
          </Button>
        )}
        {step === 0 && (
          <Button variant="contained" disabled={!step1Valid} endIcon={<ArrowForward />}
            onClick={() => setStep(1)}
            sx={{ bgcolor: accentColor, "&:hover": { bgcolor: accentColor, filter: "brightness(0.9)" } }}>
            Next: Input Schema
          </Button>
        )}
        {step === 1 && (
          <Button variant="contained" disabled={!step2Valid}
            startIcon={<Add />} onClick={handleCreate}
            sx={{ bgcolor: "#34A853", "&:hover": { bgcolor: "#34A853", filter: "brightness(0.9)" } }}>
            Create Agent
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

// ── Recent run row ───────────────────────────────────────────────────────────

interface AgentRun {
  id: string;
  agent_type: string;
  status: "queued" | "running" | "completed" | "failed";
  started_at?: string;
  output_data?: any;
  error_message?: string;
}

const RUN_STATUS_COLOR: Record<string, string> = {
  completed: "#34A853",
  failed: "#EA4335",
  queued: "#FBBC04",
  running: "#FBBC04",
};

function RecentRunRow({ run, onArchive }: {
  run: AgentRun;
  onArchive: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const hasOutput = run.status === "completed" && run.output_data;
  return (
    <Box sx={{ bgcolor: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 1.5, p: 1.25, mb: 1 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
        <Chip label={run.agent_type} size="small"
          sx={{ height: 20, fontSize: 10, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4" }} />
        <Chip label={run.status} size="small"
          sx={{ height: 20, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
            bgcolor: `${RUN_STATUS_COLOR[run.status] || "#888"}20`,
            color: RUN_STATUS_COLOR[run.status] || "#888" }} />
        {run.started_at && (
          <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>
            {new Date(run.started_at).toLocaleString()}
          </Typography>
        )}
        <Box sx={{ ml: "auto", display: "flex", alignItems: "center", gap: 0.25 }}>
          {hasOutput && (
            <Tooltip title={expanded ? "Collapse" : "Expand output"}>
              <IconButton size="small" onClick={() => setExpanded((e) => !e)} sx={{ color: "text.secondary" }}>
                {expanded ? <ExpandLess sx={{ fontSize: 16 }} /> : <ExpandMore sx={{ fontSize: 16 }} />}
              </IconButton>
            </Tooltip>
          )}
          <Tooltip title="Move to Trash">
            <IconButton size="small" onClick={onArchive}
              sx={{ color: "text.secondary", "&:hover": { color: "#EA4335" } }}>
              <Delete sx={{ fontSize: 15 }} />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>
      {hasOutput && (
        <Collapse in={expanded} timeout="auto" unmountOnExit>
          <Box sx={{ mt: 1, pt: 1, borderTop: "1px solid rgba(255,255,255,0.06)" }}>
            <Typography variant="caption" sx={{ color: "text.secondary", whiteSpace: "pre-wrap", fontSize: 11 }}>
              {typeof run.output_data === "string" ? run.output_data : JSON.stringify(run.output_data, null, 2)}
            </Typography>
          </Box>
        </Collapse>
      )}
    </Box>
  );
}

export default function Agents() {
  const qc = useQueryClient();
  const { canAct } = useViewMode();
  const { clientId: selectedClientId } = useActiveClient();
  const [configuring, setConfiguring] = useState<Agent | null>(null);
  const [newOpen, setNewOpen] = useState(false);
  const [wizardAgent, setWizardAgent] = useState<Agent | null>(null);
  const [briefingOutput, setBriefingOutput] = useState<{ output: string; provider: string; model?: string; tokens_used: number; duration_ms: number } | null>(null);
  const [briefingError, setBriefingError] = useState<string>("");
  const [pollingRunId, setPollingRunId] = useState<string | null>(null);
  const { data: me } = useQuery<MyAccess>({ queryKey: ["my-access"], queryFn: adminApi.me, retry: 0 });
  const isAdmin = !!(me?.is_admin || me?.is_admin_anywhere);

  const { data: scans = [] } = useQuery<Scan[]>({
    queryKey: ["scans-for-agents", selectedClientId],
    queryFn: () => scansApi.list(selectedClientId),
    select: (data) => data.filter((s) => s.status === "completed"),
    enabled: !!selectedClientId,
  });

  const { data: allFrameworks = [] } = useQuery<any[]>({
    queryKey: ["frameworks-all"],
    queryFn: () => customFrameworksApi.listAll(),
  });

  const [showHidden, setShowHidden] = useState(false);

  const { data: catalogData, isLoading } = useQuery<{ groups: AgentGroup[] }>({
    queryKey: ["agent-catalog", showHidden],
    queryFn: () => agentCatalogApi.list(showHidden),
  });

  const { data: hiddenData } = useQuery<{ groups: AgentGroup[] }>({
    queryKey: ["agent-catalog-hidden"],
    queryFn: () => agentCatalogApi.list(true),
    select: (d) => ({
      groups: d.groups.map((g) => ({
        ...g,
        agents: g.agents.filter((a: any) => a.is_builtin && !a.is_enabled),
      })).filter((g) => g.agents.length > 0),
    }),
  });
  const hiddenCount = hiddenData?.groups.reduce((s, g) => s + g.agents.length, 0) ?? 0;

  const allGroups = useMemo(() => catalogData?.groups || [], [catalogData]);
  const groups = allGroups;
  const groupOptions = useMemo(() => allGroups.map((g) => ({ key: g.key, label: g.label })), [allGroups]);

  // Polling query — fetches a single run until completed/failed
  const { data: pollingRun } = useQuery<AgentRun>({
    queryKey: ["agent-run-poll", selectedClientId, pollingRunId],
    queryFn: () => agentsApi.getRun(selectedClientId, pollingRunId!),
    enabled: !!pollingRunId && !!selectedClientId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (status === "completed" || status === "failed") return false;
      return 3000;
    },
  });

  // Stop polling when terminal state reached
  React.useEffect(() => {
    if (pollingRun?.status === "completed" || pollingRun?.status === "failed") {
      setPollingRunId(null);
      qc.invalidateQueries({ queryKey: ["agent-runs-list", selectedClientId] });
    }
  }, [pollingRun?.status, qc, selectedClientId]);

  // Recent runs list — last 5 for the current client
  const { data: recentRunsData } = useQuery<AgentRun[]>({
    queryKey: ["agent-runs-list", selectedClientId],
    queryFn: () => agentsApi.listRuns(selectedClientId),
    enabled: !!selectedClientId,
    refetchInterval: 15000,
    select: (runs) => runs.slice(0, 5),
  });

  const runMutation = useMutation({
    mutationFn: ({ agentType, scanId, framework }: { agentType: AgentType; scanId?: string; framework?: string }) =>
      agentsApi.run(selectedClientId, {
        agent_type: agentType,
        scan_id: scanId || undefined,
        input_data: { framework: framework || "nist_csf" },
      }),
    onSuccess: (run, vars) => {
      if (run?.id) {
        setPollingRunId(run.id);
        toast.info(`${vars.agentType} queued — polling for result…`);
      } else {
        qc.invalidateQueries({ queryKey: ["agent-runs"] });
        toast.success(`${vars.agentType} started`);
      }
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Agent run failed"),
  });

  const briefingMutation = useMutation({
    mutationFn: ({ agentId, prompt, scanId, assetIds }: { agentId: string; prompt?: string; scanId?: string; assetIds?: string[] }) =>
      agentCatalogApi.run(agentId, prompt, selectedClientId || undefined, scanId || undefined, assetIds),
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
    onSuccess: (res: any) => {
      qc.invalidateQueries({ queryKey: ["agent-catalog"] });
      qc.invalidateQueries({ queryKey: ["agent-catalog-hidden"] });
      toast.success(res?.hidden ? "Agent hidden — restore it from 'Show hidden'" : "Agent deleted");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Delete failed"),
  });

  const restoreMutation = useMutation({
    mutationFn: (id: string) => agentCatalogApi.restore(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-catalog"] });
      qc.invalidateQueries({ queryKey: ["agent-catalog-hidden"] });
      toast.success("Agent restored");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Restore failed"),
  });

  const archiveRunMutation = useMutation({
    mutationFn: (runId: string) => agentsApi.deleteRun(selectedClientId!, runId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-runs-list", selectedClientId] });
      toast.success("Moved to trash");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Archive failed"),
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
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", alignItems: "center" }}>
          {hiddenCount > 0 && (
            <Button
              size="small"
              variant="outlined"
              onClick={() => setShowHidden((v) => !v)}
              sx={{ fontSize: 12, borderColor: "rgba(255,255,255,0.2)", color: "text.secondary" }}
            >
              {showHidden ? "Hide hidden agents" : `Show hidden (${hiddenCount})`}
            </Button>
          )}
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
                  <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={agent.id}>
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
                          <Tooltip title={
                            !canAct ? "Switch to Analyst mode (top-right toggle) to run agents" :
                            !selectedClientId ? "Select a client first" :
                            !agent.is_enabled ? "Agent is disabled — enable it via configure" : ""
                          }>
                            <span>
                              <Button size="small" variant="outlined" startIcon={<PlayArrow sx={{ fontSize: 14 }} />}
                                disabled={!selectedClientId || !canAct || !agent.is_enabled || (agent.legacy_orchestrator && (runMutation.isPending || !!pollingRunId))}
                                onClick={() => { setBriefingOutput(null); setBriefingError(""); setWizardAgent(agent); }}
                                sx={{ borderColor: color, color, fontSize: 11, "&:hover": { bgcolor: `${color}1A` } }}>
                                {agent.legacy_orchestrator && pollingRunId ? "Running…" : "Run"}
                              </Button>
                            </span>
                          </Tooltip>
                          <Box sx={{ flex: 1 }} />
                          <Tooltip title={isAdmin ? "Configure" : "View configuration"}>
                            <IconButton size="small" onClick={() => setConfiguring(agent)}
                              sx={{ color: "text.secondary", "&:hover": { color } }}>
                              {isAdmin ? <Edit sx={{ fontSize: 16 }} /> : <AutoFixHigh sx={{ fontSize: 16 }} />}
                            </IconButton>
                          </Tooltip>
                          <Tooltip title={agent.is_builtin ? "Hide agent" : "Delete agent"}>
                            <IconButton size="small"
                              onClick={() => {
                                const msg = agent.is_builtin
                                  ? `Hide "${agent.name}"? You can restore it later.`
                                  : `Delete "${agent.name}"? This cannot be undone.`;
                                if (window.confirm(msg)) deleteMutation.mutate(agent.id);
                              }}
                              sx={{ color: "text.secondary", "&:hover": { color: "#EA4335" } }}>
                              <Delete sx={{ fontSize: 16 }} />
                            </IconButton>
                          </Tooltip>
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

      {/* Hidden built-in agents section */}
      {showHidden && hiddenData && hiddenData.groups.length > 0 && (
        <Box sx={{ mt: 3 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
            <Box sx={{ width: 4, height: 18, bgcolor: "#9E9E9E", borderRadius: 1 }} />
            <Typography sx={{ color: "text.secondary", fontWeight: 700, fontSize: 13, textTransform: "uppercase", letterSpacing: 1.5 }}>
              Hidden Agents
            </Typography>
            <Chip label={hiddenCount} size="small"
              sx={{ height: 20, bgcolor: "rgba(158,158,158,0.15)", color: "text.secondary", fontSize: 11, fontWeight: 700 }} />
            <Box sx={{ flex: 1, height: 1, bgcolor: "rgba(255,255,255,0.08)" }} />
          </Box>
          <Grid container spacing={2}>
            {hiddenData.groups.flatMap((g) => g.agents).map((agent: any) => (
              <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={agent.id}>
                <Card variant="outlined" sx={{ opacity: 0.55, borderStyle: "dashed" }}>
                  <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                      <Typography sx={{ fontWeight: 600, fontSize: 14, flex: 1 }}>{agent.name}</Typography>
                      <Chip label="Hidden" size="small" sx={{ height: 18, fontSize: 9, bgcolor: "rgba(158,158,158,0.15)", color: "text.secondary" }} />
                    </Box>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5 }}>
                      {agent.description}
                    </Typography>
                    <Button size="small" variant="outlined"
                      onClick={() => restoreMutation.mutate(agent.id)}
                      sx={{ fontSize: 11, borderColor: "rgba(255,255,255,0.2)", color: "text.secondary" }}>
                      Restore
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {/* Polling status banner */}
      {(pollingRunId || pollingRun?.status === "completed" || pollingRun?.status === "failed") && (
        <Box sx={{ mt: 3, mb: 2 }}>
          {pollingRunId && (
            <>
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                Agent running — waiting for result…
              </Typography>
              <LinearProgress sx={{ borderRadius: 1 }} />
            </>
          )}
          {!pollingRunId && pollingRun?.status === "failed" && (
            <Alert severity="error">
              {pollingRun.error_message || "Agent run failed"}
            </Alert>
          )}
          {!pollingRunId && pollingRun?.status === "completed" && pollingRun.output_data && (
            <Alert severity="success">
              Agent completed. View output in Recent Runs below.
            </Alert>
          )}
        </Box>
      )}

      {/* Recent Runs */}
      {selectedClientId && (recentRunsData?.length ?? 0) > 0 && (
        <Box sx={{ mt: 3 }}>
          <Box sx={{ display: "flex", alignItems: "center", mb: 1 }}>
            <Typography sx={{ color: "text.secondary", fontWeight: 700, fontSize: 12, textTransform: "uppercase", letterSpacing: 1.5, flex: 1 }}>
              Recent Runs
            </Typography>
            <Button component={Link} to="/ai-advisor/run-trash" size="small"
              sx={{ fontSize: 11, color: "text.secondary", textTransform: "none" }}>
              View Trash
            </Button>
          </Box>
          {(recentRunsData || []).map((run) => (
            <RecentRunRow key={run.id} run={run} onArchive={() => archiveRunMutation.mutate(run.id)} />
          ))}
        </Box>
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

      {/* Agent Run Wizard */}
      {wizardAgent && (
        <AgentRunWizard
          agent={wizardAgent}
          scans={scans}
          frameworks={allFrameworks}
          clientId={selectedClientId || ""}
          color={GROUP_COLOR[wizardAgent.group_key] || "#4285F4"}
          onClose={() => setWizardAgent(null)}
          onRunLegacy={(scanId, framework) =>
            runMutation.mutate({ agentType: wizardAgent.key as AgentType, scanId, framework })
          }
          onRunCatalog={(agentId, prompt, scanId, assetIds) =>
            briefingMutation.mutate({ agentId, prompt, scanId, assetIds })
          }
        />
      )}

      {/* Catalog agent output drawer */}
      <Drawer anchor="right" open={briefingMutation.isPending || !!briefingOutput || !!briefingError}
        onClose={() => { setBriefingOutput(null); setBriefingError(""); }}
        slotProps={{ paper: { sx: { width: { xs: "100%", sm: 540 }, bgcolor: "background.paper", color: "text.primary" } } }}>
        <Box sx={{ p: 2.5, display: "flex", flexDirection: "column", height: "100%" }}>
          <Typography variant="h6" sx={{ fontWeight: 700 }}>Agent Output</Typography>
          <Divider sx={{ borderColor: "divider", my: 1.5 }} />
          <Box sx={{ flex: 1, overflow: "auto" }}>
            {briefingMutation.isPending && (
              <Box sx={{ textAlign: "center", py: 6 }}>
                <CircularProgress size={28} sx={{ color: "#4285F4" }} />
                <Typography variant="caption" sx={{ display: "block", color: "text.secondary", mt: 1 }}>
                  Calling the AI engine…
                </Typography>
              </Box>
            )}
            {briefingError && <Alert severity="error">{briefingError}</Alert>}
            {briefingOutput && (
              <>
                <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
                  <Chip size="small" label={`Provider: ${briefingOutput.provider}`}
                    sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 10, height: 20 }} />
                  {briefingOutput.model && (
                    <Chip size="small" label={`Model: ${briefingOutput.model}`}
                      sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontSize: 10, height: 20 }} />
                  )}
                  {briefingOutput.tokens_used > 0 && (
                    <Chip size="small" label={`${briefingOutput.tokens_used} tokens`}
                      sx={{ bgcolor: "action.hover", color: "text.secondary", fontSize: 10, height: 20 }} />
                  )}
                  <Chip size="small" label={`${briefingOutput.duration_ms} ms`}
                    sx={{ bgcolor: "action.hover", color: "text.secondary", fontSize: 10, height: 20 }} />
                </Box>
                <RichOutput value={briefingOutput.output} />
              </>
            )}
          </Box>
        </Box>
      </Drawer>
    </Box>
  );
}
