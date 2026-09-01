import React, { useState, useCallback } from "react";
import { useIsGuest } from "../hooks/useIsGuest";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress, Alert,
  Button, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, IconButton, Grid, Tooltip, Divider,
  Accordion, AccordionSummary, AccordionDetails, Paper,
  Table, TableHead, TableRow, TableCell, TableBody,
  Select, MenuItem, FormControl, InputLabel, LinearProgress,
  Checkbox, ListItemText, OutlinedInput,
} from "@mui/material";
import {
  Add, Delete, CheckCircle, RadioButtonUnchecked, AccountTree,
  AutoAwesome, ExpandMore, Lock, ArrowUpward, ArrowDownward,
  FileDownload, Edit, Save,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ctemApi, connectorsApi } from "../services/api";
import { toast } from "react-toastify";
import { fmt } from "../utils/datetime";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const PHASES = [
  { key: "scope",      label: "1. Scope",      color: "#4285F4" },
  { key: "discover",   label: "2. Discover",   color: "#FBBC04" },
  { key: "prioritise", label: "3. Prioritise", color: "#EA4335" },
  { key: "validate",   label: "4. Validate",   color: "#9C27B0" },
  { key: "mobilise",   label: "5. Mobilise",   color: "#34A853" },
];

const SEV_COLORS: Record<string, string> = {
  critical: "#EA4335", high: "#FF6D00", medium: "#FBBC04", low: "#34A853", info: "#4285F4",
};

const SCOPE_STATUSES = [
  { value: "untagged",     label: "Untagged" },
  { value: "in_scope",     label: "In Scope" },
  { value: "out_of_scope", label: "Out of Scope" },
  { value: "crown_jewel",  label: "Crown Jewel" },
];

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface PhaseNote {
  phase: string;
  notes?: string;
  completed?: boolean;
  completed_by?: string;
  completed_at?: string;
  ai_brief?: string;
  ai_brief_generated_at?: string;
  phase_data_json?: Record<string, unknown>;
}

interface CTEMProgram {
  id: string;
  name: string;
  description?: string;
  status?: string;
  current_phase?: string;
  phases?: PhaseNote[];
  created_at?: string;
  connector_ids?: string[];
}

interface ScopeAsset {
  resource_id: string;
  resource_type: string;
  display_name: string;
  exposure_category: string;
  finding_count: number;
  scope_status: string;
  notes: string;
}

interface PriorityItem {
  rank: number;
  title: string;
  severity: string;
  source: "ai" | "analyst";
  rationale: string;
  analyst_notes: string;
  finding_id?: string;
  crown_jewel_count?: number;
  affects_crown_jewels?: boolean;
  crown_jewel_assets?: string[];
}

interface ValidationMethod {
  name: string;
  tests_run: number | string;
  confirmed: number | string;
  notes: string;
}

interface MobilisationOwner {
  team: string;
  open: number | string;
  closed_on_time: number | string;
  sla_breach: number | string;
  notes: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared: AI Brief editor
// ─────────────────────────────────────────────────────────────────────────────

function AIBriefEditor({
  clientId, programId, phase, brief, briefGeneratedAt, onRefresh,
}: {
  clientId: string; programId: string; phase: string;
  brief?: string; briefGeneratedAt?: string; onRefresh: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [localBrief, setLocalBrief] = useState(brief ?? "");
  const [generating, setGenerating] = useState(false);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const res = await ctemApi.generateAIBrief(clientId, programId, phase);
      setLocalBrief(res.brief ?? "");
      onRefresh();
      toast.success("AI brief generated");
    } catch {
      toast.error("AI generation failed — check AI Settings");
    } finally {
      setGenerating(false);
    }
  };

  const handleSave = async () => {
    try {
      await ctemApi.saveAIBrief(clientId, programId, phase, localBrief);
      onRefresh();
      setEditing(false);
      toast.success("Brief saved");
    } catch {
      toast.error("Save failed");
    }
  };

  const displayBrief = editing ? localBrief : (brief ?? localBrief);

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
        <AutoAwesome sx={{ fontSize: 15, color: "#FBBC04" }} />
        <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary" }}>
          AI ANALYSIS {briefGeneratedAt ? `· ${fmt(briefGeneratedAt)}` : ""}
        </Typography>
        <Box sx={{ ml: "auto", display: "flex", gap: 0.5 }}>
          <Button size="small" variant="outlined"
            startIcon={generating ? <CircularProgress size={11} /> : <AutoAwesome sx={{ fontSize: 13 }} />}
            onClick={handleGenerate} disabled={generating}
            sx={{ fontSize: 11, py: 0.3, px: 1 }}>
            {brief ? "Regenerate" : "Generate AI Brief"}
          </Button>
          {brief && !editing && (
            <Button size="small" variant="outlined" startIcon={<Edit sx={{ fontSize: 13 }} />}
              onClick={() => { setLocalBrief(brief ?? ""); setEditing(true); }}
              sx={{ fontSize: 11, py: 0.3, px: 1 }}>
              Edit
            </Button>
          )}
          {editing && (
            <Button size="small" variant="contained" startIcon={<Save sx={{ fontSize: 13 }} />}
              onClick={handleSave} sx={{ fontSize: 11, py: 0.3, px: 1 }}>
              Save
            </Button>
          )}
        </Box>
      </Box>
      {editing ? (
        <TextField
          multiline fullWidth minRows={6} size="small"
          value={localBrief} onChange={(e) => setLocalBrief(e.target.value)}
          sx={{ "& textarea": { fontSize: 12, fontFamily: "inherit" } }}
        />
      ) : displayBrief ? (
        <Paper variant="outlined" sx={{
          p: 1.5, bgcolor: "rgba(251,188,4,0.04)", borderColor: "rgba(251,188,4,0.2)",
          borderRadius: 1, maxHeight: 400, overflow: "auto",
          "& h1,& h2,& h3,& h4": { mt: 1, mb: 0.5, fontSize: "0.85rem", fontWeight: 700, color: "text.primary" },
          "& p": { fontSize: "0.75rem", my: 0.5, color: "text.secondary", lineHeight: 1.6 },
          "& ul,& ol": { pl: 2, my: 0.5 },
          "& li": { fontSize: "0.75rem", color: "text.secondary", mb: 0.25 },
          "& strong": { fontWeight: 700, color: "text.primary" },
          "& code": { fontSize: "0.7rem", bgcolor: "rgba(255,255,255,0.08)", px: 0.5, borderRadius: 0.5 },
        }}>
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{displayBrief}</ReactMarkdown>
        </Paper>
      ) : (
        <Typography variant="caption" sx={{ color: "text.secondary", fontStyle: "italic" }}>
          Click "Generate AI Brief" for an AI analysis grounded in your platform data.
        </Typography>
      )}
    </Box>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1: Scope
// ─────────────────────────────────────────────────────────────────────────────

function ScopePhaseContent({ clientId, programId }: { clientId: string; programId: string }) {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["ctem-scope-assets", clientId, programId],
    queryFn: () => ctemApi.getScopeAssets(clientId, programId),
    enabled: !!clientId && !!programId,
    retry: 1,
  });

  const [assets, setAssets] = useState<ScopeAsset[]>([]);
  const [initialized, setInitialized] = useState(false);
  const [saving, setSaving] = useState(false);

  React.useEffect(() => {
    if (data?.assets && !initialized) {
      setAssets(data.assets);
      setInitialized(true);
    }
  }, [data, initialized]);

  const updateAsset = (idx: number, field: keyof ScopeAsset, value: string) => {
    setAssets(prev => prev.map((a, i) => i === idx ? { ...a, [field]: value } : a));
  };

  const saveAssets = async () => {
    setSaving(true);
    try {
      await ctemApi.savePhaseData(clientId, programId, "scope", { assets });
      toast.success("Scope saved");
    } catch {
      toast.error("Save failed");
    } finally {
      setSaving(false);
    }
  };

  if (isLoading) return (
    <Box sx={{ py: 2 }}>
      <LinearProgress sx={{ borderRadius: 1 }} />
      <Typography variant="caption" sx={{ color: "text.secondary", mt: 1, display: "block" }}>
        Discovering assets from scan findings…
      </Typography>
    </Box>
  );
  if (isError) return (
    <Alert severity="error" action={<Button size="small" onClick={() => refetch()}>Retry</Button>} sx={{ mb: 1 }}>
      Failed to load assets — check that the backend is running and this program exists.
    </Alert>
  );

  const scopeCount = assets.filter(a => a.scope_status === "in_scope").length;
  const crownCount = assets.filter(a => a.scope_status === "crown_jewel").length;
  const outCount   = assets.filter(a => a.scope_status === "out_of_scope").length;

  return (
    <Box>
      <Box sx={{ display: "flex", gap: 2, mb: 2, flexWrap: "wrap" }}>
        <Chip label={`${scopeCount} In Scope`} size="small" sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontWeight: 700 }} />
        <Chip label={`${crownCount} Crown Jewel`} size="small" sx={{ bgcolor: "rgba(234,67,53,0.15)", color: "#EA4335", fontWeight: 700 }} />
        <Chip label={`${outCount} Out of Scope`} size="small" sx={{ bgcolor: "rgba(0,0,0,0.06)", color: "text.secondary", fontWeight: 700 }} />
        <Typography variant="caption" sx={{ color: "text.secondary", alignSelf: "center" }}>
          {assets.length} assets discovered from findings
        </Typography>
        <Button size="small" variant="contained" onClick={saveAssets} disabled={saving} sx={{ ml: "auto" }}>
          {saving ? "Saving…" : "Save Scope"}
        </Button>
      </Box>

      {assets.length === 0 ? (
        <Alert severity="info" action={<Button size="small" onClick={() => refetch()}>Refresh</Button>}>
          No assets found for this client yet. Run a scan first — assets are automatically discovered from scan findings.
        </Alert>
      ) : (
        <Box sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Resource</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Type / Category</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: 11, textAlign: "center" }}>Findings</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Scope Status</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Analyst Comment</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {assets.map((asset, idx) => {
                const statusColor = asset.scope_status === "crown_jewel" ? "#EA4335"
                  : asset.scope_status === "in_scope" ? "#4285F4"
                  : asset.scope_status === "out_of_scope" ? "#9E9E9E" : "text.secondary";
                return (
                  <TableRow key={`${asset.resource_id}-${idx}`} hover sx={{ opacity: asset.scope_status === "out_of_scope" ? 0.5 : 1 }}>
                    <TableCell sx={{ fontSize: 11, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      <Tooltip title={asset.resource_id}>
                        <Typography variant="caption" sx={{ fontFamily: "monospace" }}>{asset.resource_id}</Typography>
                      </Tooltip>
                    </TableCell>
                    <TableCell sx={{ fontSize: 11 }}>
                      <Box>
                        <Typography variant="caption" sx={{ display: "block" }}>{asset.resource_type}</Typography>
                        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>{asset.exposure_category}</Typography>
                      </Box>
                    </TableCell>
                    <TableCell sx={{ textAlign: "center" }}>
                      <Chip label={asset.finding_count} size="small"
                        sx={{ bgcolor: asset.finding_count > 5 ? "rgba(234,67,53,0.1)" : "rgba(0,0,0,0.05)", fontSize: 10, height: 18, color: asset.finding_count > 5 ? "#EA4335" : "text.primary" }} />
                    </TableCell>
                    <TableCell sx={{ minWidth: 150 }}>
                      <FormControl size="small" fullWidth>
                        <Select
                          value={asset.scope_status}
                          onChange={(e) => updateAsset(idx, "scope_status", e.target.value)}
                          sx={{ fontSize: 11, color: statusColor, "& .MuiSelect-select": { py: 0.5 } }}
                        >
                          {SCOPE_STATUSES.map(s => (
                            <MenuItem key={s.value} value={s.value} sx={{ fontSize: 11 }}>{s.label}</MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    </TableCell>
                    <TableCell sx={{ minWidth: 200 }}>
                      <TextField
                        size="small" fullWidth
                        placeholder="Add comment…"
                        value={asset.notes}
                        onChange={(e) => updateAsset(idx, "notes", e.target.value)}
                        sx={{ "& input": { fontSize: 11, py: 0.5 } }}
                      />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Box>
      )}
    </Box>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2: Discover
// ─────────────────────────────────────────────────────────────────────────────

function DiscoverPhaseContent({ clientId, programId, phaseData, onSave }: {
  clientId: string; programId: string;
  phaseData: Record<string, unknown>; onSave: (d: Record<string, unknown>) => void;
}) {
  const { data, isLoading } = useQuery({
    queryKey: ["ctem-discover", clientId, programId],
    queryFn: () => ctemApi.getDiscoverFindings(clientId, programId),
    enabled: !!clientId && !!programId,
  });

  const [summary, setSummary] = useState((phaseData?.summary as string) ?? "");
  const [saving, setSaving] = useState(false);

  const cats: Array<Record<string, unknown>> = (data?.exposure_categories as Array<Record<string, unknown>>) ?? [];
  const recent: Array<Record<string, unknown>> = (data?.recent_open_findings as Array<Record<string, unknown>>) ?? [];

  const handleSave = async () => {
    setSaving(true);
    const categories = cats.map(c => ({ ...c, notes: "" }));
    await onSave({ categories, summary });
    setSaving(false);
  };

  if (isLoading) return <CircularProgress size={20} sx={{ display: "block", my: 2 }} />;

  const isAllAssets = data?.all_assets_mode;
  return (
    <Box>
      {isAllAssets && (
        <Alert severity="info" sx={{ mb: 2, py: 0.5 }}>
          <Typography variant="caption">Showing all findings — tag assets as "In Scope" in the Scope phase to filter by scoped assets.</Typography>
        </Alert>
      )}
      {!isAllAssets && (
        <Alert severity="success" sx={{ mb: 2, py: 0.5 }}>
          <Typography variant="caption">Showing findings for {data?.scoped_asset_count} scoped assets ({data?.findings_total} total findings)</Typography>
        </Alert>
      )}

      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", display: "block", mb: 1 }}>
        EXPOSURE CATEGORIES
      </Typography>
      <Box sx={{ overflowX: "auto", mb: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Exposure Category</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11, textAlign: "center" }}>Total</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11, textAlign: "center", color: "#EA4335" }}>Critical</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11, textAlign: "center", color: "#FF6D00" }}>High</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11, textAlign: "center", color: "#FBBC04" }}>Medium</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11, textAlign: "center", color: "#34A853" }}>Low</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {cats.length === 0 && (
              <TableRow><TableCell colSpan={6} sx={{ textAlign: "center", color: "text.secondary", fontSize: 11 }}>No findings yet</TableCell></TableRow>
            )}
            {cats.map((c, i) => (
              <TableRow key={i} hover>
                <TableCell sx={{ fontSize: 11 }}>{c.category as string}</TableCell>
                <TableCell sx={{ textAlign: "center", fontSize: 11, fontWeight: 700 }}>{c.total as number}</TableCell>
                <TableCell sx={{ textAlign: "center", fontSize: 11, color: "#EA4335" }}>{(c.critical as number) || "—"}</TableCell>
                <TableCell sx={{ textAlign: "center", fontSize: 11, color: "#FF6D00" }}>{(c.high as number) || "—"}</TableCell>
                <TableCell sx={{ textAlign: "center", fontSize: 11, color: "#FBBC04" }}>{(c.medium as number) || "—"}</TableCell>
                <TableCell sx={{ textAlign: "center", fontSize: 11, color: "#34A853" }}>{(c.low as number) || "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Box>

      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", display: "block", mb: 1 }}>
        RECENT OPEN FINDINGS (SCOPED ASSETS)
      </Typography>
      <Box sx={{ overflowX: "auto", mb: 2 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Finding</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Severity</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Category</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Resource</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>CVSS</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {recent.slice(0, 10).map((f, i) => (
              <TableRow key={i} hover>
                <TableCell sx={{ fontSize: 11, maxWidth: 200 }}>{f.title as string}</TableCell>
                <TableCell>
                  <Chip label={f.severity as string} size="small"
                    sx={{ bgcolor: `${SEV_COLORS[f.severity as string] || "#888"}22`, color: SEV_COLORS[f.severity as string], fontSize: 10, height: 18, fontWeight: 700 }} />
                </TableCell>
                <TableCell sx={{ fontSize: 10, color: "text.secondary" }}>{f.exposure_category as string}</TableCell>
                <TableCell sx={{ fontSize: 10, fontFamily: "monospace", maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.resource_id as string}</TableCell>
                <TableCell sx={{ fontSize: 11 }}>{f.cvss ? String(f.cvss) : "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Box>

      <TextField fullWidth multiline minRows={2} size="small" label="Discovery summary notes"
        value={summary} onChange={(e) => setSummary(e.target.value)} sx={{ mb: 1 }} />
      <Button size="small" variant="outlined" onClick={handleSave} disabled={saving}>Save Notes</Button>
    </Box>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3: Prioritise
// ─────────────────────────────────────────────────────────────────────────────

function PrioritisePhaseContent({ clientId, programId, phaseData, onSave }: {
  clientId: string; programId: string;
  phaseData: Record<string, unknown>; onSave: (d: Record<string, unknown>) => void;
}) {
  const [items, setItems] = useState<PriorityItem[]>((phaseData?.items as PriorityItem[]) ?? []);
  const [generating, setGenerating] = useState(false);
  const [saving, setSaving] = useState(false);

  const generateAI = async () => {
    setGenerating(true);
    try {
      const res = await ctemApi.generatePriorities(clientId, programId);
      setItems(res.items ?? []);
      toast.success("AI priorities generated — review and adjust as needed");
    } catch {
      toast.error("AI generation failed");
    } finally {
      setGenerating(false);
    }
  };

  const addItem = () => {
    setItems(prev => [...prev, { rank: prev.length + 1, title: "", severity: "medium", source: "analyst", rationale: "", analyst_notes: "" }]);
  };

  const removeItem = (idx: number) => {
    setItems(prev => prev.filter((_, i) => i !== idx).map((it, i) => ({ ...it, rank: i + 1 })));
  };

  const moveItem = (idx: number, dir: -1 | 1) => {
    const newItems = [...items];
    const target = idx + dir;
    if (target < 0 || target >= newItems.length) return;
    [newItems[idx], newItems[target]] = [newItems[target], newItems[idx]];
    setItems(newItems.map((it, i) => ({ ...it, rank: i + 1 })));
  };

  const updateItem = (idx: number, field: keyof PriorityItem, value: string) => {
    setItems(prev => prev.map((it, i) => i === idx ? { ...it, [field]: value } : it));
  };

  const handleSave = async () => {
    setSaving(true);
    await onSave({ items });
    setSaving(false);
  };

  return (
    <Box>
      <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
        <Button size="small" variant="outlined"
          startIcon={generating ? <CircularProgress size={12} /> : <AutoAwesome sx={{ fontSize: 14 }} />}
          onClick={generateAI} disabled={generating}>
          Generate AI Top 5
        </Button>
        <Button size="small" variant="outlined" startIcon={<Add />} onClick={addItem}>Add Item</Button>
        <Button size="small" variant="contained" onClick={handleSave} disabled={saving} sx={{ ml: "auto" }}>
          {saving ? "Saving…" : "Save Priorities"}
        </Button>
      </Box>

      {items.length === 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <Typography variant="caption">Click "Generate AI Top 5" to have AI rank the most critical exposures, then add or adjust items as needed.</Typography>
        </Alert>
      )}

      {items.map((item, idx) => (
        <Paper key={idx} variant="outlined" sx={{ p: 1.5, mb: 1, position: "relative" }}>
          <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
            <Box sx={{ display: "flex", flexDirection: "column", gap: 0.3, flexShrink: 0 }}>
              <IconButton size="small" onClick={() => moveItem(idx, -1)} disabled={idx === 0} sx={{ p: 0.3 }}>
                <ArrowUpward sx={{ fontSize: 14 }} />
              </IconButton>
              <Typography variant="caption" sx={{ textAlign: "center", fontWeight: 800, color: "primary.main" }}>#{item.rank}</Typography>
              <IconButton size="small" onClick={() => moveItem(idx, 1)} disabled={idx === items.length - 1} sx={{ p: 0.3 }}>
                <ArrowDownward sx={{ fontSize: 14 }} />
              </IconButton>
            </Box>
            <Box sx={{ flex: 1 }}>
              <Grid container spacing={1}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField fullWidth size="small" label="Title" value={item.title}
                    onChange={(e) => updateItem(idx, "title", e.target.value)}
                    sx={{ "& input": { fontSize: 12 } }} />
                </Grid>
                <Grid size={{ xs: 6, md: 3 }}>
                  <FormControl fullWidth size="small">
                    <InputLabel sx={{ fontSize: 12 }}>Severity</InputLabel>
                    <Select value={item.severity} label="Severity"
                      onChange={(e) => updateItem(idx, "severity", e.target.value)}
                      sx={{ fontSize: 12, color: SEV_COLORS[item.severity] }}>
                      {["critical","high","medium","low"].map(s => (
                        <MenuItem key={s} value={s} sx={{ fontSize: 12, color: SEV_COLORS[s] }}>{s}</MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                <Grid size={{ xs: 6, md: 3 }}>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                    <Chip
                      label={item.source === "ai" ? "AI Suggested" : "Analyst Added"}
                      size="small"
                      sx={{
                        bgcolor: item.source === "ai" ? "rgba(251,188,4,0.15)" : "rgba(52,168,83,0.15)",
                        color: item.source === "ai" ? "#FBBC04" : "#34A853",
                        fontSize: 10, height: 22,
                      }}
                    />
                    {item.affects_crown_jewels && (
                      <Tooltip title={`Affects crown jewel asset${(item.crown_jewel_count ?? 0) > 1 ? "s" : ""}: ${(item.crown_jewel_assets ?? []).join(", ")}`}>
                        <Chip
                          label={`👑 ${item.crown_jewel_count ?? 1} Crown Jewel`}
                          size="small"
                          sx={{ bgcolor: "rgba(234,67,53,0.18)", color: "#EA4335", fontSize: 10, height: 22, fontWeight: 700 }}
                        />
                      </Tooltip>
                    )}
                  </Box>
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <TextField fullWidth size="small" label="Rationale" value={item.rationale}
                    onChange={(e) => updateItem(idx, "rationale", e.target.value)}
                    sx={{ "& input": { fontSize: 11 } }} />
                </Grid>
                <Grid size={{ xs: 12 }}>
                  <TextField fullWidth size="small" label="Analyst Notes" value={item.analyst_notes}
                    onChange={(e) => updateItem(idx, "analyst_notes", e.target.value)}
                    sx={{ "& input": { fontSize: 11 } }} />
                </Grid>
              </Grid>
            </Box>
            <IconButton size="small" color="error" onClick={() => removeItem(idx)} sx={{ flexShrink: 0, mt: 0.5 }}>
              <Delete fontSize="small" />
            </IconButton>
          </Box>
        </Paper>
      ))}
    </Box>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4: Validate
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_VALIDATION_METHODS: ValidationMethod[] = [
  { name: "Automated BAS (attack simulation)", tests_run: "", confirmed: "", notes: "" },
  { name: "Manual attack-path validation (red/purple team)", tests_run: "", confirmed: "", notes: "" },
  { name: "Control-efficacy check (detection review)", tests_run: "", confirmed: "", notes: "" },
];

function ValidatePhaseContent({ clientId, programId, phaseData, onSave }: {
  clientId: string; programId: string;
  phaseData: Record<string, unknown>; onSave: (d: Record<string, unknown>) => void;
}) {
  const [methods, setMethods] = useState<ValidationMethod[]>(
    (phaseData?.methods as ValidationMethod[])?.length
      ? (phaseData.methods as ValidationMethod[])
      : DEFAULT_VALIDATION_METHODS
  );
  const [notableFindings, setNotableFindings] = useState((phaseData?.notable_findings as string) ?? "");
  const [summary, setSummary] = useState((phaseData?.summary as string) ?? "");
  const [saving, setSaving] = useState(false);

  const updateMethod = (idx: number, field: keyof ValidationMethod, value: string) => {
    setMethods(prev => prev.map((m, i) => i === idx ? { ...m, [field]: value } : m));
  };

  const addMethod = () => setMethods(prev => [...prev, { name: "", tests_run: "", confirmed: "", notes: "" }]);
  const removeMethod = (idx: number) => setMethods(prev => prev.filter((_, i) => i !== idx));

  const handleSave = async () => {
    setSaving(true);
    await onSave({ methods, notable_findings: notableFindings, summary });
    setSaving(false);
  };

  const totalTests = methods.reduce((s, m) => s + (Number(m.tests_run) || 0), 0);
  const totalConfirmed = methods.reduce((s, m) => s + (Number(m.confirmed) || 0), 0);

  return (
    <Box>
      <Box sx={{ display: "flex", gap: 2, mb: 2, flexWrap: "wrap" }}>
        <Chip label={`${totalTests} Tests Run`} size="small" sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontWeight: 700 }} />
        <Chip label={`${totalConfirmed} Confirmed Exploitable`} size="small" sx={{ bgcolor: "rgba(234,67,53,0.15)", color: "#EA4335", fontWeight: 700 }} />
        {totalTests > 0 && (
          <Chip label={`${Math.round(totalConfirmed/totalTests*100)}% confirmation rate`} size="small" variant="outlined" />
        )}
      </Box>

      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", display: "block", mb: 1 }}>
        VALIDATION METHODS
      </Typography>
      <Box sx={{ overflowX: "auto", mb: 2 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Validation Method</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11, textAlign: "center" }}>Tests Run</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11, textAlign: "center" }}>Confirmed Exploitable</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Notes</TableCell>
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {methods.map((m, idx) => (
              <TableRow key={idx}>
                <TableCell sx={{ minWidth: 220 }}>
                  <TextField fullWidth size="small" value={m.name}
                    onChange={(e) => updateMethod(idx, "name", e.target.value)}
                    sx={{ "& input": { fontSize: 11 } }} />
                </TableCell>
                <TableCell sx={{ width: 100 }}>
                  <TextField size="small" type="number" value={m.tests_run}
                    onChange={(e) => updateMethod(idx, "tests_run", e.target.value)}
                    sx={{ "& input": { fontSize: 11, textAlign: "center" } }} />
                </TableCell>
                <TableCell sx={{ width: 130 }}>
                  <TextField size="small" type="number" value={m.confirmed}
                    onChange={(e) => updateMethod(idx, "confirmed", e.target.value)}
                    sx={{ "& input": { fontSize: 11, textAlign: "center" } }} />
                </TableCell>
                <TableCell>
                  <TextField fullWidth size="small" value={m.notes}
                    onChange={(e) => updateMethod(idx, "notes", e.target.value)}
                    sx={{ "& input": { fontSize: 11 } }} />
                </TableCell>
                <TableCell sx={{ width: 36 }}>
                  <IconButton size="small" color="error" onClick={() => removeMethod(idx)}>
                    <Delete sx={{ fontSize: 14 }} />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Box>
      <Button size="small" startIcon={<Add />} onClick={addMethod} sx={{ mb: 2 }}>Add Method</Button>

      <TextField fullWidth multiline minRows={4} size="small"
        label="Notable Findings (one per line — e.g. lateral movement confirmed, phishing blocked)"
        placeholder="• Simulated lateral movement from DMZ reached identity provider admin console in 3 hops — no SIEM alert&#10;• Exfiltration via misconfigured storage bucket validated as exploitable&#10;• Phishing-to-credential-reuse blocked by conditional access — control confirmed effective"
        value={notableFindings} onChange={(e) => setNotableFindings(e.target.value)}
        sx={{ mb: 1 }} />

      <TextField fullWidth multiline minRows={2} size="small" label="Validation summary"
        value={summary} onChange={(e) => setSummary(e.target.value)} sx={{ mb: 1 }} />

      <Button size="small" variant="contained" onClick={handleSave} disabled={saving}>
        {saving ? "Saving…" : "Save"}
      </Button>
    </Box>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 5: Mobilise
// ─────────────────────────────────────────────────────────────────────────────

function MobilisePhaseContent({ clientId, programId, phaseData, onSave }: {
  clientId: string; programId: string;
  phaseData: Record<string, unknown>; onSave: (d: Record<string, unknown>) => void;
}) {
  const [owners, setOwners] = useState<MobilisationOwner[]>(
    (phaseData?.owners as MobilisationOwner[]) ?? []
  );
  const [blockers, setBlockers] = useState<string[]>(
    Array.isArray(phaseData?.blockers) ? (phaseData.blockers as string[]) : [""]
  );
  const [saving, setSaving] = useState(false);

  const updateOwner = (idx: number, field: keyof MobilisationOwner, value: string) => {
    setOwners(prev => prev.map((o, i) => i === idx ? { ...o, [field]: value } : o));
  };
  const addOwner = () => setOwners(prev => [...prev, { team: "", open: "", closed_on_time: "", sla_breach: "", notes: "" }]);
  const removeOwner = (idx: number) => setOwners(prev => prev.filter((_, i) => i !== idx));

  const updateBlocker = (idx: number, val: string) => setBlockers(prev => prev.map((b, i) => i === idx ? val : b));
  const addBlocker = () => setBlockers(prev => [...prev, ""]);
  const removeBlocker = (idx: number) => setBlockers(prev => prev.filter((_, i) => i !== idx));

  const handleSave = async () => {
    setSaving(true);
    await onSave({ owners, blockers: blockers.filter(b => b.trim()) });
    setSaving(false);
  };

  const totalBreach = owners.reduce((s, o) => s + (Number(o.sla_breach) || 0), 0);

  return (
    <Box>
      {totalBreach > 0 && (
        <Alert severity="error" sx={{ mb: 2, py: 0.5 }}>
          <Typography variant="caption">{totalBreach} SLA breaches across owner teams — immediate action required</Typography>
        </Alert>
      )}

      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", display: "block", mb: 1 }}>
        OWNER TEAMS
      </Typography>
      <Box sx={{ overflowX: "auto", mb: 2 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Owner Team</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11, textAlign: "center" }}>Open</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11, textAlign: "center" }}>Closed On-Time</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11, textAlign: "center", color: "#EA4335" }}>SLA Breach</TableCell>
              <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Notes</TableCell>
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {owners.length === 0 && (
              <TableRow><TableCell colSpan={6} sx={{ textAlign: "center", color: "text.secondary", fontSize: 11 }}>No teams added yet</TableCell></TableRow>
            )}
            {owners.map((o, idx) => (
              <TableRow key={idx} hover>
                <TableCell sx={{ minWidth: 180 }}>
                  <TextField fullWidth size="small" placeholder="e.g. Cloud Platform Team" value={o.team}
                    onChange={(e) => updateOwner(idx, "team", e.target.value)}
                    sx={{ "& input": { fontSize: 11 } }} />
                </TableCell>
                <TableCell sx={{ width: 70 }}>
                  <TextField size="small" type="number" value={o.open}
                    onChange={(e) => updateOwner(idx, "open", e.target.value)}
                    sx={{ "& input": { fontSize: 11, textAlign: "center" } }} />
                </TableCell>
                <TableCell sx={{ width: 100 }}>
                  <TextField size="small" type="number" value={o.closed_on_time}
                    onChange={(e) => updateOwner(idx, "closed_on_time", e.target.value)}
                    sx={{ "& input": { fontSize: 11, textAlign: "center" } }} />
                </TableCell>
                <TableCell sx={{ width: 90 }}>
                  <TextField size="small" type="number" value={o.sla_breach}
                    onChange={(e) => updateOwner(idx, "sla_breach", e.target.value)}
                    sx={{ "& input": { fontSize: 11, textAlign: "center", color: Number(o.sla_breach) > 0 ? "#EA4335" : "inherit" } }} />
                </TableCell>
                <TableCell>
                  <TextField fullWidth size="small" value={o.notes}
                    onChange={(e) => updateOwner(idx, "notes", e.target.value)}
                    sx={{ "& input": { fontSize: 11 } }} />
                </TableCell>
                <TableCell sx={{ width: 36 }}>
                  <IconButton size="small" color="error" onClick={() => removeOwner(idx)}>
                    <Delete sx={{ fontSize: 14 }} />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Box>
      <Button size="small" startIcon={<Add />} onClick={addOwner} sx={{ mb: 2 }}>Add Team</Button>

      <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", display: "block", mb: 1 }}>
        BLOCKERS
      </Typography>
      {blockers.map((b, idx) => (
        <Box key={idx} sx={{ display: "flex", gap: 1, mb: 0.5 }}>
          <TextField fullWidth size="small" placeholder={`Blocker ${idx + 1} — e.g. OT change freeze delayed 3 critical patches`}
            value={b} onChange={(e) => updateBlocker(idx, e.target.value)}
            sx={{ "& input": { fontSize: 11 } }} />
          <IconButton size="small" color="error" onClick={() => removeBlocker(idx)}>
            <Delete sx={{ fontSize: 14 }} />
          </IconButton>
        </Box>
      ))}
      <Button size="small" startIcon={<Add />} onClick={addBlocker} sx={{ mb: 2 }}>Add Blocker</Button>

      <Button size="small" variant="contained" onClick={handleSave} disabled={saving}>
        {saving ? "Saving…" : "Save"}
      </Button>
    </Box>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase accordion wrapper
// ─────────────────────────────────────────────────────────────────────────────

function PhaseAccordion({
  ph, phaseNote, programId, clientId, isCurrentPhase, isLocked, onRefresh,
}: {
  ph: typeof PHASES[0];
  phaseNote: PhaseNote;
  programId: string; clientId: string;
  isCurrentPhase: boolean; isLocked: boolean;
  onRefresh: () => void;
}) {
  const qc = useQueryClient();
  const isGuest = useIsGuest();
  const [expanded, setExpanded] = useState(isCurrentPhase);
  const [notes, setNotes] = useState(phaseNote.notes ?? "");
  const done = phaseNote.completed ?? false;
  const pd = (phaseNote.phase_data_json as Record<string, unknown>) ?? {};

  const updateMut = useMutation({
    mutationFn: (args: { n?: string; completed?: boolean }) =>
      ctemApi.updatePhase(clientId, programId, ph.key, args.n, args.completed),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["ctem", clientId] }); toast.success("Phase updated"); },
    onError: () => toast.error("Update failed"),
  });

  const savePhaseData = useCallback(async (data: Record<string, unknown>) => {
    await ctemApi.savePhaseData(clientId, programId, ph.key, data);
    qc.invalidateQueries({ queryKey: ["ctem", clientId] });
    toast.success("Saved");
  }, [clientId, programId, ph.key, qc]);

  if (isLocked) {
    return (
      <Box sx={{
        display: "flex", alignItems: "center", gap: 1.5, px: 2, py: 1.5,
        mb: 1, border: "1px solid", borderColor: "divider", borderRadius: 1,
        opacity: 0.4, cursor: "not-allowed",
      }}>
        <Lock fontSize="small" sx={{ color: "text.disabled" }} />
        <Typography variant="body2" sx={{ fontWeight: 600, color: "text.disabled" }}>{ph.label}</Typography>
        <Typography variant="caption" sx={{ color: "text.disabled", ml: 1 }}>
          Complete the previous phase to unlock
        </Typography>
      </Box>
    );
  }

  return (
    <Accordion expanded={expanded} onChange={(_, v) => setExpanded(v)} variant="outlined"
      sx={{ mb: 1, "&:before": { display: "none" }, borderColor: done ? "rgba(52,168,83,0.3)" : isCurrentPhase ? `${ph.color}44` : "divider" }}>
      <AccordionSummary expandIcon={<ExpandMore />} sx={{ minHeight: 52 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, flex: 1 }}>
          <Box sx={{ color: done ? "#34A853" : ph.color }}>
            {done ? <CheckCircle fontSize="small" /> : <RadioButtonUnchecked fontSize="small" />}
          </Box>
          <Typography variant="body2" sx={{ fontWeight: 700 }}>{ph.label}</Typography>
          {done && <Chip label="Complete" size="small" sx={{ bgcolor: "rgba(52,168,83,0.15)", color: "#34A853", fontSize: 10, height: 18 }} />}
          {isCurrentPhase && !done && <Chip label="Active" size="small" sx={{ bgcolor: `${ph.color}22`, color: ph.color, fontSize: 10, height: 18 }} />}
          {phaseNote.ai_brief && (
            <Chip icon={<AutoAwesome sx={{ fontSize: 11 }} />} label="AI brief" size="small"
              sx={{ bgcolor: "rgba(251,188,4,0.1)", color: "#FBBC04", fontSize: 10, height: 18, ml: "auto", mr: 1 }} />
          )}
        </Box>
      </AccordionSummary>

      <AccordionDetails sx={{ pt: 0 }}>
        {/* Phase-specific content */}
        {ph.key === "scope" && <ScopePhaseContent clientId={clientId} programId={programId} />}
        {ph.key === "discover" && <DiscoverPhaseContent clientId={clientId} programId={programId} phaseData={pd} onSave={savePhaseData} />}
        {ph.key === "prioritise" && <PrioritisePhaseContent clientId={clientId} programId={programId} phaseData={pd} onSave={savePhaseData} />}
        {ph.key === "validate" && <ValidatePhaseContent clientId={clientId} programId={programId} phaseData={pd} onSave={savePhaseData} />}
        {ph.key === "mobilise" && <MobilisePhaseContent clientId={clientId} programId={programId} phaseData={pd} onSave={savePhaseData} />}

        <Divider sx={{ my: 2 }} />

        {/* AI Brief (editable) */}
        <AIBriefEditor
          clientId={clientId} programId={programId} phase={ph.key}
          brief={phaseNote.ai_brief} briefGeneratedAt={phaseNote.ai_brief_generated_at}
          onRefresh={onRefresh}
        />

        <Divider sx={{ my: 2 }} />

        {/* Analyst notes */}
        <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", display: "block", mb: 0.5 }}>
          ADDITIONAL ANALYST NOTES
        </Typography>
        <TextField multiline minRows={2} maxRows={5} fullWidth size="small"
          label="Free-form notes, decisions, or audit trail entries"
          value={notes} onChange={(e) => setNotes(e.target.value)} sx={{ mb: 1 }} />

        {done && phaseNote.completed_by && (
          <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>
            Completed by {phaseNote.completed_by}{phaseNote.completed_at ? ` on ${fmt(phaseNote.completed_at)}` : ""}
          </Typography>
        )}

        {!isGuest && (
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Button size="small" variant="outlined"
              onClick={() => updateMut.mutate({ n: notes })} disabled={updateMut.isPending}>
              Save Notes
            </Button>
            {!done && (
              <Button size="small" variant="contained"
                sx={{ bgcolor: ph.color, "&:hover": { filter: "brightness(0.85)" } }}
                onClick={() => updateMut.mutate({ n: notes, completed: true })} disabled={updateMut.isPending}>
                Mark Phase Complete
              </Button>
            )}
            {done && (
              <Button size="small" variant="outlined" color="warning"
                onClick={() => updateMut.mutate({ n: phaseNote.notes ?? "", completed: false })} disabled={updateMut.isPending}>
                Reopen Phase
              </Button>
            )}
          </Box>
        )}
      </AccordionDetails>
    </Accordion>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress indicator
// ─────────────────────────────────────────────────────────────────────────────

function ProgressBar({ phases, currentPhase }: { phases: Record<string, PhaseNote>; currentPhase: string }) {
  const completedCount = PHASES.filter(p => phases[p.key]?.completed).length;
  const pct = Math.round((completedCount / PHASES.length) * 100);
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 2, minWidth: 180 }}>
      <Box sx={{ flex: 1 }}>
        <LinearProgress variant="determinate" value={pct} sx={{ height: 6, borderRadius: 3 }} />
      </Box>
      <Typography variant="caption" sx={{ fontWeight: 700, color: "primary.main", whiteSpace: "nowrap" }}>
        {completedCount}/{PHASES.length} phases
      </Typography>
    </Box>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Program card
// ─────────────────────────────────────────────────────────────────────────────

function ProgramCard({ program, clientId, onDelete }: { program: CTEMProgram; clientId: string; onDelete: () => void }) {
  const qc = useQueryClient();
  const isGuest = useIsGuest();
  const [expanded, setExpanded] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const phaseMap: Record<string, PhaseNote> = {};
  (program.phases ?? []).forEach(pn => { phaseMap[pn.phase] = pn; });

  const currentPhase = program.current_phase || "scope";
  const currentPhaseIdx = PHASES.findIndex(p => p.key === currentPhase);
  const onRefresh = () => qc.invalidateQueries({ queryKey: ["ctem", clientId] });

  const downloadReport = (format: "pdf" | "docx") => {
    const token = localStorage.getItem("owlet-token") || "";
    const url = ctemApi.exportUrl(clientId, program.id, format);
    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.blob())
      .then(blob => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `CTEM-${program.name}.${format}`;
        a.click();
      })
      .catch(() => toast.error("Export failed"));
  };

  return (
    <Card variant="outlined" sx={{ mb: 2 }}>
      <CardContent sx={{ pb: "12px !important" }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 1 }}>
          <Box sx={{ flex: 1, cursor: "pointer" }} onClick={() => setExpanded(v => !v)}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{program.name}</Typography>
            {program.description && (
              <Typography variant="caption" sx={{ color: "text.secondary" }}>{program.description}</Typography>
            )}
            <Box sx={{ display: "flex", gap: 1, mt: 0.5, flexWrap: "wrap", alignItems: "center" }}>
              <Chip
                label={program.status === "completed" ? "Complete" : "In Progress"}
                size="small"
                sx={{ bgcolor: program.status === "completed" ? "rgba(52,168,83,0.15)" : "rgba(66,133,244,0.15)", color: program.status === "completed" ? "#34A853" : "#4285F4", fontSize: 10, height: 18 }}
              />
              <Chip label={`Active: ${PHASES[currentPhaseIdx]?.label ?? currentPhase}`} size="small" variant="outlined" sx={{ fontSize: 10, height: 18 }} />
              {program.connector_ids && program.connector_ids.length > 0 && (
                <Chip
                  label={`${program.connector_ids.length} connector${program.connector_ids.length > 1 ? "s" : ""} scoped`}
                  size="small"
                  sx={{ bgcolor: "rgba(251,188,4,0.15)", color: "#B8860B", fontSize: 10, height: 18 }}
                />
              )}
              {program.created_at && <Typography variant="caption" sx={{ color: "text.secondary" }}>{fmt(program.created_at)}</Typography>}
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 0.5, alignItems: "center", flexShrink: 0 }}>
            {!expanded && <ProgressBar phases={phaseMap} currentPhase={currentPhase} />}
            <Button size="small" onClick={() => setExpanded(v => !v)}>{expanded ? "Collapse" : "Open"}</Button>
            <Tooltip title="Download PDF">
              <IconButton size="small" onClick={() => downloadReport("pdf")}><FileDownload fontSize="small" /></IconButton>
            </Tooltip>
            <Tooltip title="Download DOCX">
              <IconButton size="small" onClick={() => downloadReport("docx")} sx={{ fontSize: 11 }}>W</IconButton>
            </Tooltip>
            {!isGuest && (
              <Tooltip title="Delete program">
                <IconButton size="small" color="error" onClick={() => setConfirmDelete(true)}><Delete fontSize="small" /></IconButton>
              </Tooltip>
            )}
          </Box>
        </Box>

        {expanded && (
          <>
            <Divider sx={{ my: 2 }} />
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
              <ProgressBar phases={phaseMap} currentPhase={currentPhase} />
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                Future phases unlock when current phase is marked complete
              </Typography>
            </Box>
            {PHASES.map((ph, idx) => (
              <PhaseAccordion
                key={ph.key} ph={ph}
                phaseNote={phaseMap[ph.key] ?? { phase: ph.key }}
                programId={program.id} clientId={clientId}
                isCurrentPhase={idx === currentPhaseIdx}
                isLocked={idx > currentPhaseIdx && !phaseMap[ph.key]?.completed}
                onRefresh={onRefresh}
              />
            ))}
          </>
        )}
      </CardContent>

      <Dialog open={confirmDelete} onClose={() => setConfirmDelete(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Delete Program?</DialogTitle>
        <DialogContent>
          <Typography>Delete <strong>{program.name}</strong>? This cannot be undone.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmDelete(false)}>Cancel</Button>
          <Button color="error" variant="contained" onClick={() => { setConfirmDelete(false); onDelete(); }}>Delete</Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export default function CTEMPage() {
  const qc = useQueryClient();
  const { clientId } = useActiveClient();
  const isGuest = useIsGuest();
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newConnectorIds, setNewConnectorIds] = useState<string[]>([]);

  const { data: programs = [], isLoading } = useQuery<CTEMProgram[]>({
    queryKey: ["ctem", clientId],
    queryFn: () => ctemApi.list(clientId),
    enabled: !!clientId,
  });

  const { data: connectors = [] } = useQuery<{ id: string; name: string; connector_type: string }[]>({
    queryKey: ["connectors", clientId],
    queryFn: () => connectorsApi.list(clientId),
    enabled: !!clientId && createOpen,
  });

  const createMut = useMutation({
    mutationFn: () => ctemApi.create(clientId, {
      name: newName.trim(),
      description: newDesc.trim() || undefined,
      connector_ids: newConnectorIds,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ctem", clientId] });
      setCreateOpen(false); setNewName(""); setNewDesc(""); setNewConnectorIds([]);
      toast.success("CTEM program created");
    },
    onError: () => toast.error("Create failed"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => ctemApi.delete(clientId, id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["ctem", clientId] }); toast.success("Deleted"); },
    onError: () => toast.error("Delete failed"),
  });

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Continuous Threat Exposure Management</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            AI-assisted 5-phase program — scope assets, discover exposures, prioritise risk, validate exploitability, mobilise remediation
          </Typography>
        </Box>
        {!isGuest && (
          <Button variant="contained" startIcon={<Add />} onClick={() => setCreateOpen(true)} disabled={!clientId}>
            New Program
          </Button>
        )}
      </Box>

      {!clientId && <Alert severity="info">Select a client to manage CTEM programs.</Alert>}
      {clientId && isLoading && <CircularProgress size={24} />}

      {clientId && !isLoading && programs.length === 0 && (
        <Box sx={{ textAlign: "center", py: 8, px: 4 }}>
          <AccountTree sx={{ fontSize: 56, color: "text.disabled", mb: 2 }} />
          <Typography variant="h6" sx={{ color: "text.secondary", fontWeight: 700, mb: 1 }}>
            No CTEM programs yet
          </Typography>
          <Typography variant="body2" sx={{ color: "text.secondary", maxWidth: 400, mx: "auto", mb: 3 }}>
            Create a program to track your Continuous Threat Exposure Management lifecycle: Scope → Discover → Prioritise → Validate → Mobilise.
          </Typography>
          {!isGuest && (
            <Button variant="contained" startIcon={<Add />} onClick={() => setCreateOpen(true)}>
              Create Program
            </Button>
          )}
        </Box>
      )}

      {clientId && !isLoading && programs.map(p => (
        <ProgramCard key={p.id} program={p} clientId={clientId} onDelete={() => deleteMut.mutate(p.id)} />
      ))}

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>New CTEM Program</DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <TextField label="Program Name" fullWidth size="small" required
                value={newName} onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g. Q3 Cloud Exposure Reduction" />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField label="Description (optional)" fullWidth size="small" multiline minRows={2}
                value={newDesc} onChange={(e) => setNewDesc(e.target.value)}
                placeholder="Brief objective or scope statement" />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <FormControl fullWidth size="small">
                <InputLabel>Scope by Connector(s)</InputLabel>
                <Select
                  multiple
                  value={newConnectorIds}
                  onChange={(e) => setNewConnectorIds(e.target.value as string[])}
                  input={<OutlinedInput label="Scope by Connector(s)" />}
                  renderValue={(selected) => (
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {(selected as string[]).map((id) => {
                        const c = connectors.find(x => x.id === id);
                        return <Chip key={id} label={c?.name || id} size="small" />;
                      })}
                    </Box>
                  )}
                >
                  {connectors.map((c) => (
                    <MenuItem key={c.id} value={c.id}>
                      <Checkbox checked={newConnectorIds.includes(c.id)} />
                      <ListItemText primary={c.name} secondary={c.connector_type} />
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <Typography variant="caption" sx={{ color: "text.secondary", mt: 0.5, display: "block" }}>
                Leave empty to include all connectors. Selecting connectors deduplicates assets automatically.
              </Typography>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={!newName.trim() || createMut.isPending} onClick={() => createMut.mutate()}>
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
