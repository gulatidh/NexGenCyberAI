/**
 * Threat Models — list of generated models per client + create dialog.
 *
 * Threat models are generated on demand via the Threat Modeler buddy. The
 * create dialog asks for: client, methodology (STRIDE / PASTA / LINDDUN /
 * MITRE ATT&CK / Kill Chain), framework (optional), scope (client-wide for
 * now in Phase 1 — project / asset narrower scopes come in Phase 2).
 *
 * Each list row links to the detail page where the diagram + STRIDE/per-
 * methodology threat table live.
 */
import React, { useState } from "react";
import { useViewMode } from "../theme/ViewModeContext";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, CardContent, Button, Chip, Grid, IconButton,
  Tooltip, FormControl, InputLabel, Select, MenuItem, Dialog, DialogTitle,
  DialogContent, DialogActions, TextField, CircularProgress, Alert,
  LinearProgress, Checkbox, ListItemText, Switch, FormControlLabel,
} from "@mui/material";
import { Add, Hub, Replay, DeleteOutlined, UploadFile } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useLocation } from "react-router-dom";
import { toast } from "react-toastify";
import { threatModelsApi, scansApi } from "../services/api";
import { Scan } from "../types";
import { fromNow } from "../utils/datetime";

interface ThreatModelSummary {
  id: string;
  client_id: string;
  name?: string | null;
  scope_type: string;
  scope_id?: string | null;
  scope_scan_ids?: string[] | null;
  framework?: string | null;
  methodology: string;
  status: string;
  component_count: number;
  threat_count: number;
  mitigation_count: number;
  created_at?: string | null;
  generated_at?: string | null;
  parent_threat_model_id?: string | null;
  error_message?: string | null;
}

interface Methodology {
  id: string;
  label: string;
  description: string;
  categories: string[];
}

const STATUS_COLOR: Record<string, string> = {
  pending: "#FBBC04",
  generating: "#4285F4",
  completed: "#34A853",
  failed: "#EA4335",
  extracted_review: "#9C27B0",
};

const ACCEPTED_UPLOAD = ".drawio,.xml,.pdf,.jpg,.jpeg,.png";

export default function ThreatModels() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const tmBase = location.pathname.startsWith("/threat-intel") ? "/threat-intel/threat-models" : "/threat-models";
  const { canAct } = useViewMode();
  const { clientId: selectedClientId } = useActiveClient();
  const [openCreate, setOpenCreate] = useState(false);
  const [openUpload, setOpenUpload] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<ThreatModelSummary | null>(null);

  // ── Create-dialog form state
  const [tmName, setTmName] = useState("");
  const [methodology, setMethodology] = useState<string>("stride");
  const [cloudProvider, setCloudProvider] = useState<string>("generic");
  const [scanIds, setScanIds] = useState<string[]>([]);
  const [dataFlowDesc, setDataFlowDesc] = useState("");
  const [notes, setNotes] = useState("");
  const [autoRemodel, setAutoRemodel] = useState(false);

  // ── Upload-dialog form state
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadName, setUploadName] = useState("");
  const [uploadMethodology, setUploadMethodology] = useState<string>("stride");

  const { data: methodologiesResp } = useQuery<{ methodologies: Methodology[]; default: string }>({
    queryKey: ["tm-methodologies"], queryFn: threatModelsApi.methodologies,
  });
  const methodologies = methodologiesResp?.methodologies || [];

  const { data: models = [], isLoading } = useQuery<ThreatModelSummary[]>({
    queryKey: ["threat-models", selectedClientId],
    queryFn: () => threatModelsApi.list(selectedClientId),
    enabled: !!selectedClientId,
    refetchInterval: (q) =>
      ((q.state.data as any) || []).some((m: any) => m.status === "pending" || m.status === "generating") ? 4000 : false,
  });

  // Completed scans for the selected client — choices for scan-scoped models.
  const { data: clientScans = [] } = useQuery<Scan[]>({
    queryKey: ["tm-scans", selectedClientId],
    queryFn: () => scansApi.list(selectedClientId),
    enabled: !!selectedClientId && openCreate,
  });

  const createMutation = useMutation({
    mutationFn: () => threatModelsApi.create(selectedClientId, {
      name: tmName || undefined,
      scope_type: scanIds.length ? "scans" : "client",
      scan_ids: scanIds.length ? scanIds : undefined,
      methodology,
      cloud_provider: cloudProvider,
      analyst_notes: [
        dataFlowDesc.trim() ? `DATA FLOWS: ${dataFlowDesc.trim()}` : "",
        notes.trim(),
      ].filter(Boolean).join("\n\n") || undefined,
      auto_remodel: autoRemodel,
    }),
    onSuccess: (created: ThreatModelSummary) => {
      qc.invalidateQueries({ queryKey: ["threat-models", selectedClientId] });
      setOpenCreate(false);
      setTmName("");
      setScanIds([]);
      setDataFlowDesc("");
      setNotes("");
      setCloudProvider("generic");
      setAutoRemodel(false);
      toast.success("Threat model generation started");
      // Auto-open detail so the user sees the generating state.
      setTimeout(() => navigate(`${tmBase}/${created.id}?client=${selectedClientId}`), 200);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to start threat model"),
  });

  const uploadMutation = useMutation({
    mutationFn: () => threatModelsApi.createFromDiagram(selectedClientId, uploadFile!, {
      name: uploadName || undefined,
      methodology: uploadMethodology,
    }),
    onSuccess: (resp: any) => {
      qc.invalidateQueries({ queryKey: ["threat-models", selectedClientId] });
      setOpenUpload(false);
      setUploadFile(null);
      setUploadName("");
      const warnSuffix = (resp?.warnings || []).length ? ` (${resp.warnings.length} warning)` : "";
      toast.success(`Extracted ${resp?.components?.length || 0} components${warnSuffix} — review and start modelling`);
      setTimeout(() => navigate(`${tmBase}/${resp.model_id}?client=${selectedClientId}`), 200);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to extract diagram"),
  });

  const rescanMutation = useMutation({
    mutationFn: (m: ThreatModelSummary) => threatModelsApi.rescan(selectedClientId, m.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["threat-models", selectedClientId] });
      toast.success("Re-modelling started");
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to re-model"),
  });

  const deleteMutation = useMutation({
    mutationFn: (m: ThreatModelSummary) => threatModelsApi.delete(selectedClientId, m.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["threat-models", selectedClientId] });
      setPendingDelete(null);
      toast.success("Threat model deleted");
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to delete"),
  });

  const methodologyLabel = (id: string) => methodologies.find((m) => m.id === id)?.label || id.toUpperCase();

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
            <Hub sx={{ color: "#4285F4", fontSize: 28 }} />
            <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Threat Models</Typography>
          </Box>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            On-demand STRIDE / PASTA / LINDDUN / MITRE ATT&CK / Kill Chain models grounded in your asset inventory + findings
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <Button variant="outlined" startIcon={<UploadFile />}
            disabled={!selectedClientId || !canAct}
            onClick={() => setOpenUpload(true)}
            sx={{
              color: "text.secondary",
              borderColor: "divider",
              "&:hover": { borderColor: "#4285F4", color: "#4285F4", bgcolor: "rgba(66,133,244,0.06)" },
            }}>
            Upload Diagram
          </Button>
          <Tooltip title={!canAct ? "Read-only in Executive mode — switch to Analyst (top-right) to generate models." : ""}>
            <span>
              <Button variant="contained" startIcon={<Add />}
                disabled={!selectedClientId || !canAct}
                onClick={() => setOpenCreate(true)}>
                New Threat Model
              </Button>
            </span>
          </Tooltip>
        </Box>
      </Box>

      {!selectedClientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "text.primary", border: "1px solid rgba(66,133,244,0.3)" }}>
          Pick a client to see its threat models or generate a new one.
        </Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 6 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      ) : models.length === 0 ? (
        <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <Hub sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary", fontWeight: 600, mb: 0.5 }}>No threat models yet</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Click "New Threat Model" to generate one on demand.
          </Typography>
        </Card>
      ) : (
        <Grid container spacing={2}>
          {models.map((m) => {
            const sc = STATUS_COLOR[m.status] || "rgba(255,255,255,0.4)";
            const inFlight = m.status === "pending" || m.status === "generating";
            return (
              <Grid key={m.id} size={{ xs: 12, sm: 6, md: 4 }}>
                <Card
                  onClick={() => navigate(`${tmBase}/${m.id}?client=${m.client_id}`)}
                  sx={{
                    bgcolor: "background.paper",
                    border: `1px solid ${sc}40`,
                    borderRadius: 2,
                    cursor: "pointer",
                    height: "100%",
                    transition: "border-color .12s, transform .12s",
                    "&:hover": { borderColor: sc, transform: "translateY(-1px)" },
                    position: "relative",
                  }}
                >
                  <Box sx={{ position: "absolute", top: 6, right: 6, display: "flex", gap: 0.25 }}>
                    <Tooltip title="Delete">
                      <IconButton size="small"
                        onClick={(e) => { e.stopPropagation(); setPendingDelete(m); }}
                        sx={{
                          color: "text.secondary",
                          "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" },
                        }}>
                        <DeleteOutlined sx={{ fontSize: 16 }} />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title={!canAct ? "Read-only in Executive mode" : inFlight ? "Re-model disabled while generation is in progress" : "Re-model (keeps history)"}>
                      <span>
                        <IconButton size="small" disabled={inFlight || rescanMutation.isPending || !canAct}
                          onClick={(e) => { e.stopPropagation(); rescanMutation.mutate(m); }}
                          sx={{
                            color: "text.secondary",
                            "&:hover": { color: "#4285F4", bgcolor: "rgba(66,133,244,0.08)" },
                            "&.Mui-disabled": { color: "text.secondary" },
                          }}>
                          <Replay sx={{ fontSize: 16 }} />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </Box>
                  <CardContent sx={{ pt: 4 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Chip label={methodologyLabel(m.methodology)} size="small"
                        sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontWeight: 700, fontSize: 10, height: 20, letterSpacing: 0.5 }} />
                      <Chip label={m.status} size="small"
                        sx={{ bgcolor: `${sc}20`, color: sc, fontWeight: 700, fontSize: 10, height: 20, textTransform: "uppercase", letterSpacing: 0.5 }} />
                    </Box>
                    <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 16, mb: 0.5 }}>
                      {m.name || `Threat Model · ${methodologyLabel(m.methodology)}`}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5 }}>
                      Scope: {m.scope_type === "scans" ? `${m.scope_scan_ids?.length || 0} scan${(m.scope_scan_ids?.length || 0) === 1 ? "" : "s"}` : m.scope_type}{m.framework ? ` · ${m.framework}` : ""}
                      {m.generated_at ? ` · generated ${fromNow(m.generated_at)}` : (m.created_at ? ` · created ${fromNow(m.created_at)}` : "")}
                    </Typography>
                    {inFlight && (
                      <LinearProgress sx={{ mb: 1.5, bgcolor: "rgba(66,133,244,0.1)", "& .MuiLinearProgress-bar": { bgcolor: "#4285F4" } }} />
                    )}
                    <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                      <Chip label={`${m.component_count} component${m.component_count === 1 ? "" : "s"}`}
                        size="small" sx={{ height: 20, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
                      <Chip label={`${m.threat_count} threat${m.threat_count === 1 ? "" : "s"}`}
                        size="small" sx={{ height: 20, fontSize: 10, bgcolor: "rgba(234,67,53,0.15)", color: "#EA4335", fontWeight: 700 }} />
                      <Chip label={`${m.mitigation_count} mitigation${m.mitigation_count === 1 ? "" : "s"}`}
                        size="small" sx={{ height: 20, fontSize: 10, bgcolor: "rgba(52,168,83,0.15)", color: "#34A853", fontWeight: 700 }} />
                    </Box>
                    {m.error_message && (
                      <Typography variant="caption" sx={{ color: "#EA4335", display: "block", mt: 1 }}>
                        Error: {m.error_message}
                      </Typography>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}

      {/* Create dialog */}
      <Dialog open={openCreate} onClose={() => setOpenCreate(false)} maxWidth="md" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle>
          Generate a new threat model
          <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>
            On-demand AI generation grounded in the selected client's asset inventory + recent findings.
          </Typography>
        </DialogTitle>
        <DialogContent dividers sx={{ borderColor: "divider" }}>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <TextField size="small" label="Name (optional)" value={tmName}
              onChange={(e) => setTmName(e.target.value)}
              placeholder='e.g. "Q2 2026 review"'
              
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />

            <Box>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mb: 1, display: "block" }}>
                METHODOLOGY
              </Typography>
              <Grid container spacing={1}>
                {methodologies.map((m) => {
                  const picked = methodology === m.id;
                  return (
                    <Grid key={m.id} size={{ xs: 12, sm: 6 }}>
                      <Card
                        onClick={() => setMethodology(m.id)}
                        sx={{
                          p: 1.5, cursor: "pointer",
                          bgcolor: picked ? "rgba(66,133,244,0.08)" : "transparent",
                          border: `1px solid ${picked ? "#4285F4" : "rgba(255,255,255,0.1)"}`,
                          borderRadius: 1.5, height: "100%",
                          "&:hover": { borderColor: "#4285F4" },
                        }}
                      >
                        <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 13, mb: 0.5 }}>{m.label}</Typography>
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", lineHeight: 1.4 }}>
                          {m.description}
                        </Typography>
                      </Card>
                    </Grid>
                  );
                })}
              </Grid>
              {!methodologies.length && (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  Loading methodologies…
                </Typography>
              )}
            </Box>

            <Box>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mb: 1, display: "block" }}>
                TARGET ENVIRONMENT
              </Typography>
              <Grid container spacing={1}>
                {[
                  { id: "aws",     label: "AWS",        desc: "Amazon Web Services — EC2, S3, RDS, Lambda…" },
                  { id: "azure",   label: "Azure",       desc: "Microsoft Azure — App Service, Cosmos DB, Key Vault…" },
                  { id: "gcp",     label: "GCP",         desc: "Google Cloud — GKE, Cloud SQL, GCS…" },
                  { id: "on_prem", label: "On-Premises", desc: "Data centre / bare-metal / private infrastructure" },
                  { id: "generic", label: "Generic / Multi-cloud", desc: "Mixed or provider-agnostic architecture" },
                ].map((env) => {
                  const picked = cloudProvider === env.id;
                  return (
                    <Grid key={env.id} size={{ xs: 12, sm: 6 }}>
                      <Card
                        onClick={() => setCloudProvider(env.id)}
                        sx={{
                          p: 1.5, cursor: "pointer",
                          bgcolor: picked ? "rgba(66,133,244,0.08)" : "transparent",
                          border: `1px solid ${picked ? "#4285F4" : "rgba(255,255,255,0.1)"}`,
                          borderRadius: 1.5, height: "100%",
                          "&:hover": { borderColor: "#4285F4" },
                        }}
                      >
                        <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 13, mb: 0.25 }}>{env.label}</Typography>
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", lineHeight: 1.4 }}>
                          {env.desc}
                        </Typography>
                      </Card>
                    </Grid>
                  );
                })}
              </Grid>
              <Typography variant="caption" sx={{ color: "text.secondary", mt: 0.5, display: "block" }}>
                Selects provider-specific icons in the draw.io diagram (AWS, Azure, GCP resource shapes).
              </Typography>
            </Box>

            <Box>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mb: 1, display: "block" }}>
                SCOPE (optional)
              </Typography>
              <FormControl size="small" fullWidth>
                <InputLabel sx={{ color: "text.secondary" }}>Scans to combine</InputLabel>
                <Select
                  multiple
                  value={scanIds}
                  onChange={(e) => setScanIds(typeof e.target.value === "string" ? e.target.value.split(",") : (e.target.value as string[]))}
                  label="Scans to combine"
                  renderValue={(sel) => (sel as string[]).length ? `${(sel as string[]).length} scan(s) selected` : ""}
                  sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                  MenuProps={{ slotProps: { paper: { sx: { maxHeight: 340, bgcolor: "background.paper" } } } }}
                >
                  {clientScans.length === 0 && <MenuItem disabled>No scans for this client</MenuItem>}
                  {clientScans.map((s) => {
                    const label = s.name || (s.scan_type as any) || s.id.slice(0, 8);
                    const total = s.summary?.total ?? 0;
                    return (
                      <MenuItem key={s.id} value={s.id} sx={{ color: "text.primary" }}>
                        <Checkbox size="small" checked={scanIds.indexOf(s.id) > -1} sx={{ color: "#4285F4" }} />
                        <ListItemText
                          primary={`${label} · ${s.status}`}
                          secondary={`${total} finding${total === 1 ? "" : "s"}${s.completed_at ? " · " + fromNow(s.completed_at) : ""}`}
                        />
                      </MenuItem>
                    );
                  })}
                </Select>
              </FormControl>
              <Typography variant="caption" sx={{ color: "text.secondary", mt: 0.5, display: "block" }}>
                Leave empty for a client-wide model, or pick one or more scans to scope the model to just those environments — avoids mixing unrelated systems into one messy diagram.
              </Typography>
            </Box>

            <Box>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mb: 1, display: "block" }}>
                DESCRIBE DATA FLOWS (optional but recommended)
              </Typography>
              <TextField fullWidth multiline minRows={2} size="small" value={dataFlowDesc}
                onChange={(e) => setDataFlowDesc(e.target.value)}
                placeholder='Describe how data moves between components — e.g. "Browser → Web App over HTTPS → REST API with JWT → PostgreSQL DB. No direct browser-to-DB access. API calls Azure Key Vault for secrets."'
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
              <Typography variant="caption" sx={{ color: "text.secondary", mt: 0.5, display: "block" }}>
                Helps the AI produce accurate DFD edges and labels. Plain English is fine.
              </Typography>
            </Box>

            <Box>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mb: 1, display: "block" }}>
                ANALYST NOTES (optional)
              </Typography>
              <TextField fullWidth multiline minRows={2} size="small" value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Guidance for the AI — e.g. 'the payments API is internet-facing', 'ignore the legacy batch job', 'focus on data exfiltration paths'."
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
            </Box>

            <Box sx={{ display: "flex", alignItems: "flex-start", flexDirection: "column", gap: 0.5 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={autoRemodel}
                    onChange={(e) => setAutoRemodel(e.target.checked)}
                    size="small"
                    sx={{
                      "& .MuiSwitch-switchBase.Mui-checked": { color: "#4285F4" },
                      "& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track": { bgcolor: "#4285F4" },
                    }}
                  />
                }
                label={
                  <Typography sx={{ color: "text.primary", fontSize: 13.5, fontWeight: 500 }}>
                    Auto re-generate on new scan
                  </Typography>
                }
              />
              <Typography variant="caption" sx={{ color: "text.secondary", ml: 4.5 }}>
                When enabled, the threat model will automatically re-run whenever a new scan completes for this client.
              </Typography>
            </Box>

            <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "text.secondary", border: "1px solid rgba(66,133,244,0.2)" }}>
              Generation runs on demand and typically takes 20–60 seconds. You can also add/remove components and refine notes afterward on the model's Components tab, then re-model.
            </Alert>
          </Box>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setOpenCreate(false)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button variant="contained"
            disabled={createMutation.isPending || !methodology}
            onClick={() => createMutation.mutate()}>
            {createMutation.isPending ? <CircularProgress size={18} /> : "Generate"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Upload dialog */}
      <Dialog open={openUpload} onClose={() => setOpenUpload(false)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle>
          Upload an architecture diagram
          <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>
            Upload a .drawio / .xml / .pdf / .jpg / .png. We'll extract components and data flows, then you review before AI threat modelling runs.
          </Typography>
        </DialogTitle>
        <DialogContent dividers sx={{ borderColor: "divider" }}>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <Box>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mb: 1, display: "block" }}>
                DIAGRAM FILE
              </Typography>
              <Box
                onDragOver={(e) => { e.preventDefault(); }}
                onDrop={(e) => {
                  e.preventDefault();
                  const f = e.dataTransfer.files?.[0];
                  if (f) setUploadFile(f);
                }}
                sx={{
                  border: "1px dashed rgba(255,255,255,0.25)",
                  borderRadius: 1.5,
                  p: 3, textAlign: "center",
                  bgcolor: "rgba(255,255,255,0.02)",
                }}
              >
                <UploadFile sx={{ fontSize: 32, color: "text.secondary", mb: 0.5 }} />
                <Typography variant="body2" sx={{ color: "text.secondary", mb: 1.5 }}>
                  {uploadFile ? uploadFile.name : "Drop file here or pick one below"}
                </Typography>
                <Button
                  component="label"
                  size="small"
                  variant="outlined"
                  sx={{ textTransform: "none", borderColor: "divider", color: "text.secondary" }}
                >
                  Choose file
                  <input
                    hidden
                    type="file"
                    accept={ACCEPTED_UPLOAD}
                    onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                  />
                </Button>
                {uploadFile && (
                  <Typography variant="caption" sx={{ display: "block", mt: 1, color: "text.secondary" }}>
                    {(uploadFile.size / 1024).toFixed(1)} KB · {uploadFile.type || "unknown"}
                  </Typography>
                )}
              </Box>
            </Box>

            <TextField size="small" label="Name (optional)" value={uploadName}
              onChange={(e) => setUploadName(e.target.value)}
              placeholder='e.g. "Payment platform architecture"'
              
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />

            <FormControl size="small">
              <InputLabel sx={{ color: "text.secondary" }}>Methodology</InputLabel>
              <Select value={uploadMethodology} onChange={(e) => setUploadMethodology(e.target.value)} label="Methodology"
                sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                {methodologies.map((m) => <MenuItem key={m.id} value={m.id}>{m.label}</MenuItem>)}
              </Select>
            </FormControl>

            <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "text.secondary", border: "1px solid rgba(66,133,244,0.2)" }}>
              <strong>How extraction works:</strong> .drawio files are parsed deterministically.
              PDFs use text extraction; if text is sparse the file is rejected — re-upload as PNG/JPG instead.
              Images are read by the configured vision LLM (OpenAI GPT-4o, Claude, Gemini all supported).
            </Alert>
          </Box>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setOpenUpload(false)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button variant="contained"
            disabled={!uploadFile || uploadMutation.isPending}
            onClick={() => uploadMutation.mutate()}>
            {uploadMutation.isPending ? <CircularProgress size={18} /> : "Extract diagram"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Confirm delete */}
      <Dialog open={!!pendingDelete} onClose={() => setPendingDelete(null)}
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle>Delete threat model?</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            This removes the model and its components / threats / mitigations. Findings and risks that informed the model are not affected.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDelete(null)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button variant="contained"
            disabled={deleteMutation.isPending}
            onClick={() => pendingDelete && deleteMutation.mutate(pendingDelete)}
            sx={{ bgcolor: "#EA4335", "&:hover": { bgcolor: "#c5362b" } }}>
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
