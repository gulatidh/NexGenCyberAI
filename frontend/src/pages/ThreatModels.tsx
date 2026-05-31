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
import {
  Box, Typography, Card, CardContent, Button, Chip, Grid, IconButton,
  Tooltip, FormControl, InputLabel, Select, MenuItem, Dialog, DialogTitle,
  DialogContent, DialogActions, TextField, CircularProgress, Alert,
  LinearProgress,
} from "@mui/material";
import { Add, Hub, Replay, DeleteOutlined } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import { clientsApi, threatModelsApi } from "../services/api";
import { Client } from "../types";
import { fromNow } from "../utils/datetime";

interface ThreatModelSummary {
  id: string;
  client_id: string;
  name?: string | null;
  scope_type: string;
  scope_id?: string | null;
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
};

export default function ThreatModels() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [selectedClientId, setSelectedClientId] = useState<string>("");
  const [openCreate, setOpenCreate] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<ThreatModelSummary | null>(null);

  // ── Create-dialog form state
  const [tmName, setTmName] = useState("");
  const [methodology, setMethodology] = useState<string>("stride");

  const { data: clients = [] } = useQuery<Client[]>({
    queryKey: ["clients"], queryFn: clientsApi.list,
  });
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

  const createMutation = useMutation({
    mutationFn: () => threatModelsApi.create(selectedClientId, {
      name: tmName || undefined,
      scope_type: "client",
      methodology,
    }),
    onSuccess: (created: ThreatModelSummary) => {
      qc.invalidateQueries({ queryKey: ["threat-models", selectedClientId] });
      setOpenCreate(false);
      setTmName("");
      toast.success("Threat model generation started");
      // Auto-open detail so the user sees the generating state.
      setTimeout(() => navigate(`/threat-models/${created.id}?client=${selectedClientId}`), 200);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to start threat model"),
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
            <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Threat Models</Typography>
          </Box>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            On-demand STRIDE / PASTA / LINDDUN / MITRE ATT&CK / Kill Chain models grounded in your asset inventory + findings
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
            <Select value={selectedClientId} onChange={(e) => setSelectedClientId(e.target.value)} label="Client"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <Button variant="contained" startIcon={<Add />}
            disabled={!selectedClientId}
            onClick={() => setOpenCreate(true)}>
            New Threat Model
          </Button>
        </Box>
      </Box>

      {!selectedClientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "white", border: "1px solid rgba(66,133,244,0.3)" }}>
          Pick a client to see its threat models or generate a new one.
        </Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 6 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      ) : models.length === 0 ? (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <Hub sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
          <Typography sx={{ color: "rgba(255,255,255,0.7)", fontWeight: 600, mb: 0.5 }}>No threat models yet</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
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
                  onClick={() => navigate(`/threat-models/${m.id}?client=${m.client_id}`)}
                  sx={{
                    bgcolor: "#1E1E1E",
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
                          color: "rgba(255,255,255,0.35)",
                          "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" },
                        }}>
                        <DeleteOutlined sx={{ fontSize: 16 }} />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title={inFlight ? "Re-model disabled while generation is in progress" : "Re-model (keeps history)"}>
                      <span>
                        <IconButton size="small" disabled={inFlight || rescanMutation.isPending}
                          onClick={(e) => { e.stopPropagation(); rescanMutation.mutate(m); }}
                          sx={{
                            color: "rgba(255,255,255,0.35)",
                            "&:hover": { color: "#4285F4", bgcolor: "rgba(66,133,244,0.08)" },
                            "&.Mui-disabled": { color: "rgba(255,255,255,0.15)" },
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
                    <Typography sx={{ color: "white", fontWeight: 700, fontSize: 16, mb: 0.5 }}>
                      {m.name || `Threat Model · ${methodologyLabel(m.methodology)}`}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 1.5 }}>
                      Scope: {m.scope_type}{m.framework ? ` · ${m.framework}` : ""}
                      {m.generated_at ? ` · generated ${fromNow(m.generated_at)}` : (m.created_at ? ` · created ${fromNow(m.created_at)}` : "")}
                    </Typography>
                    {inFlight && (
                      <LinearProgress sx={{ mb: 1.5, bgcolor: "rgba(66,133,244,0.1)", "& .MuiLinearProgress-bar": { bgcolor: "#4285F4" } }} />
                    )}
                    <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                      <Chip label={`${m.component_count} component${m.component_count === 1 ? "" : "s"}`}
                        size="small" sx={{ height: 20, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.75)" }} />
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
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
        <DialogTitle>
          Generate a new threat model
          <Typography variant="caption" sx={{ display: "block", color: "rgba(255,255,255,0.5)" }}>
            On-demand AI generation grounded in {clients.find((c) => c.id === selectedClientId)?.name || "the client"}'s asset inventory + recent findings.
          </Typography>
        </DialogTitle>
        <DialogContent dividers sx={{ borderColor: "rgba(255,255,255,0.08)" }}>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <TextField size="small" label="Name (optional)" value={tmName}
              onChange={(e) => setTmName(e.target.value)}
              placeholder='e.g. "Q2 2026 review"'
              slotProps={{ inputLabel: { sx: { color: 'rgba(255,255,255,0.5)' } }, htmlInput: { style: { color: 'white' } } }}
              sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />

            <Box>
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontWeight: 600, mb: 1, display: "block" }}>
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
                        <Typography sx={{ color: "white", fontWeight: 700, fontSize: 13, mb: 0.5 }}>{m.label}</Typography>
                        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.6)", display: "block", lineHeight: 1.4 }}>
                          {m.description}
                        </Typography>
                      </Card>
                    </Grid>
                  );
                })}
              </Grid>
              {!methodologies.length && (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>
                  Loading methodologies…
                </Typography>
              )}
            </Box>

            <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "rgba(255,255,255,0.85)", border: "1px solid rgba(66,133,244,0.2)" }}>
              Generation runs on demand and typically takes 20–60 seconds. The model uses the configured AI provider (Settings → AI Settings). If no provider is configured, a deterministic skeleton is returned.
            </Alert>
          </Box>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setOpenCreate(false)} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
          <Button variant="contained"
            disabled={createMutation.isPending || !methodology}
            onClick={() => createMutation.mutate()}>
            {createMutation.isPending ? <CircularProgress size={18} /> : "Generate"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Confirm delete */}
      <Dialog open={!!pendingDelete} onClose={() => setPendingDelete(null)}
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
        <DialogTitle>Delete threat model?</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.75)" }}>
            This removes the model and its components / threats / mitigations. Findings and risks that informed the model are not affected.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDelete(null)} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
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
