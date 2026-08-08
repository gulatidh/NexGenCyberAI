import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Grid, Button, Chip, IconButton,
  FormControl, InputLabel, Select, MenuItem, Dialog, DialogTitle,
  DialogContent, DialogActions, TextField, Alert, CircularProgress, Skeleton,
} from "@mui/material";
import { Add, Delete, Edit } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { clientsApi, projectsApi } from "../services/api";
import { Client, Project, ProjectSummary } from "../types";

const ENV_OPTIONS = ["production", "staging", "development", "dr", "other"];
const CLOUD_OPTIONS = ["azure", "aws", "gcp", "multi", "other"];

const ENV_COLOR: Record<string, string> = {
  production: "#f44336",
  staging: "#ff9800",
  development: "#4285F4",
  dr: "#34A853",
  other: "rgba(255,255,255,0.5)",
};

interface ProjectCardProps { project: Project; onEdit: () => void; onDelete: () => void; clientId: string; }

function ProjectCard({ project, onEdit, onDelete, clientId }: ProjectCardProps) {
  const { data: summary } = useQuery<ProjectSummary>({
    queryKey: ["project-summary", clientId, project.id],
    queryFn: () => projectsApi.summary(clientId, project.id),
  });
  const isDefault = project.name === "Default";
  return (
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2,
      transition: "border-color .15s", "&:hover": { borderColor: "rgba(66,133,244,0.3)" } }}>
      <CardContent>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
          <Box>
            <Typography variant="h6" sx={{ color: "text.primary", fontWeight: 600, lineHeight: 1.2 }}>{project.name}</Typography>
            {project.description && (
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.5 }}>
                {project.description}
              </Typography>
            )}
          </Box>
          <Box sx={{ display: "flex", gap: 0.5 }}>
            <IconButton size="small" onClick={onEdit} sx={{ color: "text.secondary" }}>
              <Edit fontSize="small" />
            </IconButton>
            {!isDefault && (
              <IconButton size="small" onClick={onDelete} sx={{ color: "text.secondary" }}>
                <Delete fontSize="small" />
              </IconButton>
            )}
          </Box>
        </Box>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
          {project.environment && (
            <Chip label={project.environment} size="small"
              sx={{ bgcolor: `${ENV_COLOR[project.environment] || "#888"}20`,
                color: ENV_COLOR[project.environment] || "#888", fontSize: 10, height: 20, textTransform: "capitalize" }} />
          )}
          {project.cloud_provider && (
            <Chip label={project.cloud_provider.toUpperCase()} size="small"
              sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", fontSize: 10, height: 20 }} />
          )}
        </Box>
        <Grid container spacing={1}>
          {[
            ["Connectors", summary?.connector_count],
            ["Assets", summary?.asset_count],
            ["Scans", summary?.scan_count],
          ].map(([label, val]) => (
            <Grid key={label as string} size={4}>
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", fontSize: 10, fontWeight: 600 }}>
                {(label as string).toUpperCase()}
              </Typography>
              <Typography sx={{ color: "text.primary", fontSize: 18, fontWeight: 600 }}>
                {val == null ? "…" : val}
              </Typography>
            </Grid>
          ))}
        </Grid>
      </CardContent>
    </Card>
  );
}


export default function Projects() {
  const qc = useQueryClient();
  const [clientId, setClientId] = useState("");
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Project | null>(null);
  const [form, setForm] = useState({ name: "", description: "", environment: "", cloud_provider: "" });

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: projects = [], isLoading } = useQuery<Project[]>({
    queryKey: ["projects", clientId],
    queryFn: () => projectsApi.list(clientId),
    enabled: !!clientId,
  });

  React.useEffect(() => {
    if (!clientId && clients.length > 0) setClientId(clients[0].id);
  }, [clients, clientId]);

  const createMutation = useMutation({
    mutationFn: (data: any) => editing
      ? projectsApi.update(clientId, editing.id, data)
      : projectsApi.create(clientId, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects", clientId] });
      qc.invalidateQueries({ queryKey: ["project-summary"] });
      setOpen(false);
      setEditing(null);
      setForm({ name: "", description: "", environment: "", cloud_provider: "" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => projectsApi.delete(clientId, id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects", clientId] }),
  });

  const openCreate = () => {
    setEditing(null);
    setForm({ name: "", description: "", environment: "", cloud_provider: "" });
    setOpen(true);
  };
  const openEdit = (p: Project) => {
    setEditing(p);
    setForm({ name: p.name, description: p.description || "", environment: p.environment || "", cloud_provider: p.cloud_provider || "" });
    setOpen(true);
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Projects</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Logical grouping of connectors, assets, and scans within a client
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1 }}>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Client</InputLabel>
            <Select value={clientId} onChange={(e) => setClientId(e.target.value)} label="Client"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <Button variant="contained" startIcon={<Add />} disabled={!clientId} onClick={openCreate}
            sx={{ bgcolor: "#4285F4", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}>
            New Project
          </Button>
        </Box>
      </Box>

      {!clientId && clients.length === 0 && (
        <Alert severity="info">No accounts yet. Create one in the Accounts page first.</Alert>
      )}

      <Grid container spacing={2}>
        {isLoading ? (
          [0, 1, 2].map((i) => (
            <Grid key={i} size={{ xs: 12, sm: 6, md: 4, lg: 3 }}>
              <Skeleton variant="rectangular" height={180} sx={{ borderRadius: 2, bgcolor: "rgba(255,255,255,0.04)" }} />
            </Grid>
          ))
        ) : projects.length === 0 && clientId ? (
          <Grid size={12}>
            <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
              <Typography sx={{ color: "text.secondary" }}>
                No projects yet. Create one to organize your connectors.
              </Typography>
            </Card>
          </Grid>
        ) : (
          projects.map((p) => (
            <Grid key={p.id} size={{ xs: 12, sm: 6, md: 4, lg: 3 }}>
              <ProjectCard project={p} clientId={clientId}
                onEdit={() => openEdit(p)}
                onDelete={() => {
                  if (window.confirm(`Delete project "${p.name}"? Connectors must be moved first.`)) {
                    deleteMutation.mutate(p.id);
                  }
                }} />
            </Grid>
          ))
        )}
      </Grid>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle>{editing ? `Edit Project — ${editing.name}` : "New Project"}</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 0.5 }}>
            <Grid size={12}>
              <TextField fullWidth size="small" label="Name" value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                sx={{ "& .MuiOutlinedInput-root": { color: "text.primary", "& fieldset": { borderColor: "divider" } },
                  "& .MuiInputLabel-root": { color: "text.secondary" } }} />
            </Grid>
            <Grid size={12}>
              <TextField fullWidth size="small" label="Description" multiline rows={2} value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                sx={{ "& .MuiOutlinedInput-root": { color: "text.primary", "& fieldset": { borderColor: "divider" } },
                  "& .MuiInputLabel-root": { color: "text.secondary" } }} />
            </Grid>
            <Grid size={6}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "text.secondary" }}>Environment</InputLabel>
                <Select label="Environment" value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })}
                  sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                  <MenuItem value="">—</MenuItem>
                  {ENV_OPTIONS.map((o) => <MenuItem key={o} value={o}>{o}</MenuItem>)}
                </Select>
              </FormControl>
            </Grid>
            <Grid size={6}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "text.secondary" }}>Cloud</InputLabel>
                <Select label="Cloud" value={form.cloud_provider} onChange={(e) => setForm({ ...form, cloud_provider: e.target.value })}
                  sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                  <MenuItem value="">—</MenuItem>
                  {CLOUD_OPTIONS.map((o) => <MenuItem key={o} value={o}>{o.toUpperCase()}</MenuItem>)}
                </Select>
              </FormControl>
            </Grid>
          </Grid>
          {createMutation.isError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {(createMutation.error as any)?.response?.data?.detail || "Save failed"}
            </Alert>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setOpen(false)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button variant="contained" disabled={!form.name || createMutation.isPending}
            onClick={() => createMutation.mutate({
              name: form.name,
              description: form.description || undefined,
              environment: form.environment || undefined,
              cloud_provider: form.cloud_provider || undefined,
            })}
            sx={{ bgcolor: "#4285F4", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}>
            {createMutation.isPending ? <CircularProgress size={18} /> : (editing ? "Save" : "Create")}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
