import React, { useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress, Alert,
  Button, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, IconButton, Grid, Stepper, Step, StepLabel, StepContent,
  Tooltip, Divider,
} from "@mui/material";
import {
  Add, Delete, CheckCircle, RadioButtonUnchecked, Radar,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ctemApi } from "../services/api";
import { toast } from "react-toastify";
import { fmt } from "../utils/datetime";

const PHASES = [
  { key: "scope",     label: "1. Scope",      desc: "Define what matters: crown jewels, critical systems, business processes at risk." },
  { key: "discover",  label: "2. Discover",   desc: "Enumerate the attack surface: run scans, connectors, and asset discovery." },
  { key: "prioritise",label: "3. Prioritise", desc: "Rank exposures by likelihood and business impact using AI risk scoring." },
  { key: "validate",  label: "4. Validate",   desc: "Confirm exploitability: run DAST/VAPT, verify findings are real." },
  { key: "mobilise",  label: "5. Mobilise",   desc: "Drive remediation: assign owners, set due dates, track SLA compliance." },
];

interface PhaseData {
  notes?: string;
  completed?: boolean;
  completed_by?: string;
  completed_at?: string;
}

interface CTEMProgram {
  id: string;
  name: string;
  description?: string;
  status?: string;
  current_phase?: string;
  phases?: Record<string, PhaseData>;
  created_at?: string;
}

function PhaseStepper({ program, clientId }: { program: CTEMProgram; clientId: string }) {
  const qc = useQueryClient();
  const [notes, setNotes] = useState<Record<string, string>>({});

  const updateMut = useMutation({
    mutationFn: ({ phase, n, completed }: { phase: string; n: string; completed?: boolean }) =>
      ctemApi.updatePhase(clientId, program.id, phase, n, completed),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ctem", clientId] });
      toast.success("Phase updated");
    },
    onError: () => toast.error("Update failed"),
  });

  const phases = program.phases || {};

  return (
    <Box sx={{ mt: 2 }}>
      <Stepper orientation="vertical" nonLinear>
        {PHASES.map((ph) => {
          const data: PhaseData = phases[ph.key] || {};
          const done = data.completed ?? false;
          const noteVal = notes[ph.key] ?? (data.notes || "");

          return (
            <Step key={ph.key} active completed={done}>
              <StepLabel
                icon={done
                  ? <CheckCircle sx={{ color: "#34A853" }} />
                  : <RadioButtonUnchecked sx={{ color: "text.secondary" }} />}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>{ph.label}</Typography>
                  {done && (
                    <Chip label="Done" size="small"
                      sx={{ bgcolor: "rgba(52,168,83,0.15)", color: "#34A853", fontSize: 10, height: 18 }} />
                  )}
                </Box>
              </StepLabel>
              <StepContent>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5 }}>
                  {ph.desc}
                </Typography>
                <TextField
                  multiline minRows={2} maxRows={5} fullWidth size="small"
                  label="Notes"
                  value={noteVal}
                  onChange={(e) => setNotes((prev) => ({ ...prev, [ph.key]: e.target.value }))}
                  sx={{ mb: 1 }}
                />
                {done && data.completed_by && (
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>
                    Completed by {data.completed_by}
                    {data.completed_at ? ` on ${fmt(data.completed_at)}` : ""}
                  </Typography>
                )}
                <Box sx={{ display: "flex", gap: 1 }}>
                  <Button size="small" variant="outlined"
                    onClick={() => updateMut.mutate({ phase: ph.key, n: noteVal })}
                    disabled={updateMut.isPending}>
                    Save Notes
                  </Button>
                  {!done && (
                    <Button size="small" variant="contained"
                      sx={{ bgcolor: "#34A853", "&:hover": { bgcolor: "#2e7d32" } }}
                      onClick={() => updateMut.mutate({ phase: ph.key, n: noteVal, completed: true })}
                      disabled={updateMut.isPending}>
                      Mark Complete
                    </Button>
                  )}
                  {done && (
                    <Button size="small" variant="outlined" color="warning"
                      onClick={() => updateMut.mutate({ phase: ph.key, n: noteVal, completed: false })}
                      disabled={updateMut.isPending}>
                      Reopen
                    </Button>
                  )}
                </Box>
              </StepContent>
            </Step>
          );
        })}
      </Stepper>
    </Box>
  );
}

function ProgramCard({
  program, clientId, onDelete,
}: { program: CTEMProgram; clientId: string; onDelete: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const phases = program.phases || {};
  const completedCount = PHASES.filter((p) => phases[p.key]?.completed).length;
  const currentPhase = PHASES.find((p) => !phases[p.key]?.completed)?.label ?? "All Done";

  const statusColor = completedCount === PHASES.length ? "#34A853" : completedCount > 0 ? "#FBBC04" : "#4285F4";
  const statusLabel = completedCount === PHASES.length ? "Complete" : "In Progress";

  return (
    <Card variant="outlined" sx={{ mb: 2 }}>
      <CardContent sx={{ pb: "12px !important" }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <Box sx={{ flex: 1, cursor: "pointer" }} onClick={() => setExpanded((v) => !v)}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{program.name}</Typography>
            {program.description && (
              <Typography variant="caption" sx={{ color: "text.secondary" }}>{program.description}</Typography>
            )}
            <Box sx={{ display: "flex", gap: 1, mt: 1, flexWrap: "wrap" }}>
              <Chip label={statusLabel} size="small"
                sx={{ bgcolor: `${statusColor}22`, color: statusColor, fontSize: 10, height: 18 }} />
              <Chip label={`Phase: ${currentPhase}`} size="small" variant="outlined"
                sx={{ fontSize: 10, height: 18 }} />
              <Chip label={`${completedCount}/${PHASES.length} phases`} size="small" variant="outlined"
                sx={{ fontSize: 10, height: 18 }} />
              {program.created_at && (
                <Typography variant="caption" sx={{ color: "text.secondary", alignSelf: "center" }}>
                  Created {fmt(program.created_at)}
                </Typography>
              )}
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 0.5 }}>
            <Button size="small" onClick={() => setExpanded((v) => !v)}>
              {expanded ? "Collapse" : "View"}
            </Button>
            <Tooltip title="Delete program">
              <IconButton size="small" color="error" onClick={() => setConfirmDelete(true)}>
                <Delete fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        {expanded && (
          <>
            <Divider sx={{ my: 2 }} />
            <PhaseStepper program={program} clientId={clientId} />
          </>
        )}
      </CardContent>

      <Dialog open={confirmDelete} onClose={() => setConfirmDelete(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Delete Program?</DialogTitle>
        <DialogContent>
          <Typography>Are you sure you want to delete <strong>{program.name}</strong>? This cannot be undone.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmDelete(false)}>Cancel</Button>
          <Button color="error" variant="contained" onClick={() => { setConfirmDelete(false); onDelete(); }}>Delete</Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
}

export default function CTEMPage() {
  const qc = useQueryClient();
  const { clientId } = useActiveClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");

  const { data: programs = [], isLoading } = useQuery<CTEMProgram[]>({
    queryKey: ["ctem", clientId],
    queryFn: () => ctemApi.list(clientId),
    enabled: !!clientId,
  });

  const createMut = useMutation({
    mutationFn: () => ctemApi.create(clientId, { name: newName.trim(), description: newDesc.trim() || undefined }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ctem", clientId] });
      setCreateOpen(false);
      setNewName("");
      setNewDesc("");
      toast.success("CTEM program created");
    },
    onError: () => toast.error("Create failed"),
  });

  const deleteMut = useMutation({
    mutationFn: (programId: string) => ctemApi.delete(clientId, programId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ctem", clientId] });
      toast.success("Program deleted");
    },
    onError: () => toast.error("Delete failed"),
  });

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>CTEM Programs</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Continuous Threat Exposure Management — scope, discover, prioritise, validate, mobilise
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<Add />} onClick={() => setCreateOpen(true)} disabled={!clientId}>
          New Program
        </Button>
      </Box>

      {!clientId && (
        <Alert severity="info">Select a client to manage CTEM programs.</Alert>
      )}

      {clientId && isLoading && <CircularProgress size={24} />}

      {clientId && !isLoading && programs.length === 0 && (
        <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
          <Radar sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No CTEM programs yet. Create one to start tracking your exposure management lifecycle.
          </Typography>
        </Card>
      )}

      {clientId && !isLoading && programs.map((p) => (
        <ProgramCard
          key={p.id}
          program={p}
          clientId={clientId}
          onDelete={() => deleteMut.mutate(p.id)}
        />
      ))}

      {/* Create Dialog */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>New CTEM Program</DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <TextField
                label="Program Name" fullWidth size="small" required
                value={newName} onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g. Q3 Cloud Exposure Reduction"
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField
                label="Description (optional)" fullWidth size="small" multiline minRows={2}
                value={newDesc} onChange={(e) => setNewDesc(e.target.value)}
                placeholder="Brief objective or scope statement"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={!newName.trim() || createMut.isPending}
            onClick={() => createMut.mutate()}>
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
