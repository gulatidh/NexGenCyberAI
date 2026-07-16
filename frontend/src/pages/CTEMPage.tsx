import React, { useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress, Alert,
  Button, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, IconButton, Grid, Tooltip, Divider, LinearProgress,
  Accordion, AccordionSummary, AccordionDetails, Paper,
} from "@mui/material";
import {
  Add, Delete, CheckCircle, RadioButtonUnchecked, Radar,
  AutoAwesome, ExpandMore, Cable, BugReport, Verified,
  Speed, WarningAmber, Lock,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ctemApi } from "../services/api";
import { toast } from "react-toastify";
import { fmt } from "../utils/datetime";

const PHASES = [
  {
    key: "scope",
    label: "1. Scope",
    icon: <Cable fontSize="small" />,
    desc: "Define what matters: crown jewels, critical systems, business processes at risk.",
    color: "#4285F4",
  },
  {
    key: "discover",
    label: "2. Discover",
    icon: <BugReport fontSize="small" />,
    desc: "Enumerate the attack surface: run scans, connectors, and asset discovery.",
    color: "#FBBC04",
  },
  {
    key: "prioritise",
    label: "3. Prioritise",
    icon: <Speed fontSize="small" />,
    desc: "Rank exposures by likelihood and business impact using AI risk scoring.",
    color: "#EA4335",
  },
  {
    key: "validate",
    label: "4. Validate",
    icon: <Verified fontSize="small" />,
    desc: "Confirm exploitability: run DAST/VAPT, verify findings are real.",
    color: "#9C27B0",
  },
  {
    key: "mobilise",
    label: "5. Mobilise",
    icon: <WarningAmber fontSize="small" />,
    desc: "Drive remediation: assign owners, set due dates, track SLA compliance.",
    color: "#34A853",
  },
];

interface PhaseData {
  notes?: string;
  completed?: boolean;
  completed_by?: string;
  completed_at?: string;
  ai_brief?: string;
  ai_brief_generated_at?: string;
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

// ── Stat chip helper ──────────────────────────────────────────────────────────
function StatChip({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", minWidth: 60 }}>
      <Typography variant="h6" sx={{ fontWeight: 800, color: color || "text.primary", lineHeight: 1 }}>
        {value}
      </Typography>
      <Typography variant="caption" sx={{ color: "text.secondary", textAlign: "center" }}>
        {label}
      </Typography>
    </Box>
  );
}

// ── Severity row helper ───────────────────────────────────────────────────────
const SEV_COLORS: Record<string, string> = {
  critical: "#EA4335", high: "#FF6D00", medium: "#FBBC04", low: "#34A853", info: "#4285F4",
};

function SevRow({ counts }: { counts: Record<string, number> }) {
  return (
    <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
      {Object.entries(counts).map(([sev, n]) => (
        <Chip
          key={sev}
          label={`${n} ${sev}`}
          size="small"
          sx={{
            bgcolor: `${SEV_COLORS[sev] || "#888"}22`,
            color: SEV_COLORS[sev] || "#888",
            fontSize: 10,
            height: 20,
            fontWeight: 700,
          }}
        />
      ))}
    </Box>
  );
}

// ── Phase data widget ─────────────────────────────────────────────────────────
function PhaseDataWidget({ clientId, programId, phase }: { clientId: string; programId: string; phase: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["ctem-phase-data", clientId, programId, phase],
    queryFn: () => ctemApi.getPhaseData(clientId, programId, phase),
    enabled: !!clientId && !!programId,
    staleTime: 60_000,
  });

  if (isLoading) return <CircularProgress size={16} sx={{ display: "block", my: 1 }} />;
  if (!data) return null;

  if (phase === "scope") {
    const d = data as { connectors_total: number; connectors_active: number; connectors: { name: string; type: string; status: string }[]; scan_types_available: string[] };
    return (
      <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap", my: 1.5 }}>
        <StatChip label="Connectors" value={d.connectors_total} />
        <StatChip label="Active" value={d.connectors_active} color="#34A853" />
        <StatChip label="Scan Types" value={d.scan_types_available?.length ?? 0} color="#4285F4" />
        <Box>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Scan types available:</Typography>
          <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 0.5 }}>
            {(d.scan_types_available ?? []).map((t: string) => (
              <Chip key={t} label={t} size="small" sx={{ fontSize: 10, height: 18 }} />
            ))}
            {(d.scan_types_available ?? []).length === 0 && (
              <Typography variant="caption" sx={{ color: "warning.main" }}>No active connectors — add one in Connections</Typography>
            )}
          </Box>
        </Box>
      </Box>
    );
  }

  if (phase === "discover") {
    const d = data as { scans_completed: number; findings_total: number; findings_by_severity: Record<string, number>; scan_types_run: string[] };
    return (
      <Box sx={{ my: 1.5 }}>
        <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap", mb: 1.5 }}>
          <StatChip label="Scans Run" value={d.scans_completed} color="#4285F4" />
          <StatChip label="Total Findings" value={d.findings_total} />
          <StatChip label="Critical" value={d.findings_by_severity?.critical ?? 0} color="#EA4335" />
          <StatChip label="High" value={d.findings_by_severity?.high ?? 0} color="#FF6D00" />
        </Box>
        {d.findings_by_severity && <SevRow counts={d.findings_by_severity} />}
      </Box>
    );
  }

  if (phase === "prioritise") {
    const d = data as { open_findings_total: number; open_by_severity: Record<string, number>; top_findings_by_cvss: { title: string; severity: string; cvss: number | null; cve?: string }[] };
    return (
      <Box sx={{ my: 1.5 }}>
        <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap", mb: 1.5 }}>
          <StatChip label="Open Findings" value={d.open_findings_total} />
          <StatChip label="Critical Open" value={d.open_by_severity?.critical ?? 0} color="#EA4335" />
          <StatChip label="High Open" value={d.open_by_severity?.high ?? 0} color="#FF6D00" />
        </Box>
        {d.top_findings_by_cvss?.length > 0 && (
          <Box>
            <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>Top by CVSS:</Typography>
            {d.top_findings_by_cvss.slice(0, 5).map((f, i) => (
              <Box key={i} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.4 }}>
                <Chip label={f.severity} size="small" sx={{ bgcolor: `${SEV_COLORS[f.severity] || "#888"}22`, color: SEV_COLORS[f.severity], fontSize: 10, height: 18, minWidth: 60 }} />
                {f.cvss && <Chip label={`CVSS ${f.cvss}`} size="small" sx={{ fontSize: 10, height: 18 }} />}
                <Typography variant="caption" sx={{ color: "text.primary" }} noWrap>{f.title}</Typography>
              </Box>
            ))}
          </Box>
        )}
      </Box>
    );
  }

  if (phase === "validate") {
    const d = data as { finding_statuses: Record<string, number>; vapt_reports: number; confirmed_pct: number };
    return (
      <Box sx={{ my: 1.5 }}>
        <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap", mb: 1.5 }}>
          <StatChip label="VAPT Reports" value={d.vapt_reports} color="#9C27B0" />
          <StatChip label="Confirmed %" value={`${d.confirmed_pct ?? 0}%`} color="#34A853" />
          <StatChip label="Open" value={d.finding_statuses?.open ?? 0} color="#EA4335" />
          <StatChip label="In Progress" value={d.finding_statuses?.in_progress ?? 0} color="#FBBC04" />
          <StatChip label="Remediated" value={d.finding_statuses?.remediated ?? 0} color="#34A853" />
        </Box>
        <Box>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Finding confirmation progress:</Typography>
          <LinearProgress
            variant="determinate"
            value={d.confirmed_pct ?? 0}
            sx={{ mt: 0.5, height: 6, borderRadius: 3, bgcolor: "rgba(255,255,255,0.08)" }}
          />
        </Box>
      </Box>
    );
  }

  if (phase === "mobilise") {
    const d = data as { remediation_actions: Record<string, number>; actions_total: number; sla_breaches: Record<string, number>; remediated_last_30d: number };
    const totalBreaches = Object.values(d.sla_breaches ?? {}).reduce((a, b) => a + b, 0);
    return (
      <Box sx={{ my: 1.5 }}>
        <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap", mb: 1.5 }}>
          <StatChip label="Total Actions" value={d.actions_total} />
          <StatChip label="In Progress" value={d.remediation_actions?.in_progress ?? 0} color="#FBBC04" />
          <StatChip label="Completed" value={d.remediation_actions?.completed ?? 0} color="#34A853" />
          <StatChip label="Closed (30d)" value={d.remediated_last_30d ?? 0} color="#4285F4" />
        </Box>
        {totalBreaches > 0 && (
          <Alert severity="warning" sx={{ py: 0.5, mt: 1 }}>
            <Typography variant="caption">
              SLA breaches: {d.sla_breaches?.critical ?? 0} critical (24h), {d.sla_breaches?.high ?? 0} high (7d), {d.sla_breaches?.medium ?? 0} medium (30d)
            </Typography>
          </Alert>
        )}
        {totalBreaches === 0 && <Alert severity="success" sx={{ py: 0.5, mt: 1 }}><Typography variant="caption">All SLA targets on track</Typography></Alert>}
      </Box>
    );
  }

  return null;
}

// ── AI Brief section ──────────────────────────────────────────────────────────
function AIBriefSection({
  clientId, programId, phase, brief, briefGeneratedAt,
  onBriefGenerated,
}: {
  clientId: string;
  programId: string;
  phase: string;
  brief?: string;
  briefGeneratedAt?: string;
  onBriefGenerated: () => void;
}) {
  const [generating, setGenerating] = useState(false);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      await ctemApi.generateAIBrief(clientId, programId, phase);
      onBriefGenerated();
      toast.success("AI brief generated");
    } catch {
      toast.error("AI brief generation failed — check AI provider settings");
    } finally {
      setGenerating(false);
    }
  };

  return (
    <Box sx={{ mt: 1.5 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
        <AutoAwesome sx={{ fontSize: 16, color: "#FBBC04" }} />
        <Typography variant="caption" sx={{ fontWeight: 600, color: "text.secondary" }}>
          AI Analysis {briefGeneratedAt ? `· generated ${fmt(briefGeneratedAt)}` : ""}
        </Typography>
        <Button
          size="small"
          variant="outlined"
          startIcon={generating ? <CircularProgress size={12} /> : <AutoAwesome sx={{ fontSize: 14 }} />}
          onClick={handleGenerate}
          disabled={generating}
          sx={{ ml: "auto", fontSize: 11, py: 0.3, px: 1 }}
        >
          {brief ? "Regenerate" : "Generate AI Brief"}
        </Button>
      </Box>
      {brief && (
        <Paper
          variant="outlined"
          sx={{
            p: 1.5,
            bgcolor: "rgba(251,188,4,0.04)",
            borderColor: "rgba(251,188,4,0.2)",
            borderRadius: 1,
            whiteSpace: "pre-wrap",
            fontSize: 12,
            fontFamily: "inherit",
            color: "text.primary",
            maxHeight: 320,
            overflow: "auto",
          }}
        >
          {brief}
        </Paper>
      )}
      {!brief && !generating && (
        <Typography variant="caption" sx={{ color: "text.secondary", fontStyle: "italic" }}>
          Click "Generate AI Brief" to get an AI analysis of this phase based on your platform data.
        </Typography>
      )}
    </Box>
  );
}

// ── Phase accordion ───────────────────────────────────────────────────────────
function PhaseAccordion({
  ph, phaseData, programId, clientId, isCurrentPhase, isLocked, onRefresh,
}: {
  ph: typeof PHASES[0];
  phaseData: PhaseData;
  programId: string;
  clientId: string;
  isCurrentPhase: boolean;
  isLocked: boolean;
  onRefresh: () => void;
}) {
  const qc = useQueryClient();
  const [notes, setNotes] = useState(phaseData.notes ?? "");
  const [expanded, setExpanded] = useState(isCurrentPhase);

  const done = phaseData.completed ?? false;

  const updateMut = useMutation({
    mutationFn: (args: { n?: string; completed?: boolean }) =>
      ctemApi.updatePhase(clientId, programId, ph.key, args.n, args.completed),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ctem", clientId] });
      toast.success("Phase updated");
    },
    onError: () => toast.error("Update failed"),
  });

  // Locked: future phase not yet reached — show a minimal locked row
  if (isLocked) {
    return (
      <Box
        sx={{
          display: "flex", alignItems: "center", gap: 1.5, px: 2, py: 1.2,
          mb: 1, border: "1px solid", borderColor: "divider", borderRadius: 1,
          opacity: 0.45, cursor: "not-allowed",
        }}
      >
        <Lock fontSize="small" sx={{ color: "text.disabled" }} />
        <Typography variant="body2" sx={{ fontWeight: 600, color: "text.disabled" }}>{ph.label}</Typography>
        <Typography variant="caption" sx={{ color: "text.disabled", ml: 1 }}>
          Complete the previous phase to unlock
        </Typography>
      </Box>
    );
  }

  // Completed phase: expandable but read-only (no mark-complete button)
  const isReadOnly = done;

  return (
    <Accordion
      expanded={expanded}
      onChange={(_, v) => setExpanded(v)}
      variant="outlined"
      sx={{
        mb: 1,
        "&:before": { display: "none" },
        borderColor: done ? "rgba(52,168,83,0.3)" : isCurrentPhase ? `${ph.color}44` : "divider",
      }}
    >
      <AccordionSummary expandIcon={<ExpandMore />} sx={{ minHeight: 48 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, flex: 1 }}>
          <Box sx={{ color: done ? "#34A853" : ph.color, display: "flex" }}>
            {done ? <CheckCircle fontSize="small" /> : <RadioButtonUnchecked fontSize="small" />}
          </Box>
          <Typography variant="body2" sx={{ fontWeight: 600 }}>{ph.label}</Typography>
          {done && <Chip label="Complete" size="small" sx={{ bgcolor: "rgba(52,168,83,0.15)", color: "#34A853", fontSize: 10, height: 18 }} />}
          {isCurrentPhase && !done && <Chip label="Active" size="small" sx={{ bgcolor: `${ph.color}22`, color: ph.color, fontSize: 10, height: 18 }} />}
          {phaseData.ai_brief && (
            <Chip icon={<AutoAwesome sx={{ fontSize: 12 }} />} label="AI brief" size="small"
              sx={{ bgcolor: "rgba(251,188,4,0.1)", color: "#FBBC04", fontSize: 10, height: 18, ml: "auto", mr: 1 }} />
          )}
        </Box>
      </AccordionSummary>

      <AccordionDetails sx={{ pt: 0 }}>
        <Typography variant="caption" sx={{ color: "text.secondary" }}>{ph.desc}</Typography>

        <Box sx={{ my: 1 }}>
          <Typography variant="caption" sx={{ fontWeight: 600, color: "text.secondary", display: "block", mb: 0.5 }}>
            PLATFORM DATA
          </Typography>
          <PhaseDataWidget clientId={clientId} programId={programId} phase={ph.key} />
        </Box>

        <Divider sx={{ my: 1.5 }} />

        <AIBriefSection
          clientId={clientId}
          programId={programId}
          phase={ph.key}
          brief={phaseData.ai_brief}
          briefGeneratedAt={phaseData.ai_brief_generated_at}
          onBriefGenerated={onRefresh}
        />

        <Divider sx={{ my: 1.5 }} />

        <Typography variant="caption" sx={{ fontWeight: 600, color: "text.secondary", display: "block", mb: 0.5 }}>
          ANALYST NOTES
        </Typography>
        <TextField
          multiline minRows={2} maxRows={6} fullWidth size="small"
          label="Add notes, decisions, or observations"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          sx={{ mb: 1 }}
          disabled={isReadOnly}
        />

        {done && phaseData.completed_by && (
          <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>
            Completed by {phaseData.completed_by}{phaseData.completed_at ? ` on ${fmt(phaseData.completed_at)}` : ""}
          </Typography>
        )}

        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          {!isReadOnly && (
            <Button size="small" variant="outlined"
              onClick={() => updateMut.mutate({ n: notes })}
              disabled={updateMut.isPending}>
              Save Notes
            </Button>
          )}
          {!done && (
            <Button size="small" variant="contained"
              sx={{ bgcolor: ph.color, "&:hover": { filter: "brightness(0.85)" } }}
              onClick={() => updateMut.mutate({ n: notes, completed: true })}
              disabled={updateMut.isPending}>
              Mark Phase Complete
            </Button>
          )}
          {done && (
            <Button size="small" variant="outlined" color="warning"
              onClick={() => updateMut.mutate({ n: phaseData.notes ?? "", completed: false })}
              disabled={updateMut.isPending}>
              Reopen Phase
            </Button>
          )}
        </Box>
      </AccordionDetails>
    </Accordion>
  );
}

// ── CTEM exposure score ───────────────────────────────────────────────────────
function ExposureScore({ phases, currentPhase }: { phases: Record<string, PhaseData>; currentPhase: string }) {
  const completedCount = PHASES.filter((p) => phases[p.key]?.completed).length;
  const briefCount = PHASES.filter((p) => phases[p.key]?.ai_brief).length;
  const score = Math.round((completedCount / PHASES.length) * 60 + (briefCount / PHASES.length) * 40);
  const color = score >= 80 ? "#34A853" : score >= 50 ? "#FBBC04" : "#EA4335";

  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
      <Box sx={{ position: "relative", width: 48, height: 48 }}>
        <CircularProgress variant="determinate" value={score} size={48} thickness={4} sx={{ color }} />
        <Typography
          variant="caption"
          sx={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", fontWeight: 800, fontSize: 11, color }}
        >
          {score}%
        </Typography>
      </Box>
      <Box>
        <Typography variant="body2" sx={{ fontWeight: 700 }}>CTEM Progress</Typography>
        <Typography variant="caption" sx={{ color: "text.secondary" }}>
          {completedCount}/{PHASES.length} phases · {briefCount} AI briefs
        </Typography>
      </Box>
    </Box>
  );
}

// ── Program card ──────────────────────────────────────────────────────────────
function ProgramCard({
  program, clientId, onDelete,
}: { program: CTEMProgram; clientId: string; onDelete: () => void }) {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const phases = program.phases || {};
  const phasesMap: Record<string, PhaseData> = {};
  if (Array.isArray(program.phases)) {
    (program.phases as unknown as (PhaseData & { phase: string })[]).forEach((p) => {
      phasesMap[p.phase] = p;
    });
  } else {
    Object.assign(phasesMap, phases);
  }

  const completedCount = PHASES.filter((p) => phasesMap[p.key]?.completed).length;
  const currentPhase = program.current_phase || "scope";
  const currentPhaseIdx = PHASES.findIndex((p) => p.key === currentPhase);

  const onRefresh = () => qc.invalidateQueries({ queryKey: ["ctem", clientId] });

  return (
    <Card variant="outlined" sx={{ mb: 2 }}>
      <CardContent sx={{ pb: "12px !important" }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <Box sx={{ flex: 1, cursor: "pointer" }} onClick={() => setExpanded((v) => !v)}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{program.name}</Typography>
            {program.description && (
              <Typography variant="caption" sx={{ color: "text.secondary" }}>{program.description}</Typography>
            )}
            <Box sx={{ display: "flex", gap: 1, mt: 1, flexWrap: "wrap", alignItems: "center" }}>
              <Chip
                label={completedCount === PHASES.length ? "Complete" : "In Progress"}
                size="small"
                sx={{
                  bgcolor: completedCount === PHASES.length ? "rgba(52,168,83,0.15)" : "rgba(66,133,244,0.15)",
                  color: completedCount === PHASES.length ? "#34A853" : "#4285F4",
                  fontSize: 10, height: 18,
                }}
              />
              <Chip label={`Active: ${PHASES[currentPhaseIdx]?.label ?? currentPhase}`} size="small" variant="outlined" sx={{ fontSize: 10, height: 18 }} />
              <Chip label={`${completedCount}/${PHASES.length} complete`} size="small" variant="outlined" sx={{ fontSize: 10, height: 18 }} />
              {program.created_at && (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  {fmt(program.created_at)}
                </Typography>
              )}
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 0.5, alignItems: "center" }}>
            {!expanded && <ExposureScore phases={phasesMap} currentPhase={currentPhase} />}
            <Button size="small" onClick={() => setExpanded((v) => !v)} sx={{ ml: 1 }}>
              {expanded ? "Collapse" : "Open"}
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
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
              <ExposureScore phases={phasesMap} currentPhase={currentPhase} />
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                Platform data and AI briefs load automatically · future phases unlock when current phase is marked complete
              </Typography>
            </Box>
            <Box>
              {PHASES.map((ph, idx) => (
                <PhaseAccordion
                  key={ph.key}
                  ph={ph}
                  phaseData={phasesMap[ph.key] ?? {}}
                  programId={program.id}
                  clientId={clientId}
                  isCurrentPhase={idx === currentPhaseIdx}
                  isLocked={idx > currentPhaseIdx && !phasesMap[ph.key]?.completed}
                  onRefresh={onRefresh}
                />
              ))}
            </Box>
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

// ── Main page ─────────────────────────────────────────────────────────────────
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
            AI-driven exposure management — platform data auto-populates each phase, manual notes always available
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<Add />} onClick={() => setCreateOpen(true)} disabled={!clientId}>
          New Program
        </Button>
      </Box>

      {!clientId && <Alert severity="info">Select a client to manage CTEM programs.</Alert>}
      {clientId && isLoading && <CircularProgress size={24} />}

      {clientId && !isLoading && programs.length === 0 && (
        <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
          <Radar sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary", mb: 1 }}>
            No CTEM programs yet.
          </Typography>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            Create a program to start an AI-guided exposure management cycle. Each phase shows live data from your scans, findings, and remediation tracker — plus one-click AI briefs.
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
