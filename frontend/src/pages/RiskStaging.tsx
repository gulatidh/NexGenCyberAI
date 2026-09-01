import React, { useState } from "react";
import { useIsGuest } from "../hooks/useIsGuest";
import {
  Box, Typography, Tabs, Tab, Grid, Card, CardContent, Chip,
  Button, IconButton, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, Select, MenuItem, FormControl, InputLabel, FormLabel,
  RadioGroup, FormControlLabel, Radio, CircularProgress, Alert,
  Tooltip, Divider,
} from "@mui/material";
import {
  Add, SmartToy, BugReport, Person, Archive as ArchiveIcon,
  Block, RestoreFromTrash, Assessment, ChevronRight,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useActiveClient } from "../contexts/ClientContext";
import { riskProposalsApi } from "../services/api";
import { RiskProposal } from "../types";
import { fromNow } from "../utils/datetime";
import EvaluationWizard from "../components/EvaluationWizard";

// ── Constants ─────────────────────────────────────────────────────────────────

const RISK_AREAS_SECURITY = [
  "Unauthorised Access", "Data Leakage / Breach", "Denial of Service",
  "Malware / Ransomware", "Supply Chain Risk", "Insider Threat",
  "Social Engineering / Phishing", "System Misconfiguration",
  "Vulnerability Exploitation", "Cryptographic Weakness",
  "Third-Party Vendor Risk", "Compliance & Regulatory",
];

const RISK_AREAS_PROJECT = [
  "Schedule Delay", "Resource / Budget Overrun", "Scope Creep",
  "Technology / Integration Risk", "Data Governance",
];

const SOURCE_META: Record<string, { label: string; color: string; Icon: React.ElementType }> = {
  ai:      { label: "AI",      color: "#7c3aed", Icon: SmartToy },
  finding: { label: "Finding", color: "#ea580c", Icon: BugReport },
  manual:  { label: "Manual",  color: "#2563eb", Icon: Person },
};

const TAB_STATUS = ["pending", "archived", "dismissed", "evaluated"];

// ── Proposal Card ─────────────────────────────────────────────────────────────

function ProposalCard({
  proposal,
  onEvaluate,
  onArchive,
  onDismiss,
  onRestore,
}: {
  proposal: RiskProposal;
  onEvaluate: (p: RiskProposal) => void;
  onArchive: (id: string) => void;
  onDismiss: (id: string) => void;
  onRestore: (id: string) => void;
}) {
  const navigate = useNavigate();
  const isGuest = useIsGuest();
  const src = SOURCE_META[proposal.source] || SOURCE_META.manual;
  const SrcIcon = src.Icon;

  return (
    <Card variant="outlined" sx={{ height: "100%", display: "flex", flexDirection: "column",
      "&:hover": { borderColor: "primary.main", boxShadow: "0 0 0 1px rgba(66,133,244,0.3)" },
      transition: "all 0.15s" }}>
      <CardContent sx={{ flex: 1, display: "flex", flexDirection: "column", gap: 1 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
          <Chip
            icon={<SrcIcon sx={{ fontSize: 14 }} />}
            label={src.label}
            size="small"
            sx={{ bgcolor: src.color + "22", color: src.color, fontWeight: 600,
              "& .MuiChip-icon": { color: src.color } }}
          />
          {proposal.category && (
            <Chip label={proposal.category} size="small" variant="outlined" sx={{ fontSize: 11 }} />
          )}
          {proposal.risk_type && (
            <Chip
              label={proposal.risk_type}
              size="small"
              sx={{ bgcolor: proposal.risk_type === "Project" ? "#1e40af22" : "#7c3aed22",
                color: proposal.risk_type === "Project" ? "#93c5fd" : "#c4b5fd", fontSize: 11 }}
            />
          )}
        </Box>

        <Typography variant="subtitle2" sx={{ fontWeight: 700, lineHeight: 1.3, flex: 1 }}>
          {proposal.title}
        </Typography>

        {proposal.description && (
          <Typography variant="caption" sx={{ color: "text.secondary", display: "-webkit-box",
            WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>
            {proposal.description}
          </Typography>
        )}

        <Typography variant="caption" sx={{ color: "text.disabled" }}>
          Added {fromNow(proposal.created_at)}
          {proposal.evaluated_at && ` · Evaluated ${fromNow(proposal.evaluated_at)}`}
          {proposal.dismissed_at && ` · Dismissed ${fromNow(proposal.dismissed_at)}`}
          {proposal.archived_at && ` · Archived ${fromNow(proposal.archived_at)}`}
        </Typography>
      </CardContent>

      <Divider />
      <Box sx={{ px: 2, py: 1, display: "flex", gap: 1, flexWrap: "wrap" }}>
        {!isGuest && proposal.status === "pending" && (
          <>
            <Button size="small" variant="contained" onClick={() => onEvaluate(proposal)}
              sx={{ fontWeight: 700 }}>
              Evaluate
            </Button>
            <Button size="small" variant="outlined" startIcon={<ArchiveIcon sx={{ fontSize: 14 }} />}
              onClick={() => onArchive(proposal.id)}>
              Archive
            </Button>
            <Button size="small" color="error" onClick={() => onDismiss(proposal.id)}>
              Dismiss
            </Button>
          </>
        )}
        {!isGuest && proposal.status === "archived" && (
          <>
            <Button size="small" variant="outlined" startIcon={<RestoreFromTrash sx={{ fontSize: 14 }} />}
              onClick={() => onRestore(proposal.id)}>
              Restore
            </Button>
            <Button size="small" color="error" onClick={() => onDismiss(proposal.id)}>
              Dismiss
            </Button>
          </>
        )}
        {!isGuest && proposal.status === "dismissed" && (
          <>
            <Button size="small" variant="outlined" startIcon={<RestoreFromTrash sx={{ fontSize: 14 }} />}
              onClick={() => onRestore(proposal.id)}>
              Restore
            </Button>
            <Button size="small" variant="outlined" startIcon={<ArchiveIcon sx={{ fontSize: 14 }} />}
              onClick={() => onArchive(proposal.id)}>
              Archive
            </Button>
          </>
        )}
        {proposal.status === "evaluated" && (
          <Button size="small" variant="outlined" endIcon={<ChevronRight sx={{ fontSize: 14 }} />}
            onClick={() => navigate("/analyse/risks")}>
            View in Register
          </Button>
        )}
      </Box>
    </Card>
  );
}

// ── Add Proposal Dialog ───────────────────────────────────────────────────────

function AddProposalDialog({
  open, onClose, onSaved,
}: {
  open: boolean; onClose: () => void; onSaved: () => void;
}) {
  const { clientId } = useActiveClient();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("");
  const [riskType, setRiskType] = useState("Security");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");

  const reset = () => { setTitle(""); setDescription(""); setCategory(""); setRiskType("Security"); setErr(""); };

  const handleClose = () => { reset(); onClose(); };

  const handleSave = async () => {
    if (!clientId || !title.trim()) { setErr("Title is required"); return; }
    setSaving(true);
    setErr("");
    try {
      await riskProposalsApi.create(clientId, { title, description, category, risk_type: riskType, source: "manual" });
      reset();
      onSaved();
      onClose();
    } catch (e: any) {
      setErr(e?.response?.data?.detail || "Failed to create proposal");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={handleClose} fullWidth maxWidth="sm">
      <DialogTitle sx={{ fontWeight: 700 }}>New Risk Proposal</DialogTitle>
      <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2.5, pt: 2 }}>
        {err && <Alert severity="error">{err}</Alert>}
        <TextField label="Risk Title *" fullWidth value={title} onChange={(e) => setTitle(e.target.value)} />
        <TextField label="Description" fullWidth multiline minRows={3} value={description}
          onChange={(e) => setDescription(e.target.value)} />
        <FormControl fullWidth>
          <InputLabel>Risk Area</InputLabel>
          <Select value={category} label="Risk Area"
            onChange={(e) => {
              const v = e.target.value;
              setCategory(v);
              setRiskType(RISK_AREAS_PROJECT.includes(v) ? "Project" : "Security");
            }}>
            <MenuItem disabled><em>Security Risk</em></MenuItem>
            {RISK_AREAS_SECURITY.map((a) => <MenuItem key={a} value={a}>{a}</MenuItem>)}
            <MenuItem disabled><em>Project Risk</em></MenuItem>
            {RISK_AREAS_PROJECT.map((a) => <MenuItem key={a} value={a}>{a}</MenuItem>)}
          </Select>
        </FormControl>
        <FormControl>
          <FormLabel>Risk Type</FormLabel>
          <RadioGroup row value={riskType} onChange={(e) => setRiskType(e.target.value)}>
            <FormControlLabel value="Security" control={<Radio />} label="Security Risk" />
            <FormControlLabel value="Project" control={<Radio />} label="Project Risk" />
          </RadioGroup>
        </FormControl>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose}>Cancel</Button>
        <Button variant="contained" onClick={handleSave} disabled={saving || !title.trim()}>
          {saving ? <CircularProgress size={16} /> : "Add Proposal"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ── Stat Chip ─────────────────────────────────────────────────────────────────

function StatPill({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 0.75,
      bgcolor: color + "15", border: "1px solid " + color + "40",
      borderRadius: "20px", px: 1.5, py: 0.5 }}>
      <Typography variant="caption" sx={{ color, fontWeight: 700 }}>{count}</Typography>
      <Typography variant="caption" sx={{ color: "text.secondary" }}>{label}</Typography>
    </Box>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function RiskStaging() {
  const { clientId } = useActiveClient();
  const isGuest = useIsGuest();
  const qc = useQueryClient();
  const [tab, setTab] = useState(0);
  const [addOpen, setAddOpen] = useState(false);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [selectedProposal, setSelectedProposal] = useState<RiskProposal | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["risk-proposals", clientId],
    queryFn: () => clientId ? riskProposalsApi.list(clientId) : Promise.resolve({ proposals: [], stats: {} }),
    enabled: !!clientId,
    refetchInterval: 30_000,
  });

  const proposals: RiskProposal[] = data?.proposals || [];
  const stats = data?.stats || {};
  const invalidate = () => qc.invalidateQueries({ queryKey: ["risk-proposals", clientId] });

  const archiveMut = useMutation({
    mutationFn: (id: string) => riskProposalsApi.archive(clientId!, id),
    onSuccess: invalidate,
  });
  const dismissMut = useMutation({
    mutationFn: (id: string) => riskProposalsApi.dismiss(clientId!, id),
    onSuccess: invalidate,
  });
  const restoreMut = useMutation({
    mutationFn: (id: string) => riskProposalsApi.restore(clientId!, id),
    onSuccess: invalidate,
  });

  const currentStatus = TAB_STATUS[tab];
  const filtered = proposals.filter((p) => p.status === currentStatus);

  const handleEvaluate = (p: RiskProposal) => {
    setSelectedProposal(p);
    setWizardOpen(true);
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: "auto" }}>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Risk Staging</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
            Review and evaluate proposed risks before adding to the Risk Register
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap" }}>
          <StatPill label="Pending" count={stats.pending_count ?? 0} color="#f59e0b" />
          <StatPill label="Archived" count={stats.archived_count ?? 0} color="#6b7280" />
          <StatPill label="Dismissed" count={stats.dismissed_count ?? 0} color="#ef4444" />
          <StatPill label="Evaluated" count={stats.evaluated_count ?? 0} color="#10b981" />
          {!isGuest && (
            <Button variant="contained" startIcon={<Add />} onClick={() => setAddOpen(true)}>
              Add Proposal
            </Button>
          )}
        </Box>
      </Box>

      {/* Tabs */}
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 3, borderBottom: 1, borderColor: "divider" }}>
        <Tab label={`Pending (${stats.pending_count ?? 0})`} />
        <Tab label={`Archived (${stats.archived_count ?? 0})`} />
        <Tab label={`Dismissed (${stats.dismissed_count ?? 0})`} />
        <Tab label={`Evaluated (${stats.evaluated_count ?? 0})`} />
      </Tabs>

      {/* Content */}
      {isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", py: 6 }}>
          <CircularProgress />
        </Box>
      ) : filtered.length === 0 ? (
        <Box sx={{ textAlign: "center", py: 8, color: "text.secondary" }}>
          <Assessment sx={{ fontSize: 48, opacity: 0.3, mb: 2 }} />
          <Typography variant="h6">No {currentStatus} proposals</Typography>
          <Typography variant="body2" sx={{ mt: 0.5 }}>
            {currentStatus === "pending"
              ? "Risk proposals from AI agents and manual submissions will appear here."
              : `No proposals in ${currentStatus} state.`}
          </Typography>
          {currentStatus === "pending" && (
            <Button variant="outlined" startIcon={<Add />} sx={{ mt: 2 }}
              onClick={() => setAddOpen(true)}>
              Add a Proposal
            </Button>
          )}
        </Box>
      ) : (
        <Grid container spacing={2.5}>
          {filtered.map((p) => (
            <Grid key={p.id} size={{ xs: 12, sm: 6, md: 4 }}>
              <ProposalCard
                proposal={p}
                onEvaluate={handleEvaluate}
                onArchive={(id) => archiveMut.mutate(id)}
                onDismiss={(id) => dismissMut.mutate(id)}
                onRestore={(id) => restoreMut.mutate(id)}
              />
            </Grid>
          ))}
        </Grid>
      )}

      {/* Dialogs */}
      <AddProposalDialog open={addOpen} onClose={() => setAddOpen(false)} onSaved={invalidate} />
      <EvaluationWizard
        open={wizardOpen}
        onClose={() => { setWizardOpen(false); setSelectedProposal(null); }}
        proposal={selectedProposal}
        onEvaluated={invalidate}
      />
    </Box>
  );
}
