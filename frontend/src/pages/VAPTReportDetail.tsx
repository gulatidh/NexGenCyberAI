import React, { useState, useEffect, useCallback } from "react";
import {
  Box, Typography, Button, Chip, IconButton, Tab, Tabs, TextField,
  Select, MenuItem, FormControl, InputLabel, Dialog, DialogTitle,
  DialogContent, DialogActions, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Paper, Alert, CircularProgress,
  Stack, Tooltip, Divider, Card, CardContent, CardActions, Grid,
} from "@mui/material";
import {
  ArrowBack, Save, PictureAsPdf, Description,
  Add, Edit, Delete, GppGood, CheckCircle, Shield,
  FileDownload, Replay,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { useMsal } from "@azure/msal-react";
import { loginRequest } from "../auth/msalConfig";
import { useActiveClient } from "../contexts/ClientContext";
import { vaptApi } from "../services/api";

const API_BASE = import.meta.env.REACT_APP_API_URL || "http://localhost:8000/api/v1";

const SEV_COLORS: Record<string, string> = {
  critical: "#C62828",
  high: "#E64A19",
  medium: "#F9A825",
  low: "#2E7D32",
  informational: "#1565C0",
};

const SEV_TEXT: Record<string, string> = {
  critical: "#fff",
  high: "#fff",
  medium: "#37474F",
  low: "#fff",
  informational: "#fff",
};

const RETEST_COLORS: Record<string, string> = {
  passed: "#2E7D32",
  failed: "#C62828",
  pending: "#757575",
  not_applicable: "#455A64",
};

const SEV_ORDER = ["critical", "high", "medium", "low", "informational"];

function sortBySeverity(findings: any[]) {
  return [...findings].sort((a, b) => {
    const ai = SEV_ORDER.indexOf((a.severity || "").toLowerCase());
    const bi = SEV_ORDER.indexOf((b.severity || "").toLowerCase());
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });
}

function SeverityChip({ severity }: { severity: string }) {
  const s = (severity || "").toLowerCase();
  return (
    <Chip
      label={s.charAt(0).toUpperCase() + s.slice(1)}
      size="small"
      sx={{
        bgcolor: SEV_COLORS[s] || "#757575",
        color: SEV_TEXT[s] || "#fff",
        fontWeight: 700,
        fontSize: "0.72rem",
      }}
    />
  );
}

function RetestChip({ status }: { status: string }) {
  const s = (status || "pending").toLowerCase();
  return (
    <Chip
      label={s.replace("_", " ").replace(/\b\w/g, (c) => c.toUpperCase())}
      size="small"
      sx={{
        bgcolor: RETEST_COLORS[s] || "#757575",
        color: "#fff",
        fontWeight: 600,
        fontSize: "0.72rem",
      }}
    />
  );
}

// ── ChipList: chip-style add/remove for lists ─────────────────────────────────
function ChipList({
  items, onAdd, onRemove, label, placeholder,
}: {
  items: string[];
  onAdd: (v: string) => void;
  onRemove: (i: number) => void;
  label: string;
  placeholder?: string;
}) {
  const [input, setInput] = useState("");
  return (
    <Box>
      <Typography variant="caption" color="text.secondary" sx={{ mb: 0.5, display: "block" }}>
        {label}
      </Typography>
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1 }}>
        {items.map((item, i) => (
          <Chip key={i} label={item} size="small" onDelete={() => onRemove(i)} />
        ))}
      </Box>
      <TextField
        size="small"
        placeholder={placeholder || `Add ${label.toLowerCase()} and press Enter`}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && input.trim()) {
            onAdd(input.trim());
            setInput("");
          }
        }}
        fullWidth
      />
    </Box>
  );
}

// ── Finding dialog ─────────────────────────────────────────────────────────────
const EMPTY_FINDING = {
  finding_id: "",
  title: "",
  severity: "medium",
  affected_asset: "",
  description: "",
  impact: "",
  evidence: "",
  reproduction_steps: "",
  recommendation: "",
  references: "",
  retest_status: "pending",
  retest_notes: "",
  order_index: 0,
};

function FindingDialog({
  open, onClose, onSave, initialData, existingCount, loading,
}: {
  open: boolean;
  onClose: () => void;
  onSave: (data: any) => void;
  initialData?: any;
  existingCount: number;
  loading: boolean;
}) {
  const [form, setForm] = useState({ ...EMPTY_FINDING });

  useEffect(() => {
    if (open) {
      if (initialData) {
        setForm({ ...EMPTY_FINDING, ...initialData });
      } else {
        setForm({
          ...EMPTY_FINDING,
          finding_id: `F-${String(existingCount + 1).padStart(2, "0")}`,
          order_index: existingCount,
        });
      }
    }
  }, [open, initialData, existingCount]);

  const set = (key: string, value: any) => setForm((f) => ({ ...f, [key]: value }));

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ fontWeight: 700 }}>
        {initialData ? "Edit Finding" : "Add Finding"}
      </DialogTitle>
      <DialogContent sx={{ pt: 2 }}>
        <Grid container spacing={2}>
          <Grid size={{ xs: 12, sm: 4 }}>
            <TextField label="Finding ID" value={form.finding_id}
              onChange={(e) => set("finding_id", e.target.value)} fullWidth size="small"
              placeholder="F-01" />
          </Grid>
          <Grid size={{ xs: 12, sm: 4 }}>
            <FormControl fullWidth size="small">
              <InputLabel>Severity</InputLabel>
              <Select value={form.severity} label="Severity"
                onChange={(e) => set("severity", e.target.value)}>
                {["critical", "high", "medium", "low", "informational"].map((s) => (
                  <MenuItem key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid size={{ xs: 12, sm: 4 }}>
            <FormControl fullWidth size="small">
              <InputLabel>Retest Status</InputLabel>
              <Select value={form.retest_status} label="Retest Status"
                onChange={(e) => set("retest_status", e.target.value)}>
                {["pending", "passed", "failed", "not_applicable"].map((s) => (
                  <MenuItem key={s} value={s}>{s.replace("_", " ").replace(/\b\w/g, (c) => c.toUpperCase())}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField label="Affected Asset" value={form.affected_asset}
              onChange={(e) => set("affected_asset", e.target.value)} fullWidth size="small"
              placeholder="e.g. https://app.example.com, 10.10.0.5, Login API" />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField label="Title" required value={form.title}
              onChange={(e) => set("title", e.target.value)} fullWidth size="small" />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField label="Description" value={form.description}
              onChange={(e) => set("description", e.target.value)} fullWidth multiline rows={4}
              placeholder="Describe the vulnerability in detail…" />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField label="Business Impact" value={form.impact}
              onChange={(e) => set("impact", e.target.value)} fullWidth multiline rows={3}
              placeholder="What is the potential business impact if exploited?" />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField label="Evidence" value={form.evidence}
              onChange={(e) => set("evidence", e.target.value)} fullWidth multiline rows={3}
              placeholder="Describe screenshots, request/response, file paths, tool output…" />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField label="Reproduction Steps" value={form.reproduction_steps}
              onChange={(e) => set("reproduction_steps", e.target.value)} fullWidth multiline rows={4}
              placeholder="Step-by-step reproduction instructions…" />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField label="Recommendation" value={form.recommendation}
              onChange={(e) => set("recommendation", e.target.value)} fullWidth multiline rows={4}
              placeholder="Specific remediation guidance…" />
          </Grid>
          <Grid size={{ xs: 12 }}>
            <TextField label="References" value={form.references}
              onChange={(e) => set("references", e.target.value)} fullWidth size="small"
              placeholder="CVE-2024-xxxx, CWE-79, OWASP A03:2021" />
          </Grid>
          {form.retest_status !== "pending" && (
            <Grid size={{ xs: 12 }}>
              <TextField label="Retest Notes" value={form.retest_notes}
                onChange={(e) => set("retest_notes", e.target.value)} fullWidth multiline rows={3}
                placeholder="Notes from the retest session…" />
            </Grid>
          )}
        </Grid>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={!form.title.trim() || loading}
          onClick={() => onSave(form)}
          sx={{ bgcolor: "#1A237E", "&:hover": { bgcolor: "#283593" } }}>
          {loading ? "Saving…" : "Save Finding"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function VAPTReportDetail() {
  const { reportId } = useParams<{ reportId: string }>();
  const navigate = useNavigate();
  const { clientId } = useActiveClient();
  const qc = useQueryClient();
  const { instance, accounts } = useMsal();

  const [tab, setTab] = useState(0);
  const [saved, setSaved] = useState(false);
  const [findingDialogOpen, setFindingDialogOpen] = useState(false);
  const [editFinding, setEditFinding] = useState<any>(null);
  const [deleteFindingTarget, setDeleteFindingTarget] = useState<string | null>(null);
  const [retestConfirmOpen, setRetestConfirmOpen] = useState(false);

  // Local form state (document control + scope/methodology)
  const [docForm, setDocForm] = useState<any>({});
  const [scopeForm, setScopeForm] = useState<any>({
    engagement_type: "Black Box",
    period_start: "",
    period_end: "",
    in_scope: [],
    out_of_scope: [],
  });
  const [methForm, setMethForm] = useState<any>({
    phases: [],
    tools: [],
    standards: [],
  });
  const [conclusionForm, setConclusionForm] = useState("");
  const [appendicesForm, setAppendicesForm] = useState("");
  const [phaseInput, setPhaseInput] = useState({ name: "", description: "" });

  // ── Load report ───────────────────────────────────────────────────────────
  const { data: report, isLoading, error } = useQuery({
    queryKey: ["vapt-report", clientId, reportId],
    queryFn: () => vaptApi.get(clientId!, reportId!),
    enabled: !!clientId && !!reportId,
  });

  // Sync form state when report loads
  useEffect(() => {
    if (!report) return;
    setDocForm({
      title: report.title || "",
      version: report.version || "1.0",
      classification: report.classification || "Confidential",
      status: report.status || "draft",
      prepared_by: report.prepared_by || "",
      reviewed_by: report.reviewed_by || "",
      report_date: report.report_date ? report.report_date.slice(0, 10) : "",
      retest_date: report.retest_date ? report.retest_date.slice(0, 10) : "",
      executive_summary: report.executive_summary || "",
    });
    try {
      const s = JSON.parse(report.scope_json || "{}");
      setScopeForm({
        engagement_type: s.engagement_type || "Black Box",
        period_start: s.period_start || "",
        period_end: s.period_end || "",
        in_scope: s.in_scope || [],
        out_of_scope: s.out_of_scope || [],
      });
    } catch { }
    try {
      const m = JSON.parse(report.methodology_json || "{}");
      setMethForm({
        phases: m.phases || [],
        tools: m.tools || [],
        standards: m.standards || [],
      });
    } catch { }
    setConclusionForm(report.conclusion || "");
    setAppendicesForm(report.appendices || "");
  }, [report]);

  // ── Mutations ─────────────────────────────────────────────────────────────
  const saveMutation = useMutation({
    mutationFn: (data: any) => vaptApi.update(clientId!, reportId!, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vapt-report", clientId, reportId] });
      qc.invalidateQueries({ queryKey: ["vapt-reports", clientId] });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    },
  });

  const addFindingMutation = useMutation({
    mutationFn: (data: any) => vaptApi.addFinding(clientId!, reportId!, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vapt-report", clientId, reportId] });
      setFindingDialogOpen(false);
      setEditFinding(null);
    },
  });

  const updateFindingMutation = useMutation({
    mutationFn: ({ fid, data }: { fid: string; data: any }) =>
      vaptApi.updateFinding(clientId!, reportId!, fid, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vapt-report", clientId, reportId] });
      setFindingDialogOpen(false);
      setEditFinding(null);
    },
  });

  const deleteFindingMutation = useMutation({
    mutationFn: (fid: string) => vaptApi.deleteFinding(clientId!, reportId!, fid),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vapt-report", clientId, reportId] });
      setDeleteFindingTarget(null);
    },
  });

  const retestMutation = useMutation({
    mutationFn: () => vaptApi.createRetest(clientId!, reportId!),
    onSuccess: (newReport) => {
      qc.invalidateQueries({ queryKey: ["vapt-reports", clientId] });
      setRetestConfirmOpen(false);
      navigate(`/vapt-reports/${newReport.id}`);
    },
  });

  // ── Save helpers ──────────────────────────────────────────────────────────
  const handleSave = useCallback(() => {
    const payload: any = {
      ...docForm,
      conclusion: conclusionForm,
      appendices: appendicesForm,
      scope_json: JSON.stringify(scopeForm),
      methodology_json: JSON.stringify(methForm),
    };
    // Normalise date fields — send null if empty
    if (!payload.report_date) payload.report_date = null;
    if (!payload.retest_date) payload.retest_date = null;
    saveMutation.mutate(payload);
  }, [docForm, conclusionForm, appendicesForm, scopeForm, methForm, saveMutation]);

  // ── Export ────────────────────────────────────────────────────────────────
  const downloadExport = useCallback(async (format: string) => {
    try {
      const account = accounts[0];
      let token = "";
      if (account) {
        try {
          const resp = await instance.acquireTokenSilent({ ...loginRequest, account });
          token = resp.accessToken;
        } catch { }
      }
      const url = API_BASE + vaptApi.exportUrl(clientId!, reportId!, format);
      const res = await fetch(url, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl;
      const ext = format.includes("docx") ? "docx" : "pdf";
      a.download = `vapt-${format}-${(reportId || "").slice(0, 8)}.${ext}`;
      a.click();
      URL.revokeObjectURL(blobUrl);
    } catch (err) {
      console.error("Export failed:", err);
    }
  }, [clientId, reportId, instance, accounts]);

  // ── Finding save ──────────────────────────────────────────────────────────
  const handleFindingSave = (data: any) => {
    if (editFinding) {
      updateFindingMutation.mutate({ fid: editFinding.id, data });
    } else {
      addFindingMutation.mutate(data);
    }
  };

  if (!clientId) {
    return (
      <Box sx={{ p: 4, textAlign: "center" }}>
        <Typography color="text.secondary">Select a client to view this report.</Typography>
      </Box>
    );
  }

  if (isLoading) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error || !report) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Report not found or access denied.</Alert>
        <Button startIcon={<ArrowBack />} onClick={() => navigate("/vapt-reports")} sx={{ mt: 2 }}>
          Back to Reports
        </Button>
      </Box>
    );
  }

  const sortedFindings = sortBySeverity(report.findings || []);
  const fc = report.finding_counts || {};
  const retestCounts = { passed: 0, failed: 0, pending: 0, not_applicable: 0 };
  (report.findings || []).forEach((f: any) => {
    const rs = (f.retest_status || "pending").toLowerCase() as keyof typeof retestCounts;
    if (rs in retestCounts) retestCounts[rs]++;
  });

  const isFindingLoading = addFindingMutation.isPending || updateFindingMutation.isPending;

  return (
    <Box sx={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* ── Sticky top bar ────────────────────────────────────────────────── */}
      <Box sx={{
        position: "sticky", top: 0, zIndex: 10,
        bgcolor: "background.paper",
        borderBottom: "1px solid rgba(255,255,255,0.1)",
        px: 2, py: 1,
        display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap",
      }}>
        <IconButton onClick={() => navigate("/vapt-reports")} size="small">
          <ArrowBack />
        </IconButton>
        <GppGood sx={{ color: "#1565C0" }} />
        <Typography variant="subtitle1" sx={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: 700 }}>
          {report.title}
        </Typography>
        <Chip label={`v${report.version}`} size="small"
          sx={{ bgcolor: "rgba(21,101,192,0.15)", color: "#90CAF9", fontWeight: 700 }} />
        <Chip
          label={report.status === "final" ? "Final" : "Draft"}
          size="small"
          sx={{
            bgcolor: report.status === "final" ? "rgba(46,125,50,0.15)" : "rgba(120,120,120,0.15)",
            color: report.status === "final" ? "#4CAF50" : "#9E9E9E",
            fontWeight: 600,
          }}
        />

        <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
          <Button size="small" startIcon={<Save />} onClick={handleSave}
            disabled={saveMutation.isPending}
            variant={saved ? "contained" : "outlined"}
            color={saved ? "success" : "primary"}
            sx={{ fontSize: "0.75rem" }}>
            {saved ? "Saved!" : saveMutation.isPending ? "Saving…" : "Save"}
          </Button>
          {report.status !== "final" && (
            <Button size="small" startIcon={<CheckCircle />}
              onClick={() => saveMutation.mutate({ ...docForm, status: "final" })}
              variant="outlined" color="success" sx={{ fontSize: "0.75rem" }}>
              Mark Final
            </Button>
          )}
          <Button size="small" startIcon={<Replay />}
            onClick={() => setRetestConfirmOpen(true)}
            variant="outlined" sx={{ fontSize: "0.75rem" }}>
            Create Retest v{report.version ? (parseFloat(report.version) + 0.1).toFixed(1) : "1.1"}
          </Button>
          <Tooltip title="Download Full Report PDF">
            <Button size="small" startIcon={<PictureAsPdf />} onClick={() => downloadExport("pdf")}
              sx={{ fontSize: "0.75rem" }}>PDF</Button>
          </Tooltip>
          <Tooltip title="Download Full Report DOCX">
            <Button size="small" startIcon={<Description />} onClick={() => downloadExport("docx")}
              sx={{ fontSize: "0.75rem" }}>DOCX</Button>
          </Tooltip>
        </Box>
      </Box>

      {/* ── Tabs ──────────────────────────────────────────────────────────── */}
      <Box sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ px: 2 }}>
          <Tab label="Document Control" />
          <Tab label="Scope & Methodology" />
          <Tab label={`Findings (${(report.findings || []).length})`} />
          <Tab label="Export & History" />
        </Tabs>
      </Box>

      <Box sx={{ flex: 1, overflow: "auto", p: 3 }}>

        {/* ── Tab 0: Document Control ──────────────────────────────────────── */}
        {tab === 0 && (
          <Grid container spacing={3}>
            <Grid size={{ xs: 12, sm: 8 }}>
              <TextField label="Report Title" value={docForm.title || ""}
                onChange={(e) => setDocForm((f: any) => ({ ...f, title: e.target.value }))}
                fullWidth />
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <TextField label="Version" value={docForm.version || ""}
                onChange={(e) => setDocForm((f: any) => ({ ...f, version: e.target.value }))}
                fullWidth />
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <FormControl fullWidth>
                <InputLabel>Classification</InputLabel>
                <Select value={docForm.classification || "Confidential"} label="Classification"
                  onChange={(e) => setDocForm((f: any) => ({ ...f, classification: e.target.value }))}>
                  {["Confidential", "Internal", "Public"].map((c) => (
                    <MenuItem key={c} value={c}>{c}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <FormControl fullWidth>
                <InputLabel>Status</InputLabel>
                <Select value={docForm.status || "draft"} label="Status"
                  onChange={(e) => setDocForm((f: any) => ({ ...f, status: e.target.value }))}>
                  <MenuItem value="draft">Draft</MenuItem>
                  <MenuItem value="final">Final</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <TextField label="Report Date" type="date" value={docForm.report_date || ""}
                onChange={(e) => setDocForm((f: any) => ({ ...f, report_date: e.target.value }))}
                fullWidth slotProps={{ inputLabel: { shrink: true } }} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField label="Prepared By" value={docForm.prepared_by || ""}
                onChange={(e) => setDocForm((f: any) => ({ ...f, prepared_by: e.target.value }))}
                fullWidth />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField label="Reviewed By" value={docForm.reviewed_by || ""}
                onChange={(e) => setDocForm((f: any) => ({ ...f, reviewed_by: e.target.value }))}
                fullWidth />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField label="Retest Date (if applicable)" type="date" value={docForm.retest_date || ""}
                onChange={(e) => setDocForm((f: any) => ({ ...f, retest_date: e.target.value }))}
                fullWidth slotProps={{ inputLabel: { shrink: true } }} />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField label="Executive Summary" value={docForm.executive_summary || ""}
                onChange={(e) => setDocForm((f: any) => ({ ...f, executive_summary: e.target.value }))}
                fullWidth multiline rows={8}
                placeholder="Provide a high-level summary of the engagement objectives, approach, key findings, and overall risk posture for leadership and non-technical audiences…" />
            </Grid>
          </Grid>
        )}

        {/* ── Tab 1: Scope & Methodology ────────────────────────────────── */}
        {tab === 1 && (
          <Grid container spacing={3}>
            <Grid size={{ xs: 12, sm: 4 }}>
              <FormControl fullWidth>
                <InputLabel>Engagement Type</InputLabel>
                <Select value={scopeForm.engagement_type || "Black Box"} label="Engagement Type"
                  onChange={(e) => setScopeForm((f: any) => ({ ...f, engagement_type: e.target.value }))}>
                  {["Black Box", "Grey Box", "White Box", "Red Team"].map((t) => (
                    <MenuItem key={t} value={t}>{t}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <TextField label="Period Start" type="date" value={scopeForm.period_start || ""}
                onChange={(e) => setScopeForm((f: any) => ({ ...f, period_start: e.target.value }))}
                fullWidth slotProps={{ inputLabel: { shrink: true } }} />
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <TextField label="Period End" type="date" value={scopeForm.period_end || ""}
                onChange={(e) => setScopeForm((f: any) => ({ ...f, period_end: e.target.value }))}
                fullWidth slotProps={{ inputLabel: { shrink: true } }} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <ChipList
                label="In-Scope Assets"
                items={scopeForm.in_scope || []}
                onAdd={(v) => setScopeForm((f: any) => ({ ...f, in_scope: [...(f.in_scope || []), v] }))}
                onRemove={(i) => setScopeForm((f: any) => ({ ...f, in_scope: f.in_scope.filter((_: any, idx: number) => idx !== i) }))}
                placeholder="e.g. https://app.example.com (press Enter to add)"
              />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <ChipList
                label="Out-of-Scope Items"
                items={scopeForm.out_of_scope || []}
                onAdd={(v) => setScopeForm((f: any) => ({ ...f, out_of_scope: [...(f.out_of_scope || []), v] }))}
                onRemove={(i) => setScopeForm((f: any) => ({ ...f, out_of_scope: f.out_of_scope.filter((_: any, idx: number) => idx !== i) }))}
                placeholder="e.g. Third-party APIs (press Enter to add)"
              />
            </Grid>

            <Grid size={{ xs: 12 }}>
              <Divider sx={{ my: 1 }} />
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
                Methodology Phases
              </Typography>
              <Box sx={{ display: "flex", gap: 1, mb: 1, flexWrap: "wrap" }}>
                <TextField size="small" label="Phase Name" value={phaseInput.name}
                  onChange={(e) => setPhaseInput((p) => ({ ...p, name: e.target.value }))}
                  sx={{ flex: 1, minWidth: 180 }} />
                <TextField size="small" label="Description" value={phaseInput.description}
                  onChange={(e) => setPhaseInput((p) => ({ ...p, description: e.target.value }))}
                  sx={{ flex: 2, minWidth: 240 }} />
                <Button variant="outlined" size="small" startIcon={<Add />}
                  onClick={() => {
                    if (phaseInput.name.trim()) {
                      setMethForm((f: any) => ({ ...f, phases: [...(f.phases || []), { ...phaseInput }] }));
                      setPhaseInput({ name: "", description: "" });
                    }
                  }}>
                  Add Phase
                </Button>
              </Box>
              {(methForm.phases || []).map((phase: any, i: number) => (
                <Box key={i} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5,
                  p: 1, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1 }}>
                  <Typography variant="caption" color="text.disabled" sx={{ minWidth: 24 }}>
                    {i + 1}.
                  </Typography>
                  <Typography sx={{ fontWeight: 600, minWidth: 120 }}>{phase.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ flex: 1 }}>
                    {phase.description}
                  </Typography>
                  <IconButton size="small" onClick={() =>
                    setMethForm((f: any) => ({ ...f, phases: f.phases.filter((_: any, idx: number) => idx !== i) }))}>
                    <Delete fontSize="small" />
                  </IconButton>
                </Box>
              ))}
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <ChipList
                label="Tools Used"
                items={methForm.tools || []}
                onAdd={(v) => setMethForm((f: any) => ({ ...f, tools: [...(f.tools || []), v] }))}
                onRemove={(i) => setMethForm((f: any) => ({ ...f, tools: f.tools.filter((_: any, idx: number) => idx !== i) }))}
                placeholder="e.g. Burp Suite, Nmap (press Enter)"
              />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <ChipList
                label="Standards Referenced"
                items={methForm.standards || []}
                onAdd={(v) => setMethForm((f: any) => ({ ...f, standards: [...(f.standards || []), v] }))}
                onRemove={(i) => setMethForm((f: any) => ({ ...f, standards: f.standards.filter((_: any, idx: number) => idx !== i) }))}
                placeholder="e.g. OWASP Top 10, PTES (press Enter)"
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField label="Conclusion" value={conclusionForm}
                onChange={(e) => setConclusionForm(e.target.value)}
                fullWidth multiline rows={5}
                placeholder="Summarise the overall security posture, key risk areas, and recommended next steps…" />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField label="Appendices" value={appendicesForm}
                onChange={(e) => setAppendicesForm(e.target.value)}
                fullWidth multiline rows={4}
                placeholder="Additional references, glossary, supporting evidence list…" />
            </Grid>
          </Grid>
        )}

        {/* ── Tab 2: Findings ──────────────────────────────────────────────── */}
        {tab === 2 && (
          <Box>
            {/* Stats */}
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2, justifyContent: "space-between", alignItems: "center" }}>
              <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
                {["critical", "high", "medium", "low", "informational"].map((s) => (
                  (fc[s] || 0) > 0 && (
                    <Chip key={s} size="small"
                      label={`${s.charAt(0).toUpperCase() + s.slice(1)}: ${fc[s] || 0}`}
                      sx={{ bgcolor: SEV_COLORS[s], color: "#fff", fontWeight: 700 }} />
                  )
                ))}
              </Stack>
              <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
                {Object.entries(retestCounts).map(([k, v]) =>
                  v > 0 ? (
                    <Chip key={k} size="small"
                      label={`${k.replace("_", " ")}: ${v}`}
                      sx={{ bgcolor: RETEST_COLORS[k] || "#757575", color: "#fff", fontWeight: 600 }} />
                  ) : null
                )}
              </Stack>
              <Button variant="contained" startIcon={<Add />}
                onClick={() => { setEditFinding(null); setFindingDialogOpen(true); }}
                sx={{ bgcolor: "#1A237E", "&:hover": { bgcolor: "#283593" } }}>
                Add Finding
              </Button>
            </Box>

            {sortedFindings.length === 0 ? (
              <Box sx={{ textAlign: "center", py: 6, border: "2px dashed rgba(255,255,255,0.1)", borderRadius: 2 }}>
                <Shield sx={{ fontSize: 56, color: "text.disabled", mb: 1 }} />
                <Typography color="text.secondary">No findings yet. Click "Add Finding" to document vulnerabilities.</Typography>
              </Box>
            ) : (
              <TableContainer component={Paper} sx={{ bgcolor: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.08)" }}>
                <Table>
                  <TableHead>
                    <TableRow sx={{ bgcolor: "rgba(26,35,126,0.2)" }}>
                      {["ID", "Severity", "Title", "Asset", "Retest", "Actions"].map((h) => (
                        <TableCell key={h} sx={{ fontWeight: 700, color: "text.secondary", fontSize: "0.78rem" }}>{h}</TableCell>
                      ))}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {sortedFindings.map((f: any) => (
                      <TableRow key={f.id} hover>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: "0.82rem", color: "text.secondary" }}>
                          {f.finding_id || "—"}
                        </TableCell>
                        <TableCell><SeverityChip severity={f.severity} /></TableCell>
                        <TableCell sx={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          <Typography sx={{ fontSize: "0.85rem", fontWeight: 500 }}>{f.title}</Typography>
                        </TableCell>
                        <TableCell sx={{ fontSize: "0.82rem", color: "text.secondary", maxWidth: 160,
                          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {f.affected_asset || "—"}
                        </TableCell>
                        <TableCell><RetestChip status={f.retest_status} /></TableCell>
                        <TableCell>
                          <Box sx={{ display: "flex", gap: 0.5 }}>
                            <Tooltip title="Edit">
                              <IconButton size="small" onClick={() => { setEditFinding(f); setFindingDialogOpen(true); }}>
                                <Edit fontSize="small" />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Delete">
                              <IconButton size="small" sx={{ color: "error.main" }}
                                onClick={() => setDeleteFindingTarget(f.id)}>
                                <Delete fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>
        )}

        {/* ── Tab 3: Export & History ──────────────────────────────────────── */}
        {tab === 3 && (
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Export Report</Typography>
            <Grid container spacing={2} sx={{ mb: 4 }}>
              {[
                {
                  format: "pdf",
                  icon: <PictureAsPdf sx={{ fontSize: 40, color: "#C62828" }} />,
                  title: "Full Report PDF",
                  desc: "Complete VAPT report with all sections, findings, and remediation roadmap",
                },
                {
                  format: "docx",
                  icon: <Description sx={{ fontSize: 40, color: "#1565C0" }} />,
                  title: "Full Report DOCX",
                  desc: "Microsoft Word format for editing, commenting, and track-changes collaboration",
                },
                {
                  format: "remediation-pdf",
                  icon: <PictureAsPdf sx={{ fontSize: 40, color: "#E64A19" }} />,
                  title: "Remediation Plan PDF",
                  desc: "Actionable remediation steps, prioritised action table, and sign-off sheet",
                },
                {
                  format: "remediation-docx",
                  icon: <Description sx={{ fontSize: 40, color: "#2E7D32" }} />,
                  title: "Remediation Plan DOCX",
                  desc: "Editable remediation action plan for technical and management teams",
                },
              ].map((ex) => (
                <Grid key={ex.format} size={{ xs: 12, sm: 6 }}>
                  <Card sx={{ bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.1)", height: "100%" }}>
                    <CardContent sx={{ textAlign: "center", pb: 0 }}>
                      {ex.icon}
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, mt: 1 }}>
                        {ex.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                        {ex.desc}
                      </Typography>
                    </CardContent>
                    <CardActions sx={{ justifyContent: "center", pt: 1, pb: 2 }}>
                      <Button variant="contained" startIcon={<FileDownload />}
                        onClick={() => downloadExport(ex.format)}
                        sx={{
                          bgcolor: ex.format === "pdf" ? "#C62828"
                            : ex.format === "docx" ? "#1565C0"
                            : ex.format === "remediation-pdf" ? "#E64A19"
                            : "#2E7D32",
                          "&:hover": { opacity: 0.9 },
                        }}>
                        Download
                      </Button>
                    </CardActions>
                  </Card>
                </Grid>
              ))}
            </Grid>

            {/* Version history */}
            {report.parent_report_id && (
              <Box>
                <Divider sx={{ mb: 2 }} />
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>Version History</Typography>
                <Alert severity="info">
                  This is a retest version. Parent report ID: <strong>{report.parent_report_id.slice(0, 8)}…</strong>
                </Alert>
              </Box>
            )}
          </Box>
        )}
      </Box>

      {/* ── Finding dialog ────────────────────────────────────────────────── */}
      <FindingDialog
        open={findingDialogOpen}
        onClose={() => { setFindingDialogOpen(false); setEditFinding(null); }}
        onSave={handleFindingSave}
        initialData={editFinding}
        existingCount={(report.findings || []).length}
        loading={isFindingLoading}
      />

      {/* ── Delete finding confirm ────────────────────────────────────────── */}
      <Dialog open={!!deleteFindingTarget} onClose={() => setDeleteFindingTarget(null)} maxWidth="xs" fullWidth>
        <DialogTitle sx={{ color: "error.main" }}>Delete Finding</DialogTitle>
        <DialogContent>
          <Typography>Delete this finding permanently?</Typography>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setDeleteFindingTarget(null)}>Cancel</Button>
          <Button variant="contained" color="error"
            disabled={deleteFindingMutation.isPending}
            onClick={() => deleteFindingTarget && deleteFindingMutation.mutate(deleteFindingTarget)}>
            {deleteFindingMutation.isPending ? "Deleting…" : "Delete"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Retest confirm ────────────────────────────────────────────────── */}
      <Dialog open={retestConfirmOpen} onClose={() => setRetestConfirmOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create Retest Version</DialogTitle>
        <DialogContent>
          <Typography>
            This will create a new report version <strong>v{report.version ? (parseFloat(report.version) + 0.1).toFixed(1) : "1.1"}</strong> with all findings copied. All finding retest statuses will be reset to <strong>Pending</strong>.
          </Typography>
          <Alert severity="info" sx={{ mt: 2 }}>
            The original report (v{report.version}) will remain unchanged.
          </Alert>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setRetestConfirmOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={() => retestMutation.mutate()}
            disabled={retestMutation.isPending}
            sx={{ bgcolor: "#1A237E", "&:hover": { bgcolor: "#283593" } }}>
            {retestMutation.isPending ? "Creating…" : "Create Retest Version"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
