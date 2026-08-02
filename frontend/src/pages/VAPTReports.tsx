import React, { useState } from "react";
import {
  Box, Typography, Button, Chip, IconButton, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, Paper, Dialog,
  DialogTitle, DialogContent, DialogActions, TextField, Select,
  MenuItem, FormControl, InputLabel, Tooltip, Alert, CircularProgress,
  Stack, Divider, LinearProgress,
} from "@mui/material";
import {
  GppGood, Add, Visibility, Delete, Security, CheckCircle,
  HourglassEmpty, Shield, AutoAwesome, Article,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useLocation } from "react-router-dom";
import { useActiveClient } from "../contexts/ClientContext";
import { vaptApi, scansApi } from "../services/api";

const SEV_COLORS: Record<string, string> = {
  critical: "#C62828",
  high: "#E64A19",
  medium: "#F9A825",
  low: "#2E7D32",
  informational: "#1565C0",
};

const SCAN_TYPE_LABEL: Record<string, string> = {
  web: "Web App (ZAP)",
  semgrep: "SAST (Semgrep)",
  codeql: "SAST (CodeQL)",
  sonarqube: "SAST (SonarQube)",
  nmap: "Network (Nmap)",
  openvas: "Network (OpenVAS)",
  trivy: "Container (Trivy)",
  gitleaks: "Secrets (Gitleaks)",
  trufflehog: "Secrets (TruffleHog)",
  owasp_dc: "Dependencies (OWASP DC)",
  ai_code_review: "AI Code Review",
};

function SeverityBadge({ count, severity }: { count: number; severity: string }) {
  if (!count) return null;
  return (
    <Chip
      label={`${severity.charAt(0).toUpperCase() + severity.slice(1)}: ${count}`}
      size="small"
      sx={{
        bgcolor: SEV_COLORS[severity] || "#757575",
        color: "#fff",
        fontWeight: 700,
        fontSize: "0.7rem",
        mr: 0.5,
      }}
    />
  );
}

function StatusChip({ status }: { status: string }) {
  const isDraft = status === "draft";
  return (
    <Chip
      label={isDraft ? "Draft" : "Final"}
      size="small"
      icon={isDraft ? <HourglassEmpty sx={{ fontSize: 14 }} /> : <CheckCircle sx={{ fontSize: 14 }} />}
      sx={{
        bgcolor: isDraft ? "rgba(120,120,120,0.15)" : "rgba(46,125,50,0.15)",
        color: isDraft ? "#9E9E9E" : "#4CAF50",
        border: `1px solid ${isDraft ? "rgba(120,120,120,0.3)" : "rgba(76,175,80,0.3)"}`,
        fontWeight: 600,
        fontSize: "0.72rem",
      }}
    />
  );
}

const EMPTY_FORM = {
  title: "",
  classification: "Confidential",
  version: "1.0",
  prepared_by: "",
  report_date: new Date().toISOString().slice(0, 10),
};

export default function VAPTReports() {
  const navigate = useNavigate();
  const location = useLocation();
  const vaptBase = location.pathname.startsWith("/vapt") ? "/vapt/reports" : "/vapt-reports";
  const { clientId } = useActiveClient();
  const qc = useQueryClient();

  const [createOpen, setCreateOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [mode, setMode] = useState<"scan" | "blank">("scan");
  const [selectedScanId, setSelectedScanId] = useState("");
  const [form, setForm] = useState(EMPTY_FORM);

  const { data: reports = [], isLoading, error } = useQuery({
    queryKey: ["vapt-reports", clientId],
    queryFn: () => vaptApi.list(clientId!),
    enabled: !!clientId,
  });

  const { data: scans = [] } = useQuery({
    queryKey: ["scans", clientId],
    queryFn: () => scansApi.list(clientId!),
    enabled: !!clientId && createOpen,
  });

  const completedScans = (scans as any[]).filter(
    (s: any) => s.status === "completed" && s.is_live !== false
  );

  const createFromScanMutation = useMutation({
    mutationFn: (data: any) => vaptApi.createFromScan(clientId!, data),
    onSuccess: (newReport) => {
      qc.invalidateQueries({ queryKey: ["vapt-reports", clientId] });
      handleClose();
      navigate(`${vaptBase}/${newReport.id}`);
    },
  });

  const createBlankMutation = useMutation({
    mutationFn: (data: any) => vaptApi.create(clientId!, data),
    onSuccess: (newReport) => {
      qc.invalidateQueries({ queryKey: ["vapt-reports", clientId] });
      handleClose();
      navigate(`${vaptBase}/${newReport.id}`);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (rid: string) => vaptApi.delete(clientId!, rid),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vapt-reports", clientId] });
      setDeleteTarget(null);
    },
  });

  const handleClose = () => {
    setCreateOpen(false);
    setMode("scan");
    setSelectedScanId("");
    setForm(EMPTY_FORM);
  };

  const handleSubmit = () => {
    if (mode === "scan") {
      completedScans.find((s: any) => s.id === selectedScanId);
      createFromScanMutation.mutate({
        scan_id: selectedScanId,
        title: form.title || undefined,
        classification: form.classification,
        prepared_by: form.prepared_by || undefined,
      });
    } else {
      createBlankMutation.mutate(form);
    }
  };

  const isPending = createFromScanMutation.isPending || createBlankMutation.isPending;
  const mutationError = createFromScanMutation.error || createBlankMutation.error;

  const totalReports = reports.length;
  const draftCount = reports.filter((r: any) => r.status === "draft").length;
  const finalCount = reports.filter((r: any) => r.status === "final").length;

  if (!clientId) {
    return (
      <Box sx={{ p: 4, textAlign: "center" }}>
        <Shield sx={{ fontSize: 64, color: "text.disabled", mb: 2 }} />
        <Typography color="text.secondary">
          Select a client from the top bar to view VAPT reports.
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
          <GppGood sx={{ fontSize: 36, color: "#1565C0" }} />
          <Box>
            <Typography variant="h5" sx={{ fontWeight: 700 }}>VAPT Reports</Typography>
            <Typography variant="body2" color="text.secondary">
              Vulnerability Assessment &amp; Penetration Testing reports
            </Typography>
          </Box>
        </Box>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => setCreateOpen(true)}
          sx={{ bgcolor: "#1A237E", "&:hover": { bgcolor: "#283593" } }}
        >
          New Report
        </Button>
      </Box>

      {/* Stats */}
      <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
        <Chip
          icon={<Security />}
          label={`${totalReports} Total`}
          sx={{ bgcolor: "rgba(21,101,192,0.1)", color: "#1565C0", fontWeight: 700 }}
        />
        <Chip
          icon={<HourglassEmpty />}
          label={`${draftCount} Draft`}
          sx={{ bgcolor: "rgba(120,120,120,0.1)", color: "#9E9E9E", fontWeight: 700 }}
        />
        <Chip
          icon={<CheckCircle />}
          label={`${finalCount} Final`}
          sx={{ bgcolor: "rgba(46,125,50,0.1)", color: "#4CAF50", fontWeight: 700 }}
        />
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 2 }}>Failed to load VAPT reports.</Alert>}

      {isLoading && <Box sx={{ textAlign: "center", py: 6 }}><CircularProgress /></Box>}

      {!isLoading && reports.length === 0 && (
        <Box sx={{
          textAlign: "center", py: 8, border: "2px dashed rgba(255,255,255,0.1)",
          borderRadius: 2, bgcolor: "rgba(255,255,255,0.02)",
        }}>
          <GppGood sx={{ fontSize: 72, color: "text.disabled", mb: 2 }} />
          <Typography variant="h6" color="text.secondary" gutterBottom>
            No VAPT reports yet
          </Typography>
          <Typography variant="body2" color="text.disabled" sx={{ mb: 3 }}>
            Generate a report from a completed scan — Monitara fills in scope, findings, and AI-generated remediation automatically.
          </Typography>
          <Button variant="outlined" startIcon={<Add />} onClick={() => setCreateOpen(true)}>
            Create First Report
          </Button>
        </Box>
      )}

      {!isLoading && reports.length > 0 && (
        <TableContainer component={Paper} sx={{ bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)" }}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: "rgba(26,35,126,0.2)" }}>
                {["Report / Scan", "Version", "Status", "Date", "Findings", "Actions"].map((h) => (
                  <TableCell key={h} sx={{ fontWeight: 700, color: "text.secondary", fontSize: "0.78rem", py: 1.5 }}>
                    {h}
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {(reports as any[]).map((report: any) => {
                const fc = report.finding_counts || {};
                const hasCritical = (fc.critical || 0) > 0;
                const scanLabel = [report.connector_name, report.scan_name]
                  .filter(Boolean).join(" · ") || (report.scan_type ? report.scan_type.toUpperCase() : null);
                return (
                  <TableRow
                    key={report.id}
                    hover
                    sx={{ cursor: "pointer", "&:hover": { bgcolor: "rgba(255,255,255,0.04)" } }}
                    onClick={() => navigate(`${vaptBase}/${report.id}`)}
                  >
                    <TableCell>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        {hasCritical && <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: "#C62828", flexShrink: 0 }} />}
                        <Box>
                          <Typography sx={{ fontWeight: 600, fontSize: "0.88rem" }}>{report.title}</Typography>
                          {scanLabel && (
                            <Typography variant="caption" color="text.disabled" sx={{ display: "block" }}>
                              {scanLabel}
                            </Typography>
                          )}
                          {report.parent_report_id && (
                            <Typography variant="caption" sx={{ color: "#90CAF9", display: "block" }}>Retest version</Typography>
                          )}
                        </Box>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                        <Chip label={`v${report.version}`} size="small"
                          sx={{ bgcolor: "rgba(21,101,192,0.15)", color: "#90CAF9", fontWeight: 700, alignSelf: "flex-start" }} />
                        <Chip label={report.classification} size="small" variant="outlined"
                          sx={{ borderColor: "rgba(255,255,255,0.2)", fontSize: "0.72rem", alignSelf: "flex-start" }} />
                      </Box>
                    </TableCell>
                    <TableCell><StatusChip status={report.status} /></TableCell>
                    <TableCell sx={{ fontSize: "0.82rem", color: "text.secondary", whiteSpace: "nowrap" }}>
                      {report.report_date
                        ? new Date(report.report_date).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })
                        : "—"}
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {(fc.critical || 0) > 0 && <SeverityBadge count={fc.critical} severity="critical" />}
                        {(fc.high || 0) > 0 && <SeverityBadge count={fc.high} severity="high" />}
                        {(fc.medium || 0) > 0 && <SeverityBadge count={fc.medium} severity="medium" />}
                        {(fc.low || 0) > 0 && <SeverityBadge count={fc.low} severity="low" />}
                        {(fc.informational || 0) > 0 && <SeverityBadge count={fc.informational} severity="informational" />}
                        {report.total_findings === 0 && (
                          <Typography variant="caption" color="text.disabled">No findings</Typography>
                        )}
                      </Box>
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Box sx={{ display: "flex", gap: 0.5 }}>
                        <Tooltip title="View / Edit">
                          <IconButton size="small" onClick={() => navigate(`${vaptBase}/${report.id}`)}>
                            <Visibility fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton size="small" onClick={() => setDeleteTarget(report.id)} sx={{ color: "error.main" }}>
                            <Delete fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Create dialog */}
      <Dialog open={createOpen} onClose={handleClose} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ fontWeight: 700 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <GppGood sx={{ color: "#1565C0" }} />
            New VAPT Report
          </Box>
        </DialogTitle>
        <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 0, pt: 1 }}>
          {/* Mode toggle */}
          <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
            <Button
              variant={mode === "scan" ? "contained" : "outlined"}
              startIcon={<AutoAwesome />}
              onClick={() => setMode("scan")}
              size="small"
              sx={mode === "scan" ? { bgcolor: "#1A237E" } : {}}
            >
              Generate from Scan
            </Button>
            <Button
              variant={mode === "blank" ? "contained" : "outlined"}
              startIcon={<Article />}
              onClick={() => setMode("blank")}
              size="small"
              sx={mode === "blank" ? { bgcolor: "#1A237E" } : {}}
            >
              Blank Report
            </Button>
          </Stack>

          {mode === "scan" && (
            <Alert severity="info" sx={{ mb: 2, fontSize: "0.82rem" }}>
              Monitara will import all findings from the selected scan, derive scope and methodology automatically,
              and use AI to generate executive summary, detailed remediation steps, and conclusion.
            </Alert>
          )}

          {/* Scan picker — only in scan mode */}
          {mode === "scan" && (
            <FormControl fullWidth sx={{ mb: 2 }} required>
              <InputLabel>Select Completed Scan</InputLabel>
              <Select
                value={selectedScanId}
                label="Select Completed Scan"
                onChange={(e) => {
                  setSelectedScanId(e.target.value);
                  const scan = completedScans.find((s: any) => s.id === e.target.value);
                  if (scan && !form.title) {
                    setForm((f) => ({ ...f, title: `VAPT Report — ${scan.name || scan.scan_type || "Scan"}` }));
                  }
                }}
              >
                {completedScans.length === 0 && (
                  <MenuItem disabled value="">No completed scans found</MenuItem>
                )}
                {completedScans.map((s: any) => {
                  const ct = s.connector?.connector_type || s.scan_type || "";
                  const label = SCAN_TYPE_LABEL[ct] || ct || "Scan";
                  const connectorName = s.connector?.name;
                  return (
                    <MenuItem key={s.id} value={s.id}>
                      <Box>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>
                          {s.name || `${label} — ${new Date(s.created_at).toLocaleDateString()}`}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {[connectorName, label].filter(Boolean).join(" · ")} ·{" "}
                          {new Date(s.created_at).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })} ·{" "}
                          {s.summary?.total || 0} findings
                        </Typography>
                      </Box>
                    </MenuItem>
                  );
                })}
              </Select>
            </FormControl>
          )}

          <Divider sx={{ mb: 2 }} />

          {/* Common fields */}
          <Stack spacing={2}>
            <TextField
              label={mode === "scan" ? "Report Title (optional — auto-generated if blank)" : "Report Title"}
              required={mode === "blank"}
              value={form.title}
              onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))}
              fullWidth
              placeholder="e.g. Web Application VAPT — Q2 2026"
            />
            <FormControl fullWidth>
              <InputLabel>Classification</InputLabel>
              <Select
                value={form.classification}
                label="Classification"
                onChange={(e) => setForm((f) => ({ ...f, classification: e.target.value }))}
              >
                {["Confidential", "Internal", "Public"].map((c) => (
                  <MenuItem key={c} value={c}>{c}</MenuItem>
                ))}
              </Select>
            </FormControl>
            <TextField
              label="Prepared By"
              value={form.prepared_by}
              onChange={(e) => setForm((f) => ({ ...f, prepared_by: e.target.value }))}
              fullWidth
              placeholder="Author / team name"
            />
            {mode === "blank" && (
              <TextField
                label="Version"
                value={form.version}
                onChange={(e) => setForm((f) => ({ ...f, version: e.target.value }))}
                fullWidth
                placeholder="1.0"
              />
            )}
          </Stack>

          {isPending && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="caption" color="text.secondary" sx={{ mb: 0.5, display: "block" }}>
                {mode === "scan"
                  ? "Importing findings and generating AI content — this may take 15–30 seconds…"
                  : "Creating report…"}
              </Typography>
              <LinearProgress />
            </Box>
          )}

          {mutationError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              Failed to create report. Please try again.
            </Alert>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={handleClose} disabled={isPending}>Cancel</Button>
          <Button
            variant="contained"
            startIcon={mode === "scan" ? <AutoAwesome /> : undefined}
            onClick={handleSubmit}
            disabled={
              isPending ||
              (mode === "scan" && !selectedScanId) ||
              (mode === "blank" && !form.title.trim())
            }
            sx={{ bgcolor: "#1A237E", "&:hover": { bgcolor: "#283593" } }}
          >
            {isPending
              ? mode === "scan" ? "Generating…" : "Creating…"
              : mode === "scan" ? "Generate Report" : "Create Report"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete confirm */}
      <Dialog open={!!deleteTarget} onClose={() => setDeleteTarget(null)} maxWidth="xs" fullWidth>
        <DialogTitle sx={{ color: "error.main" }}>Delete Report</DialogTitle>
        <DialogContent>
          <Typography>
            This will permanently delete the report and all its findings. This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setDeleteTarget(null)}>Cancel</Button>
          <Button
            variant="contained"
            color="error"
            onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget)}
            disabled={deleteMutation.isPending}
          >
            {deleteMutation.isPending ? "Deleting…" : "Delete"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
