import React, { useState } from "react";
import {
  Box, Typography, Button, Chip, IconButton, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, Paper, Dialog,
  DialogTitle, DialogContent, DialogActions, TextField, Select,
  MenuItem, FormControl, InputLabel, Tooltip, Alert, CircularProgress,
  Stack, Badge,
} from "@mui/material";
import {
  GppGood, Add, Visibility, Delete, Security, CheckCircle,
  HourglassEmpty, Shield,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useActiveClient } from "../contexts/ClientContext";
import { vaptApi } from "../services/api";

const SEV_COLORS: Record<string, string> = {
  critical: "#C62828",
  high: "#E64A19",
  medium: "#F9A825",
  low: "#2E7D32",
  informational: "#1565C0",
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

export default function VAPTReports() {
  const navigate = useNavigate();
  const { clientId } = useActiveClient();
  const qc = useQueryClient();

  const [createOpen, setCreateOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [form, setForm] = useState({
    title: "",
    classification: "Confidential",
    version: "1.0",
    prepared_by: "",
    report_date: new Date().toISOString().slice(0, 10),
  });

  const { data: reports = [], isLoading, error } = useQuery({
    queryKey: ["vapt-reports", clientId],
    queryFn: () => vaptApi.list(clientId!),
    enabled: !!clientId,
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => vaptApi.create(clientId!, data),
    onSuccess: (newReport) => {
      qc.invalidateQueries({ queryKey: ["vapt-reports", clientId] });
      setCreateOpen(false);
      setForm({ title: "", classification: "Confidential", version: "1.0", prepared_by: "", report_date: new Date().toISOString().slice(0, 10) });
      navigate(`/vapt-reports/${newReport.id}`);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (rid: string) => vaptApi.delete(clientId!, rid),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vapt-reports", clientId] });
      setDeleteTarget(null);
    },
  });

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

      {/* Error */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Failed to load VAPT reports.
        </Alert>
      )}

      {/* Loading */}
      {isLoading && (
        <Box sx={{ textAlign: "center", py: 6 }}>
          <CircularProgress />
        </Box>
      )}

      {/* Empty state */}
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
            Create your first report to start documenting security assessment findings.
          </Typography>
          <Button variant="outlined" startIcon={<Add />} onClick={() => setCreateOpen(true)}>
            Create First Report
          </Button>
        </Box>
      )}

      {/* Reports table */}
      {!isLoading && reports.length > 0 && (
        <TableContainer component={Paper} sx={{ bgcolor: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)" }}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: "rgba(26,35,126,0.2)" }}>
                {["Title", "Version", "Classification", "Status", "Report Date", "Findings", "Actions"].map((h) => (
                  <TableCell key={h} sx={{ fontWeight: 700, color: "text.secondary", fontSize: "0.78rem", py: 1.5 }}>
                    {h}
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {reports.map((report: any) => {
                const fc = report.finding_counts || {};
                const hasCritical = (fc.critical || 0) > 0;
                const hasHigh = (fc.high || 0) > 0;
                return (
                  <TableRow
                    key={report.id}
                    hover
                    sx={{ cursor: "pointer", "&:hover": { bgcolor: "rgba(255,255,255,0.04)" } }}
                    onClick={() => navigate(`/vapt-reports/${report.id}`)}
                  >
                    <TableCell>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        {hasCritical && <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: "#C62828", flexShrink: 0 }} />}
                        <Typography sx={{ fontWeight: 600, fontSize: "0.88rem" }}>
                          {report.title}
                        </Typography>
                      </Box>
                      {report.parent_report_id && (
                        <Typography variant="caption" color="text.disabled">
                          Retest version
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={`v${report.version}`}
                        size="small"
                        sx={{ bgcolor: "rgba(21,101,192,0.15)", color: "#90CAF9", fontWeight: 700 }}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={report.classification}
                        size="small"
                        variant="outlined"
                        sx={{ borderColor: "rgba(255,255,255,0.2)", fontSize: "0.72rem" }}
                      />
                    </TableCell>
                    <TableCell>
                      <StatusChip status={report.status} />
                    </TableCell>
                    <TableCell sx={{ fontSize: "0.82rem", color: "text.secondary" }}>
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
                          <IconButton size="small" onClick={() => navigate(`/vapt-reports/${report.id}`)}>
                            <Visibility fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton
                            size="small"
                            onClick={() => setDeleteTarget(report.id)}
                            sx={{ color: "error.main" }}
                          >
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
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ fontWeight: 700 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <GppGood sx={{ color: "#1565C0" }} />
            New VAPT Report
          </Box>
        </DialogTitle>
        <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2, pt: 2 }}>
          <TextField
            label="Report Title"
            required
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
            label="Version"
            value={form.version}
            onChange={(e) => setForm((f) => ({ ...f, version: e.target.value }))}
            fullWidth
            placeholder="1.0"
          />
          <TextField
            label="Prepared By"
            value={form.prepared_by}
            onChange={(e) => setForm((f) => ({ ...f, prepared_by: e.target.value }))}
            fullWidth
            placeholder="Author / team name"
          />
          <TextField
            label="Report Date"
            type="date"
            value={form.report_date}
            onChange={(e) => setForm((f) => ({ ...f, report_date: e.target.value }))}
            fullWidth
            slotProps={{ inputLabel: { shrink: true } }}
          />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={() => createMutation.mutate(form)}
            disabled={!form.title.trim() || createMutation.isPending}
            sx={{ bgcolor: "#1A237E", "&:hover": { bgcolor: "#283593" } }}
          >
            {createMutation.isPending ? "Creating…" : "Create Report"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete confirm dialog */}
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
