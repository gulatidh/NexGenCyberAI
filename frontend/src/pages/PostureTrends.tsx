import React, { useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Box, Typography, Button, Alert, CircularProgress, Card, CardContent,
  Grid, Chip, Table, TableHead, TableRow, TableCell, TableBody,
  TableContainer,
} from "@mui/material";
import { Refresh, TrendingUp, CheckCircle, Cancel } from "@mui/icons-material";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, AreaChart, Area,
} from "recharts";
import { postureApi } from "../services/api";
import { toast } from "react-toastify";

// ── Types ────────────────────────────────────────────────────────────────────

interface PostureSnapshot {
  id: string;
  captured_at: string;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  open_risks: number;
  mttr_critical_hours: number | null;
  mttr_high_hours: number | null;
  compliance_score: number | null;
  scan_count_30d: number;
  agent_runs_30d: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function fmtHours(h: number | null): string {
  if (h == null) return "—";
  if (h < 1) return `${Math.round(h * 60)}m`;
  if (h < 24) return `${h.toFixed(1)}h`;
  return `${(h / 24).toFixed(1)}d`;
}

const SLA_CRITICAL_H = 24;
const SLA_HIGH_H = 168; // 7 days

// ── Day selector ──────────────────────────────────────────────────────────────

const DAY_OPTIONS = [30, 60, 90, 180];

// ── MTTR Summary Table ────────────────────────────────────────────────────────

function MttrTable({ latest, prev }: { latest: PostureSnapshot | null; prev: PostureSnapshot | null }) {
  if (!latest) return null;

  const rows = [
    {
      label: "Critical",
      current: latest.mttr_critical_hours,
      previous: prev?.mttr_critical_hours ?? null,
      sla: SLA_CRITICAL_H,
      slaLabel: "< 24h",
    },
    {
      label: "High",
      current: latest.mttr_high_hours,
      previous: prev?.mttr_high_hours ?? null,
      sla: SLA_HIGH_H,
      slaLabel: "< 7d",
    },
  ];

  return (
    <TableContainer component={Card} variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow>
            {["Severity", "Current MTTR", "Previous MTTR", "Trend", "SLA Target", "SLA Status"].map((h) => (
              <TableCell key={h} sx={{ fontWeight: 700, fontSize: 11, color: "text.secondary" }}>
                {h}
              </TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((row) => {
            const withinSla = row.current != null && row.current < row.sla;
            const improving =
              row.current != null &&
              row.previous != null &&
              row.current < row.previous;
            const worsening =
              row.current != null &&
              row.previous != null &&
              row.current > row.previous;

            return (
              <TableRow key={row.label} hover>
                <TableCell sx={{ fontWeight: 600 }}>{row.label}</TableCell>
                <TableCell sx={{ fontFamily: "monospace" }}>{fmtHours(row.current)}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", color: "text.secondary" }}>
                  {fmtHours(row.previous)}
                </TableCell>
                <TableCell>
                  {improving && (
                    <Chip label="Improving" size="small"
                      sx={{ bgcolor: "rgba(52,168,83,0.15)", color: "#34A853", fontSize: 10, height: 18 }} />
                  )}
                  {worsening && (
                    <Chip label="Worsening" size="small"
                      sx={{ bgcolor: "rgba(244,67,54,0.15)", color: "#f44336", fontSize: 10, height: 18 }} />
                  )}
                  {!improving && !worsening && (
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>—</Typography>
                  )}
                </TableCell>
                <TableCell>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    {row.slaLabel}
                  </Typography>
                </TableCell>
                <TableCell>
                  {row.current == null ? (
                    <Typography variant="caption" sx={{ color: "text.disabled" }}>No data</Typography>
                  ) : withinSla ? (
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                      <CheckCircle sx={{ fontSize: 14, color: "#34A853" }} />
                      <Typography variant="caption" sx={{ color: "#34A853" }}>Met</Typography>
                    </Box>
                  ) : (
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                      <Cancel sx={{ fontSize: 14, color: "#f44336" }} />
                      <Typography variant="caption" sx={{ color: "#f44336" }}>Breached</Typography>
                    </Box>
                  )}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function PostureTrends() {
  const qc = useQueryClient();
  const { clientId } = useActiveClient();
  const [days, setDays] = useState(90);

  const { data: snapshots = [], isLoading, isError, error } = useQuery<PostureSnapshot[]>({
    queryKey: ["posture-history", clientId, days],
    queryFn: () => postureApi.getHistory(clientId, days),
    enabled: !!clientId,
  });

  const snapshotMut = useMutation({
    mutationFn: () => postureApi.triggerSnapshot(clientId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["posture-history", clientId] });
      toast.success("Snapshot captured");
    },
    onError: () => toast.error("Failed to capture snapshot"),
  });

  // Sorted ascending for charts
  const sorted = [...snapshots].sort(
    (a, b) => new Date(a.captured_at).getTime() - new Date(b.captured_at).getTime()
  );

  const chartData = sorted.map((s) => ({
    date: fmtDate(s.captured_at),
    critical: s.critical_findings,
    high: s.high_findings,
    medium: s.medium_findings,
    low: s.low_findings,
    openRisks: s.open_risks,
    mttrCritical: s.mttr_critical_hours,
    mttrHigh: s.mttr_high_hours,
    compliance: s.compliance_score,
  }));

  const latest = sorted[sorted.length - 1] ?? null;
  const prev = sorted[sorted.length - 2] ?? null;

  const hasData = sorted.length > 0;

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Posture Trends
          </Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Track your security posture over time — findings, risks, MTTR, and compliance
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1.5, alignItems: "center" }}>
          {/* Day selector chips */}
          <Box sx={{ display: "flex", gap: 0.5 }}>
            {DAY_OPTIONS.map((d) => (
              <Chip
                key={d}
                label={`${d}d`}
                size="small"
                clickable
                onClick={() => setDays(d)}
                sx={{
                  bgcolor: days === d ? "rgba(66,133,244,0.25)" : "rgba(255,255,255,0.06)",
                  color: days === d ? "#82b1ff" : "text.secondary",
                  border: days === d ? "1px solid rgba(66,133,244,0.5)" : "1px solid transparent",
                  fontWeight: days === d ? 700 : 400,
                }}
              />
            ))}
          </Box>
          <Button
            size="small"
            variant="outlined"
            startIcon={
              snapshotMut.isPending ? (
                <CircularProgress size={14} />
              ) : (
                <Refresh sx={{ fontSize: 16 }} />
              )
            }
            disabled={!clientId || snapshotMut.isPending}
            onClick={() => snapshotMut.mutate()}
            sx={{
              textTransform: "none",
              borderColor: "divider",
              color: "text.secondary",
              "&:hover": { borderColor: "#4285F4", color: "#4285F4" },
            }}
          >
            Take Snapshot Now
          </Button>
        </Box>
      </Box>

      {!clientId && (
        <Alert severity="info">Select a client to view posture trends.</Alert>
      )}

      {clientId && isError && (
        <Alert severity="error">
          Failed to load posture history:{" "}
          {(error as any)?.response?.data?.detail ||
            (error as Error).message ||
            "Unknown error"}
        </Alert>
      )}

      {clientId && isLoading && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      )}

      {clientId && !isLoading && !isError && !hasData && (
        <Card
          variant="outlined"
          sx={{ p: 6, textAlign: "center", borderStyle: "dashed" }}
        >
          <TrendingUp sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No snapshots yet. Click "Take Snapshot Now" to start tracking posture over time.
          </Typography>
        </Card>
      )}

      {clientId && !isLoading && hasData && (
        <>
          {/* Row 1 — Open Findings + Open Risks */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid size={{ xs: 12, md: 6 }}>
              <Card variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>
                  Open Findings Over Time
                </Typography>
                <ResponsiveContainer width="100%" height={240}>
                  <AreaChart data={chartData} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                    <XAxis dataKey="date" tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} />
                    <YAxis tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 4 }}
                      labelStyle={{ color: "#fff" }}
                    />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Area type="monotone" dataKey="critical" stackId="1" name="Critical"
                      stroke="#f44336" fill="#f4433640" />
                    <Area type="monotone" dataKey="high" stackId="1" name="High"
                      stroke="#ff9800" fill="#ff980040" />
                    <Area type="monotone" dataKey="medium" stackId="1" name="Medium"
                      stroke="#ffeb3b" fill="#ffeb3b40" />
                    <Area type="monotone" dataKey="low" stackId="1" name="Low"
                      stroke="#4caf50" fill="#4caf5040" />
                  </AreaChart>
                </ResponsiveContainer>
              </Card>
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <Card variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>
                  Open Risks Over Time
                </Typography>
                <ResponsiveContainer width="100%" height={240}>
                  <AreaChart data={chartData} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                    <XAxis dataKey="date" tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} />
                    <YAxis tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 4 }}
                      labelStyle={{ color: "#fff" }}
                    />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Area type="monotone" dataKey="openRisks" name="Open Risks"
                      stroke="#4285F4" fill="#4285F440" />
                  </AreaChart>
                </ResponsiveContainer>
              </Card>
            </Grid>
          </Grid>

          {/* Row 2 — MTTR + Compliance */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid size={{ xs: 12, md: 6 }}>
              <Card variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>
                  MTTR (hours) by Severity
                </Typography>
                <ResponsiveContainer width="100%" height={240}>
                  <LineChart data={chartData} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                    <XAxis dataKey="date" tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} />
                    <YAxis tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} unit="h" />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 4 }}
                      labelStyle={{ color: "#fff" }}
                      formatter={(v: any) => (v == null ? "—" : `${Number(v).toFixed(1)}h`)}
                    />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Line type="monotone" dataKey="mttrCritical" name="Critical MTTR"
                      stroke="#f44336" dot={{ r: 3 }} connectNulls />
                    <Line type="monotone" dataKey="mttrHigh" name="High MTTR"
                      stroke="#ff9800" dot={{ r: 3 }} connectNulls />
                  </LineChart>
                </ResponsiveContainer>
              </Card>
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <Card variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>
                  Compliance Score Over Time (%)
                </Typography>
                <ResponsiveContainer width="100%" height={240}>
                  <LineChart data={chartData} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                    <XAxis dataKey="date" tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} />
                    <YAxis domain={[0, 100]} tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} unit="%" />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 4 }}
                      labelStyle={{ color: "#fff" }}
                      formatter={(v: any) => (v == null ? "—" : `${Number(v).toFixed(1)}%`)}
                    />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Line type="monotone" dataKey="compliance" name="Compliance Score"
                      stroke="#34A853" dot={{ r: 3 }} connectNulls />
                  </LineChart>
                </ResponsiveContainer>
              </Card>
            </Grid>
          </Grid>

          {/* MTTR summary table */}
          <Box sx={{ mb: 1 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>
              MTTR Summary (Latest Snapshot)
            </Typography>
            <MttrTable latest={latest} prev={prev} />
          </Box>
        </>
      )}
    </Box>
  );
}
