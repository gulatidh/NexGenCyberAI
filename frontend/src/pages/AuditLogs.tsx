import React, { useState, useCallback } from "react";
import {
  Box, Typography, Chip, Table, TableHead, TableBody, TableRow, TableCell,
  TableContainer, Paper, Tooltip, LinearProgress, Alert, Button,
  TextField, InputAdornment, TablePagination,
} from "@mui/material";
import { ManageSearch, Download, Refresh, Search } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../services/api";

interface AuditRow {
  id: number;
  user_id: string;
  endpoint: string;
  provider: string;
  model: string | null;
  input_chars: number | null;
  output_chars: number | null;
  tokens_used: number | null;
  latency_ms: number | null;
  status: string;
  block_reason: string | null;
  created_at: string | null;
}

interface AuditLogsResponse {
  total: number;
  rows: AuditRow[];
}

const ENDPOINTS = ["", "nl_query", "assistant_chat", "agent_run"];

const ENDPOINT_LABELS: Record<string, string> = {
  "": "All",
  nl_query: "NL Query",
  assistant_chat: "Assistant",
  agent_run: "Agent Run",
};

const STATUS_COLOR: Record<string, "success" | "error" | "warning" | "default"> = {
  ok: "success",
  error: "error",
  blocked: "warning",
};

function fmtDate(iso: string | null) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "medium" });
}

function fmtMs(ms: number | null) {
  if (ms == null) return "—";
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

export default function AuditLogs() {
  const [endpoint, setEndpoint] = useState("");
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [userFilter, setUserFilter] = useState("");

  const { data, isLoading, isError, refetch } = useQuery<AuditLogsResponse>({
    queryKey: ["audit-logs", endpoint, page, rowsPerPage],
    queryFn: async () => {
      const params = new URLSearchParams({
        limit: String(rowsPerPage),
        offset: String(page * rowsPerPage),
      });
      if (endpoint) params.set("endpoint", endpoint);
      const res = await apiClient.get(`/ai-guardrails/audit-logs?${params}`);
      return res.data;
    },
    refetchInterval: 30_000,
  });

  const rows = data?.rows ?? [];
  const filtered = userFilter
    ? rows.filter(r => r.user_id.toLowerCase().includes(userFilter.toLowerCase()))
    : rows;

  const handleExport = useCallback(() => {
    const header = ["id", "created_at", "user_id", "endpoint", "provider", "model", "input_chars", "output_chars", "tokens_used", "latency_ms", "status", "block_reason"];
    const csvRows = [header.join(","), ...rows.map(r =>
      [r.id, r.created_at ?? "", r.user_id, r.endpoint, r.provider, r.model ?? "", r.input_chars ?? "", r.output_chars ?? "", r.tokens_used ?? "", r.latency_ms ?? "", r.status, r.block_reason ?? ""]
        .map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")
    )];
    const blob = new Blob([csvRows.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-logs-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [rows]);

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: "auto" }}>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 0.5 }}>
        <ManageSearch sx={{ color: "#2563eb", fontSize: 28 }} />
        <Typography variant="h5" sx={{ fontWeight: 700 }}>Prompt Audit Logs</Typography>
      </Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Metadata for every LLM call — user, endpoint, provider, character counts, latency. Full prompt text is never stored.
        Auto-refreshes every 30 seconds.
      </Typography>

      {/* Filters */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, flexWrap: "wrap", mb: 2 }}>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          {ENDPOINTS.map(ep => (
            <Chip
              key={ep || "all"}
              label={ENDPOINT_LABELS[ep]}
              onClick={() => { setEndpoint(ep); setPage(0); }}
              color={endpoint === ep ? "primary" : "default"}
              variant={endpoint === ep ? "filled" : "outlined"}
              size="small"
            />
          ))}
        </Box>
        <TextField
          size="small"
          placeholder="Filter by user…"
          value={userFilter}
          onChange={e => setUserFilter(e.target.value)}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <Search sx={{ fontSize: 18 }} />
                </InputAdornment>
              ),
            },
          }}
          sx={{ width: 220 }}
        />
        <Box sx={{ flex: 1 }} />
        <Button size="small" startIcon={<Refresh />} onClick={() => refetch()}>Refresh</Button>
        <Button size="small" startIcon={<Download />} onClick={handleExport} disabled={rows.length === 0}>Export CSV</Button>
      </Box>

      {/* Summary chips */}
      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
        <Chip label={`${data?.total ?? 0} total entries`} size="small" variant="outlined" />
        {endpoint && <Chip label={`Filtered: ${ENDPOINT_LABELS[endpoint]}`} size="small" color="primary" />}
      </Box>

      {isLoading && <LinearProgress sx={{ mb: 2 }} />}
      {isError && <Alert severity="error" sx={{ mb: 2 }}>Failed to load audit logs. Check your connection or permissions.</Alert>}

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow sx={{ "& th": { fontWeight: 700, fontSize: 12 } }}>
              <TableCell>Time</TableCell>
              <TableCell>User</TableCell>
              <TableCell>Endpoint</TableCell>
              <TableCell>Provider</TableCell>
              <TableCell align="right">In chars</TableCell>
              <TableCell align="right">Out chars</TableCell>
              <TableCell align="right">Tokens</TableCell>
              <TableCell align="right">Latency</TableCell>
              <TableCell>Status</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filtered.length === 0 && !isLoading && (
              <TableRow>
                <TableCell colSpan={9} align="center" sx={{ py: 4, color: "text.secondary", fontSize: 13 }}>
                  No audit log entries found. LLM calls will appear here once users start making requests.
                </TableCell>
              </TableRow>
            )}
            {filtered.map(row => (
              <TableRow key={row.id} hover>
                <TableCell sx={{ fontSize: 12, whiteSpace: "nowrap" }}>{fmtDate(row.created_at)}</TableCell>
                <TableCell sx={{ fontSize: 12 }}>
                  <Tooltip title={row.user_id}>
                    <Typography variant="caption" sx={{ maxWidth: 160, display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {row.user_id}
                    </Typography>
                  </Tooltip>
                </TableCell>
                <TableCell>
                  <Chip label={ENDPOINT_LABELS[row.endpoint] ?? row.endpoint} size="small" variant="outlined" sx={{ fontSize: 11 }} />
                </TableCell>
                <TableCell sx={{ fontSize: 12 }}>{row.provider || "—"}</TableCell>
                <TableCell align="right" sx={{ fontSize: 12 }}>{row.input_chars?.toLocaleString() ?? "—"}</TableCell>
                <TableCell align="right" sx={{ fontSize: 12 }}>{row.output_chars?.toLocaleString() ?? "—"}</TableCell>
                <TableCell align="right" sx={{ fontSize: 12 }}>{row.tokens_used?.toLocaleString() ?? "—"}</TableCell>
                <TableCell align="right" sx={{ fontSize: 12 }}>{fmtMs(row.latency_ms)}</TableCell>
                <TableCell>
                  <Chip
                    label={row.status}
                    size="small"
                    color={STATUS_COLOR[row.status] ?? "default"}
                    sx={{ fontSize: 11 }}
                  />
                  {row.block_reason && (
                    <Tooltip title={row.block_reason}>
                      <Typography variant="caption" sx={{ ml: 0.5, color: "warning.main" }}>⚠</Typography>
                    </Tooltip>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <TablePagination
        component="div"
        count={data?.total ?? 0}
        page={page}
        rowsPerPage={rowsPerPage}
        onPageChange={(_, p) => setPage(p)}
        onRowsPerPageChange={e => { setRowsPerPage(Number(e.target.value)); setPage(0); }}
        rowsPerPageOptions={[25, 50, 100]}
        sx={{ mt: 1 }}
      />
    </Box>
  );
}
