/**
 * Access Logs — admin-only audit trail of who is accessing the portal.
 * One row per authenticated API request (user, time, IP, browser, path, status).
 */
import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Table, TableHead, TableRow, TableCell,
  TableBody, TableContainer, Chip, TextField, MenuItem, Select, FormControl,
  InputLabel, Button, CircularProgress, Alert, Tooltip, Pagination,
} from "@mui/material";
import { History, Refresh } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { adminApi } from "../services/api";
import { MyAccess } from "../types";
import { fmt } from "../utils/datetime";

const PAGE = 100;
const ACCENT = "#4285F4";

function statusColor(s?: number): string {
  if (!s) return "#9e9e9e";
  if (s >= 500) return "#EA4335";
  if (s >= 400) return "#FF7043";
  if (s >= 300) return "#FBBC04";
  return "#34A853";
}

export default function AccessLogs() {
  const [userEmail, setUserEmail] = useState("");
  const [method, setMethod] = useState("");
  const [sinceHours, setSinceHours] = useState<number | "">(24);
  const [page, setPage] = useState(1);

  const { data: me } = useQuery<MyAccess>({
    queryKey: ["my-access"], queryFn: adminApi.me, retry: 0, staleTime: 60_000,
  });
  const isAdmin = !!me?.is_admin;

  const params = {
    user_email: userEmail || undefined,
    method: method || undefined,
    since_hours: sinceHours === "" ? undefined : Number(sinceHours),
    limit: PAGE,
    offset: (page - 1) * PAGE,
  };

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["access-logs", params],
    queryFn: () => adminApi.accessLogs(params),
    enabled: isAdmin,
    refetchInterval: 30_000,
  });

  const items: any[] = data?.items || [];
  const total: number = data?.total || 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE));

  if (me && !isAdmin) {
    return <Alert severity="error" sx={{ m: 2 }}>Access Logs are restricted to administrators.</Alert>;
  }

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
            <History sx={{ color: ACCENT }} /> Access Logs
          </Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Who is accessing the portal — every authenticated request (admin-only). Retained 90 days.
          </Typography>
        </Box>
        <Button variant="outlined" startIcon={<Refresh />} onClick={() => refetch()}
          sx={{ color: ACCENT, borderColor: "rgba(66,133,244,0.5)" }}>Refresh</Button>
      </Box>

      <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
        <CardContent sx={{ display: "flex", gap: 2, flexWrap: "wrap", alignItems: "center" }}>
          <TextField size="small" label="User email" value={userEmail}
            onChange={(e) => { setUserEmail(e.target.value); setPage(1); }} sx={{ minWidth: 220 }} />
          <FormControl size="small" sx={{ minWidth: 130 }}>
            <InputLabel>Method</InputLabel>
            <Select label="Method" value={method} onChange={(e) => { setMethod(e.target.value); setPage(1); }}>
              <MenuItem value="">All</MenuItem>
              {["GET", "POST", "PATCH", "PUT", "DELETE"].map((m) => <MenuItem key={m} value={m}>{m}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Time range</InputLabel>
            <Select label="Time range" value={sinceHours}
              onChange={(e) => { setSinceHours(e.target.value as any); setPage(1); }}>
              <MenuItem value={1}>Last hour</MenuItem>
              <MenuItem value={24}>Last 24 hours</MenuItem>
              <MenuItem value={168}>Last 7 days</MenuItem>
              <MenuItem value={720}>Last 30 days</MenuItem>
              <MenuItem value={"" as any}>All time</MenuItem>
            </Select>
          </FormControl>
          <Box sx={{ flex: 1 }} />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            {total.toLocaleString()} events{isFetching ? " · refreshing…" : ""}
          </Typography>
        </CardContent>
      </Card>

      <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
        <CardContent>
          {isLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}><CircularProgress sx={{ color: ACCENT }} /></Box>
          ) : items.length === 0 ? (
            <Alert severity="info">No access events for the selected filters yet.</Alert>
          ) : (
            <>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 700 } }}>
                      <TableCell>USER</TableCell>
                      <TableCell>WHEN</TableCell>
                      <TableCell>METHOD</TableCell>
                      <TableCell>PATH</TableCell>
                      <TableCell align="center">STATUS</TableCell>
                      <TableCell>IP</TableCell>
                      <TableCell>BROWSER</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {items.map((r) => (
                      <TableRow key={r.id} hover sx={{ "& td": { color: "text.primary", fontSize: 12, borderColor: "divider" } }}>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 12 }}>{r.user_email}</Typography>
                          {r.user_name && <Typography variant="caption" sx={{ color: "text.secondary" }}>{r.user_name}</Typography>}
                        </TableCell>
                        <TableCell sx={{ whiteSpace: "nowrap", color: "text.secondary" }}>{fmt(r.created_at)}</TableCell>
                        <TableCell><Chip label={r.method} size="small" sx={{ height: 18, fontSize: 10, fontWeight: 700 }} /></TableCell>
                        <TableCell sx={{ fontFamily: "monospace", fontSize: 11, maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          <Tooltip title={r.path}><span>{r.path}</span></Tooltip>
                        </TableCell>
                        <TableCell align="center">
                          <Typography variant="caption" sx={{ color: statusColor(r.status_code), fontWeight: 700 }}>{r.status_code}</Typography>
                        </TableCell>
                        <TableCell sx={{ color: "text.secondary", fontFamily: "monospace", fontSize: 11 }}>{r.ip_address || "—"}</TableCell>
                        <TableCell sx={{ color: "text.secondary", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          <Tooltip title={r.user_agent || ""}><span>{r.user_agent || "—"}</span></Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              {pageCount > 1 && (
                <Box sx={{ display: "flex", justifyContent: "center", mt: 2 }}>
                  <Pagination count={pageCount} page={page} onChange={(_, p) => setPage(p)} color="primary" size="small" />
                </Box>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}
