import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress,
  FormControl, InputLabel, Select, MenuItem, IconButton, Alert,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  Menu, MenuItem as MuiMenuItem,
} from "@mui/material";
import { Refresh, MoreVert, BugReport } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { clientsApi, threatRegisterApi } from "../services/api";
import { Client } from "../types";
import { toast } from "react-toastify";
import { fmt } from "../utils/datetime";

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853", info: "#4285F4",
};

const STATUS_COLOR: Record<string, string> = {
  active: "#FF7043", mitigated: "#34A853", false_positive: "#9e9e9e",
};

const CONFIDENCE_COLOR: Record<string, string> = {
  high: "#34A853", medium: "#FBBC04", low: "#FF7043",
};

interface ThreatEntry {
  id: string;
  client_id: string;
  agent_run_id?: string;
  scan_id?: string;
  technique_id?: string;
  technique_name?: string;
  tactic?: string;
  confidence?: string;
  finding_id?: string;
  severity?: string;
  title: string;
  description?: string;
  remediation?: string;
  framework_references?: string[];
  sigma_rule?: string;
  status: string;
  created_at?: string;
}

function StatusMenu({ entry, onUpdate }: { entry: ThreatEntry; onUpdate: (status: string) => void }) {
  const [anchor, setAnchor] = useState<null | HTMLElement>(null);
  return (
    <>
      <IconButton size="small" onClick={(e) => { e.stopPropagation(); setAnchor(e.currentTarget); }}>
        <MoreVert fontSize="small" />
      </IconButton>
      <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}>
        {["active", "mitigated", "false_positive"].map((s) => (
          <MuiMenuItem key={s} onClick={() => { onUpdate(s); setAnchor(null); }}
            selected={entry.status === s}
            sx={{ textTransform: "capitalize", fontSize: 13 }}>
            {s.replace("_", " ")}
          </MuiMenuItem>
        ))}
      </Menu>
    </>
  );
}

export default function ThreatRegister() {
  const qc = useQueryClient();
  const [clientId, setClientId] = useState(() => localStorage.getItem("aegis-active-client") || "");
  const [filterSev, setFilterSev] = useState("");
  const [filterStatus, setFilterStatus] = useState("active");

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });

  const { data: entries = [], isLoading, refetch } = useQuery<ThreatEntry[]>({
    queryKey: ["threat-register", clientId, filterSev, filterStatus],
    queryFn: () => threatRegisterApi.list(clientId, {
      severity: filterSev || undefined,
      status: filterStatus || undefined,
    }),
    enabled: !!clientId,
  });

  const updateMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      threatRegisterApi.update(clientId, id, { status }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["threat-register", clientId] }); toast.success("Updated"); },
    onError: () => toast.error("Update failed"),
  });

  const counts = { active: 0, mitigated: 0, false_positive: 0, total: entries.length };
  for (const e of entries) {
    if (e.status === "active") counts.active++;
    else if (e.status === "mitigated") counts.mitigated++;
    else counts.false_positive++;
  }

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Threat Register</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            MITRE ATT&CK–mapped threat intelligence from the Threat Intel agent
          </Typography>
        </Box>
        <IconButton onClick={() => refetch()}><Refresh /></IconButton>
      </Box>

      {/* Client + filters */}
      <Box sx={{ display: "flex", gap: 1.5, mb: 3, flexWrap: "wrap" }}>
        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel>Client</InputLabel>
          <Select value={clientId} label="Client"
            onChange={(e) => { setClientId(e.target.value); localStorage.setItem("aegis-active-client", e.target.value); }}>
            {(clients as Client[]).map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 140 }}>
          <InputLabel>Status</InputLabel>
          <Select value={filterStatus} label="Status" onChange={(e) => setFilterStatus(e.target.value)}>
            <MenuItem value="">All</MenuItem>
            <MenuItem value="active">Active</MenuItem>
            <MenuItem value="mitigated">Mitigated</MenuItem>
            <MenuItem value="false_positive">False positive</MenuItem>
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 140 }}>
          <InputLabel>Severity</InputLabel>
          <Select value={filterSev} label="Severity" onChange={(e) => setFilterSev(e.target.value)}>
            <MenuItem value="">All</MenuItem>
            {["critical", "high", "medium", "low", "info"].map((s) => (
              <MenuItem key={s} value={s} sx={{ textTransform: "capitalize" }}>{s}</MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>

      {/* KPI strip */}
      {clientId && (
        <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
          {[
            { label: "Total", value: counts.total, color: "#4285F4" },
            { label: "Active", value: counts.active, color: "#FF7043" },
            { label: "Mitigated", value: counts.mitigated, color: "#34A853" },
            { label: "False +ve", value: counts.false_positive, color: "#9e9e9e" },
          ].map(({ label, value, color }) => (
            <Card key={label} variant="outlined" sx={{ minWidth: 110 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color }}>{value}</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>{label}</Typography>
              </CardContent>
            </Card>
          ))}
        </Box>
      )}

      {!clientId && (
        <Alert severity="info">Select a client to view their threat register.</Alert>
      )}

      {clientId && isLoading && <CircularProgress size={24} />}

      {clientId && !isLoading && entries.length === 0 && (
        <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
          <BugReport sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No threat entries yet. Run the <strong>Threat Intel</strong> agent on a completed scan to populate this register.
          </Typography>
        </Card>
      )}

      {clientId && !isLoading && entries.length > 0 && (
        <TableContainer component={Card} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                {["Severity", "Finding ID", "Title / Technique", "Tactic", "Confidence", "Status", "Detected", ""].map((h) => (
                  <TableCell key={h} sx={{ fontWeight: 700, fontSize: 11 }}>{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {entries.map((e) => {
                const sev = (e.severity || "info").toLowerCase();
                const sevColor = SEV_COLOR[sev] || "#9e9e9e";
                return (
                  <TableRow key={e.id} hover>
                    <TableCell>
                      <Chip label={(e.severity || "INFO").toUpperCase()} size="small"
                        sx={{ bgcolor: `${sevColor}22`, color: sevColor, fontSize: 10, height: 18, fontWeight: 700 }} />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary" }}>
                        {e.finding_id || "—"}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ maxWidth: 280 }}>
                      <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 12.5 }}>{e.title}</Typography>
                      {e.technique_id && (
                        <Typography variant="caption" sx={{ color: "#4285F4" }}>
                          {e.technique_id}{e.technique_name ? ` — ${e.technique_name}` : ""}
                        </Typography>
                      )}
                      {e.description && (
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.25,
                          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 260 }}>
                          {e.description}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "capitalize" }}>
                        {e.tactic || "—"}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {e.confidence ? (
                        <Chip label={e.confidence} size="small"
                          sx={{ bgcolor: `${CONFIDENCE_COLOR[e.confidence.toLowerCase()] || "#9e9e9e"}22`,
                            color: CONFIDENCE_COLOR[e.confidence.toLowerCase()] || "#9e9e9e",
                            fontSize: 10, height: 18, textTransform: "capitalize" }} />
                      ) : <Typography variant="caption">—</Typography>}
                    </TableCell>
                    <TableCell>
                      <Chip label={e.status.replace("_", " ")} size="small"
                        sx={{ bgcolor: `${STATUS_COLOR[e.status] || "#9e9e9e"}22`,
                          color: STATUS_COLOR[e.status] || "#9e9e9e",
                          fontSize: 10, height: 18, textTransform: "capitalize" }} />
                    </TableCell>
                    <TableCell sx={{ fontSize: 11, whiteSpace: "nowrap" }}>{e.created_at ? fmt(e.created_at) : "—"}</TableCell>
                    <TableCell>
                      <StatusMenu entry={e} onUpdate={(status) => updateMut.mutate({ id: e.id, status })} />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}
