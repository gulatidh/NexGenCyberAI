import React, { useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress,
  FormControl, InputLabel, Select, MenuItem, IconButton, Alert,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  LinearProgress, Menu, MenuItem as MuiMenuItem,
} from "@mui/material";
import { Refresh, GppBad } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { controlDeficienciesApi } from "../services/api";
import { toast } from "react-toastify";
import { fmt } from "../utils/datetime";

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853", info: "#4285F4",
};

const STATUS_COLOR: Record<string, string> = {
  open: "#FF7043", in_remediation: "#FBBC04", closed: "#34A853",
};

const FRAMEWORK_COLOR: Record<string, string> = {
  "NIST CSF 2.0": "#4285F4", "ISO 27001": "#34A853", "GDPR": "#9C27B0",
  "PCI DSS": "#FF7043", "HIPAA": "#00ACC1",
};

interface ControlDeficiency {
  id: string;
  client_id: string;
  agent_run_id?: string;
  scan_id?: string;
  finding_id?: string;
  control_id?: string;
  framework?: string;
  severity?: string;
  title: string;
  gap_description?: string;
  regulatory_reference?: string;
  remediation?: string;
  audit_readiness_score?: number;
  status: string;
  created_at?: string;
}

function StatusMenu({ entry, onUpdate }: { entry: ControlDeficiency; onUpdate: (status: string) => void }) {
  const [anchor, setAnchor] = useState<null | HTMLElement>(null);
  return (
    <>
      <IconButton size="small" onClick={(e) => { e.stopPropagation(); setAnchor(e.currentTarget); }}>
        <Refresh fontSize="small" />
      </IconButton>
      <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}>
        {["open", "in_remediation", "closed"].map((s) => (
          <MuiMenuItem key={s} onClick={() => { onUpdate(s); setAnchor(null); }}
            selected={entry.status === s} sx={{ textTransform: "capitalize", fontSize: 13 }}>
            {s.replace("_", " ")}
          </MuiMenuItem>
        ))}
      </Menu>
    </>
  );
}

export default function ControlDeficiencies() {
  const qc = useQueryClient();
  const { clientId } = useActiveClient();
  const [filterSev, setFilterSev] = useState("");
  const [filterStatus, setFilterStatus] = useState("open");
  const [filterFramework, setFilterFramework] = useState("");

  const { data: entries = [], isLoading, refetch } = useQuery<ControlDeficiency[]>({
    queryKey: ["control-deficiencies", clientId, filterSev, filterStatus, filterFramework],
    queryFn: () => controlDeficienciesApi.list(clientId, {
      severity: filterSev || undefined,
      status: filterStatus || undefined,
      framework: filterFramework || undefined,
    }),
    enabled: !!clientId,
  });

  const updateMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      controlDeficienciesApi.update(clientId, id, { status }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["control-deficiencies", clientId] }); toast.success("Updated"); },
    onError: () => toast.error("Update failed"),
  });

  const frameworks = Array.from(new Set(entries.map((e) => e.framework).filter(Boolean))) as string[];
  const avgAuditScore = entries.filter((e) => e.audit_readiness_score != null).length
    ? Math.round(entries.filter((e) => e.audit_readiness_score != null)
        .reduce((sum, e) => sum + (e.audit_readiness_score || 0), 0) /
        entries.filter((e) => e.audit_readiness_score != null).length)
    : null;

  const counts = { open: 0, in_remediation: 0, closed: 0, total: entries.length };
  for (const e of entries) {
    if (e.status === "open") counts.open++;
    else if (e.status === "in_remediation") counts.in_remediation++;
    else if (e.status === "closed") counts.closed++;
  }

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Control Deficiencies</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Framework control gaps identified by the Compliance agent — auditor-ready register
          </Typography>
        </Box>
        <IconButton onClick={() => refetch()}><Refresh /></IconButton>
      </Box>

      <Box sx={{ display: "flex", gap: 1.5, mb: 3, flexWrap: "wrap" }}>
        <FormControl size="small" sx={{ minWidth: 140 }}>
          <InputLabel>Status</InputLabel>
          <Select value={filterStatus} label="Status" onChange={(e) => setFilterStatus(e.target.value)}>
            <MenuItem value="">All</MenuItem>
            <MenuItem value="open">Open</MenuItem>
            <MenuItem value="in_remediation">In remediation</MenuItem>
            <MenuItem value="closed">Closed</MenuItem>
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 140 }}>
          <InputLabel>Severity</InputLabel>
          <Select value={filterSev} label="Severity" onChange={(e) => setFilterSev(e.target.value)}>
            <MenuItem value="">All</MenuItem>
            {["critical", "high", "medium", "low"].map((s) => (
              <MenuItem key={s} value={s} sx={{ textTransform: "capitalize" }}>{s}</MenuItem>
            ))}
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 150 }}>
          <InputLabel>Framework</InputLabel>
          <Select value={filterFramework} label="Framework" onChange={(e) => setFilterFramework(e.target.value)}>
            <MenuItem value="">All</MenuItem>
            {frameworks.map((f) => <MenuItem key={f} value={f!}>{f}</MenuItem>)}
          </Select>
        </FormControl>
      </Box>

      {/* KPI strip */}
      {clientId && (
        <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
          {[
            { label: "Total", value: counts.total, color: "#4285F4" },
            { label: "Open", value: counts.open, color: "#FF7043" },
            { label: "In Remediation", value: counts.in_remediation, color: "#FBBC04" },
            { label: "Closed", value: counts.closed, color: "#34A853" },
          ].map(({ label, value, color }) => (
            <Card key={label} variant="outlined" sx={{ minWidth: 120 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color }}>{value}</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>{label}</Typography>
              </CardContent>
            </Card>
          ))}
          {avgAuditScore != null && (
            <Card variant="outlined" sx={{ minWidth: 180 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Typography variant="h5" sx={{ fontWeight: 700, color: avgAuditScore >= 70 ? "#34A853" : avgAuditScore >= 50 ? "#FBBC04" : "#EA4335" }}>
                    {avgAuditScore}%
                  </Typography>
                </Box>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>Avg Audit Readiness</Typography>
                <LinearProgress variant="determinate" value={avgAuditScore}
                  sx={{ mt: 0.5, height: 4, borderRadius: 2,
                    "& .MuiLinearProgress-bar": {
                      bgcolor: avgAuditScore >= 70 ? "#34A853" : avgAuditScore >= 50 ? "#FBBC04" : "#EA4335"
                    }
                  }} />
              </CardContent>
            </Card>
          )}
        </Box>
      )}

      {!clientId && <Alert severity="info">Select a client to view their control deficiencies.</Alert>}
      {clientId && isLoading && <CircularProgress size={24} />}

      {clientId && !isLoading && entries.length === 0 && (
        <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
          <GppBad sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No control deficiencies yet. Run the <strong>Compliance Monitor</strong> agent on a completed scan.
          </Typography>
        </Card>
      )}

      {clientId && !isLoading && entries.length > 0 && (
        <TableContainer component={Card} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                {["Severity", "Control ID", "Title / Gap", "Framework", "Regulatory Ref", "Status", "Detected", ""].map((h) => (
                  <TableCell key={h} sx={{ fontWeight: 700, fontSize: 11 }}>{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {entries.map((e) => {
                const sev = (e.severity || "medium").toLowerCase();
                const sevColor = SEV_COLOR[sev] || "#9e9e9e";
                const fwColor = FRAMEWORK_COLOR[e.framework || ""] || "#4285F4";
                return (
                  <TableRow key={e.id} hover>
                    <TableCell>
                      <Chip label={(e.severity || "MED").toUpperCase()} size="small"
                        sx={{ bgcolor: `${sevColor}22`, color: sevColor, fontSize: 10, height: 18, fontWeight: 700 }} />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#4285F4" }}>
                        {e.control_id || e.finding_id || "—"}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ maxWidth: 300 }}>
                      <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 12.5 }}>{e.title}</Typography>
                      {e.gap_description && (
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block",
                          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 280 }}>
                          {e.gap_description}
                        </Typography>
                      )}
                      {e.remediation && (
                        <Typography variant="caption" sx={{ color: "#34A853", display: "block", mt: 0.25 }}>
                          ↳ {e.remediation}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      {e.framework ? (
                        <Chip label={e.framework} size="small"
                          sx={{ bgcolor: `${fwColor}22`, color: fwColor, fontSize: 10, height: 18 }} />
                      ) : <Typography variant="caption">—</Typography>}
                    </TableCell>
                    <TableCell sx={{ maxWidth: 180 }}>
                      <Typography variant="caption" sx={{ color: "text.secondary",
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block", maxWidth: 180 }}>
                        {e.regulatory_reference || "—"}
                      </Typography>
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
