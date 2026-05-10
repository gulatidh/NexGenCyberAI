import React, { useState } from "react";
import {
  Box, Typography, Button, Card, Grid, Chip, IconButton,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Select, MenuItem, FormControl, InputLabel, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, Alert,
  Divider, TableSortLabel,
} from "@mui/material";
import { PlayArrow, Add, Refresh, Visibility, Delete } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { scansApi, connectorsApi, clientsApi, frameworksApi, projectsApi } from "../services/api";
import { Scan, Client, Connector, ScanType, FrameworkType, FrameworkCatalogEntry, Project } from "../types";
import { toast } from "react-toastify";
import { fromNow } from "../utils/datetime";

const STATUS_COLOR: Record<string, string> = {
  pending: "#ff9800", running: "#00e5ff", completed: "#00e676",
  failed: "#f44336", cancelled: "rgba(255,255,255,0.3)",
};

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b",
  low: "#4caf50", info: "#00e5ff",
};

export default function Scans() {
  const qc = useQueryClient();
  const [selectedClientId, setSelectedClientId] = useState("");
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [open, setOpen] = useState(false);
  const [scanType, setScanType] = useState<ScanType>("full");
  const [connectorId, setConnectorId] = useState("");
  const [framework, setFramework] = useState<FrameworkType | "">("");
  const [scanName, setScanName] = useState("");
  const [viewScan, setViewScan] = useState<Scan | null>(null);
  const [sortKey, setSortKey] = useState<string>("started_at");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", selectedClientId],
    queryFn: () => projectsApi.list(selectedClientId),
    enabled: !!selectedClientId,
  });
  const { data: frameworkCatalog = [] } = useQuery<FrameworkCatalogEntry[]>({
    queryKey: ["framework-catalog"],
    queryFn: frameworksApi.catalog,
  });
  const { data: connectors = [] } = useQuery<Connector[]>({
    queryKey: ["connectors", selectedClientId, selectedProjectId],
    queryFn: () => connectorsApi.list(selectedClientId, selectedProjectId || undefined),
    enabled: !!selectedClientId,
  });
  const { data: scans = [], isLoading, refetch } = useQuery<Scan[]>({
    queryKey: ["scans", selectedClientId, selectedProjectId],
    queryFn: () => scansApi.list(selectedClientId, selectedProjectId || undefined),
    enabled: !!selectedClientId,
    refetchInterval: (query) => (query.state.data as any[])?.some((s: any) => s.status === "running") ? 5000 : false,
  });

  const { data: findings = [], isLoading: findingsLoading } = useQuery<any[]>({
    queryKey: ["findings", selectedClientId, viewScan?.id],
    queryFn: () => scansApi.findings(selectedClientId, viewScan!.id),
    enabled: !!viewScan && !!selectedClientId,
  });

  const startMutation = useMutation({
    mutationFn: (data: any) => scansApi.start(selectedClientId, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["scans"] }); setOpen(false); setScanName(""); toast.success("Scan started"); },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error starting scan"),
  });

  const deleteMutation = useMutation({
    mutationFn: (scanId: string) => scansApi.delete(selectedClientId, scanId),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["scans"] }); toast.success("Scan deleted"); },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error deleting scan"),
  });

  const sortedScans = React.useMemo(() => {
    const dir = sortDir === "asc" ? 1 : -1;
    return [...scans].sort((a, b) => {
      const av: any = (a as any)[sortKey] ?? "";
      const bv: any = (b as any)[sortKey] ?? "";
      return String(av).localeCompare(String(bv)) * dir;
    });
  }, [scans, sortKey, sortDir]);

  const setSort = (k: string) => {
    if (sortKey === k) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else { setSortKey(k); setSortDir("desc"); }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Vulnerability & Configuration Scans</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>Run VA scans, config reviews, and compliance assessments</Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1 }}>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
            <Select value={selectedClientId} onChange={(e) => { setSelectedClientId(e.target.value); setSelectedProjectId(""); }} label="Client"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!selectedClientId}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Project</InputLabel>
            <Select value={selectedProjectId} onChange={(e) => setSelectedProjectId(e.target.value)} label="Project"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
            </Select>
          </FormControl>
          <Button variant="outlined" startIcon={<Refresh />} onClick={() => refetch()} sx={{ borderColor: "rgba(255,255,255,0.2)", color: "rgba(255,255,255,0.7)" }}>Refresh</Button>
          <Button variant="contained" startIcon={<Add />} disabled={!selectedClientId} onClick={() => setOpen(true)}
            sx={{ bgcolor: "#00e5ff", color: "#000" }}>New Scan</Button>
        </Box>
      </Box>

      {!selectedClientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(0,229,255,0.1)", color: "white" }}>Select a client to view scans.</Alert>
      ) : isLoading ? (
        <CircularProgress sx={{ color: "#00e5ff" }} />
      ) : (
        <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, overflow: "hidden" }}>
          <Table>
            <TableHead>
              <TableRow sx={{ "& th": { borderColor: "rgba(255,255,255,0.08)", color: "rgba(255,255,255,0.5)", fontSize: 12, fontWeight: 600 } }}>
                <TableCell>
                  <TableSortLabel active={sortKey === "name"} direction={sortDir} onClick={() => setSort("name")}
                    sx={{ color: "rgba(255,255,255,0.5) !important", "& .MuiTableSortLabel-icon": { color: "rgba(255,255,255,0.5) !important" } }}>
                    Name
                  </TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel active={sortKey === "scan_type"} direction={sortDir} onClick={() => setSort("scan_type")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>Type</TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel active={sortKey === "framework"} direction={sortDir} onClick={() => setSort("framework")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>Framework</TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel active={sortKey === "status"} direction={sortDir} onClick={() => setSort("status")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>Status</TableSortLabel>
                </TableCell>
                <TableCell>Findings</TableCell>
                <TableCell>
                  <TableSortLabel active={sortKey === "started_at"} direction={sortDir} onClick={() => setSort("started_at")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>Started</TableSortLabel>
                </TableCell>
                <TableCell>Duration</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {sortedScans.length === 0 ? (
                <TableRow><TableCell colSpan={8} sx={{ textAlign: "center", color: "rgba(255,255,255,0.3)", borderColor: "rgba(255,255,255,0.08)" }}>No scans yet</TableCell></TableRow>
              ) : sortedScans.map((scan) => {
                const dur = scan.started_at && scan.completed_at
                  ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)}s`
                  : scan.status === "running" ? "Running..." : "-";
                return (
                  <TableRow key={scan.id} hover sx={{ "& td": { borderColor: "rgba(255,255,255,0.05)", color: "white" } }}>
                    <TableCell><Typography variant="body2" sx={{ color: "white", fontSize: 13, fontWeight: 500 }}>{scan.name || `Scan ${scan.id.slice(0, 8)}`}</Typography></TableCell>
                    <TableCell><Chip label={scan.scan_type} size="small" sx={{ bgcolor: "rgba(0,229,255,0.1)", color: "#00e5ff", fontSize: 11 }} /></TableCell>
                    <TableCell><Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>{scan.framework || "—"}</Typography></TableCell>
                    <TableCell>
                      <Chip label={scan.status} size="small"
                        sx={{ bgcolor: `${STATUS_COLOR[scan.status]}20`, color: STATUS_COLOR[scan.status] }} />
                    </TableCell>
                    <TableCell>
                      {scan.summary ? (
                        <Box sx={{ display: "flex", gap: 0.5 }}>
                          {scan.summary.critical! > 0 && <Chip label={`${scan.summary.critical}C`} size="small" sx={{ bgcolor: "rgba(244,67,54,0.2)", color: "#f44336", fontSize: 10, height: 18 }} />}
                          {scan.summary.high! > 0 && <Chip label={`${scan.summary.high}H`} size="small" sx={{ bgcolor: "rgba(255,152,0,0.2)", color: "#ff9800", fontSize: 10, height: 18 }} />}
                          {scan.summary.medium! > 0 && <Chip label={`${scan.summary.medium}M`} size="small" sx={{ bgcolor: "rgba(255,235,59,0.2)", color: "#ffeb3b", fontSize: 10, height: 18 }} />}
                        </Box>
                      ) : "—"}
                    </TableCell>
                    <TableCell><Typography variant="caption">{fromNow(scan.started_at)}</Typography></TableCell>
                    <TableCell><Typography variant="caption">{dur}</Typography></TableCell>
                    <TableCell sx={{ whiteSpace: "nowrap" }}>
                      <Button size="small" startIcon={<Visibility sx={{ fontSize: 14 }} />}
                        onClick={() => setViewScan(scan)}
                        sx={{ color: "#00e5ff", fontSize: 11, minWidth: 0 }}>View</Button>
                      <IconButton size="small"
                        onClick={() => {
                          if (window.confirm(`Delete scan "${scan.name || scan.id.slice(0, 8)}"? Findings will also be removed.`)) {
                            deleteMutation.mutate(scan.id);
                          }
                        }}
                        sx={{ color: "rgba(255,255,255,0.4)", "&:hover": { color: "#f44336" } }}>
                        <Delete sx={{ fontSize: 16 }} />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Start scan dialog */}
      <Dialog open={open} onClose={() => setOpen(false)} slotProps={{ paper: { sx: { bgcolor: "#161b22", color: "white", minWidth: 420 } } }}>
        <DialogTitle>Start New Scan</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 0.5 }}>
            <Grid size={{ xs: 12 }}>
              <TextField fullWidth size="small" label="Scan name (optional)"
                value={scanName} onChange={(e) => setScanName(e.target.value)}
                placeholder='e.g. "Weekly Azure prod compliance"'
                slotProps={{ inputLabel: { sx: { color: 'rgba(255,255,255,0.5)' } }, htmlInput: { style: { color: 'white' } } }}
                sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Scan Type</InputLabel>
                <Select value={scanType} onChange={(e) => setScanType(e.target.value as ScanType)} label="Scan Type"
                  sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                  <MenuItem value="vulnerability">Vulnerability Assessment</MenuItem>
                  <MenuItem value="configuration">Configuration Review</MenuItem>
                  <MenuItem value="compliance">Compliance Assessment</MenuItem>
                  <MenuItem value="full">Full Assessment (all)</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Connector (optional)</InputLabel>
                <Select value={connectorId} onChange={(e) => setConnectorId(e.target.value)} label="Connector"
                  sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                  <MenuItem value="">All connectors</MenuItem>
                  {connectors.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Framework</InputLabel>
                <Select value={framework} onChange={(e) => setFramework(e.target.value as FrameworkType)} label="Framework"
                  sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                  <MenuItem value="">None</MenuItem>
                  {frameworkCatalog.map((f) => (
                    <MenuItem key={f.framework} value={f.framework}>
                      {f.name} ({f.total_controls})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setOpen(false)} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
          <Button variant="contained" startIcon={<PlayArrow />} disabled={startMutation.isPending}
            onClick={() => startMutation.mutate({ scan_type: scanType, connector_id: connectorId || undefined, framework: framework || undefined, name: scanName || undefined })}
            sx={{ bgcolor: "#00e5ff", color: "#000" }}>
            {startMutation.isPending ? <CircularProgress size={18} /> : "Start Scan"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Findings dialog */}
      <Dialog open={!!viewScan} onClose={() => setViewScan(null)} maxWidth="md" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "#161b22", color: "white" } } }}>
        <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <Box>
            <Typography variant="h6">Scan Findings</Typography>
            {viewScan && (
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                {viewScan.scan_type} · {viewScan.framework || "No framework"} · {fromNow(viewScan.started_at)}
              </Typography>
            )}
          </Box>
          {viewScan && (
            <Chip label={viewScan.status} size="small"
              sx={{ bgcolor: `${STATUS_COLOR[viewScan.status]}20`, color: STATUS_COLOR[viewScan.status] }} />
          )}
        </DialogTitle>
        <Divider sx={{ borderColor: "rgba(255,255,255,0.08)" }} />
        <DialogContent sx={{ p: 0 }}>
          {findingsLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
              <CircularProgress sx={{ color: "#00e5ff" }} />
            </Box>
          ) : findings.length === 0 ? (
            <Box sx={{ p: 4, textAlign: "center", color: "rgba(255,255,255,0.4)" }}>
              No findings recorded for this scan.
            </Box>
          ) : (
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { borderColor: "rgba(255,255,255,0.08)", color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600 } }}>
                  <TableCell>Severity</TableCell>
                  <TableCell>Title</TableCell>
                  <TableCell>Resource</TableCell>
                  <TableCell>CVE</TableCell>
                  <TableCell>CVSS</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {findings.map((f: any) => (
                  <TableRow key={f.id} hover sx={{ "& td": { borderColor: "rgba(255,255,255,0.05)", color: "white", fontSize: 12 } }}>
                    <TableCell>
                      <Chip label={f.severity} size="small"
                        sx={{ bgcolor: `${SEV_COLOR[f.severity] || "#888"}20`, color: SEV_COLOR[f.severity] || "#888", fontSize: 10, height: 18 }} />
                    </TableCell>
                    <TableCell sx={{ maxWidth: 300 }}>
                      <Typography variant="caption" sx={{ display: "block", fontWeight: 600 }}>{f.title}</Typography>
                      {f.description && (
                        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mt: 0.3 }}>
                          {f.description.slice(0, 120)}{f.description.length > 120 ? "…" : ""}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell><Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>{f.resource_id || "—"}</Typography></TableCell>
                    <TableCell><Typography variant="caption" sx={{ color: "#00e5ff" }}>{f.cve_id || "—"}</Typography></TableCell>
                    <TableCell><Typography variant="caption">{f.cvss_score ?? "—"}</Typography></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setViewScan(null)} sx={{ color: "rgba(255,255,255,0.5)" }}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
