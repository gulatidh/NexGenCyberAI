import React, { useState } from "react";
import {
  Box, Typography, Button, Card, Grid, Chip,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Select, MenuItem, FormControl, InputLabel, CircularProgress,
  Tabs, Tab, Stack, Tooltip, Divider, IconButton, Badge,
  Table, TableHead, TableRow, TableCell, TableBody,
} from "@mui/material";
import { PlayArrow, Add, Refresh, Visibility, DeleteOutlined, Replay, History } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { scansApi, connectorsApi, clientsApi, frameworksApi, assessmentsApi, findingsApi } from "../services/api";
import { useNavigate } from "react-router-dom";
import { Scan, Client, Connector, ScanType, FrameworkType, FrameworkCatalogEntry } from "../types";
import { toast } from "react-toastify";
import { fromNow } from "../utils/datetime";

const STATUS_COLOR: Record<string, string> = {
  pending: "#ff9800", running: "#4285F4", completed: "#00e676",
  failed: "#f44336", cancelled: "rgba(255,255,255,0.3)",
};

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b",
  low: "#4caf50", info: "#4285F4",
};

// ── Scanner catalog ──────────────────────────────────────────────────────────
// Drives the category → scanner cascade in the New Scan dialog. `connectorType`
// must match a backend ConnectorType value. `status` controls whether the row
// is selectable (Live) or shown as a teaser (Soon).
type ScannerStatus = "live" | "soon";
type ScanCategory = "cloud" | "dast" | "sast" | "network" | "dependency";
type ScannerDef = {
  id: string;             // unique key
  name: string;           // display label
  connectorType: string;  // backend ConnectorType.value
  category: ScanCategory;
  status: ScannerStatus;
  description: string;
};

const CATEGORY_LABEL: Record<ScanCategory, string> = {
  cloud: "Cloud & Identity",
  dast: "DAST — Dynamic AppSec",
  sast: "SAST — Static AppSec",
  network: "Network & Infrastructure",
  dependency: "Dependency & Secret",
};

const CATEGORY_COLOR: Record<ScanCategory, string> = {
  cloud: "#4285F4",       // Google Blue
  dast: "#FBBC04",        // Google Yellow — dynamic
  sast: "#4285F4",        // Google Blue — static
  network: "#34A853",     // Google Green — infra
  dependency: "#EA4335",  // Google Red — secrets / deps
};

const SCANNERS: ScannerDef[] = [
  // DAST
  { id: "zap", name: "OWASP ZAP", connectorType: "web", category: "dast", status: "live",
    description: "Web app DAST — passive (unauth) and active (auth) profiles via GitHub Actions." },
  // SAST
  { id: "semgrep", name: "Semgrep", connectorType: "semgrep", category: "sast", status: "live",
    description: "Open-source static analysis with curated rule packs. Runs in GitHub Actions via semgrep/semgrep image." },
  { id: "codeql", name: "GitHub CodeQL", connectorType: "codeql", category: "sast", status: "live",
    description: "GitHub's semantic code analysis. Auto-detects language; runs the security-and-quality query suite in GitHub Actions." },
  { id: "sonarqube", name: "SonarQube", connectorType: "sonarqube", category: "sast", status: "soon",
    description: "Community Edition (self-hosted) or Enterprise (SonarCloud via Action). Workflow coming soon." },
  // Network
  { id: "nmap", name: "NMAP", connectorType: "nmap", category: "network", status: "live",
    description: "Service / port discovery on hosts or CIDR ranges with NSE safe + vuln scripts. Runs in GitHub Actions." },
  { id: "openvas", name: "OpenVAS / Greenbone", connectorType: "openvas", category: "network", status: "soon",
    description: "Open-source network vulnerability scanner. Workflow coming soon." },
  { id: "trivy", name: "Trivy", connectorType: "trivy", category: "network", status: "live",
    description: "Container image + filesystem + IaC scanner. Runs in GitHub Actions." },
  // Dependency / Secret
  { id: "owasp_dc", name: "OWASP Dependency-Check", connectorType: "owasp_dc", category: "dependency", status: "soon",
    description: "SCA / CVE matching for application dependencies. Workflow coming soon." },
  { id: "gitleaks", name: "Gitleaks", connectorType: "gitleaks", category: "dependency", status: "live",
    description: "Secret scanner for git history. Runs in GitHub Actions." },
  { id: "trufflehog", name: "TruffleHog", connectorType: "trufflehog", category: "dependency", status: "live",
    description: "Secret scanner (git + filesystem) with verification. Runs in GitHub Actions." },
];

const CATEGORY_ORDER: ScanCategory[] = ["cloud", "dast", "sast", "network", "dependency"];

export default function Scans() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [selectedClientId, setSelectedClientId] = useState("");
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [open, setOpen] = useState(false);
  // Tile filter state
  const [tileStatusFilter, setTileStatusFilter] = useState<string>("");
  const [tileCategoryFilter, setTileCategoryFilter] = useState<string>("");
  const [scanType, setScanType] = useState<ScanType>("full");
  const [connectorId, setConnectorId] = useState("");
  const [framework, setFramework] = useState<FrameworkType | "">("");
  const [scanName, setScanName] = useState("");
  const [category, setCategory] = useState<ScanCategory>("cloud");
  const [scannerId, setScannerId] = useState<string>("");
  const [viewScan, setViewScan] = useState<Scan | null>(null);

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: frameworkCatalog = [] } = useQuery<FrameworkCatalogEntry[]>({
    queryKey: ["framework-catalog"],
    queryFn: frameworksApi.catalog,
  });
  const { data: connectors = [] } = useQuery<Connector[]>({
    queryKey: ["connectors", selectedClientId, selectedProjectId],
    queryFn: () => connectorsApi.list(selectedClientId, selectedProjectId || undefined),
    enabled: !!selectedClientId,
  });

  // Cross-client tile feed (default view). Refetches every 5s while any tile
  // is still running.
  const { data: tilesData, isLoading: tilesLoading, refetch: refetchTiles } = useQuery<{ scans: any[] }>({
    queryKey: ["assessments-tiles"],
    queryFn: () => assessmentsApi.listAll(),
    refetchInterval: (q) => ((q.state.data as any)?.scans || []).some((s: any) => s.status === "running") ? 5000 : false,
  });
  const tiles = (tilesData?.scans || []).filter((t) => {
    if (tileStatusFilter && t.status !== tileStatusFilter) return false;
    if (tileCategoryFilter && t.category !== tileCategoryFilter) return false;
    if (selectedClientId && t.client_id !== selectedClientId) return false;
    return true;
  });

  const { data: findings = [], isLoading: findingsLoading } = useQuery<any[]>({
    queryKey: ["findings", selectedClientId, viewScan?.id],
    queryFn: () => scansApi.findings(selectedClientId, viewScan!.id),
    enabled: !!viewScan && !!selectedClientId,
  });

  const [pendingDeleteFinding, setPendingDeleteFinding] = useState<any | null>(null);
  const deleteFindingMutation = useMutation({
    mutationFn: (findingId: string) => findingsApi.delete(selectedClientId, findingId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings", selectedClientId, viewScan?.id] });
      qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
      setPendingDeleteFinding(null);
      toast.success("Finding deleted");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Failed to delete finding"),
  });

  const [pendingDeleteScan, setPendingDeleteScan] = useState<any | null>(null);
  const deleteScanMutation = useMutation({
    mutationFn: (tile: any) => scansApi.delete(tile.client_id, tile.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
      setPendingDeleteScan(null);
      toast.success("Assessment deleted");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Failed to delete assessment"),
  });

  const startMutation = useMutation({
    mutationFn: (data: any) => scansApi.start(selectedClientId, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
      setOpen(false); setScanName("");
      toast.success("Assessment started");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error starting assessment"),
  });

  const rescanMutation = useMutation({
    mutationFn: (tile: any) => scansApi.rescan(tile.client_id, tile.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
      toast.success("Rescan started");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Failed to rescan"),
  });

  // Build a version-count map per tile: every tile and its parent share the
  // same root, so siblings = (parent_scan_id ?? id). Lets us show "vN of M"
  // on the live tile and an icon to open the version history.
  const versionMap = React.useMemo(() => {
    const groups = new Map<string, any[]>();
    for (const t of (tilesData?.scans || [])) {
      const root = t.parent_scan_id || t.id;
      if (!groups.has(root)) groups.set(root, []);
      groups.get(root)!.push(t);
    }
    // newest first per group
    groups.forEach((arr) => {
      arr.sort((a, b) => new Date(b.started_at || b.id).getTime() - new Date(a.started_at || a.id).getTime());
    });
    return groups;
  }, [tilesData]);

  const [historyOpenForRoot, setHistoryOpenForRoot] = useState<string | null>(null);

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Assessments</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            Every scan across all clients · click a tile for the AI verdict, findings, and agent runs
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client (filter)</InputLabel>
            <Select value={selectedClientId} onChange={(e) => { setSelectedClientId(e.target.value); setSelectedProjectId(""); }} label="Client (filter)"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All clients</MenuItem>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <Button variant="outlined" startIcon={<Refresh />}
            onClick={() => refetchTiles()}
            sx={{ borderColor: "rgba(255,255,255,0.2)", color: "rgba(255,255,255,0.7)" }}>Refresh</Button>
          <Button
            variant="contained"
            startIcon={<Add />}
            disabled={clients.length === 0}
            onClick={() => setOpen(true)}
          >
            New Assessment
          </Button>
        </Box>
      </Box>

      {/* Tile filter chips */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, flexWrap: "wrap", mb: 2 }}>
        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontWeight: 600 }}>STATUS</Typography>
        {["completed", "running", "failed", "pending", "cancelled"].map((s) => (
          <Chip key={s} size="small" label={s.charAt(0).toUpperCase() + s.slice(1)}
            onClick={() => setTileStatusFilter(tileStatusFilter === s ? "" : s)}
            sx={{
              cursor: "pointer",
              bgcolor: tileStatusFilter === s ? `${STATUS_COLOR[s] || "#888"}25` : "rgba(255,255,255,0.04)",
              color: tileStatusFilter === s ? (STATUS_COLOR[s] || "#888") : "rgba(255,255,255,0.7)",
              border: tileStatusFilter === s ? `1px solid ${STATUS_COLOR[s] || "#888"}` : "1px solid transparent",
              fontWeight: tileStatusFilter === s ? 700 : 400,
            }} />
        ))}
        <Box sx={{ width: 1, height: 18, bgcolor: "rgba(255,255,255,0.1)", mx: 1 }} />
        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontWeight: 600 }}>CATEGORY</Typography>
        {["DAST", "SAST", "Network", "Dependency", "Cloud", "Other"].map((c) => (
          <Chip key={c} size="small" label={c}
            onClick={() => setTileCategoryFilter(tileCategoryFilter === c ? "" : c)}
            sx={{
              cursor: "pointer",
              bgcolor: tileCategoryFilter === c ? "rgba(66,133,244,0.2)" : "rgba(255,255,255,0.04)",
              color: tileCategoryFilter === c ? "#4285F4" : "rgba(255,255,255,0.7)",
              border: tileCategoryFilter === c ? "1px solid #4285F4" : "1px solid transparent",
              fontWeight: tileCategoryFilter === c ? 700 : 400,
            }} />
        ))}
        {(tileStatusFilter || tileCategoryFilter) && (
          <Button size="small" sx={{ ml: 0.5, color: "rgba(255,255,255,0.5)", fontSize: 11 }}
            onClick={() => { setTileStatusFilter(""); setTileCategoryFilter(""); }}>
            Clear
          </Button>
        )}
        <Box sx={{ flex: 1 }} />
        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
          Showing {tiles.length} of {tilesData?.scans?.length || 0} assessments
        </Typography>
      </Box>

      {tilesLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 6 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      ) : tiles.length === 0 ? (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <Visibility sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
          {clients.length === 0 ? (
            <>
              <Typography sx={{ color: "rgba(255,255,255,0.7)", fontWeight: 600, mb: 0.5 }}>
                No accessible clients
              </Typography>
              <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
                Your account has no RBAC grants yet. Ask a global admin to grant you reader / editor / admin access from <b>Settings → Administration → Grant access</b>.
              </Typography>
            </>
          ) : (tilesData?.scans?.length || 0) === 0 ? (
            <>
              <Typography sx={{ color: "rgba(255,255,255,0.7)", fontWeight: 600, mb: 0.5 }}>
                No assessments yet
              </Typography>
              <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
                Click "New Assessment" to run your first scan.
              </Typography>
            </>
          ) : (
            <>
              <Typography sx={{ color: "rgba(255,255,255,0.7)", fontWeight: 600, mb: 0.5 }}>
                No assessments match the current filters
              </Typography>
              <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
                {tilesData?.scans?.length} assessment{(tilesData?.scans?.length || 0) === 1 ? "" : "s"} exist for clients you have access to — clear the Client / Status / Category filters above to see them.
              </Typography>
            </>
          )}
        </Card>
      ) : (
        <Grid container spacing={2}>
          {tiles.map((tile) => {
            const status = tile.status as string;
            const statusColor = STATUS_COLOR[status] || "rgba(255,255,255,0.3)";
            const cat = (tile.category as string) || "Other";
            const catColor = CATEGORY_COLOR[cat.toLowerCase() as ScanCategory] || "#4285F4";
            const dur = tile.duration_seconds != null
              ? (tile.duration_seconds >= 60
                  ? `${Math.round(tile.duration_seconds / 60)} min`
                  : `${tile.duration_seconds}s`)
              : (status === "running" ? "Running…" : "—");
            const agentTypes = Array.from(new Set((tile.agents_ran || []).map((a: any) => a.agent_type)));
            return (
              <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={tile.id}>
                <Card
                  onClick={() => navigate(`/scans/${tile.id}`)}
                  sx={{
                    bgcolor: "#1E1E1E",
                    border: `1px solid ${statusColor}40`,
                    borderRadius: 2,
                    cursor: "pointer",
                    transition: "transform 0.12s, border-color 0.12s, background-color 0.12s",
                    height: "100%",
                    "&:hover": { borderColor: statusColor, bgcolor: "rgba(255,255,255,0.02)", transform: "translateY(-1px)" },
                  }}>
                  <Box sx={{ p: 2, position: "relative" }}>
                    {(() => {
                      const root = tile.parent_scan_id || tile.id;
                      const versions = versionMap.get(root) || [];
                      const versionCount = versions.length;
                      // Only render the version icon on the newest tile in
                      // the group — older ones already show as siblings in
                      // the history dialog.
                      const isLive = versions[0]?.id === tile.id;
                      return (
                        <>
                          <Tooltip title="Delete assessment">
                            <IconButton
                              size="small"
                              onClick={(e) => { e.stopPropagation(); setPendingDeleteScan(tile); }}
                              sx={{
                                position: "absolute", top: 6, right: 6,
                                color: "rgba(255,255,255,0.35)",
                                "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" },
                              }}
                            >
                              <DeleteOutlined sx={{ fontSize: 16 }} />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title={status === "running" ? "Rescan disabled while a run is in progress" : "Rescan — keeps history of this assessment"}>
                            <span>
                              <IconButton
                                size="small"
                                disabled={status === "running" || rescanMutation.isPending}
                                onClick={(e) => { e.stopPropagation(); rescanMutation.mutate(tile); }}
                                sx={{
                                  position: "absolute", top: 6, right: 32,
                                  color: "rgba(255,255,255,0.35)",
                                  "&:hover": { color: "#4285F4", bgcolor: "rgba(66,133,244,0.08)" },
                                  "&.Mui-disabled": { color: "rgba(255,255,255,0.15)" },
                                }}
                              >
                                <Replay sx={{ fontSize: 16 }} />
                              </IconButton>
                            </span>
                          </Tooltip>
                          {isLive && versionCount > 1 && (
                            <Tooltip title={`${versionCount - 1} previous run${versionCount - 1 === 1 ? "" : "s"}`}>
                              <IconButton
                                size="small"
                                onClick={(e) => { e.stopPropagation(); setHistoryOpenForRoot(root); }}
                                sx={{
                                  position: "absolute", top: 6, right: 58,
                                  color: "#FBBC04",
                                  bgcolor: "rgba(251,188,4,0.10)",
                                  "&:hover": { bgcolor: "rgba(251,188,4,0.22)" },
                                  pr: 0.5,
                                }}
                              >
                                <Badge
                                  badgeContent={versionCount}
                                  sx={{ "& .MuiBadge-badge": { fontSize: 9, height: 14, minWidth: 14, bgcolor: "#FBBC04", color: "#0d1117", fontWeight: 700 } }}
                                >
                                  <History sx={{ fontSize: 16 }} />
                                </Badge>
                              </IconButton>
                            </Tooltip>
                          )}
                        </>
                      );
                    })()}
                    <Chip
                      label={status}
                      size="small"
                      sx={{
                        position: "absolute", top: 12, right: 84,
                        bgcolor: `${statusColor}20`,
                        color: statusColor, fontWeight: 700, fontSize: 10, height: 20,
                        textTransform: "uppercase", letterSpacing: 0.5,
                      }} />
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, pr: 9 }}>
                      <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: catColor, flexShrink: 0 }} />
                      <Typography variant="caption"
                        sx={{ color: catColor, fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1 }}>
                        {cat}
                      </Typography>
                    </Box>
                    <Typography sx={{ color: "white", fontWeight: 700, fontSize: 15, lineHeight: 1.25, mb: 0.5 }}>
                      {tile.tile_name}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 1.25 }}>
                      {tile.started_at ? fromNow(tile.started_at) : "Not started"} · {dur}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.7)", display: "block", fontSize: 12, mb: 1.25, minHeight: 32 }}>
                      {tile.name || `${tile.scan_type} scan`}
                      {tile.findings_count > 0 ? ` · ${tile.findings_count} finding${tile.findings_count === 1 ? "" : "s"}` : ""}
                      {tile.framework ? ` · ${tile.framework}` : ""}
                    </Typography>
                    <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", alignItems: "center" }}>
                      {tile.summary?.critical > 0 && (
                        <Chip size="small" label={`${tile.summary.critical}C`}
                          sx={{ bgcolor: "rgba(234,67,53,0.18)", color: "#EA4335", height: 18, fontSize: 10, fontWeight: 700 }} />
                      )}
                      {tile.summary?.high > 0 && (
                        <Chip size="small" label={`${tile.summary.high}H`}
                          sx={{ bgcolor: "rgba(255,112,67,0.18)", color: "#FF7043", height: 18, fontSize: 10, fontWeight: 700 }} />
                      )}
                      {tile.summary?.medium > 0 && (
                        <Chip size="small" label={`${tile.summary.medium}M`}
                          sx={{ bgcolor: "rgba(251,188,4,0.18)", color: "#FBBC04", height: 18, fontSize: 10, fontWeight: 700 }} />
                      )}
                      {tile.has_verdict && (
                        <Chip size="small" label="AI verdict"
                          sx={{ bgcolor: "rgba(66,133,244,0.18)", color: "#4285F4", height: 18, fontSize: 10, fontWeight: 700 }} />
                      )}
                      <Box sx={{ flex: 1 }} />
                      {agentTypes.length > 0 && (
                        <Tooltip title={`Agents that ran: ${agentTypes.join(", ")}`}>
                          <Chip size="small" label={`${agentTypes.length} agent${agentTypes.length === 1 ? "" : "s"}`}
                            sx={{ bgcolor: "rgba(124,77,255,0.15)", color: "#9C27B0", height: 18, fontSize: 10, fontWeight: 700 }} />
                        </Tooltip>
                      )}
                    </Box>
                  </Box>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}

      {/* Start scan dialog — category → scanner cascade */}
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
        <DialogTitle>
          Start New Scan
          <Typography variant="caption" sx={{ display: "block", color: "rgba(255,255,255,0.5)" }}>
            Pick a category, choose a scanner, then point it at a connector.
          </Typography>
        </DialogTitle>
        <DialogContent dividers sx={{ borderColor: "rgba(255,255,255,0.08)" }}>
          {/* Client picker — required first step. Allows starting a scan
              from this dialog even when no tile-grid client filter is set. */}
          <FormControl fullWidth size="small" sx={{ mb: 2 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
            <Select
              value={selectedClientId}
              onChange={(e) => {
                setSelectedClientId(e.target.value);
                setSelectedProjectId("");
                setConnectorId("");
                setScannerId("");
              }}
              label="Client"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}
            >
              {clients.map((c) => (
                <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>
              ))}
              {clients.length === 0 && (
                <MenuItem value="" disabled>No clients you can access — ask an admin for a grant</MenuItem>
              )}
            </Select>
          </FormControl>

          {!selectedClientId ? (
            <Box sx={{
              p: 3, textAlign: "center", border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 1.5,
              color: "rgba(255,255,255,0.55)",
            }}>
              <Typography variant="body2">Pick a client above to continue.</Typography>
            </Box>
          ) : (
          <>
          {/* Category tabs */}
          <Tabs
            value={category}
            onChange={(_, v) => { setCategory(v as ScanCategory); setScannerId(""); setConnectorId(""); }}
            sx={{
              mb: 2,
              borderBottom: "1px solid rgba(255,255,255,0.08)",
              "& .MuiTab-root": { color: "rgba(255,255,255,0.6)", textTransform: "none", fontWeight: 600, minHeight: 40 },
              "& .Mui-selected": { color: CATEGORY_COLOR[category] },
              "& .MuiTabs-indicator": { backgroundColor: CATEGORY_COLOR[category] },
            }}
          >
            {CATEGORY_ORDER.map((c) => (
              <Tab key={c} value={c} label={CATEGORY_LABEL[c]} />
            ))}
          </Tabs>

          {category === "cloud" ? (
            // Cloud & Identity keeps the existing scan-type / framework form.
            <Grid container spacing={2} sx={{ mt: 0.5 }}>
              <Grid size={{ xs: 12 }}>
                <TextField fullWidth size="small" label="Scan name (optional)"
                  value={scanName} onChange={(e) => setScanName(e.target.value)}
                  placeholder='e.g. "Weekly Azure prod compliance"'
                  slotProps={{ inputLabel: { sx: { color: 'rgba(255,255,255,0.5)' } }, htmlInput: { style: { color: 'white' } } }}
                  sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
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
              <Grid size={{ xs: 12, md: 6 }}>
                <FormControl fullWidth size="small">
                  <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Connector (optional)</InputLabel>
                  <Select value={connectorId} onChange={(e) => setConnectorId(e.target.value)} label="Connector"
                    sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                    <MenuItem value="">All connectors</MenuItem>
                    {connectors
                      .filter((c) => !SCANNERS.some((s) => s.connectorType === c.connector_type))
                      .map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
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
          ) : (
            // Scanner-driven categories (DAST/SAST/Network/Dependency)
            <Box>
              {/* Scanner cards */}
              <Stack spacing={1} sx={{ mb: 2 }}>
                {SCANNERS.filter((s) => s.category === category).map((s) => {
                  const isPicked = scannerId === s.id;
                  const isLive = s.status === "live";
                  return (
                    <Card
                      key={s.id}
                      onClick={() => isLive && setScannerId(s.id)}
                      sx={{
                        bgcolor: isPicked ? "rgba(66,133,244,0.08)" : "transparent",
                        border: `1px solid ${isPicked ? CATEGORY_COLOR[category] : "rgba(255,255,255,0.1)"}`,
                        borderRadius: 2, p: 1.5, cursor: isLive ? "pointer" : "not-allowed",
                        opacity: isLive ? 1 : 0.55,
                        transition: "all 0.15s",
                        "&:hover": isLive ? { borderColor: CATEGORY_COLOR[category], bgcolor: "rgba(255,255,255,0.03)" } : {},
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
                        <Typography sx={{ fontWeight: 600, fontSize: 14, color: "white" }}>{s.name}</Typography>
                        <Chip
                          label={isLive ? "Live" : "Coming soon"}
                          size="small"
                          sx={{
                            bgcolor: isLive ? "rgba(52,168,83,0.15)" : "rgba(255,255,255,0.06)",
                            color: isLive ? "#34A853" : "rgba(255,255,255,0.5)",
                            fontWeight: 700, fontSize: 10, height: 20,
                          }}
                        />
                      </Box>
                      <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.55)", display: "block" }}>
                        {s.description}
                      </Typography>
                    </Card>
                  );
                })}
              </Stack>

              {/* Per-scanner config: connector picker + name */}
              {scannerId && (
                <Grid container spacing={2}>
                  <Grid size={{ xs: 12 }}>
                    <TextField fullWidth size="small" label="Scan name (optional)"
                      value={scanName} onChange={(e) => setScanName(e.target.value)}
                      slotProps={{ inputLabel: { sx: { color: 'rgba(255,255,255,0.5)' } }, htmlInput: { style: { color: 'white' } } }}
                      sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }} />
                  </Grid>
                  <Grid size={{ xs: 12 }}>
                    <FormControl fullWidth size="small">
                      <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Connector</InputLabel>
                      <Select value={connectorId} onChange={(e) => setConnectorId(e.target.value)} label="Connector"
                        sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                        {(() => {
                          const def = SCANNERS.find((s) => s.id === scannerId);
                          const matching = connectors.filter((c) => c.connector_type === def?.connectorType);
                          if (matching.length === 0) {
                            return <MenuItem disabled value="">No {def?.name} connector configured — create one under Connectors first</MenuItem>;
                          }
                          return matching.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>);
                        })()}
                      </Select>
                    </FormControl>
                  </Grid>
                </Grid>
              )}
            </Box>
          )}
          </>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setOpen(false)} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
          <Button variant="contained" startIcon={<PlayArrow />}
            disabled={
              startMutation.isPending ||
              (category !== "cloud" && (!scannerId || !connectorId))
            }
            onClick={() => startMutation.mutate({
              scan_type: scanType,
              connector_id: connectorId || undefined,
              framework: framework || undefined,
              name: scanName || undefined,
            })}>
            {startMutation.isPending ? <CircularProgress size={18} /> : "Start Scan"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Findings dialog */}
      <Dialog open={!!viewScan} onClose={() => setViewScan(null)} maxWidth="md" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
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
              <CircularProgress sx={{ color: "#4285F4" }} />
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
                  <TableCell align="right" sx={{ width: 44 }} />
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
                    <TableCell><Typography variant="caption" sx={{ color: "#4285F4" }}>{f.cve_id || "—"}</Typography></TableCell>
                    <TableCell><Typography variant="caption">{f.cvss_score ?? "—"}</Typography></TableCell>
                    <TableCell align="right" sx={{ width: 44 }}>
                      <Tooltip title="Delete finding">
                        <IconButton
                          size="small"
                          onClick={(e) => { e.stopPropagation(); setPendingDeleteFinding(f); }}
                          sx={{
                            color: "rgba(255,255,255,0.4)",
                            "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" },
                          }}
                        >
                          <DeleteOutlined sx={{ fontSize: 18 }} />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
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

      {/* Version history — all rescans of the same assessment, newest first */}
      <Dialog open={!!historyOpenForRoot} onClose={() => setHistoryOpenForRoot(null)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <History sx={{ color: "#FBBC04" }} />
            <Typography component="span" sx={{ fontWeight: 700 }}>Assessment history</Typography>
          </Box>
        </DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          {historyOpenForRoot && (() => {
            const versions = versionMap.get(historyOpenForRoot) || [];
            return (
              <Box>
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 1.5 }}>
                  {versions.length} run{versions.length === 1 ? "" : "s"} for this assessment, newest first. v{versions.length} is the live tile; older runs stay queryable for comparison.
                </Typography>
                {versions.map((v: any, idx: number) => {
                  const isLatest = idx === 0;
                  const versionNum = versions.length - idx;
                  const vStatus = (v.status || "").toLowerCase();
                  const vColor = STATUS_COLOR[vStatus] || "rgba(255,255,255,0.4)";
                  return (
                    <Box
                      key={v.id}
                      onClick={() => { setHistoryOpenForRoot(null); navigate(`/scans/${v.id}`); }}
                      sx={{
                        display: "flex", alignItems: "center", gap: 1.5, p: 1.25, mb: 0.75,
                        borderRadius: 1, cursor: "pointer",
                        bgcolor: isLatest ? "rgba(66,133,244,0.08)" : "rgba(255,255,255,0.03)",
                        border: `1px solid ${isLatest ? "rgba(66,133,244,0.3)" : "rgba(255,255,255,0.06)"}`,
                        "&:hover": { borderColor: "#4285F4", bgcolor: "rgba(66,133,244,0.12)" },
                      }}
                    >
                      <Chip
                        label={`v${versionNum}${isLatest ? " · LIVE" : ""}`}
                        size="small"
                        sx={{
                          height: 22, fontSize: 10, fontWeight: 700, letterSpacing: 0.5, minWidth: 78,
                          bgcolor: isLatest ? "rgba(66,133,244,0.2)" : "rgba(255,255,255,0.06)",
                          color: isLatest ? "#4285F4" : "rgba(255,255,255,0.65)",
                        }} />
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography variant="body2" sx={{ color: "white", fontSize: 13, fontWeight: 500 }}>
                          {v.started_at ? new Date(v.started_at).toLocaleString() : (v.created_at ? new Date(v.created_at).toLocaleString() : "—")}
                        </Typography>
                        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                          {v.findings_count || 0} finding{(v.findings_count || 0) === 1 ? "" : "s"}
                          {v.duration_seconds != null
                            ? ` · ${v.duration_seconds >= 60 ? Math.round(v.duration_seconds / 60) + " min" : v.duration_seconds + "s"}`
                            : ""}
                        </Typography>
                      </Box>
                      <Chip label={vStatus} size="small"
                        sx={{ height: 18, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                          bgcolor: `${vColor}25`, color: vColor }} />
                    </Box>
                  );
                })}
              </Box>
            );
          })()}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setHistoryOpenForRoot(null)} sx={{ color: "rgba(255,255,255,0.5)" }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Confirm assessment (scan) delete */}
      <Dialog open={!!pendingDeleteScan} onClose={() => setPendingDeleteScan(null)}
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>Delete assessment?</DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.75)" }}>
            This permanently removes the scan and every finding, agent run, and AI verdict tied to it. It does NOT delete the connector or affect future scans.
          </Typography>
          {pendingDeleteScan && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "white", fontWeight: 600 }}>{pendingDeleteScan.tile_name}</Typography>
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                {pendingDeleteScan.scan_type} · {pendingDeleteScan.findings_count ?? 0} finding{pendingDeleteScan.findings_count === 1 ? "" : "s"}
                {pendingDeleteScan.framework ? ` · ${pendingDeleteScan.framework}` : ""}
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDeleteScan(null)} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
          <Button
            variant="contained"
            disabled={deleteScanMutation.isPending}
            onClick={() => pendingDeleteScan && deleteScanMutation.mutate(pendingDeleteScan)}
            sx={{ bgcolor: "#EA4335", "&:hover": { bgcolor: "#c5362b" } }}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Confirm finding delete */}
      <Dialog open={!!pendingDeleteFinding} onClose={() => setPendingDeleteFinding(null)}
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>Delete finding?</DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.75)" }}>
            This permanently removes the finding. If the same issue is detected on the next scan it will be re-created.
          </Typography>
          {pendingDeleteFinding && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "white", fontWeight: 600 }}>{pendingDeleteFinding.title || "(no title)"}</Typography>
              {pendingDeleteFinding.resource_id && (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>{pendingDeleteFinding.resource_id}</Typography>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDeleteFinding(null)} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
          <Button
            variant="contained"
            disabled={deleteFindingMutation.isPending}
            onClick={() => pendingDeleteFinding && deleteFindingMutation.mutate(pendingDeleteFinding.id)}
            sx={{ bgcolor: "#EA4335", "&:hover": { bgcolor: "#c5362b" } }}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
