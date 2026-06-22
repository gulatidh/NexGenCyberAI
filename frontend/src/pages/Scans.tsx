import React, { useState } from "react";
import { useViewMode } from "../theme/ViewModeContext";
import {
  Box, Typography, Button, Card, Grid, Chip,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Select, MenuItem, FormControl, InputLabel, CircularProgress,
  Tabs, Tab, Stack, Tooltip, Divider, IconButton, Badge,
  Table, TableHead, TableRow, TableCell, TableBody,
} from "@mui/material";
import { PlayArrow, Add, Refresh, Visibility, DeleteOutlined, Replay, History } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { scansApi, connectorsApi, clientsApi, frameworksApi, assessmentsApi, findingsApi, apiClient } from "../services/api";
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
  { id: "ai_code_review", name: "AI Code Review", connectorType: "ai_code_review", category: "sast", status: "live",
    description: "LLM-powered vulnerability discovery — triage, per-function analysis, self-critique, and cross-file taint tracing. Runs fully in-process; no GitHub Actions required." },
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
  { id: "owasp_dc", name: "OWASP Dependency-Check", connectorType: "owasp_dc", category: "dependency", status: "live",
    description: "SCA / CVE matching for application dependencies. Clones the repo and runs Dependency-Check in GitHub Actions (add an NVD API key to avoid rate-limits)." },
  { id: "gitleaks", name: "Gitleaks", connectorType: "gitleaks", category: "dependency", status: "live",
    description: "Secret scanner for git history. Runs in GitHub Actions." },
  { id: "trufflehog", name: "TruffleHog", connectorType: "trufflehog", category: "dependency", status: "live",
    description: "Secret scanner (git + filesystem) with verification. Runs in GitHub Actions." },
];

const CATEGORY_ORDER: ScanCategory[] = ["cloud", "dast", "sast", "network", "dependency"];

export default function Scans() {
  const { canAct } = useViewMode();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [selectedClientId, setSelectedClientId] = useState(() => localStorage.getItem("aegis-active-client") || "");
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
  // CodeQL binary-mode upload state
  const [codeqlMode, setCodeqlMode] = useState<"source" | "binary">("source");
  const [binaryFile, setBinaryFile] = useState<File | null>(null);
  // AI Code Review source mode: git repo vs zip archive upload
  const [acrMode, setAcrMode] = useState<"repo" | "archive">("repo");
  const [acrRepoUrl, setAcrRepoUrl] = useState("");
  const [acrGitToken, setAcrGitToken] = useState("");
  const [codeArchive, setCodeArchive] = useState<File | null>(null);

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
  // Group scans by version root (parent_scan_id ?? id). Only the newest
  // sibling in each group renders as its own tile — older versions live in
  // the History dialog accessible via the yellow badge.
  const { tiles, versionMap: _versionMap } = React.useMemo(() => {
    const allScans = (tilesData?.scans || []) as any[];
    const groups = new Map<string, any[]>();
    for (const t of allScans) {
      const root = t.parent_scan_id || t.id;
      if (!groups.has(root)) groups.set(root, []);
      groups.get(root)!.push(t);
    }
    groups.forEach((arr) => {
      arr.sort((a, b) => {
        const at = new Date(a.started_at || a.created_at || 0).getTime();
        const bt = new Date(b.started_at || b.created_at || 0).getTime();
        return bt - at;
      });
    });
    // Keep only the newest sibling per group, then apply user filters.
    const latestIds = new Set<string>();
    groups.forEach((arr) => { if (arr[0]) latestIds.add(arr[0].id); });
    const filtered = allScans
      .filter((t) => latestIds.has(t.id))
      .filter((t) => {
        if (tileStatusFilter && t.status !== tileStatusFilter) return false;
        if (tileCategoryFilter && t.category !== tileCategoryFilter) return false;
        if (selectedClientId && t.client_id !== selectedClientId) return false;
        return true;
      });
    return { tiles: filtered, versionMap: groups };
  }, [tilesData, tileStatusFilter, tileCategoryFilter, selectedClientId]);

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
      setOpen(false); setScanName(""); setAcrRepoUrl(""); setAcrGitToken(""); setAcrMode("repo");
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

  const versionMap = _versionMap;
  const [historyOpenForRoot, setHistoryOpenForRoot] = useState<string | null>(null);

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Assessments</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Every scan across all clients · click a tile for the AI verdict, findings, and agent runs
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Client (filter)</InputLabel>
            <Select value={selectedClientId} onChange={(e) => { setSelectedClientId(e.target.value); localStorage.setItem("aegis-active-client", e.target.value); setSelectedProjectId(""); }} label="Client (filter)"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All clients</MenuItem>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <Button variant="outlined" startIcon={<Refresh />}
            onClick={() => refetchTiles()}
            sx={{ borderColor: "divider", color: "text.secondary" }}>Refresh</Button>
          <Tooltip title={!canAct ? "Read-only in Executive mode — switch to Analyst (top-right) to run scans." : ""}>
            <span>
              <Button
                variant="contained"
                startIcon={<Add />}
                disabled={clients.length === 0 || !canAct}
                onClick={() => setOpen(true)}
              >
                New Assessment
              </Button>
            </span>
          </Tooltip>
        </Box>
      </Box>

      {/* Tile filter chips */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, flexWrap: "wrap", mb: 2 }}>
        <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600 }}>STATUS</Typography>
        {["completed", "running", "failed", "pending", "cancelled"].map((s) => (
          <Chip key={s} size="small" label={s.charAt(0).toUpperCase() + s.slice(1)}
            onClick={() => setTileStatusFilter(tileStatusFilter === s ? "" : s)}
            sx={{
              cursor: "pointer",
              bgcolor: tileStatusFilter === s ? `${STATUS_COLOR[s] || "#888"}25` : "rgba(255,255,255,0.04)",
              color: tileStatusFilter === s ? (STATUS_COLOR[s] || "#888") : "text.secondary",
              border: tileStatusFilter === s ? `1px solid ${STATUS_COLOR[s] || "#888"}` : "1px solid transparent",
              fontWeight: tileStatusFilter === s ? 700 : 400,
            }} />
        ))}
        <Box sx={{ width: 1, height: 18, bgcolor: "rgba(255,255,255,0.1)", mx: 1 }} />
        <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600 }}>CATEGORY</Typography>
        {["DAST", "SAST", "Network", "Dependency", "Cloud", "Other"].map((c) => (
          <Chip key={c} size="small" label={c}
            onClick={() => setTileCategoryFilter(tileCategoryFilter === c ? "" : c)}
            sx={{
              cursor: "pointer",
              bgcolor: tileCategoryFilter === c ? "rgba(66,133,244,0.2)" : "rgba(255,255,255,0.04)",
              color: tileCategoryFilter === c ? "#4285F4" : "text.secondary",
              border: tileCategoryFilter === c ? "1px solid #4285F4" : "1px solid transparent",
              fontWeight: tileCategoryFilter === c ? 700 : 400,
            }} />
        ))}
        {(tileStatusFilter || tileCategoryFilter) && (
          <Button size="small" sx={{ ml: 0.5, color: "text.secondary", fontSize: 11 }}
            onClick={() => { setTileStatusFilter(""); setTileCategoryFilter(""); }}>
            Clear
          </Button>
        )}
        <Box sx={{ flex: 1 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>
          Showing {tiles.length} of {tilesData?.scans?.length || 0} assessments
        </Typography>
      </Box>

      {tilesLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 6 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      ) : tiles.length === 0 ? (
        <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <Visibility sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          {clients.length === 0 ? (
            <>
              <Typography sx={{ color: "text.secondary", fontWeight: 600, mb: 0.5 }}>
                No accessible clients
              </Typography>
              <Typography variant="body2" sx={{ color: "text.secondary" }}>
                Your account has no RBAC grants yet. Ask a global admin to grant you reader / editor / admin access from <b>Settings → Administration → Grant access</b>.
              </Typography>
            </>
          ) : (tilesData?.scans?.length || 0) === 0 ? (
            <>
              <Typography sx={{ color: "text.secondary", fontWeight: 600, mb: 0.5 }}>
                No assessments yet
              </Typography>
              <Typography variant="body2" sx={{ color: "text.secondary" }}>
                Click "New Assessment" to run your first scan.
              </Typography>
            </>
          ) : (
            <>
              <Typography sx={{ color: "text.secondary", fontWeight: 600, mb: 0.5 }}>
                No assessments match the current filters
              </Typography>
              <Typography variant="body2" sx={{ color: "text.secondary" }}>
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
            // Distinct buddies that ran — prefer the friendly catalog name so
            // advisory buddies (all stored as agent_type="orchestrator") don't
            // collapse into one entry.
            const agentRuns = (tile.agents_ran || []) as any[];
            const agentNames = Array.from(new Set(agentRuns.map((a) => a.agent_name || a.agent_type)));
            const anyAgentFailed = agentRuns.some(
              (a) => /fail|error/i.test(String(a.status || "")),
            );
            return (
              <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={tile.id}>
                <Card
                  onClick={() => navigate(`/scans/${tile.id}`)}
                  sx={{
                    bgcolor: "background.paper",
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
                                color: "text.secondary",
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
                                  color: "text.secondary",
                                  "&:hover": { color: "#4285F4", bgcolor: "rgba(66,133,244,0.08)" },
                                  "&.Mui-disabled": { color: "text.secondary" },
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
                    <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 15, lineHeight: 1.25, mb: 0.5 }}>
                      {tile.tile_name}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.25 }}>
                      {tile.started_at ? fromNow(tile.started_at) : "Not started"} · {dur}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block", fontSize: 12, mb: 1.25, minHeight: 32 }}>
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
                      {tile.summary?.tokens_used != null && (() => {
                        const used = tile.summary.tokens_used as number;
                        const budget = tile.summary.token_budget as number;
                        const pct = tile.summary.budget_pct as number;
                        const label = `${(used / 1000).toFixed(0)}k tokens`;
                        const tipText = `${used.toLocaleString()} / ${budget.toLocaleString()} tokens used (${pct}% of budget)`;
                        const color = pct >= 90 ? "#EA4335" : pct >= 70 ? "#FBBC04" : "#34A853";
                        const bg = pct >= 90 ? "rgba(234,67,53,0.15)" : pct >= 70 ? "rgba(251,188,4,0.15)" : "rgba(52,168,83,0.15)";
                        return (
                          <Tooltip title={tipText}>
                            <Chip size="small" label={label}
                              sx={{ bgcolor: bg, color, height: 18, fontSize: 10, fontWeight: 700 }} />
                          </Tooltip>
                        );
                      })()}
                      <Box sx={{ flex: 1 }} />
                      {agentNames.length > 0 && (
                        <Tooltip title={`${anyAgentFailed ? "Some agent runs failed. " : ""}Agents that ran: ${agentNames.join(", ")}`}>
                          <Chip size="small" label={`${agentNames.length} agent${agentNames.length === 1 ? "" : "s"}`}
                            sx={{
                              bgcolor: anyAgentFailed ? "rgba(234,67,53,0.18)" : "rgba(124,77,255,0.15)",
                              color: anyAgentFailed ? "#EA4335" : "#9C27B0",
                              height: 18, fontSize: 10, fontWeight: 700,
                            }} />
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
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle>
          Start New Scan
          <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>
            Pick a category, choose a scanner, then point it at a connector.
          </Typography>
        </DialogTitle>
        <DialogContent dividers sx={{ borderColor: "divider" }}>
          {/* Client picker — required first step. Allows starting a scan
              from this dialog even when no tile-grid client filter is set. */}
          <FormControl fullWidth size="small" sx={{ mb: 2 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Client</InputLabel>
            <Select
              value={selectedClientId}
              onChange={(e) => {
                setSelectedClientId(e.target.value);
                localStorage.setItem("aegis-active-client", e.target.value);
                setSelectedProjectId("");
                setConnectorId("");
                setScannerId("");
              }}
              label="Client"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
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
              color: "text.secondary",
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
              "& .MuiTab-root": { color: "text.secondary", textTransform: "none", fontWeight: 600, minHeight: 40 },
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
                  sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <FormControl fullWidth size="small">
                  <InputLabel sx={{ color: "text.secondary" }}>Scan Type</InputLabel>
                  <Select value={scanType} onChange={(e) => setScanType(e.target.value as ScanType)} label="Scan Type"
                    sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                    <MenuItem value="vulnerability">Vulnerability Assessment</MenuItem>
                    <MenuItem value="configuration">Configuration Review</MenuItem>
                    <MenuItem value="compliance">Compliance Assessment</MenuItem>
                    <MenuItem value="full">Full Assessment (all)</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <FormControl fullWidth size="small">
                  <InputLabel sx={{ color: "text.secondary" }}>Connector (optional)</InputLabel>
                  <Select value={connectorId} onChange={(e) => setConnectorId(e.target.value)} label="Connector"
                    sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                    <MenuItem value="">All connectors</MenuItem>
                    {connectors
                      .filter((c) => !SCANNERS.some((s) => s.connectorType === c.connector_type))
                      .map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
                  </Select>
                </FormControl>
              </Grid>
              <Grid size={{ xs: 12 }}>
                <FormControl fullWidth size="small">
                  <InputLabel sx={{ color: "text.secondary" }}>Framework</InputLabel>
                  <Select value={framework} onChange={(e) => setFramework(e.target.value as FrameworkType)} label="Framework"
                    sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
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
                        <Typography sx={{ fontWeight: 600, fontSize: 14, color: "text.primary" }}>{s.name}</Typography>
                        <Chip
                          label={isLive ? "Live" : "Coming soon"}
                          size="small"
                          sx={{
                            bgcolor: isLive ? "rgba(52,168,83,0.15)" : "rgba(255,255,255,0.06)",
                            color: isLive ? "#34A853" : "text.secondary",
                            fontWeight: 700, fontSize: 10, height: 20,
                          }}
                        />
                      </Box>
                      <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
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
                      sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
                  </Grid>
                  {scannerId !== "ai_code_review" && (
                    <Grid size={{ xs: 12 }}>
                      <FormControl fullWidth size="small">
                        <InputLabel sx={{ color: "text.secondary" }}>Connector</InputLabel>
                        <Select value={connectorId} onChange={(e) => setConnectorId(e.target.value)} label="Connector"
                          sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
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
                  )}
                  {/* AI Code Review — pick git repo mode vs archive upload. */}
                  {scannerId === "ai_code_review" && (
                    <>
                      <Grid size={{ xs: 12 }}>
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                          SOURCE MODE
                        </Typography>
                        <Box sx={{ display: "flex", gap: 1 }}>
                          {([
                            { id: "repo",    label: "Git repo",       hint: "The connector's repo_url is cloned and analysed. Best for CI/CD integration." },
                            { id: "archive", label: "Upload archive",  hint: "Upload a .zip or .tar.gz of your source code. No git credentials needed." },
                          ] as const).map((opt) => {
                            const picked = acrMode === opt.id;
                            return (
                              <Tooltip key={opt.id} title={opt.hint}>
                                <Card
                                  onClick={() => { setAcrMode(opt.id); if (opt.id === "repo") setCodeArchive(null); }}
                                  sx={{
                                    flex: 1, p: 1.25, cursor: "pointer",
                                    bgcolor: picked ? "rgba(66,133,244,0.08)" : "transparent",
                                    border: `1px solid ${picked ? "#4285F4" : "rgba(255,255,255,0.1)"}`,
                                    borderRadius: 1.5,
                                    "&:hover": { borderColor: "#4285F4" },
                                  }}
                                >
                                  <Typography sx={{ color: "text.primary", fontSize: 13, fontWeight: 600 }}>{opt.label}</Typography>
                                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.25 }}>
                                    {opt.hint}
                                  </Typography>
                                </Card>
                              </Tooltip>
                            );
                          })}
                        </Box>
                      </Grid>
                      {acrMode === "repo" && (
                        <>
                          <Grid size={{ xs: 12 }}>
                            <TextField
                              fullWidth
                              size="small"
                              label="Repository URL"
                              placeholder="https://github.com/owner/repo"
                              value={acrRepoUrl}
                              onChange={(e) => setAcrRepoUrl(e.target.value)}
                              slotProps={{ input: { sx: { color: "text.primary" } } }}
                            />
                          </Grid>
                          <Grid size={{ xs: 12 }}>
                            <TextField
                              fullWidth
                              size="small"
                              type="password"
                              label="Access Token (optional — required for private repos)"
                              placeholder="ghp_xxxxxxxxxxxx"
                              value={acrGitToken}
                              onChange={(e) => setAcrGitToken(e.target.value)}
                              helperText="GitHub PAT or GitLab token with repo read access. Not stored after the scan runs."
                              slotProps={{ input: { sx: { color: "text.primary" } } }}
                            />
                          </Grid>
                        </>
                      )}
                      {acrMode === "archive" && (
                        <Grid size={{ xs: 12 }}>
                          <Box sx={{ p: 1.5, border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 1.5 }}>
                            <Button
                              component="label"
                              size="small"
                              variant="outlined"
                              sx={{ borderColor: "divider", color: "text.secondary" }}
                            >
                              {codeArchive ? "Change archive" : "Choose code archive"}
                              <input
                                hidden
                                type="file"
                                accept=".zip,.tar.gz,.tgz,.tar"
                                onChange={(e) => setCodeArchive(e.target.files?.[0] || null)}
                              />
                            </Button>
                            {codeArchive && (
                              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>
                                <b>{codeArchive.name}</b> · {(codeArchive.size / 1024 / 1024).toFixed(2)} MB
                              </Typography>
                            )}
                            {!codeArchive && (
                              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>
                                Accepts .zip, .tar.gz, or .tar archives of your source code.
                              </Typography>
                            )}
                          </Box>
                        </Grid>
                      )}
                    </>
                  )}
                  {/* CodeQL-only: pick source-repo mode vs upload-binary mode. */}
                  {scannerId === "codeql" && (
                    <>
                      <Grid size={{ xs: 12 }}>
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                          SCAN MODE
                        </Typography>
                        <Box sx={{ display: "flex", gap: 1 }}>
                          {([
                            { id: "source", label: "Source repo", hint: "Workflow clones the connector's repo_url and runs the security-and-quality suite." },
                            { id: "binary", label: "Upload binary", hint: "Upload a JAR / WAR / EAR / ZIP / tar.gz. Workflow runs CodeQL with --build-mode=none (JVM / .NET). 500 MB max. Auto-deleted after 30 days." },
                          ] as const).map((opt) => {
                            const picked = codeqlMode === opt.id;
                            return (
                              <Tooltip key={opt.id} title={opt.hint}>
                                <Card
                                  onClick={() => { setCodeqlMode(opt.id); if (opt.id === "source") setBinaryFile(null); }}
                                  sx={{
                                    flex: 1, p: 1.25, cursor: "pointer",
                                    bgcolor: picked ? "rgba(66,133,244,0.08)" : "transparent",
                                    border: `1px solid ${picked ? "#4285F4" : "rgba(255,255,255,0.1)"}`,
                                    borderRadius: 1.5,
                                    "&:hover": { borderColor: "#4285F4" },
                                  }}
                                >
                                  <Typography sx={{ color: "text.primary", fontSize: 13, fontWeight: 600 }}>{opt.label}</Typography>
                                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.25 }}>
                                    {opt.hint}
                                  </Typography>
                                </Card>
                              </Tooltip>
                            );
                          })}
                        </Box>
                      </Grid>
                      {codeqlMode === "binary" && (
                        <Grid size={{ xs: 12 }}>
                          <Box sx={{ p: 1.5, border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 1.5 }}>
                            <Button
                              component="label"
                              size="small"
                              variant="outlined"
                              sx={{ borderColor: "divider", color: "text.secondary" }}
                            >
                              {binaryFile ? "Change file" : "Choose binary archive"}
                              <input
                                hidden
                                type="file"
                                accept=".jar,.war,.ear,.zip,.tar,.tar.gz,.tgz,.dll,.exe"
                                onChange={(e) => setBinaryFile(e.target.files?.[0] || null)}
                              />
                            </Button>
                            {binaryFile && (
                              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>
                                <b>{binaryFile.name}</b> · {(binaryFile.size / 1024 / 1024).toFixed(2)} MB
                              </Typography>
                            )}
                            {!binaryFile && (
                              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>
                                Accepts JAR / WAR / EAR / ZIP / tar.gz / DLL / EXE up to 500 MB.
                              </Typography>
                            )}
                          </Box>
                        </Grid>
                      )}
                    </>
                  )}
                </Grid>
              )}
            </Box>
          )}
          </>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => { setOpen(false); setAcrRepoUrl(""); setAcrGitToken(""); setAcrMode("repo"); }} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button variant="contained" startIcon={<PlayArrow />}
            disabled={
              startMutation.isPending ||
              (category !== "cloud" && scannerId !== "ai_code_review" && (!scannerId || !connectorId)) ||
              (scannerId === "codeql" && codeqlMode === "binary" && !binaryFile) ||
              (scannerId === "ai_code_review" && acrMode === "archive" && !codeArchive) ||
              (scannerId === "ai_code_review" && acrMode === "repo" && !acrRepoUrl.trim())
            }
            onClick={async () => {
              const isBinary = scannerId === "codeql" && codeqlMode === "binary" && binaryFile;
              const isAcrArchive = scannerId === "ai_code_review" && acrMode === "archive" && codeArchive;
              if (isBinary) {
                try {
                  // Two-step: create scan with defer_dispatch=true so the
                  // workflow only fires AFTER the binary upload lands.
                  const created = await scansApi.start(selectedClientId, {
                    scan_type: scanType,
                    connector_id: connectorId || undefined,
                    framework: framework || undefined,
                    name: scanName || undefined,
                    defer_dispatch: true,
                  });
                  const fd = new FormData();
                  fd.append("file", binaryFile);
                  await apiClient.post(
                    `/clients/${selectedClientId}/scans/${created.id}/upload-binary`,
                    fd,
                    { headers: { "Content-Type": "multipart/form-data" } }
                  );
                  qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
                  setOpen(false); setScanName(""); setBinaryFile(null);
                  toast.success(`Uploaded ${binaryFile.name} — scan starting`);
                } catch (e: any) {
                  toast.error(e?.response?.data?.detail || "Binary upload failed");
                }
              } else if (isAcrArchive) {
                try {
                  // Two-step: create scan (deferred), then upload archive which
                  // fires the AI review pipeline as a background task.
                  const created = await scansApi.start(selectedClientId, {
                    scan_type: scanType,
                    connector_id: connectorId || undefined,
                    framework: framework || undefined,
                    name: scanName || undefined,
                    defer_dispatch: true,
                  });
                  const fd = new FormData();
                  fd.append("file", codeArchive);
                  await apiClient.post(
                    `/clients/${selectedClientId}/scans/${created.id}/upload-code/`,
                    fd,
                    { headers: { "Content-Type": "multipart/form-data" } }
                  );
                  qc.invalidateQueries({ queryKey: ["assessments-tiles"] });
                  setOpen(false); setScanName(""); setCodeArchive(null); setAcrMode("repo");
                  toast.success(`Uploaded ${codeArchive.name} — AI code review starting`);
                } catch (e: any) {
                  toast.error(e?.response?.data?.detail || "Code archive upload failed");
                }
              } else {
                const isAcrRepo = scannerId === "ai_code_review" && acrMode === "repo";
                startMutation.mutate({
                  scan_type: scanType,
                  connector_id: isAcrRepo ? undefined : (connectorId || undefined),
                  framework: framework || undefined,
                  name: scanName || undefined,
                  ...(isAcrRepo && acrRepoUrl.trim() ? { repo_url: acrRepoUrl.trim() } : {}),
                  ...(isAcrRepo && acrGitToken.trim() ? { git_token: acrGitToken.trim() } : {}),
                });
              }
            }}>
            {startMutation.isPending ? <CircularProgress size={18} /> : "Start Scan"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Findings dialog */}
      <Dialog open={!!viewScan} onClose={() => setViewScan(null)} maxWidth="md" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <Box>
            <Typography variant="h6">Scan Findings</Typography>
            {viewScan && (
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {viewScan.scan_type} · {viewScan.framework || "No framework"} · {fromNow(viewScan.started_at)}
              </Typography>
            )}
          </Box>
          {viewScan && (
            <Chip label={viewScan.status} size="small"
              sx={{ bgcolor: `${STATUS_COLOR[viewScan.status]}20`, color: STATUS_COLOR[viewScan.status] }} />
          )}
        </DialogTitle>
        <Divider sx={{ borderColor: "divider" }} />
        <DialogContent sx={{ p: 0 }}>
          {findingsLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
              <CircularProgress sx={{ color: "#4285F4" }} />
            </Box>
          ) : findings.length === 0 ? (
            <Box sx={{ p: 4, textAlign: "center", color: "text.secondary" }}>
              No findings recorded for this scan.
            </Box>
          ) : (
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { borderColor: "divider", color: "text.secondary", fontSize: 11, fontWeight: 600 } }}>
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
                  <TableRow key={f.id} hover sx={{ "& td": { borderColor: "divider", color: "text.primary", fontSize: 12 } }}>
                    <TableCell>
                      <Chip label={f.severity} size="small"
                        sx={{ bgcolor: `${SEV_COLOR[f.severity] || "#888"}20`, color: SEV_COLOR[f.severity] || "#888", fontSize: 10, height: 18 }} />
                    </TableCell>
                    <TableCell sx={{ maxWidth: 300 }}>
                      <Typography variant="caption" sx={{ display: "block", fontWeight: 600 }}>{f.title}</Typography>
                      {f.description && (
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.3 }}>
                          {f.description.slice(0, 120)}{f.description.length > 120 ? "…" : ""}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell><Typography variant="caption" sx={{ color: "text.secondary" }}>{f.resource_id || "—"}</Typography></TableCell>
                    <TableCell><Typography variant="caption" sx={{ color: "#4285F4" }}>{f.cve_id || "—"}</Typography></TableCell>
                    <TableCell><Typography variant="caption">{f.cvss_score ?? "—"}</Typography></TableCell>
                    <TableCell align="right" sx={{ width: 44 }}>
                      <Tooltip title="Delete finding">
                        <IconButton
                          size="small"
                          onClick={(e) => { e.stopPropagation(); setPendingDeleteFinding(f); }}
                          sx={{
                            color: "text.secondary",
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
          <Button onClick={() => setViewScan(null)} sx={{ color: "text.secondary" }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Version history — all rescans of the same assessment, newest first */}
      <Dialog open={!!historyOpenForRoot} onClose={() => setHistoryOpenForRoot(null)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
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
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5 }}>
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
                          color: isLatest ? "#4285F4" : "text.secondary",
                        }} />
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography variant="body2" sx={{ color: "text.primary", fontSize: 13, fontWeight: 500 }}>
                          {v.started_at ? new Date(v.started_at).toLocaleString() : (v.created_at ? new Date(v.created_at).toLocaleString() : "—")}
                        </Typography>
                        <Typography variant="caption" sx={{ color: "text.secondary" }}>
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
          <Button onClick={() => setHistoryOpenForRoot(null)} sx={{ color: "text.secondary" }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Confirm assessment (scan) delete */}
      <Dialog open={!!pendingDeleteScan} onClose={() => setPendingDeleteScan(null)}
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>Delete assessment?</DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            This permanently removes the scan and every finding, agent run, and AI verdict tied to it. It does NOT delete the connector or affect future scans.
          </Typography>
          {pendingDeleteScan && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600 }}>{pendingDeleteScan.tile_name}</Typography>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {pendingDeleteScan.scan_type} · {pendingDeleteScan.findings_count ?? 0} finding{pendingDeleteScan.findings_count === 1 ? "" : "s"}
                {pendingDeleteScan.framework ? ` · ${pendingDeleteScan.framework}` : ""}
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDeleteScan(null)} sx={{ color: "text.secondary" }}>Cancel</Button>
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
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>Delete finding?</DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            This permanently removes the finding. If the same issue is detected on the next scan it will be re-created.
          </Typography>
          {pendingDeleteFinding && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600 }}>{pendingDeleteFinding.title || "(no title)"}</Typography>
              {pendingDeleteFinding.resource_id && (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>{pendingDeleteFinding.resource_id}</Typography>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDeleteFinding(null)} sx={{ color: "text.secondary" }}>Cancel</Button>
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
