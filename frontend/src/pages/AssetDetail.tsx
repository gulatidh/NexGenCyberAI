import React, { useState } from "react";
import {
  Box, Typography, Card, Chip, CircularProgress, Button, IconButton,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  Grid, Alert, Tooltip, FormControl, InputLabel, Select, MenuItem, LinearProgress,
} from "@mui/material";
import {
  ArrowBack, PlayArrow, Refresh,
  BugReport, Warning, Timeline, AccountTree, FileCopy, GppGood, MenuBook, DataObject,
} from "@mui/icons-material";
import { useNavigate, useParams, useLocation } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { clientsApi, assetsApi, connectorsApi, attackPathApi, frameworksApi } from "../services/api";
import { Client, Connector, AssetDetail, Finding, Risk, AssetTimelinePoint, CveDuplicateGroup, AssetCompliance } from "../types";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip,
  ResponsiveContainer, Legend,
} from "recharts";
import { fmt, fromNow } from "../utils/datetime";
import PageDetailLayout, { DetailNavItem } from "../components/layout/PageDetailLayout";
import { AttackGraphInner, AttackPathData } from "./AttackPaths";
import { ReactFlowProvider } from "@xyflow/react";

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#4285F4",
};
const RISK_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50",
};
const CLASS_COLOR: Record<string, string> = {
  vm: "#4285F4", storage: "#ff9800", network: "#34A853", database: "#00e676",
  identity: "#f06292", keyvault: "#ffd54f", other: "rgba(255,255,255,0.5)",
};
const STATUS_COLOR: Record<string, string> = {
  active: "#00e676", stale: "#ff9800", deleted: "rgba(255,255,255,0.4)",
};

const ASSET_TAB_MAP: Record<string, number> = {
  findings: 0, risks: 1, cves: 2, metadata: 3,
  timeline: 4, attack_path: 5, duplicates: 6, compliance: 7, platform: 8,
};
const ASSET_TAB_KEY: Record<number, string> = {
  0: "findings", 1: "risks", 2: "cves", 3: "metadata",
  4: "timeline", 5: "attack_path", 6: "duplicates", 7: "compliance", 8: "platform",
};

export default function AssetDetailPage() {
  const { assetId = "" } = useParams<{ assetId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const assetsBase = location.pathname.startsWith("/platform") ? "/platform/assets" : "/assets";
  const qc = useQueryClient();
  const [tab, setTab] = useState(0);

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });

  // We don't know the clientId from the URL; resolve it by querying each client until we find the asset.
  // In practice the user comes from /assets where clientId is in state, but for direct URLs we fall back to scanning.
  const { data: assetResolution } = useQuery<{ clientId: string; asset: AssetDetail } | null>({
    queryKey: ["asset-resolve", assetId, clients.map((c) => c.id).join(",")],
    queryFn: async () => {
      for (const c of clients) {
        try {
          const a = await assetsApi.get(c.id, assetId);
          if (a) return { clientId: c.id, asset: a };
        } catch {
          // continue trying other clients
        }
      }
      return null;
    },
    enabled: !!assetId && clients.length > 0,
  });

  const clientId = assetResolution?.clientId || "";
  const asset = assetResolution?.asset;

  const { data: connectors = [] } = useQuery<Connector[]>({
    queryKey: ["connectors", clientId],
    queryFn: () => connectorsApi.list(clientId),
    enabled: !!clientId,
  });

  const scanMutation = useMutation({
    mutationFn: () => assetsApi.scan(clientId, assetId),
    onSuccess: () => {
      setTimeout(() => qc.invalidateQueries({ queryKey: ["asset-resolve"] }), 4000);
    },
  });

  const syncMutation = useMutation({
    mutationFn: () => assetsApi.sync(clientId, asset?.connector_id),
    onSuccess: () => {
      setTimeout(() => qc.invalidateQueries({ queryKey: ["asset-resolve"] }), 2000);
    },
  });

  if (!asset) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
        <CircularProgress sx={{ color: "#4285F4" }} />
      </Box>
    );
  }

  const klass = asset.asset_class || "other";
  const connectorName = connectors.find((c) => c.id === asset.connector_id)?.name || asset.connector_id;
  const findings: Finding[] = asset.findings || [];
  const risks: Risk[] = asset.risks || [];
  const openFindings = findings.filter((f) => f.status === "open").length;

  const metaItems: { label: string; value: React.ReactNode }[] = [
    { label: "Connector", value: connectorName },
    { label: "Asset Type", value: asset.asset_type || "—" },
    { label: "Region", value: asset.region || "—" },
    { label: "Subscription", value: asset.subscription_id || "—" },
    { label: "Resource Group", value: asset.resource_group || "—" },
    { label: "Account", value: asset.account_id || "—" },
    { label: "Project", value: asset.project_id || "—" },
    { label: "First Seen", value: fmt(asset.first_seen_at) },
    { label: "Last Synced", value: fromNow(asset.last_synced_at) },
  ];

  const navItems: DetailNavItem[] = [
    { id: "findings",    label: `Findings (${findings.length})`,  Icon: BugReport,    color: "#EA4335" },
    { id: "risks",       label: `Risks (${risks.length})`,        Icon: Warning,      color: "#FF9800" },
    { id: "cves",        label: "CVEs",                           Icon: BugReport,    color: "#FF5722" },
    { id: "timeline",    label: "Timeline",                       Icon: Timeline,     color: "#4285F4" },
    { id: "attack_path", label: "Attack Path",                    Icon: AccountTree,  color: "#9C27B0" },
    { id: "compliance",  label: "Compliance",                     Icon: GppGood,      color: "#34A853" },
    { id: "metadata",    label: "Metadata",                       Icon: DataObject,   color: "#757575" },
    { id: "duplicates",  label: "Duplicates",                     Icon: FileCopy,     color: "#607D8B" },
    { id: "platform",   label: "Platform",                       Icon: DataObject,   color: "#9C27B0" },
    { id: "help",        label: "Help",                           Icon: MenuBook,     color: "#00BCD4" },
  ];

  return (
    <PageDetailLayout
      entityName={asset?.name ?? "Asset"}
      entityType="Asset"
      avatarColor="#9C27B0"
      navItems={navItems}
      activeId={ASSET_TAB_KEY[tab] ?? "findings"}
      onSelect={(id: string) => {
        if (id === "help") navigate("/help");
        else setTab(ASSET_TAB_MAP[id] ?? 0);
      }}
    >
      <Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
          <IconButton onClick={() => navigate(assetsBase)} sx={{ color: "text.secondary" }}>
            <ArrowBack />
          </IconButton>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Asset Inventory</Typography>
        </Box>

        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3, flexWrap: "wrap", gap: 2 }}>
          <Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5, flexWrap: "wrap" }}>
              <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>{asset.name}</Typography>
              <Chip label={klass} size="small"
                sx={{ bgcolor: `${CLASS_COLOR[klass] || "#888"}20`, color: CLASS_COLOR[klass] || "#888", fontSize: 11 }} />
              <Chip label={asset.status} size="small"
                sx={{ bgcolor: `${STATUS_COLOR[asset.status] || "#888"}20`, color: STATUS_COLOR[asset.status] || "#888", fontSize: 11 }} />
            </Box>
            <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace" }}>
              {asset.external_id}
            </Typography>
          </Box>
          <Box sx={{ display: "flex", gap: 1 }}>
            <Tooltip title="Refresh inventory for this connector">
              <span>
                <Button startIcon={syncMutation.isPending ? <CircularProgress size={14} sx={{ color: "text.primary" }} /> : <Refresh />}
                  onClick={() => syncMutation.mutate()}
                  disabled={syncMutation.isPending}
                  sx={{ color: "text.secondary", borderColor: "divider" }}
                  variant="outlined">
                  Refresh
                </Button>
              </span>
            </Tooltip>
            <Tooltip title="Run on-demand scan against this asset">
              <span>
                <Button startIcon={scanMutation.isPending ? <CircularProgress size={14} sx={{ color: "#0d1117" }} /> : <PlayArrow />}
                  onClick={() => scanMutation.mutate()}
                  disabled={scanMutation.isPending}
                  sx={{ bgcolor: "#4285F4", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}
                  variant="contained">
                  Scan This Asset
                </Button>
              </span>
            </Tooltip>
          </Box>
        </Box>

        {scanMutation.isSuccess && (
          <Alert severity="info" sx={{ mb: 2, bgcolor: "rgba(66,133,244,0.1)", color: "text.primary" }}>
            Scan started. Findings will appear here once it completes.
          </Alert>
        )}

        {/* Summary cards */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid size={{ xs: 12, sm: 4 }}>
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2 }}>
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>Severity Breakdown</Typography>
              <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                {(["critical", "high", "medium", "low", "info"] as const).map((s) => {
                  const count = asset.severity_breakdown?.[s] ?? findings.filter((f) => f.status === "open" && ((f.severity as any)?.value ?? f.severity) === s).length;
                  return count > 0 ? (
                    <Chip key={s} label={`${count} ${s}`} size="small"
                      sx={{ bgcolor: `${SEV_COLOR[s]}22`, color: SEV_COLOR[s], fontSize: 10, height: 20 }} />
                  ) : null;
                })}
                {openFindings === 0 && <Typography variant="body2" sx={{ color: "text.secondary" }}>No open findings</Typography>}
              </Box>
              <Typography variant="caption" sx={{ color: "text.secondary", mt: 0.5, display: "block" }}>
                {openFindings} open of {findings.length} total
              </Typography>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 4 }}>
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2 }}>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>Linked Risks</Typography>
              <Typography variant="h4" sx={{ color: risks.length > 0 ? "#ff9800" : "text.secondary", fontWeight: 700 }}>
                {risks.length}
              </Typography>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, sm: 4 }}>
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2 }}>
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>Unique CVEs</Typography>
              <Typography variant="h4" sx={{ color: (asset.cve_count ?? 0) > 0 ? "#4285F4" : "text.secondary", fontWeight: 700 }}>
                {asset.cve_count ?? Array.from(new Set(findings.filter((f) => f.cve_id).map((f) => f.cve_id))).length}
              </Typography>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {asset.last_scan_date ? `Last scan ${fromNow(asset.last_scan_date)}` : "No scans yet"}
              </Typography>
            </Card>
          </Grid>
        </Grid>

        {/* Metadata grid */}
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2, mb: 3 }}>
          <Grid container spacing={2}>
            {metaItems.map((m) => (
              <Grid key={m.label} size={{ xs: 6, sm: 4, md: 3 }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>{m.label}</Typography>
                <Typography variant="body2" sx={{ color: "text.primary", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {m.value}
                </Typography>
              </Grid>
            ))}
          </Grid>
        </Card>

        {/* Tab panels */}
        {tab === 0 && (
          findings.length === 0 ? (
            <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
              <Typography sx={{ color: "text.secondary" }}>No findings linked to this asset.</Typography>
            </Card>
          ) : (
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                      <TableCell>SEVERITY</TableCell>
                      <TableCell>TITLE</TableCell>
                      <TableCell>CVE</TableCell>
                      <TableCell>CVSS</TableCell>
                      <TableCell>STATUS</TableCell>
                      <TableCell>FOUND</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {findings.map((f) => {
                      const sev = (typeof f.severity === "object" ? (f.severity as any).value : f.severity) || "info";
                      return (
                        <TableRow key={f.id} sx={{ "& td": { borderColor: "divider", py: 1 } }}>
                          <TableCell>
                            <Chip label={sev} size="small"
                              sx={{ bgcolor: `${SEV_COLOR[sev] || "#888"}20`, color: SEV_COLOR[sev] || "#888", fontSize: 10, height: 18 }} />
                          </TableCell>
                          <TableCell sx={{ color: "text.primary", maxWidth: 400 }}>
                            <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              {f.title}
                            </Typography>
                          </TableCell>
                          <TableCell sx={{ color: f.cve_id ? "#4285F4" : "text.secondary", fontSize: 12 }}>{f.cve_id || "—"}</TableCell>
                          <TableCell sx={{ fontSize: 12, color: f.cvss_score != null ? (f.cvss_score >= 9 ? "#f44336" : f.cvss_score >= 7 ? "#ff9800" : "white") : "rgba(255,255,255,0.3)" }}>
                            {f.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}
                          </TableCell>
                          <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>{f.status || "open"}</TableCell>
                          <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>
                            {fromNow(f.created_at)}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            </Card>
          )
        )}

        {tab === 1 && (
          risks.length === 0 ? (
            <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
              <Typography sx={{ color: "text.secondary" }}>No risks linked to this asset.</Typography>
            </Card>
          ) : (
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                      <TableCell>LEVEL</TableCell>
                      <TableCell>TITLE</TableCell>
                      <TableCell>SCORE</TableCell>
                      <TableCell>OWNER</TableCell>
                      <TableCell>STATUS</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {risks.map((r) => {
                      const lvl = (typeof r.risk_level === "object" ? (r.risk_level as any).value : r.risk_level) || "low";
                      return (
                        <TableRow key={r.id} sx={{ "& td": { borderColor: "divider", py: 1 } }}>
                          <TableCell>
                            <Chip label={lvl} size="small"
                              sx={{ bgcolor: `${RISK_COLOR[lvl] || "#888"}20`, color: RISK_COLOR[lvl] || "#888", fontSize: 10, height: 18 }} />
                          </TableCell>
                          <TableCell sx={{ color: "text.primary" }}>{r.title}</TableCell>
                          <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>
                            {r.risk_score != null ? r.risk_score.toFixed(1) : "—"}
                          </TableCell>
                          <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>{r.owner || "—"}</TableCell>
                          <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>{r.status}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            </Card>
          )
        )}

        {tab === 2 && (() => {
          const cveIds = asset.cves ?? Array.from(new Set(findings.filter((f) => f.cve_id).map((f) => f.cve_id!))).sort();
          return cveIds.length === 0 ? (
            <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
              <Typography sx={{ color: "text.secondary" }}>No CVEs found for findings on this asset.</Typography>
            </Card>
          ) : (
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                      <TableCell>CVE ID</TableCell>
                      <TableCell>TITLE</TableCell>
                      <TableCell>SEVERITY</TableCell>
                      <TableCell align="right">CVSS</TableCell>
                      <TableCell>STATUS</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {cveIds.map((cveId) => {
                      const f = findings.find((fi) => fi.cve_id === cveId);
                      const sev = f ? ((f.severity as any)?.value ?? f.severity) : "info";
                      return (
                        <TableRow key={cveId} sx={{ "& td": { borderColor: "divider", py: 1 } }}>
                          <TableCell>
                            <Typography variant="body2" sx={{ color: "#4285F4", fontFamily: "monospace", fontSize: 12 }}>
                              {cveId}
                            </Typography>
                          </TableCell>
                          <TableCell sx={{ color: "text.primary", maxWidth: 400 }}>
                            <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              {f?.title || "—"}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip label={sev} size="small"
                              sx={{ bgcolor: `${SEV_COLOR[sev] || "#888"}22`, color: SEV_COLOR[sev] || "#888", fontSize: 10, height: 18 }} />
                          </TableCell>
                          <TableCell align="right" sx={{ fontSize: 12, color: f?.cvss_score != null ? (f.cvss_score >= 9 ? "#f44336" : f.cvss_score >= 7 ? "#ff9800" : "white") : "rgba(255,255,255,0.3)" }}>
                            {f?.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}
                          </TableCell>
                          <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>{f?.status || "open"}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            </Card>
          );
        })()}

        {tab === 3 && <ProviderMetadataCard meta={asset.provider_metadata || {}} />}

        {tab === 4 && <AssetTimeline clientId={clientId} assetId={assetId} />}
        {tab === 5 && <AssetAttackPath clientId={clientId} assetId={assetId} />}
        {tab === 6 && <AssetDuplicates clientId={clientId} assetId={assetId} />}
        {tab === 7 && <AssetComplianceTab clientId={clientId} assetId={assetId} />}
        {tab === 8 && <PlatformDetailTab detail={(asset as any).platform_detail} />}
      </Box>
    </PageDetailLayout>
  );
}

// ── Timeline sub-component ─────────────────────────────────────────────────────

const PHASE_COLOR: Record<string, string> = {
  initial_access: "#f44336",
  credential_access: "#ff9800",
  privilege_escalation: "#ffeb3b",
  lateral_movement: "#4285F4",
  data_access: "#ce93d8",
  execution: "#ff7043",
  persistence: "#26c6da",
  exfiltration: "#ef5350",
};

function AssetTimeline({ clientId, assetId }: { clientId: string; assetId: string }) {
  const { data, isLoading, isError } = useQuery<{ timeline: AssetTimelinePoint[] }>({
    queryKey: ["asset-timeline", clientId, assetId],
    queryFn: () => assetsApi.timeline(clientId, assetId),
    enabled: !!clientId && !!assetId,
  });

  if (isLoading) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
        <CircularProgress sx={{ color: "#4285F4" }} />
      </Box>
    );
  }
  if (isError || !data?.timeline?.length) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
        <Typography sx={{ color: "text.secondary" }}>No timeline data available for this asset yet.</Typography>
      </Card>
    );
  }

  const timeline = data.timeline;
  const firstScore = timeline[0]?.risk_score;
  const lastScore = timeline[timeline.length - 1]?.risk_score;
  const scoreTrend = lastScore - firstScore;
  const trendColor = scoreTrend > 0 ? "#f44336" : scoreTrend < 0 ? "#4caf50" : "text.secondary";

  const chartData = timeline.map((pt) => ({
    ...pt,
    date: pt.date ? new Date(pt.date).toLocaleDateString() : pt.scan_id.slice(0, 8),
  }));

  return (
    <Box>
      {/* Risk score trend summary */}
      <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2, mb: 2 }}>
        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>Risk Score Trend</Typography>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <Typography variant="h6" sx={{ color: "text.primary", fontWeight: 700 }}>
            {firstScore} → {lastScore}
          </Typography>
          <Chip
            label={scoreTrend > 0 ? `+${scoreTrend} worsened` : scoreTrend < 0 ? `${scoreTrend} improved` : "stable"}
            size="small"
            sx={{ bgcolor: `${trendColor}22`, color: trendColor, fontSize: 11 }}
          />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            across {timeline.length} scan{timeline.length !== 1 ? "s" : ""}
          </Typography>
        </Box>
      </Card>

      {/* Area chart */}
      <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2 }}>
        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 2 }}>Findings Over Time</Typography>
        <ResponsiveContainer width="100%" height={280}>
          <AreaChart data={chartData} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f44336" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#f44336" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ff9800" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ff9800" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="medGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ffeb3b" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#ffeb3b" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
            <XAxis dataKey="date" stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 11, fill: "rgba(255,255,255,0.4)" }} />
            <YAxis stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 11, fill: "rgba(255,255,255,0.4)" }} />
            <RTooltip
              contentStyle={{ background: "#1a1f2e", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 8 }}
              labelStyle={{ color: "rgba(255,255,255,0.7)", fontSize: 12 }}
              itemStyle={{ fontSize: 12 }}
            />
            <Legend wrapperStyle={{ fontSize: 12, color: "rgba(255,255,255,0.5)" }} />
            <Area type="monotone" dataKey="critical" stroke="#f44336" fill="url(#critGrad)" strokeWidth={2} name="Critical" />
            <Area type="monotone" dataKey="high" stroke="#ff9800" fill="url(#highGrad)" strokeWidth={2} name="High" />
            <Area type="monotone" dataKey="medium" stroke="#ffeb3b" fill="url(#medGrad)" strokeWidth={2} name="Medium" />
          </AreaChart>
        </ResponsiveContainer>
      </Card>
    </Box>
  );
}

// ── Attack Path sub-component ──────────────────────────────────────────────────

function AssetAttackPath({ clientId, assetId }: { clientId: string; assetId: string }) {
  const { data, isLoading, isError } = useQuery<AttackPathData>({
    queryKey: ["asset-attack-path", clientId, assetId],
    queryFn: () => attackPathApi.getForAsset(clientId, assetId),
    enabled: !!clientId && !!assetId,
  });

  if (isLoading) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
        <CircularProgress sx={{ color: "#4285F4" }} />
      </Box>
    );
  }

  if (isError || !data || data.nodes.length === 0) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
        <AccountTree sx={{ fontSize: 40, color: "text.secondary", mb: 1 }} />
        <Typography sx={{ color: "text.secondary" }}>
          No attack path data for this asset. Run a scan to populate findings.
        </Typography>
      </Card>
    );
  }

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
      {/* Stats strip */}
      <Box sx={{ display: "flex", gap: 1.5, flexWrap: "wrap" }}>
        <Chip label={`${data.stats.total_findings} findings`} size="small" sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4" }} />
        {data.stats.critical > 0 && (
          <Chip label={`${data.stats.critical} critical`} size="small" sx={{ bgcolor: "rgba(234,67,53,0.15)", color: "#EA4335" }} />
        )}
        {data.stats.phases_present.map((ph) => (
          <Chip key={ph} label={ph.replace(/_/g, " ")} size="small"
            sx={{ fontSize: 10, height: 20, textTransform: "capitalize", bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
        ))}
      </Box>

      {/* Graph */}
      <ReactFlowProvider>
        <AttackGraphInner data={data} />
      </ReactFlowProvider>
    </Box>
  );
}

// ── Duplicates sub-component ───────────────────────────────────────────────────

function AssetDuplicates({ clientId, assetId }: { clientId: string; assetId: string }) {
  const { data, isLoading, isError } = useQuery<{ groups: CveDuplicateGroup[]; total_duplicates: number }>({
    queryKey: ["asset-deduplicate", clientId, assetId],
    queryFn: () => assetsApi.deduplicate(clientId, assetId),
    enabled: !!clientId && !!assetId,
  });

  if (isLoading) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
        <CircularProgress sx={{ color: "#4285F4" }} />
      </Box>
    );
  }

  const groups: CveDuplicateGroup[] = data?.groups || [];
  const totalDuplicates = data?.total_duplicates ?? groups.reduce((sum, g) => sum + g.duplicate_count, 0);

  if (isError || groups.length === 0) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
        <Typography sx={{ color: "text.secondary" }}>No duplicate findings detected for this asset.</Typography>
      </Card>
    );
  }

  return (
    <Box>
      <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2, mb: 2 }}>
        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>Deduplication Summary</Typography>
        <Box sx={{ display: "flex", gap: 2 }}>
          <Box>
            <Typography variant="h5" sx={{ color: "#ff9800", fontWeight: 700 }}>{groups.length}</Typography>
            <Typography variant="caption" sx={{ color: "text.secondary" }}>duplicate groups</Typography>
          </Box>
          <Box>
            <Typography variant="h5" sx={{ color: "#f44336", fontWeight: 700 }}>{totalDuplicates}</Typography>
            <Typography variant="caption" sx={{ color: "text.secondary" }}>redundant findings</Typography>
          </Box>
        </Box>
      </Card>
      <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                <TableCell>CVE ID</TableCell>
                <TableCell>SEVERITY</TableCell>
                <TableCell align="right">CVSS</TableCell>
                <TableCell align="right">DUPLICATES</TableCell>
                <TableCell align="right">SCANNERS</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {groups.map((g) => {
                const sev = g.severity || "info";
                return (
                  <TableRow key={g.cve_id} sx={{ "& td": { borderColor: "divider", py: 1 } }}>
                    <TableCell>
                      <Typography variant="body2" sx={{ color: "#4285F4", fontFamily: "monospace", fontSize: 12 }}>
                        {g.cve_id}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={sev} size="small"
                        sx={{ bgcolor: `${SEV_COLOR[sev] || "#888"}20`, color: SEV_COLOR[sev] || "#888", fontSize: 10, height: 18 }} />
                    </TableCell>
                    <TableCell align="right" sx={{ fontSize: 12, color: g.cvss_score != null ? (g.cvss_score >= 9 ? "#f44336" : g.cvss_score >= 7 ? "#ff9800" : "white") : "rgba(255,255,255,0.3)" }}>
                      {g.cvss_score != null ? g.cvss_score.toFixed(1) : "—"}
                    </TableCell>
                    <TableCell align="right" sx={{ color: "#ff9800", fontWeight: 600, fontSize: 13 }}>
                      {g.duplicate_count}
                    </TableCell>
                    <TableCell align="right" sx={{ color: "text.secondary", fontSize: 12 }}>
                      {g.scanners?.length ?? 0}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      </Card>
    </Box>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 7: Compliance Posture
// ─────────────────────────────────────────────────────────────────────────────


const SEV_COLOR_MAP: Record<string, string> = { critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#4285F4" };

// ── Platform Detail tab ────────────────────────────────────────────────────────

const CT_COLORS: Record<string, string> = {
  azure: "#0078D4", aws: "#FF9900", gcp: "#4285F4",
  entraid: "#00A4EF", okta: "#007DC1", qualys: "#ED1C24",
  servicenow: "#62D84E", cyberark: "#6759D1", onprem: "#607D8B", containers: "#326CE5",
};
const LIFECYCLE_COLOR: Record<string, string> = {
  running: "#34A853", active: "#34A853",
  stopped: "#FBBC04", inactive: "#FBBC04", suspended: "#FBBC04", on_order: "#FBBC04",
  terminated: "#EA4335", deprovisioned: "#EA4335", retired: "#EA4335", stolen: "#EA4335",
};

// ── Provider metadata — structured card view ───────────────────────────────────

const HEADER_FIELDS = ["id", "name", "type", "location"] as const;

function MetaRow({ label, value }: { label: string; value: any }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5, py: 0.5 }}>
      <Typography variant="caption" sx={{ color: "text.secondary", minWidth: 130, flexShrink: 0, pt: "2px", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.04em", fontSize: 10 }}>
        {label}
      </Typography>
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <MetadataTree data={value} depth={1} />
      </Box>
    </Box>
  );
}

// Named sections lifted out of the flat remaining bucket — keeps cross-cloud shapes clean
const NAMED_SECTIONS: { key: string; label: string }[] = [
  { key: "config",      label: "Configuration" },   // Entra ID + AWS connector format
  { key: "properties",  label: "Properties" },       // Azure ARM format
  { key: "tags",        label: "Tags" },              // Azure / AWS tags
  { key: "sku",         label: "SKU" },               // Azure SKU object
];

function ProviderMetadataCard({ meta }: { meta: Record<string, any> }) {
  const headerEntries = HEADER_FIELDS.map((k) => [k, meta[k]] as [string, any]).filter(([, v]) => v !== undefined && v !== null && v !== "");
  const sectionKeys = new Set([...HEADER_FIELDS as readonly string[], ...NAMED_SECTIONS.map((s) => s.key)]);
  const remaining = Object.entries(meta).filter(([k]) => !sectionKeys.has(k) && meta[k] !== null && meta[k] !== undefined && meta[k] !== "");

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
      {/* Summary — id, name, type, location */}
      {headerEntries.length > 0 && (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "text.primary" }}>Summary</Typography>
          {headerEntries.map(([k, v]) => <MetaRow key={k} label={k} value={v} />)}
        </Card>
      )}

      {/* Named sections: config / properties / tags / sku */}
      {NAMED_SECTIONS.map(({ key, label }) => {
        const val = meta[key];
        if (!val || typeof val !== "object" || Object.keys(val).length === 0) return null;
        const entries = Object.entries(val).filter(([, v]) => v !== null && v !== undefined && v !== "");
        if (entries.length === 0) return null;
        return (
          <Card key={key} sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "text.primary" }}>{label}</Typography>
            {entries.map(([k, v]) => <MetaRow key={k} label={k.replace(/_/g, " ")} value={v} />)}
          </Card>
        );
      })}

      {/* Remaining flat keys */}
      {remaining.length > 0 && (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "text.primary" }}>Additional Metadata</Typography>
          {remaining.map(([k, v]) => <MetaRow key={k} label={k.replace(/_/g, " ")} value={v} />)}
        </Card>
      )}

      {/* Empty state */}
      {headerEntries.length === 0 && NAMED_SECTIONS.every(({ key }) => !meta[key]) && remaining.length === 0 && (
        <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>No metadata available for this asset.</Typography>
        </Card>
      )}
    </Box>
  );
}

function MetadataTree({ data, depth = 0 }: { data: any; depth?: number }) {
  if (data === null || data === undefined)
    return <Typography variant="caption" sx={{ color: "text.disabled" }}>null</Typography>;
  if (typeof data === "boolean")
    return <Chip label={data ? "true" : "false"} size="small" sx={{ height: 18, fontSize: 10, bgcolor: data ? "rgba(52,168,83,0.12)" : "rgba(234,67,53,0.12)", color: data ? "#34A853" : "#EA4335" }} />;
  if (typeof data === "number")
    return <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#FBBC04" }}>{data}</Typography>;
  if (typeof data === "string")
    return <Typography variant="body2" sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>{data || '""'}</Typography>;
  if (Array.isArray(data)) {
    if (data.length === 0)
      return <Typography variant="caption" sx={{ color: "text.disabled" }}>[]</Typography>;
    if (data.every((i) => typeof i !== "object"))
      return (
        <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
          {data.map((v, i) => <Chip key={i} label={String(v)} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)" }} />)}
        </Box>
      );
    return (
      <Box sx={{ pl: depth > 0 ? 1.5 : 0 }}>
        {data.map((v, i) => <Box key={i} sx={{ mb: 0.5 }}><MetadataTree data={v} depth={depth + 1} /></Box>)}
      </Box>
    );
  }
  if (typeof data === "object") {
    const entries = Object.entries(data).filter(([, v]) => v !== null && v !== undefined && v !== "");
    return (
      <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
        {entries.map(([k, v]) => (
          <Box key={k} sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
            <Typography variant="caption" sx={{ color: "text.secondary", minWidth: 160, flexShrink: 0, pt: "2px", fontFamily: "monospace" }}>
              {k.replace(/_/g, " ")}
            </Typography>
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <MetadataTree data={v} depth={depth + 1} />
            </Box>
          </Box>
        ))}
      </Box>
    );
  }
  return <Typography variant="body2">{String(data)}</Typography>;
}

function PlatformDetailTab({ detail }: { detail: any }) {
  if (!detail) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
        <Typography variant="body2" sx={{ color: "text.secondary" }}>
          No platform detail synced yet. Trigger a connector sync to populate this tab.
        </Typography>
      </Card>
    );
  }

  const ctColor = CT_COLORS[detail.connector_type?.toLowerCase()] || "#888";
  const lcColor = LIFECYCLE_COLOR[detail.lifecycle_state?.toLowerCase()] || "#888";

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
      <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
        <Box sx={{ p: 2 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>Platform Identity</Typography>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 6, md: 4 }}>
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>Connector</Typography>
              <Chip label={detail.connector_type} size="small"
                sx={{ bgcolor: `${ctColor}20`, color: ctColor, fontWeight: 700, mt: 0.5, textTransform: "uppercase", fontSize: 11 }} />
            </Grid>
            {detail.lifecycle_state && (
              <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>Lifecycle State</Typography>
                <Chip label={detail.lifecycle_state} size="small"
                  sx={{ bgcolor: `${lcColor}20`, color: lcColor, fontWeight: 700, mt: 0.5, textTransform: "capitalize" }} />
              </Grid>
            )}
            {detail.tenant_account_id && (
              <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>Account / Subscription</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: 12, mt: 0.5, wordBreak: "break-all" }}>{detail.tenant_account_id}</Typography>
              </Grid>
            )}
            {detail.namespace && (
              <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>Namespace / Group</Typography>
                <Typography variant="body2" sx={{ mt: 0.5 }}>{detail.namespace}</Typography>
              </Grid>
            )}
            {detail.owner && (
              <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>Owner</Typography>
                <Typography variant="body2" sx={{ mt: 0.5 }}>{detail.owner}</Typography>
              </Grid>
            )}
            {detail.department && (
              <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>Department</Typography>
                <Typography variant="body2" sx={{ mt: 0.5 }}>{detail.department}</Typography>
              </Grid>
            )}
            {detail.fqdn && (
              <Grid size={{ xs: 12, sm: 6 }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>FQDN / Hostname</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: 12, mt: 0.5 }}>{detail.fqdn}</Typography>
              </Grid>
            )}
            {detail.ip_addresses?.length > 0 && (
              <Grid size={{ xs: 12, sm: 6 }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>IP Addresses</Typography>
                <Box sx={{ display: "flex", gap: 0.75, flexWrap: "wrap" }}>
                  {detail.ip_addresses.map((ip: string) => (
                    <Chip key={ip} label={ip} size="small" sx={{ fontFamily: "monospace", fontSize: 11, bgcolor: "rgba(255,255,255,0.06)" }} />
                  ))}
                </Box>
              </Grid>
            )}
            {detail.security_score != null && (
              <Grid size={{ xs: 6, sm: 3 }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>Security Score</Typography>
                <Typography variant="h5" sx={{ fontWeight: 700, mt: 0.5,
                  color: detail.security_score >= 80 ? "#34A853" : detail.security_score >= 50 ? "#FBBC04" : "#EA4335" }}>
                  {Math.round(detail.security_score)}
                </Typography>
              </Grid>
            )}
            {detail.vulnerability_count != null && (
              <Grid size={{ xs: 6, sm: 3 }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>Platform Vulns</Typography>
                <Typography variant="h5" sx={{ fontWeight: 700, mt: 0.5,
                  color: detail.vulnerability_count === 0 ? "#34A853" : detail.vulnerability_count < 10 ? "#FBBC04" : "#EA4335" }}>
                  {detail.vulnerability_count}
                </Typography>
              </Grid>
            )}
          </Grid>
        </Box>
      </Card>

      {detail.platform_metadata && Object.keys(detail.platform_metadata).length > 0 && (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <Box sx={{ p: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>
              Native Platform Metadata
              <Typography component="span" variant="caption" sx={{ color: "text.secondary", ml: 1 }}>
                ({Object.keys(detail.platform_metadata).length} fields · {detail.connector_type})
              </Typography>
            </Typography>
            <MetadataTree data={detail.platform_metadata} />
          </Box>
        </Card>
      )}

      {detail.synced_at && (
        <Typography variant="caption" sx={{ color: "text.disabled", textAlign: "right" }}>
          Last synced: {new Date(detail.synced_at).toLocaleString()}
        </Typography>
      )}
    </Box>
  );
}

function AssetComplianceTab({ clientId, assetId }: { clientId: string; assetId: string }) {
  const [framework, setFramework] = useState("nist_csf");

  const { data: catalogData } = useQuery<any[]>({
    queryKey: ["frameworks-all"],
    queryFn: frameworksApi.catalogAll,
    staleTime: 5 * 60 * 1000,
  });

  const { data, isLoading, isError } = useQuery<AssetCompliance>({
    queryKey: ["asset-compliance", clientId, assetId, framework],
    queryFn: () => assetsApi.compliance(clientId, assetId, framework),
    enabled: !!clientId && !!assetId,
  });

  const score = data?.compliance_score;
  const scoreColor = score == null ? "rgba(255,255,255,0.3)"
    : score >= 80 ? "#34A853" : score >= 60 ? "#FBBC04" : "#EA4335";

  return (
    <Box>
      {/* Framework selector */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
        <FormControl size="small" sx={{ minWidth: 240 }}>
          <InputLabel sx={{ color: "text.secondary" }}>Framework</InputLabel>
          <Select value={framework} onChange={(e) => setFramework(e.target.value)} label="Framework"
            sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
            {(catalogData ?? []).map((f: any) => (
              <MenuItem key={f.framework} value={f.framework}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  {f.name}
                  {f.is_custom && (
                    <Chip label="Custom" size="small" sx={{ height: 16, fontSize: 9, bgcolor: "rgba(156,39,176,0.15)", color: "#ce93d8" }} />
                  )}
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        {isLoading && <CircularProgress size={18} />}
      </Box>

      {isError && <Alert severity="error">Failed to load compliance data.</Alert>}

      {data && (
        <>
          {/* Summary cards */}
          <Grid container spacing={2} sx={{ mb: 2.5 }}>
            <Grid size={{ xs: 6, sm: 3 }}>
              <Card variant="outlined" sx={{ p: 1.5, textAlign: "center" }}>
                <Typography variant="h4" sx={{ fontWeight: 800, color: scoreColor }}>
                  {score != null ? `${score}%` : "—"}
                </Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>Compliance Score</Typography>
                {score != null && (
                  <LinearProgress variant="determinate" value={score}
                    sx={{ mt: 0.5, height: 4, borderRadius: 2, bgcolor: "rgba(255,255,255,0.08)",
                      "& .MuiLinearProgress-bar": { bgcolor: scoreColor } }} />
                )}
              </Card>
            </Grid>
            <Grid size={{ xs: 6, sm: 3 }}>
              <Card variant="outlined" sx={{ p: 1.5, textAlign: "center" }}>
                <Typography variant="h4" sx={{ fontWeight: 800, color: "#EA4335" }}>
                  {data.failing_controls_count}
                </Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>Controls Failing</Typography>
              </Card>
            </Grid>
            <Grid size={{ xs: 6, sm: 3 }}>
              <Card variant="outlined" sx={{ p: 1.5, textAlign: "center" }}>
                <Typography variant="h4" sx={{ fontWeight: 800, color: "text.primary" }}>
                  {data.total_framework_controls ?? "—"}
                </Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>Total Controls</Typography>
              </Card>
            </Grid>
            <Grid size={{ xs: 6, sm: 3 }}>
              <Card variant="outlined" sx={{ p: 1.5, textAlign: "center" }}>
                <Typography variant="h4" sx={{ fontWeight: 800, color: "#4285F4" }}>
                  {data.open_findings_total}
                </Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>Open Findings</Typography>
              </Card>
            </Grid>
          </Grid>

          {data.findings_with_control_mapping === 0 && (
            <Alert severity="info" sx={{ mb: 2 }}>
              No findings on this asset have framework control mappings yet. Run a scanner with control mapping support (e.g. AI Code Review, Compliance Monitor agent) to populate this view.
            </Alert>
          )}

          {data.failing_controls.length > 0 && (
            <Card variant="outlined">
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                      <TableCell>CONTROL</TableCell>
                      <TableCell>DOMAIN</TableCell>
                      <TableCell>TITLE</TableCell>
                      <TableCell>WORST SEVERITY</TableCell>
                      <TableCell align="right">FINDINGS</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {data.failing_controls.map((ctrl) => (
                      <TableRow key={ctrl.control_id} sx={{ "& td": { borderColor: "divider", py: 0.75 } }}>
                        <TableCell>
                          <Chip label={ctrl.control_id} size="small" variant="outlined"
                            sx={{ fontSize: 10, height: 20, borderColor: "divider", color: "text.secondary" }} />
                        </TableCell>
                        <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{ctrl.domain || "—"}</TableCell>
                        <TableCell sx={{ color: "text.primary", fontSize: 12, maxWidth: 320 }}>
                          <Tooltip title={ctrl.findings.map(f => f.title).join(" · ")} placement="top">
                            <span>{ctrl.title}</span>
                          </Tooltip>
                        </TableCell>
                        <TableCell>
                          <Chip label={ctrl.max_severity} size="small"
                            sx={{ fontSize: 10, height: 18, bgcolor: `${SEV_COLOR_MAP[ctrl.max_severity]}22`,
                              color: SEV_COLOR_MAP[ctrl.max_severity] }} />
                        </TableCell>
                        <TableCell align="right" sx={{ color: "#EA4335", fontWeight: 700, fontSize: 13 }}>
                          {ctrl.finding_count}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Card>
          )}
        </>
      )}
    </Box>
  );
}
