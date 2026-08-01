import React, { useState } from "react";
import {
  Box, Typography, Card, Chip, CircularProgress, Button, IconButton,
  Tabs, Tab, Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  Grid, Alert, Tooltip,
} from "@mui/material";
import { ArrowBack, PlayArrow, Refresh } from "@mui/icons-material";
import { useNavigate, useParams, useLocation } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { clientsApi, assetsApi, connectorsApi, attackPathApi } from "../services/api";
import { Client, Connector, AssetDetail, Finding, Risk, AssetTimelinePoint, CveDuplicateGroup } from "../types";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip,
  ResponsiveContainer, Legend,
} from "recharts";
import { fmt, fromNow } from "../utils/datetime";

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

  return (
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

      {/* Tabs */}
      <Tabs value={tab} onChange={(_, v) => setTab(v)}
        sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)", mb: 2,
          "& .MuiTab-root": { color: "text.secondary", textTransform: "none" },
          "& .Mui-selected": { color: "#4285F4" }, "& .MuiTabs-indicator": { backgroundColor: "#4285F4" } }}>
        <Tab label={`Findings (${findings.length})`} />
        <Tab label={`Risks (${risks.length})`} />
        <Tab label={`CVEs (${asset.cve_count ?? Array.from(new Set(findings.filter((f) => f.cve_id).map((f) => f.cve_id))).length})`} />
        <Tab label="Raw Metadata" />
        <Tab label="Timeline" />
        <Tab label="Attack Path" />
        <Tab label="Duplicates" />
      </Tabs>

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

      {tab === 3 && (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2 }}>
          <Box component="pre" sx={{ color: "text.secondary", fontSize: 12, m: 0, overflow: "auto", maxHeight: 600 }}>
            {JSON.stringify(asset.provider_metadata || {}, null, 2)}
          </Box>
        </Card>
      )}

      {tab === 4 && <AssetTimeline clientId={clientId} assetId={assetId} />}
      {tab === 5 && <AssetAttackPath clientId={clientId} assetId={assetId} />}
      {tab === 6 && <AssetDuplicates clientId={clientId} assetId={assetId} />}
    </Box>
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
  const { data, isLoading, isError } = useQuery<any>({
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

  const nodes: any[] = data?.nodes || [];
  const filteredNodes = nodes.filter((n) => n.asset_id === assetId || n.resource_id === assetId || nodes.length > 0);

  if (isError || filteredNodes.length === 0) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
        <Typography sx={{ color: "text.secondary" }}>No attack path data available for this asset.</Typography>
      </Card>
    );
  }

  return (
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
      <TableContainer>
        <Table size="small">
          <TableHead>
            <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
              <TableCell>PHASE</TableCell>
              <TableCell>SEVERITY</TableCell>
              <TableCell>TITLE</TableCell>
              <TableCell align="right">CVSS</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredNodes.map((node: any, idx: number) => {
              const phase = node.phase || node.attack_phase || "unknown";
              const sev = node.severity || "info";
              const phaseColor = PHASE_COLOR[phase] || "rgba(255,255,255,0.4)";
              return (
                <TableRow key={node.id || idx} sx={{ "& td": { borderColor: "divider", py: 1 } }}>
                  <TableCell>
                    <Chip
                      label={phase.replace(/_/g, " ")}
                      size="small"
                      sx={{ bgcolor: `${phaseColor}20`, color: phaseColor, fontSize: 10, height: 18, textTransform: "capitalize" }}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={sev}
                      size="small"
                      sx={{ bgcolor: `${SEV_COLOR[sev] || "#888"}20`, color: SEV_COLOR[sev] || "#888", fontSize: 10, height: 18 }}
                    />
                  </TableCell>
                  <TableCell sx={{ color: "text.primary", maxWidth: 400 }}>
                    <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {node.title || node.label || "—"}
                    </Typography>
                  </TableCell>
                  <TableCell align="right" sx={{ fontSize: 12, color: node.cvss_score != null ? (node.cvss_score >= 9 ? "#f44336" : node.cvss_score >= 7 ? "#ff9800" : "white") : "rgba(255,255,255,0.3)" }}>
                    {node.cvss_score != null ? node.cvss_score.toFixed(1) : "—"}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
    </Card>
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
