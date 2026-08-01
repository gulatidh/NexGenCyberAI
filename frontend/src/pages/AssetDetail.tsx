import React, { useState } from "react";
import {
  Box, Typography, Card, Chip, CircularProgress, Button, IconButton,
  Tabs, Tab, Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  Grid, Alert, Tooltip,
} from "@mui/material";
import { ArrowBack, PlayArrow, Refresh } from "@mui/icons-material";
import { useNavigate, useParams, useLocation } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { clientsApi, assetsApi, connectorsApi } from "../services/api";
import { Client, Connector, AssetDetail, Finding, Risk } from "../types";
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
    </Box>
  );
}
