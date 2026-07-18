import React, { useState } from "react";
import {
  Box, Typography, Card, Chip, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer, TableSortLabel,
  FormControl, InputLabel, Select, MenuItem, Button, TextField, Alert, Tooltip,
} from "@mui/material";
import { Storage, Refresh, PlayArrow } from "@mui/icons-material";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { clientsApi, connectorsApi, assetsApi, projectsApi } from "../services/api";
import { Client, Connector, Asset, Project } from "../types";
import { fromNow } from "../utils/datetime";

const CLASS_COLOR: Record<string, string> = {
  vm: "#4285F4",
  storage: "#ff9800",
  network: "#34A853",
  database: "#00e676",
  identity: "#f06292",
  keyvault: "#ffd54f",
  other: "rgba(255,255,255,0.5)",
};

const STATUS_COLOR: Record<string, string> = {
  active: "#00e676",
  stale: "#ff9800",
  deleted: "rgba(255,255,255,0.4)",
};

const ASSET_CLASSES = ["vm", "storage", "network", "database", "identity", "keyvault", "other"];

export default function Assets() {
  const qc = useQueryClient();
  const navigate = useNavigate();

  const [clientId, setClientId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [connectorId, setConnectorId] = useState("");
  const [assetClass, setAssetClass] = useState("");
  const [resourceGroup, setResourceGroup] = useState("");
  const [region, setRegion] = useState("");
  const [statusFilter, setStatusFilter] = useState("active");
  const [search, setSearch] = useState("");

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", clientId],
    queryFn: () => projectsApi.list(clientId),
    enabled: !!clientId,
  });
  const { data: connectors = [] } = useQuery<Connector[]>({
    queryKey: ["connectors", clientId, projectId],
    queryFn: () => connectorsApi.list(clientId, projectId || undefined),
    enabled: !!clientId,
  });

  // Reset connector + class filters when project changes so we don't show stale picks
  React.useEffect(() => {
    setConnectorId("");
  }, [projectId]);
  const { data: facets = {} as any } = useQuery<any>({
    queryKey: ["asset-facets", clientId],
    queryFn: () => assetsApi.facets(clientId),
    enabled: !!clientId,
  });
  const { data: assets = [], isLoading } = useQuery<Asset[]>({
    queryKey: ["assets", clientId, projectId, connectorId, assetClass, resourceGroup, region, statusFilter, search],
    queryFn: () =>
      assetsApi.list(clientId, {
        project_id: projectId || undefined,
        connector_id: connectorId || undefined,
        asset_class: assetClass || undefined,
        resource_group: resourceGroup || undefined,
        region: region || undefined,
        status: statusFilter || undefined,
        q: search || undefined,
      }),
    enabled: !!clientId,
    refetchInterval: 30000, // auto-refresh every 30 s so new assets appear after a scan completes
  });

  const syncMutation = useMutation({
    mutationFn: () => assetsApi.sync(clientId, connectorId || undefined),
    onSuccess: () => {
      // Sync runs as a background task; poll a few times to catch when it lands.
      setTimeout(() => qc.invalidateQueries({ queryKey: ["assets"] }), 3000);
      setTimeout(() => qc.invalidateQueries({ queryKey: ["assets"] }), 10000);
      setTimeout(() => qc.invalidateQueries({ queryKey: ["assets"] }), 20000);
    },
  });

  const { data: allAssets = [] } = useQuery<Asset[]>({
    queryKey: ["assets-all-status", clientId],
    queryFn: () => assetsApi.list(clientId, { status: "all" }),
    enabled: !!clientId,
    refetchInterval: 30000,
  });
  const staleCount = allAssets.filter((a) => a.status === "stale").length;

  const restoreStaleMutation = useMutation({
    mutationFn: () => assetsApi.restoreStale(clientId, connectorId || undefined),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["assets-all-status"] });
    },
  });

  const scanMutation = useMutation({
    mutationFn: (assetId: string) => assetsApi.scan(clientId, assetId),
    onSuccess: () => {
      setTimeout(() => qc.invalidateQueries({ queryKey: ["assets"] }), 4000);
    },
  });

  const BADGE_DAYS = 7;
  const badgeCutoff = Date.now() - BADGE_DAYS * 24 * 60 * 60 * 1000;
  // "N" = newly discovered (first_seen_at within 7 days, never been stale)
  const isNewAsset = (a: Asset) =>
    !!a.first_seen_at &&
    new Date(a.first_seen_at).getTime() >= badgeCutoff &&
    !a.reappeared_at;
  // "R" = was STALE, reappeared in the live inventory within 7 days
  const isReappeared = (a: Asset) =>
    !!a.reappeared_at && new Date(a.reappeared_at).getTime() >= badgeCutoff;

  const [newOnly, setNewOnly] = useState(false);
  const displayedAssets = newOnly ? assets.filter((a) => isNewAsset(a) || isReappeared(a)) : assets;
  const newCount = assets.filter(isNewAsset).length;
  const reappearedCount = assets.filter(isReappeared).length;

  const classCounts = displayedAssets.reduce((acc: Record<string, number>, a) => {
    const c = a.asset_class || "other";
    acc[c] = (acc[c] || 0) + 1;
    return acc;
  }, {});

  const accountColumn = (a: Asset) => a.subscription_id || a.account_id || a.project_id || "—";
  const groupColumn = (a: Asset) => a.resource_group || a.region || "—";

  const [sortKey, setSortKey] = React.useState<string>("name");
  const [sortDir, setSortDir] = React.useState<"asc" | "desc">("asc");
  const sortedAssets = React.useMemo(() => {
    const dir = sortDir === "asc" ? 1 : -1;
    return [...displayedAssets].sort((a, b) => {
      const av: any = (a as any)[sortKey] ?? "";
      const bv: any = (b as any)[sortKey] ?? "";
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
  }, [displayedAssets, sortKey, sortDir]);
  const setSort = (k: string) => {
    if (sortKey === k) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else { setSortKey(k); setSortDir("asc"); }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Asset Inventory</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            All cloud resources discovered by your connectors
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", alignItems: "center" }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Client</InputLabel>
            <Select value={clientId} onChange={(e) => { setClientId(e.target.value); setProjectId(""); }} label="Client"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!clientId}>
            <InputLabel sx={{ color: "text.secondary" }}>Project</InputLabel>
            <Select value={projectId} onChange={(e) => setProjectId(e.target.value)} label="Project"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => (
                <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!clientId}>
            <InputLabel sx={{ color: "text.secondary" }}>Connector</InputLabel>
            <Select value={connectorId} onChange={(e) => setConnectorId(e.target.value)} label="Connector"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All</MenuItem>
              {connectors.map((c) => (
                <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>
              ))}
            </Select>
          </FormControl>
          {staleCount > 0 && (
            <Tooltip title={`${staleCount} stale asset(s). Click to restore all to Active — next sync will re-evaluate automatically.`}>
              <Button
                variant="outlined"
                size="small"
                disabled={restoreStaleMutation.isPending}
                onClick={() => restoreStaleMutation.mutate()}
                sx={{ color: "#ff9800", borderColor: "#ff9800", textTransform: "none",
                  "&:hover": { bgcolor: "rgba(255,152,0,0.08)", borderColor: "#ff9800" } }}
              >
                Restore {staleCount} stale
              </Button>
            </Tooltip>
          )}
          <Button
            variant="contained"
            startIcon={syncMutation.isPending ? <CircularProgress size={14} sx={{ color: "text.primary" }} /> : <Refresh />}
            disabled={!clientId || syncMutation.isPending}
            onClick={() => syncMutation.mutate()}
            sx={{ bgcolor: "#4285F4", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}
          >
            Sync Now
          </Button>
        </Box>
      </Box>

      {clientId && (
        <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap", alignItems: "center" }}>
          <Chip label={`All: ${displayedAssets.length}`} size="small" clickable
            onClick={() => { setAssetClass(""); setNewOnly(false); }}
            sx={{ bgcolor: assetClass || newOnly ? "rgba(255,255,255,0.05)" : "rgba(66,133,244,0.2)", color: "text.primary", border: assetClass || newOnly ? "none" : "1px solid #4285F4" }} />
          {(newCount > 0 || reappearedCount > 0) && (
            <Tooltip title={`${newCount} new asset(s) discovered + ${reappearedCount} reappeared in the last ${BADGE_DAYS} days. Click to filter.`}>
              <Chip
                label={[newCount > 0 && `N:${newCount}`, reappearedCount > 0 && `R:${reappearedCount}`].filter(Boolean).join("  ")}
                size="small"
                clickable
                onClick={() => { setNewOnly(!newOnly); setAssetClass(""); }}
                sx={{
                  bgcolor: newOnly ? "rgba(0,230,118,0.25)" : "rgba(0,230,118,0.1)",
                  color: "#00e676",
                  border: newOnly ? "1px solid #00e676" : "none",
                  fontWeight: 600,
                }}
              />
            </Tooltip>
          )}
          {ASSET_CLASSES.filter((c) => classCounts[c]).map((c) => (
            <Chip key={c} label={`${c.charAt(0).toUpperCase() + c.slice(1)}: ${classCounts[c]}`} size="small" clickable
              onClick={() => setAssetClass(assetClass === c ? "" : c)}
              sx={{
                bgcolor: `${CLASS_COLOR[c]}${assetClass === c ? "40" : "20"}`,
                color: CLASS_COLOR[c],
                border: assetClass === c ? `1px solid ${CLASS_COLOR[c]}` : "none",
              }} />
          ))}
          <Box sx={{ flexGrow: 1 }} />
          <FormControl size="small" sx={{ minWidth: 140 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Resource Group</InputLabel>
            <Select value={resourceGroup} onChange={(e) => setResourceGroup(e.target.value)} label="Resource Group"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All</MenuItem>
              {(facets.resource_group || []).map((rg: string) => (
                <MenuItem key={rg} value={rg}>{rg}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Region</InputLabel>
            <Select value={region} onChange={(e) => setRegion(e.target.value)} label="Region"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All</MenuItem>
              {(facets.region || []).map((r: string) => (
                <MenuItem key={r} value={r}>{r}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Status</InputLabel>
            <Select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} label="Status"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="active">Active</MenuItem>
              <MenuItem value="all">All (incl. stale)</MenuItem>
            </Select>
          </FormControl>
          <TextField size="small" placeholder="Search name…" value={search}
            onChange={(e) => setSearch(e.target.value)}
            sx={{ minWidth: 180,
              "& .MuiOutlinedInput-root": { color: "text.primary", "& fieldset": { borderColor: "divider" } },
              "& input::placeholder": { color: "text.secondary" } }} />
          <Tooltip title="Stale assets (not seen in the latest sync) — excluded from assessments & reports">
            <Button variant="outlined" size="small" onClick={() => navigate("/stale-assets")}
              sx={{ color: "#ff9800", borderColor: "rgba(255,152,0,0.5)", whiteSpace: "nowrap" }}>
              Stale assets →
            </Button>
          </Tooltip>
        </Box>
      )}

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "text.primary" }}>
          Select a client to view its asset inventory.
        </Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      ) : assets.length === 0 ? (
        <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <Storage sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No assets discovered yet. Click <b>Sync Now</b> to pull inventory from your connectors.
          </Typography>
        </Card>
      ) : (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                  <TableCell><TableSortLabel active={sortKey === "name"} direction={sortDir} onClick={() => setSort("name")}
                    sx={{ color: "rgba(255,255,255,0.5) !important", "& .MuiTableSortLabel-icon": { color: "rgba(255,255,255,0.5) !important" } }}>NAME</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "asset_type"} direction={sortDir} onClick={() => setSort("asset_type")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>TYPE</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "asset_class"} direction={sortDir} onClick={() => setSort("asset_class")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>CLASS</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "subscription_id"} direction={sortDir} onClick={() => setSort("subscription_id")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>SUBSCRIPTION / ACCOUNT</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "resource_group"} direction={sortDir} onClick={() => setSort("resource_group")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>RESOURCE GROUP / REGION</TableSortLabel></TableCell>
                  <TableCell align="right"><TableSortLabel active={sortKey === "open_findings_count"} direction={sortDir} onClick={() => setSort("open_findings_count")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>OPEN FINDINGS</TableSortLabel></TableCell>
                  <TableCell align="right"><TableSortLabel active={sortKey === "risks_count"} direction={sortDir} onClick={() => setSort("risks_count")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>RISKS</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "status"} direction={sortDir} onClick={() => setSort("status")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>STATUS</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "last_synced_at"} direction={sortDir} onClick={() => setSort("last_synced_at")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>SYNCED</TableSortLabel></TableCell>
                  <TableCell align="right">ACTIONS</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sortedAssets.map((a) => {
                  const klass = a.asset_class || "other";
                  const findingColor = a.open_findings_count > 0 ? "#f44336" : "rgba(255,255,255,0.3)";
                  const riskColor = a.risks_count > 0 ? "#ff9800" : "rgba(255,255,255,0.3)";
                  return (
                    <TableRow key={a.id}
                      sx={{ cursor: "pointer", "&:hover": { bgcolor: "rgba(255,255,255,0.03)" },
                        "& td": { borderColor: "divider", py: 1 } }}
                      onClick={() => navigate(`/assets/${a.id}`)}>
                      <TableCell sx={{ color: "text.primary", maxWidth: 240 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                          <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {a.name}
                          </Typography>
                          {isReappeared(a) && (
                            <Tooltip title="Reappeared — this asset was previously STALE and is now back in the live inventory">
                              <Chip label="R" size="small"
                                sx={{ bgcolor: "rgba(255,152,0,0.2)", color: "#ff9800", fontSize: 10, height: 16, minWidth: 20, flexShrink: 0, fontWeight: 700 }} />
                            </Tooltip>
                          )}
                          {isNewAsset(a) && (
                            <Tooltip title="New — first discovered in the last 7 days">
                              <Chip label="N" size="small"
                                sx={{ bgcolor: "rgba(0,230,118,0.2)", color: "#00e676", fontSize: 10, height: 16, minWidth: 20, flexShrink: 0, fontWeight: 700 }} />
                            </Tooltip>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 12, maxWidth: 200 }}>
                        <Typography variant="caption" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>
                          {a.asset_type || "—"}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={klass} size="small"
                          sx={{ bgcolor: `${CLASS_COLOR[klass] || "#888"}20`, color: CLASS_COLOR[klass] || "#888", fontSize: 10, height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 12, maxWidth: 200 }}>
                        <Typography variant="caption" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>
                          {accountColumn(a)}
                        </Typography>
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>
                        {groupColumn(a)}
                      </TableCell>
                      <TableCell align="right" sx={{ color: findingColor, fontWeight: 600 }}>
                        {a.open_findings_count}
                      </TableCell>
                      <TableCell align="right" sx={{ color: riskColor, fontWeight: 600 }}>
                        {a.risks_count}
                      </TableCell>
                      <TableCell>
                        <Chip label={a.status} size="small"
                          sx={{ bgcolor: `${STATUS_COLOR[a.status] || "#888"}20`, color: STATUS_COLOR[a.status] || "#888", fontSize: 10, height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>
                        {fromNow(a.last_synced_at)}
                      </TableCell>
                      <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                        <Tooltip title="Run on-demand scan against this asset">
                          <span>
                            <Button
                              size="small"
                              variant="outlined"
                              startIcon={<PlayArrow sx={{ fontSize: 14 }} />}
                              disabled={scanMutation.isPending}
                              onClick={() => scanMutation.mutate(a.id)}
                              sx={{ borderColor: "#4285F4", color: "#4285F4", fontSize: 10, py: 0.25, minWidth: 0 }}
                            >
                              Scan
                            </Button>
                          </span>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </Card>
      )}
    </Box>
  );
}
