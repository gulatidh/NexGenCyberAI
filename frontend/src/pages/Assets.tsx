import React, { useState } from "react";
import {
  Box, Typography, Card, Chip, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer, TableSortLabel,
  FormControl, InputLabel, Select, MenuItem, Button, TextField, Alert, Tooltip,
  Checkbox, Tabs, Tab,
} from "@mui/material";
import { Storage, Refresh, PlayArrow, CheckCircle } from "@mui/icons-material";
import { useNavigate, useLocation } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { connectorsApi, assetsApi, projectsApi } from "../services/api";
import { Connector, Asset, Project } from "../types";
import { useActiveClient } from "../contexts/ClientContext";
import { fromNow } from "../utils/datetime";

const CLASS_COLOR: Record<string, string> = {
  vm: "#4285F4",
  storage: "#ff9800",
  network: "#34A853",
  database: "#00e676",
  identity: "#f06292",
  keyvault: "#ffd54f",
  other: "#9e9e9e",
};

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#4285F4",
};

const STATUS_COLOR: Record<string, string> = {
  active: "#00e676",
  stale: "#ff9800",
  deleted: "#9e9e9e",
  new: "#4285F4",
  reappeared: "#ce93d8",
};

const ASSET_CLASSES = ["vm", "storage", "network", "database", "identity", "keyvault", "other"];

type ActiveTab = "active" | "new" | "reappeared" | "stale";

export default function Assets() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const assetsBase = location.pathname.startsWith("/platform") ? "/platform/assets" : "/assets";

  const { clientId } = useActiveClient();
  const [projectId, setProjectId] = useState("");
  const [connectorId, setConnectorId] = useState("");
  const [assetClass, setAssetClass] = useState("");
  const [resourceGroup, setResourceGroup] = useState("");
  const [region, setRegion] = useState("");
  const [search, setSearch] = useState("");

  // Tab state
  const [activeTab, setActiveTab] = useState<ActiveTab>("active");
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  // Reset project/connectors when account changes
  React.useEffect(() => { setProjectId(""); setSelectedIds([]); }, [clientId]);

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

  React.useEffect(() => { setConnectorId(""); }, [projectId]);

  const { data: facets = {} as any } = useQuery<any>({
    queryKey: ["asset-facets", clientId],
    queryFn: () => assetsApi.facets(clientId),
    enabled: !!clientId,
  });

  // All assets — used for tab counts
  const { data: allAssets = [] } = useQuery<Asset[]>({
    queryKey: ["assets-all-status", clientId],
    queryFn: () => assetsApi.list(clientId, { status: "all" }),
    enabled: !!clientId,
    refetchInterval: 30000,
  });

  // Tab-specific assets — what's shown in the table
  const { data: tabAssets = [], isLoading } = useQuery<Asset[]>({
    queryKey: ["assets", clientId, projectId, activeTab, search],
    queryFn: () =>
      assetsApi.list(clientId, {
        project_id: projectId || undefined,
        status: activeTab,
        q: search || undefined,
      }),
    enabled: !!clientId,
    refetchInterval: 30000,
  });

  // Tab counts from allAssets
  const activeCount = allAssets.filter((a) => a.status === "active").length;
  const newCount = allAssets.filter((a) => a.status === "new").length;
  const reappearedCount = allAssets.filter((a) => a.status === "reappeared").length;
  const staleCount = allAssets.filter((a) => a.status === "stale").length;

  const syncMutation = useMutation({
    mutationFn: () => assetsApi.sync(clientId, connectorId || undefined),
    onSuccess: () => {
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ["assets"] });
        qc.invalidateQueries({ queryKey: ["assets-all-status"] });
      }, 3000);
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ["assets"] });
        qc.invalidateQueries({ queryKey: ["assets-all-status"] });
      }, 10000);
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ["assets"] });
        qc.invalidateQueries({ queryKey: ["assets-all-status"] });
      }, 20000);
    },
  });

  const approveMutation = useMutation({
    mutationFn: (ids: string[]) => assetsApi.approve(clientId, ids),
    onSuccess: () => {
      setSelectedIds([]);
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

  // Apply connector + assetClass filters client-side (they are visual filters, not tab filters)
  const displayedAssets = tabAssets.filter((a) => {
    if (connectorId && a.connector_id !== connectorId) return false;
    if (assetClass && a.asset_class !== assetClass) return false;
    if (resourceGroup && a.resource_group !== resourceGroup) return false;
    if (region && a.region !== region) return false;
    return true;
  });

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

  const showCheckboxes = activeTab === "new" || activeTab === "reappeared";
  const allVisibleSelected = displayedAssets.length > 0 && displayedAssets.every((a) => selectedIds.includes(a.id));
  const someSelected = selectedIds.length > 0 && !allVisibleSelected;

  const toggleSelectAll = () => {
    if (allVisibleSelected) {
      setSelectedIds([]);
    } else {
      setSelectedIds(displayedAssets.map((a) => a.id));
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const handleTabChange = (_: React.SyntheticEvent, val: ActiveTab) => {
    setActiveTab(val);
    setSelectedIds([]);
  };

  const TAB_COLORS: Record<ActiveTab, string> = {
    active: "#00e676",
    new: "#4285F4",
    reappeared: "#ce93d8",
    stale: "#ff9800",
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
        <>
          {/* Tab bar */}
          <Box sx={{ borderBottom: 1, borderColor: "divider", mb: 2 }}>
            <Tabs
              value={activeTab}
              onChange={handleTabChange}
              sx={{
                "& .MuiTab-root": { color: "text.secondary", textTransform: "none", fontWeight: 600 },
                "& .MuiTabs-indicator": { backgroundColor: TAB_COLORS[activeTab] },
              }}
            >
              <Tab
                value="active"
                label={`Active (${activeCount})`}
                sx={{ "&.Mui-selected": { color: "#00e676" } }}
              />
              <Tab
                value="new"
                label={`New (${newCount})`}
                sx={{ "&.Mui-selected": { color: "#4285F4" } }}
              />
              <Tab
                value="reappeared"
                label={`Reappeared (${reappearedCount})`}
                sx={{ "&.Mui-selected": { color: "#ce93d8" } }}
              />
              <Tab
                value="stale"
                label={`Stale (${staleCount})`}
                sx={{ "&.Mui-selected": { color: "#ff9800" } }}
              />
            </Tabs>
          </Box>

          {/* Filters row */}
          <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap", alignItems: "center" }}>
            <Chip label={`All: ${displayedAssets.length}`} size="small" clickable
              onClick={() => setAssetClass("")}
              sx={{ bgcolor: assetClass ? "rgba(255,255,255,0.05)" : "rgba(66,133,244,0.2)", color: "text.primary", border: assetClass ? "none" : "1px solid #4285F4" }} />
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
            <TextField size="small" placeholder="Search name…" value={search}
              onChange={(e) => setSearch(e.target.value)}
              sx={{ minWidth: 180,
                "& .MuiOutlinedInput-root": { color: "text.primary", "& fieldset": { borderColor: "divider" } },
                "& input::placeholder": { color: "text.secondary" } }} />
          </Box>

          {/* Approve action bar — only for new/reappeared tabs */}
          {showCheckboxes && (
            <Box sx={{ display: "flex", gap: 1, mb: 2, alignItems: "center" }}>
              <Button
                variant="contained"
                size="small"
                startIcon={<CheckCircle sx={{ fontSize: 16 }} />}
                disabled={selectedIds.length === 0 || approveMutation.isPending}
                onClick={() => approveMutation.mutate(selectedIds)}
                sx={{ bgcolor: "#00e676", color: "#0d1117", "&:hover": { bgcolor: "#00c853" }, textTransform: "none" }}
              >
                Approve selected ({selectedIds.length})
              </Button>
              <Button
                variant="outlined"
                size="small"
                disabled={displayedAssets.length === 0 || approveMutation.isPending}
                onClick={() => approveMutation.mutate(displayedAssets.map((a) => a.id))}
                sx={{ color: "#00e676", borderColor: "#00e676", textTransform: "none",
                  "&:hover": { bgcolor: "rgba(0,230,118,0.08)", borderColor: "#00e676" } }}
              >
                Approve all ({displayedAssets.length})
              </Button>
              {approveMutation.isPending && (
                <CircularProgress size={16} sx={{ color: "#00e676" }} />
              )}
            </Box>
          )}
        </>
      )}

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "text.primary" }}>
          Select an account from the top toolbar to view its asset inventory.
        </Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      ) : displayedAssets.length === 0 ? (
        <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <Storage sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            {activeTab === "active" && "No active assets. Click Sync Now to pull inventory from your connectors."}
            {activeTab === "new" && "No new assets pending approval."}
            {activeTab === "reappeared" && "No reappeared assets pending approval."}
            {activeTab === "stale" && "No stale assets."}
          </Typography>
        </Card>
      ) : (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                  {showCheckboxes && (
                    <TableCell padding="checkbox">
                      <Checkbox
                        size="small"
                        checked={allVisibleSelected}
                        indeterminate={someSelected}
                        onChange={toggleSelectAll}
                        sx={{ color: "text.secondary", "&.Mui-checked": { color: "#00e676" }, "&.MuiCheckbox-indeterminate": { color: "#00e676" } }}
                      />
                    </TableCell>
                  )}
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
                  <TableCell><TableSortLabel active={sortKey === "open_findings_count"} direction={sortDir} onClick={() => setSort("open_findings_count")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>SEVERITY</TableSortLabel></TableCell>
                  <TableCell align="right"><TableSortLabel active={sortKey === "cve_count"} direction={sortDir} onClick={() => setSort("cve_count")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>CVEs</TableSortLabel></TableCell>
                  <TableCell align="right"><TableSortLabel active={sortKey === "risks_count"} direction={sortDir} onClick={() => setSort("risks_count")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>RISKS</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "status"} direction={sortDir} onClick={() => setSort("status")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>STATUS</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "last_scan_date"} direction={sortDir} onClick={() => setSort("last_scan_date")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>LAST SCAN</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "last_synced_at"} direction={sortDir} onClick={() => setSort("last_synced_at")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>SYNCED</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "risk_score"} direction={sortDir} onClick={() => setSort("risk_score")}
                    sx={{ color: "rgba(255,255,255,0.5) !important", "& .MuiTableSortLabel-icon": { color: "rgba(255,255,255,0.5) !important" } }}>RISK SCORE</TableSortLabel></TableCell>
                  <TableCell align="right">ACTIONS</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sortedAssets.map((a) => {
                  const klass = a.asset_class || "other";
                  const riskColor = a.risks_count > 0 ? "#ff9800" : "rgba(255,255,255,0.3)";
                  const isSelected = selectedIds.includes(a.id);
                  return (
                    <TableRow key={a.id}
                      sx={{ cursor: "pointer", "&:hover": { bgcolor: "rgba(255,255,255,0.03)" },
                        "& td": { borderColor: "divider", py: 1 },
                        ...(isSelected ? { bgcolor: "rgba(0,230,118,0.05)" } : {}),
                      }}
                      onClick={() => showCheckboxes ? toggleSelect(a.id) : navigate(`${assetsBase}/${a.id}`)}>
                      {showCheckboxes && (
                        <TableCell padding="checkbox" onClick={(e) => { e.stopPropagation(); toggleSelect(a.id); }}>
                          <Checkbox
                            size="small"
                            checked={isSelected}
                            sx={{ color: "text.secondary", "&.Mui-checked": { color: "#00e676" } }}
                          />
                        </TableCell>
                      )}
                      <TableCell sx={{ color: "text.primary", maxWidth: 240 }}>
                        <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {a.name}
                        </Typography>
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
                      <TableCell>
                        <Box sx={{ display: "flex", gap: 0.5, alignItems: "center" }}>
                          {(["critical", "high", "medium", "low"] as const).map((s) => {
                            const count = a.severity_breakdown?.[s] ?? 0;
                            if (count === 0) return null;
                            return (
                              <Tooltip key={s} title={`${count} ${s}`}>
                                <Chip
                                  label={count}
                                  size="small"
                                  sx={{ bgcolor: `${SEV_COLOR[s]}22`, color: SEV_COLOR[s], fontSize: 10, height: 18, minWidth: 28, cursor: "pointer" }}
                                />
                              </Tooltip>
                            );
                          })}
                          {a.open_findings_count === 0 && (
                            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.2)" }}>—</Typography>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell align="right" sx={{ color: (a.cve_count ?? 0) > 0 ? "#4285F4" : "rgba(255,255,255,0.2)", fontWeight: 600, fontSize: 13 }}>
                        {(a.cve_count ?? 0) > 0 ? a.cve_count : "—"}
                      </TableCell>
                      <TableCell align="right" sx={{ color: riskColor, fontWeight: 600 }}>
                        {a.risks_count || "—"}
                      </TableCell>
                      <TableCell>
                        <Chip label={a.status} size="small"
                          sx={{ bgcolor: `${STATUS_COLOR[a.status] || "#888"}20`, color: STATUS_COLOR[a.status] || "#888", fontSize: 10, height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>
                        {a.last_scan_date ? fromNow(a.last_scan_date) : "—"}
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>
                        {fromNow(a.last_synced_at)}
                      </TableCell>
                      <TableCell>
                        {a.risk_score != null ? (
                          <Chip
                            label={a.risk_score}
                            size="small"
                            sx={{
                              fontWeight: 700, fontSize: 11,
                              bgcolor: a.risk_score > 70 ? "rgba(244,67,54,0.15)"
                                     : a.risk_score > 40 ? "rgba(255,152,0,0.15)"
                                     : a.risk_score > 20 ? "rgba(255,235,59,0.12)"
                                     : "rgba(76,175,80,0.12)",
                              color: a.risk_score > 70 ? "#f44336"
                                   : a.risk_score > 40 ? "#ff9800"
                                   : a.risk_score > 20 ? "#ffeb3b"
                                   : "#4caf50",
                            }}
                          />
                        ) : <Typography sx={{ color: "text.disabled", fontSize: 12 }}>—</Typography>}
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
