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
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
dayjs.extend(relativeTime);

const CLASS_COLOR: Record<string, string> = {
  vm: "#00e5ff",
  storage: "#ff9800",
  network: "#7c4dff",
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
  const [statusFilter, setStatusFilter] = useState("");
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
  });

  const syncMutation = useMutation({
    mutationFn: () => assetsApi.sync(clientId, connectorId || undefined),
    onSuccess: () => {
      // Refetch shortly after the background sync has likely completed.
      setTimeout(() => qc.invalidateQueries({ queryKey: ["assets"] }), 1500);
      setTimeout(() => qc.invalidateQueries({ queryKey: ["assets"] }), 6000);
    },
  });

  const scanMutation = useMutation({
    mutationFn: (assetId: string) => assetsApi.scan(clientId, assetId),
    onSuccess: () => {
      setTimeout(() => qc.invalidateQueries({ queryKey: ["assets"] }), 4000);
    },
  });

  const classCounts = assets.reduce((acc: Record<string, number>, a) => {
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
    return [...assets].sort((a, b) => {
      const av: any = (a as any)[sortKey] ?? "";
      const bv: any = (b as any)[sortKey] ?? "";
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
  }, [assets, sortKey, sortDir]);
  const setSort = (k: string) => {
    if (sortKey === k) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else { setSortKey(k); setSortDir("asc"); }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Asset Inventory</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            All cloud resources discovered by your connectors
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", alignItems: "center" }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
            <Select value={clientId} onChange={(e) => { setClientId(e.target.value); setProjectId(""); }} label="Client"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!clientId}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Project</InputLabel>
            <Select value={projectId} onChange={(e) => setProjectId(e.target.value)} label="Project"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => (
                <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!clientId}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Connector</InputLabel>
            <Select value={connectorId} onChange={(e) => setConnectorId(e.target.value)} label="Connector"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All</MenuItem>
              {connectors.map((c) => (
                <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <Button
            variant="contained"
            startIcon={syncMutation.isPending ? <CircularProgress size={14} sx={{ color: "white" }} /> : <Refresh />}
            disabled={!clientId || syncMutation.isPending}
            onClick={() => syncMutation.mutate()}
            sx={{ bgcolor: "#00e5ff", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}
          >
            Sync Now
          </Button>
        </Box>
      </Box>

      {clientId && (
        <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap", alignItems: "center" }}>
          <Chip label={`All: ${assets.length}`} size="small" clickable
            onClick={() => setAssetClass("")}
            sx={{ bgcolor: assetClass ? "rgba(255,255,255,0.05)" : "rgba(0,229,255,0.2)", color: "white", border: assetClass ? "none" : "1px solid #00e5ff" }} />
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
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Resource Group</InputLabel>
            <Select value={resourceGroup} onChange={(e) => setResourceGroup(e.target.value)} label="Resource Group"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All</MenuItem>
              {(facets.resource_group || []).map((rg: string) => (
                <MenuItem key={rg} value={rg}>{rg}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Region</InputLabel>
            <Select value={region} onChange={(e) => setRegion(e.target.value)} label="Region"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All</MenuItem>
              {(facets.region || []).map((r: string) => (
                <MenuItem key={r} value={r}>{r}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Status</InputLabel>
            <Select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} label="Status"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All</MenuItem>
              <MenuItem value="active">Active</MenuItem>
              <MenuItem value="stale">Stale</MenuItem>
            </Select>
          </FormControl>
          <TextField size="small" placeholder="Search name…" value={search}
            onChange={(e) => setSearch(e.target.value)}
            sx={{ minWidth: 180,
              "& .MuiOutlinedInput-root": { color: "white", "& fieldset": { borderColor: "rgba(255,255,255,0.2)" } },
              "& input::placeholder": { color: "rgba(255,255,255,0.4)" } }} />
        </Box>
      )}

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(0,229,255,0.1)", color: "white" }}>
          Select a client to view its asset inventory.
        </Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress sx={{ color: "#00e5ff" }} />
        </Box>
      ) : assets.length === 0 ? (
        <Card sx={{ bgcolor: "#161b22", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <Storage sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
          <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>
            No assets discovered yet. Click <b>Sync Now</b> to pull inventory from your connectors.
          </Typography>
        </Card>
      ) : (
        <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
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
                        "& td": { borderColor: "rgba(255,255,255,0.05)", py: 1 } }}
                      onClick={() => navigate(`/assets/${a.id}`)}>
                      <TableCell sx={{ color: "white", maxWidth: 240 }}>
                        <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {a.name}
                        </Typography>
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.7)", fontSize: 12, maxWidth: 200 }}>
                        <Typography variant="caption" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>
                          {a.asset_type || "—"}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={klass} size="small"
                          sx={{ bgcolor: `${CLASS_COLOR[klass] || "#888"}20`, color: CLASS_COLOR[klass] || "#888", fontSize: 10, height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.6)", fontSize: 12, maxWidth: 200 }}>
                        <Typography variant="caption" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>
                          {accountColumn(a)}
                        </Typography>
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>
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
                      <TableCell sx={{ color: "rgba(255,255,255,0.4)", fontSize: 11 }}>
                        {a.last_synced_at ? dayjs(a.last_synced_at).fromNow() : "—"}
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
                              sx={{ borderColor: "#00e5ff", color: "#00e5ff", fontSize: 10, py: 0.25, minWidth: 0 }}
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
