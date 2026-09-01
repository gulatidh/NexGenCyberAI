/**
 * /data-model — Interactive Relationship Explorer
 *
 * Features:
 * 1. Edge weight: stroke width scales with connection density from stats
 * 2. Health rings: coloured outer ring per node (red/amber/green) from stats
 * 3. Blast radius: anchor panel shows downstream entity counts + gap indicators
 * 4. Hover preview: floating tooltip with top-3 records + stats breakdown
 * 5. Right-click menu: View All / Run Agent / Export CSV
 * 6. Path finder: Shift+click two nodes → BFS shortest-path highlight (gold)
 */
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, TextField, InputAdornment,
  List, ListItemButton, ListItemText,
  Chip, CircularProgress, alpha, useTheme, IconButton,
  Menu, MenuItem, ListItemIcon, Divider,
  Alert, Table, TableHead, TableRow, TableCell, TableBody,
  TableContainer, TablePagination, Tabs, Tab, Tooltip,
} from "@mui/material";
import {
  Search, Close, OpenInNew, SmartToy, Download,
  ArrowForward, WarningAmber, Storage, Key,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { dataModelApi, dbBrowserApi, usersApi } from "../services/api";
import { useActiveClient } from "../contexts/ClientContext";

// ── Static ontology data ──────────────────────────────────────────────────────

interface ONode {
  entity: string; label: string;
  cx: number; cy: number; labelX: number; labelW: number; color: string;
}
interface OEdge {
  from: string; to: string;
  x1: number; y1: number; x2: number; y2: number; dashed?: boolean;
}
interface SubNode {
  id: string; entity: string; label: string; detail?: string; severity?: string | null;
}
interface AnchorRecord {
  id: string; label: string; entityKey: string; detail?: string;
}

const ONT_NODES: ONode[] = [
  { entity:"Client",      label:"Client",             cx: 70,  cy:300, labelX: 35,   labelW: 70,  color:"#2563eb" },
  { entity:"Asset",       label:"Asset",              cx:250,  cy:190, labelX:215,   labelW: 70,  color:"#2563eb" },
  { entity:"Control",     label:"Control",            cx:250,  cy:470, labelX:213.5, labelW: 73,  color:"#7c3aed" },
  { entity:"DataFlow",    label:"Data Flow",          cx:440,  cy: 90, labelX:396.5, labelW: 87,  color:"#7c3aed" },
  { entity:"Finding",     label:"Finding",            cx:440,  cy:280, labelX:403.5, labelW: 73,  color:"#0f766e" },
  { entity:"SmartIntel",  label:"Smart Intelligence", cx:440,  cy:560, labelX:365,   labelW:150,  color:"#4338ca" },
  { entity:"Risk",        label:"Risk",               cx:640,  cy:220, labelX:605,   labelW: 70,  color:"#b45309" },
  { entity:"Evidence",    label:"Evidence",           cx:640,  cy:470, labelX:600,   labelW: 80,  color:"#15803d" },
  { entity:"AttackPath",  label:"Attack Path",        cx:830,  cy:130, labelX:779.5, labelW:101,  color:"#b45309" },
  { entity:"Technique",   label:"MITRE Technique",    cx:830,  cy:300, labelX:765.5, labelW:129,  color:"#b91c1c" },
  { entity:"Remediation", label:"Remediation",        cx:830,  cy:420, labelX:779.5, labelW:101,  color:"#b91c1c" },
  { entity:"Report",      label:"Report",             cx:1020, cy:300, labelX:985,   labelW: 70,  color:"#15803d" },
];

const ONT_EDGES: OEdge[] = [
  { from:"Client",      to:"Asset",       x1: 70, y1:300, x2:250,  y2:190 },
  { from:"Asset",       to:"DataFlow",    x1:250, y1:190, x2:440,  y2: 90 },
  { from:"Asset",       to:"Finding",     x1:250, y1:190, x2:440,  y2:280 },
  { from:"Finding",     to:"Risk",        x1:440, y1:280, x2:640,  y2:220 },
  { from:"Risk",        to:"AttackPath",  x1:640, y1:220, x2:830,  y2:130 },
  { from:"DataFlow",    to:"Technique",   x1:440, y1: 90, x2:830,  y2:300 },
  { from:"AttackPath",  to:"Technique",   x1:830, y1:130, x2:830,  y2:300 },
  { from:"Risk",        to:"Remediation", x1:640, y1:220, x2:830,  y2:420 },
  { from:"Technique",   to:"Remediation", x1:830, y1:300, x2:830,  y2:420 },
  { from:"Control",     to:"Evidence",    x1:250, y1:470, x2:640,  y2:470 },
  { from:"Remediation", to:"Evidence",    x1:830, y1:420, x2:640,  y2:470 },
  { from:"Finding",     to:"Report",      x1:440, y1:280, x2:1020, y2:300 },
  { from:"Remediation", to:"Report",      x1:830, y1:420, x2:1020, y2:300 },
  { from:"Evidence",    to:"Report",      x1:640, y1:470, x2:1020, y2:300 },
  { from:"SmartIntel",  to:"Asset",       x1:440, y1:560, x2:250,  y2:190, dashed:true },
  { from:"SmartIntel",  to:"Finding",     x1:440, y1:560, x2:440,  y2:280, dashed:true },
  { from:"SmartIntel",  to:"Risk",        x1:440, y1:560, x2:640,  y2:220, dashed:true },
  { from:"SmartIntel",  to:"Control",     x1:440, y1:560, x2:250,  y2:470, dashed:true },
];

const TO_KEY: Record<string, string> = {
  Asset:"asset", Finding:"finding", Risk:"risk", Control:"control",
  Remediation:"remediation", Technique:"technique", Report:"report",
  Evidence:"report", AttackPath:"risk", SmartIntel:"finding",
  DataFlow:"", Client:"",
};

const KEY_TO_NODE: Record<string, string> = {
  asset:"Asset", finding:"Finding", risk:"Risk", control:"Control",
  remediation:"Remediation", technique:"Technique", report:"Report",
};

const ONT_ROUTES: Record<string, string> = {
  Client:"/platform/clients", Asset:"/platform/assets",
  Control:"/compliance/frameworks", DataFlow:"/threat-intel/threat-models",
  Finding:"/vulnerability/findings", SmartIntel:"/intelligence/nl-query",
  Risk:"/risk/register", Evidence:"/compliance/evidence",
  AttackPath:"/threat-intel/attack-paths", Technique:"/threat-intel/register",
  Remediation:"/governance/remediation", Report:"/vapt/reports",
};

const LISTABLE = new Set(["asset","finding","risk","remediation"]);
const AGENT_NODES = new Set(["Finding","Risk","Control","Technique","Remediation"]);

const SEV_COLOR: Record<string,string> = {
  critical:"#b91c1c", high:"#ea580c", medium:"#d97706", low:"#16a34a", info:"#0284c7",
};

const ENT_ICON: Record<string,string> = {
  finding:"⚠", risk:"◈", asset:"⬡", remediation:"⚙", control:"⬟",
  technique:"⬡", report:"▤",
};

// Expected downstream entity types per anchor (for blast radius gap detection)
const EXPECTED_DOWNSTREAM: Record<string, string[]> = {
  finding: ["asset","risk","control"],
  risk: ["remediation","technique"],
  asset: ["finding","risk"],
  remediation: ["risk","report"],
};

// ── Sub-node layout ────────────────────────────────────────────────────────────

const GRAPH_CX = 560;
const GRAPH_CY = 300;
const SUB_R = 88;
const MAX_VIS = 5;

function subPositions(cx: number, cy: number, n: number): {x:number; y:number}[] {
  if (!n) return [];
  const base = Math.atan2(cy - GRAPH_CY, cx - GRAPH_CX);
  const spread = Math.min(Math.PI * 0.7, n * 0.42);
  return Array.from({length: n}, (_, i) => {
    const t = n === 1 ? 0 : i/(n-1) - 0.5;
    return {
      x: Math.round(cx + SUB_R * Math.cos(base + t * spread)),
      y: Math.round(cy + SUB_R * Math.sin(base + t * spread)),
    };
  });
}

// ── Path finder BFS ────────────────────────────────────────────────────────────

function findPath(startEntity: string, endEntity: string): {nodes: Set<string>; edges: Set<number>} {
  const adj: Record<string, {neighbor: string; edgeIdx: number}[]> = {};
  ONT_EDGES.forEach((e, i) => {
    if (!adj[e.from]) adj[e.from] = [];
    if (!adj[e.to])   adj[e.to]   = [];
    adj[e.from].push({neighbor: e.to,   edgeIdx: i});
    adj[e.to].push(  {neighbor: e.from, edgeIdx: i});
  });
  const queue: {node: string; np: string[]; ep: number[]}[] = [{node: startEntity, np: [startEntity], ep: []}];
  const visited = new Set<string>([startEntity]);
  while (queue.length) {
    const item = queue.shift()!;
    if (item.node === endEntity) return {nodes: new Set(item.np), edges: new Set(item.ep)};
    for (const {neighbor, edgeIdx} of adj[item.node] ?? []) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        queue.push({node: neighbor, np: [...item.np, neighbor], ep: [...item.ep, edgeIdx]});
      }
    }
  }
  return {nodes: new Set(), edges: new Set()};
}

// ── Database Browser component ────────────────────────────────────────────────

function DatabaseBrowser() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const [tableFilter, setTableFilter] = useState("");
  const [selectedTable, setSelectedTable] = useState<string | null>(null);
  const [selectedCol, setSelectedCol] = useState<string | null>(null);
  const [rowPage, setRowPage] = useState(1);

  const { data: me } = useQuery({ queryKey: ["me"], queryFn: usersApi.me, staleTime: 60_000 });
  const isAdmin = !!(me as any)?.is_admin;

  const { data: tables, isLoading: tablesLoading } = useQuery({
    queryKey: ["db-tables"],
    queryFn: dbBrowserApi.tables,
    staleTime: 30_000,
    enabled: isAdmin,
  });

  const { data: schema, isLoading: schemaLoading } = useQuery({
    queryKey: ["db-schema", selectedTable],
    queryFn: () => dbBrowserApi.schema(selectedTable!),
    enabled: isAdmin && !!selectedTable,
  });

  const { data: rowDataRaw, isLoading: rowsLoading } = useQuery({
    queryKey: ["db-rows", selectedTable, rowPage],
    queryFn: () => dbBrowserApi.rows(selectedTable!, rowPage),
    enabled: isAdmin && !!selectedTable,
  });
  const rowData = rowDataRaw as { columns: string[]; rows: unknown[][]; page: number; limit: number } | undefined;

  const { data: samples, isLoading: samplesLoading } = useQuery({
    queryKey: ["db-samples", selectedTable, selectedCol],
    queryFn: () => dbBrowserApi.samples(selectedTable!, selectedCol!),
    enabled: isAdmin && !!selectedTable && !!selectedCol,
  });

  if (!isAdmin) {
    return (
      <Alert severity="info" sx={{ mt: 2 }}>
        Database Browser is available to administrators only.
      </Alert>
    );
  }

  const filtered = (tables ?? []).filter((t) =>
    t.table.toLowerCase().includes(tableFilter.toLowerCase())
  );

  function tableGroup(name: string): "raw" | "import" | "system" | "normal" {
    if (name.startsWith("raw_")) return "raw";
    if (name.includes("import") || name.includes("assessment")) return "import";
    if (name === "alembic_version") return "system";
    return "normal";
  }

  const dotColor = (g: ReturnType<typeof tableGroup>) =>
    g === "raw" ? "#4285F4" : g === "import" ? "#FBBC04" : g === "system" ? "#6b7280" : "transparent";

  const truncate = (v: unknown, n: number) => {
    const s = v === null || v === undefined ? "" : String(v);
    return s.length > n ? s.slice(0, n) + "…" : s;
  };

  const selectedTableInfo = (tables ?? []).find((t) => t.table === selectedTable);

  return (
    <Box sx={{ display: "flex", gap: 0, height: 640, border: "1px solid", borderColor: "divider", borderRadius: 2, overflow: "hidden" }}>

      {/* Left: table list */}
      <Box sx={{ width: 260, flexShrink: 0, borderRight: "1px solid", borderColor: "divider", display: "flex", flexDirection: "column", bgcolor: "background.paper" }}>
        <Box sx={{ p: 1.25, borderBottom: "1px solid", borderColor: "divider" }}>
          <TextField
            size="small" fullWidth placeholder="Filter tables…"
            value={tableFilter} onChange={(e) => setTableFilter(e.target.value)}
            slotProps={{ input: { startAdornment: <InputAdornment position="start"><Search sx={{ fontSize: 15 }} /></InputAdornment> } }}
            sx={{ "& .MuiInputBase-root": { fontSize: 12 } }}
          />
        </Box>
        <Box sx={{ flex: 1, overflow: "auto" }}>
          {tablesLoading && <Box sx={{ display: "flex", justifyContent: "center", py: 3 }}><CircularProgress size={20} /></Box>}
          <List dense disablePadding>
            {filtered.map((t) => {
              const g = tableGroup(t.table);
              const dot = dotColor(g);
              return (
                <ListItemButton
                  key={t.table}
                  selected={selectedTable === t.table}
                  onClick={() => { setSelectedTable(t.table); setSelectedCol(null); setRowPage(1); }}
                  sx={{ py: 0.6, px: 1.5, opacity: g === "system" ? 0.55 : 1 }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, flex: 1, minWidth: 0 }}>
                    {dot !== "transparent"
                      ? <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: dot, flexShrink: 0 }} />
                      : <Box sx={{ width: 6, flexShrink: 0 }} />
                    }
                    <Typography sx={{ fontSize: 12, fontFamily: "monospace", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {t.table}
                    </Typography>
                    <Typography sx={{ fontSize: 10, color: "text.disabled", flexShrink: 0 }}>
                      {t.row_count >= 0 ? t.row_count.toLocaleString() : "—"}
                    </Typography>
                  </Box>
                </ListItemButton>
              );
            })}
          </List>
        </Box>
      </Box>

      {/* Right: schema + samples + rows */}
      <Box sx={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {!selectedTable ? (
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "text.disabled" }}>
            <Typography sx={{ fontSize: 13 }}>Select a table from the list to explore its schema and data.</Typography>
          </Box>
        ) : (
          <Box sx={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>

            {/* Schema section */}
            <Box sx={{ p: 1.5, borderBottom: "1px solid", borderColor: "divider", flexShrink: 0 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                <Typography sx={{ fontFamily: "monospace", fontWeight: 700, fontSize: 14 }}>{selectedTable}</Typography>
                {selectedTableInfo && (
                  <Chip label={`${selectedTableInfo.row_count.toLocaleString()} rows`} size="small"
                    sx={{ fontSize: 10, height: 18 }} />
                )}
                {schemaLoading && <CircularProgress size={12} />}
              </Box>
              {schema && (
                <TableContainer sx={{ maxHeight: 180 }}>
                  <Table size="small" stickyHeader>
                    <TableHead>
                      <TableRow>
                        {["Column", "Type", "Nullable", "PK"].map((h) => (
                          <TableCell key={h} sx={{ fontSize: 10, fontWeight: 700, py: 0.4, px: 1, bgcolor: isDark ? "#1e1e2e" : "#f5f5f5" }}>{h}</TableCell>
                        ))}
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {schema.map((col) => (
                        <TableRow key={col.name} hover
                          onClick={() => setSelectedCol(selectedCol === col.name ? null : col.name)}
                          sx={{ cursor: "pointer", bgcolor: selectedCol === col.name ? alpha("#4285F4", 0.08) : undefined }}
                        >
                          <TableCell sx={{ fontSize: 11, fontFamily: "monospace", py: 0.3, px: 1 }}>
                            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                              {col.primary_key && <Key sx={{ fontSize: 11, color: "#FBBC04" }} />}
                              <Typography sx={{ fontSize: 11, fontFamily: "monospace", fontWeight: col.primary_key ? 700 : 400 }}>{col.name}</Typography>
                            </Box>
                          </TableCell>
                          <TableCell sx={{ fontSize: 10, fontFamily: "monospace", color: "text.secondary", py: 0.3, px: 1 }}>{col.type}</TableCell>
                          <TableCell sx={{ py: 0.3, px: 1 }}>
                            {!col.nullable && <Chip label="NOT NULL" size="small" sx={{ fontSize: 9, height: 16, bgcolor: alpha("#EA4335", 0.1), color: "#EA4335" }} />}
                          </TableCell>
                          <TableCell sx={{ py: 0.3, px: 1 }}>
                            {col.primary_key && <Chip label="PK" size="small" sx={{ fontSize: 9, height: 16, bgcolor: alpha("#FBBC04", 0.12), color: "#FBBC04" }} />}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </Box>

            {/* Samples section */}
            {selectedCol && (
              <Box sx={{ p: 1.5, borderBottom: "1px solid", borderColor: "divider", flexShrink: 0, maxHeight: 200, overflow: "auto" }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.75 }}>
                  <Typography sx={{ fontSize: 12, fontWeight: 600 }}>
                    Sample values for <span style={{ fontFamily: "monospace" }}>{selectedCol}</span>
                  </Typography>
                  <IconButton size="small" onClick={() => setSelectedCol(null)}><Close sx={{ fontSize: 14 }} /></IconButton>
                </Box>
                {samplesLoading && <CircularProgress size={14} />}
                {samples && (
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontSize: 10, fontWeight: 700, py: 0.3, px: 1 }}>Value</TableCell>
                        <TableCell sx={{ fontSize: 10, fontWeight: 700, py: 0.3, px: 1 }}>Count</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {samples.map((s, i) => (
                        <TableRow key={i}>
                          <TableCell sx={{ fontSize: 11, fontFamily: "monospace", py: 0.25, px: 1 }}>
                            {s.value === null
                              ? <Typography component="span" sx={{ fontSize: 11, color: "text.disabled", fontStyle: "italic" }}>&lt;null&gt;</Typography>
                              : truncate(s.value, 60)
                            }
                          </TableCell>
                          <TableCell sx={{ fontSize: 11, py: 0.25, px: 1 }}>{s.count}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </Box>
            )}

            {/* Row viewer */}
            <Box sx={{ flex: 1, overflow: "auto", display: "flex", flexDirection: "column" }}>
              <>{rowsLoading && (
                <Box sx={{ display: "flex", justifyContent: "center", py: 2 }}><CircularProgress size={20} /></Box>
              )}
              {rowData && (
                <>
                  <Box sx={{ overflowX: "auto", flex: 1 }}>
                    <Table size="small" stickyHeader>
                      <TableHead>
                        <TableRow>
                          {rowData.columns.map((col: string) => (
                            <TableCell key={col} sx={{ fontSize: 10, fontWeight: 700, fontFamily: "monospace", py: 0.4, px: 1, bgcolor: isDark ? "#1e1e2e" : "#f5f5f5", whiteSpace: "nowrap" }}>
                              {col}
                            </TableCell>
                          ))}
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {rowData.rows.map((row: unknown[], ri: number) => (
                          <TableRow key={ri} hover>
                            {row.map((cell, ci) => (
                              <TableCell key={ci} sx={{ fontSize: 11, py: 0.3, px: 1, maxWidth: 200, whiteSpace: "nowrap" }}
                                title={cell === null ? "<null>" : String(cell)}>
                                {cell === null
                                  ? <Typography component="span" sx={{ fontSize: 11, color: "text.disabled", fontStyle: "italic" }}>&lt;null&gt;</Typography>
                                  : truncate(cell, 80)
                                }
                              </TableCell>
                            ))}
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </Box>
                  <TablePagination
                    component="div"
                    count={selectedTableInfo?.row_count ?? -1}
                    page={rowPage - 1}
                    rowsPerPage={50}
                    rowsPerPageOptions={[50]}
                    onPageChange={(_, p) => setRowPage(p + 1)}
                    sx={{ flexShrink: 0, fontSize: 11 }}
                  />
                </>
              )}</>
            </Box>

          </Box>
        )}
      </Box>
    </Box>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function DataModel() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const navigate = useNavigate();
  const { clientId } = useActiveClient();

  const [activeTab, setActiveTab] = useState<"graph" | "database">("graph");

  // Existing state
  const [listKey, setListKey]     = useState<string|null>(null);
  const [search, setSearch]       = useState("");
  const [anchor, setAnchor]       = useState<AnchorRecord|null>(null);
  const [expanded, setExpanded]   = useState<Set<string>>(new Set());
  const [connByKey, setConnByKey] = useState<Record<string, SubNode[]>>({});

  // Feature 4: hover preview
  const [hovered, setHovered]   = useState<string|null>(null);
  const [hoverPos, setHoverPos] = useState({x: 0, y: 0});

  // Feature 5: right-click context menu
  const [ctxMenu, setCtxMenu] = useState<{mouseX:number; mouseY:number; entity:string}|null>(null);

  // Feature 6: path finder
  const [pathStart, setPathStart]         = useState<string|null>(null);
  const [pathNodes, setPathNodes]         = useState<Set<string>>(new Set());
  const [pathEdgeIdxs, setPathEdgeIdxs]   = useState<Set<number>>(new Set());

  const edgeCol  = isDark ? "#3a4250" : "#c3c9d4";
  const raisedBg = isDark ? "#141b25" : "#f2f4f8";
  const lineBdr  = isDark ? "#232b36" : "#e6e9ef";

  useEffect(() => { setSearch(""); }, [listKey]);

  // ── Queries ────────────────────────────────────────────────────────────────

  // Features 1+2: stats for edge weights and health rings
  const { data: statsData } = useQuery<Record<string, any> | null>({
    queryKey: ["dm-stats", clientId],
    queryFn: () => clientId ? dataModelApi.stats(clientId) : Promise.resolve(null),
    enabled: !!clientId,
    staleTime: 60_000,
  });

  const { data: listData, isLoading: listLoading } = useQuery({
    queryKey: ["dm-list", clientId, listKey, search],
    queryFn: () =>
      clientId && listKey
        ? dataModelApi.list(clientId, listKey, search || undefined)
        : Promise.resolve({ items: [] }),
    enabled: !!clientId && !!listKey && !anchor,
    staleTime: 30_000,
  });

  // Feature 4: preview data for hover tooltip (limit=3)
  const hoveredKey = hovered ? TO_KEY[hovered] : null;
  const { data: previewData } = useQuery({
    queryKey: ["dm-preview", clientId, hoveredKey],
    queryFn: () =>
      clientId && hoveredKey && LISTABLE.has(hoveredKey)
        ? dataModelApi.list(clientId, hoveredKey, undefined, 3)
        : Promise.resolve(null),
    enabled: !!clientId && !!hoveredKey && LISTABLE.has(hoveredKey ?? ""),
    staleTime: 60_000,
  });

  const { data: connData, isLoading: connLoading } = useQuery({
    queryKey: ["dm-conn", clientId, anchor?.entityKey, anchor?.id],
    queryFn: () =>
      clientId && anchor
        ? dataModelApi.connections(clientId, anchor.entityKey, anchor.id)
        : Promise.resolve(null),
    enabled: !!clientId && !!anchor,
    staleTime: 60_000,
  });

  useEffect(() => {
    if (!connData?.nodes) { setConnByKey({}); return; }
    const g: Record<string, SubNode[]> = {};
    for (const n of connData.nodes as SubNode[]) {
      if (!g[n.entity]) g[n.entity] = [];
      g[n.entity].push(n);
    }
    setConnByKey(g);
    setExpanded(new Set());
  }, [connData]);

  // ── Feature helpers ────────────────────────────────────────────────────────

  // Feature 1: compute edge stroke width from entity counts
  function edgeWeight(e: OEdge): number {
    if (!statsData) return 1.4;
    const fk = TO_KEY[e.from]; const tk = TO_KEY[e.to];
    if (!fk || !tk) return 1.2;
    const fc = statsData[fk] ? statsData[fk].total : 0;
    const tc = statsData[tk] ? statsData[tk].total : 0;
    if (!fc && !tc) return 1.2;
    const allTotals = Object.values(statsData).map((s: any) => s?.total ?? 0);
    const maxCount = Math.max(...allTotals, 1);
    const norm = Math.log1p(Math.min(fc || maxCount, tc || maxCount)) / Math.log1p(maxCount);
    return 1.4 + norm * 5;
  }

  // Feature 2: outer ring colour from stats breakdown
  function nodeHealthColor(entity: string): string | null {
    if (!statsData) return null;
    const key = TO_KEY[entity];
    if (!key || !statsData[key] || !statsData[key].total) return null;
    const bd = statsData[key].breakdown ?? {};
    if (key === "finding") {
      if ((bd.critical ?? 0) > 0) return "#ef4444";
      if ((bd.high ?? 0) > 0) return "#f97316";
      return "#22c55e";
    }
    if (key === "risk") {
      if ((bd.critical ?? bd.critical_risk ?? 0) > 0) return "#ef4444";
      if ((bd.high ?? bd.high_risk ?? 0) > 0) return "#f97316";
      return "#22c55e";
    }
    if (key === "remediation") {
      const openRem = (bd.open ?? 0) + (bd.in_progress ?? bd["in progress"] ?? 0);
      return openRem > 0 ? "#f59e0b" : "#22c55e";
    }
    if (key === "control") {
      return (bd.critical ?? 0) + (bd.high ?? 0) > 0 ? "#f97316" : "#22c55e";
    }
    if (key === "technique") {
      return (bd.critical ?? 0) + (bd.high ?? 0) > 0 ? "#ef4444" : "#f59e0b";
    }
    return statsData[key].total > 0 ? "#22c55e" : null;
  }

  // ── Handlers ───────────────────────────────────────────────────────────────

  function handleNodeClick(entityName: string, e: React.MouseEvent) {
    // Feature 6: shift+click activates path finder
    if (e.shiftKey) {
      e.stopPropagation();
      if (!pathStart) {
        setPathStart(entityName);
        setPathNodes(new Set([entityName]));
        setPathEdgeIdxs(new Set());
      } else if (pathStart === entityName) {
        setPathStart(null); setPathNodes(new Set()); setPathEdgeIdxs(new Set());
      } else {
        const result = findPath(pathStart, entityName);
        setPathNodes(result.nodes); setPathEdgeIdxs(result.edges);
        setPathStart(null);
      }
      return;
    }

    const key = TO_KEY[entityName];
    if (!anchor) {
      if (LISTABLE.has(key)) setListKey(k => k === key ? null : key);
      return;
    }
    if (key && key === anchor.entityKey) { clearAll(); return; }
    const subnodes = connByKey[key] ?? [];
    if (!key || !subnodes.length) return;
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(entityName) ? next.delete(entityName) : next.add(entityName);
      return next;
    });
  }

  // Feature 5: right-click handler
  function handleNodeRightClick(entityName: string, e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    setCtxMenu({mouseX: e.clientX, mouseY: e.clientY, entity: entityName});
  }

  function handleSelectRecord(item: {id:string; label:string; detail?:string}) {
    if (!listKey) return;
    setAnchor({id: item.id, label: item.label, entityKey: listKey, detail: item.detail});
    setListKey(null);
  }

  function handleSubNodeClick(sn: SubNode, e: React.MouseEvent) {
    e.stopPropagation();
    setAnchor({id: sn.id, label: sn.label, entityKey: sn.entity, detail: sn.detail});
    setExpanded(new Set());
    setConnByKey({});
  }

  function clearAll() {
    setAnchor(null); setExpanded(new Set()); setConnByKey({}); setListKey(null);
    setPathStart(null); setPathNodes(new Set()); setPathEdgeIdxs(new Set());
  }

  // Feature 5: export CSV from list data
  function handleExportCSV(entity: string) {
    const key = TO_KEY[entity];
    if (!key || !clientId || !LISTABLE.has(key)) return;
    dataModelApi.list(clientId, key, undefined, 1000).then((data: any) => {
      const items: any[] = data?.items ?? [];
      const csv = ["id,label,detail",
        ...items.map(i => `${i.id},"${String(i.label||"").replace(/"/g,'""')}","${String(i.detail||"").replace(/"/g,'""')}"`)
      ].join("\n");
      const url = URL.createObjectURL(new Blob([csv], {type:"text/csv"}));
      const a = document.createElement("a");
      a.href = url; a.download = `${key}_export.csv`; a.click();
      URL.revokeObjectURL(url);
    });
  }

  // ── SVG layer helpers ──────────────────────────────────────────────────────

  function SubLayer({n}: {n: ONode}) {
    if (!expanded.has(n.entity)) return null;
    const key = TO_KEY[n.entity];
    if (!key) return null;
    const all = connByKey[key] ?? [];
    const vis = all.slice(0, MAX_VIS);
    const extra = all.length - MAX_VIS;
    const totalPos = vis.length + (extra > 0 ? 1 : 0);
    const pos = subPositions(n.cx, n.cy, totalPos);

    return (
      <g>
        {pos.map((p, i) => (
          <path key={`e${i}`}
            d={`M ${n.cx} ${n.cy} Q ${(n.cx+p.x)/2} ${(n.cy+p.y)/2 - 14} ${p.x} ${p.y}`}
            fill="none" stroke={n.color} strokeWidth={1.5} strokeOpacity={0.5} strokeLinecap="round"
          />
        ))}
        {vis.map((sn, i) => {
          const p = pos[i];
          const sc = sn.severity ? SEV_COLOR[sn.severity] : undefined;
          return (
            <g key={sn.id} style={{cursor:"pointer"}} onClick={ev => handleSubNodeClick(sn, ev)}>
              {sc && <circle cx={p.x} cy={p.y} r={22} fill="none" stroke={sc} strokeWidth={2} opacity={0.6}/>}
              <circle cx={p.x} cy={p.y} r={17} fill={isDark?"#1a2232":"#fff"} stroke={n.color} strokeWidth={2}/>
              <text x={p.x} y={p.y} textAnchor="middle" dominantBaseline="middle"
                fontSize={10} fontWeight={700} fill={n.color}>{ENT_ICON[sn.entity]??"●"}</text>
              <text x={p.x} y={p.y+28} textAnchor="middle" fontSize={8} fill={isDark?"#9ca3af":"#4b5563"}>
                {sn.label.length>14 ? sn.label.slice(0,12)+"…" : sn.label}
              </text>
            </g>
          );
        })}
        {extra > 0 && (() => {
          const p = pos[pos.length-1];
          return (
            <g key="more">
              <circle cx={p.x} cy={p.y} r={17} fill={alpha(n.color, 0.1)} stroke={n.color} strokeWidth={1.5} strokeDasharray="3 2"/>
              <text x={p.x} y={p.y} textAnchor="middle" dominantBaseline="middle"
                fontSize={9} fontWeight={700} fill={n.color}>+{extra}</text>
            </g>
          );
        })()}
      </g>
    );
  }

  function OntNode({n}: {n: ONode}) {
    const key = TO_KEY[n.entity];
    const isAnchorEnt = !!anchor && !!key && key === anchor.entityKey;
    const isListEnt   = !anchor && listKey === key && !!key;
    const isExp       = expanded.has(n.entity);
    const hasConn     = !!key && (connByKey[key]?.length ?? 0) > 0;
    const clickable   = !!key && (LISTABLE.has(key) || !!anchor);
    const dim         = !!anchor && !isAnchorEnt && !hasConn;
    const inPath      = pathNodes.has(n.entity);
    const isPathStart = pathStart === n.entity;
    const healthColor = nodeHealthColor(n.entity);

    const r  = isAnchorEnt ? 14 : isExp ? 12 : 9;
    const sw = isListEnt ? 2.5 : isExp ? 2.5 : 1.8;

    return (
      <g
        style={{
          cursor: (clickable || inPath || isPathStart) ? "pointer" : "default",
          opacity: (dim && !inPath) ? 0.22 : 1,
          transition: "opacity 0.2s",
        }}
        onClick={e => handleNodeClick(n.entity, e)}
        onContextMenu={e => handleNodeRightClick(n.entity, e)}
        onMouseEnter={e => { setHovered(n.entity); setHoverPos({x: e.clientX, y: e.clientY}); }}
        onMouseLeave={() => setHovered(null)}
        onMouseMove={e => setHoverPos({x: e.clientX, y: e.clientY})}
      >
        {/* Feature 2: health ring */}
        {healthColor && (
          <circle cx={n.cx} cy={n.cy} r={r+13} fill="none"
            stroke={healthColor} strokeWidth={2.5} opacity={0.5}
            style={{transition:"all 0.2s"}}/>
        )}
        {/* Feature 6: path highlight ring */}
        {inPath && (
          <circle cx={n.cx} cy={n.cy} r={r+9} fill={alpha("#eab308", 0.15)}
            stroke="#eab308" strokeWidth={2} opacity={0.9}/>
        )}
        {/* Path start waiting indicator */}
        {isPathStart && (
          <circle cx={n.cx} cy={n.cy} r={r+9} fill="none"
            stroke="#eab308" strokeWidth={2} strokeDasharray="4 2" opacity={0.9}/>
        )}
        {/* Halo */}
        {(hasConn || isAnchorEnt) && (
          <circle cx={n.cx} cy={n.cy} r={r+7} fill="none" stroke={n.color}
            strokeWidth={1} opacity={isAnchorEnt?0.45:0.2}/>
        )}
        {/* List selection dashed ring */}
        {isListEnt && (
          <circle cx={n.cx} cy={n.cy} r={r+5} fill="none" stroke="#4338ca"
            strokeWidth={1.5} strokeDasharray="4 2" opacity={0.6}/>
        )}
        {/* Main circle */}
        <circle cx={n.cx} cy={n.cy} r={r}
          fill={isAnchorEnt ? n.color : inPath ? alpha("#eab308", isDark?0.2:0.12) : raisedBg}
          stroke={inPath ? "#eab308" : n.color}
          strokeWidth={inPath ? 2.5 : sw}
          style={{transition:"r 0.18s, fill 0.18s"}}/>
        {/* Count badge from stats */}
        {!isAnchorEnt && statsData && key && statsData[key]?.total > 0 && (
          <text x={n.cx} y={n.cy} textAnchor="middle" dominantBaseline="middle"
            fontFamily="monospace" fontSize={statsData[key].total > 99 ? 7 : 9}
            fontWeight={700} fill={inPath ? "#eab308" : n.color}>
            {statsData[key].total > 999 ? "999+" : statsData[key].total}
          </text>
        )}
        {/* Anchor star */}
        {isAnchorEnt && (
          <text x={n.cx} y={n.cy} textAnchor="middle" dominantBaseline="middle"
            fontSize={10} fill="#fff" fontWeight={700}>✦</text>
        )}
        {/* Label pill */}
        <rect x={n.labelX} y={n.cy+14} width={n.labelW} height={20} rx={10}
          fill={isAnchorEnt||isExp ? n.color : inPath ? alpha("#eab308", isDark?0.25:0.12) : raisedBg}
          stroke={isAnchorEnt||isExp ? n.color : inPath ? "#eab308" : lineBdr}
          strokeWidth={1}
          style={{transition:"fill 0.18s"}}/>
        <text x={n.cx} y={n.cy+27} textAnchor="middle" dominantBaseline="middle"
          fontFamily="monospace" fontSize={10}
          fontWeight={isAnchorEnt||isExp||inPath?700:500}
          fill={isAnchorEnt||isExp?"#fff":inPath?"#eab308":theme.palette.text.primary}
          style={{transition:"fill 0.18s"}}>
          {n.label}
        </text>
        {isAnchorEnt && anchor && (
          <text x={n.cx} y={n.cy+44} textAnchor="middle" fontSize={8.5}
            fill={n.color} fontWeight={500}>
            {anchor.label.length>16 ? anchor.label.slice(0,14)+"…" : anchor.label}
          </text>
        )}
      </g>
    );
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  const showList   = !anchor && !!listKey;
  const showAnchor = !!anchor;
  const showPanel  = showList || showAnchor;
  const anchorColor = ONT_NODES.find(n => TO_KEY[n.entity] === anchor?.entityKey)?.color ?? "#6b7280";

  // Feature 3: blast radius — downstream types and gap detection
  const blastTypes = Object.entries(connByKey).map(([ent, nodes]) => ({
    ent, count: nodes.length,
    color: ONT_NODES.find(n => TO_KEY[n.entity] === ent)?.color ?? "#6b7280",
  }));
  const expectedDown = anchor ? (EXPECTED_DOWNSTREAM[anchor.entityKey] ?? []) : [];
  const missingTypes = expectedDown.filter(t => !connByKey[t]?.length);

  return (
    <Box sx={{display:"flex", flexDirection:"column", gap:2.5}}>

      {/* Header */}
      <Box sx={{display:"flex", alignItems:"flex-start", justifyContent:"space-between", flexWrap:"wrap", gap:1}}>
        <Box>
          <Typography variant="h5" sx={{fontWeight:700, mb:0.25}}>Data Model</Typography>
          <Typography sx={{fontSize:13, color:"text.secondary"}}>
            {pathStart
              ? `Shift-click another node to trace path from "${pathStart}" · Shift-click same to cancel`
              : !anchor
                ? "Click a node to select a record as anchor · Shift+click two nodes to trace a path"
                : `Anchor: ${anchor.label} · Click highlighted nodes to sprout connections`}
          </Typography>
        </Box>
        <Box sx={{display:"flex", gap:1, alignItems:"center"}}>
          {(pathNodes.size > 0 || pathStart) && (
            <Chip
              label={pathNodes.size > 0 ? Array.from(pathNodes).join(" → ") : `From: ${pathStart}`}
              size="small"
              onDelete={() => { setPathStart(null); setPathNodes(new Set()); setPathEdgeIdxs(new Set()); }}
              sx={{
                bgcolor: alpha("#eab308", 0.15), color:"#eab308", fontSize:11, maxWidth:300,
                "& .MuiChip-deleteIcon": {color:"#eab308"},
              }}
            />
          )}
          {anchor && (
            <IconButton size="small" onClick={clearAll} title="Clear anchor">
              <Close fontSize="small"/>
            </IconButton>
          )}
        </Box>
      </Box>

      {/* Tab bar */}
      <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} sx={{ borderBottom: "1px solid", borderColor: "divider", minHeight: 38 }}>
        <Tab value="graph" label="Ontology Graph" sx={{ fontSize: 12, minHeight: 38, textTransform: "none" }} />
        <Tab value="database" label="Database Browser" icon={<Storage sx={{ fontSize: 14 }} />} iconPosition="start"
          sx={{ fontSize: 12, minHeight: 38, textTransform: "none" }} />
      </Tabs>

      {activeTab === "database" && <DatabaseBrowser />}

      {activeTab === "graph" && <>
      <Box sx={{display:"flex", gap:2, alignItems:"flex-start"}}>

        {/* ── Graph ── */}
        <Box sx={{
          flex:1, minWidth:0, position:"relative",
          bgcolor:"background.paper",
          border:"1px solid", borderColor:"divider",
          borderRadius:2, p:2, overflowX:"auto",
        }}>
          {connLoading && (
            <Box sx={{display:"flex", alignItems:"center", gap:1, mb:1}}>
              <CircularProgress size={13}/>
              <Typography sx={{fontSize:11, color:"text.secondary"}}>Loading connections…</Typography>
            </Box>
          )}

          <svg viewBox="0 0 1120 660" style={{width:"100%", minWidth:520, height:"auto", display:"block"}}>
            <defs>
              <marker id="dm-arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill={edgeCol}/>
              </marker>
              <marker id="dm-arr-lit" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill="#4338ca"/>
              </marker>
              <marker id="dm-arr-path" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill="#eab308"/>
              </marker>
            </defs>

            {/* Layer 1 — base edges (Feature 1: weight + Feature 6: path) */}
            <g>
              {ONT_EDGES.map((e, i) => {
                const litFrom = TO_KEY[e.from] === anchor?.entityKey;
                const litTo   = TO_KEY[e.to]   === anchor?.entityKey;
                const lit     = litFrom || litTo;
                const inPath  = pathEdgeIdxs.has(i);
                const w       = edgeWeight(e);
                return (
                  <line key={i} x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2}
                    stroke={inPath ? "#eab308" : lit ? "#4338ca" : edgeCol}
                    strokeWidth={inPath ? 3.5 : lit ? 2.5 : w}
                    opacity={anchor && !lit && !inPath ? 0.15 : 1}
                    strokeDasharray={e.dashed ? "3 4" : undefined}
                    markerEnd={inPath ? "url(#dm-arr-path)" : lit ? "url(#dm-arr-lit)" : "url(#dm-arr)"}
                    style={{transition:"stroke 0.2s, stroke-width 0.3s, opacity 0.2s"}}
                  />
                );
              })}
            </g>

            {/* Layer 2 — sprouted sub-nodes */}
            <g>
              {ONT_NODES.map(n => <SubLayer key={`sl-${n.entity}`} n={n}/>)}
            </g>

            {/* Layer 3 — entity type nodes */}
            <g>
              {ONT_NODES.map(n => <OntNode key={n.entity} n={n}/>)}
            </g>
          </svg>

          {/* Legend */}
          <Box sx={{display:"flex", flexWrap:"wrap", gap:2, mt:1.5, pt:1.5, borderTop:"1px solid", borderColor:"divider", alignItems:"center"}}>
            {[
              "●  click node to select record",
              "✦  anchor · click connected nodes to sprout",
              "⬤  health ring: red critical / amber high / green ok",
              "━  edge weight = connection density",
              "gold highlight  shift+click path finder",
              "right-click  actions menu",
            ].map(txt => (
              <Typography key={txt} sx={{fontSize:10, color:"text.disabled"}}>{txt}</Typography>
            ))}
          </Box>
        </Box>

        {/* ── Right panel ── */}
        {showPanel && (
          <Box sx={{
            width:270, flexShrink:0,
            border:"1px solid", borderColor:"divider",
            borderRadius:2, bgcolor:"background.paper",
            display:"flex", flexDirection:"column",
            maxHeight:640, overflow:"hidden",
          }}>

            {/* LIST PANEL */}
            {showList && (
              <>
                <Box sx={{p:1.5, borderBottom:"1px solid", borderColor:"divider",
                  display:"flex", alignItems:"center", justifyContent:"space-between"}}>
                  <Box sx={{display:"flex", alignItems:"center", gap:1}}>
                    <Box sx={{width:8, height:8, borderRadius:"50%",
                      bgcolor: ONT_NODES.find(n=>TO_KEY[n.entity]===listKey)?.color ?? "#6b7280"}}/>
                    <Typography sx={{fontSize:13, fontWeight:700, textTransform:"capitalize"}}>
                      Select {listKey}
                    </Typography>
                  </Box>
                  <IconButton size="small" onClick={() => setListKey(null)}><Close fontSize="small"/></IconButton>
                </Box>
                <Box sx={{p:1.25}}>
                  <TextField size="small" fullWidth placeholder="Search…"
                    value={search} onChange={e => setSearch(e.target.value)}
                    slotProps={{input:{startAdornment:
                      <InputAdornment position="start"><Search sx={{fontSize:15}}/></InputAdornment>
                    }}}
                    sx={{"& .MuiInputBase-root":{fontSize:12}}}
                  />
                </Box>
                <Box sx={{flex:1, overflow:"auto"}}>
                  {listLoading
                    ? <Box sx={{display:"flex",justifyContent:"center",py:3}}><CircularProgress size={20}/></Box>
                    : (listData?.items ?? []).length === 0
                      ? <Typography sx={{fontSize:12, color:"text.disabled", textAlign:"center", py:3}}>No records found</Typography>
                      : <List dense disablePadding>
                          {(listData?.items ?? []).map((item: {id:string; label:string; detail?:string}) => (
                            <ListItemButton key={item.id} onClick={() => handleSelectRecord(item)} sx={{py:0.75, px:1.5}}>
                              <ListItemText
                                primary={<Typography sx={{fontSize:12, fontWeight:500, lineHeight:1.3}}>{item.label}</Typography>}
                                secondary={item.detail
                                  ? <Typography sx={{fontSize:10, color:"text.disabled"}}>{item.detail}</Typography>
                                  : undefined}
                              />
                            </ListItemButton>
                          ))}
                        </List>
                  }
                </Box>
              </>
            )}

            {/* ANCHOR PANEL */}
            {showAnchor && (
              <>
                <Box sx={{p:1.5, borderBottom:"1px solid", borderColor:"divider"}}>
                  <Box sx={{display:"flex", alignItems:"center", justifyContent:"space-between", mb:0.75}}>
                    <Chip label={anchor!.entityKey} size="small" sx={{
                      fontSize:10, height:18, textTransform:"capitalize",
                      bgcolor: alpha(anchorColor, 0.12), color: anchorColor,
                    }}/>
                    <IconButton size="small" onClick={clearAll}><Close fontSize="small"/></IconButton>
                  </Box>
                  <Typography sx={{fontSize:13, fontWeight:700, lineHeight:1.3}}>{anchor!.label}</Typography>
                  {anchor!.detail && (
                    <Typography sx={{fontSize:11, color:"text.secondary", mt:0.25}}>{anchor!.detail}</Typography>
                  )}
                </Box>

                {/* Feature 3: Blast radius summary */}
                {(blastTypes.length > 0 || connLoading) && (
                  <Box sx={{px:1.5, py:1, borderBottom:"1px solid", borderColor:"divider"}}>
                    <Typography sx={{
                      fontSize:10, color:"text.secondary", mb:0.75,
                      textTransform:"uppercase", letterSpacing:"0.05em", fontWeight:600,
                    }}>
                      Blast Radius
                    </Typography>
                    {connLoading
                      ? <CircularProgress size={14}/>
                      : (
                        <Box sx={{display:"flex", flexWrap:"wrap", gap:0.5}}>
                          {blastTypes.map(({ent, color, count}) => (
                            <Box key={ent} sx={{
                              display:"flex", alignItems:"center", gap:0.4,
                              px:0.9, py:0.25, borderRadius:"12px",
                              bgcolor: alpha(color, 0.1), border:"1px solid", borderColor: alpha(color, 0.25),
                            }}>
                              <ArrowForward sx={{fontSize:9, color}}/>
                              <Typography sx={{fontSize:10, color, fontWeight:700}}>{count}</Typography>
                              <Typography sx={{fontSize:10, color:"text.secondary"}}>{ent}</Typography>
                            </Box>
                          ))}
                          {missingTypes.map(ent => (
                            <Box key={`gap-${ent}`} sx={{
                              display:"flex", alignItems:"center", gap:0.4,
                              px:0.9, py:0.25, borderRadius:"12px",
                              bgcolor: alpha("#6b7280", 0.06), border:"1px solid", borderColor: alpha("#6b7280", 0.2),
                            }}>
                              <WarningAmber sx={{fontSize:9, color:"text.disabled"}}/>
                              <Typography sx={{fontSize:10, color:"text.disabled"}}>0 {ent}</Typography>
                            </Box>
                          ))}
                        </Box>
                      )
                    }
                  </Box>
                )}

                <Box sx={{p:1.5, flex:1, overflow:"auto"}}>
                  <Typography sx={{
                    fontSize:10, color:"text.secondary", mb:1,
                    textTransform:"uppercase", letterSpacing:"0.05em",
                  }}>
                    Connections
                  </Typography>

                  {connLoading && <CircularProgress size={16}/>}

                  {!connLoading && Object.keys(connByKey).length === 0 && (
                    <Typography sx={{fontSize:12, color:"text.disabled"}}>No connections found</Typography>
                  )}

                  {Object.entries(connByKey).map(([ent, nodes]) => {
                    const color = ONT_NODES.find(n => TO_KEY[n.entity] === ent)?.color ?? "#6b7280";
                    const primName = KEY_TO_NODE[ent];
                    const isExp = primName ? expanded.has(primName) : false;
                    return (
                      <Box key={ent}
                        onClick={() => { if (primName) handleNodeClick(primName, {shiftKey:false} as React.MouseEvent); }}
                        sx={{
                          display:"flex", alignItems:"center", justifyContent:"space-between",
                          py:0.75, px:1, mb:0.5, borderRadius:1, cursor:"pointer",
                          bgcolor: isExp ? alpha(color, 0.1) : "action.hover",
                          "&:hover": {bgcolor: alpha(color, 0.14)},
                          border:"1px solid", borderColor: isExp ? alpha(color, 0.35) : "transparent",
                        }}
                      >
                        <Box sx={{display:"flex", alignItems:"center", gap:1}}>
                          <Box sx={{width:8, height:8, borderRadius:"50%", bgcolor:color}}/>
                          <Typography sx={{fontSize:12, textTransform:"capitalize"}}>{ent}</Typography>
                        </Box>
                        <Box sx={{display:"flex", alignItems:"center", gap:0.75}}>
                          <Typography sx={{fontSize:12, fontWeight:700}}>{nodes.length}</Typography>
                          <Typography sx={{fontSize:10, color:"text.secondary"}}>{isExp?"▾":"▸"}</Typography>
                        </Box>
                      </Box>
                    );
                  })}

                  <Typography sx={{fontSize:10, color:"text.disabled", mt:2, lineHeight:1.6}}>
                    Click a row (or graph node) to sprout records. Click a sub-node to pivot.
                  </Typography>
                </Box>
              </>
            )}
          </Box>
        )}
      </Box>

      {/* Feature 4: Hover preview tooltip */}
      {hovered && (
        <Box sx={{
          position:"fixed",
          top: hoverPos.y + 14,
          left: hoverPos.x + 14,
          zIndex: 2000,
          bgcolor:"background.paper",
          border:"1px solid", borderColor:"divider",
          borderRadius:2, p:1.5, width:210,
          boxShadow: isDark ? "0 8px 24px rgba(0,0,0,0.5)" : "0 4px 16px rgba(0,0,0,0.12)",
          pointerEvents:"none",
        }}>
          {(() => {
            const n = ONT_NODES.find(x => x.entity === hovered);
            const key = TO_KEY[hovered];
            const stat = key && statsData ? statsData[key] : null;
            const health = nodeHealthColor(hovered);
            const preview: any[] = (previewData as any)?.items ?? [];
            return (
              <>
                <Box sx={{display:"flex", alignItems:"center", gap:1, mb:1}}>
                  <Box sx={{width:10, height:10, borderRadius:"50%", bgcolor: n?.color ?? "#6b7280",
                    ...(health ? {boxShadow: `0 0 0 2px ${health}`} : {})}}/>
                  <Typography sx={{fontSize:12, fontWeight:700}}>{hovered}</Typography>
                  {stat && (
                    <Typography sx={{fontSize:12, fontWeight:700, color: n?.color ?? "text.primary", ml:"auto"}}>
                      {stat.total}
                    </Typography>
                  )}
                </Box>
                {stat && Object.entries(stat.breakdown ?? {})
                  .filter(([,v]) => (v as number) > 0)
                  .slice(0,3)
                  .map(([k,v]) => (
                    <Box key={k} sx={{display:"flex", justifyContent:"space-between", mb:0.25}}>
                      <Typography sx={{fontSize:10, color:"text.secondary", textTransform:"capitalize"}}>{k}</Typography>
                      <Typography sx={{fontSize:10, fontWeight:600}}>{String(v)}</Typography>
                    </Box>
                  ))
                }
                {preview.length > 0 && (
                  <>
                    <Divider sx={{my:0.75}}/>
                    {preview.map((item: any) => (
                      <Typography key={item.id} sx={{
                        fontSize:10, color:"text.secondary", lineHeight:1.5,
                        overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap",
                      }}>
                        · {item.label}
                      </Typography>
                    ))}
                  </>
                )}
                <Typography sx={{fontSize:9, color:"text.disabled", mt:0.75}}>
                  Right-click for actions · Shift+click to trace path
                </Typography>
              </>
            );
          })()}
        </Box>
      )}

      {/* Feature 5: Right-click context menu */}
      <Menu
        open={!!ctxMenu}
        onClose={() => setCtxMenu(null)}
        anchorReference="anchorPosition"
        anchorPosition={ctxMenu ? {top: ctxMenu.mouseY, left: ctxMenu.mouseX} : undefined}
        slotProps={{paper:{sx:{minWidth:200}}}}
      >
        {ctxMenu && ONT_ROUTES[ctxMenu.entity] && (
          <MenuItem dense onClick={() => { navigate(ONT_ROUTES[ctxMenu!.entity]); setCtxMenu(null); }}>
            <ListItemIcon><OpenInNew fontSize="small"/></ListItemIcon>
            <Typography sx={{fontSize:13}}>View all {ctxMenu.entity}s</Typography>
          </MenuItem>
        )}
        {ctxMenu && AGENT_NODES.has(ctxMenu.entity) && (
          <MenuItem dense onClick={() => { navigate("/ai-advisor"); setCtxMenu(null); }}>
            <ListItemIcon><SmartToy fontSize="small"/></ListItemIcon>
            <Typography sx={{fontSize:13}}>Run AI Agent</Typography>
          </MenuItem>
        )}
        {ctxMenu && TO_KEY[ctxMenu.entity] && LISTABLE.has(TO_KEY[ctxMenu.entity]) && [
          <Divider key="d"/>,
          <MenuItem key="csv" dense onClick={() => { handleExportCSV(ctxMenu!.entity); setCtxMenu(null); }}>
            <ListItemIcon><Download fontSize="small"/></ListItemIcon>
            <Typography sx={{fontSize:13}}>Export CSV</Typography>
          </MenuItem>,
        ]}
      </Menu>
      </>}

    </Box>
  );
}
