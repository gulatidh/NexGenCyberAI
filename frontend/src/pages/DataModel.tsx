/**
 * /data-model — Relationship Explorer
 *
 * Entity type tabs → search / pick a record → radial spider graph
 * showing all connected entities fanning out from the anchor node.
 */
import { useState, useRef, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Tabs, Tab, TextField, InputAdornment,
  List, ListItemButton, ListItemText, Chip, CircularProgress,
  Paper, Divider, alpha, useTheme, IconButton, Tooltip,
} from "@mui/material";
import {
  Search, Computer, BugReport, Warning, Build,
  Policy, Security, Description, Close, OpenInNew,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { dataModelApi } from "../services/api";
import { useActiveClient } from "../contexts/ClientContext";

// ── Types ─────────────────────────────────────────────────────────────────────

interface GraphNode {
  id: string;
  entity: string;
  label: string;
  detail?: string;
  icon?: string;
  severity?: string | null;
  // layout — computed client-side
  x?: number;
  y?: number;
  isAnchor?: boolean;
}

interface GraphEdge {
  source: string;
  target: string;
  label?: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ENTITY_TYPES = [
  { key: "asset",       label: "Asset",       Icon: Computer,     color: "#2563eb" },
  { key: "finding",     label: "Finding",     Icon: BugReport,    color: "#b91c1c" },
  { key: "risk",        label: "Risk",        Icon: Warning,      color: "#b45309" },
  { key: "remediation", label: "Remediation", Icon: Build,        color: "#15803d" },
];

const ENTITY_ICON_MAP: Record<string, React.ElementType> = {
  asset: Computer, finding: BugReport, risk: Warning,
  remediation: Build, control: Policy, technique: Security,
  report: Description,
};

const ENTITY_COLOR: Record<string, string> = {
  asset: "#2563eb", finding: "#b91c1c", risk: "#b45309",
  remediation: "#15803d", control: "#7c3aed", technique: "#b91c1c",
  report: "#0f766e",
};

const SEV_RING: Record<string, string> = {
  critical: "#b91c1c", high: "#ea580c", medium: "#d97706",
  low: "#16a34a", info: "#0284c7",
};

// ── Radial layout ─────────────────────────────────────────────────────────────

const CX = 420; // graph centre
const CY = 340;
const R1 = 180; // inner ring radius
const R2 = 280; // outer ring (for overflow)

function layoutNodes(anchor: GraphNode, relatedNodes: GraphNode[]): GraphNode[] {
  const placed: GraphNode[] = [{ ...anchor, x: CX, y: CY, isAnchor: true }];
  const total = relatedNodes.length;
  if (total === 0) return placed;

  // Group by entity type for nicer clustering
  const groups: Record<string, GraphNode[]> = {};
  for (const n of relatedNodes) {
    if (!groups[n.entity]) groups[n.entity] = [];
    groups[n.entity].push(n);
  }

  let angleOffset = -Math.PI / 2; // start at top
  const groupKeys = Object.keys(groups);
  const totalAngle = 2 * Math.PI;
  const anglePer = totalAngle / Math.max(total, 1);

  let idx = 0;
  for (const gk of groupKeys) {
    const grp = groups[gk];
    for (let i = 0; i < grp.length; i++) {
      const angle = angleOffset + idx * anglePer;
      const r = idx < 14 ? R1 : R2;
      placed.push({
        ...grp[i],
        x: CX + r * Math.cos(angle),
        y: CY + r * Math.sin(angle),
        isAnchor: false,
      });
      idx++;
    }
  }
  return placed;
}

// ── Cubic bezier path from anchor to satellite ────────────────────────────────

function bezierPath(x1: number, y1: number, x2: number, y2: number): string {
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;
  const dx = x2 - x1;
  const dy = y2 - y1;
  const cx1 = mx - dy * 0.25;
  const cy1 = my + dx * 0.25;
  return `M ${x1} ${y1} Q ${cx1} ${cy1} ${x2} ${y2}`;
}

// ── Node icon renderer (SVG foreignObject) ────────────────────────────────────

function NodeCircle({
  node, selected, onSelect,
}: {
  node: GraphNode;
  selected: boolean;
  onSelect: (n: GraphNode) => void;
}) {
  const r = node.isAnchor ? 36 : 26;
  const color = ENTITY_COLOR[node.entity] ?? "#6b7280";
  const ringColor = node.severity ? SEV_RING[node.severity] ?? color : color;
  const bg = node.isAnchor ? color : selected ? alpha(color, 0.15) : "white";
  const stroke = node.isAnchor ? "none" : ringColor;

  return (
    <g
      transform={`translate(${node.x},${node.y})`}
      style={{ cursor: "pointer" }}
      onClick={() => onSelect(node)}
    >
      {/* Glow ring on selected */}
      {selected && !node.isAnchor && (
        <circle r={r + 6} fill="none" stroke={color} strokeWidth={2} opacity={0.4} />
      )}
      {/* Severity outer ring */}
      {node.severity && !node.isAnchor && (
        <circle r={r + 3} fill="none" stroke={ringColor} strokeWidth={2.5} />
      )}
      <circle r={r} fill={bg} stroke={stroke} strokeWidth={node.isAnchor ? 0 : 2} />
      {/* Icon — use text emoji-style hack with a simple letter fallback */}
      <text
        textAnchor="middle" dominantBaseline="middle"
        fontSize={node.isAnchor ? 18 : 14}
        fontWeight={700}
        fill={node.isAnchor ? "white" : color}
      >
        {node.entity === "asset" ? "⬡" :
         node.entity === "finding" ? "⚠" :
         node.entity === "risk" ? "◈" :
         node.entity === "remediation" ? "⚙" :
         node.entity === "control" ? "⬟" :
         node.entity === "technique" ? "⬡" :
         node.entity === "report" ? "▤" : "●"}
      </text>
      {/* Label */}
      <text
        y={r + 16}
        textAnchor="middle"
        fontSize={node.isAnchor ? 12 : 10}
        fontWeight={node.isAnchor ? 700 : 500}
        fill={node.isAnchor ? color : "#374151"}
      >
        {node.label.length > 20 ? node.label.slice(0, 18) + "…" : node.label}
      </text>
      {node.detail && !node.isAnchor && (
        <text y={r + 28} textAnchor="middle" fontSize={9} fill="#9ca3af">
          {node.detail.length > 16 ? node.detail.slice(0, 14) + "…" : node.detail}
        </text>
      )}
    </g>
  );
}

// ── Detail side panel ─────────────────────────────────────────────────────────

function NodeDetail({
  node, onClose,
}: {
  node: GraphNode;
  onClose: () => void;
}) {
  const navigate = useNavigate();
  const color = ENTITY_COLOR[node.entity] ?? "#6b7280";
  const Icon = ENTITY_ICON_MAP[node.entity] ?? Security;

  const routeMap: Record<string, string> = {
    asset: "platform/assets",
    finding: "vulnerability/findings",
    risk: "risk/register",
    remediation: "governance/remediation",
    control: "compliance/deficiencies",
    technique: "threat-intel/register",
    report: "vapt/reports",
  };

  return (
    <Paper elevation={0} sx={{
      width: 280, flexShrink: 0,
      border: "1px solid", borderColor: "divider",
      borderRadius: 2, p: 2,
      display: "flex", flexDirection: "column", gap: 1.5,
    }}>
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <Icon sx={{ color, fontSize: 20 }} />
          <Typography sx={{ fontWeight: 700, fontSize: 13, textTransform: "capitalize", color }}>
            {node.entity}
          </Typography>
        </Box>
        <IconButton size="small" onClick={onClose}><Close fontSize="small" /></IconButton>
      </Box>

      <Divider />

      <Box>
        <Typography sx={{ fontSize: 14, fontWeight: 600, lineHeight: 1.4, mb: 0.5 }}>
          {node.label}
        </Typography>
        {node.detail && (
          <Typography sx={{ fontSize: 12, color: "text.secondary" }}>{node.detail}</Typography>
        )}
        {node.severity && (
          <Chip label={node.severity} size="small" sx={{
            mt: 1, fontSize: 11, height: 20,
            bgcolor: alpha(SEV_RING[node.severity] ?? color, 0.12),
            color: SEV_RING[node.severity] ?? color,
            fontWeight: 600,
          }} />
        )}
      </Box>

      <Divider />

      <Box
        sx={{ display: "flex", alignItems: "center", gap: 0.5, cursor: "pointer", color: "primary.main", fontSize: 12 }}
        onClick={() => navigate(`/${routeMap[node.entity] ?? ""}`)}
      >
        <OpenInNew sx={{ fontSize: 14 }} />
        View in {node.entity} module
      </Box>
    </Paper>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DataModel() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const { clientId } = useActiveClient();

  const [tab, setTab] = useState(0);
  const [search, setSearch] = useState("");
  const [selectedRecord, setSelectedRecord] = useState<{ id: string; label: string } | null>(null);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [clickedNode, setClickedNode] = useState<GraphNode | null>(null);

  const entityType = ENTITY_TYPES[tab].key;

  // Search picker
  const { data: listData, isLoading: listLoading } = useQuery({
    queryKey: ["dm-list", clientId, entityType, search],
    queryFn: () => clientId ? dataModelApi.list(clientId, entityType, search || undefined) : Promise.resolve({ items: [] }),
    enabled: !!clientId,
    staleTime: 30_000,
  });

  // Connection graph
  const { data: connData, isLoading: connLoading } = useQuery({
    queryKey: ["dm-connections", clientId, entityType, selectedRecord?.id],
    queryFn: () =>
      clientId && selectedRecord
        ? dataModelApi.connections(clientId, entityType, selectedRecord.id)
        : Promise.resolve(null),
    enabled: !!clientId && !!selectedRecord,
    staleTime: 30_000,
  });

  // Layout nodes
  const layoutedNodes: GraphNode[] = connData?.anchor
    ? layoutNodes(connData.anchor, connData.nodes ?? [])
    : [];

  const edgeColor = isDark ? "#f97316" : "#ea580c"; // Sentinel-style orange

  const panelNode = clickedNode && !clickedNode.isAnchor ? clickedNode : null;

  // Reset on tab change
  useEffect(() => {
    setSelectedRecord(null);
    setClickedNode(null);
    setSearch("");
  }, [tab]);

  const handleNodeClick = useCallback((n: GraphNode) => {
    setClickedNode(prev => prev?.id === n.id ? null : n);
  }, []);

  const eType = ENTITY_TYPES[tab];

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
      {/* Header */}
      <Box>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 0.5 }}>
          Relationship Explorer
        </Typography>
        <Typography sx={{ fontSize: 13, color: "text.secondary" }}>
          Select an entity type, pick a record, and explore its connections across your security data model.
        </Typography>
      </Box>

      <Box sx={{ display: "flex", gap: 2.5, alignItems: "flex-start", minHeight: 640 }}>

        {/* ── Left: picker panel ── */}
        <Box sx={{
          width: 260, flexShrink: 0,
          border: "1px solid", borderColor: "divider",
          borderRadius: 2, bgcolor: "background.paper",
          display: "flex", flexDirection: "column", overflow: "hidden",
        }}>
          {/* Entity type tabs */}
          <Tabs
            value={tab}
            onChange={(_, v) => setTab(v)}
            variant="scrollable"
            scrollButtons={false}
            sx={{
              minHeight: 40, borderBottom: "1px solid", borderColor: "divider",
              "& .MuiTab-root": { minHeight: 40, fontSize: 12, py: 0, px: 1.5 },
            }}
          >
            {ENTITY_TYPES.map((et, i) => (
              <Tab key={et.key} label={et.label} value={i}
                icon={<et.Icon sx={{ fontSize: 14 }} />}
                iconPosition="start"
              />
            ))}
          </Tabs>

          {/* Search */}
          <Box sx={{ p: 1.5 }}>
            <TextField
              size="small" fullWidth placeholder={`Search ${eType.label}s…`}
              value={search} onChange={e => setSearch(e.target.value)}
              slotProps={{
                input: {
                  startAdornment: <InputAdornment position="start"><Search sx={{ fontSize: 16 }} /></InputAdornment>,
                },
              }}
              sx={{ "& .MuiInputBase-root": { fontSize: 13 } }}
            />
          </Box>

          {/* Record list */}
          <Box sx={{ flex: 1, overflow: "auto" }}>
            {listLoading ? (
              <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
                <CircularProgress size={24} />
              </Box>
            ) : (listData?.items ?? []).length === 0 ? (
              <Typography sx={{ fontSize: 12, color: "text.disabled", textAlign: "center", py: 4 }}>
                No {eType.label.toLowerCase()}s found
              </Typography>
            ) : (
              <List dense disablePadding>
                {(listData?.items ?? []).map((item: { id: string; label: string; detail: string }) => (
                  <ListItemButton
                    key={item.id}
                    selected={selectedRecord?.id === item.id}
                    onClick={() => { setSelectedRecord(item); setClickedNode(null); }}
                    sx={{ py: 0.75, px: 1.5 }}
                  >
                    <ListItemText
                      primary={<Typography sx={{ fontSize: 12, fontWeight: 500, lineHeight: 1.3 }}>{item.label}</Typography>}
                      secondary={item.detail ? <Typography sx={{ fontSize: 10, color: "text.disabled" }}>{item.detail}</Typography> : undefined}
                    />
                  </ListItemButton>
                ))}
              </List>
            )}
          </Box>
        </Box>

        {/* ── Centre: graph ── */}
        <Box sx={{
          flex: 1, minWidth: 0,
          border: "1px solid", borderColor: "divider",
          borderRadius: 2, bgcolor: isDark ? "#0d1117" : "#f8fafc",
          position: "relative", overflow: "hidden",
        }}>
          {!selectedRecord ? (
            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: 540, gap: 2, color: "text.disabled" }}>
              <eType.Icon sx={{ fontSize: 48, opacity: 0.3 }} />
              <Typography sx={{ fontSize: 14 }}>
                Select a {eType.label.toLowerCase()} from the list to explore its connections
              </Typography>
            </Box>
          ) : connLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", height: 540 }}>
              <CircularProgress />
            </Box>
          ) : !connData?.anchor ? (
            <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", height: 540 }}>
              <Typography sx={{ color: "text.disabled", fontSize: 13 }}>No connections found</Typography>
            </Box>
          ) : (
            <svg
              viewBox="0 0 840 680"
              style={{ width: "100%", height: "100%", minHeight: 540, display: "block" }}
            >
              <defs>
                <radialGradient id="glow-bg" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor={eType.color} stopOpacity="0.04" />
                  <stop offset="100%" stopColor="transparent" stopOpacity="0" />
                </radialGradient>
              </defs>

              {/* Soft glow behind anchor */}
              <circle cx={CX} cy={CY} r={220} fill="url(#glow-bg)" />

              {/* Edges */}
              {(connData.edges ?? []).map((e: GraphEdge, i: number) => {
                const src = layoutedNodes.find(n => n.id === e.source);
                const tgt = layoutedNodes.find(n => n.id === e.target);
                if (!src || !tgt || !src.x || !tgt.x) return null;
                const isHighlighted = clickedNode?.id === tgt.id || clickedNode?.id === src.id;
                return (
                  <g key={i}>
                    <path
                      d={bezierPath(src.x!, src.y!, tgt.x!, tgt.y!)}
                      fill="none"
                      stroke={isHighlighted ? eType.color : edgeColor}
                      strokeWidth={isHighlighted ? 2.5 : 1.5}
                      strokeOpacity={isHighlighted ? 0.9 : 0.5}
                      strokeLinecap="round"
                    />
                    {/* Edge label at midpoint */}
                    {e.label && (
                      <text
                        x={(src.x! + tgt.x!) / 2}
                        y={(src.y! + tgt.y!) / 2 - 6}
                        textAnchor="middle"
                        fontSize={9}
                        fill={isDark ? "#6b7280" : "#9ca3af"}
                      >
                        {e.label}
                      </text>
                    )}
                  </g>
                );
              })}

              {/* Nodes */}
              {layoutedNodes.map((n) => (
                <NodeCircle
                  key={n.id}
                  node={n}
                  selected={clickedNode?.id === n.id}
                  onSelect={handleNodeClick}
                />
              ))}
            </svg>
          )}

          {/* Stats overlay — node count + type counts */}
          {connData?.anchor && (
            <Box sx={{
              position: "absolute", top: 12, left: 12,
              display: "flex", gap: 0.75, flexWrap: "wrap",
            }}>
              <Chip label={`${layoutedNodes.length - 1} connections`} size="small"
                sx={{ fontSize: 10, height: 20, bgcolor: alpha(eType.color, 0.12), color: eType.color, fontWeight: 600 }} />
            </Box>
          )}
        </Box>

        {/* ── Right: detail panel (slides in on node click) ── */}
        {panelNode && (
          <NodeDetail node={panelNode} onClose={() => setClickedNode(null)} />
        )}
      </Box>
    </Box>
  );
}
