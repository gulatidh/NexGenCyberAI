/**
 * Interactive Data Flow Diagram renderer for Threat Models.
 *
 * Uses React Flow + dagre to produce a draggable, zoomable DFD that is
 * visually consistent with Attack Paths while remaining compliant with
 * the threat-modelling standard:
 *
 *   External Entity  → rectangle (actor / user / internet-facing system)
 *   Process / API    → rounded-rect / circle (computation)
 *   Data Store / DB  → cylinder-style box (data at rest)
 *   Trust Boundary   → coloured dashed-border group (React Flow parent node)
 *   Data Flow edge   → labelled arrow; red-dashed when unencrypted
 *   Threat badge     → count chip in top-right corner of affected nodes
 *
 * Props mirror what ThreatModelDetail already has on `data`:
 *   components     Component[]
 *   data_flows     DataFlow[]
 *   threats        Threat[]
 *   trust_boundaries  any[]   (optional)
 */
import React, { useEffect, useMemo } from "react";
import { Box, Typography, Tooltip, useTheme } from "@mui/material";
import {
  Public, Storage, Code, VpnKey, Inbox, Lock, Source,
  Computer, Hub, Warning, Person,
} from "@mui/icons-material";
import {
  ReactFlow, Background, Controls, MiniMap,
  useNodesState, useEdgesState, ReactFlowProvider,
  Handle, Position, BaseEdge, EdgeLabelRenderer, getBezierPath,
  MarkerType, type Node, type Edge, type NodeTypes, type EdgeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import * as dagreLib from "@dagrejs/dagre";

// ── Trust-zone colours ────────────────────────────────────────────────────────

function zoneColor(zone: string): { border: string; bg: string; text: string } {
  const z = (zone || "").toLowerCase();
  if (/(internet|external|public|untrust|wan)/.test(z))
    return { border: "#EA4335", bg: "#EA433514", text: "#EA4335" };
  if (/(dmz|perimeter|edge|public.facing)/.test(z))
    return { border: "#F9AB00", bg: "#F9AB0014", text: "#F59E0B" };
  if (/(private|internal|trusted|corp|lan|intranet)/.test(z))
    return { border: "#34A853", bg: "#34A85314", text: "#34A853" };
  if (/(data|database|storage|tier|backend)/.test(z))
    return { border: "#9C27B0", bg: "#9C27B014", text: "#9C27B0" };
  if (/(manage|mgmt|admin|control)/.test(z))
    return { border: "#4285F4", bg: "#4285F414", text: "#4285F4" };
  return { border: "#78909C", bg: "#78909C14", text: "#78909C" };
}

// ── Component type → icon + base colour ──────────────────────────────────────

const TYPE_CFG: Record<string, { icon: React.ReactNode; color: string; shape: "process" | "store" | "external" }> = {
  endpoint:      { icon: <Public sx={{ fontSize: 18, color: "#fff" }} />,   color: "#1565C0", shape: "external" },
  api:           { icon: <Code sx={{ fontSize: 18, color: "#fff" }} />,     color: "#0277BD", shape: "process"  },
  database:      { icon: <Storage sx={{ fontSize: 18, color: "#fff" }} />,  color: "#6A1B9A", shape: "store"    },
  storage:       { icon: <Storage sx={{ fontSize: 18, color: "#fff" }} />,  color: "#4527A0", shape: "store"    },
  identity:      { icon: <VpnKey sx={{ fontSize: 18, color: "#fff" }} />,   color: "#AD1457", shape: "process"  },
  queue:         { icon: <Inbox sx={{ fontSize: 18, color: "#fff" }} />,    color: "#00695C", shape: "store"    },
  "secret-store":{ icon: <Lock sx={{ fontSize: 18, color: "#fff" }} />,    color: "#4E342E", shape: "store"    },
  repo:          { icon: <Source sx={{ fontSize: 18, color: "#fff" }} />,   color: "#37474F", shape: "store"    },
  vm:            { icon: <Computer sx={{ fontSize: 18, color: "#fff" }} />, color: "#E64A19", shape: "process"  },
  service:       { icon: <Hub sx={{ fontSize: 18, color: "#fff" }} />,      color: "#0288D1", shape: "process"  },
  user:          { icon: <Person sx={{ fontSize: 18, color: "#fff" }} />,   color: "#2E7D32", shape: "external" },
  other:         { icon: <Hub sx={{ fontSize: 18, color: "#fff" }} />,      color: "#546E7A", shape: "process"  },
};
const FALLBACK_CFG = TYPE_CFG.other;

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853",
};

// ── Node dimensions ───────────────────────────────────────────────────────────

const W = 140; // node width
const H = 72;  // node height

// ── Custom component node ─────────────────────────────────────────────────────

function ComponentNode({ id, data }: { id: string; data: Record<string, any> }) {
  const theme = useTheme();
  const cfg = TYPE_CFG[data.compType as string] ?? FALLBACK_CFG;
  const shape = cfg.shape as "process" | "store" | "external";
  const threatCount = (data.threatCount as number) ?? 0;
  const maxSev = data.maxSeverity as string | null;
  const badgeColor = maxSev ? SEV_COLOR[maxSev] ?? "#78909C" : null;
  const criticality = (data.criticality as string ?? "").toLowerCase();

  // Border radius per DFD shape
  const rx = shape === "process" ? "12px" : shape === "store" ? "4px" : "0px";

  return (
    <Box sx={{ position: "relative", width: W }}>
      <Handle type="target" position={Position.Left}  style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Top}   style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />

      {/* Main card */}
      <Box sx={{
        width: W, minHeight: H,
        borderRadius: rx,
        bgcolor: "background.paper",
        border: `2px solid ${cfg.color}`,
        boxShadow: criticality === "critical"
          ? `0 0 12px ${cfg.color}55, 0 2px 8px rgba(0,0,0,0.12)`
          : "0 2px 8px rgba(0,0,0,0.10)",
        display: "flex", flexDirection: "column",
        overflow: "hidden",
        position: "relative",
        // Data-store: double bottom line to mimic DFD cylinder notation
        ...(shape === "store" && {
          "&::after": {
            content: '""',
            position: "absolute", bottom: 0, left: 0, right: 0,
            height: 6, bgcolor: `${cfg.color}40`,
            borderTop: `2px solid ${cfg.color}`,
          },
        }),
      }}>
        {/* Coloured icon header strip */}
        <Box sx={{
          bgcolor: cfg.color,
          display: "flex", alignItems: "center", gap: 0.5,
          px: 1, py: 0.5,
        }}>
          {cfg.icon}
          <Typography sx={{ fontSize: 9, color: "#fff", fontWeight: 700, opacity: 0.8,
            textTransform: "uppercase", letterSpacing: 0.5 }}>
            {(data.compType as string).replace(/-/g, " ")}
          </Typography>
        </Box>

        {/* Name */}
        <Box sx={{ px: 1, py: 0.5, pb: shape === "store" ? 1.5 : 0.5 }}>
          <Typography sx={{
            fontSize: 11, fontWeight: 700, color: "text.primary", lineHeight: 1.3,
            overflow: "hidden", display: "-webkit-box",
            WebkitLineClamp: 2, WebkitBoxOrient: "vertical",
          }}>
            {data.label as string}
          </Typography>
          {data.trustZone && (
            <Typography sx={{ fontSize: 9, color: "#888", mt: 0.25 }}>
              {data.trustZone as string}
            </Typography>
          )}
        </Box>
      </Box>

      {/* Threat count badge */}
      {threatCount > 0 && badgeColor && (
        <Tooltip title={`${threatCount} threat${threatCount > 1 ? "s" : ""} — max ${maxSev}`}>
          <Box sx={{
            position: "absolute", top: -8, right: -8,
            width: 22, height: 22, borderRadius: "50%",
            bgcolor: badgeColor, border: "2px solid #fff",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: `0 2px 6px ${badgeColor}88`,
            cursor: "default",
          }}>
            <Warning sx={{ fontSize: 12, color: "#fff" }} />
            <Typography sx={{ fontSize: 8, color: "#fff", fontWeight: 700, lineHeight: 1, ml: 0.1 }}>
              {threatCount}
            </Typography>
          </Box>
        </Tooltip>
      )}
    </Box>
  );
}

// ── Trust-boundary group node ─────────────────────────────────────────────────

function BoundaryNode({ data }: { data: Record<string, any> }) {
  const { border, bg, text } = zoneColor(data.zoneName as string ?? "");
  return (
    <Box sx={{
      width: "100%", height: "100%",
      border: `2px dashed ${border}`,
      borderRadius: 3, bgcolor: bg,
      position: "relative", pointerEvents: "none",
    }}>
      <Box sx={{
        position: "absolute", top: -11, left: 12,
        bgcolor: "background.paper", px: 1, py: 0.1,
        border: `1.5px solid ${border}`, borderRadius: 1,
      }}>
        <Typography sx={{ fontSize: 10, fontWeight: 700, color: text, whiteSpace: "nowrap" }}>
          {data.label as string}
        </Typography>
      </Box>
    </Box>
  );
}

// ── Data-flow edge ────────────────────────────────────────────────────────────

function DataFlowEdge({ id, sourceX, sourceY, targetX, targetY, data }: any) {
  const theme = useTheme();
  const [path, lx, ly] = getBezierPath({ sourceX, sourceY, targetX, targetY });
  const encrypted = data?.encrypted !== false;
  const stroke = encrypted ? "#4285F4" : "#EA4335";
  const dash  = encrypted ? undefined : "6 3";

  return (
    <>
      <BaseEdge id={id} path={path} style={{ stroke, strokeWidth: 2, strokeDasharray: dash }} />
      {data?.label && (
        <EdgeLabelRenderer>
          <Box
            className="nodrag nopan"
            sx={{
              position: "absolute",
              transform: `translate(-50%,-50%) translate(${lx}px,${ly}px)`,
              fontSize: 9, fontWeight: 600,
              color: encrypted ? "#1565C0" : "#B71C1C",
              bgcolor: theme.palette.background.paper,
              opacity: 0.95,
              px: 0.6, py: 0.15, borderRadius: 0.5,
              border: `1px solid ${stroke}66`,
              pointerEvents: "none", whiteSpace: "nowrap", maxWidth: 120,
              overflow: "hidden", textOverflow: "ellipsis",
            }}
          >
            {data.label}
          </Box>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

const NODE_TYPES: NodeTypes = { component: ComponentNode, boundary: BoundaryNode };
const EDGE_TYPES: EdgeTypes = { dataflow: DataFlowEdge };

// ── Dagre layout ──────────────────────────────────────────────────────────────

function applyLayout(nodes: Node[], edges: Edge[]): Node[] {
  const dagre: any = (dagreLib as any).default ?? dagreLib;
  const g = new dagre.graphlib.Graph({ compound: true });
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "LR", nodesep: 50, ranksep: 100, marginx: 40, marginy: 40 });

  nodes.forEach((n) => {
    if (n.type === "boundary") {
      // Boundaries will be sized based on children later — give a placeholder
      g.setNode(n.id, { width: 200, height: 150 });
    } else {
      g.setNode(n.id, { width: W + 16, height: H + 40 });
      if (n.parentId) g.setParent(n.id, n.parentId);
    }
  });
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);

  return nodes.map((n) => {
    const pos = g.node(n.id);
    if (!pos) return n;
    return { ...n, position: { x: pos.x - pos.width / 2, y: pos.y - pos.height / 2 } };
  });
}

// ── Converter: ThreatModel data → React Flow nodes + edges ───────────────────

interface Component {
  id: string; name: string; type: string;
  trust_zone: string; criticality: string;
}
interface DataFlow {
  from: string; to: string; protocol: string; data: string; encrypted: boolean;
}
interface Threat {
  id: string; asset_id: string; severity: string;
}

function buildGraph(
  components: Component[],
  dataFlows: DataFlow[],
  threats: Threat[],
  trustBoundaries: any[],
) {
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  // Count + max-severity threats per component
  const threatsByComp = new Map<string, { count: number; maxSev: string }>();
  for (const t of threats) {
    const id = t.asset_id;
    const cur = threatsByComp.get(id);
    const sev = (t.severity || "info").toLowerCase();
    if (!cur) {
      threatsByComp.set(id, { count: 1, maxSev: sev });
    } else {
      cur.count++;
      if (SEV_ORDER.indexOf(sev) < SEV_ORDER.indexOf(cur.maxSev)) cur.maxSev = sev;
    }
  }

  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Build trust-zone set from components (group automatically)
  const zoneSet = new Set<string>();
  components.forEach((c) => { if (c.trust_zone) zoneSet.add(c.trust_zone); });

  // Also add any explicitly listed boundaries
  const explicitBoundaries = trustBoundaries || [];
  explicitBoundaries.forEach((b) => { if (b.name) zoneSet.add(b.name); });

  // Boundary nodes (parent)
  const zoneIds = new Map<string, string>();
  let zi = 0;
  zoneSet.forEach((zone) => {
    const nid = `boundary-${zi++}`;
    zoneIds.set(zone, nid);
    const { text } = zoneColor(zone);
    nodes.push({
      id: nid,
      type: "boundary",
      position: { x: 0, y: 0 },
      data: { label: zone, zoneName: zone },
      style: { width: 280, height: 180 },
      draggable: false,
    } as Node);
  });

  // Component nodes
  components.forEach((c) => {
    const td = threatsByComp.get(c.id);
    const parentId = c.trust_zone ? zoneIds.get(c.trust_zone) : undefined;
    nodes.push({
      id: c.id,
      type: "component",
      position: { x: 0, y: 0 },
      parentId: parentId,
      extent: parentId ? "parent" : undefined,
      data: {
        label: c.name,
        compType: c.type || "other",
        trustZone: c.trust_zone || "",
        criticality: c.criticality || "",
        threatCount: td?.count ?? 0,
        maxSeverity: td?.maxSev ?? null,
      },
      draggable: true,
    } as Node);
  });

  // Data flow edges
  const compIds = new Set(components.map((c) => c.id));
  dataFlows.forEach((df, i) => {
    if (!compIds.has(df.from) || !compIds.has(df.to)) return;
    const label = [df.protocol, df.data].filter(Boolean).join(": ").slice(0, 32);
    edges.push({
      id: `df-${i}`,
      source: df.from,
      target: df.to,
      type: "dataflow",
      data: { label, encrypted: df.encrypted !== false },
      markerEnd: { type: MarkerType.ArrowClosed, color: df.encrypted !== false ? "#4285F4" : "#EA4335" },
    });
  });

  return { nodes, edges };
}

// ── Inner graph component ─────────────────────────────────────────────────────

function DfdGraphInner({
  components, dataFlows, threats, trustBoundaries,
}: {
  components: Component[];
  dataFlows: DataFlow[];
  threats: Threat[];
  trustBoundaries: any[];
}) {
  const { nodes: rfNodes, edges: rfEdges } = useMemo(
    () => buildGraph(components, dataFlows, threats, trustBoundaries),
    [components, dataFlows, threats, trustBoundaries],
  );

  // Apply dagre layout — skip boundary nodes in layout (they wrap children)
  const laidNodes = useMemo(() => applyLayout(rfNodes, rfEdges), [rfNodes, rfEdges]);

  const [nodes, setNodes, onNodesChange] = useNodesState(laidNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(rfEdges);
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  useEffect(() => { setNodes(laidNodes); }, [laidNodes, setNodes]);
  useEffect(() => { setEdges(rfEdges); }, [rfEdges, setEdges]);

  if (components.length === 0) {
    return (
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: 300,
        border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 2, color: "text.secondary" }}>
        <Typography variant="body2">No components yet — generate the threat model first.</Typography>
      </Box>
    );
  }
  const canvasBg = isDark ? "#1a1f2e" : "#F0F4F8";
  const dotColor = isDark ? "#2d3550" : "#CBD5E1";

  return (
    <Box sx={{ width: "100%", height: 580, bgcolor: canvasBg, borderRadius: 2,
      border: `1px solid ${isDark ? "rgba(255,255,255,0.08)" : "#CBD5E1"}`, overflow: "hidden" }}>
      <ReactFlow
        nodes={nodes} edges={edges}
        onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
        nodeTypes={NODE_TYPES} edgeTypes={EDGE_TYPES}
        fitView fitViewOptions={{ padding: 0.12 }}
        minZoom={0.2} maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
      >
        <Background color={dotColor} gap={24} size={1} />
        <Controls showInteractive={false}
          style={{ bottom: 12, right: 12, left: "auto", top: "auto" }} />
        <MiniMap
          nodeColor={(n) => {
            if (n.type === "boundary") return "transparent";
            const cfg = TYPE_CFG[(n.data as any)?.compType ?? ""] ?? FALLBACK_CFG;
            return cfg.color;
          }}
          maskColor={isDark ? "rgba(20,25,40,0.6)" : "rgba(220,228,240,0.6)"}
          style={{ bottom: 12, left: 12, width: 140, height: 90 }}
          zoomable pannable
        />
      </ReactFlow>
    </Box>
  );
}

// ── Legend ────────────────────────────────────────────────────────────────────

const LEGEND_SHAPES = [
  { label: "External Entity", rx: "0px",  color: "#1565C0" },
  { label: "Process / API",   rx: "12px", color: "#0277BD" },
  { label: "Data Store",      rx: "4px",  color: "#6A1B9A" },
];
const LEGEND_ZONES = [
  { label: "Internet",  color: "#EA4335" },
  { label: "DMZ",       color: "#F9AB00" },
  { label: "Internal",  color: "#34A853" },
  { label: "Data tier", color: "#9C27B0" },
];

// ── Public component ──────────────────────────────────────────────────────────

interface Props {
  components: Component[];
  dataFlows: DataFlow[];
  threats: Threat[];
  trustBoundaries?: any[];
}

export default function DfdReactFlow({ components, dataFlows, threats, trustBoundaries = [] }: Props) {
  const threatCount = threats.length;
  const critCount   = threats.filter((t) => (t.severity || "").toLowerCase() === "critical").length;

  return (
    <Box>
      <ReactFlowProvider>
        <DfdGraphInner
          components={components}
          dataFlows={dataFlows}
          threats={threats}
          trustBoundaries={trustBoundaries}
        />
      </ReactFlowProvider>

      {/* Legend */}
      <Box sx={{ mt: 1.5, display: "flex", flexWrap: "wrap", gap: 3, alignItems: "flex-start" }}>
        {/* DFD shape legend */}
        <Box>
          <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, display: "block", mb: 0.75, textTransform: "uppercase", letterSpacing: 0.5, fontSize: 9 }}>
            DFD Node Shape
          </Typography>
          <Box sx={{ display: "flex", gap: 1.5, flexWrap: "wrap" }}>
            {LEGEND_SHAPES.map((s) => (
              <Box key={s.label} sx={{ display: "flex", alignItems: "center", gap: 0.6 }}>
                <Box sx={{ width: 20, height: 14, borderRadius: s.rx, border: `2px solid ${s.color}`, bgcolor: "#fff", flexShrink: 0 }} />
                <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>{s.label}</Typography>
              </Box>
            ))}
          </Box>
        </Box>

        {/* Trust zone colours */}
        <Box>
          <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, display: "block", mb: 0.75, textTransform: "uppercase", letterSpacing: 0.5, fontSize: 9 }}>
            Trust Zone
          </Typography>
          <Box sx={{ display: "flex", gap: 1.5, flexWrap: "wrap" }}>
            {LEGEND_ZONES.map((z) => (
              <Box key={z.label} sx={{ display: "flex", alignItems: "center", gap: 0.6 }}>
                <Box sx={{ width: 14, height: 14, border: `2px dashed ${z.color}`, borderRadius: 1, bgcolor: `${z.color}14`, flexShrink: 0 }} />
                <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>{z.label}</Typography>
              </Box>
            ))}
          </Box>
        </Box>

        {/* Edge legend */}
        <Box>
          <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, display: "block", mb: 0.75, textTransform: "uppercase", letterSpacing: 0.5, fontSize: 9 }}>
            Data Flow
          </Typography>
          <Box sx={{ display: "flex", gap: 1.5, flexWrap: "wrap", alignItems: "center" }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.6 }}>
              <Box sx={{ width: 22, height: 2.5, bgcolor: "#4285F4", borderRadius: 1 }} />
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>Encrypted</Typography>
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.6 }}>
              <Box sx={{ width: 22, height: 2.5, background: "repeating-linear-gradient(90deg,#EA4335 0,#EA4335 5px,transparent 5px,transparent 9px)", borderRadius: 1 }} />
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>Unencrypted</Typography>
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.6 }}>
              <Box sx={{ width: 22, height: 16, borderRadius: "50%", bgcolor: "#EA4335", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Typography sx={{ fontSize: 8, color: "#fff", fontWeight: 700 }}>{critCount || "N"}</Typography>
              </Box>
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>Threat badge ({threatCount} total)</Typography>
            </Box>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}
