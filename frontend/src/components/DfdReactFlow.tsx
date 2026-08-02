/**
 * Interactive DFD renderer — Microsoft TMT / OWASP Threat Dragon style.
 *
 * Layout: two-pass dagre.
 *   Pass 1 — lay out nodes WITHIN each trust zone independently.
 *   Pass 2 — lay out trust-zone boxes relative to each other based on
 *             cross-zone data flows.
 *
 * Containment: component nodes have parentId + extent:"parent" so they
 * cannot be dragged outside their trust-zone box.  Users can resize the
 * zone box with NodeResizer to give more room.
 *
 * Shapes (standard DFD):
 *   External Entity  → plain rectangle
 *   Process          → circle (border-radius 50%)
 *   Data Store       → Yourdon parallel-line (top + bottom border only)
 *   Trust Boundary   → dashed red parent box, resizable, label tab at top
 *   Data Flow edge   → green pill label on bezier arrow
 */
import React, { useEffect, useMemo } from "react";
import { Box, Typography, Tooltip, useTheme } from "@mui/material";
import { Warning } from "@mui/icons-material";
import {
  ReactFlow, Background, Controls, MiniMap,
  useNodesState, useEdgesState, ReactFlowProvider,
  Handle, Position, BaseEdge, EdgeLabelRenderer, getBezierPath,
  MarkerType, NodeResizer,
  type Node, type Edge, type NodeTypes, type EdgeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import * as dagreLib from "@dagrejs/dagre";

// ── DFD shape classifier ──────────────────────────────────────────────────────

type DfdShape = "external_entity" | "process" | "data_store";

function toDfdShape(compType: string, explicitDfdType?: string): DfdShape {
  const e = (explicitDfdType || "").toLowerCase();
  if (e === "external_entity") return "external_entity";
  if (e === "data_store")      return "data_store";
  if (e === "process")         return "process";
  const t = (compType || "").toLowerCase();
  if (t === "user")                                           return "external_entity";
  if (t === "endpoint")                                       return "external_entity";
  if (t === "database" || t === "storage" || t === "secret-store" || t === "repo") return "data_store";
  return "process";
}

// ── Node dimensions ───────────────────────────────────────────────────────────

const DIM: Record<DfdShape, { w: number; h: number }> = {
  external_entity: { w: 120, h: 60 },
  process:         { w: 88,  h: 88 },
  data_store:      { w: 136, h: 48 },
};

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853",
};



// ── Threat badge ──────────────────────────────────────────────────────────────

function ThreatBadge({ count, maxSev }: { count: number; maxSev: string | null }) {
  if (!count || !maxSev) return null;
  const bg = SEV_COLOR[maxSev] ?? "#78909C";
  return (
    <Tooltip title={`${count} threat${count > 1 ? "s" : ""} — max: ${maxSev}`}>
      <Box sx={{
        position: "absolute", top: -9, right: -9,
        width: 22, height: 22, borderRadius: "50%",
        bgcolor: bg, border: "2px solid white",
        display: "flex", alignItems: "center", justifyContent: "center",
        boxShadow: `0 1px 4px ${bg}88`, zIndex: 10,
      }}>
        <Warning sx={{ fontSize: 10, color: "#fff" }} />
        <Typography sx={{ fontSize: 8, color: "#fff", fontWeight: 700, lineHeight: 1, ml: 0.1 }}>
          {count > 9 ? "9+" : count}
        </Typography>
      </Box>
    </Tooltip>
  );
}

// ── Component node ────────────────────────────────────────────────────────────

function ComponentNode({ data }: { data: Record<string, any> }) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const borderColor = isDark ? "#9E9E9E" : "#444444";
  const textColor = isDark ? "#E0E0E0" : "#212121";

  const shape = (data.dfdShape as DfdShape) ?? "process";
  const threatCount = (data.threatCount as number) ?? 0;
  const maxSev = data.maxSeverity as string | null;
  const label = data.label as string ?? "";

  const handles = (
    <>
      <Handle type="target" position={Position.Left}   style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Top}    style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right}  style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
    </>
  );

  const labelEl = (
    <Typography sx={{
      fontSize: 10.5, fontWeight: 600, color: textColor, textAlign: "center",
      lineHeight: 1.3, overflow: "hidden", display: "-webkit-box",
      WebkitLineClamp: 3, WebkitBoxOrient: "vertical", wordBreak: "break-word",
    }}>
      {label}
    </Typography>
  );

  if (shape === "external_entity") {
    return (
      <Box sx={{ position: "relative", width: DIM.external_entity.w }}>
        {handles}
        <Box sx={{
          width: DIM.external_entity.w, height: DIM.external_entity.h,
          border: `2px solid ${borderColor}`, bgcolor: "transparent",
          display: "flex", alignItems: "center", justifyContent: "center", p: 1,
        }}>
          {labelEl}
        </Box>
        <ThreatBadge count={threatCount} maxSev={maxSev} />
      </Box>
    );
  }

  if (shape === "process") {
    return (
      <Box sx={{ position: "relative", width: DIM.process.w }}>
        {handles}
        <Box sx={{
          width: DIM.process.w, height: DIM.process.h,
          borderRadius: "50%", border: `2px solid ${borderColor}`,
          bgcolor: "transparent",
          display: "flex", alignItems: "center", justifyContent: "center", p: 1.5,
        }}>
          {labelEl}
        </Box>
        <ThreatBadge count={threatCount} maxSev={maxSev} />
      </Box>
    );
  }

  // data_store — Yourdon parallel-line notation
  return (
    <Box sx={{ position: "relative", width: DIM.data_store.w }}>
      {handles}
      <Box sx={{
        width: DIM.data_store.w, height: DIM.data_store.h,
        borderTop: `2px solid ${borderColor}`, borderBottom: `2px solid ${borderColor}`,
        bgcolor: "transparent", display: "flex", alignItems: "center", px: 1.5,
      }}>
        <Typography sx={{
          fontSize: 10.5, fontWeight: 600, color: textColor,
          overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", width: "100%",
        }}>
          {label}
        </Typography>
      </Box>
      <ThreatBadge count={threatCount} maxSev={maxSev} />
    </Box>
  );
}

// ── Trust-boundary parent node (resizable) ────────────────────────────────────

function BoundaryNode({ selected, data }: { selected?: boolean; data: Record<string, any> }) {
  return (
    <>
      <NodeResizer
        color="#EA4335"
        isVisible={!!selected}
        minWidth={220}
        minHeight={140}
        lineStyle={{ borderWidth: 2 }}
        handleStyle={{ width: 10, height: 10, borderRadius: 2 }}
      />
      <Box sx={{
        width: "100%", height: "100%",
        border: "2px dashed #EA4335", borderRadius: "4px",
        bgcolor: "rgba(234,67,53,0.04)",
        position: "relative",
      }}>
        <Box sx={{
          position: "absolute", top: -13, left: 10,
          bgcolor: "background.paper", px: 0.75, py: 0,
          border: "1px solid #EA4335", borderRadius: "3px",
        }}>
          <Typography sx={{ fontSize: 10, fontWeight: 700, color: "#EA4335", whiteSpace: "nowrap" }}>
            {data.label as string}
          </Typography>
        </Box>
      </Box>
    </>
  );
}

// ── Data-flow edge — green pill label ─────────────────────────────────────────

function DataFlowEdge({ id, sourceX, sourceY, targetX, targetY, data }: any) {
  const [path, lx, ly] = getBezierPath({ sourceX, sourceY, targetX, targetY });
  const encrypted = data?.encrypted !== false;
  const stroke = encrypted ? "#5CB85C" : "#D9534F";
  const dash = encrypted ? undefined : "6 3";

  return (
    <>
      <BaseEdge
        id={id} path={path}
        style={{ stroke, strokeWidth: 1.5, strokeDasharray: dash }}
        markerEnd={MarkerType.ArrowClosed as any}
      />
      {data?.label && (
        <EdgeLabelRenderer>
          <Box
            className="nodrag nopan"
            sx={{
              position: "absolute",
              transform: `translate(-50%,-50%) translate(${lx}px,${ly}px)`,
              bgcolor: "#DFF0D8", border: "1px solid #5CB85C",
              color: "#2D6A2D", borderRadius: "4px",
              px: 0.75, py: 0.25, fontSize: 10, fontWeight: 600,
              pointerEvents: "none", whiteSpace: "nowrap",
              maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis",
              boxShadow: "0 1px 3px rgba(0,0,0,0.12)",
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

// ── Two-pass dagre layout ─────────────────────────────────────────────────────

const PAD_INNER = 30;   // padding inside zone around nodes
const PAD_LABEL = 28;   // extra top padding for the zone label tab

function buildGraph(
  components: ComponentInput[],
  dataFlows: DataFlowInput[],
  threats: ThreatInput[],
  _trustBoundaries: any[],
): { nodes: Node[]; edges: Edge[] } {

  const dagre: any = (dagreLib as any).default ?? dagreLib;

  // Threat count per component
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  const threatMap = new Map<string, { count: number; maxSev: string }>();
  for (const t of threats) {
    const cur = threatMap.get(t.asset_id);
    const sev = (t.severity || "info").toLowerCase();
    if (!cur) {
      threatMap.set(t.asset_id, { count: 1, maxSev: sev });
    } else {
      cur.count++;
      if (SEV_ORDER.indexOf(sev) < SEV_ORDER.indexOf(cur.maxSev)) cur.maxSev = sev;
    }
  }

  // Map component id → shape
  const shapeOf: Record<string, DfdShape> = {};
  components.forEach((c) => {
    shapeOf[c.id] = toDfdShape(c.type, c.dfd_type);
  });

  // Group components by zone
  const DEFAULT_ZONE = "private";
  const zoneMap = new Map<string, ComponentInput[]>();
  components.forEach((c) => {
    const z = (c.trust_zone || DEFAULT_ZONE).toLowerCase().trim() || DEFAULT_ZONE;
    if (!zoneMap.has(z)) zoneMap.set(z, []);
    zoneMap.get(z)!.push({ ...c, trust_zone: z });
  });

  const compIdSet = new Set(components.map((c) => c.id));

  // ── Pass 1: layout nodes WITHIN each zone ──────────────────────────────────
  //
  // We use a separate dagre graph per zone. Edges used in pass-1 are only
  // intra-zone edges (source and target in same zone).
  //
  // Result: for each zone, we know
  //   • relative positions of its nodes (top-left = 0,0 inside the zone)
  //   • zone box size (width + height)

  type ZoneLayout = {
    nodes: Record<string, { rx: number; ry: number }>;
    w: number;
    h: number;
  };

  const zoneLayouts = new Map<string, ZoneLayout>();

  zoneMap.forEach((comps, zone) => {
    const g = new dagre.graphlib.Graph();
    g.setDefaultEdgeLabel(() => ({}));
    g.setGraph({ rankdir: "LR", nodesep: 44, ranksep: 60 });

    comps.forEach((c) => {
      const d = DIM[shapeOf[c.id]] ?? DIM.process;
      g.setNode(c.id, { width: d.w + 20, height: d.h + 20 });
    });

    // Only intra-zone edges
    dataFlows.forEach((f) => {
      const fz = (components.find((c) => c.id === f.from)?.trust_zone || DEFAULT_ZONE).toLowerCase().trim();
      const tz = (components.find((c) => c.id === f.to)?.trust_zone || DEFAULT_ZONE).toLowerCase().trim();
      if (fz === zone && tz === zone && compIdSet.has(f.from) && compIdSet.has(f.to)) {
        try { g.setEdge(f.from, f.to); } catch { /* skip */ }
      }
    });

    dagre.layout(g);

    // Compute bounding box (dagre centres nodes so top-left = x-w/2)
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    comps.forEach((c) => {
      const pos = g.node(c.id);
      if (!pos) return;
      const d = DIM[shapeOf[c.id]] ?? DIM.process;
      minX = Math.min(minX, pos.x - d.w / 2);
      minY = Math.min(minY, pos.y - d.h / 2);
      maxX = Math.max(maxX, pos.x + d.w / 2);
      maxY = Math.max(maxY, pos.y + d.h / 2);
    });

    if (minX === Infinity) { minX = 0; minY = 0; maxX = 160; maxY = 100; }

    const rNodes: Record<string, { rx: number; ry: number }> = {};
    comps.forEach((c) => {
      const pos = g.node(c.id);
      if (!pos) return;
      const d = DIM[shapeOf[c.id]] ?? DIM.process;
      rNodes[c.id] = {
        rx: pos.x - d.w / 2 - minX + PAD_INNER,
        ry: pos.y - d.h / 2 - minY + PAD_INNER + PAD_LABEL,
      };
    });

    zoneLayouts.set(zone, {
      nodes: rNodes,
      w: (maxX - minX) + PAD_INNER * 2,
      h: (maxY - minY) + PAD_INNER * 2 + PAD_LABEL,
    });
  });

  // ── Pass 2: layout zones relative to each other ────────────────────────────

  const zoneG = new dagre.graphlib.Graph();
  zoneG.setDefaultEdgeLabel(() => ({}));
  zoneG.setGraph({ rankdir: "TB", nodesep: 60, ranksep: 80, marginx: 40, marginy: 40 });

  const zones = Array.from(zoneMap.keys());
  zones.forEach((z) => {
    const zl = zoneLayouts.get(z)!;
    zoneG.setNode(z, { width: zl.w, height: zl.h });
  });

  // Cross-zone edges drive zone ordering
  const seenZoneEdge = new Set<string>();
  dataFlows.forEach((f) => {
    const fz = (components.find((c) => c.id === f.from)?.trust_zone || DEFAULT_ZONE).toLowerCase().trim();
    const tz = (components.find((c) => c.id === f.to)?.trust_zone || DEFAULT_ZONE).toLowerCase().trim();
    if (fz !== tz) {
      const key = `${fz}→${tz}`;
      if (!seenZoneEdge.has(key)) {
        seenZoneEdge.add(key);
        try { zoneG.setEdge(fz, tz); } catch { /* skip */ }
      }
    }
  });

  // Hint zone order via rank
  // (dagre doesn't support explicit ranks easily via the graph option alone,
  //  so we just let the edges drive it — cross-zone flows create natural ranking)
  dagre.layout(zoneG);

  // ── Assemble React Flow nodes ──────────────────────────────────────────────

  const rfNodes: Node[] = [];
  const boundaryIdOf: Record<string, string> = {};

  zones.forEach((zone, zi) => {
    const zl  = zoneLayouts.get(zone)!;
    const zPos = zoneG.node(zone);
    if (!zPos) return;

    const bId = `boundary-${zi}`;
    boundaryIdOf[zone] = bId;

    // Boundary (parent) node
    rfNodes.push({
      id: bId,
      type: "boundary",
      position: { x: zPos.x - zl.w / 2, y: zPos.y - zl.h / 2 },
      style: { width: zl.w, height: zl.h },
      data: { label: zone },
      zIndex: -1,
      draggable: true,
      selectable: true,
    } as Node);

    // Component (child) nodes — positions are RELATIVE to parent
    (zoneMap.get(zone) || []).forEach((c) => {
      const rl = zl.nodes[c.id];
      if (!rl) return;
      const td = threatMap.get(c.id);
      rfNodes.push({
        id: c.id,
        type: "component",
        parentId: bId,
        extent: "parent" as const,
        position: { x: rl.rx, y: rl.ry },
        data: {
          label: c.name,
          dfdShape: shapeOf[c.id],
          compType: c.type || "other",
          trustZone: zone,
          criticality: c.criticality || "",
          threatCount: td?.count ?? 0,
          maxSeverity: td?.maxSev ?? null,
        },
        draggable: true,
        zIndex: 1,
      } as Node);
    });
  });

  // ── Edges ──────────────────────────────────────────────────────────────────

  const rfEdges: Edge[] = dataFlows
    .filter((f) => compIdSet.has(f.from) && compIdSet.has(f.to))
    .map((f, i) => ({
      id: `e${i}`,
      source: f.from,
      target: f.to,
      type: "dataflow",
      data: {
        label: f.label || f.notes || `${f.protocol || "data"}`,
        protocol: f.protocol,
        encrypted: f.encrypted,
      },
      markerEnd: { type: MarkerType.ArrowClosed },
      zIndex: 5,
    } as Edge));

  return { nodes: rfNodes, edges: rfEdges };
}

// ── Interfaces ────────────────────────────────────────────────────────────────

interface ComponentInput {
  id: string; name: string; type: string; dfd_type?: string;
  trust_zone: string; criticality: string;
}
interface DataFlowInput {
  from: string; to: string; protocol: string; data: string;
  encrypted: boolean; label?: string; notes?: string;
}
interface ThreatInput { id: string; asset_id: string; severity: string; }

// ── Inner graph ───────────────────────────────────────────────────────────────

function DfdGraphInner({
  components, dataFlows, threats, trustBoundaries,
}: {
  components: ComponentInput[];
  dataFlows: DataFlowInput[];
  threats: ThreatInput[];
  trustBoundaries: any[];
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const { nodes: rfNodes, edges: rfEdges } = useMemo(
    () => buildGraph(components, dataFlows, threats, trustBoundaries),
    [components, dataFlows, threats, trustBoundaries],
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(rfNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(rfEdges);

  useEffect(() => { setNodes(rfNodes); }, [rfNodes, setNodes]);
  useEffect(() => { setEdges(rfEdges); }, [rfEdges, setEdges]);

  const canvasBg = isDark ? "#111827" : "#FFFFFF";
  const dotColor = isDark ? "#1f2937" : "#E5E7EB";

  if (components.length === 0) {
    return (
      <Box sx={{
        display: "flex", alignItems: "center", justifyContent: "center", height: 300,
        border: "1px dashed rgba(156,163,175,0.4)", borderRadius: 2, color: "text.secondary",
      }}>
        <Typography variant="body2">No components yet — generate the threat model first.</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{
      width: "100%", height: 620, bgcolor: canvasBg, borderRadius: 2,
      border: `1px solid ${isDark ? "rgba(255,255,255,0.08)" : "#E5E7EB"}`,
      overflow: "hidden",
    }}>
      <ReactFlow
        nodes={nodes} edges={edges}
        onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
        nodeTypes={NODE_TYPES} edgeTypes={EDGE_TYPES}
        fitView fitViewOptions={{ padding: 0.12 }}
        minZoom={0.15} maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
      >
        <Background color={dotColor} gap={20} size={1} />
        <Controls showInteractive={false}
          style={{ bottom: 12, right: 12, left: "auto", top: "auto" }} />
        <MiniMap
          nodeColor={(n) => n.type === "boundary" ? "transparent" : "#4285F4"}
          maskColor={isDark ? "rgba(10,15,30,0.6)" : "rgba(220,228,240,0.6)"}
          style={{ bottom: 12, left: 12, width: 140, height: 90 }}
          zoomable pannable
        />
      </ReactFlow>
    </Box>
  );
}

// ── Legend ────────────────────────────────────────────────────────────────────

function DfdLegend() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const border = isDark ? "#9E9E9E" : "#444";

  return (
    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, mt: 1.5, px: 0.5, alignItems: "center" }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 36, height: 22, border: `2px solid ${border}`, flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>External Entity</Typography>
      </Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 26, height: 26, border: `2px solid ${border}`, borderRadius: "50%", flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>Process</Typography>
      </Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 40, height: 18, borderTop: `2px solid ${border}`, borderBottom: `2px solid ${border}`, flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>Data Store</Typography>
      </Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 36, height: 22, border: "2px dashed #EA4335", borderRadius: "3px", flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>Trust Boundary (select to resize)</Typography>
      </Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 32, height: 2, bgcolor: "#5CB85C", flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>Encrypted flow</Typography>
      </Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 32, height: 2, background: "repeating-linear-gradient(90deg,#D9534F 0,#D9534F 6px,transparent 6px,transparent 9px)", flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>Unencrypted</Typography>
      </Box>
    </Box>
  );
}

// ── Public export ─────────────────────────────────────────────────────────────

interface Props {
  components: ComponentInput[];
  dataFlows: DataFlowInput[];
  threats: ThreatInput[];
  trustBoundaries?: any[];
}

export default function DfdReactFlow({ components, dataFlows, threats, trustBoundaries = [] }: Props) {
  const critCount = threats.filter((t) => (t.severity || "").toLowerCase() === "critical").length;

  return (
    <Box>
      {critCount > 0 && (
        <Box sx={{
          display: "flex", alignItems: "center", gap: 1, mb: 1,
          px: 1.5, py: 0.75,
          bgcolor: "rgba(234,67,53,0.08)", borderRadius: 1,
          border: "1px solid rgba(234,67,53,0.2)",
        }}>
          <Warning sx={{ fontSize: 16, color: "#EA4335" }} />
          <Typography variant="caption" sx={{ color: "#EA4335", fontWeight: 600 }}>
            {critCount} critical threat{critCount > 1 ? "s" : ""} — nodes marked with red badge
          </Typography>
        </Box>
      )}
      <ReactFlowProvider>
        <DfdGraphInner
          components={components}
          dataFlows={dataFlows}
          threats={threats}
          trustBoundaries={trustBoundaries}
        />
      </ReactFlowProvider>
      <DfdLegend />
    </Box>
  );
}
