/**
 * Interactive DFD renderer — Microsoft TMT / OWASP Threat Dragon style.
 *
 * Shapes:
 *   External Entity  → plain rectangle (actor / user / internet-facing system)
 *   Process          → true circle (computation / service)
 *   Data Store       → Yourdon parallel-line notation (data at rest)
 *   Trust Boundary   → dashed red rectangle overlay, resizable
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

function dfdType(compType: string): "external_entity" | "process" | "data_store" {
  const t = (compType || "").toLowerCase();
  if (t === "user" || t === "endpoint") return "external_entity";
  if (t === "database" || t === "storage" || t === "secret-store" || t === "repo") return "data_store";
  return "process";
}

// ── Node dimensions ───────────────────────────────────────────────────────────

const DIM = {
  external_entity: { w: 120, h: 64 },
  process:         { w: 90,  h: 90  },
  data_store:      { w: 140, h: 50  },
};

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853",
};

// ── Threat badge ──────────────────────────────────────────────────────────────

function ThreatBadge({ count, maxSev }: { count: number; maxSev: string | null }) {
  if (!count || !maxSev) return null;
  const bg = SEV_COLOR[maxSev] ?? "#78909C";
  return (
    <Tooltip title={`${count} threat${count > 1 ? "s" : ""} — max severity: ${maxSev}`}>
      <Box sx={{
        position: "absolute", top: -9, right: -9,
        width: 22, height: 22, borderRadius: "50%",
        bgcolor: bg, border: "2px solid white",
        display: "flex", alignItems: "center", justifyContent: "center",
        boxShadow: `0 1px 4px ${bg}88`,
        zIndex: 10,
      }}>
        <Warning sx={{ fontSize: 11, color: "#fff" }} />
        <Typography sx={{ fontSize: 8, color: "#fff", fontWeight: 700, lineHeight: 1, ml: 0.1 }}>
          {count > 9 ? "9+" : count}
        </Typography>
      </Box>
    </Tooltip>
  );
}

// ── Component node ────────────────────────────────────────────────────────────

function ComponentNode({ id, data }: { id: string; data: Record<string, any> }) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const borderColor = isDark ? "#9E9E9E" : "#444444";
  const textColor = isDark ? "#E0E0E0" : "#212121";

  const shape = (data.dfdShape as "external_entity" | "process" | "data_store") ?? "process";
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

  if (shape === "external_entity") {
    return (
      <Box sx={{ position: "relative", width: DIM.external_entity.w }}>
        {handles}
        <Box sx={{
          width: DIM.external_entity.w, height: DIM.external_entity.h,
          border: `2px solid ${borderColor}`,
          bgcolor: "transparent",
          display: "flex", alignItems: "center", justifyContent: "center",
          p: 1,
        }}>
          <Typography sx={{
            fontSize: 11, fontWeight: 600, color: textColor,
            textAlign: "center", lineHeight: 1.3,
            overflow: "hidden", display: "-webkit-box",
            WebkitLineClamp: 3, WebkitBoxOrient: "vertical",
          }}>
            {label}
          </Typography>
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
          borderRadius: "50%",
          border: `2px solid ${borderColor}`,
          bgcolor: "transparent",
          display: "flex", alignItems: "center", justifyContent: "center",
          p: 1,
        }}>
          <Typography sx={{
            fontSize: 10.5, fontWeight: 600, color: textColor,
            textAlign: "center", lineHeight: 1.3,
            overflow: "hidden", display: "-webkit-box",
            WebkitLineClamp: 3, WebkitBoxOrient: "vertical",
          }}>
            {label}
          </Typography>
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
        borderTop: `2px solid ${borderColor}`,
        borderBottom: `2px solid ${borderColor}`,
        bgcolor: "transparent",
        display: "flex", alignItems: "center",
        px: 1.5,
      }}>
        <Typography sx={{
          fontSize: 11, fontWeight: 600, color: textColor,
          overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis",
          width: "100%",
        }}>
          {label}
        </Typography>
      </Box>
      <ThreatBadge count={threatCount} maxSev={maxSev} />
    </Box>
  );
}

// ── Trust-boundary node (resizable dashed overlay) ───────────────────────────

function BoundaryNode({ selected, data }: { selected?: boolean; data: Record<string, any> }) {
  return (
    <>
      <NodeResizer
        color="#EA4335"
        isVisible={!!selected}
        minWidth={200}
        minHeight={120}
        lineStyle={{ borderWidth: 2 }}
        handleStyle={{ width: 10, height: 10, borderRadius: 2 }}
      />
      <Box sx={{
        width: "100%", height: "100%",
        border: "2px dashed #EA4335",
        borderRadius: "4px",
        bgcolor: "rgba(234,67,53,0.04)",
        position: "relative",
        pointerEvents: "none",
      }}>
        <Box sx={{
          position: "absolute", top: -13, left: 10,
          bgcolor: "background.paper",
          px: 0.75, py: 0,
          border: "1px solid #EA4335",
          borderRadius: "3px",
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
              bgcolor: "#DFF0D8",
              border: "1px solid #5CB85C",
              color: "#2D6A2D",
              borderRadius: "4px",
              px: 0.75, py: 0.25,
              fontSize: 10, fontWeight: 600,
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

// ── Dagre layout (component nodes only) ───────────────────────────────────────

function layoutComponents(nodes: Node[], edges: Edge[]): Node[] {
  const dagre: any = (dagreLib as any).default ?? dagreLib;
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "TB", nodesep: 60, ranksep: 80, marginx: 60, marginy: 60 });

  nodes.forEach((n) => {
    const shape = (n.data as any).dfdShape as "external_entity" | "process" | "data_store";
    const dim = DIM[shape] ?? DIM.process;
    g.setNode(n.id, { width: dim.w + 24, height: dim.h + 40 });
  });
  edges.forEach((e) => { try { g.setEdge(e.source, e.target); } catch { /* skip invalid */ } });
  dagre.layout(g);

  return nodes.map((n) => {
    const pos = g.node(n.id);
    if (!pos) return n;
    const shape = (n.data as any).dfdShape as "external_entity" | "process" | "data_store";
    const dim = DIM[shape] ?? DIM.process;
    return { ...n, position: { x: pos.x - dim.w / 2, y: pos.y - dim.h / 2 } };
  });
}

// ── Build boundary nodes sized around their components' bounding boxes ────────

function buildBoundaryNodes(
  compNodes: Node[],
  trustBoundaries: any[],
  compType: Record<string, string>,
): Node[] {
  // zone → bounding box from laid-out component positions
  const bbox: Record<string, { x1: number; y1: number; x2: number; y2: number }> = {};

  compNodes.forEach((n) => {
    const zone = (n.data as any).trustZone as string;
    if (!zone) return;
    const shape = (n.data as any).dfdShape as "external_entity" | "process" | "data_store";
    const dim = DIM[shape] ?? DIM.process;
    const { x, y } = n.position;
    const b = bbox[zone] ?? { x1: Infinity, y1: Infinity, x2: -Infinity, y2: -Infinity };
    bbox[zone] = {
      x1: Math.min(b.x1, x),
      y1: Math.min(b.y1, y),
      x2: Math.max(b.x2, x + dim.w),
      y2: Math.max(b.y2, y + dim.h),
    };
  });

  const PAD = 40;
  const boundaryNodes: Node[] = [];

  // Zones from component data
  const zones = new Set<string>(compNodes.map((n) => (n.data as any).trustZone as string).filter(Boolean));

  // Also from explicit trust_boundaries list
  (trustBoundaries || []).forEach((tb: any) => {
    if (tb.name) zones.add(tb.name);
    if (tb.from_zone) zones.add(tb.from_zone);
    if (tb.to_zone) zones.add(tb.to_zone);
  });

  let bi = 0;
  zones.forEach((zone) => {
    const b = bbox[zone];
    let x = 20, y = 20, w = 260, h = 180;
    if (b && b.x1 !== Infinity) {
      x = b.x1 - PAD;
      y = b.y1 - PAD;
      w = (b.x2 - b.x1) + PAD * 2;
      h = (b.y2 - b.y1) + PAD * 2;
    } else {
      x = 30 + bi * 280; y = 20;
    }
    boundaryNodes.push({
      id: `boundary-${bi++}`,
      type: "boundary",
      position: { x, y },
      style: { width: Math.max(w, 200), height: Math.max(h, 150) },
      data: { label: zone },
      draggable: true,
      selectable: true,
      zIndex: -1,
    } as Node);
  });

  return boundaryNodes;
}

// ── Converter: ThreatModel data → React Flow nodes + edges ───────────────────

interface Component {
  id: string; name: string; type: string; dfd_type?: string;
  trust_zone: string; criticality: string;
}
interface DataFlow {
  from: string; to: string; protocol: string; data: string;
  encrypted: boolean; label?: string; notes?: string;
}
interface Threat { id: string; asset_id: string; severity: string; }

function buildGraph(
  components: Component[],
  dataFlows: DataFlow[],
  threats: Threat[],
  trustBoundaries: any[],
): { nodes: Node[]; edges: Edge[] } {
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  const threatsByComp = new Map<string, { count: number; maxSev: string }>();
  for (const t of threats) {
    const cur = threatsByComp.get(t.asset_id);
    const sev = (t.severity || "info").toLowerCase();
    if (!cur) {
      threatsByComp.set(t.asset_id, { count: 1, maxSev: sev });
    } else {
      cur.count++;
      if (SEV_ORDER.indexOf(sev) < SEV_ORDER.indexOf(cur.maxSev)) cur.maxSev = sev;
    }
  }

  // Component nodes (no parentId)
  const compNodes: Node[] = components.map((c) => {
    const td = threatsByComp.get(c.id);
    const shape = (c.dfd_type as "external_entity" | "process" | "data_store") ?? dfdType(c.type);
    return {
      id: c.id,
      type: "component",
      position: { x: 0, y: 0 },
      data: {
        label: c.name,
        dfdShape: shape,
        compType: c.type || "other",
        trustZone: c.trust_zone || "",
        criticality: c.criticality || "",
        threatCount: td?.count ?? 0,
        maxSeverity: td?.maxSev ?? null,
      },
      draggable: true,
    } as Node;
  });

  // Edges
  const compIdSet = new Set(components.map((c) => c.id));
  const edges: Edge[] = dataFlows
    .filter((f) => compIdSet.has(f.from) && compIdSet.has(f.to))
    .map((f, i) => {
      const flowLabel = f.label || f.notes || `${f.from} → ${f.to}`;
      return {
        id: `e${i}`,
        source: f.from,
        target: f.to,
        type: "dataflow",
        data: {
          label: flowLabel,
          protocol: f.protocol,
          encrypted: f.encrypted,
        },
        markerEnd: { type: MarkerType.ArrowClosed },
      } as Edge;
    });

  // Layout component nodes with dagre
  const laidComponents = layoutComponents(compNodes, edges);

  // Build boundary nodes sized around laid-out components
  const compTypeMap: Record<string, string> = {};
  laidComponents.forEach((n) => { compTypeMap[n.id] = (n.data as any).compType; });
  const boundaryNodes = buildBoundaryNodes(laidComponents, trustBoundaries, compTypeMap);

  // Boundaries first so they render behind components
  return { nodes: [...boundaryNodes, ...laidComponents], edges };
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
  const dotColor = isDark ? "#2d3550" : "#D1D5DB";

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
      width: "100%", height: 580, bgcolor: canvasBg, borderRadius: 2,
      border: `1px solid ${isDark ? "rgba(255,255,255,0.08)" : "#E5E7EB"}`,
      overflow: "hidden",
    }}>
      <ReactFlow
        nodes={nodes} edges={edges}
        onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
        nodeTypes={NODE_TYPES} edgeTypes={EDGE_TYPES}
        fitView fitViewOptions={{ padding: 0.15 }}
        minZoom={0.2} maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
      >
        <Background color={dotColor} gap={20} size={1} />
        <Controls showInteractive={false}
          style={{ bottom: 12, right: 12, left: "auto", top: "auto" }} />
        <MiniMap
          nodeColor={(n) => {
            if (n.type === "boundary") return "transparent";
            const shape = (n.data as any)?.dfdShape as string;
            return shape === "external_entity" ? "#6B7280"
              : shape === "data_store" ? "#6B7280"
              : "#4285F4";
          }}
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
      {/* External Entity */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 36, height: 22, border: `2px solid ${border}`, flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>External Entity</Typography>
      </Box>
      {/* Process */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 26, height: 26, border: `2px solid ${border}`, borderRadius: "50%", flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>Process</Typography>
      </Box>
      {/* Data Store */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 42, height: 18, borderTop: `2px solid ${border}`, borderBottom: `2px solid ${border}`, flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>Data Store</Typography>
      </Box>
      {/* Trust Boundary */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 36, height: 22, border: "2px dashed #EA4335", borderRadius: "3px", flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>Trust Boundary (drag to resize)</Typography>
      </Box>
      {/* Flows */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 32, height: 2, bgcolor: "#5CB85C", flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>Encrypted</Typography>
      </Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Box sx={{ width: 32, height: 2, background: "repeating-linear-gradient(90deg,#D9534F 0,#D9534F 6px,transparent 6px,transparent 9px)", flexShrink: 0 }} />
        <Typography variant="caption" sx={{ color: "text.secondary" }}>Unencrypted</Typography>
      </Box>
    </Box>
  );
}

// ── Public component ──────────────────────────────────────────────────────────

interface Props {
  components: Component[];
  dataFlows: DataFlow[];
  threats: Threat[];
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
            {critCount} critical threat{critCount > 1 ? "s" : ""} — nodes with red badge
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
