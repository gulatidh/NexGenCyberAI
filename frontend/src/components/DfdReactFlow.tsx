/**
 * Threat Model DFD — security-domain layout with threat actors, colored zone
 * boundaries and attack-vector edges.
 *
 * Layout: two-pass dagre.
 *   Pass 1 — lay out nodes within each trust zone independently.
 *   Pass 2 — lay out trust-zone boxes relative to each other via cross-zone flows.
 *
 * Visual semantics:
 *   Threat Actor    → red/orange rectangle with ⚠ icon (external entity)
 *   External Entity → plain rectangle (user, browser, CDN)
 *   Process         → circle (web app, API, service)
 *   Data Store      → Yourdon parallel-line (DB, storage, secrets)
 *   Trust Boundary  → zone-colored dashed box, labeled, resizable
 *   Attack Vector   → red dashed arrow with orange pill label
 *   Data Flow       → green pill label (encrypted) / red dashed (unencrypted)
 */
import React, { useEffect, useMemo } from "react";
import { Box, Typography, Tooltip, Chip, useTheme } from "@mui/material";
import { Warning, BugReport, Person } from "@mui/icons-material";
import {
  ReactFlow, Background, Controls, MiniMap,
  useNodesState, useEdgesState, ReactFlowProvider,
  Handle, Position, BaseEdge, EdgeLabelRenderer, getBezierPath,
  MarkerType, NodeResizer,
  type Node, type Edge, type NodeTypes, type EdgeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import * as dagreLib from "@dagrejs/dagre";

// ── Security-domain zone → visual style ──────────────────────────────────────

interface ZoneStyle { border: string; bg: string; label: string; }

function zoneStyle(zone: string): ZoneStyle {
  const z = (zone || "").toLowerCase();
  if (/internet|untrust|external|attacker/.test(z))
    return { border: "#EA4335", bg: "rgba(234,67,53,0.06)", label: "#EA4335" };
  if (/dmz|perimeter|edge/.test(z))
    return { border: "#F9AB00", bg: "rgba(249,171,0,0.06)", label: "#E37400" };
  if (/corporate|internal|private|company/.test(z))
    return { border: "#1A73E8", bg: "rgba(26,115,232,0.06)", label: "#1A73E8" };
  if (/vendor|cloud|third|partner|saas/.test(z))
    return { border: "#FF7043", bg: "rgba(255,112,67,0.06)", label: "#FF7043" };
  if (/database|data.tier|data.store|restricted|storage/.test(z))
    return { border: "#9C27B0", bg: "rgba(156,39,176,0.06)", label: "#9C27B0" };
  if (/manage|admin|privilege|control|zone/.test(z))
    return { border: "#00897B", bg: "rgba(0,137,123,0.06)", label: "#00897B" };
  return { border: "#EA4335", bg: "rgba(234,67,53,0.04)", label: "#EA4335" };
}

// ── DFD shape classifier ──────────────────────────────────────────────────────

type DfdShape = "external_entity" | "process" | "data_store";

function toDfdShape(compType: string, explicitDfdType?: string): DfdShape {
  const e = (explicitDfdType || "").toLowerCase();
  if (e === "external_entity") return "external_entity";
  if (e === "data_store")      return "data_store";
  if (e === "process")         return "process";
  const t = (compType || "").toLowerCase();
  if (t === "user" || t === "endpoint" || t === "threat_actor") return "external_entity";
  if (t === "database" || t === "storage" || t === "secret-store" || t === "repo") return "data_store";
  return "process";
}

// ── Node dimensions ───────────────────────────────────────────────────────────

const DIM: Record<DfdShape, { w: number; h: number }> = {
  external_entity: { w: 110, h: 60 },
  process:         { w: 88,  h: 88 },
  data_store:      { w: 130, h: 48 },
};

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853",
};

// ── Threat badge ──────────────────────────────────────────────────────────────

function ThreatBadge({ count, maxSev }: { count: number; maxSev: string | null }) {
  if (!count || !maxSev) return null;
  const bg = SEV_COLOR[maxSev] ?? "#78909C";
  return (
    <Tooltip title={`${count} threat${count > 1 ? "s" : ""} · max: ${maxSev}`}>
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
  const isThreatActor = !!data.isThreatActor;
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

  // ── Threat Actor: distinctive red node ──────────────────────────────────────
  if (isThreatActor) {
    const actorType = (data.threatActorType as string || "external_attacker").replace(/_/g, " ");
    const iconEl = actorType.includes("insider")
      ? <Person sx={{ fontSize: 18, color: "#EA4335" }} />
      : <BugReport sx={{ fontSize: 18, color: "#EA4335" }} />;
    return (
      <Box sx={{ position: "relative", width: DIM.external_entity.w }}>
        {handles}
        <Box sx={{
          width: DIM.external_entity.w, minHeight: 70,
          border: "2px solid #EA4335",
          bgcolor: isDark ? "rgba(234,67,53,0.12)" : "rgba(234,67,53,0.08)",
          borderRadius: "4px",
          display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center",
          gap: 0.5, px: 1, py: 1,
        }}>
          {iconEl}
          <Typography sx={{
            fontSize: 10, fontWeight: 700, color: "#EA4335",
            textAlign: "center", lineHeight: 1.3,
            overflow: "hidden", display: "-webkit-box",
            WebkitLineClamp: 2, WebkitBoxOrient: "vertical", wordBreak: "break-word",
          }}>
            {label}
          </Typography>
          <Typography sx={{ fontSize: 8.5, color: "#EA433599", fontStyle: "italic" }}>
            {actorType}
          </Typography>
        </Box>
        <ThreatBadge count={threatCount} maxSev={maxSev} />
      </Box>
    );
  }

  // ── Standard shapes ──────────────────────────────────────────────────────────
  const borderColor = isDark ? "#9E9E9E" : "#444";
  const textColor   = isDark ? "#E0E0E0" : "#212121";

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

  // data_store — Yourdon parallel-line
  return (
    <Box sx={{ position: "relative", width: DIM.data_store.w }}>
      {handles}
      <Box sx={{
        width: DIM.data_store.w, height: DIM.data_store.h,
        borderTop: `2px solid ${borderColor}`, borderBottom: `2px solid ${borderColor}`,
        bgcolor: "transparent",
        display: "flex", alignItems: "center", px: 1.5,
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

// ── Trust-boundary parent node ────────────────────────────────────────────────

function BoundaryNode({ selected, data }: { selected?: boolean; data: Record<string, any> }) {
  const { border, bg, label: labelColor } = zoneStyle(data.label as string ?? "");
  return (
    <>
      <NodeResizer
        color={border}
        isVisible={!!selected}
        minWidth={220} minHeight={140}
        lineStyle={{ borderWidth: 2 }}
        handleStyle={{ width: 10, height: 10, borderRadius: 2 }}
      />
      <Box sx={{
        width: "100%", height: "100%",
        border: `2px dashed ${border}`, borderRadius: "4px",
        bgcolor: bg, position: "relative",
      }}>
        <Box sx={{
          position: "absolute", top: -13, left: 10,
          bgcolor: "background.paper", px: 0.75, py: 0,
          border: `1px solid ${border}`, borderRadius: "3px",
        }}>
          <Typography sx={{ fontSize: 10, fontWeight: 700, color: labelColor, whiteSpace: "nowrap" }}>
            {data.label as string}
          </Typography>
        </Box>
      </Box>
    </>
  );
}

// ── Data-flow / attack-vector edge ────────────────────────────────────────────

function DataFlowEdge({ id, sourceX, sourceY, targetX, targetY, data }: any) {
  const [path, lx, ly] = getBezierPath({ sourceX, sourceY, targetX, targetY });
  const isAttack   = !!data?.isAttackVector;
  const encrypted  = data?.encrypted !== false;

  const stroke     = isAttack ? "#EA4335" : (encrypted ? "#5CB85C" : "#D9534F");
  const dash       = (isAttack || !encrypted) ? "6 3" : undefined;
  const strokeW    = isAttack ? 2 : 1.5;
  const pillBg     = isAttack ? "#FEECE9" : "#DFF0D8";
  const pillBorder = isAttack ? "#EA4335" : "#5CB85C";
  const pillText   = isAttack ? "#C0392B" : "#2D6A2D";

  return (
    <>
      <BaseEdge
        id={id} path={path}
        style={{ stroke, strokeWidth: strokeW, strokeDasharray: dash }}
        markerEnd={MarkerType.ArrowClosed as any}
      />
      {data?.label && (
        <EdgeLabelRenderer>
          <Box
            className="nodrag nopan"
            sx={{
              position: "absolute",
              transform: `translate(-50%,-50%) translate(${lx}px,${ly}px)`,
              bgcolor: pillBg, border: `1px solid ${pillBorder}`,
              color: pillText, borderRadius: "4px",
              px: 0.75, py: 0.25, fontSize: 10, fontWeight: 600,
              pointerEvents: "none", whiteSpace: "nowrap",
              maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis",
              boxShadow: "0 1px 3px rgba(0,0,0,0.12)",
            }}
          >
            {isAttack && "⚠ "}{data.label}
          </Box>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

const NODE_TYPES: NodeTypes = { component: ComponentNode, boundary: BoundaryNode };
const EDGE_TYPES: EdgeTypes = { dataflow: DataFlowEdge };

// ── Two-pass dagre layout ─────────────────────────────────────────────────────

const PAD_INNER = 32;
const PAD_LABEL = 26;

function buildGraph(
  components: ComponentInput[],
  dataFlows: DataFlowInput[],
  threats: ThreatInput[],
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

  const shapeOf: Record<string, DfdShape> = {};
  components.forEach((c) => { shapeOf[c.id] = toDfdShape(c.type, c.dfd_type); });

  const DEFAULT_ZONE = "Corporate Network";
  const compIdSet = new Set(components.map((c) => c.id));

  // Normalise zone name (legacy "public"/"private"/"data-tier" → new names)
  function normZone(z: string): string {
    const l = (z || "").toLowerCase().trim();
    if (!l || l === "private" || l === "internal") return "Corporate Network";
    if (l === "public" || l === "internet") return "Internet";
    if (l === "data-tier") return "Database Tier";
    if (l === "management") return "Management Zone";
    if (l === "dmz") return "DMZ";
    // Already a good name
    return z;
  }

  // Group components by normalised zone
  const zoneMap = new Map<string, ComponentInput[]>();
  components.forEach((c) => {
    const z = normZone(c.trust_zone || DEFAULT_ZONE);
    if (!zoneMap.has(z)) zoneMap.set(z, []);
    zoneMap.get(z)!.push({ ...c, trust_zone: z });
  });

  // ── Pass 1: layout within each zone ───────────────────────────────────────

  type ZoneLayout = {
    nodes: Record<string, { rx: number; ry: number }>;
    w: number; h: number;
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
    dataFlows.forEach((f) => {
      const fz = normZone(components.find((c) => c.id === f.from)?.trust_zone || DEFAULT_ZONE);
      const tz = normZone(components.find((c) => c.id === f.to)?.trust_zone || DEFAULT_ZONE);
      if (fz === zone && tz === zone && compIdSet.has(f.from) && compIdSet.has(f.to)) {
        try { g.setEdge(f.from, f.to); } catch { /* ignore */ }
      }
    });
    dagre.layout(g);

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    comps.forEach((c) => {
      const pos = g.node(c.id);
      if (!pos) return;
      const d = DIM[shapeOf[c.id]] ?? DIM.process;
      minX = Math.min(minX, pos.x - d.w / 2); minY = Math.min(minY, pos.y - d.h / 2);
      maxX = Math.max(maxX, pos.x + d.w / 2); maxY = Math.max(maxY, pos.y + d.h / 2);
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
  const seenZE = new Set<string>();
  dataFlows.forEach((f) => {
    const fz = normZone(components.find((c) => c.id === f.from)?.trust_zone || DEFAULT_ZONE);
    const tz = normZone(components.find((c) => c.id === f.to)?.trust_zone || DEFAULT_ZONE);
    if (fz !== tz) {
      const key = `${fz}→${tz}`;
      if (!seenZE.has(key)) { seenZE.add(key); try { zoneG.setEdge(fz, tz); } catch { /* ignore */ } }
    }
  });
  dagre.layout(zoneG);

  // ── Assemble React Flow nodes ──────────────────────────────────────────────

  const rfNodes: Node[] = [];

  zones.forEach((zone, zi) => {
    const zl   = zoneLayouts.get(zone)!;
    const zPos = zoneG.node(zone);
    if (!zPos) return;

    const bId = `boundary-${zi}`;
    rfNodes.push({
      id: bId, type: "boundary",
      position: { x: zPos.x - zl.w / 2, y: zPos.y - zl.h / 2 },
      style: { width: zl.w, height: zl.h },
      data: { label: zone },
      zIndex: -1, draggable: true, selectable: true,
    } as Node);

    (zoneMap.get(zone) || []).forEach((c) => {
      const rl = zl.nodes[c.id];
      if (!rl) return;
      const td = threatMap.get(c.id);
      rfNodes.push({
        id: c.id, type: "component",
        parentId: bId,
        extent: "parent" as const,
        position: { x: rl.rx, y: rl.ry },
        data: {
          label: c.name,
          dfdShape: shapeOf[c.id],
          compType: c.type || "other",
          isThreatActor: !!(c as any).is_threat_actor,
          threatActorType: (c as any).threat_actor_type || null,
          trustZone: zone,
          criticality: c.criticality || "",
          threatCount: td?.count ?? 0,
          maxSeverity: td?.maxSev ?? null,
        },
        draggable: true, zIndex: 1,
      } as Node);
    });
  });

  // ── Edges ──────────────────────────────────────────────────────────────────

  const rfEdges: Edge[] = dataFlows
    .filter((f) => compIdSet.has(f.from) && compIdSet.has(f.to))
    .map((f, i) => ({
      id: `e${i}`,
      source: f.from, target: f.to,
      type: "dataflow",
      data: {
        label: f.label || f.notes || f.protocol || "data",
        protocol: f.protocol,
        encrypted: f.encrypted,
        isAttackVector: !!(f as any).is_attack_vector,
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
  is_threat_actor?: boolean; threat_actor_type?: string;
}
interface DataFlowInput {
  from: string; to: string; protocol: string; data: string;
  encrypted: boolean; label?: string; notes?: string;
  is_attack_vector?: boolean;
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
    () => buildGraph(components, dataFlows, threats),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [components, dataFlows, threats],
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(rfNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(rfEdges);

  useEffect(() => { setNodes(rfNodes); }, [rfNodes, setNodes]);
  useEffect(() => { setEdges(rfEdges); }, [rfEdges, setEdges]);

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

  const attackEdgeCount = rfEdges.filter((e) => (e.data as any)?.isAttackVector).length;
  const threatActorCount = components.filter((c) => c.is_threat_actor).length;

  return (
    <Box>
      {(attackEdgeCount > 0 || threatActorCount > 0) && (
        <Box sx={{
          display: "flex", gap: 1, mb: 1, flexWrap: "wrap",
        }}>
          {threatActorCount > 0 && (
            <Chip size="small" icon={<BugReport sx={{ fontSize: 14 }} />}
              label={`${threatActorCount} threat actor${threatActorCount > 1 ? "s" : ""}`}
              sx={{ bgcolor: "rgba(234,67,53,0.1)", color: "#EA4335", fontWeight: 700, fontSize: 11 }} />
          )}
          {attackEdgeCount > 0 && (
            <Chip size="small" icon={<Warning sx={{ fontSize: 14 }} />}
              label={`${attackEdgeCount} attack vector${attackEdgeCount > 1 ? "s" : ""}`}
              sx={{ bgcolor: "rgba(234,67,53,0.08)", color: "#C0392B", fontWeight: 700, fontSize: 11 }} />
          )}
        </Box>
      )}
      <Box sx={{
        width: "100%", height: 640,
        bgcolor: isDark ? "#111827" : "#FFFFFF",
        borderRadius: 2,
        border: `1px solid ${isDark ? "rgba(255,255,255,0.08)" : "#E5E7EB"}`,
        overflow: "hidden",
      }}>
        <ReactFlow
          nodes={nodes} edges={edges}
          onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
          nodeTypes={NODE_TYPES} edgeTypes={EDGE_TYPES}
          fitView fitViewOptions={{ padding: 0.12 }}
          minZoom={0.12} maxZoom={2.5}
          proOptions={{ hideAttribution: true }}
        >
          <Background color={isDark ? "#1f2937" : "#E5E7EB"} gap={20} size={1} />
          <Controls showInteractive={false}
            style={{ bottom: 12, right: 12, left: "auto", top: "auto" }} />
          <MiniMap
            nodeColor={(n) => {
              if (n.type === "boundary") return "transparent";
              return (n.data as any)?.isThreatActor ? "#EA4335" : "#4285F4";
            }}
            maskColor={isDark ? "rgba(10,15,30,0.6)" : "rgba(220,228,240,0.6)"}
            style={{ bottom: 12, left: 12, width: 140, height: 90 }}
            zoomable pannable
          />
        </ReactFlow>
      </Box>
    </Box>
  );
}

// ── Legend ────────────────────────────────────────────────────────────────────

function DfdLegend() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const border = isDark ? "#9E9E9E" : "#444";

  const zones = [
    { label: "Internet",        color: "#EA4335" },
    { label: "DMZ",             color: "#F9AB00" },
    { label: "Corporate",       color: "#1A73E8" },
    { label: "Vendor Cloud",    color: "#FF7043" },
    { label: "Database Tier",   color: "#9C27B0" },
    { label: "Management Zone", color: "#00897B" },
  ];

  return (
    <Box sx={{ mt: 1.5, px: 0.5 }}>
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1.5, mb: 1, alignItems: "center" }}>
        {/* DFD shapes */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
          <BugReport sx={{ fontSize: 16, color: "#EA4335" }} />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Threat Actor</Typography>
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
          <Box sx={{ width: 28, height: 18, border: `2px solid ${border}`, flexShrink: 0 }} />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>External Entity</Typography>
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
          <Box sx={{ width: 22, height: 22, border: `2px solid ${border}`, borderRadius: "50%", flexShrink: 0 }} />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Process</Typography>
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
          <Box sx={{ width: 34, height: 14, borderTop: `2px solid ${border}`, borderBottom: `2px solid ${border}`, flexShrink: 0 }} />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Data Store</Typography>
        </Box>
        {/* Flows */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
          <Box sx={{ width: 28, height: 2, background: "repeating-linear-gradient(90deg,#EA4335 0,#EA4335 6px,transparent 6px,transparent 9px)", flexShrink: 0 }} />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Attack Vector</Typography>
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
          <Box sx={{ width: 28, height: 2, bgcolor: "#5CB85C", flexShrink: 0 }} />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Encrypted Flow</Typography>
        </Box>
      </Box>
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
        <Typography variant="caption" sx={{ color: "text.secondary", mr: 0.5 }}>Trust Zones:</Typography>
        {zones.map((z) => (
          <Box key={z.label} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <Box sx={{ width: 12, height: 12, border: `2px dashed ${z.color}`, borderRadius: "2px", flexShrink: 0 }} />
            <Typography variant="caption" sx={{ color: "text.secondary" }}>{z.label}</Typography>
          </Box>
        ))}
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
      <DfdLegend />
    </Box>
  );
}
