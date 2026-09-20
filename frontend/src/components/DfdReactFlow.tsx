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
  if (/api.tier|api.layer|api.gateway/.test(z))
    return { border: "#0097A7", bg: "rgba(0,151,167,0.06)", label: "#0097A7" };
  if (/report.server|reporting|ssrs|bi.server/.test(z))
    return { border: "#6D4C41", bg: "rgba(109,76,65,0.06)", label: "#6D4C41" };
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
  const environment = (data.environment as string) || "";
  const datacenter  = (data.datacenter  as string) || "";
  const envDcParts  = [environment, datacenter].filter(Boolean);
  const envDcLabel  = envDcParts.join(" · ");

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
    <Box sx={{ textAlign: "center" }}>
      <Typography sx={{
        fontSize: 10.5, fontWeight: 600, color: textColor,
        lineHeight: 1.3, overflow: "hidden", display: "-webkit-box",
        WebkitLineClamp: 3, WebkitBoxOrient: "vertical", wordBreak: "break-word",
      }}>
        {label}
      </Typography>
      {envDcLabel && (
        <Typography sx={{ fontSize: 8.5, color: isDark ? "#78909C" : "#757575", mt: 0.25, lineHeight: 1.2 }}>
          {envDcLabel}
        </Typography>
      )}
    </Box>
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

// ── Datacenter (Level 0) outermost node ──────────────────────────────────────

function DatacenterNode({ selected, data }: { selected?: boolean; data: Record<string, any> }) {
  const label = (data.label as string) ?? "";
  return (
    <>
      <NodeResizer color="#1e293b" isVisible={!!selected}
        minWidth={500} minHeight={400}
        lineStyle={{ borderWidth: 3 }}
        handleStyle={{ width: 10, height: 10, borderRadius: 2 }}
      />
      <Box sx={{
        width: "100%", height: "100%",
        border: "3px solid #1e293b",
        borderRadius: "12px",
        bgcolor: "rgba(30,41,59,0.025)",
        position: "relative",
      }}>
        <Box sx={{
          position: "absolute", top: -20, left: 16,
          bgcolor: "#1e293b",
          px: 1.5, py: 0.25, borderRadius: "6px",
          display: "flex", alignItems: "center", gap: 0.75,
        }}>
          <Typography sx={{
            fontSize: 13, fontWeight: 800, color: "#f1f5f9",
            whiteSpace: "nowrap", letterSpacing: "0.03em",
          }}>
            🏢 {label}
          </Typography>
        </Box>
      </Box>
    </>
  );
}

// ── Platform (Level 1) node ───────────────────────────────────────────────────

const PLATFORM_STYLE: Record<string, { border: string; bg: string }> = {
  "Azure":       { border: "#0078D4", bg: "rgba(0,120,212,0.03)" },
  "AWS":         { border: "#FF9900", bg: "rgba(255,153,0,0.03)" },
  "GCP":         { border: "#4285F4", bg: "rgba(66,133,244,0.03)" },
  "Corporate":   { border: "#34A853", bg: "rgba(52,168,83,0.03)" },
  "Internet":    { border: "#EA4335", bg: "rgba(234,67,53,0.03)" },
  "Third-Party": { border: "#9C27B0", bg: "rgba(156,39,176,0.03)" },
};

function PlatformNode({ selected, data }: { selected?: boolean; data: Record<string, any> }) {
  const label = (data.label as string) ?? "";
  const ps = PLATFORM_STYLE[label] ?? { border: "#78909C", bg: "rgba(120,144,156,0.03)" };
  return (
    <>
      <NodeResizer color={ps.border} isVisible={!!selected}
        minWidth={300} minHeight={200}
        lineStyle={{ borderWidth: 2 }}
        handleStyle={{ width: 10, height: 10, borderRadius: 2 }}
      />
      <Box sx={{
        width: "100%", height: "100%",
        border: `2px solid ${ps.border}`, borderRadius: "8px",
        bgcolor: ps.bg, position: "relative",
      }}>
        <Box sx={{
          position: "absolute", top: -15, left: 14,
          bgcolor: "background.paper", px: 1,
          border: `1.5px solid ${ps.border}`, borderRadius: "4px",
        }}>
          <Typography sx={{ fontSize: 11, fontWeight: 800, color: ps.border, whiteSpace: "nowrap", letterSpacing: "0.02em" }}>
            {label}
          </Typography>
        </Box>
      </Box>
    </>
  );
}

// ── Trust-boundary (Level 2) tier node ────────────────────────────────────────

function BoundaryNode({ selected, data }: { selected?: boolean; data: Record<string, any> }) {
  const { border, bg, label: labelColor } = zoneStyle(data.label as string ?? "");
  return (
    <>
      <NodeResizer
        color={border}
        isVisible={!!selected}
        minWidth={200} minHeight={120}
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

const NODE_TYPES: NodeTypes = { component: ComponentNode, boundary: BoundaryNode, platform: PlatformNode, datacenter: DatacenterNode };
const EDGE_TYPES: EdgeTypes = { dataflow: DataFlowEdge };

// ── Multi-pass dagre layout (datacenter → platform → tier → component) ───────

// Padding inside tier boxes
const PAD_COMP_H   = 28;  // horizontal pad each side
const PAD_COMP_TOP = 32;  // top pad (tier label space)
const PAD_COMP_BOT = 20;
// Padding inside platform boxes
const PAD_TIER_H   = 32;
const PAD_TIER_TOP = 44;  // top pad (platform label space)
const PAD_TIER_BOT = 28;
// Padding inside datacenter boxes (used only when DC level is active)
const PAD_PLAT_H   = 48;
const PAD_PLAT_TOP = 60;  // room for DC label chip
const PAD_PLAT_BOT = 40;

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
  const compIdSet = new Set(components.map((c) => c.id));

  // ── Normalizers ────────────────────────────────────────────────────────────

  function normPlatform(p: string): string {
    const l = (p || "").toLowerCase().trim();
    if (!l) return "Corporate";
    if (/^azure/.test(l) || l === "microsoft azure") return "Azure";
    if (/^aws/.test(l) || l.includes("amazon")) return "AWS";
    if (/^gcp/.test(l) || l.includes("google")) return "GCP";
    if (l === "internet" || l === "external" || l === "untrusted") return "Internet";
    if (l === "third-party" || l === "third party" || l === "vendor cloud" || l === "vendor" || l === "saas") return "Third-Party";
    if (l === "corporate" || l === "on-premises" || l === "on premises" || l === "corporate network") return "Corporate";
    return p;
  }

  function normTier(z: string): string {
    const l = (z || "").toLowerCase().trim();
    if (!l || l === "private" || l === "internal" || l === "application tier" || l === "corporate network") return "Application Tier";
    if (l === "internet" || l === "external" || l === "untrusted") return "External";
    if (l === "dmz" || l === "perimeter" || l === "edge" || l === "public") return "DMZ";
    if (l === "web tier" || l === "web") return "Web Tier";
    if (l === "api tier" || l === "api" || l === "api gateway" || l === "api layer") return "API Tier";
    if (l === "report server" || l === "reporting" || l === "ssrs" || l === "bi server") return "Report Server";
    if (l === "data tier" || l === "data-tier" || l === "database tier" || l === "database") return "Data Tier";
    if (l === "management" || l === "management zone") return "Management Zone";
    if (l === "vendor cloud" || l === "vendor") return "Application Tier";
    return z;
  }

  function getPlatform(c: ComponentInput): string {
    if (c.platform) return normPlatform(c.platform);
    const z = (c.trust_zone || "").toLowerCase();
    if (z === "internet") return "Internet";
    if (z === "vendor cloud") return "Third-Party";
    if (c.is_threat_actor) return "Internet";
    return "Corporate";
  }

  function getTier(c: ComponentInput): string {
    const z = (c.trust_zone || "").toLowerCase();
    if (z === "vendor cloud") return "Application Tier";
    if (z === "internet" && !c.is_threat_actor) return "Application Tier";
    return normTier(c.trust_zone || "");
  }

  function getDatacenter(c: ComponentInput): string {
    return (c.datacenter || "").trim();
  }

  // ── Decide whether to activate datacenter level ────────────────────────────
  // Only activate when 2+ distinct non-empty datacenter values exist.

  const uniqueDCVals = Array.from(new Set(components.map(c => getDatacenter(c))));
  const useDatacenterLevel = uniqueDCVals.filter(Boolean).length >= 2;

  // Separator unlikely to appear in user-entered names
  const S = "\x01";
  function mkGKey(c: ComponentInput): string {
    return `${getDatacenter(c)}${S}${getPlatform(c)}${S}${getTier(c)}`;
  }
  function mkPKey(dc: string, plat: string): string { return `${dc}${S}${plat}`; }

  // ── Group: (dc, platform, tier) → components ──────────────────────────────

  const groupMap = new Map<string, ComponentInput[]>();
  components.forEach((c) => {
    const k = mkGKey(c);
    if (!groupMap.has(k)) groupMap.set(k, []);
    groupMap.get(k)!.push(c);
  });

  // platKeyMap: "dc\x01platform" → Set<groupKey>
  const platKeyMap = new Map<string, Set<string>>();
  groupMap.forEach((_, gk) => {
    const [dc, plat] = gk.split(S);
    const pk = mkPKey(dc, plat);
    if (!platKeyMap.has(pk)) platKeyMap.set(pk, new Set());
    platKeyMap.get(pk)!.add(gk);
  });

  // dcMap: dc → Set<platKey>
  const dcMap = new Map<string, Set<string>>();
  platKeyMap.forEach((_, pk) => {
    const dc = pk.split(S)[0];
    if (!dcMap.has(dc)) dcMap.set(dc, new Set());
    dcMap.get(dc)!.add(pk);
  });

  // ── Pass 1: layout components within each (dc, platform, tier) group ───────

  type GroupLayout = { nodes: Record<string, { rx: number; ry: number }>; w: number; h: number };
  const groupLayouts = new Map<string, GroupLayout>();

  groupMap.forEach((comps, gk) => {
    const tier = gk.split(S)[2];
    const g = new dagre.graphlib.Graph();
    g.setDefaultEdgeLabel(() => ({}));
    g.setGraph({ rankdir: "LR", nodesep: 44, ranksep: 60 });
    comps.forEach((c) => {
      const d = DIM[shapeOf[c.id]] ?? DIM.process;
      g.setNode(c.id, { width: d.w + 20, height: d.h + 20 });
    });
    dataFlows.forEach((f) => {
      const fc = components.find((c) => c.id === f.from);
      const tc = components.find((c) => c.id === f.to);
      if (!fc || !tc) return;
      if (mkGKey(fc) === gk && mkGKey(tc) === gk && compIdSet.has(f.from) && compIdSet.has(f.to)) {
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
    if (minX === Infinity) { minX = 0; minY = 0; maxX = 140; maxY = 80; }

    const rNodes: Record<string, { rx: number; ry: number }> = {};
    comps.forEach((c) => {
      const pos = g.node(c.id);
      if (!pos) return;
      const d = DIM[shapeOf[c.id]] ?? DIM.process;
      rNodes[c.id] = {
        rx: pos.x - d.w / 2 - minX + PAD_COMP_H,
        ry: pos.y - d.h / 2 - minY + PAD_COMP_TOP,
      };
    });

    groupLayouts.set(gk, {
      nodes: rNodes,
      w: (maxX - minX) + PAD_COMP_H * 2,
      h: (maxY - minY) + PAD_COMP_TOP + PAD_COMP_BOT,
    });
  });

  // ── Pass 2: layout tier boxes within each (dc, platform) ──────────────────

  type PlatLayout = { tiers: Record<string, { rx: number; ry: number }>; w: number; h: number };
  const platLayoutMap = new Map<string, PlatLayout>();

  platKeyMap.forEach((groupKeys, pk) => {
    const g = new dagre.graphlib.Graph();
    g.setDefaultEdgeLabel(() => ({}));
    g.setGraph({ rankdir: "TB", nodesep: 36, ranksep: 48 });
    groupKeys.forEach((gk) => {
      const gl = groupLayouts.get(gk)!;
      g.setNode(gk, { width: gl.w, height: gl.h });
    });
    const seenTE = new Set<string>();
    dataFlows.forEach((f) => {
      const fc = components.find((c) => c.id === f.from);
      const tc = components.find((c) => c.id === f.to);
      if (!fc || !tc) return;
      const fPK = mkPKey(getDatacenter(fc), getPlatform(fc));
      const tPK = mkPKey(getDatacenter(tc), getPlatform(tc));
      if (fPK !== pk || tPK !== pk) return;
      const fGK = mkGKey(fc), tGK = mkGKey(tc);
      if (fGK === tGK) return;
      const ek = `${fGK}→${tGK}`;
      if (!seenTE.has(ek) && groupKeys.has(fGK) && groupKeys.has(tGK)) {
        seenTE.add(ek);
        try { g.setEdge(fGK, tGK); } catch { /* ignore */ }
      }
    });
    dagre.layout(g);

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    groupKeys.forEach((gk) => {
      const pos = g.node(gk);
      if (!pos) return;
      const gl = groupLayouts.get(gk)!;
      minX = Math.min(minX, pos.x - gl.w / 2); minY = Math.min(minY, pos.y - gl.h / 2);
      maxX = Math.max(maxX, pos.x + gl.w / 2); maxY = Math.max(maxY, pos.y + gl.h / 2);
    });
    if (minX === Infinity) { minX = 0; minY = 0; maxX = 200; maxY = 150; }

    const tiers: Record<string, { rx: number; ry: number }> = {};
    groupKeys.forEach((gk) => {
      const pos = g.node(gk);
      if (!pos) return;
      const gl = groupLayouts.get(gk)!;
      tiers[gk] = {
        rx: pos.x - gl.w / 2 - minX + PAD_TIER_H,
        ry: pos.y - gl.h / 2 - minY + PAD_TIER_TOP,
      };
    });

    platLayoutMap.set(pk, {
      tiers,
      w: (maxX - minX) + PAD_TIER_H * 2,
      h: (maxY - minY) + PAD_TIER_TOP + PAD_TIER_BOT,
    });
  });

  // ── Assemble React Flow nodes ──────────────────────────────────────────────

  const rfNodes: Node[] = [];

  if (useDatacenterLevel) {
    // ── Pass 3: layout platform boxes within each datacenter ─────────────────

    type DCLayout = { plats: Record<string, { rx: number; ry: number }>; w: number; h: number };
    const dcLayoutMap = new Map<string, DCLayout>();

    dcMap.forEach((platKeys, dc) => {
      const g = new dagre.graphlib.Graph();
      g.setDefaultEdgeLabel(() => ({}));
      g.setGraph({ rankdir: "LR", nodesep: 40, ranksep: 56 });
      platKeys.forEach((pk) => {
        const pl = platLayoutMap.get(pk)!;
        g.setNode(pk, { width: pl.w, height: pl.h });
      });
      const seenPE = new Set<string>();
      dataFlows.forEach((f) => {
        const fc = components.find((c) => c.id === f.from);
        const tc = components.find((c) => c.id === f.to);
        if (!fc || !tc) return;
        const fDC = getDatacenter(fc), tDC = getDatacenter(tc);
        if (fDC !== dc || tDC !== dc) return;
        const fPK = mkPKey(fDC, getPlatform(fc));
        const tPK = mkPKey(tDC, getPlatform(tc));
        if (fPK === tPK) return;
        const ek = `${fPK}→${tPK}`;
        if (!seenPE.has(ek) && platKeys.has(fPK) && platKeys.has(tPK)) {
          seenPE.add(ek);
          try { g.setEdge(fPK, tPK); } catch { /* ignore */ }
        }
      });
      dagre.layout(g);

      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      platKeys.forEach((pk) => {
        const pos = g.node(pk);
        if (!pos) return;
        const pl = platLayoutMap.get(pk)!;
        minX = Math.min(minX, pos.x - pl.w / 2); minY = Math.min(minY, pos.y - pl.h / 2);
        maxX = Math.max(maxX, pos.x + pl.w / 2); maxY = Math.max(maxY, pos.y + pl.h / 2);
      });
      if (minX === Infinity) { minX = 0; minY = 0; maxX = 300; maxY = 200; }

      const plats: Record<string, { rx: number; ry: number }> = {};
      platKeys.forEach((pk) => {
        const pos = g.node(pk);
        if (!pos) return;
        const pl = platLayoutMap.get(pk)!;
        plats[pk] = {
          rx: pos.x - pl.w / 2 - minX + PAD_PLAT_H,
          ry: pos.y - pl.h / 2 - minY + PAD_PLAT_TOP,
        };
      });

      dcLayoutMap.set(dc, {
        plats,
        w: (maxX - minX) + PAD_PLAT_H * 2,
        h: (maxY - minY) + PAD_PLAT_TOP + PAD_PLAT_BOT,
      });
    });

    // ── Pass 4: layout datacenter boxes ────────────────────────────────────────

    const dcG = new dagre.graphlib.Graph();
    dcG.setDefaultEdgeLabel(() => ({}));
    dcG.setGraph({ rankdir: "LR", nodesep: 72, ranksep: 100, marginx: 48, marginy: 48 });
    const dcs = Array.from(dcMap.keys());
    dcs.forEach((dc) => {
      const dl = dcLayoutMap.get(dc)!;
      dcG.setNode(dc, { width: dl.w, height: dl.h });
    });
    const seenDCE = new Set<string>();
    dataFlows.forEach((f) => {
      const fc = components.find((c) => c.id === f.from);
      const tc = components.find((c) => c.id === f.to);
      if (!fc || !tc) return;
      const fDC = getDatacenter(fc), tDC = getDatacenter(tc);
      if (fDC === tDC) return;
      const ek = `${fDC}→${tDC}`;
      if (!seenDCE.has(ek)) {
        seenDCE.add(ek);
        try { dcG.setEdge(fDC, tDC); } catch { /* ignore */ }
      }
    });
    dagre.layout(dcG);

    // Assemble: DC → Platform → Tier → Component
    dcs.forEach((dc, di) => {
      const dl = dcLayoutMap.get(dc)!;
      const dcPos = dcG.node(dc);
      if (!dcPos) return;

      const dcId = `dc-${di}`;
      rfNodes.push({
        id: dcId, type: "datacenter",
        position: { x: dcPos.x - dl.w / 2, y: dcPos.y - dl.h / 2 },
        style: { width: dl.w, height: dl.h },
        data: { label: dc || "Shared Infrastructure" },
        zIndex: -3, draggable: true, selectable: true,
      } as Node);

      Array.from(dcMap.get(dc)!).forEach((pk, pi) => {
        const pl = platLayoutMap.get(pk)!;
        const platPos = dl.plats[pk];
        if (!platPos) return;
        const platform = pk.split(S)[1];

        const pId = `platform-${di}-${pi}`;
        rfNodes.push({
          id: pId, type: "platform",
          parentId: dcId,
          extent: "parent" as const,
          position: { x: platPos.rx, y: platPos.ry },
          style: { width: pl.w, height: pl.h },
          data: { label: platform },
          zIndex: -2, draggable: true, selectable: true,
        } as Node);

        Array.from(platKeyMap.get(pk)!).forEach((gk, ti) => {
          const gl = groupLayouts.get(gk)!;
          const tierPos = pl.tiers[gk];
          if (!tierPos) return;
          const tier = gk.split(S)[2];

          const tId = `tier-${di}-${pi}-${ti}`;
          rfNodes.push({
            id: tId, type: "boundary",
            parentId: pId,
            extent: "parent" as const,
            position: { x: tierPos.rx, y: tierPos.ry },
            style: { width: gl.w, height: gl.h },
            data: { label: tier },
            zIndex: -1, draggable: true, selectable: true,
          } as Node);

          (groupMap.get(gk) || []).forEach((c) => {
            const rl = gl.nodes[c.id];
            if (!rl) return;
            const td = threatMap.get(c.id);
            rfNodes.push({
              id: c.id, type: "component",
              parentId: tId,
              extent: "parent" as const,
              position: { x: rl.rx, y: rl.ry },
              data: {
                label: c.name, dfdShape: shapeOf[c.id], compType: c.type || "other",
                isThreatActor: !!c.is_threat_actor, threatActorType: c.threat_actor_type || null,
                platform, trustZone: tier, criticality: c.criticality || "",
                environment: c.environment || "", datacenter: c.datacenter || "",
                threatCount: td?.count ?? 0, maxSeverity: td?.maxSev ?? null,
              },
              draggable: true, zIndex: 1,
            } as Node);
          });
        });
      });
    });

  } else {
    // ── Pass 3 (no DC level): layout platform boxes directly ──────────────────

    const platG = new dagre.graphlib.Graph();
    platG.setDefaultEdgeLabel(() => ({}));
    platG.setGraph({ rankdir: "LR", nodesep: 64, ranksep: 88, marginx: 48, marginy: 48 });
    const platKeys = Array.from(platKeyMap.keys());
    platKeys.forEach((pk) => {
      const pl = platLayoutMap.get(pk)!;
      platG.setNode(pk, { width: pl.w, height: pl.h });
    });
    const seenPE = new Set<string>();
    dataFlows.forEach((f) => {
      const fc = components.find((c) => c.id === f.from);
      const tc = components.find((c) => c.id === f.to);
      if (!fc || !tc) return;
      const fPK = mkPKey(getDatacenter(fc), getPlatform(fc));
      const tPK = mkPKey(getDatacenter(tc), getPlatform(tc));
      if (fPK === tPK) return;
      const ek = `${fPK}→${tPK}`;
      if (!seenPE.has(ek)) { seenPE.add(ek); try { platG.setEdge(fPK, tPK); } catch { /* ignore */ } }
    });
    dagre.layout(platG);

    // Assemble: Platform → Tier → Component (existing behavior)
    platKeys.forEach((pk, pi) => {
      const pl = platLayoutMap.get(pk)!;
      const pPos = platG.node(pk);
      if (!pPos) return;
      const platform = pk.split(S)[1];

      const pId = `platform-${pi}`;
      rfNodes.push({
        id: pId, type: "platform",
        position: { x: pPos.x - pl.w / 2, y: pPos.y - pl.h / 2 },
        style: { width: pl.w, height: pl.h },
        data: { label: platform },
        zIndex: -2, draggable: true, selectable: true,
      } as Node);

      Array.from(platKeyMap.get(pk)!).forEach((gk, ti) => {
        const gl = groupLayouts.get(gk)!;
        const tierPos = pl.tiers[gk];
        if (!tierPos) return;
        const tier = gk.split(S)[2];

        const tId = `tier-${pi}-${ti}`;
        rfNodes.push({
          id: tId, type: "boundary",
          parentId: pId,
          extent: "parent" as const,
          position: { x: tierPos.rx, y: tierPos.ry },
          style: { width: gl.w, height: gl.h },
          data: { label: tier },
          zIndex: -1, draggable: true, selectable: true,
        } as Node);

        (groupMap.get(gk) || []).forEach((c) => {
          const rl = gl.nodes[c.id];
          if (!rl) return;
          const td = threatMap.get(c.id);
          rfNodes.push({
            id: c.id, type: "component",
            parentId: tId,
            extent: "parent" as const,
            position: { x: rl.rx, y: rl.ry },
            data: {
              label: c.name, dfdShape: shapeOf[c.id], compType: c.type || "other",
              isThreatActor: !!c.is_threat_actor, threatActorType: c.threat_actor_type || null,
              platform, trustZone: tier, criticality: c.criticality || "",
              environment: c.environment || "", datacenter: c.datacenter || "",
              threatCount: td?.count ?? 0, maxSeverity: td?.maxSev ?? null,
            },
            draggable: true, zIndex: 1,
          } as Node);
        });
      });
    });
  }

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
  platform?: string; trust_zone: string; criticality: string;
  is_threat_actor?: boolean; threat_actor_type?: string;
  environment?: string; datacenter?: string;
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
              if (n.type === "platform") return "transparent";
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

  const platforms = [
    { label: "Azure",       color: "#0078D4" },
    { label: "AWS",         color: "#FF9900" },
    { label: "GCP",         color: "#4285F4" },
    { label: "Corporate",   color: "#34A853" },
    { label: "Internet",    color: "#EA4335" },
    { label: "Third-Party", color: "#9C27B0" },
  ];
  const tiers = [
    { label: "Internet",         color: "#EA4335" },
    { label: "DMZ",              color: "#F9AB00" },
    { label: "Web Tier",         color: "#FF7043" },
    { label: "API Tier",         color: "#0097A7" },
    { label: "Application Tier", color: "#1A73E8" },
    { label: "Report Server",    color: "#6D4C41" },
    { label: "Data Tier",        color: "#9C27B0" },
    { label: "Management Zone",  color: "#00897B" },
    { label: "External",         color: "#EA4335" },
  ];

  return (
    <Box sx={{ mt: 1.5, px: 0.5 }}>
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1.5, mb: 1, alignItems: "center" }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
          <Box sx={{ width: 32, height: 20, border: "3px solid #1e293b", borderRadius: "3px", flexShrink: 0 }} />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Datacenter</Typography>
        </Box>
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
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
          <Box sx={{ width: 28, height: 2, background: "repeating-linear-gradient(90deg,#EA4335 0,#EA4335 6px,transparent 6px,transparent 9px)", flexShrink: 0 }} />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Attack Vector</Typography>
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
          <Box sx={{ width: 28, height: 2, bgcolor: "#5CB85C", flexShrink: 0 }} />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Encrypted Flow</Typography>
        </Box>
      </Box>
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 0.5 }}>
        <Typography variant="caption" sx={{ color: "text.secondary", mr: 0.5, fontWeight: 600 }}>Platforms:</Typography>
        {platforms.map((p) => (
          <Box key={p.label} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <Box sx={{ width: 12, height: 12, border: `2px solid ${p.color}`, borderRadius: "2px", flexShrink: 0 }} />
            <Typography variant="caption" sx={{ color: "text.secondary" }}>{p.label}</Typography>
          </Box>
        ))}
      </Box>
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
        <Typography variant="caption" sx={{ color: "text.secondary", mr: 0.5, fontWeight: 600 }}>Security Tiers:</Typography>
        {tiers.map((z) => (
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
