import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import { useQuery } from "@tanstack/react-query";
import {
  Box, Typography, Chip, CircularProgress, Alert, Card, CardContent,
  FormControl, InputLabel, Select, MenuItem,
} from "@mui/material";
import {
  AccountTree, VpnKey, Security, SyncAlt,
  Storage, Loop, BugReport, GppBad, Dns, Public, Warning,
} from "@mui/icons-material";
import {
  ReactFlow, Background, Controls, MiniMap,
  useNodesState, useEdgesState,
  MarkerType, Handle, Position,
  BaseEdge, EdgeLabelRenderer, getBezierPath,
  ReactFlowProvider,
  type Node, type Edge, type NodeTypes, type EdgeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import * as dagreLib from "@dagrejs/dagre";
import { attackPathApi, scansApi, projectsApi } from "../services/api";

// ── Types ────────────────────────────────────────────────────────────────────

interface AttackNode {
  id: string;
  label: string;
  type: string;
  severity: string | null;
  cvss?: number;
  finding_id?: string;
  resource?: string;
}

interface AttackEdge {
  source: string;
  target: string;
  label: string;
  weight: number;
}

interface AttackPath {
  label: string;
  nodes: string[];
}

export interface AttackPathData {
  nodes: AttackNode[];
  edges: AttackEdge[];
  paths: AttackPath[];
  stats: { total_findings: number; critical: number; phases_present: string[] };
}

// ── Visual config ─────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335",
  high:     "#FF7043",
  medium:   "#FBBC04",
  low:      "#34A853",
  info:     "#78909C",
};

const TYPE_CFG: Record<string, { color: string; icon: React.ReactNode }> = {
  attacker:             { color: "#2E7D32", icon: <Public     sx={{ fontSize: 26, color: "#fff" }} /> },
  initial_access:       { color: "#C62828", icon: <Warning    sx={{ fontSize: 26, color: "#fff" }} /> },
  vulnerability:        { color: "#B71C1C", icon: <BugReport  sx={{ fontSize: 26, color: "#fff" }} /> },
  credential_access:    { color: "#AD1457", icon: <VpnKey     sx={{ fontSize: 26, color: "#fff" }} /> },
  privilege_escalation: { color: "#6A1B9A", icon: <Security   sx={{ fontSize: 26, color: "#fff" }} /> },
  lateral_movement:     { color: "#E64A19", icon: <SyncAlt    sx={{ fontSize: 26, color: "#fff" }} /> },
  data_access:          { color: "#00695C", icon: <Storage    sx={{ fontSize: 26, color: "#fff" }} /> },
  persistence:          { color: "#4E342E", icon: <Loop       sx={{ fontSize: 26, color: "#fff" }} /> },
  impact:               { color: "#B71C1C", icon: <GppBad     sx={{ fontSize: 26, color: "#fff" }} /> },
  resource:             { color: "#0277BD", icon: <Dns        sx={{ fontSize: 26, color: "#fff" }} /> },
};

const FALLBACK_CFG = { color: "#607D8B", icon: <BugReport sx={{ fontSize: 26, color: "#fff" }} /> };

const NODE_D = 88; // circle diameter

// ── Dagre layout (LR) ─────────────────────────────────────────────────────────

function layoutGraph(nodes: Node[], edges: Edge[]): { nodes: Node[]; edges: Edge[] } {
  // @dagrejs/dagre exports as a module with graphlib inside
  const dagre: any = (dagreLib as any).default ?? dagreLib;
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "LR", nodesep: 90, ranksep: 170, marginx: 60, marginy: 60 });

  nodes.forEach((n) => g.setNode(n.id, { width: NODE_D + 40, height: NODE_D + 56 }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);

  return {
    nodes: nodes.map((n) => {
      const { x, y } = g.node(n.id);
      return { ...n, position: { x: x - (NODE_D + 40) / 2, y: y - (NODE_D + 56) / 2 } };
    }),
    edges,
  };
}

// ── Custom circular node ──────────────────────────────────────────────────────

function CircleNode({ id, data }: { id: string; data: Record<string, any> }) {
  const cfg = TYPE_CFG[data.attackType as string] ?? FALLBACK_CFG;
  const sev  = data.severity as string | null;
  const sevColor = sev ? (SEV_COLOR[sev] ?? cfg.color) : cfg.color;
  const isCrit   = data.isCritPath as boolean;
  const collapsed = data.collapsed as boolean;
  const childCount = (data.childCount as number) ?? 0;
  const hasChildren = childCount > 0;
  const onToggle = data.onToggle as ((id: string) => void) | null;

  return (
    <Box
      onClick={hasChildren && onToggle ? () => onToggle(id) : undefined}
      sx={{
        display: "flex", flexDirection: "column", alignItems: "center",
        cursor: hasChildren && onToggle ? "pointer" : "default",
        userSelect: "none",
        width: NODE_D + 40,
      }}
    >
      <Handle type="target" position={Position.Left}  style={{ opacity: 0 }} />

      {/* Circle */}
      <Box sx={{ position: "relative" }}>
        {/* Critical glow ring */}
        {isCrit && (
          <Box sx={{
            position: "absolute", inset: -7, borderRadius: "50%",
            border: "3px solid #EA4335",
            boxShadow: "0 0 18px #EA4335aa",
            pointerEvents: "none",
          }} />
        )}
        <Box sx={{
          width: NODE_D, height: NODE_D, borderRadius: "50%",
          border: `4px solid ${sevColor}`,
          background: `radial-gradient(circle at 35% 35%, ${cfg.color}dd, ${cfg.color})`,
          display: "flex", alignItems: "center", justifyContent: "center",
          boxShadow: `0 6px 20px ${cfg.color}44`,
          position: "relative",
          transition: "transform 0.15s",
          "&:hover": hasChildren ? { transform: "scale(1.06)" } : {},
        }}>
          {cfg.icon}

          {/* Severity badge */}
          {sev && data.attackType !== "attacker" && data.attackType !== "resource" && (
            <Box sx={{
              position: "absolute", bottom: 3, right: 3,
              width: 20, height: 20, borderRadius: "50%",
              bgcolor: sevColor, border: "2px solid #fff",
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <Typography sx={{ fontSize: 8, color: "#fff", fontWeight: 700, lineHeight: 1 }}>
                {(sev[0] ?? "").toUpperCase()}
              </Typography>
            </Box>
          )}
        </Box>

        {/* Collapsed count bubble */}
        {collapsed && childCount > 0 && (
          <Box sx={{
            position: "absolute", top: -6, right: -6,
            width: 22, height: 22, borderRadius: "50%",
            bgcolor: "#FF6F00", border: "2px solid #fff",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 9, color: "#fff", fontWeight: 700,
          }}>
            {childCount}
          </Box>
        )}
      </Box>

      {/* Label */}
      <Typography sx={{
        mt: 0.75, fontSize: 10.5, fontWeight: 700, textAlign: "center",
        color: "#1a1a2e", lineHeight: 1.3, maxWidth: NODE_D + 36,
        overflow: "hidden",
        display: "-webkit-box",
        WebkitLineClamp: 2,
        WebkitBoxOrient: "vertical",
      }}>
        {data.label as string}
      </Typography>

      {/* Sub-label */}
      <Typography sx={{ fontSize: 9, color: "#777", textAlign: "center", maxWidth: NODE_D + 24 }}>
        {data.sublabel as string}
      </Typography>

      {/* Collapse hint */}
      {hasChildren && (
        <Typography sx={{ fontSize: 8.5, color: collapsed ? "#FF8F00" : "#9E9E9E", mt: 0.25 }}>
          {collapsed ? "Click to expand" : "Click to collapse"}
        </Typography>
      )}

      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </Box>
  );
}

// ── Labeled edge ──────────────────────────────────────────────────────────────

function LabeledEdge({ id, sourceX, sourceY, targetX, targetY, data }: any) {
  const [path, lx, ly] = getBezierPath({ sourceX, sourceY, targetX, targetY });
  const isCrit  = data?.isCrit as boolean;
  const stroke  = isCrit ? "#EA4335" : "#F59E0B";
  const txtColor = isCrit ? "#EA4335" : "#92400E";

  return (
    <>
      <BaseEdge id={id} path={path} style={{ stroke, strokeWidth: isCrit ? 2.5 : 1.5 }} />
      {data?.label && (
        <EdgeLabelRenderer>
          <Box
            className="nodrag nopan"
            sx={{
              position: "absolute",
              transform: `translate(-50%,-50%) translate(${lx}px,${ly}px)`,
              fontSize: 9, fontWeight: 600, color: txtColor,
              bgcolor: "rgba(255,255,255,0.93)",
              px: 0.6, py: 0.15, borderRadius: 0.5,
              border: `1px solid ${stroke}44`,
              pointerEvents: "none", whiteSpace: "nowrap",
            }}
          >
            {data.label}
          </Box>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

const NODE_TYPES: NodeTypes = { circle: CircleNode };
const EDGE_TYPES: EdgeTypes = { labeled: LabeledEdge };

// ── Inner graph (must be inside ReactFlowProvider) ────────────────────────────

export function AttackGraphInner({ data }: { data: AttackPathData }) {
  const { nodes: rawNodes, edges: rawEdges, paths } = data;
  const critSet = useMemo(() => new Set<string>(paths[0]?.nodes ?? []), [paths]);

  // Direct children map
  const childrenOf = useMemo(() => {
    const m = new Map<string, string[]>();
    rawEdges.forEach((e) => {
      if (!m.has(e.source)) m.set(e.source, []);
      m.get(e.source)!.push(e.target);
    });
    return m;
  }, [rawEdges]);

  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const toggleCollapse = useCallback((id: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  // Hidden ids = all nodes reachable exclusively through a collapsed node
  const hiddenIds = useMemo(() => {
    const hidden = new Set<string>();
    const queue = Array.from(collapsed);
    while (queue.length) {
      const cur = queue.shift()!;
      for (const c of childrenOf.get(cur) ?? []) {
        if (!hidden.has(c)) { hidden.add(c); queue.push(c); }
      }
    }
    return hidden;
  }, [collapsed, childrenOf]);

  // Build React Flow nodes
  const rfNodes: Node[] = useMemo(() =>
    rawNodes
      .filter((n) => !hiddenIds.has(n.id))
      .map((n) => ({
        id: n.id,
        type: "circle",
        position: { x: 0, y: 0 },
        data: {
          label: n.label,
          attackType: n.type,
          severity: n.severity?.toLowerCase() ?? null,
          isCritPath: critSet.has(n.id),
          collapsed: collapsed.has(n.id),
          childCount: (childrenOf.get(n.id) ?? []).length,
          onToggle: childrenOf.has(n.id) ? toggleCollapse : null,
          sublabel:
            n.type === "attacker" ? "Entry Point"
            : n.type === "resource" ? (n.resource ? n.resource.slice(0, 20) : "Asset")
            : n.cvss ? `CVSS ${(n.cvss as number).toFixed(1)}`
            : (n.severity ?? n.type).replace(/_/g, " "),
        },
        draggable: true,
      })),
  [rawNodes, hiddenIds, critSet, collapsed, childrenOf, toggleCollapse]);

  // Build React Flow edges
  const rfEdges: Edge[] = useMemo(() =>
    rawEdges
      .filter((e) => !hiddenIds.has(e.source) && !hiddenIds.has(e.target))
      .map((e, i) => ({
        id: `e-${i}`,
        source: e.source,
        target: e.target,
        type: "labeled",
        data: { label: e.label, isCrit: critSet.has(e.source) && critSet.has(e.target) },
        markerEnd: { type: MarkerType.ArrowClosed, color: critSet.has(e.source) && critSet.has(e.target) ? "#EA4335" : "#F59E0B" },
      })),
  [rawEdges, hiddenIds, critSet]);

  // Apply dagre
  const { nodes: laidNodes, edges: laidEdges } = useMemo(
    () => layoutGraph(rfNodes, rfEdges),
    [rfNodes, rfEdges],
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(laidNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(laidEdges);

  useEffect(() => { setNodes(laidNodes); }, [laidNodes, setNodes]);
  useEffect(() => { setEdges(laidEdges); }, [laidEdges, setEdges]);

  return (
    <Box sx={{ width: "100%", height: 600, bgcolor: "#FAFAFA", borderRadius: 2, border: "1px solid #e0e0e0", overflow: "hidden" }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={NODE_TYPES}
        edgeTypes={EDGE_TYPES}
        fitView
        fitViewOptions={{ padding: 0.12 }}
        minZoom={0.2}
        maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
        defaultEdgeOptions={{ animated: false }}
      >
        <Background color="#e8ecf0" gap={28} size={1} />
        <Controls showInteractive={false} style={{ bottom: 12, right: 12, left: "auto", top: "auto" }} />
        <MiniMap
          nodeColor={(n) => (TYPE_CFG[(n.data as any)?.attackType ?? ""] ?? FALLBACK_CFG).color}
          maskColor="rgba(240,244,248,0.6)"
          style={{ bottom: 12, left: 12, width: 140, height: 90 }}
          zoomable pannable
        />
      </ReactFlow>
    </Box>
  );
}

// ── Legend ────────────────────────────────────────────────────────────────────

const LEGEND_ITEMS = [
  { color: "#2E7D32", label: "Entry Point" },
  { color: "#C62828", label: "Initial Access" },
  { color: "#AD1457", label: "Credential / Privilege" },
  { color: "#E64A19", label: "Lateral Movement" },
  { color: "#00695C", label: "Data Access" },
  { color: "#0277BD", label: "Affected Asset" },
];

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AttackPaths() {
  const { clientId } = useActiveClient();
  const [scanId, setScanId] = useState<string>("");
  const [projectId, setProjectId] = useState<string>("");

  const { data: scans = [] } = useQuery<any[]>({
    queryKey: ["scans", clientId],
    queryFn: () => scansApi.list(clientId),
    enabled: !!clientId,
    select: (s) => s.filter((x: any) => x.status === "completed" && x.is_live !== false),
  });

  const { data: projects = [] } = useQuery<any[]>({
    queryKey: ["projects", clientId],
    queryFn: () => projectsApi.list(clientId),
    enabled: !!clientId,
  });

  const { data, isLoading, isError, error } = useQuery<AttackPathData>({
    queryKey: ["attack-paths", clientId, scanId, projectId],
    queryFn: () => attackPathApi.get(clientId, scanId || undefined, projectId || undefined),
    enabled: !!clientId,
  });

  const isEmpty  = !isLoading && !isError && data && data.nodes.length === 0;
  const hasData  = !!data && data.nodes.length > 0;

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Attack Paths</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Visualise how an attacker can chain findings into a full compromise. Click nodes to expand/collapse branches.
          </Typography>
        </Box>

        {clientId && (
          <Box sx={{ display: "flex", gap: 1.5 }}>
            <FormControl size="small" sx={{ minWidth: 190 }}>
              <InputLabel sx={{ fontSize: 13 }}>Scan</InputLabel>
              <Select value={scanId} label="Scan"
                onChange={(e) => { setScanId(e.target.value); setProjectId(""); }}>
                <MenuItem value=""><em>All Scans</em></MenuItem>
                {scans.map((s: any) => (
                  <MenuItem key={s.id} value={s.id} sx={{ fontSize: 13 }}>
                    {s.name}
                    <Typography component="span" variant="caption" sx={{ ml: 1, color: "text.secondary" }}>
                      ({s.connector_type})
                    </Typography>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <FormControl size="small" sx={{ minWidth: 160 }}>
              <InputLabel sx={{ fontSize: 13 }}>Project</InputLabel>
              <Select value={projectId} label="Project"
                onChange={(e) => { setProjectId(e.target.value); setScanId(""); }}>
                <MenuItem value=""><em>All Projects</em></MenuItem>
                {projects.map((p: any) => (
                  <MenuItem key={p.id} value={p.id} sx={{ fontSize: 13 }}>{p.name}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>
        )}
      </Box>

      {!clientId && <Alert severity="info">Select a client to view attack paths.</Alert>}

      {clientId && isLoading && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress />
        </Box>
      )}

      {clientId && isError && (
        <Alert severity="error">
          {(error as any)?.response?.data?.detail || (error as Error).message || "Failed to load attack paths"}
        </Alert>
      )}

      {clientId && isEmpty && (
        <Card variant="outlined" sx={{ p: 6, textAlign: "center", borderStyle: "dashed" }}>
          <AccountTree sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No findings available to build attack paths. Run a scan first.
          </Typography>
        </Card>
      )}

      {clientId && hasData && (
        <>
          {/* Stats bar */}
          <Box sx={{ display: "flex", gap: 2, mb: 2.5, flexWrap: "wrap" }}>
            <Card variant="outlined" sx={{ minWidth: 110 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color: "#1565C0" }}>
                  {data!.stats.total_findings}
                </Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>Findings</Typography>
              </CardContent>
            </Card>
            <Card variant="outlined" sx={{ minWidth: 110 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color: "#EA4335" }}>
                  {data!.stats.critical}
                </Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>Critical</Typography>
              </CardContent>
            </Card>
            <Card variant="outlined" sx={{ flexGrow: 1 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                  Attack Phases
                </Typography>
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                  {data!.stats.phases_present.map((ph) => (
                    <Chip key={ph} label={ph.replace(/_/g, " ")} size="small"
                      sx={{ fontSize: 10, height: 20, textTransform: "capitalize",
                            bgcolor: "rgba(21,101,192,0.1)", color: "#1565C0" }} />
                  ))}
                </Box>
              </CardContent>
            </Card>
          </Box>

          {/* Graph */}
          <ReactFlowProvider>
            <AttackGraphInner data={data!} />
          </ReactFlowProvider>

          {/* Legend */}
          <Card variant="outlined" sx={{ mt: 2 }}>
            <CardContent sx={{ py: 1.5, "&:last-child": { pb: 1.5 } }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, display: "block", mb: 1 }}>
                LEGEND
              </Typography>
              <Box sx={{ display: "flex", gap: 2.5, flexWrap: "wrap", alignItems: "center" }}>
                {LEGEND_ITEMS.map((item) => (
                  <Box key={item.label} sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                    <Box sx={{ width: 16, height: 16, borderRadius: "50%", bgcolor: item.color, flexShrink: 0 }} />
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>{item.label}</Typography>
                  </Box>
                ))}
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                  <Box sx={{ width: 22, height: 3, bgcolor: "#EA4335", borderRadius: 1, flexShrink: 0 }} />
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>Critical path</Typography>
                </Box>
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                  <Box sx={{ width: 22, height: 3, bgcolor: "#F59E0B", borderRadius: 1, flexShrink: 0 }} />
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>Attack chain</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>

          {/* Critical path breadcrumb */}
          {data!.paths.length > 0 && (
            <Card variant="outlined" sx={{ mt: 2 }}>
              <CardContent>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#EA4335" }}>
                  Critical Attack Path
                </Typography>
                {data!.paths.map((path, pi) => {
                  const nodeMap = new Map(data!.nodes.map((n) => [n.id, n]));
                  return (
                    <Box key={pi} sx={{ mb: pi < data!.paths.length - 1 ? 2 : 0 }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.75 }}>
                        {path.label}
                      </Typography>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, flexWrap: "wrap" }}>
                        {path.nodes.map((nid, ni) => {
                          const n = nodeMap.get(nid);
                          const sev = n?.severity?.toLowerCase();
                          const col = (sev && SEV_COLOR[sev]) ? SEV_COLOR[sev] : "#1565C0";
                          return (
                            <React.Fragment key={nid}>
                              <Chip label={n?.label ?? nid} size="small"
                                sx={{ bgcolor: `${col}18`, color: col, fontSize: 11, height: 22,
                                      border: `1px solid ${col}50`, fontWeight: 600 }} />
                              {ni < path.nodes.length - 1 && (
                                <Typography variant="caption" sx={{ color: "#F59E0B", fontWeight: 700 }}>→</Typography>
                              )}
                            </React.Fragment>
                          );
                        })}
                      </Box>
                    </Box>
                  );
                })}
              </CardContent>
            </Card>
          )}
        </>
      )}
    </Box>
  );
}
