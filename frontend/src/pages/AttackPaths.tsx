import React, { useMemo } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import { useQuery } from "@tanstack/react-query";
import {
  Box, Typography, Chip, CircularProgress, Alert, Card, CardContent,
} from "@mui/material";
import { AccountTree } from "@mui/icons-material";
import { attackPathApi } from "../services/api";

// ── Types ────────────────────────────────────────────────────────────────────

interface AttackNode {
  id: string;
  label: string;
  type: string;
  severity: string | null;
  cvss?: number;
  finding_id?: string;
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

interface AttackPathData {
  nodes: AttackNode[];
  edges: AttackEdge[];
  paths: AttackPath[];
  stats: { total_findings: number; critical: number; phases_present: string[] };
}

// ── Layout constants ─────────────────────────────────────────────────────────

const COLUMN_ORDER = [
  "attacker",
  "initial_access",
  "credential_access",
  "privilege_escalation",
  "lateral_movement",
  "data_access",
  "persistence",
  "impact",
  "vulnerability",
  "resource",
];

const NODE_RADIUS = 28;
const COL_WIDTH = 160;
const ROW_HEIGHT = 90;
const PAD_X = 60;
const PAD_Y = 60;

// ── Color helpers ─────────────────────────────────────────────────────────────

const SEV_FILL: Record<string, string> = {
  critical: "#f44336",
  high: "#ff9800",
  medium: "#ffeb3b",
  low: "#4caf50",
};

function nodeColor(node: AttackNode): string {
  if (node.type === "attacker") return "#4285F4";
  if (node.type === "resource") return "rgba(255,255,255,0.12)";
  if (node.severity && SEV_FILL[node.severity.toLowerCase()]) {
    return SEV_FILL[node.severity.toLowerCase()];
  }
  return "#9e9e9e";
}

function nodeStroke(node: AttackNode): string {
  if (node.type === "attacker") return "#82b1ff";
  if (node.type === "resource") return "rgba(255,255,255,0.3)";
  return "rgba(0,0,0,0.4)";
}

// ── SVG Graph ─────────────────────────────────────────────────────────────────

function AttackGraph({ data }: { data: AttackPathData }) {
  const { nodes, edges } = data;

  // Assign column index to each node type
  const colIndex = (type: string): number => {
    const idx = COLUMN_ORDER.indexOf(type);
    return idx >= 0 ? idx : COLUMN_ORDER.length - 1;
  };

  // Group nodes by column
  const columns = useMemo(() => {
    const cols: Map<number, AttackNode[]> = new Map();
    for (const n of nodes) {
      const ci = colIndex(n.type);
      if (!cols.has(ci)) cols.set(ci, []);
      cols.get(ci)!.push(n);
    }
    return cols;
  }, [nodes]);

  // Compute (x, y) for each node id
  const positions = useMemo(() => {
    const pos: Map<string, { x: number; y: number }> = new Map();
    columns.forEach((colNodes, ci) => {
      colNodes.forEach((n, ri) => {
        const x = PAD_X + ci * COL_WIDTH;
        const y = PAD_Y + ri * ROW_HEIGHT;
        pos.set(n.id, { x, y });
      });
    });
    return pos;
  }, [columns]);

  // SVG canvas size
  const usedCols = columns.size || 1;
  const maxRowsInCol = Math.max(...Array.from(columns.values()).map((c) => c.length), 1);
  const svgWidth = PAD_X * 2 + (usedCols - 1) * COL_WIDTH + NODE_RADIUS * 2;
  const svgHeight = PAD_Y * 2 + (maxRowsInCol - 1) * ROW_HEIGHT + NODE_RADIUS * 2;

  // Highlight nodes in first critical path
  const critPathNodes = new Set<string>(data.paths[0]?.nodes ?? []);

  return (
    <svg
      width={svgWidth}
      height={svgHeight}
      style={{ display: "block", minWidth: svgWidth }}
      aria-label="Attack path graph"
    >
      <defs>
        <marker
          id="arrowhead"
          markerWidth="8"
          markerHeight="6"
          refX="7"
          refY="3"
          orient="auto"
        >
          <polygon points="0 0, 8 3, 0 6" fill="rgba(255,255,255,0.45)" />
        </marker>
        <marker
          id="arrowhead-crit"
          markerWidth="8"
          markerHeight="6"
          refX="7"
          refY="3"
          orient="auto"
        >
          <polygon points="0 0, 8 3, 0 6" fill="#f44336" />
        </marker>
      </defs>

      {/* Edges */}
      {edges.map((e, i) => {
        const src = positions.get(e.source);
        const tgt = positions.get(e.target);
        if (!src || !tgt) return null;
        const isCrit =
          critPathNodes.has(e.source) && critPathNodes.has(e.target);
        const mx = (src.x + tgt.x) / 2;
        const my = (src.y + tgt.y) / 2;
        const dx = tgt.x - src.x;
        const dy = tgt.y - src.y;
        const len = Math.sqrt(dx * dx + dy * dy) || 1;
        const x1 = src.x + (dx / len) * NODE_RADIUS;
        const y1 = src.y + (dy / len) * NODE_RADIUS;
        const x2 = tgt.x - (dx / len) * (NODE_RADIUS + 6);
        const y2 = tgt.y - (dy / len) * (NODE_RADIUS + 6);

        return (
          <g key={i}>
            <line
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke={isCrit ? "#f44336" : "rgba(255,255,255,0.25)"}
              strokeWidth={isCrit ? 2 : 1}
              markerEnd={isCrit ? "url(#arrowhead-crit)" : "url(#arrowhead)"}
            />
            {e.label && (
              <text
                x={mx}
                y={my - 4}
                textAnchor="middle"
                fill="rgba(255,255,255,0.45)"
                fontSize={9}
              >
                {e.label.length > 16 ? e.label.slice(0, 15) + "…" : e.label}
              </text>
            )}
          </g>
        );
      })}

      {/* Nodes */}
      {nodes.map((n) => {
        const pos = positions.get(n.id);
        if (!pos) return null;
        const fill = nodeColor(n);
        const stroke = nodeStroke(n);
        const isHighlighted = critPathNodes.has(n.id);
        const displayLabel =
          n.label.length > 20 ? n.label.slice(0, 19) + "…" : n.label;

        return (
          <g key={n.id}>
            <circle
              cx={pos.x}
              cy={pos.y}
              r={NODE_RADIUS}
              fill={fill}
              stroke={isHighlighted ? "#fff" : stroke}
              strokeWidth={isHighlighted ? 2 : 1}
              opacity={0.9}
            />
            {n.cvss != null && (
              <text
                x={pos.x}
                y={pos.y + 4}
                textAnchor="middle"
                fill="#000"
                fontSize={10}
                fontWeight="bold"
              >
                {n.cvss.toFixed(1)}
              </text>
            )}
            <text
              x={pos.x}
              y={pos.y + NODE_RADIUS + 14}
              textAnchor="middle"
              fill="rgba(255,255,255,0.75)"
              fontSize={10}
            >
              {displayLabel}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

// ── Legend ────────────────────────────────────────────────────────────────────

const LEGEND_ITEMS = [
  { color: "#4285F4", label: "Attacker / Entry point" },
  { color: "#f44336", label: "Critical severity" },
  { color: "#ff9800", label: "High severity" },
  { color: "#ffeb3b", label: "Medium severity" },
  { color: "#4caf50", label: "Low severity" },
  { color: "rgba(255,255,255,0.12)", label: "Resource / target" },
  { color: "#9e9e9e", label: "Unknown severity" },
];

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AttackPaths() {
  const { clientId } = useActiveClient();

  const { data, isLoading, isError, error } = useQuery<AttackPathData>({
    queryKey: ["attack-paths", clientId],
    queryFn: () => attackPathApi.get(clientId),
    enabled: !!clientId,
  });

  const isEmpty = !isLoading && !isError && data && data.nodes.length === 0;
  const hasData = !!data && data.nodes.length > 0;

  return (
    <Box>
      {/* Page header */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Attack Paths</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Visualise how an attacker can chain findings into a full compromise path
          </Typography>
        </Box>
      </Box>

      {!clientId && (
        <Alert severity="info">Select a client to view attack paths.</Alert>
      )}

      {clientId && isLoading && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      )}

      {clientId && isError && (
        <Alert severity="error">
          Failed to load attack paths:{" "}
          {(error as any)?.response?.data?.detail ||
            (error as Error).message ||
            "Unknown error"}
        </Alert>
      )}

      {clientId && isEmpty && (
        <Card
          variant="outlined"
          sx={{ p: 6, textAlign: "center", borderStyle: "dashed" }}
        >
          <AccountTree sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No findings available to build attack paths. Run a scan first.
          </Typography>
        </Card>
      )}

      {clientId && hasData && (
        <>
          {/* Stats bar */}
          <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
            <Card variant="outlined" sx={{ minWidth: 120 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color: "#4285F4" }}>
                  {data.stats.total_findings}
                </Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  Total Findings
                </Typography>
              </CardContent>
            </Card>
            <Card variant="outlined" sx={{ minWidth: 120 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color: "#f44336" }}>
                  {data.stats.critical}
                </Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  Critical
                </Typography>
              </CardContent>
            </Card>
            <Card variant="outlined" sx={{ minWidth: 200 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                  Phases Present
                </Typography>
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                  {data.stats.phases_present.length === 0 ? (
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>—</Typography>
                  ) : (
                    data.stats.phases_present.map((ph) => (
                      <Chip
                        key={ph}
                        label={ph.replace(/_/g, " ")}
                        size="small"
                        sx={{
                          bgcolor: "rgba(66,133,244,0.15)",
                          color: "#82b1ff",
                          fontSize: 10,
                          height: 18,
                          textTransform: "capitalize",
                        }}
                      />
                    ))
                  )}
                </Box>
              </CardContent>
            </Card>
          </Box>

          {/* SVG graph in a scrollable container */}
          <Card
            variant="outlined"
            sx={{ mb: 3, overflow: "hidden", bgcolor: "#0d0d0d" }}
          >
            <Box
              sx={{
                height: 500,
                overflowX: "auto",
                overflowY: "auto",
                p: 1,
              }}
            >
              <AttackGraph data={data} />
            </Box>
          </Card>

          {/* Legend */}
          <Card variant="outlined" sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, display: "block", mb: 1 }}>
                LEGEND
              </Typography>
              <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                {LEGEND_ITEMS.map((item) => (
                  <Box key={item.label} sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                    <Box
                      sx={{
                        width: 14,
                        height: 14,
                        borderRadius: "50%",
                        bgcolor: item.color,
                        border: "1px solid rgba(255,255,255,0.2)",
                        flexShrink: 0,
                      }}
                    />
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>
                      {item.label}
                    </Typography>
                  </Box>
                ))}
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                  <Box sx={{ width: 24, height: 2, bgcolor: "#f44336", flexShrink: 0 }} />
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    Critical attack path
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>

          {/* Critical Attack Path section */}
          {data.paths.length > 0 && (
            <Card variant="outlined">
              <CardContent>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f44336" }}>
                  Critical Attack Path
                </Typography>
                {data.paths.map((path, pi) => {
                  const nodeMap = new Map(data.nodes.map((n) => [n.id, n]));
                  return (
                    <Box key={pi} sx={{ mb: pi < data.paths.length - 1 ? 2 : 0 }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.75 }}>
                        {path.label}
                      </Typography>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, flexWrap: "wrap" }}>
                        {path.nodes.map((nid, ni) => {
                          const n = nodeMap.get(nid);
                          const sev = n?.severity?.toLowerCase();
                          const color = sev && SEV_FILL[sev] ? SEV_FILL[sev] : "#4285F4";
                          return (
                            <React.Fragment key={nid}>
                              <Chip
                                label={n?.label ?? nid}
                                size="small"
                                sx={{
                                  bgcolor: `${color}20`,
                                  color: color,
                                  fontSize: 11,
                                  height: 20,
                                  border: `1px solid ${color}50`,
                                }}
                              />
                              {ni < path.nodes.length - 1 && (
                                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                  →
                                </Typography>
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
