import React, { useMemo, useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import { useQuery } from "@tanstack/react-query";
import {
  Box, Typography, Chip, CircularProgress, Alert, Card, CardContent,
  FormControl, InputLabel, Select, MenuItem,
} from "@mui/material";
import { AccountTree } from "@mui/icons-material";
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

interface AttackPathData {
  nodes: AttackNode[];
  edges: AttackEdge[];
  paths: AttackPath[];
  stats: { total_findings: number; critical: number; phases_present: string[] };
}

// ── Card dimensions ───────────────────────────────────────────────────────────

const CARD_W = 150;
const CARD_HEADER_H = 48;
const CARD_SUB_H = 24;
const CARD_H = CARD_HEADER_H + CARD_SUB_H;
const COL_W = 200;
const ROW_GAP = 24;
const PAD_X = 48;
const PAD_Y = 72; // room for column header labels

// ── Column assignment — maps node type → column index ────────────────────────

const COLUMN_MAP: Record<string, number> = {
  attacker: 0,
  initial_access: 1,
  vulnerability: 1,
  credential_access: 2,
  privilege_escalation: 2,
  lateral_movement: 2,
  data_access: 3,
  persistence: 3,
  impact: 3,
  resource: 4,
};

const COL_HEADERS: Record<number, string> = {
  0: "Scope",
  1: "Initial Access",
  2: "Lateral Movement",
  3: "Impact / Exfil",
  4: "Affected Assets",
};

// ── Colors by node type ───────────────────────────────────────────────────────

const TYPE_COLOR: Record<string, string> = {
  attacker: "#4285F4",
  initial_access: "#EA4335",
  vulnerability: "#E53935",
  credential_access: "#AD1457",
  privilege_escalation: "#6A1B9A",
  lateral_movement: "#E64A19",
  data_access: "#EF6C00",
  persistence: "#4E342E",
  impact: "#B71C1C",
  resource: "#00838F",
};

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335",
  high: "#FF7043",
  medium: "#FBBC04",
  low: "#34A853",
};

function nodeColor(node: AttackNode): string {
  if (node.type === "resource") return "#00838F";
  if (node.severity && SEV_COLOR[node.severity.toLowerCase()]) {
    return SEV_COLOR[node.severity.toLowerCase()];
  }
  return TYPE_COLOR[node.type] || "#607D8B";
}

// ── Text wrapping helper ──────────────────────────────────────────────────────

function wrapText(text: string, maxChars: number): string[] {
  if (text.length <= maxChars) return [text];
  const words = text.split(" ");
  const lines: string[] = [];
  let cur = "";
  for (const w of words) {
    if ((cur + " " + w).trim().length > maxChars) {
      if (cur) lines.push(cur.trim());
      cur = w;
    } else {
      cur = (cur + " " + w).trim();
    }
  }
  if (cur) lines.push(cur.trim());
  return lines.slice(0, 3); // max 3 lines
}

// ── Sub-label for card ────────────────────────────────────────────────────────

function subLabel(node: AttackNode): string {
  if (node.type === "attacker") return "Entry Point";
  if (node.type === "resource") return node.resource ? node.resource.slice(0, 22) : "Asset";
  if (node.cvss != null && node.cvss > 0) return `CVSS ${node.cvss.toFixed(1)}`;
  if (node.severity) return node.severity.toUpperCase();
  return node.type.replace(/_/g, " ");
}

// ── Attack card (SVG) ─────────────────────────────────────────────────────────

function AttackCard({
  x, y, node, isCritPath,
}: {
  x: number; y: number; node: AttackNode; isCritPath: boolean;
}) {
  const color = nodeColor(node);
  const cx = x + CARD_W / 2;
  const lines = wrapText(node.label, 17);
  const lineH = CARD_HEADER_H / (lines.length + 1);
  const sub = subLabel(node);

  return (
    <g>
      {/* Card shadow / outline */}
      <rect
        x={x} y={y} width={CARD_W} height={CARD_H}
        rx={8} fill="#141414"
        stroke={isCritPath ? "#fff" : "rgba(255,255,255,0.12)"}
        strokeWidth={isCritPath ? 2 : 1}
      />
      {/* Colored header block */}
      <rect x={x} y={y} width={CARD_W} height={CARD_HEADER_H} rx={8} fill={color} opacity={0.92} />
      {/* Square off bottom corners of header */}
      <rect x={x} y={y + CARD_HEADER_H - 8} width={CARD_W} height={8} fill={color} opacity={0.92} />
      {/* Header text lines */}
      {lines.map((line, i) => (
        <text
          key={i}
          x={cx}
          y={y + lineH * (i + 1)}
          textAnchor="middle"
          fill="#fff"
          fontSize={10}
          fontWeight="700"
          fontFamily="sans-serif"
        >
          {line}
        </text>
      ))}
      {/* Divider */}
      <line x1={x + 10} y1={y + CARD_HEADER_H} x2={x + CARD_W - 10} y2={y + CARD_HEADER_H}
        stroke="rgba(255,255,255,0.15)" strokeWidth={1} />
      {/* Sub-label */}
      <text
        x={cx} y={y + CARD_HEADER_H + CARD_SUB_H / 2 + 4}
        textAnchor="middle"
        fill="rgba(255,255,255,0.55)"
        fontSize={9}
        fontFamily="sans-serif"
      >
        {sub.length > 22 ? sub.slice(0, 21) + "…" : sub}
      </text>
    </g>
  );
}

// ── Bezier edge ───────────────────────────────────────────────────────────────

function EdgePath({
  x1, y1, x2, y2, isCrit,
}: {
  x1: number; y1: number; x2: number; y2: number; isCrit: boolean;
}) {
  const mx = (x1 + x2) / 2;
  return (
    <path
      d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
      fill="none"
      stroke={isCrit ? "#f44336" : "rgba(255,255,255,0.18)"}
      strokeWidth={isCrit ? 2 : 1}
      markerEnd={isCrit ? "url(#arr-crit)" : "url(#arr)"}
    />
  );
}

// ── Main graph ────────────────────────────────────────────────────────────────

function AttackGraph({ data }: { data: AttackPathData }) {
  const { nodes, edges, paths } = data;

  const critSet = useMemo(() => new Set<string>(paths[0]?.nodes ?? []), [paths]);

  // Assign column to each node
  const colOf = (n: AttackNode) => COLUMN_MAP[n.type] ?? 2;

  // Group nodes by column
  const byCol = useMemo(() => {
    const map = new Map<number, AttackNode[]>();
    for (const n of nodes) {
      const c = colOf(n);
      if (!map.has(c)) map.set(c, []);
      map.get(c)!.push(n);
    }
    return map;
  }, [nodes]);

  // Compute positions — centre column vertically within the canvas
  const positions = useMemo(() => {
    const pos = new Map<string, { x: number; y: number }>();
    byCol.forEach((colNodes, ci) => {
      const colH = colNodes.length * (CARD_H + ROW_GAP) - ROW_GAP;
      const startY = PAD_Y;
      colNodes.forEach((n, ri) => {
        pos.set(n.id, {
          x: PAD_X + ci * COL_W,
          y: startY + ri * (CARD_H + ROW_GAP),
        });
      });
    });
    return pos;
  }, [byCol]);

  const usedCols = byCol.size || 1;
  const maxNodesInCol = Math.max(...Array.from(byCol.values()).map((c) => c.length), 1);
  const svgW = PAD_X * 2 + (usedCols - 1) * COL_W + CARD_W;
  const svgH = PAD_Y + maxNodesInCol * (CARD_H + ROW_GAP) + 24;

  return (
    <svg
      width={svgW}
      height={svgH}
      style={{ display: "block", minWidth: svgW }}
      aria-label="Attack path graph"
    >
      <defs>
        <marker id="arr" markerWidth="7" markerHeight="5" refX="6" refY="2.5" orient="auto">
          <polygon points="0 0, 7 2.5, 0 5" fill="rgba(255,255,255,0.3)" />
        </marker>
        <marker id="arr-crit" markerWidth="7" markerHeight="5" refX="6" refY="2.5" orient="auto">
          <polygon points="0 0, 7 2.5, 0 5" fill="#f44336" />
        </marker>
      </defs>

      {/* Column header labels */}
      {Array.from(byCol.keys()).map((ci) => (
        COL_HEADERS[ci] && (
          <text
            key={ci}
            x={PAD_X + ci * COL_W + CARD_W / 2}
            y={PAD_Y - 18}
            textAnchor="middle"
            fill="rgba(255,255,255,0.35)"
            fontSize={10}
            fontStyle="italic"
            fontFamily="sans-serif"
          >
            {COL_HEADERS[ci]}
          </text>
        )
      ))}

      {/* Edges (drawn first, behind cards) */}
      {edges.map((e, i) => {
        const src = positions.get(e.source);
        const tgt = positions.get(e.target);
        if (!src || !tgt) return null;
        const isCrit = critSet.has(e.source) && critSet.has(e.target);
        return (
          <EdgePath
            key={i}
            x1={src.x + CARD_W}
            y1={src.y + CARD_H / 2}
            x2={tgt.x}
            y2={tgt.y + CARD_H / 2}
            isCrit={isCrit}
          />
        );
      })}

      {/* Cards */}
      {nodes.map((n) => {
        const pos = positions.get(n.id);
        if (!pos) return null;
        return (
          <AttackCard
            key={n.id}
            x={pos.x}
            y={pos.y}
            node={n}
            isCritPath={critSet.has(n.id)}
          />
        );
      })}
    </svg>
  );
}

// ── Legend ────────────────────────────────────────────────────────────────────

const LEGEND = [
  { color: "#4285F4", label: "Scope / Attacker" },
  { color: "#EA4335", label: "Initial Access" },
  { color: "#AD1457", label: "Credential / Privilege" },
  { color: "#E64A19", label: "Lateral Movement" },
  { color: "#EF6C00", label: "Data Access / Persistence" },
  { color: "#00838F", label: "Affected Asset" },
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

  const isEmpty = !isLoading && !isError && data && data.nodes.length === 0;
  const hasData = !!data && data.nodes.length > 0;

  const selectSx = {
    fontSize: 13,
    "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.15)" },
    "&:hover .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.3)" },
    "&.Mui-focused .MuiOutlinedInput-notchedOutline": { borderColor: "#4285F4" },
  };

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

        {clientId && (
          <Box sx={{ display: "flex", gap: 1.5, alignItems: "center" }}>
            <FormControl size="small" sx={{ minWidth: 190 }}>
              <InputLabel sx={{ fontSize: 13 }}>Scan</InputLabel>
              <Select value={scanId} label="Scan"
                onChange={(e) => { setScanId(e.target.value); setProjectId(""); }} sx={selectSx}>
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
                onChange={(e) => { setProjectId(e.target.value); setScanId(""); }} sx={selectSx}>
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
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      )}

      {clientId && isError && (
        <Alert severity="error">
          Failed to load attack paths:{" "}
          {(error as any)?.response?.data?.detail || (error as Error).message || "Unknown error"}
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
          <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
            <Card variant="outlined" sx={{ minWidth: 120 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color: "#4285F4" }}>
                  {data.stats.total_findings}
                </Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>Total Findings</Typography>
              </CardContent>
            </Card>
            <Card variant="outlined" sx={{ minWidth: 120 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color: "#EA4335" }}>
                  {data.stats.critical}
                </Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>Critical</Typography>
              </CardContent>
            </Card>
            <Card variant="outlined" sx={{ minWidth: 220 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                  Phases Present
                </Typography>
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                  {data.stats.phases_present.length === 0 ? (
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>—</Typography>
                  ) : (
                    data.stats.phases_present.map((ph) => (
                      <Chip key={ph} label={ph.replace(/_/g, " ")} size="small"
                        sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#82b1ff", fontSize: 10, height: 18, textTransform: "capitalize" }} />
                    ))
                  )}
                </Box>
              </CardContent>
            </Card>
          </Box>

          {/* Graph — scrollable both axes */}
          <Card variant="outlined" sx={{ mb: 3, bgcolor: "#0a0a0a", overflow: "hidden" }}>
            <Box sx={{ overflowX: "auto", overflowY: "auto", maxHeight: 560, p: 1 }}>
              <AttackGraph data={data} />
            </Box>
          </Card>

          {/* Legend */}
          <Card variant="outlined" sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, display: "block", mb: 1 }}>
                LEGEND
              </Typography>
              <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", alignItems: "center" }}>
                {LEGEND.map((item) => (
                  <Box key={item.label} sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                    <Box sx={{ width: 28, height: 14, borderRadius: 1, bgcolor: item.color, flexShrink: 0 }} />
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>{item.label}</Typography>
                  </Box>
                ))}
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                  <Box sx={{ width: 28, height: 2, bgcolor: "#f44336", flexShrink: 0 }} />
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>Critical path</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>

          {/* Critical path chain */}
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
                          const color = (sev && SEV_COLOR[sev]) ? SEV_COLOR[sev] : "#4285F4";
                          return (
                            <React.Fragment key={nid}>
                              <Chip label={n?.label ?? nid} size="small"
                                sx={{ bgcolor: `${color}20`, color, fontSize: 11, height: 20, border: `1px solid ${color}50` }} />
                              {ni < path.nodes.length - 1 && (
                                <Typography variant="caption" sx={{ color: "text.secondary" }}>→</Typography>
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
