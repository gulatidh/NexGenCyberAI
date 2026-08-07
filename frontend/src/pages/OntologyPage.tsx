import { useState, useEffect } from "react";
import { Box, Typography, Paper, useTheme, alpha } from "@mui/material";
import { useNavigate } from "react-router-dom";

// ── Entity and edge data (mirrors monitara_ontology_only.html SVG) ─────────────

interface ONode {
  entity: string;
  label: string;
  cx: number; cy: number;
  labelX: number; labelW: number;
  color: string;
}

interface OEdge {
  from: string; to: string;
  x1: number; y1: number;
  x2: number; y2: number;
  dashed?: boolean;
}

const NODES: ONode[] = [
  { entity: "Client",      label: "Client",            cx:  70, cy: 300, labelX:  35.0, labelW:  70, color: "#2563eb" },
  { entity: "Asset",       label: "Asset",             cx: 250, cy: 190, labelX: 215.0, labelW:  70, color: "#2563eb" },
  { entity: "Control",     label: "Control",           cx: 250, cy: 470, labelX: 213.5, labelW:  73, color: "#8b5cf6" },
  { entity: "DataFlow",    label: "Data Flow",         cx: 440, cy:  90, labelX: 396.5, labelW:  87, color: "#8b5cf6" },
  { entity: "Finding",     label: "Finding",           cx: 440, cy: 280, labelX: 403.5, labelW:  73, color: "#0ea5a4" },
  { entity: "SmartIntel",  label: "Smart Intelligence",cx: 440, cy: 560, labelX: 365.0, labelW: 150, color: "#6366f1" },
  { entity: "Risk",        label: "Risk",              cx: 640, cy: 220, labelX: 605.0, labelW:  70, color: "#f59e0b" },
  { entity: "Evidence",    label: "Evidence",          cx: 640, cy: 470, labelX: 600.0, labelW:  80, color: "#22c55e" },
  { entity: "AttackPath",  label: "Attack Path",       cx: 830, cy: 130, labelX: 779.5, labelW: 101, color: "#f59e0b" },
  { entity: "Technique",   label: "MITRE Technique",   cx: 830, cy: 300, labelX: 765.5, labelW: 129, color: "#ef4444" },
  { entity: "Remediation", label: "Remediation",       cx: 830, cy: 420, labelX: 779.5, labelW: 101, color: "#ef4444" },
  { entity: "Report",      label: "Report",            cx:1020, cy: 300, labelX: 985.0, labelW:  70, color: "#22c55e" },
];

const EDGES: OEdge[] = [
  { from:"Client",      to:"Asset",       x1: 70,  y1:300, x2:250,  y2:190 },
  { from:"Asset",       to:"DataFlow",    x1:250,  y1:190, x2:440,  y2: 90 },
  { from:"Asset",       to:"Finding",     x1:250,  y1:190, x2:440,  y2:280 },
  { from:"Finding",     to:"Risk",        x1:440,  y1:280, x2:640,  y2:220 },
  { from:"Risk",        to:"AttackPath",  x1:640,  y1:220, x2:830,  y2:130 },
  { from:"DataFlow",    to:"Technique",   x1:440,  y1: 90, x2:830,  y2:300 },
  { from:"AttackPath",  to:"Technique",   x1:830,  y1:130, x2:830,  y2:300 },
  { from:"Risk",        to:"Remediation", x1:640,  y1:220, x2:830,  y2:420 },
  { from:"Technique",   to:"Remediation", x1:830,  y1:300, x2:830,  y2:420 },
  { from:"Control",     to:"Evidence",    x1:250,  y1:470, x2:640,  y2:470 },
  { from:"Remediation", to:"Evidence",    x1:830,  y1:420, x2:640,  y2:470 },
  { from:"Finding",     to:"Report",      x1:440,  y1:280, x2:1020, y2:300 },
  { from:"Remediation", to:"Report",      x1:830,  y1:420, x2:1020, y2:300 },
  { from:"Evidence",    to:"Report",      x1:640,  y1:470, x2:1020, y2:300 },
  { from:"SmartIntel",  to:"Asset",       x1:440,  y1:560, x2:250,  y2:190, dashed:true },
  { from:"SmartIntel",  to:"Finding",     x1:440,  y1:560, x2:440,  y2:280, dashed:true },
  { from:"SmartIntel",  to:"Risk",        x1:440,  y1:560, x2:640,  y2:220, dashed:true },
  { from:"SmartIntel",  to:"Control",     x1:440,  y1:560, x2:250,  y2:470, dashed:true },
];

const ENTITY_ROUTES: Record<string, string> = {
  Client:      "/clients",
  Asset:       "/assets",
  Control:     "/compliance/frameworks",
  DataFlow:    "/threat-intel/threat-models",
  Finding:     "/vulnerability/findings",
  SmartIntel:  "/intelligence/nl-query",
  Risk:        "/risk/register",
  Evidence:    "/compliance/evidence",
  AttackPath:  "/threat-intel/attack-paths",
  Technique:   "/threat-intel/register",
  Remediation: "/governance/remediation",
  Report:      "/vapt/reports",
};

const LEGEND_COLORS = [
  { color: "#2563eb", label: "foundation" },
  { color: "#8b5cf6", label: "design" },
  { color: "#0ea5a4", label: "discover" },
  { color: "#f59e0b", label: "analyse" },
  { color: "#ef4444", label: "respond" },
  { color: "#22c55e", label: "report" },
  { color: "#6366f1", label: "cross-cutting hub" },
];

// ── Page ──────────────────────────────────────────────────────────────────────

export default function OntologyPage() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const navigate = useNavigate();
  const [selected, setSelected] = useState<string | null>(null);

  // Load fonts
  useEffect(() => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;700&display=swap";
    document.head.appendChild(link);
    return () => { document.head.removeChild(link); };
  }, []);

  const edgeColor = isDark ? "#3a4250" : "#c3c9d4";
  const panelBg   = isDark ? "#10151d" : "#fff";
  const raisedBg  = isDark ? "#141b25" : "#f2f4f8";
  const lineColor = isDark ? "#232b36" : "#e6e9ef";
  const textColor = isDark ? "#e7ecf2" : "#0f172a";
  const textDim   = isDark ? "#8b96a5" : "#5b6472";

  function toggle(entity: string) {
    setSelected((prev) => (prev === entity ? null : entity));
  }

  function edgeClass(e: OEdge): { stroke: string; opacity: number; strokeWidth: number; strokeDasharray?: string } {
    const connected = selected && (e.from === selected || e.to === selected);
    const dimmed    = selected && !connected;
    return {
      stroke: connected ? "#6366f1" : edgeColor,
      opacity: dimmed ? 0.1 : 1,
      strokeWidth: connected ? 2.4 : 1.6,
      ...(e.dashed ? { strokeDasharray: "3 4" } : {}),
    };
  }

  function nodeIsLit(entity: string)  { return !!selected && entity === selected; }
  function nodeIsDim(entity: string)  { return !!selected && entity !== selected; }

  return (
    <Box sx={{ maxWidth: 1100, mx: "auto", px: { xs: 2, md: 4 }, py: { xs: 4, md: 7 }, pb: 12 }}>

      {/* Hero */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.25, mb: 2.5 }}>
          <Box sx={{ width: 8, height: 8, borderRadius: "50%", background: "linear-gradient(90deg,#2563eb,#22c55e)", boxShadow: "0 0 10px 1px #2563eb88" }} />
          <Typography sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.72rem", letterSpacing: "0.1em", textTransform: "uppercase", color: "text.disabled" }}>
            Owlet · Data Ontology
          </Typography>
        </Box>

        <Typography sx={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700, fontSize: { xs: 26, md: 38 }, letterSpacing: "-0.02em", lineHeight: 1.1, mb: 1.75 }}>
          Eleven{" "}
          <Box component="span" sx={{ background: "linear-gradient(90deg,#2563eb,#8b5cf6 20%,#0ea5a4 40%,#f59e0b 60%,#ef4444 80%,#22c55e)", WebkitBackgroundClip: "text", backgroundClip: "text", color: "transparent" }}>
            entities
          </Box>
          , one connected data model.
        </Typography>

        <Typography sx={{ color: "text.secondary", fontSize: "0.97rem", maxWidth: 680, mb: 2 }}>
          Every module reads from or writes to this same set of entities. Solid arrows are direct hand-offs. Dashed lines show Smart Intelligence's cross-cutting correlation layer.
        </Typography>

        <Box sx={{ display: "inline-flex", alignItems: "center", gap: 1, fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.72rem", color: "text.disabled", border: "1px dashed", borderColor: "divider", px: 1.75, py: 0.9, borderRadius: 2 }}>
          ◎ click any node to trace what feeds it and what it feeds · double-click to open that module
        </Box>
      </Box>

      {/* SVG panel */}
      <Paper elevation={0} sx={{ border: "1px solid", borderColor: "divider", borderRadius: "14px", p: 3, bgcolor: panelBg, overflow: "hidden" }}>
        <Box sx={{ width: "100%", overflowX: "auto" }}>
          <svg
            viewBox="0 0 1120 640"
            xmlns="http://www.w3.org/2000/svg"
            style={{ width: "100%", minWidth: 640, height: "auto", display: "block" }}
          >
            {/* Arrow marker */}
            <defs>
              <marker id="ont-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill={edgeColor} />
              </marker>
              <marker id="ont-arrow-lit" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill="#6366f1" />
              </marker>
            </defs>

            {/* Edges */}
            <g>
              {EDGES.map((e, i) => {
                const s = edgeClass(e);
                const lit = selected && (e.from === selected || e.to === selected);
                return (
                  <line
                    key={i}
                    x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2}
                    stroke={s.stroke}
                    strokeWidth={s.strokeWidth}
                    opacity={s.opacity}
                    strokeDasharray={s.strokeDasharray}
                    markerEnd={lit ? "url(#ont-arrow-lit)" : "url(#ont-arrow)"}
                    style={{ transition: "stroke 0.2s, stroke-width 0.2s, opacity 0.2s" }}
                  />
                );
              })}
            </g>

            {/* Nodes */}
            <g>
              {NODES.map((n) => {
                const lit = nodeIsLit(n.entity);
                const dim = nodeIsDim(n.entity);
                const dotR = lit ? 10 : 7;
                return (
                  <g
                    key={n.entity}
                    style={{ cursor: "pointer", opacity: dim ? 0.22 : 1, transition: "opacity 0.18s" }}
                    onClick={() => toggle(n.entity)}
                    onDoubleClick={() => navigate(ENTITY_ROUTES[n.entity] || "/")}
                  >
                    <circle
                      cx={n.cx} cy={n.cy}
                      r={dotR}
                      fill={n.color}
                      stroke={isDark ? "#0b0f14" : "#fff"}
                      strokeWidth={2}
                      style={{ transition: "r 0.15s" }}
                    />
                    <rect
                      x={n.labelX} y={n.cy + 12}
                      width={n.labelW} height={22}
                      rx={11}
                      fill={lit ? n.color : raisedBg}
                      stroke={lit ? n.color : lineColor}
                      strokeWidth={1}
                      style={{ transition: "fill 0.15s, stroke 0.15s" }}
                    />
                    <text
                      x={n.cx} y={n.cy + 27}
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fontFamily="'IBM Plex Mono', monospace"
                      fontSize={11}
                      fontWeight={lit ? 600 : 500}
                      fill={lit ? "#fff" : textColor}
                      style={{ transition: "fill 0.15s" }}
                    >
                      {n.label}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        </Box>

        {/* Legend */}
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2.25, mt: 2.5, pt: 2.25, borderTop: "1px solid", borderColor: "divider" }}>
          {/* Edge types */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.72rem", color: textDim }}>
            <Box sx={{ width: 22, borderTop: `2px solid ${edgeColor}` }} />
            produces / feeds
          </Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.72rem", color: textDim }}>
            <Box sx={{ width: 22, borderTop: `2px dashed ${edgeColor}` }} />
            cross-cutting correlation
          </Box>

          {/* Phase dots */}
          {LEGEND_COLORS.map((l) => (
            <Box key={l.label} sx={{ display: "flex", alignItems: "center", gap: 1, fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.72rem", color: textDim }}>
              <Box sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: l.color }} />
              {l.label}
            </Box>
          ))}
        </Box>
      </Paper>

      {/* Entity quick-list */}
      {selected && (
        <Box sx={{ mt: 2.5 }}>
          {(() => {
            const node = NODES.find((n) => n.entity === selected)!;
            const outgoing = EDGES.filter((e) => !e.dashed && e.from === selected).map((e) => e.to);
            const incoming = EDGES.filter((e) => !e.dashed && e.to   === selected).map((e) => e.from);
            const correlation = EDGES.filter((e) => e.dashed && (e.from === selected || e.to === selected))
              .map((e) => (e.from === selected ? e.to : e.from));
            return (
              <Paper elevation={0} sx={{ border: "1px solid", borderColor: node.color, borderRadius: 2, p: 2.5, bgcolor: alpha(node.color, 0.05) }}>
                <Typography sx={{ fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, fontSize: "0.82rem", color: node.color, mb: 1.25 }}>
                  {node.label} — tracing connections
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                  {incoming.length > 0 && (
                    <Box>
                      <Typography sx={{ fontSize: "0.72rem", color: "text.disabled", fontFamily: "monospace", mb: 0.5 }}>← fed by</Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.75 }}>
                        {incoming.map((e) => {
                          const n = NODES.find((x) => x.entity === e)!;
                          return <Box key={e} onClick={() => toggle(e)} sx={{ cursor: "pointer", fontFamily: "monospace", fontSize: "0.75rem", px: 1.25, py: 0.5, borderRadius: 1, bgcolor: alpha(n.color, 0.12), color: n.color, border: `1px solid ${alpha(n.color, 0.3)}`, "&:hover": { bgcolor: alpha(n.color, 0.22) } }}>{n.label}</Box>;
                        })}
                      </Box>
                    </Box>
                  )}
                  {outgoing.length > 0 && (
                    <Box>
                      <Typography sx={{ fontSize: "0.72rem", color: "text.disabled", fontFamily: "monospace", mb: 0.5 }}>→ feeds</Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.75 }}>
                        {outgoing.map((e) => {
                          const n = NODES.find((x) => x.entity === e)!;
                          return <Box key={e} onClick={() => toggle(e)} sx={{ cursor: "pointer", fontFamily: "monospace", fontSize: "0.75rem", px: 1.25, py: 0.5, borderRadius: 1, bgcolor: alpha(n.color, 0.12), color: n.color, border: `1px solid ${alpha(n.color, 0.3)}`, "&:hover": { bgcolor: alpha(n.color, 0.22) } }}>{n.label}</Box>;
                        })}
                      </Box>
                    </Box>
                  )}
                  {correlation.length > 0 && (
                    <Box>
                      <Typography sx={{ fontSize: "0.72rem", color: "text.disabled", fontFamily: "monospace", mb: 0.5 }}>⋯ correlates with</Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.75 }}>
                        {correlation.map((e) => {
                          const n = NODES.find((x) => x.entity === e)!;
                          return <Box key={e} onClick={() => toggle(e)} sx={{ cursor: "pointer", fontFamily: "monospace", fontSize: "0.75rem", px: 1.25, py: 0.5, borderRadius: 1, bgcolor: alpha(n.color, 0.12), color: n.color, border: `1px solid ${alpha(n.color, 0.3)}`, "&:hover": { bgcolor: alpha(n.color, 0.22) } }}>{n.label}</Box>;
                        })}
                      </Box>
                    </Box>
                  )}
                </Box>
                <Typography sx={{ mt: 1.5, fontFamily: "monospace", fontSize: "0.69rem", color: "text.disabled" }}>
                  Double-click the node to open this module · click the label to jump to a connected entity
                </Typography>
              </Paper>
            );
          })()}
        </Box>
      )}

      {/* Footer */}
      <Box sx={{ mt: 8, pt: 3, borderTop: "1px solid", borderColor: "divider", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 1.5 }}>
        <Typography sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.72rem", color: "text.disabled" }}>
          CLIENT → ASSET → FINDING → RISK → REMEDIATION → REPORT
        </Typography>
        <Box sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.69rem", color: "text.secondary", border: "1px solid", borderColor: "divider", px: 1.5, py: 0.75, borderRadius: "20px" }}>
          Owlet · NexGenAI
        </Box>
      </Box>
    </Box>
  );
}
