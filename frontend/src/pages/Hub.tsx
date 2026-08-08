import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Button, Chip, CircularProgress,
  Divider, Tooltip, alpha, useTheme,
} from "@mui/material";
import { InfoOutlined } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import AssistantWidget from "../components/AssistantWidget";
import MegaMenuBar from "../components/layout/MegaMenuBar";
import AppControls from "../components/layout/AppControls";
import OwletLogo from "../components/OwletLogo";
import { dataModelApi, clientsApi, dashboardApi } from "../services/api";
import { useActiveClient } from "../contexts/ClientContext";
import { Client } from "../types";

// ── Types ─────────────────────────────────────────────────────────────────────

interface DashSummary {
  total_clients?: number;
  active_connectors?: number;
  open_findings?: number;
  scans_last_30d?: number;
  findings_by_severity?: Record<string, number>;
  risks_open?: number;
  recent_scans?: { name?: string; scan_type?: string }[];
}

interface LiveCardDef {
  letter: string;
  name: string;
  desc: string;
  route: string;
  manageRoute?: string;
  primaryLabel: string;
  secondaryLabel?: string;
  countFn?: (accounts: Client[], dash: DashSummary | null) => string | null;
  rowsFn?: (accounts: Client[], dash: DashSummary | null) => { label: string; value: string }[];
}

interface StageDef {
  num: string; id: string; label: string; color: string;
  title: string; sub: string; info: string;
  cards: LiveCardDef[];
}

// ── Stage + card definitions ──────────────────────────────────────────────────

const STAGE_DEFS: StageDef[] = [
  {
    num: "01", id: "setup", label: "Setup", color: "#2563eb",
    title: "Stand up the environment",
    sub: "Configure your accounts, connectors, and AI providers before any scanning begins.",
    info: "Complete this stage first — every downstream scan and analysis depends on at least one connected account and a configured AI provider.",
    cards: [
      {
        letter: "A", name: "Accounts", primaryLabel: "Add Account", secondaryLabel: "Manage", manageRoute: "/platform/clients",
        desc: "Client profiles, contact details, and security posture scoping.",
        route: "/platform/clients",
        countFn: (accounts) => `${accounts.length} active`,
        rowsFn: (accounts) => accounts.slice(0, 3).map(a => ({
          label: a.name,
          value: [a.industry, a.country].filter(Boolean).join(", ") || "—",
        })),
      },
      {
        letter: "C", name: "Connections", primaryLabel: "Add Connector", secondaryLabel: "Manage", manageRoute: "/connections",
        desc: "Scanner integrations, enterprise tools, and AI provider credentials.",
        route: "/connections",
        countFn: (_, dash) => dash?.active_connectors != null ? `${dash.active_connectors} connected` : null,
        rowsFn: (_, dash) => [
          { label: "Scans this month", value: String(dash?.scans_last_30d ?? "—") },
          { label: "Open findings", value: String(dash?.open_findings ?? "—") },
        ],
      },
      {
        letter: "T", name: "Threat Models", primaryLabel: "Open Designer",
        desc: "Data flow diagrams, STRIDE analysis, and Sigma detection rules.",
        route: "/threat-intel/threat-models",
      },
      {
        letter: "F", name: "Frameworks", primaryLabel: "View Standards",
        desc: "NIST CSF, CIS v8, ISO 27001, PCI DSS, GDPR, and custom standards.",
        route: "/compliance/frameworks",
      },
    ],
  },
  {
    num: "02", id: "discover", label: "Discover", color: "#0f766e",
    title: "Find what's actually exposed",
    sub: "Scan the environment — via inbuilt scanners, enterprise integrations, or an AI-guided conversation.",
    info: "CVE enrichment and severity scoring run automatically after each scan. Import results from external scanners via the Import tab.",
    cards: [
      {
        letter: "V", name: "Vulnerability Management", primaryLabel: "Start Scan", secondaryLabel: "Findings", manageRoute: "/vulnerability/findings",
        desc: "All scanners, findings, posture trends, and CVE blast radius in one place.",
        route: "/vulnerability",
        countFn: (_, dash) => dash?.open_findings != null ? `${dash.open_findings} open` : null,
        rowsFn: (_, dash) => {
          const sev = dash?.findings_by_severity ?? {};
          return [
            { label: "Critical", value: String(sev.critical ?? 0) },
            { label: "High", value: String(sev.high ?? 0) },
            { label: "Medium", value: String(sev.medium ?? 0) },
          ];
        },
      },
      {
        letter: "CV", name: "CVE Blast Radius", primaryLabel: "Explore CVEs",
        desc: "Which assets does a specific CVE actually affect? Map the full exposure path.",
        route: "/cve-pivot",
      },
      {
        letter: "AS", name: "AI-Assisted Scan", primaryLabel: "Start Wizard",
        desc: "Conversational guided assessment — describe your environment, and AI configures the scan.",
        route: "/intelligence/ai-assisted-scan",
      },
    ],
  },
  {
    num: "03", id: "analyse", label: "Analyse", color: "#b45309",
    title: "Turn findings into risk",
    sub: "Score findings, apply FAIR-lite ALE modelling, and query your entire posture in plain language.",
    info: "Risk domains are automatically normalised. Attack paths are derived from finding combinations — no manual correlation needed.",
    cards: [
      {
        letter: "R", name: "Risk Manager", primaryLabel: "Open Register", secondaryLabel: "Attack Paths", manageRoute: "/threat-intel/attack-paths",
        desc: "FAIR-scored risk register, financial ALE exposure, and attack path visualisation.",
        route: "/risk",
        countFn: (_, dash) => dash?.risks_open != null ? `${dash.risks_open} open` : null,
        rowsFn: (_, dash) => {
          const sev = dash?.findings_by_severity ?? {};
          const total = (sev.critical ?? 0) + (sev.high ?? 0);
          return [
            { label: "Critical + High findings", value: String(total) },
            { label: "Scans this month", value: String(dash?.scans_last_30d ?? "—") },
          ];
        },
      },
      {
        letter: "I", name: "Smart Intelligence", primaryLabel: "Open",
        desc: "NL queries, compliance heatmap, account comparison, and executive reports.",
        route: "/intelligence",
      },
    ],
  },
  {
    num: "04", id: "respond", label: "Respond", color: "#b91c1c",
    title: "Act on the picture",
    sub: "Map risk to real adversary behaviour, then track remediation through structured CTEM programs.",
    info: "Threat entries are automatically mapped to MITRE ATT&CK techniques by the Threat Intel agent. CTEM programs progress through 5 phases: Scope → Discover → Prioritise → Validate → Mobilise.",
    cards: [
      {
        letter: "TI", name: "Threat Intelligence", primaryLabel: "Open Register", secondaryLabel: "Attack Paths", manageRoute: "/threat-intel/attack-paths",
        desc: "MITRE ATT&CK–mapped threat entries, IOCs, and attack path graph from your findings.",
        route: "/threat-intel",
      },
      {
        letter: "G", name: "Governance", primaryLabel: "Open Programs",
        desc: "CTEM programs, control deficiency gaps, remediation tracker, and public scorecard.",
        route: "/governance",
      },
    ],
  },
  {
    num: "05", id: "report", label: "Report", color: "#15803d",
    title: "Prove it happened",
    sub: "Close the loop with evidence the auditor — or the client — can actually use.",
    info: "VAPT reports are AI-generated from scan findings. Evidence packages are audit-ready ZIPs containing findings CSV, control deficiencies, remediation actions, and agent logs.",
    cards: [
      {
        letter: "P", name: "Pen Testing / VAPT", primaryLabel: "Open Reports",
        desc: "Engagement reports with retest versioning and PDF/DOCX export.",
        route: "/vapt",
      },
      {
        letter: "CM", name: "Compliance Monitor", primaryLabel: "View Framework Status", secondaryLabel: "Evidence",
        desc: "Framework compliance assessments, control deficiency gaps, and audit evidence packages.",
        route: "/compliance",
        manageRoute: "/compliance/evidence",
      },
    ],
  },
  {
    num: "06", id: "automate", label: "Automate", color: "#4338ca",
    title: "Let AI carry the load",
    sub: "Agents run the full analysis loop — risk, intel, remediation, compliance — on demand or on repeat.",
    info: "AI Buddies output structured data directly into the Risk, Threat, Compliance, and Remediation registers. The Orchestrator runs all four in sequence from a single trigger.",
    cards: [
      {
        letter: "AB", name: "AI Buddies", primaryLabel: "Open Agents",
        desc: "60+ AI agents — orchestrator, risk manager, threat intel, and remediation planner.",
        route: "/ai-advisor",
      },
      {
        letter: "K", name: "Knowledge & Docs", primaryLabel: "Open",
        desc: "Security document RAG, ask-your-data queries, and the Aegis knowledge base.",
        route: "/intelligence/knowledge",
      },
    ],
  },
];

// ── HubCard ───────────────────────────────────────────────────────────────────

function HubCard({
  card, color, accounts, dash, loading,
}: {
  card: LiveCardDef;
  color: string;
  accounts: Client[];
  dash: DashSummary | null;
  loading: boolean;
}) {
  const navigate = useNavigate();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const count = card.countFn ? card.countFn(accounts, dash) : null;
  const rows = card.rowsFn ? card.rowsFn(accounts, dash) : [];

  return (
    <Box sx={{
      bgcolor: "background.paper",
      border: "1px solid", borderColor: "divider",
      borderRadius: 2, p: 2.5,
      display: "flex", flexDirection: "column", gap: 2,
      transition: "border-color .18s, box-shadow .18s",
      "&:hover": {
        borderColor: color,
        boxShadow: `0 4px 20px ${alpha(color, 0.12)}`,
      },
    }}>
      {/* Top row: avatar + count badge */}
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
        <Box sx={{
          width: 44, height: 44, borderRadius: 1.5, flexShrink: 0,
          bgcolor: alpha(color, isDark ? 0.18 : 0.1),
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <Typography sx={{
            fontWeight: 800, fontSize: card.letter.length > 1 ? 13 : 20,
            color, lineHeight: 1, fontFamily: "monospace", letterSpacing: -0.5,
          }}>
            {card.letter}
          </Typography>
        </Box>
        {count !== null && (
          <Box sx={{
            px: 1.25, py: 0.4, borderRadius: "20px",
            bgcolor: alpha(color, isDark ? 0.18 : 0.1),
            color, fontSize: 11, fontWeight: 700, lineHeight: 1.6,
          }}>
            {loading ? <CircularProgress size={10} /> : count}
          </Box>
        )}
      </Box>

      {/* Name + desc */}
      <Box>
        <Typography sx={{ fontWeight: 700, fontSize: 16, mb: 0.5, lineHeight: 1.3 }}>{card.name}</Typography>
        <Typography sx={{ fontSize: 12.5, color: "text.secondary", lineHeight: 1.5 }}>{card.desc}</Typography>
      </Box>

      {/* Data rows */}
      {rows.length > 0 && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75, borderTop: "1px solid", borderColor: "divider", pt: 1.5 }}>
          {rows.map((row, i) => (
            <Box key={i} sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <Typography sx={{ fontSize: 12.5, color: "text.secondary" }}>{row.label}</Typography>
              <Typography sx={{ fontSize: 12.5, fontWeight: 600 }}>{loading ? "…" : row.value}</Typography>
            </Box>
          ))}
        </Box>
      )}

      {/* Spacer */}
      <Box sx={{ flex: 1 }} />

      {/* Actions */}
      <Box sx={{ display: "flex", gap: 1 }}>
        <Button
          size="small" variant="contained"
          onClick={() => navigate(card.route)}
          sx={{
            flex: 1, bgcolor: "#111827", "&:hover": { bgcolor: "#1f2937" },
            borderRadius: 1.5, fontWeight: 600, fontSize: 12.5,
            textTransform: "none", py: 0.9,
          }}
        >
          {card.primaryLabel}
        </Button>
        {card.manageRoute && (
          <Button
            size="small" variant="outlined"
            onClick={() => navigate(card.manageRoute!)}
            sx={{
              flex: 1, borderRadius: 1.5, fontWeight: 600, fontSize: 12.5,
              textTransform: "none", py: 0.9,
              borderColor: "divider", color: "text.primary",
              "&:hover": { bgcolor: "action.hover", borderColor: color },
            }}
          >
            {card.secondaryLabel ?? "Manage"}
          </Button>
        )}
      </Box>
    </Box>
  );
}

// ── StageSection ──────────────────────────────────────────────────────────────

function StageSection({
  stage, si, accounts, dash, loading,
}: {
  stage: StageDef; si: number;
  accounts: Client[]; dash: DashSummary | null; loading: boolean;
}) {
  return (
    <Box
      id={`stage-${stage.id}`}
      sx={{
        position: "relative", pl: "64px",
        mb: si < STAGE_DEFS.length - 1 ? 7 : 0,
        scrollMarginTop: 24,
        opacity: 0, transform: "translateY(12px)",
        animation: `hubrise 0.5s ease ${si * 0.07}s forwards`,
        "@keyframes hubrise": { to: { opacity: 1, transform: "translateY(0)" } },
      }}
    >
      {/* Circle node */}
      <Box sx={{
        position: "absolute", left: 0, top: 0,
        width: 48, height: 48, borderRadius: "50%",
        bgcolor: "background.default",
        border: `2px solid ${stage.color}`,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontFamily: "monospace", fontWeight: 700, fontSize: "1rem",
        color: stage.color,
        boxShadow: `0 0 18px -4px ${stage.color}60`,
        zIndex: 2,
      }}>
        {stage.num}
      </Box>

      {/* Stage header */}
      <Box sx={{ pt: "4px", mb: 2.5 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.75 }}>
          <Box sx={{ width: 4, height: 16, borderRadius: 2, bgcolor: stage.color }} />
          <Typography sx={{ fontSize: "0.71rem", fontWeight: 700, color: stage.color, textTransform: "uppercase", letterSpacing: "0.1em" }}>
            Stage {stage.num} · {stage.label}
          </Typography>
        </Box>
        <Typography sx={{
          fontFamily: "'Space Grotesk', sans-serif",
          fontSize: { xs: 20, md: 26 }, fontWeight: 700, letterSpacing: "-0.02em", mb: 0.75,
        }}>
          {stage.title}
        </Typography>
        <Typography sx={{ color: "text.secondary", fontSize: "0.88rem", maxWidth: 560, lineHeight: 1.6, mb: 2 }}>
          {stage.sub}
        </Typography>
        {/* Info callout */}
        <Box sx={{
          display: "flex", alignItems: "flex-start", gap: 1.5,
          bgcolor: alpha(stage.color, 0.06),
          border: "1px solid", borderColor: alpha(stage.color, 0.2),
          borderRadius: 1.5, px: 2, py: 1.25,
        }}>
          <InfoOutlined sx={{ color: stage.color, fontSize: 15, mt: "2px", flexShrink: 0 }} />
          <Typography sx={{ fontSize: 12.5, color: "text.secondary", lineHeight: 1.55 }}>{stage.info}</Typography>
        </Box>
      </Box>

      {/* Cards */}
      <Box sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" },
        gap: 1.5,
      }}>
        {stage.cards.map((card) => (
          <HubCard key={card.name} card={card} color={stage.color} accounts={accounts} dash={dash} loading={loading} />
        ))}
      </Box>
    </Box>
  );
}

// ── Ontology mini-map ─────────────────────────────────────────────────────────

interface ONode { entity: string; label: string; cx: number; cy: number; labelX: number; labelW: number; color: string }
interface OEdge { from: string; to: string; x1: number; y1: number; x2: number; y2: number; dashed?: boolean }

const ONT_NODES: ONode[] = [
  { entity:"Client",      label:"Client",             cx: 70,  cy:300, labelX: 35,   labelW: 70,  color:"#2563eb" },
  { entity:"Asset",       label:"Asset",              cx:250,  cy:190, labelX:215,   labelW: 70,  color:"#2563eb" },
  { entity:"Control",     label:"Control",            cx:250,  cy:470, labelX:213.5, labelW: 73,  color:"#7c3aed" },
  { entity:"DataFlow",    label:"Data Flow",          cx:440,  cy: 90, labelX:396.5, labelW: 87,  color:"#7c3aed" },
  { entity:"Finding",     label:"Finding",            cx:440,  cy:280, labelX:403.5, labelW: 73,  color:"#0f766e" },
  { entity:"SmartIntel",  label:"Smart Intelligence", cx:440,  cy:560, labelX:365,   labelW:150,  color:"#4338ca" },
  { entity:"Risk",        label:"Risk",               cx:640,  cy:220, labelX:605,   labelW: 70,  color:"#b45309" },
  { entity:"Evidence",    label:"Evidence",           cx:640,  cy:470, labelX:600,   labelW: 80,  color:"#15803d" },
  { entity:"AttackPath",  label:"Attack Path",        cx:830,  cy:130, labelX:779.5, labelW:101,  color:"#b45309" },
  { entity:"Technique",   label:"MITRE Technique",    cx:830,  cy:300, labelX:765.5, labelW:129,  color:"#b91c1c" },
  { entity:"Remediation", label:"Remediation",        cx:830,  cy:420, labelX:779.5, labelW:101,  color:"#b91c1c" },
  { entity:"Report",      label:"Report",             cx:1020, cy:300, labelX:985,   labelW: 70,  color:"#15803d" },
];
const ONT_EDGES: OEdge[] = [
  { from:"Client",      to:"Asset",       x1: 70, y1:300, x2:250,  y2:190 },
  { from:"Asset",       to:"DataFlow",    x1:250, y1:190, x2:440,  y2: 90 },
  { from:"Asset",       to:"Finding",     x1:250, y1:190, x2:440,  y2:280 },
  { from:"Finding",     to:"Risk",        x1:440, y1:280, x2:640,  y2:220 },
  { from:"Risk",        to:"AttackPath",  x1:640, y1:220, x2:830,  y2:130 },
  { from:"DataFlow",    to:"Technique",   x1:440, y1: 90, x2:830,  y2:300 },
  { from:"AttackPath",  to:"Technique",   x1:830, y1:130, x2:830,  y2:300 },
  { from:"Risk",        to:"Remediation", x1:640, y1:220, x2:830,  y2:420 },
  { from:"Technique",   to:"Remediation", x1:830, y1:300, x2:830,  y2:420 },
  { from:"Control",     to:"Evidence",    x1:250, y1:470, x2:640,  y2:470 },
  { from:"Remediation", to:"Evidence",    x1:830, y1:420, x2:640,  y2:470 },
  { from:"Finding",     to:"Report",      x1:440, y1:280, x2:1020, y2:300 },
  { from:"Remediation", to:"Report",      x1:830, y1:420, x2:1020, y2:300 },
  { from:"Evidence",    to:"Report",      x1:640, y1:470, x2:1020, y2:300 },
  { from:"SmartIntel",  to:"Asset",       x1:440, y1:560, x2:250,  y2:190, dashed:true },
  { from:"SmartIntel",  to:"Finding",     x1:440, y1:560, x2:440,  y2:280, dashed:true },
  { from:"SmartIntel",  to:"Risk",        x1:440, y1:560, x2:640,  y2:220, dashed:true },
  { from:"SmartIntel",  to:"Control",     x1:440, y1:560, x2:250,  y2:470, dashed:true },
];
const ONT_ROUTES: Record<string, string> = {
  Client:"platform/clients", Asset:"platform/assets", Control:"compliance/frameworks",
  DataFlow:"threat-intel/threat-models", Finding:"vulnerability/findings",
  SmartIntel:"intelligence/nl-query", Risk:"risk/register",
  Evidence:"compliance/evidence", AttackPath:"threat-intel/attack-paths",
  Technique:"threat-intel/register", Remediation:"governance/remediation",
  Report:"vapt/reports",
};

const SEV_COLOR: Record<string, string> = {
  critical: "#b91c1c", high: "#ea580c", medium: "#d97706",
  low: "#16a34a", info: "#0284c7",
  critical_risk: "#b91c1c", high_risk: "#ea580c", medium_risk: "#d97706", low_risk: "#16a34a",
};
function severityColor(k: string) { return SEV_COLOR[k] ?? "#6b7280"; }

interface StatData {
  total: number;
  breakdown: Record<string, number>;
  key: string;
  status?: Record<string, number>;
}

function OntologyStatPanel({ entity, stats, color, route }: {
  entity: string; stats: StatData; color: string; route: string;
}) {
  const navigate = useNavigate();
  const breakdownEntries = Object.entries(stats.breakdown).filter(([, v]) => v > 0).sort(([, a], [, b]) => b - a);
  const maxVal = Math.max(...breakdownEntries.map(([, v]) => v), 1);

  return (
    <Box sx={{
      width: 260, flexShrink: 0, border: "1px solid", borderColor: "divider",
      borderRadius: 2, bgcolor: "background.paper", p: 2,
      display: "flex", flexDirection: "column", gap: 1.5,
    }}>
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <Box sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: color }} />
          <Typography sx={{ fontWeight: 700, fontSize: 14, textTransform: "capitalize" }}>{entity}</Typography>
        </Box>
        <Typography sx={{ fontSize: 22, fontWeight: 800, color, lineHeight: 1 }}>{stats.total}</Typography>
      </Box>
      <Divider />
      {breakdownEntries.length > 0 ? (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
          {breakdownEntries.map(([k, v]) => (
            <Box key={k}>
              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.25 }}>
                <Typography sx={{ fontSize: 11, color: "text.secondary", textTransform: "capitalize" }}>{k}</Typography>
                <Typography sx={{ fontSize: 11, fontWeight: 600 }}>{v}</Typography>
              </Box>
              <Box sx={{ height: 5, borderRadius: 3, bgcolor: "action.hover", overflow: "hidden" }}>
                <Box sx={{ height: "100%", borderRadius: 3, bgcolor: severityColor(k), width: `${Math.round((v / maxVal) * 100)}%`, transition: "width 0.4s ease" }} />
              </Box>
            </Box>
          ))}
        </Box>
      ) : (
        <Typography sx={{ fontSize: 12, color: "text.disabled", textAlign: "center", py: 1 }}>No data</Typography>
      )}
      {stats.status && Object.keys(stats.status).length > 0 && (
        <>
          <Divider />
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
            {Object.entries(stats.status).filter(([, v]) => v > 0).map(([k, v]) => (
              <Chip key={k} label={`${k}: ${v}`} size="small" sx={{ fontSize: 10, height: 20, bgcolor: "action.hover" }} />
            ))}
          </Box>
        </>
      )}
      <Divider />
      <Box
        onClick={() => navigate(`/${route}`)}
        sx={{ fontSize: 12, color: "primary.main", cursor: "pointer", textAlign: "center", py: 0.5, borderRadius: 1, "&:hover": { bgcolor: alpha(color, 0.08) } }}
      >
        View all {entity}s →
      </Box>
    </Box>
  );
}

function OntologyMini() {
  const theme = useTheme();
  const navigate = useNavigate();
  const { clientId } = useActiveClient();
  const [sel, setSel] = useState<string | null>(null);
  const isDark = theme.palette.mode === "dark";
  const edgeCol  = isDark ? "#3a4250" : "#c3c9d4";
  const raisedBg = isDark ? "#141b25" : "#f2f4f8";
  const lineBdr  = isDark ? "#232b36" : "#e6e9ef";

  const { data: statsRaw, isLoading } = useQuery({
    queryKey: ["ontology-stats", clientId],
    queryFn: () => clientId ? dataModelApi.stats(clientId) : Promise.resolve(null),
    enabled: !!clientId,
    staleTime: 60_000,
  });

  const stats: Record<string, StatData> = statsRaw ?? {};

  const ENTITY_STAT_KEY: Record<string, string> = {
    Asset: "asset", Finding: "finding", Risk: "risk",
    Control: "control", Remediation: "remediation",
    Technique: "technique", Report: "report",
    SmartIntel: "finding", DataFlow: "asset", AttackPath: "risk", Evidence: "report",
    Client: "asset",
  };

  function nodeCount(entity: string): number | null {
    const key = ENTITY_STAT_KEY[entity];
    return key && stats[key] ? stats[key].total : null;
  }

  const eStyle = (e: OEdge) => {
    const hit = sel && (e.from === sel || e.to === sel);
    const dim = sel && !hit;
    return { stroke: hit ? "#4338ca" : edgeCol, strokeWidth: hit ? 2.4 : 1.6, opacity: dim ? 0.1 : 1, strokeDasharray: e.dashed ? "3 4" : undefined };
  };

  const selNode = ONT_NODES.find(n => n.entity === sel);
  const selStatKey = sel ? ENTITY_STAT_KEY[sel] : null;
  const selStats = selStatKey ? stats[selStatKey] : null;

  return (
    <Box sx={{ mt: 6, pt: 5, borderTop: "1px solid", borderColor: "divider" }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.75 }}>
        <Box sx={{ width: 4, height: 20, borderRadius: 2, bgcolor: "#4338ca" }} />
        <Typography sx={{ fontWeight: 700, fontSize: 15 }}>Data Ontology</Typography>
        {isLoading && <CircularProgress size={14} sx={{ ml: 1 }} />}
      </Box>
      <Typography sx={{ fontSize: 13, color: "text.secondary", mb: 2.5, maxWidth: 600 }}>
        Live entity counts across your security data. Click any node to see the breakdown.
      </Typography>

      <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
        <Box sx={{ flex: 1, bgcolor: "background.paper", border: "1px solid", borderColor: "divider", borderRadius: 2, p: 2.5, overflowX: "auto", minWidth: 0 }}>
          <svg viewBox="0 0 1120 640" style={{ width: "100%", minWidth: 480, height: "auto", display: "block" }}>
            <defs>
              <marker id="ont-a"   viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill={edgeCol}/></marker>
              <marker id="ont-lit" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#4338ca"/></marker>
            </defs>
            <g>
              {ONT_EDGES.map((e, i) => {
                const s = eStyle(e);
                const lit = sel && (e.from === sel || e.to === sel);
                return <line key={i} x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2} stroke={s.stroke} strokeWidth={s.strokeWidth} opacity={s.opacity} strokeDasharray={s.strokeDasharray} markerEnd={lit ? "url(#ont-lit)" : "url(#ont-a)"} style={{ transition: "stroke 0.2s, opacity 0.2s" }} />;
              })}
            </g>
            <g>
              {ONT_NODES.map((n) => {
                const lit = sel === n.entity;
                const dim = !!sel && !lit;
                const cnt = nodeCount(n.entity);
                return (
                  <Tooltip key={n.entity} title={cnt !== null ? `${n.label}: ${cnt} total` : n.label} placement="top">
                    <g style={{ cursor: "pointer", opacity: dim ? 0.2 : 1, transition: "opacity 0.18s" }}
                       onClick={() => setSel((p) => p === n.entity ? null : n.entity)}
                       onDoubleClick={() => navigate(`/${ONT_ROUTES[n.entity] ?? ""}`)}
                    >
                      <circle cx={n.cx} cy={n.cy} r={lit ? 12 : 9} fill={n.color} stroke={isDark ? "#0b0f14" : "#fff"} strokeWidth={2} style={{ transition: "r 0.15s" }} />
                      {cnt !== null && cnt > 0 && (
                        <text x={n.cx} y={n.cy} textAnchor="middle" dominantBaseline="middle"
                          fontFamily="monospace" fontSize={cnt > 99 ? 7 : 9} fontWeight={700} fill="#fff">
                          {cnt > 999 ? "999+" : cnt}
                        </text>
                      )}
                      <rect x={n.labelX} y={n.cy+14} width={n.labelW} height={22} rx={11} fill={lit ? n.color : raisedBg} stroke={lit ? n.color : lineBdr} strokeWidth={1} style={{ transition: "fill 0.15s" }} />
                      <text x={n.cx} y={n.cy+29} textAnchor="middle" dominantBaseline="middle" fontFamily="monospace" fontSize={11} fontWeight={lit ? 600 : 500} fill={lit ? "#fff" : theme.palette.text.primary} style={{ transition: "fill 0.15s" }}>
                        {n.label}
                      </text>
                    </g>
                  </Tooltip>
                );
              })}
            </g>
          </svg>

          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, mt: 2, pt: 2, borderTop: "1px solid", borderColor: "divider", alignItems: "center" }}>
            {STAGE_DEFS.map((s) => (
              <Box key={s.id} sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                <Box sx={{ width: 9, height: 9, borderRadius: "50%", bgcolor: s.color }} />
                <Typography sx={{ fontSize: 11, color: "text.secondary" }}>{s.label.toLowerCase()}</Typography>
              </Box>
            ))}
            <Box onClick={() => navigate("/data-model")} sx={{
              ml: "auto", fontSize: 12, color: "primary.main",
              border: "1px solid", borderColor: "divider", px: 1.5, py: 0.5, borderRadius: "20px", cursor: "pointer",
              "&:hover": { bgcolor: alpha("#1565C0", 0.06) },
            }}>
              Relationship Explorer →
            </Box>
          </Box>
        </Box>

        {sel && selNode && selStats && (
          <OntologyStatPanel entity={selStatKey ?? sel} stats={selStats} color={selNode.color} route={ONT_ROUTES[sel] ?? ""} />
        )}
      </Box>
    </Box>
  );
}

// ── Main Hub ──────────────────────────────────────────────────────────────────

export default function Hub() {
  useEffect(() => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@600;700&display=swap";
    document.head.appendChild(link);
    return () => { document.head.removeChild(link); };
  }, []);

  const { data: accounts = [], isLoading: acctLoading } = useQuery<Client[]>({
    queryKey: ["clients"],
    queryFn: clientsApi.list,
    staleTime: 60_000,
  });

  const { data: dash = null, isLoading: dashLoading } = useQuery<DashSummary | null>({
    queryKey: ["dashboard-summary"],
    queryFn: () => dashboardApi.summary().catch(() => null),
    staleTime: 60_000,
  });

  const loading = acctLoading || dashLoading;

  const RAIL = "linear-gradient(180deg,#2563eb,#0f766e 25%,#b45309 50%,#b91c1c 65%,#15803d 80%,#4338ca)";

  return (
    <>
      <Box sx={{ display: "flex", flexDirection: "column", minHeight: "100vh", bgcolor: "background.default" }}>

        {/* Top bar */}
        <Box sx={{
          position: "sticky", top: 0, zIndex: 1200,
          bgcolor: "background.paper",
          borderBottom: "1px solid", borderColor: "divider",
          height: 52,
        }}>
          <MegaMenuBar brand={<OwletLogo height={32} />} trailing={<AppControls />} />
        </Box>

        {/* Main content */}
        <Box sx={{ flex: 1, overflow: "auto", px: { xs: 2.5, md: 6 }, py: { xs: 4, md: 6 }, pb: 12, maxWidth: 1200, mx: "auto", width: "100%" }}>

          {/* Hero */}
          <Box sx={{ mb: 7 }}>
            <Typography sx={{
              fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700,
              fontSize: { xs: 28, md: 42 }, letterSpacing: "-0.02em", lineHeight: 1.1, mb: 1.5,
            }}>
              One{" "}
              <Box component="span" sx={{ background: RAIL, WebkitBackgroundClip: "text", backgroundClip: "text", color: "transparent" }}>
                signal path
              </Box>
              , from setup to evidence.
            </Typography>
            <Typography sx={{ color: "text.secondary", fontSize: "0.97rem", maxWidth: 560 }}>
              Six stages run in order — each hands its output to the next. Hover the nav above to jump anywhere, or click a card below.
            </Typography>
          </Box>

          {/* Pipeline */}
          <Box sx={{ position: "relative" }}>
            {/* Vertical rail */}
            <Box sx={{ position: "absolute", left: 23, top: 14, bottom: 14, width: 2, background: RAIL, opacity: 0.35 }} />

            {STAGE_DEFS.map((stage, si) => (
              <StageSection
                key={stage.id}
                stage={stage}
                si={si}
                accounts={accounts}
                dash={dash}
                loading={loading}
              />
            ))}
          </Box>

          {/* Ontology */}
          <OntologyMini />

          {/* Footer */}
          <Box sx={{ mt: 8, pt: 3, borderTop: "1px solid", borderColor: "divider", display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 1 }}>
            <Typography sx={{ fontSize: "0.72rem", color: "text.disabled", fontFamily: "monospace" }}>
              SETUP · DISCOVER · ANALYSE · RESPOND · REPORT · AUTOMATE
            </Typography>
            <Typography sx={{ fontSize: "0.72rem", color: "text.disabled", fontFamily: "monospace" }}>
              Owlet · NexGenAI
            </Typography>
          </Box>
        </Box>
      </Box>
      <AssistantWidget />
    </>
  );
}
