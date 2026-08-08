import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Avatar, Card, CardActionArea,
  List, ListItemButton, ListItemText, Divider,
  FormControl, Select, MenuItem, Drawer, IconButton,
  Tooltip, useMediaQuery, useTheme, alpha,
} from "@mui/material";
import {
  Shield, BugReport, Psychology, Radar, Assessment,
  GppBad, PlaylistAddCheck, SmartToy, Cable, Settings,
  Storage, Menu as MenuIcon, Help as HelpOutline,
  Dashboard, AutoStories, Tune, Policy,
  Hub as HubIcon,
} from "@mui/icons-material";
import MegaMenuBar from "../components/layout/MegaMenuBar";
import OwletLogo from "../components/OwletLogo";
import { useMsal } from "@azure/msal-react";
import { useQuery } from "@tanstack/react-query";
import { adminApi, clientsApi } from "../services/api";
import AssistantWidget from "../components/AssistantWidget";
import { MyAccess, Client } from "../types";
import { useActiveClient } from "../contexts/ClientContext";

// ── Stage + product data ──────────────────────────────────────────────────────

interface StageProduct {
  abbrev: string;
  name: string;
  desc: string;
  route: string;
  Icon: React.ElementType;
}

interface Stage {
  num: string;
  id: string;
  label: string;
  color: string;
  bgColor: string;
  title: string;
  sub: string;
  products: StageProduct[];
}

const STAGES: Stage[] = [
  {
    num: "01", id: "setup", label: "Setup",
    color: "#2563eb", bgColor: "#EFF6FF",
    title: "Stand up the environment",
    sub: "Get the tenant ready — clients, connectors, and AI providers.",
    products: [
      { abbrev: "ST", name: "Setup",    desc: "Clients, assets, connectors, AI providers, and platform settings.", route: "/platform",    Icon: Tune },
    ],
  },
  {
    num: "02", id: "design", label: "Design",
    color: "#7c3aed", bgColor: "#F5F3FF",
    title: "Define the blueprint",
    sub: "Model how data moves, then pick which standards it has to satisfy.",
    products: [
      { abbrev: "TM", name: "Threat Models",  desc: "Data flow diagrams, STRIDE analysis, and Sigma detection rules.", route: "/threat-intel/threat-models", Icon: HubIcon   },
      { abbrev: "FW", name: "Frameworks",     desc: "NIST, CIS, ISO 27001, PCI DSS, GDPR, and custom standards.",    route: "/compliance/frameworks",     Icon: Policy    },
    ],
  },
  {
    num: "03", id: "discover", label: "Discover",
    color: "#0f766e", bgColor: "#F0FDFA",
    title: "Find what's actually exposed",
    sub: "Scan the environment — manually or through a guided AI conversation.",
    products: [
      { abbrev: "VM", name: "Vulnerability Management", desc: "Scans, findings, posture trends, CVE enrichment, and scan import.",    route: "/vulnerability",                Icon: BugReport  },
      { abbrev: "AI", name: "AI Assisted Scan",         desc: "Conversational guided assessment — describe your environment, launch a scan.", route: "/intelligence/ai-assisted-scan", Icon: SmartToy   },
    ],
  },
  {
    num: "04", id: "analyse", label: "Analyse",
    color: "#b45309", bgColor: "#FFFBEB",
    title: "Turn findings into risk",
    sub: "Score findings, map attack paths, and query your entire posture in plain language.",
    products: [
      { abbrev: "RM", name: "Risk Manager",       desc: "FAIR-scored risk register, ALE exposure, and attack path graph.", route: "/risk",          Icon: Assessment  },
      { abbrev: "IG", name: "Smart Intelligence", desc: "Natural language queries, compliance heatmap, and asset inventory.", route: "/intelligence", Icon: Psychology  },
    ],
  },
  {
    num: "05", id: "respond", label: "Respond",
    color: "#b91c1c", bgColor: "#FEF2F2",
    title: "Act on the picture",
    sub: "Map risk to real adversary behaviour, then track remediation programs.",
    products: [
      { abbrev: "TI", name: "Threat Intelligence", desc: "MITRE ATT&CK threat register and attack path visualisation.", route: "/threat-intel",    Icon: Radar           },
      { abbrev: "GR", name: "Governance",           desc: "CTEM programs, control gaps, remediation tracker, and scorecard.", route: "/governance", Icon: PlaylistAddCheck },
    ],
  },
  {
    num: "06", id: "report", label: "Report",
    color: "#15803d", bgColor: "#F0FDF4",
    title: "Prove it happened",
    sub: "Close the loop with evidence the client — or the auditor — can keep.",
    products: [
      { abbrev: "PT", name: "Pen Testing / VAPT",   desc: "VAPT reports with retest lifecycle and PDF/DOCX export.",           route: "/vapt",       Icon: Shield        },
      { abbrev: "CM", name: "Compliance Monitor",   desc: "Framework assessments, evidence packages, and audit-ready output.", route: "/compliance", Icon: GppBad        },
    ],
  },
  {
    num: "07", id: "automate", label: "Automate",
    color: "#4338ca", bgColor: "#EEF2FF",
    title: "Let AI carry the load",
    sub: "Agents run the loop — analysis, intel, remediation, knowledge — on repeat.",
    products: [
      { abbrev: "AB", name: "AI Buddies",       desc: "60+ AI agents — orchestrator, risk manager, threat intel, remediation.", route: "/ai-advisor",           Icon: SmartToy   },
      { abbrev: "KB", name: "Knowledge & Docs", desc: "Knowledge base, security doc RAG, and ask-your-data queries.",          route: "/intelligence/knowledge", Icon: AutoStories },
    ],
  },
];

const QUICK_NAV = [
  { label: "Dashboard",  Icon: Dashboard,    route: "/dashboard"   },
  { label: "Connectors", Icon: Cable,        route: "/connections" },
  { label: "Assets",     Icon: Storage,      route: "/assets"      },
  { label: "AI Buddies", Icon: SmartToy,     route: "/agents"      },
  { label: "Settings",   Icon: Settings,     route: "/settings"    },
  { label: "Help",       Icon: HelpOutline,  route: "/help"        },
];

// ── Client picker ─────────────────────────────────────────────────────────────

function ClientPicker() {
  const { clientId, setClientId } = useActiveClient();
  const { data: clients = [], isLoading } = useQuery<Client[]>({
    queryKey: ["clients"], queryFn: clientsApi.list, staleTime: 60_000,
  });
  return (
    <FormControl fullWidth size="small" sx={{ px: 1.5, py: 1 }}>
      <Select
        displayEmpty value={clientId || ""}
        onChange={(e) => setClientId(e.target.value as string)}
        disabled={isLoading || clients.length === 0}
        sx={{ fontSize: 12, bgcolor: "background.default", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
      >
        <MenuItem value="" disabled><em>{isLoading ? "Loading…" : "Select client…"}</em></MenuItem>
        {clients.map((c) => <MenuItem key={c.id} value={c.id} sx={{ fontSize: 12 }}>{c.name}</MenuItem>)}
      </Select>
    </FormControl>
  );
}

// ── Sidebar content ───────────────────────────────────────────────────────────

function SidebarContent({ onClose }: { onClose?: () => void }) {
  const navigate = useNavigate();
  const { accounts } = useMsal();
  const { data: me } = useQuery<MyAccess>({ queryKey: ["my-access"], queryFn: adminApi.me, retry: 0, staleTime: 60_000 });

  const go = (p: string) => { navigate(p); onClose?.(); };

  return (
    <Box sx={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* Logo */}
      <Box sx={{ px: 1.5, py: 1.5 }}>
        <OwletLogo height={32} />
      </Box>

      <Divider />
      <ClientPicker />
      <Divider />

      {/* Stage nav */}
      <Typography sx={{ px: 2, pt: 1.5, pb: 0.5, fontSize: 10, fontWeight: 700, color: "text.disabled", textTransform: "uppercase", letterSpacing: 1 }}>
        Phases
      </Typography>
      <List dense disablePadding sx={{ px: 1 }}>
        {STAGES.map((s) => (
          <ListItemButton
            key={s.id}
            onClick={() => { document.getElementById(`stage-${s.id}`)?.scrollIntoView({ behavior: "smooth" }); onClose?.(); }}
            sx={{ borderRadius: 1.5, mb: 0.25, gap: 1, "&:hover": { bgcolor: alpha(s.color, 0.07) } }}
          >
            <Box sx={{
              width: 24, height: 24, borderRadius: "50%", flexShrink: 0,
              border: `1.5px solid ${s.color}`,
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <Typography sx={{ fontFamily: "monospace", fontSize: "0.58rem", fontWeight: 700, color: s.color, lineHeight: 1 }}>
                {s.num}
              </Typography>
            </Box>
            <ListItemText
              primary={s.label}
              slotProps={{ primary: { sx: { fontSize: 13 } } }}
            />
          </ListItemButton>
        ))}
      </List>

      <Divider sx={{ mt: 1 }} />

      {/* Quick nav */}
      <Typography sx={{ px: 2, pt: 1.5, pb: 0.5, fontSize: 10, fontWeight: 700, color: "text.disabled", textTransform: "uppercase", letterSpacing: 1 }}>
        Quick Access
      </Typography>
      <List dense disablePadding sx={{ px: 1 }}>
        {QUICK_NAV.map(({ label, Icon, route }) => (
          <ListItemButton key={label} onClick={() => go(route)} sx={{ borderRadius: 1.5, mb: 0.25, gap: 1 }}>
            <Icon sx={{ fontSize: 16, color: "text.secondary" }} />
            <ListItemText primary={label} slotProps={{ primary: { sx: { fontSize: 13 } } }} />
          </ListItemButton>
        ))}
      </List>

      {/* User */}
      <Box sx={{ mt: "auto", px: 2, py: 1.5, borderTop: "1px solid", borderColor: "divider", display: "flex", alignItems: "center", gap: 1.5 }}>
        <Avatar sx={{ width: 28, height: 28, fontSize: 11, bgcolor: "primary.main" }}>
          {(accounts[0]?.name || "U").charAt(0).toUpperCase()}
        </Avatar>
        <Box sx={{ minWidth: 0 }}>
          <Typography noWrap sx={{ fontSize: 12, fontWeight: 600 }}>{accounts[0]?.name || "User"}</Typography>
          {me?.is_admin && <Typography sx={{ fontSize: 10, color: "primary.main", fontWeight: 600 }}>Admin</Typography>}
        </Box>
      </Box>
    </Box>
  );
}

// ── Product card (sample4 style) ──────────────────────────────────────────────

function ProductCard({ p, stageColor, stageBg }: { p: StageProduct; stageColor: string; stageBg: string }) {
  const navigate = useNavigate();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const cardBg = isDark ? alpha(stageColor, 0.08) : stageBg;

  return (
    <Card elevation={0} sx={{
      border: "1px solid", borderColor: "divider",
      borderRadius: 2, overflow: "hidden",
      transition: "box-shadow .18s, transform .18s, border-color .18s",
      "&:hover": { boxShadow: `0 4px 20px ${alpha(stageColor, 0.18)}`, transform: "translateY(-2px)", borderColor: stageColor },
    }}>
      <CardActionArea onClick={() => navigate(p.route)} sx={{ display: "flex", alignItems: "center", p: 0 }}>
        {/* Left accent */}
        <Box sx={{
          width: 68, flexShrink: 0, alignSelf: "stretch",
          bgcolor: cardBg,
          display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 0.5,
          borderRight: "1px solid", borderColor: "divider",
        }}>
          <p.Icon sx={{ fontSize: 22, color: stageColor }} />
          <Typography sx={{ fontSize: 10, fontWeight: 800, color: stageColor, letterSpacing: 0.5 }}>
            {p.abbrev}
          </Typography>
        </Box>
        {/* Right content */}
        <Box sx={{ px: 2, py: 1.5, flexGrow: 1, textAlign: "left" }}>
          <Typography sx={{ fontWeight: 700, fontSize: 14, lineHeight: 1.3, mb: 0.4 }}>
            {p.name}
          </Typography>
          <Typography sx={{ fontSize: 12, color: "text.secondary", lineHeight: 1.45 }}>
            {p.desc}
          </Typography>
        </Box>
      </CardActionArea>
    </Card>
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
  Client:"clients", Asset:"assets", Control:"compliance/frameworks",
  DataFlow:"threat-intel/threat-models", Finding:"vulnerability/findings",
  SmartIntel:"intelligence/nl-query", Risk:"risk/register",
  Evidence:"compliance/evidence", AttackPath:"threat-intel/attack-paths",
  Technique:"threat-intel/register", Remediation:"governance/remediation",
  Report:"vapt/reports",
};

function OntologyMini() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [sel, setSel] = useState<string | null>(null);
  const isDark = theme.palette.mode === "dark";
  const edgeCol  = isDark ? "#3a4250" : "#c3c9d4";
  const raisedBg = isDark ? "#141b25" : "#f2f4f8";
  const lineBdr  = isDark ? "#232b36" : "#e6e9ef";

  const eStyle = (e: OEdge) => {
    const hit = sel && (e.from === sel || e.to === sel);
    const dim = sel && !hit;
    return { stroke: hit ? "#4338ca" : edgeCol, strokeWidth: hit ? 2.4 : 1.6, opacity: dim ? 0.1 : 1, strokeDasharray: e.dashed ? "3 4" : undefined };
  };

  return (
    <Box sx={{ mt: 6, pt: 5, borderTop: "1px solid", borderColor: "divider" }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.75 }}>
        <Box sx={{ width: 4, height: 20, borderRadius: 2, bgcolor: "#4338ca" }} />
        <Typography sx={{ fontWeight: 700, fontSize: 15 }}>Data Ontology</Typography>
      </Box>
      <Typography sx={{ fontSize: 13, color: "text.secondary", mb: 2.5, maxWidth: 600 }}>
        Eleven entities, one connected data model. Click any node to trace connections — double-click to open that module.
      </Typography>

      <Box sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "divider", borderRadius: 2, p: 2.5, overflowX: "auto" }}>
        <svg viewBox="0 0 1120 640" style={{ width: "100%", minWidth: 540, height: "auto", display: "block" }}>
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
              return (
                <g key={n.entity} style={{ cursor: "pointer", opacity: dim ? 0.2 : 1, transition: "opacity 0.18s" }}
                   onClick={() => setSel((p) => p === n.entity ? null : n.entity)}
                   onDoubleClick={() => navigate(`/${ONT_ROUTES[n.entity] ?? ""}`)}
                >
                  <circle cx={n.cx} cy={n.cy} r={lit ? 10 : 7} fill={n.color} stroke={isDark ? "#0b0f14" : "#fff"} strokeWidth={2} style={{ transition: "r 0.15s" }} />
                  <rect x={n.labelX} y={n.cy+12} width={n.labelW} height={22} rx={11} fill={lit ? n.color : raisedBg} stroke={lit ? n.color : lineBdr} strokeWidth={1} style={{ transition: "fill 0.15s" }} />
                  <text x={n.cx} y={n.cy+27} textAnchor="middle" dominantBaseline="middle" fontFamily="monospace" fontSize={11} fontWeight={lit ? 600 : 500} fill={lit ? "#fff" : theme.palette.text.primary} style={{ transition: "fill 0.15s" }}>
                    {n.label}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Legend + link */}
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, mt: 2, pt: 2, borderTop: "1px solid", borderColor: "divider", alignItems: "center" }}>
          {STAGES.map((s) => (
            <Box key={s.id} sx={{ display: "flex", alignItems: "center", gap: 0.75, fontSize: 11, color: "text.secondary" }}>
              <Box sx={{ width: 9, height: 9, borderRadius: "50%", bgcolor: s.color }} />
              <Typography sx={{ fontSize: 11, color: "text.secondary" }}>{s.label.toLowerCase()}</Typography>
            </Box>
          ))}
          <Box
            onClick={() => navigate("/data-model")}
            sx={{ ml: "auto", fontSize: 12, color: "primary.main", border: "1px solid", borderColor: "divider", px: 1.5, py: 0.5, borderRadius: "20px", cursor: "pointer", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.06) } }}
          >
            Full screen →
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

// ── Main Hub ──────────────────────────────────────────────────────────────────

const DRAWER_WIDTH = 220;

export default function Hub() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [drawerOpen, setDrawerOpen] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@600;700&display=swap";
    document.head.appendChild(link);
    return () => { document.head.removeChild(link); };
  }, []);

  const RAIL = "linear-gradient(180deg,#2563eb,#7c3aed 22%,#0f766e 38%,#b45309 54%,#b91c1c 70%,#15803d 84%,#4338ca)";

  return (
    <>
      <Box sx={{ display: "flex", minHeight: "100vh", bgcolor: "background.default" }}>

        {/* Mobile drawer */}
        <Drawer anchor="left" open={drawerOpen} onClose={() => setDrawerOpen(false)}
          sx={{ display: { xs: "block", md: "none" }, "& .MuiDrawer-paper": { width: DRAWER_WIDTH, bgcolor: "background.paper" } }}>
          <SidebarContent onClose={() => setDrawerOpen(false)} />
        </Drawer>

        {/* Desktop sidebar — same style as ProductLayout */}
        <Box sx={{
          width: DRAWER_WIDTH, flexShrink: 0,
          bgcolor: "background.paper",
          borderRight: "1px solid", borderColor: "divider",
          display: { xs: "none", md: "flex" }, flexDirection: "column",
          position: "sticky", top: 0, height: "100vh", overflowY: "auto",
        }}>
          <SidebarContent />
        </Box>

        {/* Page content */}
        <Box sx={{ flexGrow: 1, display: "flex", flexDirection: "column", minHeight: "100vh" }}>

          {/* Top bar with mega menu */}
          <Box sx={{
            position: "sticky", top: 0, zIndex: 1200,
            bgcolor: "background.paper",
            borderBottom: "1px solid", borderColor: "divider",
            height: 52,
          }}>
            <MegaMenuBar
              brand={
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                  {isMobile && (
                    <IconButton size="small" onClick={() => setDrawerOpen(true)} sx={{ mr: 0.5 }}>
                      <MenuIcon fontSize="small" />
                    </IconButton>
                  )}
                  <OwletLogo height={36} />
                </Box>
              }
              trailing={
                <Tooltip title="Dashboard">
                  <IconButton size="small" onClick={() => navigate("/dashboard")} sx={{ color: "text.secondary" }}>
                    <Dashboard fontSize="small" />
                  </IconButton>
                </Tooltip>
              }
            />
          </Box>

          {/* Main scrollable area */}
          <Box sx={{ flex: 1, overflow: "auto", px: { xs: 2.5, md: 5 }, py: { xs: 4, md: 6 }, pb: 12 }}>

            {/* Hero */}
            <Box sx={{ mb: 6 }}>
              <Typography sx={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700, fontSize: { xs: 26, md: 36 }, letterSpacing: "-0.02em", lineHeight: 1.1, mb: 1.5 }}>
                One{" "}
                <Box component="span" sx={{ background: RAIL, WebkitBackgroundClip: "text", backgroundClip: "text", color: "transparent" }}>
                  signal path
                </Box>
                , from setup to evidence.
              </Typography>
              <Typography sx={{ color: "text.secondary", fontSize: "0.97rem", maxWidth: 560 }}>
                Seven stages run in order — each hands its output to the next. Every product card opens directly into that module.
              </Typography>
            </Box>

            {/* Pipeline */}
            <Box sx={{ position: "relative" }}>
              {/* Rail */}
              <Box sx={{ position: "absolute", left: 23, top: 14, bottom: 14, width: 2, background: RAIL, opacity: 0.4 }} />

              {STAGES.map((stage, si) => (
                <Box
                  key={stage.id}
                  id={`stage-${stage.id}`}
                  sx={{
                    position: "relative", pl: "64px",
                    mb: si < STAGES.length - 1 ? 6 : 0,
                    scrollMarginTop: 24,
                    opacity: 0, transform: "translateY(12px)",
                    animation: `hubrise 0.5s ease ${si * 0.06}s forwards`,
                    "@keyframes hubrise": { to: { opacity: 1, transform: "translateY(0)" } },
                  }}
                >
                  {/* Stage node */}
                  <Box sx={{
                    position: "absolute", left: 0, top: 0,
                    width: 48, height: 48, borderRadius: "50%",
                    bgcolor: "background.default",
                    border: `2px solid ${stage.color}`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontFamily: "monospace", fontWeight: 700, fontSize: "1rem",
                    color: stage.color,
                    boxShadow: `0 0 0 4px background.default, 0 0 18px -4px ${stage.color}`,
                    zIndex: 2,
                  }}>
                    {stage.num}
                  </Box>

                  {/* Stage header */}
                  <Box sx={{ pt: "4px", mb: 2 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                      <Box sx={{ width: 4, height: 16, borderRadius: 2, bgcolor: stage.color }} />
                      <Typography sx={{ fontSize: "0.72rem", fontWeight: 700, color: stage.color, textTransform: "uppercase", letterSpacing: "0.1em" }}>
                        Stage {stage.num} · {stage.label}
                      </Typography>
                    </Box>
                    <Typography sx={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: { xs: 18, md: 22 }, fontWeight: 600, letterSpacing: "-0.01em", mb: 0.5 }}>
                      {stage.title}
                    </Typography>
                    <Typography sx={{ color: "text.secondary", fontSize: "0.88rem", maxWidth: 540 }}>
                      {stage.sub}
                    </Typography>
                  </Box>

                  {/* Product cards */}
                  <Box sx={{
                    display: "grid",
                    gridTemplateColumns: stage.products.length === 1 ? "minmax(0,520px)" : { xs: "1fr", sm: "1fr 1fr" },
                    gap: 1.5,
                  }}>
                    {stage.products.map((p) => (
                      <ProductCard key={p.abbrev} p={p} stageColor={stage.color} stageBg={stage.bgColor} />
                    ))}
                  </Box>
                </Box>
              ))}
            </Box>

            {/* Ontology section */}
            <OntologyMini />

            {/* Footer */}
            <Box sx={{ mt: 8, pt: 3, borderTop: "1px solid", borderColor: "divider", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 1 }}>
              <Typography sx={{ fontSize: "0.72rem", color: "text.disabled", fontFamily: "monospace" }}>
                SETUP · DESIGN · DISCOVER · ANALYSE · RESPOND · REPORT · AUTOMATE
              </Typography>
              <Typography sx={{ fontSize: "0.72rem", color: "text.disabled", fontFamily: "monospace" }}>
                Owlet · NexGenAI
              </Typography>
            </Box>
          </Box>
        </Box>
      </Box>
      <AssistantWidget />
    </>
  );
}
