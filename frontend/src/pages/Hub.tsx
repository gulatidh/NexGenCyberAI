import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Avatar, List, ListItemButton, ListItemText,
  Divider, FormControl, Select, MenuItem, Drawer, IconButton,
  useMediaQuery, useTheme, alpha,
} from "@mui/material";
import {
  Shield, SmartToy, Cable, Settings,
  Storage, Menu as MenuIcon, Help as HelpOutline, Dashboard, AutoStories,
} from "@mui/icons-material";
import { useMsal } from "@azure/msal-react";
import { useQuery } from "@tanstack/react-query";
import { adminApi, clientsApi } from "../services/api";
import AssistantWidget from "../components/AssistantWidget";
import { MyAccess, Client } from "../types";
import { useActiveClient } from "../contexts/ClientContext";

// ── Stage definitions ─────────────────────────────────────────────────────────

interface StageModule {
  tag: string;
  name: string;
  desc: string;
  route: string;
  chips: { label: string; route: string }[];
}

interface Stage {
  num: string;
  id: string;
  label: string;
  color: string;
  title: string;
  sub: string;
  modules: StageModule[];
}

const STAGES: Stage[] = [
  {
    num: "01", id: "setup", label: "Setup", color: "#3b82f6",
    title: "Stand up the environment",
    sub: "Nothing downstream works without this. Get the tenant ready — clients, connectors, and AI providers.",
    modules: [
      {
        tag: "ST", name: "Setup", route: "/platform",
        desc: "Clients, assets, connectors, AI providers, and platform settings.",
        chips: [
          { label: "Clients",      route: "/clients" },
          { label: "Assets",       route: "/assets" },
          { label: "Connectors",   route: "/connections" },
          { label: "AI providers", route: "/connections" },
          { label: "Settings",     route: "/settings" },
        ],
      },
    ],
  },
  {
    num: "02", id: "design", label: "Design", color: "#a855f7",
    title: "Define the blueprint",
    sub: "Model how data actually moves, then pick which standards it has to satisfy.",
    modules: [
      {
        tag: "TM", name: "Threat Models", route: "/threat-intel/threat-models",
        desc: "Data flow diagrams, STRIDE analysis, and Sigma detection rules.",
        chips: [
          { label: "Data flow diagrams",    route: "/threat-intel/threat-models" },
          { label: "STRIDE analysis",       route: "/threat-intel/threat-models" },
          { label: "Sigma detection rules", route: "/threat-intel/threat-models" },
        ],
      },
      {
        tag: "FW", name: "Frameworks", route: "/compliance/frameworks",
        desc: "NIST, CIS, ISO 27001, PCI DSS, GDPR, and custom standards.",
        chips: [
          { label: "NIST CSF",       route: "/compliance/frameworks" },
          { label: "CIS Controls",   route: "/compliance/frameworks" },
          { label: "ISO 27001",      route: "/compliance/frameworks" },
          { label: "PCI DSS",        route: "/compliance/frameworks" },
          { label: "GDPR",           route: "/compliance/frameworks" },
          { label: "Custom policy",  route: "/compliance/custom-frameworks" },
        ],
      },
    ],
  },
  {
    num: "03", id: "discover", label: "Discover", color: "#14b8a6",
    title: "Find what's actually exposed",
    sub: "Scan the environment the blueprint just described — manually or through a guided AI conversation.",
    modules: [
      {
        tag: "VM", name: "Vulnerability Management", route: "/vulnerability",
        desc: "Scans, findings, posture trends, CVE enrichment, and scan import.",
        chips: [
          { label: "Scans",           route: "/vulnerability/scans" },
          { label: "Findings",        route: "/vulnerability/findings" },
          { label: "CVE enrichment",  route: "/vulnerability/findings" },
          { label: "Posture trends",  route: "/vulnerability/posture" },
          { label: "Scan import",     route: "/vulnerability/scans" },
        ],
      },
      {
        tag: "AI", name: "AI Assisted Scan", route: "/intelligence/ai-assisted-scan",
        desc: "Conversational guided assessment — describe your environment, launch a scan.",
        chips: [
          { label: "Guided wizard",    route: "/intelligence/ai-assisted-scan" },
          { label: "Environment chat", route: "/intelligence/ai-assisted-scan" },
          { label: "Auto-launch",      route: "/intelligence/ai-assisted-scan" },
        ],
      },
    ],
  },
  {
    num: "04", id: "analyse", label: "Analyse", color: "#f59e0b",
    title: "Turn findings into risk",
    sub: "Raw findings get scored, attack paths mapped, and the whole posture becomes queryable in plain language.",
    modules: [
      {
        tag: "RM", name: "Risk Manager", route: "/risk",
        desc: "FAIR-scored risk register, ALE exposure, and attack path graph.",
        chips: [
          { label: "Risk register",  route: "/risk/register" },
          { label: "FAIR / ALE",     route: "/risk/overview" },
          { label: "Attack paths",   route: "/threat-intel/attack-paths" },
          { label: "CVE blast radius", route: "/intelligence/nl-query" },
        ],
      },
      {
        tag: "IG", name: "Smart Intelligence", route: "/intelligence",
        desc: "Natural language queries, compliance heatmap, and asset inventory.",
        chips: [
          { label: "Ask your data",       route: "/intelligence/nl-query" },
          { label: "Compliance heatmap",  route: "/intelligence/reports" },
          { label: "Client comparison",   route: "/intelligence/reports" },
          { label: "Asset inventory",     route: "/platform/assets" },
        ],
      },
    ],
  },
  {
    num: "05", id: "respond", label: "Respond", color: "#ef4444",
    title: "Act on the picture",
    sub: "Map risk to real adversary behaviour, then push it into a tracked remediation program.",
    modules: [
      {
        tag: "TI", name: "Threat Intelligence", route: "/threat-intel",
        desc: "MITRE ATT&CK threat register and attack path visualisation.",
        chips: [
          { label: "Threat register",   route: "/threat-intel/register" },
          { label: "MITRE ATT&CK",      route: "/threat-intel/register" },
          { label: "Attack paths",      route: "/threat-intel/attack-paths" },
        ],
      },
      {
        tag: "GR", name: "Governance", route: "/governance",
        desc: "CTEM programs, control gaps, remediation tracker, and scorecard.",
        chips: [
          { label: "CTEM programs",     route: "/governance/ctem" },
          { label: "Control gaps",      route: "/compliance/deficiencies" },
          { label: "Remediation",       route: "/governance/remediation" },
          { label: "AI remediations",   route: "/governance/remediation-jobs" },
        ],
      },
    ],
  },
  {
    num: "06", id: "report", label: "Report", color: "#22c55e",
    title: "Prove it happened",
    sub: "Close the loop with evidence the client — or the auditor — can actually keep.",
    modules: [
      {
        tag: "PT", name: "Pen Testing / VAPT", route: "/vapt",
        desc: "VAPT reports with retest lifecycle and PDF/DOCX export.",
        chips: [
          { label: "VAPT reports",   route: "/vapt/reports" },
          { label: "Retest lifecycle", route: "/vapt/reports" },
          { label: "PDF / DOCX",     route: "/vapt/reports" },
          { label: "Attack evidence", route: "/vapt/attack-paths" },
        ],
      },
      {
        tag: "CM", name: "Compliance Monitor", route: "/compliance",
        desc: "Framework assessments, evidence packages, and audit-ready output.",
        chips: [
          { label: "Framework assessments", route: "/compliance/frameworks" },
          { label: "Evidence packages",     route: "/compliance/evidence" },
          { label: "Control deficiencies",  route: "/compliance/deficiencies" },
          { label: "Posture trends",        route: "/vulnerability/posture" },
        ],
      },
    ],
  },
  {
    num: "07", id: "automate", label: "Automate", color: "#6366f1",
    title: "Let AI carry the load",
    sub: "Once the first run is done, agents run the loop — analysis, intel, remediation, knowledge — on repeat.",
    modules: [
      {
        tag: "AB", name: "AI Buddies", route: "/ai-advisor",
        desc: "60+ AI agents — orchestrator, risk manager, threat intel, remediation.",
        chips: [
          { label: "Orchestrator",      route: "/ai-advisor/agents" },
          { label: "Risk Manager",      route: "/ai-advisor/agents" },
          { label: "Threat Intel",      route: "/ai-advisor/agents" },
          { label: "Remediation",       route: "/ai-advisor/agents" },
          { label: "Workflows",         route: "/ai-advisor/workflows" },
        ],
      },
      {
        tag: "KB", name: "Knowledge & Docs", route: "/intelligence/knowledge",
        desc: "Knowledge base, security doc RAG, and ask-your-data queries.",
        chips: [
          { label: "Knowledge base",  route: "/intelligence/knowledge" },
          { label: "Security docs",   route: "/intelligence/security-docs" },
          { label: "Ask your data",   route: "/intelligence/nl-query" },
          { label: "Webhooks",        route: "/platform/settings" },
          { label: "API keys",        route: "/platform/settings" },
        ],
      },
    ],
  },
];

const QUICK_NAV = [
  { label: "Dashboard",    icon: <Dashboard sx={{ fontSize: 16 }} />,     route: "/dashboard" },
  { label: "Connections",  icon: <Cable sx={{ fontSize: 16 }} />,          route: "/connections" },
  { label: "AI Buddies",   icon: <SmartToy sx={{ fontSize: 16 }} />,       route: "/agents" },
  { label: "Assets",       icon: <Storage sx={{ fontSize: 16 }} />,        route: "/assets" },
  { label: "Settings",     icon: <Settings sx={{ fontSize: 16 }} />,       route: "/settings" },
  { label: "Data Model",   icon: <AutoStories sx={{ fontSize: 16 }} />,    route: "/data-model" },
  { label: "Help",         icon: <HelpOutline sx={{ fontSize: 16 }} />,    route: "/help" },
];

// ── Client picker ─────────────────────────────────────────────────────────────

function ClientPicker() {
  const { clientId, setClientId } = useActiveClient();
  const { data: clients = [], isLoading } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list, staleTime: 60_000 });
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

// ── Sidebar ───────────────────────────────────────────────────────────────────

function Sidebar({ accounts, me, navigate, onClose }: { accounts: any[]; me: MyAccess | undefined; navigate: (p: string) => void; onClose?: () => void }) {
  const go = (p: string) => { navigate(p); onClose?.(); };
  return (
    <Box sx={{ display: "flex", flexDirection: "column", height: "100%", py: 2 }}>
      {/* Logo */}
      <Box sx={{ px: 2, mb: 2 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
          <Box sx={{ width: 34, height: 34, borderRadius: 1.5, background: "linear-gradient(135deg,#3b82f6,#6366f1)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Shield sx={{ color: "#fff", fontSize: 18 }} />
          </Box>
          <Box>
            <Typography sx={{ fontWeight: 800, fontSize: 14, lineHeight: 1.1 }}>Owlet</Typography>
            <Typography sx={{ fontSize: 10, color: "text.secondary" }}>Security Platform</Typography>
          </Box>
        </Box>
      </Box>

      <Divider />
      <ClientPicker />
      <Divider sx={{ mb: 1 }} />

      {/* Phase shortcuts */}
      <Typography sx={{ px: 2, pb: 0.5, fontSize: 10, fontWeight: 700, color: "text.secondary", textTransform: "uppercase", letterSpacing: 1 }}>
        Phases
      </Typography>
      <List dense disablePadding sx={{ px: 1, mb: 1 }}>
        {STAGES.map((s) => (
          <ListItemButton key={s.id} onClick={() => { document.getElementById(`stage-${s.id}`)?.scrollIntoView({ behavior: "smooth" }); onClose?.(); }}
            sx={{ borderRadius: 1.5, mb: 0.25, gap: 1, "&:hover": { bgcolor: alpha(s.color, 0.08) } }}>
            <Box sx={{ width: 22, height: 22, borderRadius: "50%", border: `1.5px solid ${s.color}`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              <Typography sx={{ fontFamily: "monospace", fontSize: "0.6rem", fontWeight: 700, color: s.color }}>{s.num}</Typography>
            </Box>
            <ListItemText primary={s.label} slotProps={{ primary: { sx: { fontSize: 13 } } }} />
          </ListItemButton>
        ))}
      </List>

      <Divider sx={{ mb: 1 }} />

      {/* Quick nav */}
      <Typography sx={{ px: 2, pb: 0.5, fontSize: 10, fontWeight: 700, color: "text.secondary", textTransform: "uppercase", letterSpacing: 1 }}>
        Quick Access
      </Typography>
      <List dense disablePadding sx={{ px: 1 }}>
        {QUICK_NAV.map((item) => (
          <ListItemButton key={item.label} onClick={() => go(item.route)} sx={{ borderRadius: 1.5, mb: 0.25, gap: 1 }}>
            <Box sx={{ color: "text.secondary" }}>{item.icon}</Box>
            <ListItemText primary={item.label} slotProps={{ primary: { sx: { fontSize: 13 } } }} />
          </ListItemButton>
        ))}
      </List>

      {/* User */}
      <Box sx={{ mt: "auto", pt: 1.5, px: 2, borderTop: "1px solid", borderColor: "divider" }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
          <Avatar sx={{ width: 28, height: 28, fontSize: 11, bgcolor: "#3b82f6" }}>
            {(accounts[0]?.name || "U").charAt(0).toUpperCase()}
          </Avatar>
          <Box sx={{ minWidth: 0 }}>
            <Typography noWrap sx={{ fontSize: 12, fontWeight: 600 }}>{accounts[0]?.name || "User"}</Typography>
            {me?.is_admin && <Typography sx={{ fontSize: 10, color: "#3b82f6", fontWeight: 600 }}>Admin</Typography>}
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

// ── Feature chip ──────────────────────────────────────────────────────────────

function FeatureChip({ label, route, stageColor }: { label: string; route: string; stageColor: string }) {
  const navigate = useNavigate();
  const [active, setActive] = useState(false);
  return (
    <Box
      component="button"
      onClick={() => { setActive((v) => !v); navigate(route); }}
      sx={{
        fontFamily: "monospace", fontSize: "0.72rem", lineHeight: 1.2,
        color: active ? "#fff" : "text.secondary",
        bgcolor: active ? alpha(stageColor, 0.18) : "background.default",
        border: "1px solid", borderColor: active ? stageColor : "divider",
        px: 1.25, py: 0.65, borderRadius: "6px",
        cursor: "pointer", transition: "all 0.14s ease",
        "&:hover": { borderColor: stageColor, color: "text.primary" },
        "&::before": active ? { content: '"✓ "', color: stageColor } : {},
      }}
    >
      {active ? `✓ ${label}` : label}
    </Box>
  );
}

// ── Module card ───────────────────────────────────────────────────────────────

function ModuleCard({ mod, stageColor }: { mod: StageModule; stageColor: string }) {
  const navigate = useNavigate();
  return (
    <Box sx={{
      bgcolor: "background.paper",
      border: "1px solid", borderColor: "divider",
      borderRadius: "10px", p: "16px 18px",
      transition: "border-color 0.15s, transform 0.15s",
      "&:hover": { borderColor: stageColor, transform: "translateY(-1px)" },
    }}>
      {/* Tag + name */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.25, mb: 1, cursor: "pointer" }} onClick={() => navigate(mod.route)}>
        <Box sx={{
          fontFamily: "monospace", fontSize: "0.66rem", fontWeight: 700,
          color: stageColor, bgcolor: alpha(stageColor, 0.14),
          px: 0.9, py: 0.4, borderRadius: "4px", letterSpacing: "0.05em",
          flexShrink: 0,
        }}>
          {mod.tag}
        </Box>
        <Typography sx={{ fontWeight: 700, fontSize: "0.94rem", "&:hover": { color: stageColor } }}>
          {mod.name}
        </Typography>
      </Box>
      {/* Desc */}
      <Typography sx={{ color: "text.secondary", fontSize: "0.81rem", lineHeight: 1.55, mb: 1.25 }}>
        {mod.desc}
      </Typography>
      {/* Chips */}
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
        {mod.chips.map((c) => (
          <FeatureChip key={c.label} label={c.label} route={c.route} stageColor={stageColor} />
        ))}
      </Box>
    </Box>
  );
}

// ── Main Hub ──────────────────────────────────────────────────────────────────

export default function Hub() {
  const { accounts } = useMsal();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const isDark = theme.palette.mode === "dark";
  const navigate = useNavigate();

  const { data: me } = useQuery<MyAccess>({ queryKey: ["my-access"], queryFn: adminApi.me, retry: 0, staleTime: 60_000 });

  const displayName = accounts[0]?.name?.split(" ")[0] || accounts[0]?.username?.split("@")[0] || "there";

  // Load Space Grotesk + IBM Plex Mono for the pipeline design
  useEffect(() => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=IBM+Plex+Mono:wght@400;600&display=swap";
    document.head.appendChild(link);
    return () => { document.head.removeChild(link); };
  }, []);

  const RAIL_GRADIENT = "linear-gradient(180deg,#3b82f6,#a855f7 25%,#14b8a6 42%,#f59e0b 58%,#ef4444 75%,#22c55e 88%,#6366f1)";

  const sidebarProps = { accounts, me, navigate, onClose: () => setDrawerOpen(false) };

  return (
    <>
      <Box sx={{ display: "flex", height: "100%", bgcolor: isDark ? "#0b0f14" : "background.default" }}>

        {/* Mobile drawer */}
        <Drawer anchor="left" open={drawerOpen} onClose={() => setDrawerOpen(false)}
          sx={{ display: { xs: "block", md: "none" }, "& .MuiDrawer-paper": { width: 240, bgcolor: isDark ? "#10151d" : "background.paper" } }}>
          <Sidebar {...sidebarProps} />
        </Drawer>

        {/* Desktop sidebar */}
        <Box sx={{
          width: 220, flexShrink: 0,
          bgcolor: isDark ? "#10151d" : "background.paper",
          borderRight: "1px solid", borderColor: isDark ? "#232b36" : "divider",
          display: { xs: "none", md: "flex" }, flexDirection: "column",
        }}>
          <Sidebar {...{ accounts, me, navigate }} />
        </Box>

        {/* Main content */}
        <Box sx={{ flexGrow: 1, overflow: "auto" }}>

          {/* Mobile top bar */}
          {isMobile && (
            <Box sx={{ position: "sticky", top: 0, zIndex: 100, bgcolor: isDark ? "#10151d" : "background.paper", borderBottom: "1px solid", borderColor: isDark ? "#232b36" : "divider", px: 1.5, py: 1, display: "flex", alignItems: "center", gap: 1 }}>
              <IconButton size="small" onClick={() => setDrawerOpen(true)}><MenuIcon /></IconButton>
              <Typography sx={{ fontWeight: 800, fontSize: 14 }}>Owlet</Typography>
            </Box>
          )}

          <Box sx={{ maxWidth: 860, mx: "auto", px: { xs: 2.5, md: 5 }, py: { xs: 4, md: 8 }, pb: 14 }}>

            {/* ── Hero ── */}
            <Box sx={{ pb: 7, borderBottom: "1px solid", borderColor: isDark ? "#232b36" : "divider", mb: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.25, mb: 2.75 }}>
                <Box sx={{ width: 8, height: 8, borderRadius: "50%", background: RAIL_GRADIENT, boxShadow: "0 0 10px 1px #3b82f688" }} />
                <Typography sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.75rem", letterSpacing: "0.14em", textTransform: "uppercase", color: isDark ? "#5b6675" : "text.disabled" }}>
                  Owlet · Security Operations Platform
                </Typography>
              </Box>

              <Typography sx={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700, fontSize: { xs: 30, md: 44 }, letterSpacing: "-0.02em", lineHeight: 1.08, mb: 2.25 }}>
                Hi {displayName} — one{" "}
                <Box component="span" sx={{ background: RAIL_GRADIENT, WebkitBackgroundClip: "text", backgroundClip: "text", color: "transparent" }}>
                  signal path
                </Box>
                ,<br />from setup to evidence.
              </Typography>

              <Typography sx={{ color: isDark ? "#8b96a5" : "text.secondary", fontSize: "1rem", maxWidth: 600, mb: 3.5 }}>
                Seven stages run in order — each one hands its output to the next. Click any chip to jump straight there.
              </Typography>
            </Box>

            {/* ── Pipeline ── */}
            <Box sx={{ position: "relative", mt: 7 }}>
              {/* Vertical rail */}
              <Box sx={{
                position: "absolute", left: 23, top: 14, bottom: 14, width: 2,
                background: RAIL_GRADIENT, opacity: 0.55,
              }} />

              {STAGES.map((stage, si) => (
                <Box
                  key={stage.id}
                  id={`stage-${stage.id}`}
                  sx={{
                    position: "relative", pl: "64px", mb: si < STAGES.length - 1 ? 8 : 0,
                    scrollMarginTop: 24,
                    opacity: 0, transform: "translateY(14px)",
                    animation: `rise 0.55s ease ${si * 0.07}s forwards`,
                    "@keyframes rise": { to: { opacity: 1, transform: "translateY(0)" } },
                  }}
                >
                  {/* Stage node */}
                  <Box sx={{
                    position: "absolute", left: 0, top: 0,
                    width: 48, height: 48, borderRadius: "50%",
                    bgcolor: isDark ? "#141b25" : "background.paper",
                    border: `2px solid ${stage.color}`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, fontSize: "1.05rem",
                    color: stage.color,
                    boxShadow: `0 0 0 5px ${isDark ? "#0b0f14" : theme.palette.background.default}, 0 0 22px -4px ${stage.color}`,
                    zIndex: 2,
                  }}>
                    {stage.num}
                  </Box>

                  {/* Stage header */}
                  <Box sx={{ pt: "5px", mb: 2.5 }}>
                    <Typography sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.75rem", color: stage.color, letterSpacing: "0.1em", textTransform: "uppercase", mb: 0.75 }}>
                      Stage {stage.num} · {stage.label}
                    </Typography>
                    <Typography sx={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: { xs: 20, md: 26 }, fontWeight: 600, letterSpacing: "-0.01em", mb: 0.75 }}>
                      {stage.title}
                    </Typography>
                    <Typography sx={{ color: isDark ? "#8b96a5" : "text.secondary", fontSize: "0.91rem", maxWidth: 560 }}>
                      {stage.sub}
                    </Typography>
                  </Box>

                  {/* Module cards */}
                  <Box sx={{
                    display: "grid",
                    gridTemplateColumns: stage.modules.length === 1 ? "1fr" : { xs: "1fr", sm: "1fr 1fr" },
                    gap: 1.5,
                  }}>
                    {stage.modules.map((mod) => (
                      <ModuleCard key={mod.tag} mod={mod} stageColor={stage.color} />
                    ))}
                  </Box>
                </Box>
              ))}
            </Box>

            {/* ── Footer ── */}
            <Box sx={{ mt: 10, pt: 3.5, borderTop: "1px solid", borderColor: isDark ? "#232b36" : "divider", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 1.5 }}>
              <Typography sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.72rem", color: isDark ? "#5b6675" : "text.disabled", letterSpacing: "0.02em" }}>
                SETUP → DESIGN → DISCOVER → ANALYSE → RESPOND → REPORT → AUTOMATE
              </Typography>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                <Box
                  onClick={() => navigate("/data-model")}
                  sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.69rem", color: "#6366f1", border: "1px solid", borderColor: "#6366f155", px: 1.5, py: 0.75, borderRadius: "20px", cursor: "pointer", "&:hover": { bgcolor: "#6366f110" } }}
                >
                  Data Ontology →
                </Box>
                <Box sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.69rem", color: isDark ? "#8b96a5" : "text.secondary", border: "1px solid", borderColor: isDark ? "#232b36" : "divider", px: 1.5, py: 0.75, borderRadius: "20px" }}>
                  Owlet · NexGenAI
                </Box>
              </Box>
            </Box>
          </Box>
        </Box>
      </Box>
      <AssistantWidget />
    </>
  );
}
