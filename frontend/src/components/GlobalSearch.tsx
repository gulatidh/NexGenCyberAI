import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, List, ListItemButton, ListItemIcon,
  ListItemText, Paper, Chip, alpha, InputBase,
} from "@mui/material";
import {
  Search, Dashboard, Security, BugReport, Insights, Hub, Cable,
  Radar, GppGood, GppBad, SmartToy, Policy, Storage, AutoStories,
  Psychology, Description, Assessment, PlaylistAddCheck, TrendingUp,
  Engineering, GridView, People, LibraryAdd, AccountTree, Schedule,
  Settings, Add, PlayArrow, SearchOff, CompareArrows,
  VpnKey, Webhook, MenuBook, BarChart, Apps, History,
} from "@mui/icons-material";
import { useTheme } from "@mui/material/styles";

interface SearchItem {
  id: string;
  label: string;
  Icon: React.ElementType;
  path: string;
  section?: string;
  keywords?: string[];
  type?: "nav" | "action";
  color?: string;
}

const NAV_ITEMS: SearchItem[] = [
  { id: "dashboard",     label: "Dashboard",           Icon: Dashboard,        path: "/dashboard",              section: "Overview",      keywords: ["home", "overview", "summary", "posture"] },
  { id: "reports",       label: "Reports",             Icon: BarChart,         path: "/reports",                section: "Overview",      keywords: ["report", "export", "pdf"] },
  { id: "clients",       label: "Accounts",            Icon: People,           path: "/clients",                section: "Setup",         keywords: ["customer", "tenant", "org", "workspace", "clients"] },
  { id: "connections",   label: "Integrations",        Icon: Cable,            path: "/platform/integrations",  section: "Setup",         keywords: ["connector", "integration", "azure", "aws", "api", "ai settings", "provider", "webhook", "api key"] },
  { id: "assets",        label: "Asset Inventory",     Icon: Storage,          path: "/discover/assets",        section: "Discover",      keywords: ["inventory", "resource", "server", "cloud", "host", "infra"] },
  { id: "technologies",  label: "Technologies",        Icon: Apps,             path: "/discover/technologies",  section: "Discover",      keywords: ["tech", "stack", "language", "framework"] },
  { id: "frameworks",    label: "Frameworks",          Icon: Policy,           path: "/report/frameworks",      section: "Report",        keywords: ["nist", "cis", "iso", "pci", "gdpr", "compliance", "control", "standard"] },
  { id: "custom-fw",     label: "Custom Standards",    Icon: LibraryAdd,       path: "/report/custom-frameworks",section: "Report",       keywords: ["custom framework", "policy", "standard", "build"] },
  { id: "threat-models", label: "Threat Models",       Icon: Hub,              path: "/analyse/threat-models",  section: "Analyse",       keywords: ["dfd", "stride", "data flow", "diagram", "model", "design"] },
  { id: "scans",         label: "Assessments",         Icon: BugReport,        path: "/discover/scans",         section: "Discover",      keywords: ["scan", "assessment", "nmap", "zap", "trivy", "semgrep", "burp", "tenable", "qualys"] },
  { id: "findings",      label: "Findings",            Icon: Security,         path: "/discover/findings",      section: "Discover",      keywords: ["vulnerability", "issue", "alert", "cve", "open", "critical", "high"] },
  { id: "ai-scan",       label: "AI Assisted Scan",    Icon: SmartToy,         path: "/discover/ai-scan",       section: "Discover",      keywords: ["ai scan", "guided", "wizard", "chat scan", "conversational"] },
  { id: "coverage",      label: "Scan Coverage",       Icon: History,          path: "/discover/coverage",      section: "Discover",      keywords: ["coverage", "policy", "stale", "last scanned"] },
  { id: "risk-overview", label: "Risk Overview",       Icon: Insights,         path: "/analyse/risk-overview",  section: "Analyse",       keywords: ["risk", "score", "posture", "ale", "fair", "exposure"] },
  { id: "risks",         label: "Risk Register",       Icon: Assessment,       path: "/analyse/risks",          section: "Analyse",       keywords: ["risk register", "fair", "likelihood", "impact", "score"] },
  { id: "risk-appetite", label: "Risk Appetite",       Icon: Assessment,       path: "/analyse/risk-appetite",  section: "Analyse",       keywords: ["appetite", "tolerance", "threshold"] },
  { id: "attack-paths",  label: "Attack Paths",        Icon: AccountTree,      path: "/analyse/attack-paths",   section: "Analyse",       keywords: ["attack chain", "lateral movement", "kill chain", "mitre", "path", "graph"] },
  { id: "data-model",    label: "Data Ontology",       Icon: AccountTree,      path: "/data-model",             section: "Analyse",       keywords: ["ontology", "data model", "entity", "graph", "schema"] },
  { id: "heatmap",       label: "Compliance Heatmap",  Icon: GridView,         path: "/analyse/compliance-heatmap", section: "Analyse",  keywords: ["heatmap", "compliance", "control", "matrix", "gap"] },
  { id: "incidents",     label: "Incidents",           Icon: BugReport,        path: "/respond/incidents",      section: "Respond",       keywords: ["incident", "case", "response", "ir"] },
  { id: "threat-intel",  label: "Threat Register",     Icon: Radar,            path: "/respond/threats",        section: "Respond",       keywords: ["threat", "intel", "ioc", "mitre", "att&ck", "ttp"] },
  { id: "gaps",          label: "Control Gaps",        Icon: GppBad,           path: "/respond/gaps",           section: "Respond",       keywords: ["gap", "deficiency", "control", "missing", "compliance gap"] },
  { id: "remediation",   label: "Remediation",         Icon: PlaylistAddCheck, path: "/respond/remediation",    section: "Respond",       keywords: ["fix", "remediate", "action", "patch", "tracker"] },
  { id: "ctem",          label: "CTEM Programs",       Icon: Engineering,      path: "/respond/ctem",           section: "Respond",       keywords: ["ctem", "exposure management", "scope", "validate", "mobilise"] },
  { id: "vapt",          label: "VAPT Reports",        Icon: GppGood,          path: "/respond/vapt-reports",   section: "Respond",       keywords: ["penetration test", "pen test", "report", "vapt", "engagement"] },
  { id: "exec-summary",  label: "Executive Summary",   Icon: Description,      path: "/report/executive-summary",section: "Report",       keywords: ["executive", "leadership", "summary", "board"] },
  { id: "posture",       label: "Posture Trends",      Icon: TrendingUp,       path: "/discover/posture",       section: "Discover",      keywords: ["posture", "trend", "history", "chart", "audit readiness"] },
  { id: "evidence",      label: "Evidence Package",    Icon: Description,      path: "/report/evidence",        section: "Report",        keywords: ["evidence", "zip", "audit", "package"] },
  { id: "agents",        label: "AI Buddies",          Icon: SmartToy,         path: "/automate/agents",        section: "Automate",      keywords: ["agent", "buddy", "buddies", "ai", "orchestrator", "llm", "automation"] },
  { id: "workflows",     label: "AI Workflows",        Icon: Schedule,         path: "/automate/workflows",     section: "Automate",      keywords: ["mission", "workflow", "pipeline", "scheduled", "automated"] },
  { id: "sec-docs",      label: "Security Docs",       Icon: Description,      path: "/respond/security-docs",  section: "Respond",       keywords: ["document", "upload", "policy", "rag", "ask docs"] },
  { id: "nlquery",       label: "Ask Your Data",       Icon: Psychology,       path: "/analyse/nl-query",       section: "Analyse",       keywords: ["nl query", "natural language", "sql", "ask", "question"] },
  { id: "knowledge",     label: "Knowledge Base",      Icon: AutoStories,      path: "/automate/knowledge",     section: "Automate",      keywords: ["kb", "knowledge", "articles", "wiki"] },
  { id: "settings",      label: "Settings",            Icon: Settings,         path: "/platform/settings",      section: "Setup",         keywords: ["config", "settings", "admin"] },
  { id: "help",          label: "Help",                Icon: MenuBook,         path: "/platform/help",          section: "Setup",         keywords: ["help", "docs", "guide", "how to", "faq"] },
];

const QUICK_ACTIONS: SearchItem[] = [
  { id: "a-scan",  label: "New Scan",        Icon: Add,       path: "/discover/scans",          type: "action", color: "#42A5F5", keywords: ["launch scan", "start scan", "new scan"] },
  { id: "a-agent", label: "Run AI Buddy",    Icon: PlayArrow, path: "/automate/agents",         type: "action", color: "#5C6BC0", keywords: ["run agent", "launch agent", "ai buddy"] },
  { id: "a-vapt",  label: "New VAPT Report", Icon: GppGood,   path: "/respond/vapt-reports",    type: "action", color: "#66BB6A", keywords: ["create report", "new report", "vapt"] },
  { id: "a-nlq",   label: "Ask Your Data",   Icon: Psychology,path: "/analyse/nl-query",        type: "action", color: "#FFA726", keywords: ["ask", "query", "nl"] },
  { id: "a-int",   label: "Add Connector",   Icon: Cable,     path: "/platform/integrations",   type: "action", color: "#EC407A", keywords: ["connector", "integration", "add", "connect"] },
];

function scoreItem(item: SearchItem, words: string[]): number {
  const label = item.label.toLowerCase();
  const kws   = (item.keywords ?? []).join(" ").toLowerCase();
  const sec   = (item.section ?? "").toLowerCase();
  let s = 0;
  for (const w of words) {
    if (label === w)               s += 100;
    else if (label.startsWith(w))  s += 80;
    else if (label.includes(w))    s += 60;
    else if (kws.includes(w))      s += 40;
    else if (sec.includes(w))      s += 10;
    else return -1;
  }
  return s;
}

function Highlight({ text, query }: { text: string; query: string }) {
  if (!query.trim()) return <>{text}</>;
  const re = new RegExp(
    `(${query.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&").split(/\s+/).join("|")})`,
    "gi"
  );
  return (
    <>
      {text.split(re).map((p, i) =>
        re.test(p)
          ? <Box key={i} component="mark" sx={{ bgcolor: "rgba(66,133,244,0.28)", color: "inherit", borderRadius: "2px", px: "1px" }}>{p}</Box>
          : p
      )}
    </>
  );
}

export default function GlobalSearch() {
  const theme    = useTheme();
  const navigate = useNavigate();
  const isDark   = theme.palette.mode === "dark";

  const [query, setQuery]     = useState("");
  const [open, setOpen]       = useState(false);
  const [activeIdx, setActiveIdx] = useState(0);

  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef     = useRef<HTMLInputElement>(null);

  const allItems = useMemo(() => [...NAV_ITEMS, ...QUICK_ACTIONS], []);

  // Only show results when there's a query
  const { grouped, flat } = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return { grouped: [], flat: [] };

    const words  = q.split(/\s+/).filter(Boolean);
    const scored = allItems
      .map((item) => ({ item, s: scoreItem(item, words) }))
      .filter(({ s }) => s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, 12);

    if (!scored.length) return { grouped: [], flat: [] };

    const sectionMap = new Map<string, SearchItem[]>();
    scored.forEach(({ item }) => {
      const key = item.type === "action" ? "Quick Actions" : (item.section ?? "Other");
      if (!sectionMap.has(key)) sectionMap.set(key, []);
      sectionMap.get(key)!.push(item);
    });

    return {
      grouped: Array.from(sectionMap.entries()).map(([header, items]) => ({ header, items })),
      flat: scored.map(({ item }) => item),
    };
  }, [query, allItems]);

  // Open dropdown only when query has text
  useEffect(() => {
    setOpen(query.trim().length > 0);
    setActiveIdx(0);
  }, [query]);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
        setQuery("");
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  // ⌘K / Ctrl+K to focus
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  const go = useCallback((item: SearchItem) => {
    setOpen(false);
    setQuery("");
    navigate(item.path);
  }, [navigate]);

  const handleKey = (e: React.KeyboardEvent) => {
    if (!open) return;
    if (e.key === "ArrowDown") { e.preventDefault(); setActiveIdx((i) => Math.min(i + 1, flat.length - 1)); }
    if (e.key === "ArrowUp")   { e.preventDefault(); setActiveIdx((i) => Math.max(i - 1, 0)); }
    if (e.key === "Enter" && flat[activeIdx]) { e.preventDefault(); go(flat[activeIdx]); }
    if (e.key === "Escape")    { setOpen(false); setQuery(""); inputRef.current?.blur(); }
  };

  const hasResults = flat.length > 0;
  const noResults  = query.trim().length > 0 && flat.length === 0;

  return (
    <Box ref={containerRef} sx={{ position: "relative" }}>
      {/* Search input */}
      <Box
        sx={{
          display: "flex", alignItems: "center", gap: 0.75,
          px: 1.25, py: 0.55,
          borderRadius: 2,
          border: `1px solid ${open ? alpha(theme.palette.primary.main, 0.5) : alpha(theme.palette.divider, 0.6)}`,
          bgcolor: isDark ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.03)",
          transition: "border-color 0.15s, box-shadow 0.15s",
          boxShadow: open ? `0 0 0 3px ${alpha(theme.palette.primary.main, 0.1)}` : "none",
          width: { xs: 160, sm: 220, md: 280 },
        }}
      >
        <Search sx={{ fontSize: 16, color: open ? "primary.main" : "text.disabled", flexShrink: 0, transition: "color 0.15s" }} />
        <InputBase
          inputRef={inputRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Search…"
          inputProps={{ "aria-label": "search" }}
          sx={{
            flex: 1,
            fontSize: "0.85rem",
            color: "text.primary",
            "& input": { p: 0, "&::placeholder": { color: "text.disabled", opacity: 1 } },
          }}
        />
        {!query && (
          <Box sx={{
            px: 0.6, py: 0.1, borderRadius: 0.75,
            bgcolor: alpha(theme.palette.divider, 0.5),
            fontFamily: "monospace", fontSize: "0.6rem",
            color: "text.disabled", flexShrink: 0,
            display: { xs: "none", md: "block" },
          }}>
            ⌘K
          </Box>
        )}
        {query && (
          <Box
            onClick={() => { setQuery(""); inputRef.current?.focus(); }}
            sx={{
              fontSize: "0.65rem", color: "text.disabled", cursor: "pointer",
              px: 0.6, py: 0.1, borderRadius: 0.75,
              bgcolor: alpha(theme.palette.divider, 0.5),
              flexShrink: 0,
              "&:hover": { color: "text.secondary" },
            }}
          >
            ✕
          </Box>
        )}
      </Box>

      {/* Dropdown results */}
      {(hasResults || noResults) && open && (
        <Paper
          elevation={8}
          sx={{
            position: "absolute",
            top: "calc(100% + 6px)",
            left: 0,
            right: 0,
            minWidth: 340,
            maxHeight: 420,
            overflowY: "auto",
            zIndex: 1500,
            borderRadius: 2,
            border: `1px solid ${alpha(theme.palette.divider, 0.3)}`,
            bgcolor: "background.paper",
            "&::-webkit-scrollbar": { width: 4 },
            "&::-webkit-scrollbar-thumb": { bgcolor: alpha(theme.palette.divider, 0.8), borderRadius: 2 },
          }}
        >
          {noResults ? (
            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 4, gap: 0.75 }}>
              <SearchOff sx={{ fontSize: 28, color: "text.disabled" }} />
              <Typography variant="body2" color="text.disabled" sx={{ fontWeight: 500, fontSize: "0.82rem" }}>
                No results for "{query}"
              </Typography>
              <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.72rem" }}>
                Try: findings · risks · scan · agent · compliance
              </Typography>
            </Box>
          ) : (
            <Box sx={{ py: 0.75 }}>
              {grouped.map((group, gi) => (
                <Box key={group.header}>
                  {grouped.length > 1 && (
                    <Typography
                      variant="caption"
                      sx={{
                        display: "block",
                        px: 2, pt: gi === 0 ? 1 : 0.5, pb: 0.25,
                        color: "text.disabled",
                        fontWeight: 700,
                        letterSpacing: "0.08em",
                        fontSize: "0.62rem",
                        textTransform: "uppercase",
                      }}
                    >
                      {group.header}
                    </Typography>
                  )}
                  <List dense disablePadding>
                    {group.items.map((item) => {
                      const gIdx  = flat.indexOf(item);
                      const active = gIdx === activeIdx;
                      const { Icon } = item;
                      return (
                        <ListItemButton
                          key={item.id}
                          selected={active}
                          onClick={() => go(item)}
                          onMouseEnter={() => setActiveIdx(gIdx)}
                          sx={{
                            px: 1.5, py: 0.7, mx: 0.75, borderRadius: 1.5, mb: 0.1,
                            bgcolor: active ? alpha(theme.palette.primary.main, 0.1) : "transparent",
                            "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.07) },
                            "&.Mui-selected": { bgcolor: alpha(theme.palette.primary.main, 0.1) },
                          }}
                        >
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
                              <Icon sx={{ fontSize: 16, color: item.color ?? (active ? "primary.main" : "text.secondary") }} />
                            </Box>
                          </ListItemIcon>
                          <ListItemText
                            primary={
                              <Typography variant="body2" sx={{ fontSize: "0.86rem", fontWeight: active ? 600 : 400, color: active ? "text.primary" : "text.secondary" }}>
                                <Highlight text={item.label} query={query} />
                              </Typography>
                            }
                            secondary={
                              item.section
                                ? <Typography variant="caption" sx={{ color: "text.disabled", fontSize: "0.68rem" }}>{item.section}</Typography>
                                : null
                            }
                            sx={{ m: 0 }}
                          />
                          {item.type === "action" && (
                            <Chip label="action" size="small" sx={{ height: 16, fontSize: "0.58rem", ml: 1, bgcolor: alpha(item.color ?? theme.palette.primary.main, 0.12), color: item.color ?? "primary.main" }} />
                          )}
                          {active && (
                            <Typography variant="caption" color="text.disabled" sx={{ ml: 0.5, fontFamily: "monospace", fontSize: "0.72rem" }}>↵</Typography>
                          )}
                        </ListItemButton>
                      );
                    })}
                  </List>
                </Box>
              ))}
            </Box>
          )}
        </Paper>
      )}
    </Box>
  );
}
