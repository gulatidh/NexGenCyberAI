import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Chip, Dialog, DialogContent,
  List, ListItemButton, ListItemIcon, ListItemText, alpha,
} from "@mui/material";
import {
  Search, Dashboard, Security, BugReport, Insights, Hub, Cable,
  Radar, GppGood, GppBad, SmartToy, Policy, Storage, AutoStories,
  Psychology, Description, Assessment, PlaylistAddCheck, TrendingUp,
  Engineering, GridView, People, LibraryAdd, AccountTree, Schedule,
  Settings, Add, PlayArrow, SearchOff, AutoFixHigh, CompareArrows,
  VpnKey, Webhook, MenuBook, BarChart, SyncAlt, Apps, History,
} from "@mui/icons-material";
import { useTheme } from "@mui/material/styles";

// ── All searchable items (mirrors NAV_GROUPS + quick actions) ─────────────────

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
  // Overview
  { id: "dashboard",      label: "Dashboard",           Icon: Dashboard,        path: "/dashboard",                  section: "Overview",     keywords: ["home", "overview", "summary", "posture"] },
  { id: "reports",        label: "Reports",             Icon: BarChart,         path: "/reports",                    section: "Overview",     keywords: ["report", "export", "pdf"] },
  // Setup
  { id: "clients",        label: "Clients",             Icon: People,           path: "/clients",                    section: "1 · Setup",    keywords: ["customer", "tenant", "org", "workspace"] },
  { id: "connections",    label: "Connections",         Icon: Cable,            path: "/connections",                section: "1 · Setup",    keywords: ["connector", "integration", "azure", "aws", "api", "ai settings", "provider"] },
  { id: "ticket-sync",    label: "Ticket Sync",         Icon: SyncAlt,          path: "/ticket-sync",                section: "1 · Setup",    keywords: ["jira", "servicenow", "ticket", "sync"] },
  { id: "assets",         label: "Assets",              Icon: Storage,          path: "/assets",                     section: "1 · Setup",    keywords: ["inventory", "resource", "server", "cloud", "host", "infra"] },
  { id: "technologies",   label: "Technologies",        Icon: Apps,             path: "/assets/technologies",        section: "1 · Setup",    keywords: ["tech", "stack", "language", "framework"] },
  { id: "stale-assets",   label: "Stale Assets",        Icon: History,          path: "/stale-assets",               section: "1 · Setup",    keywords: ["stale", "unused", "old", "expired"] },
  { id: "frameworks",     label: "Frameworks",          Icon: Policy,           path: "/frameworks",                 section: "2 · Design",   keywords: ["nist", "cis", "iso", "pci", "gdpr", "compliance", "control", "standard"] },
  { id: "custom-fw",      label: "Custom Policy",       Icon: LibraryAdd,       path: "/custom-frameworks",          section: "2 · Design",   keywords: ["custom framework", "policy", "standard", "build"] },
  // Discover
  { id: "scans",          label: "Scans",               Icon: BugReport,        path: "/scans",                      section: "3 · Discover", keywords: ["scan", "assessment", "nmap", "zap", "trivy", "semgrep", "burp", "tenable", "qualys"] },
  { id: "findings",       label: "Findings",            Icon: Security,         path: "/findings",                   section: "3 · Discover", keywords: ["vulnerability", "issue", "alert", "cve", "open", "critical", "high"] },
  { id: "vapt",           label: "VAPT Reports",        Icon: GppGood,          path: "/vapt/reports",               section: "6 · Report",   keywords: ["penetration test", "pen test", "report", "vapt", "engagement", "pdf", "docx"] },
  // Analyse
  { id: "risk-overview",  label: "Risk Overview",       Icon: Insights,         path: "/risk-overview",              section: "4 · Analyse",  keywords: ["risk", "score", "posture", "ale", "fair", "exposure"] },
  { id: "threat-models",  label: "Threat Models",       Icon: Hub,              path: "/threat-models",              section: "2 · Design",   keywords: ["dfd", "stride", "data flow", "diagram", "model", "design"] },
  { id: "threat-intel",   label: "Threat Intelligence", Icon: Radar,            path: "/threat-register",            section: "5 · Respond",  keywords: ["threat", "intel", "ioc", "mitre", "att&ck", "ttp"] },
  { id: "risks",          label: "Risk Register",       Icon: Assessment,       path: "/risks",                      section: "4 · Analyse",  keywords: ["risk register", "fair", "likelihood", "impact", "score"] },
  { id: "attack-paths",   label: "Attack Paths",        Icon: AccountTree,      path: "/attack-paths",               section: "4 · Analyse",  keywords: ["attack chain", "lateral movement", "kill chain", "mitre", "path", "graph"] },
  { id: "cve-pivot",      label: "CVE Blast Radius",    Icon: BugReport,        path: "/cve-pivot",                  section: "4 · Analyse",  keywords: ["cve", "blast radius", "affected", "impact", "vulnerability"] },
  { id: "heatmap",        label: "Compliance Heatmap",  Icon: GridView,         path: "/compliance-heatmap",         section: "4 · Analyse",  keywords: ["heatmap", "compliance", "control", "matrix", "gap"] },
  // Respond
  { id: "gaps",           label: "Control Gaps",        Icon: GppBad,           path: "/control-deficiencies",       section: "5 · Respond",  keywords: ["gap", "deficiency", "control", "missing", "compliance gap"] },
  { id: "remediation",    label: "Remediation",         Icon: PlaylistAddCheck, path: "/governance/remediation",     section: "5 · Respond",  keywords: ["fix", "remediate", "action", "patch", "tracker"] },
  { id: "ai-remediations",label: "AI Remediations",     Icon: AutoFixHigh,      path: "/governance/remediation-jobs",section: "5 · Respond",  keywords: ["ai fix", "auto remediate", "job", "automated"] },
  { id: "ctem",           label: "CTEM Programs",       Icon: Engineering,      path: "/governance/ctem",            section: "5 · Respond",  keywords: ["ctem", "exposure management", "scope", "validate", "mobilise"] },
  // Report
  { id: "posture",        label: "Posture Trends",      Icon: TrendingUp,       path: "/posture-trends",             section: "6 · Report",   keywords: ["posture", "trend", "history", "chart", "audit readiness"] },
  { id: "comparison",     label: "Client Comparison",   Icon: CompareArrows,    path: "/client-comparison",          section: "6 · Report",   keywords: ["compare", "benchmark", "client", "multi"] },
  // Automate
  { id: "agents",         label: "AI Buddies",          Icon: SmartToy,         path: "/agents",                     section: "7 · Automate", keywords: ["agent", "buddy", "buddies", "ai", "orchestrator", "llm", "automation", "run agent"] },
  { id: "workflows",      label: "Workflows",           Icon: Schedule,         path: "/missions",                   section: "7 · Automate", keywords: ["mission", "workflow", "pipeline", "scheduled", "automated"] },
  { id: "ai-scan",        label: "AI Assisted Scan",    Icon: SmartToy,         path: "/ai-assisted-scan",           section: "7 · Automate", keywords: ["ai scan", "guided", "wizard", "chat scan", "conversational"] },
  { id: "knowledge",      label: "Knowledge Base",      Icon: AutoStories,      path: "/knowledge",                  section: "7 · Automate", keywords: ["kb", "knowledge", "articles", "wiki"] },
  { id: "sec-docs",       label: "Security Docs",       Icon: Description,      path: "/security-docs",              section: "7 · Automate", keywords: ["document", "upload", "policy", "rag", "ask docs"] },
  { id: "nlquery",        label: "Ask Your Data",       Icon: Psychology,       path: "/nl-query",                   section: "7 · Automate", keywords: ["nl query", "natural language", "sql", "ask", "question"] },
  // Configure
  { id: "settings",       label: "Settings",            Icon: Settings,         path: "/settings",                   section: "8 · Configure",keywords: ["config", "settings", "api keys", "webhooks", "auth", "admin"] },
  { id: "webhooks",       label: "Webhooks",            Icon: Webhook,          path: "/webhooks",                   section: "8 · Configure",keywords: ["webhook", "slack", "teams", "notification", "event"] },
  { id: "api-keys",       label: "API Keys",            Icon: VpnKey,           path: "/api-keys",                   section: "8 · Configure",keywords: ["api key", "token", "m2m", "ci/cd", "integration"] },
  { id: "help",           label: "Help",                Icon: MenuBook,         path: "/help",                       section: "8 · Configure",keywords: ["help", "docs", "guide", "how to", "faq"] },
];

const QUICK_ACTIONS: SearchItem[] = [
  { id: "a-scan",   label: "New Scan",        Icon: Add,        path: "/scans",          type: "action", color: "#42A5F5", keywords: ["launch scan", "start scan", "new scan"] },
  { id: "a-agent",  label: "Run AI Buddy",    Icon: PlayArrow,  path: "/agents",         type: "action", color: "#5C6BC0", keywords: ["run agent", "launch agent", "ai buddy"] },
  { id: "a-vapt",   label: "New VAPT Report", Icon: GppGood,    path: "/vapt/reports",   type: "action", color: "#66BB6A", keywords: ["create report", "new report", "vapt"] },
  { id: "a-nlq",    label: "Ask Your Data",   Icon: Psychology, path: "/nl-query",       type: "action", color: "#FFA726", keywords: ["ask", "query", "nl"] },
];

// ── Scoring ───────────────────────────────────────────────────────────────────

function score(item: SearchItem, words: string[]): number {
  const label = item.label.toLowerCase();
  const kws   = (item.keywords ?? []).join(" ").toLowerCase();
  const sec   = (item.section ?? "").toLowerCase();
  let s = 0;
  for (const w of words) {
    if (label === w)              s += 100;
    else if (label.startsWith(w)) s += 80;
    else if (label.includes(w))   s += 60;
    else if (kws.includes(w))     s += 40;
    else if (sec.includes(w))     s += 10;
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
          ? <Box key={i} component="mark" sx={{ bgcolor: "rgba(66,133,244,0.25)", color: "inherit", borderRadius: "2px", px: "1px" }}>{p}</Box>
          : p
      )}
    </>
  );
}

// ── Command Palette dialog ────────────────────────────────────────────────────

function CommandPalette({ open, onClose, initialQuery }: { open: boolean; onClose: () => void; initialQuery: string }) {
  const theme    = useTheme();
  const navigate = useNavigate();
  const [query, setQuery]         = useState(initialQuery);
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const isDark = theme.palette.mode === "dark";

  useEffect(() => {
    if (open) { setQuery(initialQuery); setActiveIdx(0); setTimeout(() => inputRef.current?.focus(), 50); }
  }, [open, initialQuery]);

  const allItems = useMemo(() => [...NAV_ITEMS, ...QUICK_ACTIONS], []);

  const { grouped, flat } = useMemo(() => {
    const q = query.trim().toLowerCase();
    const words = q.split(/\s+/).filter(Boolean);

    if (!q) {
      const sectionMap = new Map<string, SearchItem[]>();
      NAV_ITEMS.forEach((n) => {
        const s = n.section ?? "Other";
        if (!sectionMap.has(s)) sectionMap.set(s, []);
        sectionMap.get(s)!.push(n);
      });
      const grouped = [
        { header: "QUICK ACTIONS", items: QUICK_ACTIONS },
        ...Array.from(sectionMap.entries()).map(([h, items]) => ({ header: h.toUpperCase(), items })),
      ];
      return { grouped, flat: [...QUICK_ACTIONS, ...NAV_ITEMS] };
    }

    const scored = allItems
      .map((item) => ({ item, s: score(item, words) }))
      .filter(({ s }) => s > 0)
      .sort((a, b) => b.s - a.s);

    if (!scored.length) return { grouped: [], flat: [] };

    const sectionMap = new Map<string, SearchItem[]>();
    scored.forEach(({ item }) => {
      const key = item.type === "action" ? "QUICK ACTIONS" : (item.section ?? "OTHER").toUpperCase();
      if (!sectionMap.has(key)) sectionMap.set(key, []);
      sectionMap.get(key)!.push(item);
    });
    return {
      grouped: Array.from(sectionMap.entries()).map(([header, items]) => ({ header, items })),
      flat: scored.map(({ item }) => item),
    };
  }, [query, allItems]);

  const go = useCallback((item: SearchItem) => { onClose(); navigate(item.path); }, [onClose, navigate]);

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActiveIdx((i) => Math.min(i + 1, flat.length - 1)); }
    if (e.key === "ArrowUp")   { e.preventDefault(); setActiveIdx((i) => Math.max(i - 1, 0)); }
    if (e.key === "Enter" && flat[activeIdx]) go(flat[activeIdx]);
    if (e.key === "Escape") onClose();
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="sm"
      fullWidth
      slotProps={{
        paper: { sx: { borderRadius: 2, overflow: "hidden", boxShadow: "0 24px 64px rgba(0,0,0,0.55)", mt: "6vh", verticalAlign: "top", border: `1px solid ${alpha(theme.palette.divider, 0.5)}`, maxHeight: "75vh" } },
        backdrop: { sx: { backdropFilter: "blur(6px)", bgcolor: alpha("#000", 0.5) } },
      }}
    >
      <DialogContent sx={{ p: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {/* Input */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, px: 2, py: 1.25, borderBottom: `1px solid ${theme.palette.divider}` }}>
          <Search sx={{ color: "text.disabled", fontSize: 20, flexShrink: 0 }} />
          <Box
            component="input"
            ref={inputRef}
            value={query}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => { setQuery(e.target.value); setActiveIdx(0); }}
            onKeyDown={handleKey}
            placeholder="Search pages, features, actions…"
            sx={{ flex: 1, border: "none", outline: "none", background: "transparent", color: "text.primary", fontSize: "1rem", fontFamily: "inherit", "&::placeholder": { color: isDark ? "rgba(255,255,255,0.3)" : "rgba(0,0,0,0.35)" } }}
          />
          {query && (
            <Box onClick={() => { setQuery(""); setActiveIdx(0); inputRef.current?.focus(); }} sx={{ cursor: "pointer", fontSize: "0.72rem", color: "text.disabled", px: 0.75, py: 0.15, borderRadius: 0.5, bgcolor: alpha(theme.palette.divider, 0.6), "&:hover": { color: "text.primary" } }}>
              clear
            </Box>
          )}
          <Box sx={{ px: 0.75, py: 0.15, borderRadius: 0.5, bgcolor: alpha(theme.palette.divider, 0.6), fontFamily: "monospace", fontSize: "0.65rem", color: "text.disabled", flexShrink: 0 }}>esc</Box>
        </Box>

        {/* Results */}
        <Box sx={{ flex: 1, overflowY: "auto", "&::-webkit-scrollbar": { width: 4 }, "&::-webkit-scrollbar-thumb": { bgcolor: alpha(theme.palette.divider, 0.8), borderRadius: 2 } }}>
          {flat.length === 0 && query.trim() ? (
            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 5, gap: 1 }}>
              <SearchOff sx={{ fontSize: 36, color: "text.disabled" }} />
              <Typography variant="body2" color="text.disabled">No results for "{query}"</Typography>
              <Typography variant="caption" color="text.disabled">Try "scan", "agent", "risk", "compliance", "buddy"…</Typography>
            </Box>
          ) : (
            grouped.map((group) => (
              <Box key={group.header}>
                <Typography variant="caption" sx={{ display: "block", px: 2, py: 0.6, color: "text.disabled", fontWeight: 700, letterSpacing: "0.08em", fontSize: "0.65rem", bgcolor: alpha(theme.palette.background.default, 0.6), position: "sticky", top: 0, zIndex: 1 }}>
                  {group.header}
                </Typography>
                <List dense disablePadding>
                  {group.items.map((item) => {
                    const gIdx = flat.indexOf(item);
                    const active = gIdx === activeIdx;
                    const { Icon } = item;
                    return (
                      <ListItemButton
                        key={item.id}
                        selected={active}
                        onClick={() => go(item)}
                        onMouseEnter={() => setActiveIdx(gIdx)}
                        sx={{ px: 2, py: 0.85, borderLeft: active ? `3px solid ${theme.palette.primary.main}` : "3px solid transparent", "&.Mui-selected": { bgcolor: alpha(theme.palette.primary.main, 0.08) } }}
                      >
                        <ListItemIcon sx={{ minWidth: 36 }}>
                          <Icon sx={{ fontSize: 18, color: item.color ?? (active ? "primary.main" : "text.disabled") }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={<Typography variant="body2" sx={{ color: active ? "text.primary" : "text.secondary", fontSize: "0.86rem" }}><Highlight text={item.label} query={query} /></Typography>}
                          secondary={item.section && <Typography variant="caption" sx={{ color: "text.disabled", fontSize: "0.7rem" }}>{item.section}</Typography>}
                          sx={{ m: 0 }}
                        />
                        {item.type === "action" && <Chip label="action" size="small" sx={{ height: 18, fontSize: "0.62rem", ml: 1, opacity: 0.7 }} />}
                        {active && <Typography variant="caption" color="text.disabled" sx={{ ml: 1, flexShrink: 0 }}>↵</Typography>}
                      </ListItemButton>
                    );
                  })}
                </List>
              </Box>
            ))
          )}
        </Box>

        {/* Footer */}
        <Box sx={{ px: 2, py: 0.75, borderTop: `1px solid ${theme.palette.divider}`, display: "flex", gap: 2, alignItems: "center", flexShrink: 0 }}>
          {([["↑↓", "navigate"], ["↵", "open"], ["esc", "close"]] as const).map(([k, a]) => (
            <Box key={k} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              <Box sx={{ px: 0.75, py: 0.1, borderRadius: 0.5, bgcolor: alpha(theme.palette.divider, 0.6), fontFamily: "monospace", fontSize: "0.65rem" }}>{k}</Box>
              <Typography variant="caption" color="text.disabled">{a}</Typography>
            </Box>
          ))}
          <Typography variant="caption" color="text.disabled" sx={{ ml: "auto" }}>{flat.length} result{flat.length !== 1 ? "s" : ""}</Typography>
        </Box>
      </DialogContent>
    </Dialog>
  );
}

// ── Search bar trigger (drop into any toolbar) ────────────────────────────────

export default function GlobalSearch() {
  const theme = useTheme();
  const [open, setOpen]       = useState(false);
  const [query, setQuery]     = useState("");
  const isDark = theme.palette.mode === "dark";

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") { e.preventDefault(); setOpen((v) => !v); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  const close = useCallback(() => { setOpen(false); setQuery(""); }, []);

  return (
    <>
      {/* Search bar — click or type to open palette */}
      <Box
        sx={{
          display: "flex", alignItems: "center", gap: 1,
          flex: 1, maxWidth: 520, mx: 2,
          bgcolor: isDark ? alpha("#fff", 0.06) : alpha("#000", 0.05),
          border: "1px solid", borderColor: "divider",
          borderRadius: 1.5, px: 1.5, py: 0.55,
          cursor: "text",
          transition: "all 0.15s",
          "&:hover": { borderColor: "primary.main", bgcolor: isDark ? alpha("#fff", 0.09) : alpha("#4285F4", 0.05) },
        }}
        onClick={() => setOpen(true)}
      >
        <Search sx={{ fontSize: 16, color: "text.disabled", flexShrink: 0 }} />
        <Typography variant="body2" sx={{ flex: 1, color: "text.disabled", fontSize: "0.85rem", userSelect: "none" }}>
          Search pages, features, actions…
        </Typography>
        <Box sx={{ px: 0.75, py: 0.1, borderRadius: 0.5, bgcolor: isDark ? alpha("#fff", 0.1) : alpha("#000", 0.07), fontFamily: "monospace", fontSize: "0.65rem", color: "text.disabled", whiteSpace: "nowrap", flexShrink: 0 }}>
          ⌘K
        </Box>
      </Box>

      <CommandPalette open={open} onClose={close} initialQuery={query} />
    </>
  );
}
