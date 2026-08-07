/**
 * SampleAzure — Azure-Portal-style full-page layout sample
 * Route: /sample3
 * Renders its own top bar + left blade — NOT inside AppLayout.
 */
import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, IconButton, Chip, Avatar,
  Tooltip, alpha, Badge, Dialog, DialogContent,
  List, ListItemButton, ListItemIcon, ListItemText,
  Divider,
} from "@mui/material";
import {
  Menu as MenuIcon, Search, Notifications, Settings,
  Dashboard, Security, BugReport, Insights, Hub, Cable,
  Radar, GppGood, SmartToy, Policy, Storage,
  AutoStories, Psychology, Description, Assessment, GppBad,
  PlaylistAddCheck, TrendingUp, Engineering, GridView,
  Add, PlayArrow, People, LibraryAdd, AccountTree, Schedule,
  ChevronRight, SearchOff,
} from "@mui/icons-material";
import { useTheme } from "@mui/material/styles";

// ── Constants ────────────────────────────────────────────────────────────────

const BLADE_COLLAPSED = 52;
const BLADE_EXPANDED  = 236;
const TOPBAR_HEIGHT   = 52;

// ── Search item type ─────────────────────────────────────────────────────────

interface SearchItem {
  id: string;
  label: string;
  Icon: React.ElementType;
  path: string;
  section?: string;
  keywords?: string[];
  pinned?: boolean;
  type?: "nav" | "action";
  color?: string;
}

// ── Nav items — every item has keywords for alias search ─────────────────────

const NAV_ITEMS: SearchItem[] = [
  { id: "dashboard",    label: "Dashboard",           Icon: Dashboard,        path: "/dashboard",             pinned: true,  keywords: ["home", "overview", "summary", "main"] },
  { id: "findings",     label: "Findings",            Icon: Security,         path: "/findings",              pinned: true,  keywords: ["vulnerabilities", "issues", "alerts", "bugs", "cve", "open"] },
  { id: "scans",        label: "Scans",               Icon: BugReport,        path: "/scans",                 pinned: true,  keywords: ["assessment", "scan", "test", "nmap", "zap", "trivy", "semgrep"] },
  { id: "risk",         label: "Risk Overview",       Icon: Insights,         path: "/risk-overview",         pinned: true,  keywords: ["risk", "score", "ale", "fair", "exposure", "posture"] },
  { id: "connections",  label: "Connections",         Icon: Cable,            path: "/connections",           section: "1 · Setup",    keywords: ["connectors", "integrations", "azure", "aws", "setup", "configure", "api key", "ai settings", "providers"] },
  { id: "clients",      label: "Clients",             Icon: People,           path: "/clients",               section: "1 · Setup",    keywords: ["customers", "tenants", "organisations", "workspace"] },
  { id: "threat-models",label: "Threat Models",       Icon: Hub,              path: "/threat-models",         section: "2 · Design",   keywords: ["dfd", "stride", "data flow", "diagram", "model", "attack surface", "design"] },
  { id: "frameworks",   label: "Frameworks",          Icon: Policy,           path: "/frameworks",            section: "2 · Design",   keywords: ["nist", "cis", "gdpr", "iso", "pci", "compliance", "controls", "standards"] },
  { id: "custom-fw",    label: "Custom Policy",       Icon: LibraryAdd,       path: "/custom-frameworks",     section: "2 · Design",   keywords: ["custom framework", "policy", "standard", "controls", "build"] },
  { id: "ai-scan",      label: "AI Assisted Scan",    Icon: SmartToy,         path: "/ai-assisted-scan",      section: "3 · Discover", keywords: ["ai scan", "guided", "wizard", "conversational", "chat scan"] },
  { id: "assets",       label: "Assets",              Icon: Storage,          path: "/assets",                section: "3 · Discover", keywords: ["inventory", "resources", "servers", "cloud", "hosts", "infra"] },
  { id: "risks",        label: "Risk Register",       Icon: Assessment,       path: "/risks",                 section: "4 · Analyse",  keywords: ["risk register", "risks", "fair", "score", "likelihood", "impact"] },
  { id: "attack",       label: "Attack Paths",        Icon: AccountTree,      path: "/attack-paths",          section: "4 · Analyse",  keywords: ["attack chain", "lateral movement", "kill chain", "mitre", "path", "graph"] },
  { id: "heatmap",      label: "Compliance Heatmap",  Icon: GridView,         path: "/compliance-heatmap",    section: "4 · Analyse",  keywords: ["heatmap", "compliance", "control", "matrix", "gap"] },
  { id: "threat-intel", label: "Threat Intelligence", Icon: Radar,            path: "/threat-register",       section: "5 · Respond",  keywords: ["threat", "intel", "ioc", "mitre", "att&ck", "ttp", "threat register"] },
  { id: "gaps",         label: "Control Gaps",        Icon: GppBad,           path: "/control-deficiencies",  section: "5 · Respond",  keywords: ["gaps", "deficiencies", "control", "compliance gaps", "missing"] },
  { id: "remediation",  label: "Remediation",         Icon: PlaylistAddCheck, path: "/governance/remediation",section: "5 · Respond",  keywords: ["fix", "remediate", "action", "ticket", "patch", "tracker"] },
  { id: "ctem",         label: "CTEM Programs",       Icon: Engineering,      path: "/governance/ctem",       section: "5 · Respond",  keywords: ["ctem", "exposure management", "scope", "validate", "mobilise"] },
  { id: "vapt",         label: "VAPT Reports",        Icon: GppGood,          path: "/vapt/reports",          section: "6 · Report",   keywords: ["penetration test", "pen test", "report", "vapt", "engagement", "pdf"] },
  { id: "posture",      label: "Posture Trends",      Icon: TrendingUp,       path: "/posture-trends",        section: "6 · Report",   keywords: ["posture", "trend", "history", "graph", "chart", "audit readiness"] },
  { id: "agents",       label: "AI Buddies",          Icon: SmartToy,         path: "/agents",                section: "7 · Automate", keywords: ["agent", "buddy", "buddies", "ai", "orchestrator", "llm", "run agent", "automation", "ai agent"] },
  { id: "workflows",    label: "Workflows",           Icon: Schedule,         path: "/missions",              section: "7 · Automate", keywords: ["mission", "workflow", "pipeline", "scheduled", "automated"] },
  { id: "knowledge",    label: "Knowledge Base",      Icon: AutoStories,      path: "/knowledge",             section: "7 · Automate", keywords: ["kb", "knowledge", "articles", "docs", "wiki", "info"] },
  { id: "sec-docs",     label: "Security Docs",       Icon: Description,      path: "/security-docs",         section: "7 · Automate", keywords: ["document", "upload", "policy", "rag", "question", "ask docs"] },
  { id: "nlquery",      label: "Ask Your Data",       Icon: Psychology,       path: "/nl-query",              section: "7 · Automate", keywords: ["nl query", "natural language", "sql", "ask", "question", "query"] },
  { id: "settings",     label: "Settings",            Icon: Settings,         path: "/settings",              section: "8 · Configure",keywords: ["config", "settings", "api keys", "webhooks", "auth", "admin"] },
];

const QUICK_ACTIONS: SearchItem[] = [
  { id: "a-scan",   label: "New Scan",       Icon: Add,        path: "/scans",        type: "action", color: "#42A5F5", keywords: ["launch scan", "start scan", "new scan"] },
  { id: "a-agent",  label: "Run AI Buddy",   Icon: PlayArrow,  path: "/agents",       type: "action", color: "#5C6BC0", keywords: ["run agent", "launch agent", "ai"] },
  { id: "a-vapt",   label: "New VAPT Report",Icon: GppGood,    path: "/vapt/reports", type: "action", color: "#66BB6A", keywords: ["create report", "new report", "vapt"] },
  { id: "a-nlq",    label: "Ask Your Data",  Icon: Psychology, path: "/nl-query",     type: "action", color: "#FFA726", keywords: ["ask", "query", "nl"] },
];

// ── Mock data ─────────────────────────────────────────────────────────────────

const RECENT = [
  { label: "Findings",        sub: "12 critical open",     Icon: Security,   color: "#EF5350", path: "/findings" },
  { label: "Risk Overview",   sub: "Score: 72 / 100",      Icon: Insights,   color: "#FFA726", path: "/risk-overview" },
  { label: "AI Buddies",      sub: "Last run: 2h ago",     Icon: SmartToy,   color: "#5C6BC0", path: "/agents" },
  { label: "Scans",           sub: "1 running now",        Icon: BugReport,  color: "#26A69A", path: "/scans" },
  { label: "Threat Models",   sub: "2 models, 18 threats", Icon: Hub,        color: "#AB47BC", path: "/threat-models" },
  { label: "VAPT Reports",    sub: "3 reports",            Icon: GppGood,    color: "#66BB6A", path: "/vapt/reports" },
];

const METRICS = [
  { label: "Posture Score",     value: "72", unit: "/ 100",  icon: TrendingUp, color: "#FFA726", path: "/posture-trends" },
  { label: "Critical Findings", value: "12", unit: "open",   icon: Security,   color: "#EF5350", path: "/findings" },
  { label: "Active Scans",      value: "1",  unit: "running",icon: BugReport,  color: "#26A69A", path: "/scans" },
  { label: "Risks Scored",      value: "47", unit: "total",  icon: Insights,   color: "#42A5F5", path: "/risk-overview" },
  { label: "Control Gaps",      value: "8",  unit: "open",   icon: GppBad,     color: "#AB47BC", path: "/control-deficiencies" },
  { label: "VAPT Reports",      value: "3",  unit: "total",  icon: GppGood,    color: "#66BB6A", path: "/vapt/reports" },
];

const ACTIVITY = [
  { msg: "Orchestrator agent completed successfully",  time: "2 min ago",  type: "success" },
  { msg: "12 new findings from Azure cloud scan",      time: "18 min ago", type: "warning" },
  { msg: "VAPT Report generated — Acme Corp Q3",      time: "1 hr ago",   type: "success" },
  { msg: "Critical CVE CVE-2024-3094 detected",        time: "3 hr ago",   type: "error" },
  { msg: "Threat model updated — Customer Portal DFD", time: "Yesterday",  type: "info" },
];

// ── Search scoring ────────────────────────────────────────────────────────────

function scoreItem(item: SearchItem, words: string[]): number {
  const label = item.label.toLowerCase();
  const kws   = (item.keywords ?? []).join(" ").toLowerCase();
  const sec   = (item.section ?? "").toLowerCase();

  let score = 0;
  for (const w of words) {
    if (label === w)                  score += 100; // exact label
    else if (label.startsWith(w))     score += 80;  // label starts with
    else if (label.includes(w))       score += 60;  // label contains
    else if (kws.includes(w))         score += 40;  // keyword match
    else if (sec.includes(w))         score += 10;  // section match
    else return -1;                                  // word not found anywhere → exclude
  }
  return score;
}

function highlightText(text: string, query: string): React.ReactNode {
  if (!query.trim()) return text;
  const regex = new RegExp(`(${query.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&").split(/\s+/).join("|")})`, "gi");
  const parts = text.split(regex);
  return parts.map((part, i) =>
    regex.test(part)
      ? <Box key={i} component="mark" sx={{ bgcolor: "rgba(66,133,244,0.25)", color: "inherit", borderRadius: "2px", px: "1px" }}>{part}</Box>
      : part
  );
}

// ── Command Palette ───────────────────────────────────────────────────────────

function CommandPalette({
  open, onClose, initialQuery = "",
}: {
  open: boolean;
  onClose: () => void;
  initialQuery?: string;
}) {
  const theme   = useTheme();
  const navigate = useNavigate();
  const [query, setQuery]       = useState(initialQuery);
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery(initialQuery);
      setActiveIdx(0);
      setTimeout(() => inputRef.current?.focus(), 60);
    }
  }, [open, initialQuery]);

  // All searchable items
  const allItems = useMemo(() => [...NAV_ITEMS, ...QUICK_ACTIONS], []);

  const { grouped, flat } = useMemo(() => {
    const q = query.trim().toLowerCase();
    const words = q.split(/\s+/).filter(Boolean);

    if (!q) {
      // Default: pinned nav + quick actions, grouped
      const pinned = NAV_ITEMS.filter((n) => n.pinned);
      const sections = new Map<string, SearchItem[]>();
      NAV_ITEMS.filter((n) => !n.pinned).forEach((n) => {
        const s = n.section ?? "Other";
        if (!sections.has(s)) sections.set(s, []);
        sections.get(s)!.push(n);
      });
      const grouped: { header: string; items: SearchItem[] }[] = [
        { header: "FAVOURITES", items: pinned },
        { header: "QUICK ACTIONS", items: QUICK_ACTIONS },
        ...Array.from(sections.entries()).map(([h, items]) => ({ header: h.toUpperCase(), items })),
      ];
      const flat = grouped.flatMap((g) => g.items);
      return { grouped, flat };
    }

    // Scored search
    const scored = allItems
      .map((item) => ({ item, score: scoreItem(item, words) }))
      .filter(({ score }) => score > 0)
      .sort((a, b) => b.score - a.score);

    if (!scored.length) return { grouped: [], flat: [] };

    // Group scored results by section (or "Actions" for action type)
    const sectionMap = new Map<string, SearchItem[]>();
    scored.forEach(({ item }) => {
      const s = item.type === "action" ? "QUICK ACTIONS" : (item.section ?? "FAVOURITES").toUpperCase();
      if (!sectionMap.has(s)) sectionMap.set(s, []);
      sectionMap.get(s)!.push(item);
    });
    const grouped = Array.from(sectionMap.entries()).map(([header, items]) => ({ header, items }));
    const flat = scored.map(({ item }) => item);
    return { grouped, flat };
  }, [query, allItems]);

  const go = useCallback((item: SearchItem) => { onClose(); navigate(item.path); }, [onClose, navigate]);

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActiveIdx((i) => Math.min(i + 1, flat.length - 1)); }
    if (e.key === "ArrowUp")   { e.preventDefault(); setActiveIdx((i) => Math.max(i - 1, 0)); }
    if (e.key === "Enter" && flat[activeIdx]) go(flat[activeIdx]);
    if (e.key === "Escape") onClose();
  };

  const isDark = theme.palette.mode === "dark";

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="sm"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            borderRadius: 2, overflow: "hidden",
            boxShadow: "0 24px 64px rgba(0,0,0,0.55)",
            mt: "6vh", verticalAlign: "top",
            border: `1px solid ${alpha(theme.palette.divider, 0.5)}`,
            maxHeight: "75vh",
          },
        },
        backdrop: { sx: { backdropFilter: "blur(6px)", bgcolor: alpha("#000", 0.5) } },
      }}
    >
      <DialogContent sx={{ p: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {/* Search input */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, px: 2, py: 1.25, borderBottom: `1px solid ${theme.palette.divider}` }}>
          <Search sx={{ color: "text.disabled", fontSize: 20, flexShrink: 0 }} />
          <Box
            component="input"
            ref={inputRef}
            value={query}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => { setQuery(e.target.value); setActiveIdx(0); }}
            onKeyDown={handleKey}
            placeholder="Search resources, features, actions…"
            sx={{
              flex: 1, border: "none", outline: "none",
              background: "transparent", color: "text.primary",
              fontSize: "1rem", fontFamily: "inherit",
              "&::placeholder": { color: isDark ? "rgba(255,255,255,0.3)" : "rgba(0,0,0,0.35)" },
            }}
          />
          {query && (
            <Box
              onClick={() => { setQuery(""); setActiveIdx(0); inputRef.current?.focus(); }}
              sx={{ cursor: "pointer", fontSize: "0.72rem", color: "text.disabled", px: 0.75, py: 0.15, borderRadius: 0.5, bgcolor: alpha(theme.palette.divider, 0.6), "&:hover": { color: "text.primary" } }}
            >
              clear
            </Box>
          )}
          <Box sx={{ px: 0.75, py: 0.15, borderRadius: 0.5, bgcolor: alpha(theme.palette.divider, 0.6), fontFamily: "monospace", fontSize: "0.65rem", color: "text.disabled", flexShrink: 0 }}>
            esc
          </Box>
        </Box>

        {/* Results */}
        <Box sx={{ flex: 1, overflowY: "auto", "&::-webkit-scrollbar": { width: 4 }, "&::-webkit-scrollbar-thumb": { bgcolor: alpha(theme.palette.divider, 0.8), borderRadius: 2 } }}>
          {flat.length === 0 && query.trim() ? (
            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 5, gap: 1 }}>
              <SearchOff sx={{ fontSize: 36, color: "text.disabled" }} />
              <Typography variant="body2" color="text.disabled">No results for "{query}"</Typography>
              <Typography variant="caption" color="text.disabled">Try "agent", "scan", "risk", "compliance"…</Typography>
            </Box>
          ) : (
            grouped.map((group) => (
              <Box key={group.header}>
                <Typography variant="caption" sx={{
                  display: "block", px: 2, py: 0.6,
                  color: "text.disabled", fontWeight: 700,
                  letterSpacing: "0.08em", fontSize: "0.65rem",
                  bgcolor: alpha(theme.palette.background.default, 0.6),
                  position: "sticky", top: 0, zIndex: 1,
                }}>
                  {group.header}
                </Typography>
                <List dense disablePadding>
                  {group.items.map((item) => {
                    const globalIdx = flat.indexOf(item);
                    const isActive = globalIdx === activeIdx;
                    const { Icon } = item;
                    const iconColor = item.color ?? (isActive ? theme.palette.primary.main : undefined);
                    return (
                      <ListItemButton
                        key={item.id}
                        selected={isActive}
                        onClick={() => go(item)}
                        onMouseEnter={() => setActiveIdx(globalIdx)}
                        sx={{
                          px: 2, py: 0.85,
                          borderLeft: isActive ? `3px solid ${theme.palette.primary.main}` : "3px solid transparent",
                          "&.Mui-selected": { bgcolor: alpha(theme.palette.primary.main, 0.08) },
                        }}
                      >
                        <ListItemIcon sx={{ minWidth: 36 }}>
                          <Icon sx={{ fontSize: 18, color: iconColor ?? (isActive ? "primary.main" : "text.disabled") }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Typography variant="body2" sx={{ color: isActive ? "text.primary" : "text.secondary", fontSize: "0.86rem" }}>
                              {highlightText(item.label, query)}
                            </Typography>
                          }
                          secondary={item.section && (
                            <Typography variant="caption" sx={{ color: "text.disabled", fontSize: "0.7rem" }}>
                              {item.section}
                            </Typography>
                          )}
                          sx={{ m: 0 }}
                        />
                        {item.type === "action" && (
                          <Chip label="action" size="small" sx={{ height: 18, fontSize: "0.62rem", ml: 1, opacity: 0.7 }} />
                        )}
                        {isActive && <Typography variant="caption" color="text.disabled" sx={{ ml: 1, flexShrink: 0 }}>↵</Typography>}
                      </ListItemButton>
                    );
                  })}
                </List>
              </Box>
            ))
          )}
        </Box>

        {/* Footer hints */}
        <Box sx={{ px: 2, py: 0.75, borderTop: `1px solid ${theme.palette.divider}`, display: "flex", gap: 2, alignItems: "center", flexShrink: 0 }}>
          {([["↑↓", "navigate"], ["↵", "open"], ["esc", "close"]] as const).map(([k, a]) => (
            <Box key={k} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              <Box sx={{ px: 0.75, py: 0.1, borderRadius: 0.5, bgcolor: alpha(theme.palette.divider, 0.6), fontFamily: "monospace", fontSize: "0.65rem" }}>{k}</Box>
              <Typography variant="caption" color="text.disabled">{a}</Typography>
            </Box>
          ))}
          <Typography variant="caption" color="text.disabled" sx={{ ml: "auto" }}>
            {flat.length} result{flat.length !== 1 ? "s" : ""}
          </Typography>
        </Box>
      </DialogContent>
    </Dialog>
  );
}

// ── Left blade ────────────────────────────────────────────────────────────────

function LeftBlade({ expanded, onToggle }: { expanded: boolean; onToggle: () => void }) {
  const theme = useTheme();
  const navigate = useNavigate();
  const isDark = theme.palette.mode === "dark";
  const bladeBg = isDark ? "#1a1a2e" : "#1e3a5f";
  const hoverBg = alpha("#fff", 0.08);

  const pinned = NAV_ITEMS.filter((n) => n.pinned);
  const sections = useMemo(() => {
    const map = new Map<string, SearchItem[]>();
    NAV_ITEMS.filter((n) => !n.pinned).forEach((n) => {
      const sec = n.section ?? "Other";
      if (!map.has(sec)) map.set(sec, []);
      map.get(sec)!.push(n);
    });
    return map;
  }, []);

  const item = (nav: SearchItem) => {
    const { Icon } = nav;
    return (
      <Tooltip key={nav.id} title={expanded ? "" : nav.label} placement="right">
        <Box
          onClick={() => navigate(nav.path)}
          sx={{
            display: "flex", alignItems: "center",
            gap: expanded ? 1.5 : 0,
            px: expanded ? 1.5 : 0,
            justifyContent: expanded ? "flex-start" : "center",
            height: 40, cursor: "pointer", borderRadius: 1,
            mx: 0.5, mb: 0.25,
            transition: "background 0.15s",
            "&:hover": { bgcolor: hoverBg },
          }}
        >
          <Icon sx={{ fontSize: 18, color: alpha("#fff", 0.75), flexShrink: 0 }} />
          {expanded && (
            <Typography variant="body2" sx={{ color: alpha("#fff", 0.85), fontSize: "0.82rem", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
              {nav.label}
            </Typography>
          )}
        </Box>
      </Tooltip>
    );
  };

  return (
    <Box sx={{
      position: "fixed",
      top: TOPBAR_HEIGHT, left: 0, bottom: 0,
      width: expanded ? BLADE_EXPANDED : BLADE_COLLAPSED,
      bgcolor: bladeBg,
      transition: "width 0.2s ease",
      overflow: "hidden",
      display: "flex", flexDirection: "column",
      zIndex: 1100,
      boxShadow: "2px 0 8px rgba(0,0,0,0.3)",
    }}>
      <Box sx={{ pt: 1, pb: 0.5 }}>
        {expanded && (
          <Typography variant="caption" sx={{ display: "block", px: 1.5, py: 0.5, color: alpha("#fff", 0.4), fontWeight: 700, letterSpacing: "0.08em", fontSize: "0.65rem" }}>
            FAVOURITES
          </Typography>
        )}
        {pinned.map(item)}
      </Box>
      <Divider sx={{ borderColor: alpha("#fff", 0.1), mx: 1 }} />
      <Box sx={{ flex: 1, overflowY: "auto", overflowX: "hidden", pt: 0.5, pb: 2, "&::-webkit-scrollbar": { width: 4 }, "&::-webkit-scrollbar-thumb": { bgcolor: alpha("#fff", 0.15), borderRadius: 2 } }}>
        {expanded && (
          <Typography variant="caption" sx={{ display: "block", px: 1.5, py: 0.5, color: alpha("#fff", 0.4), fontWeight: 700, letterSpacing: "0.08em", fontSize: "0.65rem" }}>
            ALL SERVICES
          </Typography>
        )}
        {Array.from(sections.entries()).map(([section, items]) => (
          <Box key={section}>
            {expanded && (
              <Typography variant="caption" sx={{ display: "block", px: 1.5, pt: 1.25, pb: 0.25, color: alpha("#fff", 0.35), fontSize: "0.68rem", whiteSpace: "nowrap" }}>
                {section}
              </Typography>
            )}
            {items.map(item)}
          </Box>
        ))}
      </Box>
    </Box>
  );
}

// ── Top bar ───────────────────────────────────────────────────────────────────

function TopBar({
  onMenuClick,
  onSearchOpen,
  searchQuery,
  onSearchChange,
}: {
  onMenuClick: () => void;
  onSearchOpen: () => void;
  searchQuery: string;
  onSearchChange: (v: string) => void;
}) {
  const theme = useTheme();
  const navigate = useNavigate();
  const isDark = theme.palette.mode === "dark";
  const barBg = isDark ? "#0f1117" : "#003087";
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <Box sx={{
      position: "fixed", top: 0, left: 0, right: 0, height: TOPBAR_HEIGHT,
      bgcolor: barBg, zIndex: 1200,
      display: "flex", alignItems: "center", px: 1, gap: 1,
      boxShadow: "0 2px 8px rgba(0,0,0,0.4)",
    }}>
      {/* Hamburger */}
      <IconButton onClick={onMenuClick} sx={{ color: alpha("#fff", 0.8), "&:hover": { color: "#fff", bgcolor: alpha("#fff", 0.08) } }}>
        <MenuIcon />
      </IconButton>

      {/* Logo */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mr: 2, cursor: "pointer" }} onClick={() => navigate("/sample3")}>
        <Box sx={{ width: 26, height: 26, borderRadius: "6px", bgcolor: "#4285F4", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Typography sx={{ color: "#fff", fontSize: "0.75rem", fontWeight: 800 }}>O</Typography>
        </Box>
        <Typography sx={{ color: "#fff", fontWeight: 700, fontSize: "0.95rem", letterSpacing: "-0.02em", whiteSpace: "nowrap" }}>
          Owlet
        </Typography>
      </Box>

      {/* Search bar — real inline input, opens palette on focus/enter */}
      <Box sx={{
        flex: 1, maxWidth: 600, mx: "auto",
        display: "flex", alignItems: "center", gap: 1,
        bgcolor: alpha("#fff", 0.1),
        border: `1px solid ${alpha("#fff", 0.15)}`,
        borderRadius: 1, px: 1.5, py: 0.5,
        transition: "all 0.15s",
        "&:focus-within": { bgcolor: alpha("#fff", 0.16), borderColor: alpha("#fff", 0.35) },
        "&:hover": { bgcolor: alpha("#fff", 0.13) },
      }}>
        <Search sx={{ fontSize: 16, color: alpha("#fff", 0.55), flexShrink: 0 }} />
        <Box
          component="input"
          ref={inputRef}
          value={searchQuery}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => onSearchChange(e.target.value)}
          onFocus={onSearchOpen}
          onKeyDown={(e: React.KeyboardEvent<HTMLInputElement>) => {
            if (e.key === "Enter" || e.key === "ArrowDown") { e.preventDefault(); onSearchOpen(); }
          }}
          placeholder="Search resources, features, actions… (⌘K)"
          sx={{
            flex: 1, border: "none", outline: "none",
            background: "transparent", color: "#fff",
            fontSize: "0.85rem", fontFamily: "inherit",
            "&::placeholder": { color: alpha("#fff", 0.45) },
          }}
        />
        <Box sx={{ px: 0.75, py: 0.15, borderRadius: 0.5, bgcolor: alpha("#fff", 0.12), fontFamily: "monospace", fontSize: "0.65rem", color: alpha("#fff", 0.5), whiteSpace: "nowrap", flexShrink: 0 }}>
          ⌘K
        </Box>
      </Box>

      {/* Right utilities */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, ml: 1 }}>
        <Tooltip title="Notifications">
          <IconButton sx={{ color: alpha("#fff", 0.7), "&:hover": { color: "#fff", bgcolor: alpha("#fff", 0.08) } }}>
            <Badge badgeContent={3} color="error" sx={{ "& .MuiBadge-badge": { fontSize: "0.6rem", minWidth: 16, height: 16 } }}>
              <Notifications sx={{ fontSize: 20 }} />
            </Badge>
          </IconButton>
        </Tooltip>
        <Tooltip title="Settings">
          <IconButton onClick={() => navigate("/settings")} sx={{ color: alpha("#fff", 0.7), "&:hover": { color: "#fff", bgcolor: alpha("#fff", 0.08) } }}>
            <Settings sx={{ fontSize: 20 }} />
          </IconButton>
        </Tooltip>
        <Tooltip title="Dheeraj Gulati">
          <Avatar sx={{ width: 30, height: 30, bgcolor: "#4285F4", fontSize: "0.8rem", cursor: "pointer", ml: 0.5 }}>D</Avatar>
        </Tooltip>
      </Box>
    </Box>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function SampleAzure() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [bladeExpanded, setBladeExpanded]   = useState(false);
  const [paletteOpen,   setPaletteOpen]     = useState(false);
  const [searchQuery,   setSearchQuery]     = useState("");

  const openPalette = useCallback(() => setPaletteOpen(true), []);
  const closePalette = useCallback(() => { setPaletteOpen(false); setSearchQuery(""); }, []);

  // ⌘K shortcut
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") { e.preventDefault(); setPaletteOpen((v) => !v); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  const contentLeft = bladeExpanded ? BLADE_EXPANDED : BLADE_COLLAPSED;

  const activityColor = (type: string) =>
    type === "success" ? "#66BB6A" : type === "warning" ? "#FFA726" : type === "error" ? "#EF5350" : theme.palette.primary.main;

  return (
    <Box sx={{ bgcolor: "background.default", minHeight: "100vh" }}>
      <TopBar
        onMenuClick={() => setBladeExpanded((v) => !v)}
        onSearchOpen={openPalette}
        searchQuery={searchQuery}
        onSearchChange={(v) => { setSearchQuery(v); setPaletteOpen(true); }}
      />
      <LeftBlade expanded={bladeExpanded} onToggle={() => setBladeExpanded((v) => !v)} />

      {/* Main content */}
      <Box sx={{
        ml: `${contentLeft}px`,
        mt: `${TOPBAR_HEIGHT}px`,
        transition: "margin-left 0.2s ease",
        p: { xs: 2, md: 3 },
        minHeight: `calc(100vh - ${TOPBAR_HEIGHT}px)`,
      }}>
        {/* Breadcrumb */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mb: 2 }}>
          <Chip label="Sample — Option 3" size="small" color="secondary" variant="outlined" sx={{ mr: 1 }} />
          <Typography variant="caption" sx={{ color: "text.disabled", fontSize: "0.75rem" }}>Home</Typography>
        </Box>

        {/* Greeting */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 0.5 }}>Good morning, Dheeraj</Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mb: 3 }}>Here's your security operations overview</Typography>

        {/* Metrics row */}
        <Box sx={{ display: "flex", gap: 1.5, mb: 3, flexWrap: "wrap" }}>
          {METRICS.map((m) => {
            const { icon: Icon } = m;
            return (
              <Box
                key={m.label}
                onClick={() => navigate(m.path)}
                sx={{
                  flex: "1 1 130px", minWidth: 120,
                  bgcolor: "background.paper",
                  border: "1px solid", borderColor: "divider",
                  borderTop: `3px solid ${m.color}`,
                  borderRadius: 1.5, p: 1.5, cursor: "pointer",
                  transition: "box-shadow 0.15s, transform 0.15s",
                  "&:hover": { boxShadow: `0 4px 20px ${alpha(m.color, 0.2)}`, transform: "translateY(-2px)" },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                  <Icon sx={{ fontSize: 16, color: m.color }} />
                  <Typography variant="caption" sx={{ color: "text.secondary", fontSize: "0.72rem" }}>{m.label}</Typography>
                </Box>
                <Box sx={{ display: "flex", alignItems: "baseline", gap: 0.5 }}>
                  <Typography variant="h5" sx={{ fontWeight: 700, color: m.color, lineHeight: 1 }}>{m.value}</Typography>
                  <Typography variant="caption" sx={{ color: "text.disabled" }}>{m.unit}</Typography>
                </Box>
              </Box>
            );
          })}
        </Box>

        {/* Two-column layout */}
        <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
          {/* Left */}
          <Box sx={{ flex: "2 1 500px", minWidth: 280 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "text.secondary", fontSize: "0.78rem", letterSpacing: "0.06em" }}>
              RECENTLY VISITED
            </Typography>
            <Box sx={{ display: "flex", gap: 1.5, flexWrap: "wrap", mb: 3 }}>
              {RECENT.map((r) => {
                const { Icon } = r;
                return (
                  <Box
                    key={r.label}
                    onClick={() => navigate(r.path)}
                    sx={{
                      flex: "1 1 140px", minWidth: 130,
                      bgcolor: "background.paper",
                      border: "1px solid", borderColor: "divider",
                      borderRadius: 1.5, p: 1.5, cursor: "pointer",
                      transition: "all 0.15s",
                      "&:hover": { borderColor: r.color, boxShadow: `0 2px 12px ${alpha(r.color, 0.15)}`, transform: "translateY(-2px)" },
                    }}
                  >
                    <Box sx={{ width: 36, height: 36, borderRadius: "8px", bgcolor: alpha(r.color, 0.12), display: "flex", alignItems: "center", justifyContent: "center", mb: 1 }}>
                      <Icon sx={{ fontSize: 18, color: r.color }} />
                    </Box>
                    <Typography variant="body2" sx={{ fontWeight: 600, fontSize: "0.82rem", mb: 0.25 }}>{r.label}</Typography>
                    <Typography variant="caption" sx={{ color: "text.disabled", fontSize: "0.72rem" }}>{r.sub}</Typography>
                  </Box>
                );
              })}
            </Box>

            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "text.secondary", fontSize: "0.78rem", letterSpacing: "0.06em" }}>
              QUICK ACTIONS
            </Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              {QUICK_ACTIONS.map((a) => {
                const { Icon } = a;
                return (
                  <Box
                    key={a.id}
                    onClick={() => navigate(a.path)}
                    sx={{
                      display: "flex", alignItems: "center", gap: 1,
                      px: 2, py: 1,
                      bgcolor: "background.paper",
                      border: "1px solid", borderColor: "divider",
                      borderRadius: 1.5, cursor: "pointer",
                      transition: "all 0.15s",
                      "&:hover": { borderColor: a.color, bgcolor: alpha(a.color!, 0.06) },
                    }}
                  >
                    <Icon sx={{ fontSize: 16, color: a.color }} />
                    <Typography variant="body2" sx={{ fontWeight: 500, fontSize: "0.82rem" }}>{a.label}</Typography>
                  </Box>
                );
              })}
            </Box>
          </Box>

          {/* Right */}
          <Box sx={{ flex: "1 1 260px", minWidth: 240 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "text.secondary", fontSize: "0.78rem", letterSpacing: "0.06em" }}>
              RECENT ACTIVITY
            </Typography>
            <Box sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "divider", borderRadius: 1.5, overflow: "hidden" }}>
              {ACTIVITY.map((a, idx) => (
                <Box
                  key={idx}
                  sx={{
                    display: "flex", alignItems: "flex-start", gap: 1.5,
                    px: 2, py: 1.25,
                    borderBottom: idx < ACTIVITY.length - 1 ? "1px solid" : "none",
                    borderColor: "divider",
                    "&:hover": { bgcolor: "action.hover", cursor: "pointer" },
                  }}
                >
                  <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: activityColor(a.type), mt: 0.6, flexShrink: 0 }} />
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Typography variant="body2" sx={{ fontSize: "0.8rem", lineHeight: 1.3 }}>{a.msg}</Typography>
                    <Typography variant="caption" sx={{ color: "text.disabled", fontSize: "0.7rem" }}>{a.time}</Typography>
                  </Box>
                </Box>
              ))}
            </Box>

            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, mt: 3, color: "text.secondary", fontSize: "0.78rem", letterSpacing: "0.06em" }}>
              WORKFLOW PHASES
            </Typography>
            <Box sx={{ bgcolor: "background.paper", border: "1px solid", borderColor: "divider", borderRadius: 1.5, overflow: "hidden" }}>
              {[
                { label: "1 · Setup",     color: "#42A5F5", path: "/connections" },
                { label: "2 · Design",    color: "#AB47BC", path: "/threat-models" },
                { label: "3 · Discover",  color: "#26A69A", path: "/scans" },
                { label: "4 · Analyse",   color: "#FFA726", path: "/risk-overview" },
                { label: "5 · Respond",   color: "#EF5350", path: "/control-deficiencies" },
                { label: "6 · Report",    color: "#66BB6A", path: "/vapt/reports" },
                { label: "7 · Automate",  color: "#5C6BC0", path: "/agents" },
                { label: "8 · Configure", color: "#78909C", path: "/settings" },
              ].map((p, idx, arr) => (
                <Box
                  key={p.label}
                  onClick={() => navigate(p.path)}
                  sx={{
                    display: "flex", alignItems: "center", gap: 1.5,
                    px: 2, py: 1,
                    borderBottom: idx < arr.length - 1 ? "1px solid" : "none",
                    borderColor: "divider",
                    cursor: "pointer",
                    "&:hover": { bgcolor: "action.hover" },
                  }}
                >
                  <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: p.color, flexShrink: 0 }} />
                  <Typography variant="body2" sx={{ flex: 1, fontSize: "0.8rem" }}>{p.label}</Typography>
                  <ChevronRight sx={{ fontSize: 14, color: "text.disabled" }} />
                </Box>
              ))}
            </Box>
          </Box>
        </Box>
      </Box>

      <CommandPalette open={paletteOpen} onClose={closePalette} initialQuery={searchQuery} />
    </Box>
  );
}
