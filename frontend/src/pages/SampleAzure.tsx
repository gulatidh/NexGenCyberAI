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
  Dashboard, Security, BugReport, Hub, Cable,
  Radar, GppGood, SmartToy, Policy, Storage,
  AutoStories, Psychology, Description, Assessment, GppBad,
  PlaylistAddCheck, TrendingUp, Engineering, GridView,
  Add, PlayArrow, People, LibraryAdd, AccountTree, Schedule,
  SearchOff,
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

// ── Stage color map (matches pipeline rail) ───────────────────────────────────

const STAGE_META: { num: string; label: string; color: string }[] = [
  { num: "01", label: "Setup",    color: "#3b82f6" },
  { num: "02", label: "Design",   color: "#a855f7" },
  { num: "03", label: "Discover", color: "#14b8a6" },
  { num: "04", label: "Analyse",  color: "#f59e0b" },
  { num: "05", label: "Respond",  color: "#ef4444" },
  { num: "06", label: "Report",   color: "#22c55e" },
  { num: "07", label: "Automate", color: "#6366f1" },
];

// ── Nav items aligned to pipeline stages ──────────────────────────────────────

const NAV_ITEMS: SearchItem[] = [
  // ── home ──────────────────────────────────────────────────────────────────
  { id: "dashboard",    label: "Dashboard",           Icon: Dashboard,        path: "/dashboard",              pinned: true, keywords: ["home", "overview", "summary", "main"] },

  // ── 01 · Setup ────────────────────────────────────────────────────────────
  { id: "clients",      label: "Clients",             Icon: People,           path: "/clients",                section: "01 · Setup",    keywords: ["customers", "tenants", "organisations", "workspace"] },
  { id: "assets",       label: "Assets",              Icon: Storage,          path: "/assets",                 section: "01 · Setup",    keywords: ["inventory", "resources", "servers", "cloud", "hosts"] },
  { id: "connections",  label: "Connectors",          Icon: Cable,            path: "/connections",            section: "01 · Setup",    keywords: ["connectors", "integrations", "azure", "aws", "configure", "api", "providers"] },
  { id: "settings",     label: "Settings",            Icon: Settings,         path: "/settings",               section: "01 · Setup",    keywords: ["config", "api keys", "webhooks", "auth", "admin"] },

  // ── 02 · Design ───────────────────────────────────────────────────────────
  { id: "threat-models",label: "Threat Models",       Icon: Hub,              path: "/threat-models",          section: "02 · Design",   keywords: ["dfd", "stride", "data flow", "diagram", "model", "attack surface"] },
  { id: "frameworks",   label: "Frameworks",          Icon: Policy,           path: "/frameworks",             section: "02 · Design",   keywords: ["nist", "cis", "gdpr", "iso", "pci", "compliance", "controls", "standards"] },
  { id: "custom-fw",    label: "Custom Policy",       Icon: LibraryAdd,       path: "/custom-frameworks",      section: "02 · Design",   keywords: ["custom framework", "policy", "standard", "build"] },

  // ── 03 · Discover ─────────────────────────────────────────────────────────
  { id: "scans",        label: "Scans",               Icon: BugReport,        path: "/scans",                  section: "03 · Discover", keywords: ["assessment", "scan", "test", "nmap", "zap", "trivy", "semgrep"] },
  { id: "findings",     label: "Findings",            Icon: Security,         path: "/findings",               section: "03 · Discover", keywords: ["vulnerabilities", "issues", "alerts", "bugs", "cve", "open"] },
  { id: "ai-scan",      label: "AI Assisted Scan",    Icon: SmartToy,         path: "/ai-assisted-scan",       section: "03 · Discover", keywords: ["ai scan", "guided", "wizard", "conversational", "chat"] },

  // ── 04 · Analyse ──────────────────────────────────────────────────────────
  { id: "risks",        label: "Risk Register",       Icon: Assessment,       path: "/risks",                  section: "04 · Analyse",  keywords: ["risk register", "risks", "fair", "score", "likelihood", "impact"] },
  { id: "attack",       label: "Attack Paths",        Icon: AccountTree,      path: "/attack-paths",           section: "04 · Analyse",  keywords: ["attack chain", "kill chain", "mitre", "path", "graph"] },
  { id: "nlquery",      label: "Ask Your Data",       Icon: Psychology,       path: "/nl-query",               section: "04 · Analyse",  keywords: ["nl query", "natural language", "sql", "ask", "question", "query"] },
  { id: "data-model",   label: "Data Model",          Icon: GridView,         path: "/data-model",             section: "04 · Analyse",  keywords: ["ontology", "entity", "graph", "schema", "relationships"] },

  // ── 05 · Respond ──────────────────────────────────────────────────────────
  { id: "threat-intel", label: "Threat Intelligence", Icon: Radar,            path: "/threat-register",        section: "05 · Respond",  keywords: ["threat", "intel", "ioc", "mitre", "att&ck", "ttp"] },
  { id: "gaps",         label: "Control Gaps",        Icon: GppBad,           path: "/control-deficiencies",   section: "05 · Respond",  keywords: ["gaps", "deficiencies", "control", "compliance", "missing"] },
  { id: "remediation",  label: "Remediation",         Icon: PlaylistAddCheck, path: "/governance/remediation", section: "05 · Respond",  keywords: ["fix", "remediate", "action", "ticket", "patch", "tracker"] },
  { id: "ctem",         label: "CTEM Programs",       Icon: Engineering,      path: "/governance/ctem",        section: "05 · Respond",  keywords: ["ctem", "exposure management", "scope", "validate", "mobilise"] },

  // ── 06 · Report ───────────────────────────────────────────────────────────
  { id: "vapt",         label: "VAPT Reports",        Icon: GppGood,          path: "/vapt/reports",           section: "06 · Report",   keywords: ["penetration test", "pen test", "report", "vapt", "engagement", "pdf"] },
  { id: "posture",      label: "Posture Trends",      Icon: TrendingUp,       path: "/posture-trends",         section: "06 · Report",   keywords: ["posture", "trend", "history", "graph", "chart", "audit"] },
  { id: "evidence",     label: "Compliance Monitor",  Icon: Description,      path: "/compliance/deficiencies",section: "06 · Report",   keywords: ["compliance monitor", "evidence", "control deficiency", "audit ready"] },

  // ── 07 · Automate ─────────────────────────────────────────────────────────
  { id: "agents",       label: "AI Buddies",          Icon: SmartToy,         path: "/agents",                 section: "07 · Automate", keywords: ["agent", "buddy", "buddies", "ai", "orchestrator", "llm", "run agent", "automation"] },
  { id: "knowledge",    label: "Knowledge Base",      Icon: AutoStories,      path: "/knowledge",              section: "07 · Automate", keywords: ["kb", "knowledge", "articles", "docs", "wiki"] },
  { id: "sec-docs",     label: "Security Docs",       Icon: Description,      path: "/security-docs",          section: "07 · Automate", keywords: ["document", "upload", "policy", "rag", "question", "ask docs"] },
  { id: "workflows",    label: "Workflows",           Icon: Schedule,         path: "/missions",               section: "07 · Automate", keywords: ["mission", "workflow", "pipeline", "scheduled", "automated"] },
];

const QUICK_ACTIONS: SearchItem[] = [
  { id: "a-scan",   label: "New Scan",       Icon: Add,        path: "/scans",        type: "action", color: "#42A5F5", keywords: ["launch scan", "start scan", "new scan"] },
  { id: "a-agent",  label: "Run AI Buddy",   Icon: PlayArrow,  path: "/agents",       type: "action", color: "#5C6BC0", keywords: ["run agent", "launch agent", "ai"] },
  { id: "a-vapt",   label: "New VAPT Report",Icon: GppGood,    path: "/vapt/reports", type: "action", color: "#66BB6A", keywords: ["create report", "new report", "vapt"] },
  { id: "a-nlq",    label: "Ask Your Data",  Icon: Psychology, path: "/nl-query",     type: "action", color: "#FFA726", keywords: ["ask", "query", "nl"] },
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

  // colour lookup by section key
  const stageColorOf = (sec: string): string => {
    const m = STAGE_META.find((s) => sec.startsWith(s.num));
    return m ? m.color : alpha("#fff", 0.5);
  };

  const pinned = NAV_ITEMS.filter((n) => n.pinned);

  const sections = useMemo(() => {
    const map = new Map<string, SearchItem[]>();
    STAGE_META.forEach((s) => map.set(`${s.num} · ${s.label}`, []));
    NAV_ITEMS.filter((n) => !n.pinned).forEach((n) => {
      const sec = n.section ?? "Other";
      if (!map.has(sec)) map.set(sec, []);
      map.get(sec)!.push(n);
    });
    return map;
  }, []);

  const navItem = (nav: SearchItem, iconColor?: string) => {
    const { Icon } = nav;
    const ic = iconColor ?? alpha("#fff", 0.65);
    return (
      <Tooltip key={nav.id} title={expanded ? "" : nav.label} placement="right">
        <Box
          onClick={() => navigate(nav.path)}
          sx={{
            display: "flex", alignItems: "center",
            gap: expanded ? 1.5 : 0,
            px: expanded ? 1.5 : 0,
            justifyContent: expanded ? "flex-start" : "center",
            height: 36, cursor: "pointer", borderRadius: 1,
            mx: 0.5, mb: 0.15,
            transition: "background 0.15s",
            "&:hover": { bgcolor: hoverBg },
          }}
        >
          <Icon sx={{ fontSize: 17, color: ic, flexShrink: 0 }} />
          {expanded && (
            <Typography sx={{ color: alpha("#fff", 0.82), fontSize: "0.8rem", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
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
      boxShadow: "2px 0 8px rgba(0,0,0,0.35)",
    }}>

      {/* Home row */}
      <Box sx={{ pt: 1, pb: 0.5 }}>
        {pinned.map((n) => navItem(n, alpha("#fff", 0.55)))}
      </Box>

      <Divider sx={{ borderColor: alpha("#fff", 0.08), mx: 1, mb: 0.5 }} />

      {/* Stage sections */}
      <Box sx={{ flex: 1, overflowY: "auto", overflowX: "hidden", pb: 2, "&::-webkit-scrollbar": { width: 3 }, "&::-webkit-scrollbar-thumb": { bgcolor: alpha("#fff", 0.12), borderRadius: 2 } }}>
        {Array.from(sections.entries()).map(([sec, items]) => {
          if (items.length === 0) return null;
          const color = stageColorOf(sec);
          const meta  = STAGE_META.find((s) => sec.startsWith(s.num));
          return (
            <Box key={sec} sx={{ mb: 0.5 }}>
              {/* Stage header */}
              {expanded ? (
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, px: 1.5, pt: 1.5, pb: 0.5 }}>
                  {/* Colored stage node */}
                  <Box sx={{
                    width: 22, height: 22, borderRadius: "50%", flexShrink: 0,
                    border: `1.5px solid ${color}`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    boxShadow: `0 0 8px -2px ${color}`,
                  }}>
                    <Typography sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.55rem", fontWeight: 700, color, lineHeight: 1 }}>
                      {meta?.num}
                    </Typography>
                  </Box>
                  <Typography sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.65rem", fontWeight: 600, color, letterSpacing: "0.08em", textTransform: "uppercase", whiteSpace: "nowrap" }}>
                    {meta?.label}
                  </Typography>
                </Box>
              ) : (
                /* Collapsed: just a colored 2px left accent line before icons */
                <Box sx={{ width: 2, height: 6, bgcolor: color, ml: "25px", borderRadius: 1, mb: 0.25, mt: 1 }} />
              )}

              {items.map((n) => navItem(n, color))}
            </Box>
          );
        })}
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

  return (
    <Box sx={{ bgcolor: "background.default", minHeight: "100vh" }}>
      <TopBar
        onMenuClick={() => setBladeExpanded((v) => !v)}
        onSearchOpen={openPalette}
        searchQuery={searchQuery}
        onSearchChange={(v) => { setSearchQuery(v); setPaletteOpen(true); }}
      />
      <LeftBlade expanded={bladeExpanded} onToggle={() => setBladeExpanded((v) => !v)} />

      {/* ── Pipeline main content ─────────────────────────────────────── */}
      <Box sx={{
        ml: `${contentLeft}px`,
        mt: `${TOPBAR_HEIGHT}px`,
        transition: "margin-left 0.2s ease",
        minHeight: `calc(100vh - ${TOPBAR_HEIGHT}px)`,
      }}>
        <Pipeline navigate={navigate} />
      </Box>

      <CommandPalette open={paletteOpen} onClose={closePalette} initialQuery={searchQuery} />
    </Box>
  );
}

// ── Pipeline stage data ───────────────────────────────────────────────────────

interface StageChip  { label: string; route: string }
interface StageModule { tag: string; name: string; desc: string; route: string; chips: StageChip[] }
interface Stage { num: string; id: string; color: string; title: string; sub: string; modules: StageModule[] }

const STAGES: Stage[] = [
  {
    num: "01", id: "setup", color: "#3b82f6",
    title: "Stand up the environment",
    sub: "Nothing downstream works without this. Get the tenant ready — clients, connectors, and AI providers.",
    modules: [
      { tag: "ST", name: "Setup", route: "/platform",
        desc: "Clients, assets, connectors, AI providers, and platform settings.",
        chips: [
          { label: "Clients",      route: "/clients" },
          { label: "Assets",       route: "/assets" },
          { label: "Connectors",   route: "/connections" },
          { label: "AI providers", route: "/connections" },
          { label: "Settings",     route: "/settings" },
        ] },
    ],
  },
  {
    num: "02", id: "design", color: "#a855f7",
    title: "Define the blueprint",
    sub: "Model how data actually moves, then pick which standards it has to satisfy.",
    modules: [
      { tag: "TM", name: "Threat Models", route: "/threat-intel/threat-models",
        desc: "Data flow diagrams, STRIDE analysis, and Sigma detection rules.",
        chips: [
          { label: "Data flow diagrams",    route: "/threat-intel/threat-models" },
          { label: "STRIDE analysis",       route: "/threat-intel/threat-models" },
          { label: "Sigma detection rules", route: "/threat-intel/threat-models" },
        ] },
      { tag: "FW", name: "Frameworks", route: "/compliance/frameworks",
        desc: "NIST, CIS, ISO 27001, PCI DSS, GDPR, and custom standards.",
        chips: [
          { label: "NIST CSF",      route: "/compliance/frameworks" },
          { label: "CIS Controls",  route: "/compliance/frameworks" },
          { label: "ISO 27001",     route: "/compliance/frameworks" },
          { label: "PCI DSS",       route: "/compliance/frameworks" },
          { label: "GDPR",          route: "/compliance/frameworks" },
          { label: "Custom policy", route: "/compliance/custom-frameworks" },
        ] },
    ],
  },
  {
    num: "03", id: "discover", color: "#14b8a6",
    title: "Find what's actually exposed",
    sub: "Scan the environment the blueprint just described — manually or through a guided AI conversation.",
    modules: [
      { tag: "VM", name: "Vulnerability Management", route: "/vulnerability",
        desc: "Scans, findings, posture trends, CVE enrichment, and scan import.",
        chips: [
          { label: "Scans",           route: "/vulnerability/scans" },
          { label: "Findings",        route: "/vulnerability/findings" },
          { label: "CVE enrichment",  route: "/vulnerability/findings" },
          { label: "Posture trends",  route: "/vulnerability/posture" },
          { label: "Scan import",     route: "/vulnerability/scans" },
        ] },
      { tag: "AI", name: "AI Assisted Scan", route: "/intelligence/ai-assisted-scan",
        desc: "Conversational guided assessment — describe your environment, launch a scan.",
        chips: [
          { label: "Guided wizard",    route: "/intelligence/ai-assisted-scan" },
          { label: "Environment chat", route: "/intelligence/ai-assisted-scan" },
          { label: "Auto-launch",      route: "/intelligence/ai-assisted-scan" },
        ] },
    ],
  },
  {
    num: "04", id: "analyse", color: "#f59e0b",
    title: "Turn findings into risk",
    sub: "Raw findings get scored, attack paths mapped, and the whole posture becomes queryable in plain language.",
    modules: [
      { tag: "RM", name: "Risk Manager", route: "/risk",
        desc: "FAIR-scored risk register, ALE exposure, and attack path graph.",
        chips: [
          { label: "Risk register",    route: "/risk/register" },
          { label: "FAIR / ALE",       route: "/risk/overview" },
          { label: "Attack paths",     route: "/threat-intel/attack-paths" },
          { label: "CVE blast radius", route: "/cve-pivot" },
        ] },
      { tag: "IG", name: "Smart Intelligence", route: "/intelligence",
        desc: "Natural language queries, compliance heatmap, and asset inventory.",
        chips: [
          { label: "Ask your data",      route: "/intelligence/nl-query" },
          { label: "Compliance heatmap", route: "/intelligence/reports" },
          { label: "Asset inventory",    route: "/assets" },
          { label: "Data model",         route: "/data-model" },
        ] },
    ],
  },
  {
    num: "05", id: "respond", color: "#ef4444",
    title: "Act on the picture",
    sub: "Map risk to real adversary behaviour, then push it into a tracked remediation program.",
    modules: [
      { tag: "TI", name: "Threat Intelligence", route: "/threat-intel",
        desc: "MITRE ATT&CK threat register and attack path visualisation.",
        chips: [
          { label: "Threat register", route: "/threat-intel/register" },
          { label: "MITRE ATT&CK",    route: "/threat-intel/register" },
          { label: "Attack paths",    route: "/threat-intel/attack-paths" },
        ] },
      { tag: "GR", name: "Governance", route: "/governance",
        desc: "CTEM programs, control gaps, remediation tracker, and scorecard.",
        chips: [
          { label: "CTEM programs",   route: "/governance/ctem" },
          { label: "Control gaps",    route: "/compliance/deficiencies" },
          { label: "Remediation",     route: "/governance/remediation" },
        ] },
    ],
  },
  {
    num: "06", id: "report", color: "#22c55e",
    title: "Prove it happened",
    sub: "Close the loop with evidence the client — or the auditor — can actually keep.",
    modules: [
      { tag: "PT", name: "Pen Testing / VAPT", route: "/vapt",
        desc: "VAPT reports with retest lifecycle and PDF/DOCX export.",
        chips: [
          { label: "VAPT reports",     route: "/vapt/reports" },
          { label: "Retest lifecycle", route: "/vapt/reports" },
          { label: "PDF / DOCX",       route: "/vapt/reports" },
        ] },
      { tag: "CM", name: "Compliance Monitor", route: "/compliance",
        desc: "Framework assessments, evidence packages, and audit-ready output.",
        chips: [
          { label: "Framework assessments", route: "/compliance/frameworks" },
          { label: "Evidence packages",     route: "/compliance/evidence" },
          { label: "Control deficiencies",  route: "/compliance/deficiencies" },
        ] },
    ],
  },
  {
    num: "07", id: "automate", color: "#6366f1",
    title: "Let AI carry the load",
    sub: "Once the first run is done, agents run the loop — analysis, intel, remediation, knowledge — on repeat.",
    modules: [
      { tag: "AB", name: "AI Buddies", route: "/agents",
        desc: "60+ AI agents — orchestrator, risk manager, threat intel, remediation.",
        chips: [
          { label: "Orchestrator", route: "/agents" },
          { label: "Risk Manager", route: "/agents" },
          { label: "Threat Intel", route: "/agents" },
          { label: "Remediation",  route: "/agents" },
        ] },
      { tag: "KB", name: "Knowledge & Docs", route: "/knowledge",
        desc: "Knowledge base, security doc RAG, and ask-your-data queries.",
        chips: [
          { label: "Knowledge base", route: "/knowledge" },
          { label: "Security docs",  route: "/security-docs" },
          { label: "Ask your data",  route: "/intelligence/nl-query" },
        ] },
    ],
  },
];

// ── Pipeline component ────────────────────────────────────────────────────────

function FeatureChip({ label, route, color, nav }: { label: string; route: string; color: string; nav: (p: string) => void }) {
  const [active, setActive] = useState(false);
  return (
    <Box
      component="button"
      onClick={() => { setActive((v) => !v); nav(route); }}
      sx={{
        fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.72rem",
        color: active ? "#fff" : "text.secondary",
        bgcolor: active ? alpha(color, 0.18) : "background.default",
        border: "1px solid", borderColor: active ? color : "divider",
        px: 1.25, py: 0.65, borderRadius: "6px",
        cursor: "pointer", transition: "all 0.14s",
        "&:hover": { borderColor: color, color: "text.primary" },
      }}
    >
      {active ? `✓ ${label}` : label}
    </Box>
  );
}

function ModuleCard({ mod, color, nav }: { mod: StageModule; color: string; nav: (p: string) => void }) {
  return (
    <Box sx={{
      bgcolor: "background.paper",
      border: "1px solid", borderColor: "divider",
      borderRadius: "10px", p: "16px 18px",
      transition: "border-color 0.15s, transform 0.15s",
      "&:hover": { borderColor: color, transform: "translateY(-1px)" },
    }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.25, mb: 1, cursor: "pointer" }} onClick={() => nav(mod.route)}>
        <Box sx={{
          fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.66rem", fontWeight: 700,
          color, bgcolor: alpha(color, 0.14),
          px: 0.9, py: 0.4, borderRadius: "4px", letterSpacing: "0.05em", flexShrink: 0,
        }}>
          {mod.tag}
        </Box>
        <Typography sx={{ fontWeight: 700, fontSize: "0.94rem", "&:hover": { color } }}>
          {mod.name}
        </Typography>
      </Box>
      <Typography sx={{ color: "text.secondary", fontSize: "0.81rem", lineHeight: 1.55, mb: 1.25 }}>
        {mod.desc}
      </Typography>
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
        {mod.chips.map((c) => (
          <FeatureChip key={c.label} label={c.label} route={c.route} color={color} nav={nav} />
        ))}
      </Box>
    </Box>
  );
}

function Pipeline({ navigate: nav }: { navigate: (p: string) => void }) {
  const RAIL = "linear-gradient(180deg,#3b82f6,#a855f7 25%,#14b8a6 42%,#f59e0b 58%,#ef4444 75%,#22c55e 88%,#6366f1)";

  // Load fonts
  useEffect(() => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Space+Grotesk:wght@400;600;700&display=swap";
    document.head.appendChild(link);
    return () => { document.head.removeChild(link); };
  }, []);

  return (
    <Box sx={{ maxWidth: 900, px: { xs: 2.5, md: 5 }, py: { xs: 4, md: 7 }, pb: 14 }}>

      {/* Hero */}
      <Box sx={{ pb: 6, borderBottom: "1px solid", borderColor: "divider", mb: 1 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.25, mb: 2.5 }}>
          <Box sx={{ width: 8, height: 8, borderRadius: "50%", background: RAIL, boxShadow: "0 0 10px 1px #3b82f688" }} />
          <Typography sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.72rem", letterSpacing: "0.14em", textTransform: "uppercase", color: "text.disabled" }}>
            Owlet · Security Operations Platform
          </Typography>
        </Box>
        <Typography sx={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700, fontSize: { xs: 28, md: 40 }, letterSpacing: "-0.02em", lineHeight: 1.08, mb: 2 }}>
          One{" "}
          <Box component="span" sx={{ background: RAIL, WebkitBackgroundClip: "text", backgroundClip: "text", color: "transparent" }}>
            signal path
          </Box>
          ,{" "}from setup to evidence.
        </Typography>
        <Typography sx={{ color: "text.secondary", fontSize: "0.97rem", maxWidth: 580 }}>
          Seven stages run in order — each one hands its output to the next. Click any chip to jump straight there.
        </Typography>
      </Box>

      {/* Pipeline */}
      <Box sx={{ position: "relative", mt: 7 }}>
        {/* Rail */}
        <Box sx={{ position: "absolute", left: 23, top: 14, bottom: 14, width: 2, background: RAIL, opacity: 0.5 }} />

        {STAGES.map((stage, si) => (
          <Box
            key={stage.id}
            id={`stage-${stage.id}`}
            sx={{
              position: "relative", pl: "64px",
              mb: si < STAGES.length - 1 ? 8 : 0,
              opacity: 0, transform: "translateY(14px)",
              animation: `s3rise 0.55s ease ${si * 0.07}s forwards`,
              "@keyframes s3rise": { to: { opacity: 1, transform: "translateY(0)" } },
            }}
          >
            {/* Node */}
            <Box sx={{
              position: "absolute", left: 0, top: 0,
              width: 48, height: 48, borderRadius: "50%",
              bgcolor: "background.default",
              border: `2px solid ${stage.color}`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontFamily: "'IBM Plex Mono', monospace", fontWeight: 600, fontSize: "1.05rem",
              color: stage.color,
              boxShadow: `0 0 0 5px background.default, 0 0 22px -4px ${stage.color}`,
              zIndex: 2,
            }}>
              {stage.num}
            </Box>

            {/* Stage header */}
            <Box sx={{ pt: "5px", mb: 2.5 }}>
              <Typography sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.75rem", color: stage.color, letterSpacing: "0.1em", textTransform: "uppercase", mb: 0.75 }}>
                Stage {stage.num} · {STAGES[si].id.charAt(0).toUpperCase() + STAGES[si].id.slice(1)}
              </Typography>
              <Typography sx={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: { xs: 20, md: 24 }, fontWeight: 600, letterSpacing: "-0.01em", mb: 0.75 }}>
                {stage.title}
              </Typography>
              <Typography sx={{ color: "text.secondary", fontSize: "0.9rem", maxWidth: 560 }}>
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
                <ModuleCard key={mod.tag} mod={mod} color={stage.color} nav={nav} />
              ))}
            </Box>
          </Box>
        ))}
      </Box>

      {/* Footer */}
      <Box sx={{ mt: 10, pt: 3, borderTop: "1px solid", borderColor: "divider", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 1.5 }}>
        <Typography sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.69rem", color: "text.disabled", letterSpacing: "0.02em" }}>
          SETUP → DESIGN → DISCOVER → ANALYSE → RESPOND → REPORT → AUTOMATE
        </Typography>
        <Box sx={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: "0.69rem", color: "text.secondary", border: "1px solid", borderColor: "divider", px: 1.5, py: 0.75, borderRadius: "20px" }}>
          Owlet · NexGenAI
        </Box>
      </Box>
    </Box>
  );
}
