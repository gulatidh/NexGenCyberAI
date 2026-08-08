import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, IconButton, List, ListItemButton, ListItemIcon,
  ListItemText, Slide, alpha, Chip, Divider,
} from "@mui/material";
import {
  Search, Close, Dashboard, Security, BugReport, Insights, Hub, Cable,
  Radar, GppGood, GppBad, SmartToy, Policy, Storage, AutoStories,
  Psychology, Description, Assessment, PlaylistAddCheck, TrendingUp,
  Engineering, GridView, People, LibraryAdd, AccountTree, Schedule,
  Settings, Add, PlayArrow, SearchOff, CompareArrows,
  VpnKey, Webhook, MenuBook, BarChart, Apps, History,
  AccessTime,
} from "@mui/icons-material";
import { useTheme } from "@mui/material/styles";

// ── Types & data ──────────────────────────────────────────────────────────────

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
  { id: "dashboard",       label: "Dashboard",           Icon: Dashboard,        path: "/dashboard",                  section: "Overview",     keywords: ["home", "overview", "summary", "posture"] },
  { id: "reports",         label: "Reports",             Icon: BarChart,         path: "/reports",                    section: "Overview",     keywords: ["report", "export", "pdf"] },
  { id: "clients",         label: "Accounts",            Icon: People,           path: "/clients",                    section: "1 · Setup",    keywords: ["customer", "tenant", "org", "workspace", "clients"] },
  { id: "connections",     label: "Connections",         Icon: Cable,            path: "/connections",                section: "1 · Setup",    keywords: ["connector", "integration", "azure", "aws", "api", "ai settings", "provider"] },
  { id: "assets",          label: "Asset Inventory",     Icon: Storage,          path: "/assets",                     section: "1 · Setup",    keywords: ["inventory", "resource", "server", "cloud", "host", "infra"] },
  { id: "technologies",    label: "Technologies",        Icon: Apps,             path: "/assets/technologies",        section: "1 · Setup",    keywords: ["tech", "stack", "language", "framework"] },
  { id: "stale-assets",    label: "Stale Assets",        Icon: History,          path: "/stale-assets",               section: "1 · Setup",    keywords: ["stale", "unused", "old", "expired"] },
  { id: "frameworks",      label: "Frameworks",          Icon: Policy,           path: "/frameworks",                 section: "2 · Design",   keywords: ["nist", "cis", "iso", "pci", "gdpr", "compliance", "control", "standard"] },
  { id: "custom-fw",       label: "Custom Standards",    Icon: LibraryAdd,       path: "/custom-frameworks",          section: "2 · Design",   keywords: ["custom framework", "policy", "standard", "build"] },
  { id: "threat-models",   label: "Threat Models",       Icon: Hub,              path: "/threat-models",              section: "2 · Design",   keywords: ["dfd", "stride", "data flow", "diagram", "model", "design"] },
  { id: "scans",           label: "Assessments",         Icon: BugReport,        path: "/scans",                      section: "3 · Discover", keywords: ["scan", "assessment", "nmap", "zap", "trivy", "semgrep", "burp", "tenable", "qualys"] },
  { id: "findings",        label: "Findings",            Icon: Security,         path: "/findings",                   section: "3 · Discover", keywords: ["vulnerability", "issue", "alert", "cve", "open", "critical", "high"] },
  { id: "ai-scan",         label: "AI Assisted Scan",    Icon: SmartToy,         path: "/ai-assisted-scan",           section: "3 · Discover", keywords: ["ai scan", "guided", "wizard", "chat scan", "conversational"] },
  { id: "risk-overview",   label: "Risk Overview",       Icon: Insights,         path: "/risk-overview",              section: "4 · Analyse",  keywords: ["risk", "score", "posture", "ale", "fair", "exposure"] },
  { id: "risks",           label: "Risk Register",       Icon: Assessment,       path: "/risks",                      section: "4 · Analyse",  keywords: ["risk register", "fair", "likelihood", "impact", "score"] },
  { id: "attack-paths",    label: "Attack Paths",        Icon: AccountTree,      path: "/attack-paths",               section: "4 · Analyse",  keywords: ["attack chain", "lateral movement", "kill chain", "mitre", "path", "graph"] },
  { id: "cve-pivot",       label: "CVE Blast Radius",    Icon: BugReport,        path: "/cve-pivot",                  section: "4 · Analyse",  keywords: ["cve", "blast radius", "affected", "impact", "vulnerability"] },
  { id: "data-model",      label: "Data Ontology",       Icon: AccountTree,      path: "/data-model",                 section: "4 · Analyse",  keywords: ["ontology", "data model", "entity", "graph", "schema", "entities"] },
  { id: "heatmap",         label: "Compliance Heatmap",  Icon: GridView,         path: "/compliance-heatmap",         section: "4 · Analyse",  keywords: ["heatmap", "compliance", "control", "matrix", "gap"] },
  { id: "threat-intel",    label: "Threat Intelligence", Icon: Radar,            path: "/threat-register",            section: "5 · Respond",  keywords: ["threat", "intel", "ioc", "mitre", "att&ck", "ttp"] },
  { id: "gaps",            label: "Control Gaps",        Icon: GppBad,           path: "/control-deficiencies",       section: "5 · Respond",  keywords: ["gap", "deficiency", "control", "missing", "compliance gap"] },
  { id: "remediation",     label: "Remediation Tracker", Icon: PlaylistAddCheck, path: "/governance/remediation",     section: "5 · Respond",  keywords: ["fix", "remediate", "action", "patch", "tracker"] },
  { id: "ctem",            label: "CTEM Programs",       Icon: Engineering,      path: "/governance/ctem",            section: "5 · Respond",  keywords: ["ctem", "exposure management", "scope", "validate", "mobilise"] },
  { id: "vapt",            label: "VAPT Reports",        Icon: GppGood,          path: "/vapt/reports",               section: "6 · Report",   keywords: ["penetration test", "pen test", "report", "vapt", "engagement", "pdf", "docx"] },
  { id: "posture",         label: "Posture Trends",      Icon: TrendingUp,       path: "/posture-trends",             section: "6 · Report",   keywords: ["posture", "trend", "history", "chart", "audit readiness"] },
  { id: "comparison",      label: "Account Comparison",  Icon: CompareArrows,    path: "/client-comparison",          section: "6 · Report",   keywords: ["compare", "benchmark", "client", "multi"] },
  { id: "agents",          label: "AI Buddies",          Icon: SmartToy,         path: "/agents",                     section: "7 · Automate", keywords: ["agent", "buddy", "buddies", "ai", "orchestrator", "llm", "automation", "run agent"] },
  { id: "workflows",       label: "Workflows",           Icon: Schedule,         path: "/missions",                   section: "7 · Automate", keywords: ["mission", "workflow", "pipeline", "scheduled", "automated"] },
  { id: "sec-docs",        label: "Security Docs",       Icon: Description,      path: "/security-docs",              section: "7 · Automate", keywords: ["document", "upload", "policy", "rag", "ask docs"] },
  { id: "nlquery",         label: "Ask Your Data",       Icon: Psychology,       path: "/nl-query",                   section: "7 · Automate", keywords: ["nl query", "natural language", "sql", "ask", "question"] },
  { id: "knowledge",       label: "Knowledge Base",      Icon: AutoStories,      path: "/knowledge",                  section: "7 · Automate", keywords: ["kb", "knowledge", "articles", "wiki"] },
  { id: "settings",        label: "Settings",            Icon: Settings,         path: "/settings",                   section: "8 · Configure",keywords: ["config", "settings", "admin"] },
  { id: "webhooks",        label: "Webhooks",            Icon: Webhook,          path: "/webhooks",                   section: "8 · Configure",keywords: ["webhook", "slack", "teams", "notification", "event"] },
  { id: "api-keys",        label: "API Keys",            Icon: VpnKey,           path: "/api-keys",                   section: "8 · Configure",keywords: ["api key", "token", "m2m", "ci/cd", "integration"] },
  { id: "help",            label: "Help",                Icon: MenuBook,         path: "/help",                       section: "8 · Configure",keywords: ["help", "docs", "guide", "how to", "faq"] },
];

const QUICK_ACTIONS: SearchItem[] = [
  { id: "a-scan",  label: "New Scan",        Icon: Add,       path: "/scans",        type: "action", color: "#42A5F5", keywords: ["launch scan", "start scan", "new scan"] },
  { id: "a-agent", label: "Run AI Buddy",    Icon: PlayArrow, path: "/agents",       type: "action", color: "#5C6BC0", keywords: ["run agent", "launch agent", "ai buddy"] },
  { id: "a-vapt",  label: "New VAPT Report", Icon: GppGood,   path: "/vapt/reports", type: "action", color: "#66BB6A", keywords: ["create report", "new report", "vapt"] },
  { id: "a-nlq",   label: "Ask Your Data",   Icon: Psychology,path: "/nl-query",     type: "action", color: "#FFA726", keywords: ["ask", "query", "nl"] },
];

const RECENT_KEY = "aegis-search-recent";
const MAX_RECENT = 6;

function getRecent(): SearchItem[] {
  try {
    const ids: string[] = JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
    const all = [...NAV_ITEMS, ...QUICK_ACTIONS];
    return ids.map((id) => all.find((x) => x.id === id)).filter(Boolean) as SearchItem[];
  } catch { return []; }
}

function addRecent(id: string) {
  try {
    const prev: string[] = JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
    const next = [id, ...prev.filter((x) => x !== id)].slice(0, MAX_RECENT);
    localStorage.setItem(RECENT_KEY, JSON.stringify(next));
  } catch {}
}

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
          ? <Box key={i} component="mark" sx={{ bgcolor: "rgba(66,133,244,0.28)", color: "inherit", borderRadius: "2px", px: "1px" }}>{p}</Box>
          : p
      )}
    </>
  );
}

// ── Full-screen overlay search ────────────────────────────────────────────────

function SearchOverlay({ open, onClose }: { open: boolean; onClose: () => void }) {
  const theme    = useTheme();
  const navigate = useNavigate();
  const [query, setQuery]         = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  const [recentItems, setRecentItems] = useState<SearchItem[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const isDark = theme.palette.mode === "dark";

  useEffect(() => {
    if (open) {
      setQuery("");
      setActiveIdx(0);
      setRecentItems(getRecent());
      setTimeout(() => inputRef.current?.focus(), 60);
    }
  }, [open]);

  const allItems = useMemo(() => [...NAV_ITEMS, ...QUICK_ACTIONS], []);

  const { grouped, flat } = useMemo(() => {
    const q = query.trim().toLowerCase();
    const words = q.split(/\s+/).filter(Boolean);

    if (!q) {
      const recent = recentItems.slice(0, MAX_RECENT);
      if (recent.length) {
        return {
          grouped: [
            { header: "RECENT", items: recent, isRecent: true },
            { header: "QUICK ACTIONS", items: QUICK_ACTIONS, isRecent: false },
          ],
          flat: [...recent, ...QUICK_ACTIONS],
        };
      }
      return {
        grouped: [{ header: "QUICK ACTIONS", items: QUICK_ACTIONS, isRecent: false }],
        flat: QUICK_ACTIONS,
      };
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
      grouped: Array.from(sectionMap.entries()).map(([header, items]) => ({ header, items, isRecent: false })),
      flat: scored.map(({ item }) => item),
    };
  }, [query, allItems, recentItems]);

  const go = useCallback((item: SearchItem) => {
    addRecent(item.id);
    onClose();
    navigate(item.path);
  }, [onClose, navigate]);

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActiveIdx((i) => Math.min(i + 1, flat.length - 1)); }
    if (e.key === "ArrowUp")   { e.preventDefault(); setActiveIdx((i) => Math.max(i - 1, 0)); }
    if (e.key === "Enter" && flat[activeIdx]) go(flat[activeIdx]);
    if (e.key === "Escape") onClose();
  };

  const overlay = isDark
    ? { bg: "#0f172a", border: "rgba(148,163,184,0.14)", inputBg: "rgba(255,255,255,0.04)" }
    : { bg: "#ffffff", border: "rgba(15,23,42,0.1)", inputBg: "rgba(15,23,42,0.03)" };

  return (
    <Slide in={open} direction="down" timeout={180} mountOnEnter unmountOnExit>
      <Box
        sx={{
          position: "fixed", top: 0, left: 0, right: 0, zIndex: 1600,
          bgcolor: overlay.bg,
          boxShadow: isDark
            ? "0 8px 48px rgba(0,0,0,0.7)"
            : "0 8px 48px rgba(15,23,42,0.18)",
          borderBottom: `1px solid ${overlay.border}`,
        }}
      >
        {/* ── Top search bar row ── */}
        <Box sx={{
          display: "flex", alignItems: "center", gap: 0,
          px: { xs: 2, md: 4 }, py: 0,
          height: 64,
          borderBottom: `1px solid ${overlay.border}`,
        }}>
          {/* Search icon + label */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, pr: 3, flexShrink: 0 }}>
            <Search sx={{ fontSize: 22, color: "primary.main" }} />
            <Typography sx={{ fontWeight: 700, fontSize: 15, color: "text.primary", letterSpacing: "-0.01em" }}>
              Search
            </Typography>
          </Box>

          {/* Divider */}
          <Box sx={{ width: 1, height: 32, bgcolor: overlay.border, flexShrink: 0 }} />

          {/* Input */}
          <Box
            component="input"
            ref={inputRef}
            value={query}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => { setQuery(e.target.value); setActiveIdx(0); }}
            onKeyDown={handleKey}
            placeholder="Search pages, features, connectors, actions…"
            sx={{
              flex: 1,
              border: "none", outline: "none",
              background: "transparent",
              color: "text.primary",
              fontSize: "1.05rem",
              fontFamily: "inherit",
              px: 2.5,
              height: "100%",
              "&::placeholder": { color: isDark ? "rgba(230,235,243,0.35)" : "rgba(15,23,42,0.35)" },
            }}
          />

          {/* Clear + close */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexShrink: 0, pr: 0.5 }}>
            {query && (
              <Box
                onClick={() => { setQuery(""); setActiveIdx(0); inputRef.current?.focus(); }}
                sx={{
                  cursor: "pointer", fontSize: "0.72rem", color: "text.disabled",
                  px: 0.9, py: 0.25, borderRadius: 0.75,
                  bgcolor: alpha(theme.palette.divider, 0.5),
                  "&:hover": { color: "text.primary" },
                }}
              >
                clear
              </Box>
            )}
            <Box sx={{ px: 0.9, py: 0.2, borderRadius: 0.75, bgcolor: alpha(theme.palette.divider, 0.5), fontFamily: "monospace", fontSize: "0.65rem", color: "text.disabled" }}>
              esc
            </Box>
            <IconButton size="small" onClick={onClose} sx={{ ml: 0.5, color: "text.secondary", "&:hover": { color: "text.primary" } }}>
              <Close sx={{ fontSize: 20 }} />
            </IconButton>
          </Box>
        </Box>

        {/* ── Results panel ── */}
        <Box sx={{
          maxHeight: "calc(100vh - 128px)",
          overflowY: "auto",
          "&::-webkit-scrollbar": { width: 4 },
          "&::-webkit-scrollbar-thumb": { bgcolor: alpha(theme.palette.divider, 0.8), borderRadius: 2 },
        }}>
          {flat.length === 0 && query.trim() ? (
            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 6, gap: 1 }}>
              <SearchOff sx={{ fontSize: 40, color: "text.disabled" }} />
              <Typography variant="body2" color="text.disabled" sx={{ fontWeight: 500 }}>
                No results for "{query}"
              </Typography>
              <Typography variant="caption" color="text.disabled">
                Try "findings", "risk", "scan", "agent", "compliance"…
              </Typography>
            </Box>
          ) : (
            <Box sx={{ px: { xs: 2, md: 4 }, py: 1.5, display: "flex", gap: 6 }}>
              {/* Results list */}
              <Box sx={{ flex: 1, minWidth: 0 }}>
                {grouped.map((group, gi) => (
                  <Box key={group.header} sx={{ mb: gi < grouped.length - 1 ? 1.5 : 0 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                      {group.isRecent && <AccessTime sx={{ fontSize: 11, color: "text.disabled" }} />}
                      <Typography variant="caption" sx={{ color: "text.disabled", fontWeight: 700, letterSpacing: "0.09em", fontSize: "0.63rem" }}>
                        {group.header}
                      </Typography>
                    </Box>
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
                            sx={{
                              px: 1.5, py: 0.8, borderRadius: 1.5, mb: 0.25,
                              borderLeft: "none",
                              bgcolor: active ? alpha(theme.palette.primary.main, 0.1) : "transparent",
                              "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.07) },
                              "&.Mui-selected": { bgcolor: alpha(theme.palette.primary.main, 0.1) },
                            }}
                          >
                            <ListItemIcon sx={{ minWidth: 34 }}>
                              <Box sx={{
                                width: 28, height: 28, borderRadius: 1,
                                bgcolor: active ? alpha(item.color ?? theme.palette.primary.main, 0.18) : alpha(theme.palette.divider, 0.4),
                                display: "flex", alignItems: "center", justifyContent: "center",
                                transition: "background 0.12s",
                              }}>
                                <Icon sx={{ fontSize: 15, color: item.color ?? (active ? "primary.main" : "text.secondary") }} />
                              </Box>
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <Typography variant="body2" sx={{ color: active ? "text.primary" : "text.secondary", fontSize: "0.88rem", fontWeight: active ? 600 : 400 }}>
                                  <Highlight text={item.label} query={query} />
                                </Typography>
                              }
                              secondary={item.section && !query &&
                                <Typography variant="caption" sx={{ color: "text.disabled", fontSize: "0.68rem" }}>{item.section}</Typography>
                              }
                              sx={{ m: 0 }}
                            />
                            {item.type === "action" && (
                              <Chip label="action" size="small" sx={{ height: 17, fontSize: "0.6rem", ml: 1, opacity: 0.65, bgcolor: alpha(item.color ?? theme.palette.primary.main, 0.12), color: item.color ?? "primary.main" }} />
                            )}
                            {active && <Typography variant="caption" color="text.disabled" sx={{ ml: 1, flexShrink: 0, fontFamily: "monospace" }}>↵</Typography>}
                          </ListItemButton>
                        );
                      })}
                    </List>
                    {gi < grouped.length - 1 && <Divider sx={{ mt: 1.5, borderColor: overlay.border }} />}
                  </Box>
                ))}
              </Box>

              {/* Right hint panel (only when no query) */}
              {!query && (
                <Box sx={{ width: 240, flexShrink: 0, display: { xs: "none", lg: "block" } }}>
                  <Typography variant="caption" sx={{ color: "text.disabled", fontWeight: 700, letterSpacing: "0.09em", fontSize: "0.63rem", display: "block", mb: 1 }}>
                    KEYBOARD
                  </Typography>
                  {([["↑↓", "navigate"], ["↵", "open"], ["esc", "close"], ["⌘K", "toggle"]] as const).map(([k, a]) => (
                    <Box key={k} sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", py: 0.6 }}>
                      <Typography variant="caption" color="text.disabled">{a}</Typography>
                      <Box sx={{ px: 0.9, py: 0.2, borderRadius: 0.75, bgcolor: alpha(theme.palette.divider, 0.5), fontFamily: "monospace", fontSize: "0.65rem", color: "text.secondary" }}>{k}</Box>
                    </Box>
                  ))}
                  <Divider sx={{ my: 1.5, borderColor: overlay.border }} />
                  <Typography variant="caption" sx={{ color: "text.disabled", fontWeight: 700, letterSpacing: "0.09em", fontSize: "0.63rem", display: "block", mb: 1 }}>
                    TIPS
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.disabled", lineHeight: 1.7, display: "block" }}>
                    Type to search all pages, connectors, and features. Recent pages appear at the top.
                  </Typography>
                </Box>
              )}
            </Box>
          )}

          {/* Footer */}
          <Box sx={{ px: { xs: 2, md: 4 }, py: 1, borderTop: `1px solid ${overlay.border}`, display: "flex", alignItems: "center", gap: 2 }}>
            <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.68rem" }}>
              {flat.length} result{flat.length !== 1 ? "s" : ""}
            </Typography>
            <Typography variant="caption" color="text.disabled" sx={{ ml: "auto", fontSize: "0.68rem" }}>
              Monitara AI
            </Typography>
          </Box>
        </Box>
      </Box>
    </Slide>
  );
}

// ── Icon-only trigger ─────────────────────────────────────────────────────────

export default function GlobalSearch() {
  const theme = useTheme();
  const [open, setOpen] = useState(false);

  // ⌘K / Ctrl+K keyboard shortcut
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") { e.preventDefault(); setOpen((v) => !v); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  const close = useCallback(() => setOpen(false), []);

  return (
    <>
      <Box
        onClick={() => setOpen(true)}
        sx={{
          display: "flex", alignItems: "center", gap: 0.75,
          cursor: "pointer", px: 1.25, py: 0.6,
          borderRadius: 1.5,
          border: "1px solid transparent",
          color: "text.secondary",
          transition: "all 0.15s",
          "&:hover": {
            color: "text.primary",
            bgcolor: alpha(theme.palette.primary.main, 0.08),
            border: `1px solid ${alpha(theme.palette.primary.main, 0.25)}`,
          },
        }}
      >
        <Search sx={{ fontSize: 19 }} />
        <Box sx={{
          display: { xs: "none", md: "flex" },
          alignItems: "center",
          px: 0.7, py: 0.1, borderRadius: 0.75,
          bgcolor: alpha(theme.palette.divider, 0.5),
          fontFamily: "monospace", fontSize: "0.65rem",
          color: "text.disabled",
        }}>
          ⌘K
        </Box>
      </Box>

      <SearchOverlay open={open} onClose={close} />
    </>
  );
}
