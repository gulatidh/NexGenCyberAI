/**
 * SampleAzure — Azure-Portal-style full-page layout sample
 * Route: /sample3
 * Renders its own top bar + left blade — NOT inside AppLayout.
 */
import React, { useState, useEffect, useRef, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, IconButton, InputBase, Chip, Avatar,
  Tooltip, alpha, Badge, Card, Dialog, DialogContent,
  List, ListItemButton, ListItemIcon, ListItemText,
  InputAdornment, TextField, Divider,
} from "@mui/material";
import {
  Menu as MenuIcon, Search, Notifications, Settings,
  Dashboard, Security, BugReport, Insights, Hub, Cable,
  Radar, GppGood, SmartToy, Policy, Storage,
  AutoStories, Psychology, Description, Assessment, GppBad,
  PlaylistAddCheck, TrendingUp, Engineering, GridView,
  Star, Add, PlayArrow, CheckCircle, People,
  LibraryAdd, AccountTree, Warning, Schedule,
  ChevronRight, AccountCircle,
} from "@mui/icons-material";
import { useTheme } from "@mui/material/styles";

// ── Constants ────────────────────────────────────────────────────────────────

const BLADE_COLLAPSED = 52;
const BLADE_EXPANDED  = 236;
const TOPBAR_HEIGHT   = 52;

// ── Nav items ────────────────────────────────────────────────────────────────

interface NavItem { id: string; label: string; Icon: React.ElementType; path: string; section?: string; pinned?: boolean }

const NAV_ITEMS: NavItem[] = [
  { id: "dashboard",    label: "Dashboard",          Icon: Dashboard,       path: "/dashboard",            pinned: true },
  { id: "findings",     label: "Findings",           Icon: Security,        path: "/findings",             pinned: true },
  { id: "scans",        label: "Scans",              Icon: BugReport,       path: "/scans",                pinned: true },
  { id: "risk",         label: "Risk Overview",      Icon: Insights,        path: "/risk-overview",        pinned: true },
  { id: "setup",        label: "Setup",              Icon: Cable,           path: "/connections",          section: "1 · Setup" },
  { id: "clients",      label: "Clients",            Icon: People,          path: "/clients",              section: "1 · Setup" },
  { id: "design",       label: "Threat Models",      Icon: Hub,             path: "/threat-models",        section: "2 · Design" },
  { id: "frameworks",   label: "Frameworks",         Icon: Policy,          path: "/frameworks",           section: "2 · Design" },
  { id: "custom",       label: "Custom Policy",      Icon: LibraryAdd,      path: "/custom-frameworks",    section: "2 · Design" },
  { id: "ai-scan",      label: "AI Assisted Scan",   Icon: SmartToy,        path: "/ai-assisted-scan",     section: "3 · Discover" },
  { id: "assets",       label: "Assets",             Icon: Storage,         path: "/assets",               section: "3 · Discover" },
  { id: "risk-reg",     label: "Risk Register",      Icon: Assessment,      path: "/risks",                section: "4 · Analyse" },
  { id: "attack",       label: "Attack Paths",       Icon: AccountTree,     path: "/attack-paths",         section: "4 · Analyse" },
  { id: "heatmap",      label: "Compliance Heatmap", Icon: GridView,        path: "/compliance-heatmap",   section: "4 · Analyse" },
  { id: "threat-intel", label: "Threat Intelligence",Icon: Radar,           path: "/threat-register",      section: "5 · Respond" },
  { id: "gaps",         label: "Control Gaps",       Icon: GppBad,          path: "/control-deficiencies", section: "5 · Respond" },
  { id: "remediation",  label: "Remediation",        Icon: PlaylistAddCheck,path: "/governance/remediation",section: "5 · Respond" },
  { id: "ctem",         label: "CTEM Programs",      Icon: Engineering,     path: "/governance/ctem",      section: "5 · Respond" },
  { id: "vapt",         label: "VAPT Reports",       Icon: GppGood,         path: "/vapt/reports",         section: "6 · Report" },
  { id: "posture",      label: "Posture Trends",     Icon: TrendingUp,      path: "/posture-trends",       section: "6 · Report" },
  { id: "agents",       label: "AI Buddies",         Icon: SmartToy,        path: "/agents",               section: "7 · Automate" },
  { id: "workflows",    label: "Workflows",          Icon: Schedule,        path: "/missions",             section: "7 · Automate" },
  { id: "knowledge",    label: "Knowledge Base",     Icon: AutoStories,     path: "/knowledge",            section: "7 · Automate" },
  { id: "docs",         label: "Security Docs",      Icon: Description,     path: "/security-docs",        section: "7 · Automate" },
  { id: "nlquery",      label: "Ask Your Data",      Icon: Psychology,      path: "/nl-query",             section: "7 · Automate" },
  { id: "settings",     label: "Settings",           Icon: Settings,        path: "/settings",             section: "8 · Configure" },
];

// ── Recently visited (mock) ──────────────────────────────────────────────────

const RECENT = [
  { label: "Findings",        sub: "12 critical open",  Icon: Security,   color: "#EF5350", path: "/findings" },
  { label: "Risk Overview",   sub: "Score: 72 / 100",   Icon: Insights,   color: "#FFA726", path: "/risk-overview" },
  { label: "AI Buddies",      sub: "Last run: 2h ago",  Icon: SmartToy,   color: "#5C6BC0", path: "/agents" },
  { label: "Scans",           sub: "1 running now",     Icon: BugReport,  color: "#26A69A", path: "/scans" },
  { label: "Threat Models",   sub: "2 models, 18 threats", Icon: Hub,    color: "#AB47BC", path: "/threat-models" },
  { label: "VAPT Reports",    sub: "3 reports",         Icon: GppGood,    color: "#66BB6A", path: "/vapt/reports" },
];

// ── Quick actions ────────────────────────────────────────────────────────────

const QUICK_ACTIONS = [
  { label: "New Scan",      Icon: Add,       color: "#42A5F5", path: "/scans" },
  { label: "Run Agent",     Icon: PlayArrow, color: "#5C6BC0", path: "/agents" },
  { label: "VAPT Report",   Icon: GppGood,   color: "#66BB6A", path: "/vapt/reports" },
  { label: "Ask Your Data", Icon: Psychology,color: "#FFA726", path: "/nl-query" },
];

// ── Security metrics (mock) ──────────────────────────────────────────────────

const METRICS = [
  { label: "Posture Score",     value: "72",  unit: "/ 100", icon: TrendingUp,  color: "#FFA726", path: "/posture-trends" },
  { label: "Critical Findings", value: "12",  unit: "open",  icon: Security,    color: "#EF5350", path: "/findings" },
  { label: "Active Scans",      value: "1",   unit: "running",icon: BugReport,  color: "#26A69A", path: "/scans" },
  { label: "Risks Scored",      value: "47",  unit: "total", icon: Insights,    color: "#42A5F5", path: "/risk-overview" },
  { label: "Control Gaps",      value: "8",   unit: "open",  icon: GppBad,      color: "#AB47BC", path: "/control-deficiencies" },
  { label: "VAPT Reports",      value: "3",   unit: "total", icon: GppGood,     color: "#66BB6A", path: "/vapt/reports" },
];

// ── Activity feed (mock) ─────────────────────────────────────────────────────

const ACTIVITY = [
  { msg: "Orchestrator agent completed successfully",  time: "2 min ago",   type: "success" },
  { msg: "12 new findings from Azure cloud scan",      time: "18 min ago",  type: "warning" },
  { msg: "VAPT Report generated — Acme Corp Q3",      time: "1 hr ago",    type: "success" },
  { msg: "Critical CVE CVE-2024-3094 detected",        time: "3 hr ago",    type: "error" },
  { msg: "Threat model updated — Customer Portal DFD", time: "Yesterday",   type: "info" },
];

// ── Command palette ──────────────────────────────────────────────────────────

function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const theme = useTheme();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) { setQuery(""); setActiveIdx(0); setTimeout(() => inputRef.current?.focus(), 60); }
  }, [open]);

  const filtered = useMemo(() => {
    if (!query.trim()) return NAV_ITEMS.slice(0, 10);
    const q = query.toLowerCase();
    return NAV_ITEMS.filter(
      (n) => n.label.toLowerCase().includes(q) || (n.section ?? "").toLowerCase().includes(q)
    );
  }, [query]);

  const go = (item: NavItem) => { onClose(); navigate(item.path); };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActiveIdx((i) => Math.min(i + 1, filtered.length - 1)); }
    if (e.key === "ArrowUp")   { e.preventDefault(); setActiveIdx((i) => Math.max(i - 1, 0)); }
    if (e.key === "Enter" && filtered[activeIdx]) go(filtered[activeIdx]);
    if (e.key === "Escape") onClose();
  };

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
            boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
            mt: "6vh", verticalAlign: "top",
            border: `1px solid ${alpha(theme.palette.divider, 0.4)}`,
          },
        },
        backdrop: { sx: { backdropFilter: "blur(6px)", bgcolor: alpha("#000", 0.55) } },
      }}
    >
      <DialogContent sx={{ p: 0 }}>
        <TextField
          inputRef={inputRef}
          fullWidth
          placeholder="Search resources, services, docs…"
          value={query}
          onChange={(e) => { setQuery(e.target.value); setActiveIdx(0); }}
          onKeyDown={handleKey}
          variant="outlined"
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <Search sx={{ color: "text.disabled", fontSize: 20 }} />
                </InputAdornment>
              ),
            },
          }}
          sx={{
            "& .MuiOutlinedInput-root": {
              borderRadius: 0,
              borderBottom: `1px solid ${theme.palette.divider}`,
              fontSize: "1rem",
              "& fieldset": { border: "none" },
            },
          }}
        />
        <Box sx={{ maxHeight: 400, overflow: "auto" }}>
          {!query.trim() && (
            <Typography variant="caption" sx={{ display: "block", px: 2, py: 0.75, color: "text.disabled", fontWeight: 600, letterSpacing: "0.08em", fontSize: "0.68rem", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
              ALL SERVICES
            </Typography>
          )}
          <List dense disablePadding>
            {filtered.map((item, idx) => {
              const { Icon } = item;
              const isActive = idx === activeIdx;
              return (
                <ListItemButton
                  key={item.id}
                  selected={isActive}
                  onClick={() => go(item)}
                  onMouseEnter={() => setActiveIdx(idx)}
                  sx={{
                    px: 2, py: 0.85,
                    borderLeft: isActive ? `3px solid ${theme.palette.primary.main}` : "3px solid transparent",
                    "&.Mui-selected": { bgcolor: alpha(theme.palette.primary.main, 0.08) },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 36 }}>
                    <Icon sx={{ fontSize: 18, color: isActive ? "primary.main" : "text.disabled" }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={<Typography variant="body2" sx={{ color: isActive ? "text.primary" : "text.secondary" }}>{item.label}</Typography>}
                    secondary={item.section && <Typography variant="caption" color="text.disabled">{item.section}</Typography>}
                    sx={{ m: 0 }}
                  />
                  {isActive && <Typography variant="caption" color="text.disabled">↵</Typography>}
                </ListItemButton>
              );
            })}
          </List>
        </Box>
        <Box sx={{ px: 2, py: 0.75, borderTop: `1px solid ${theme.palette.divider}`, display: "flex", gap: 2, alignItems: "center" }}>
          {([["↑↓", "navigate"], ["↵", "open"], ["esc", "close"]] as const).map(([k, a]) => (
            <Box key={k} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              <Box sx={{ px: 0.75, py: 0.1, borderRadius: 0.5, bgcolor: alpha(theme.palette.divider, 0.6), fontFamily: "monospace", fontSize: "0.65rem" }}>{k}</Box>
              <Typography variant="caption" color="text.disabled">{a}</Typography>
            </Box>
          ))}
        </Box>
      </DialogContent>
    </Dialog>
  );
}

// ── Left blade ───────────────────────────────────────────────────────────────

function LeftBlade({ expanded, onToggle }: { expanded: boolean; onToggle: () => void }) {
  const theme = useTheme();
  const navigate = useNavigate();
  const isDark = theme.palette.mode === "dark";
  const bladeBg = isDark ? "#1a1a2e" : "#1e3a5f";
  const hoverBg = alpha("#fff", 0.08);

  const pinned = NAV_ITEMS.filter((n) => n.pinned);

  // Build section groups
  const sections = useMemo(() => {
    const map = new Map<string, NavItem[]>();
    NAV_ITEMS.filter((n) => !n.pinned).forEach((n) => {
      const sec = n.section ?? "Other";
      if (!map.has(sec)) map.set(sec, []);
      map.get(sec)!.push(n);
    });
    return map;
  }, []);

  const item = (nav: NavItem) => {
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
      {/* Pinned favourites */}
      <Box sx={{ pt: 1, pb: 0.5 }}>
        {expanded && (
          <Typography variant="caption" sx={{ display: "block", px: 1.5, py: 0.5, color: alpha("#fff", 0.4), fontWeight: 700, letterSpacing: "0.08em", fontSize: "0.65rem" }}>
            FAVOURITES
          </Typography>
        )}
        {pinned.map(item)}
      </Box>

      <Divider sx={{ borderColor: alpha("#fff", 0.1), mx: 1 }} />

      {/* All services */}
      <Box sx={{ flex: 1, overflowY: "auto", overflowX: "hidden", pt: 0.5, pb: 2,
        "&::-webkit-scrollbar": { width: 4 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha("#fff", 0.15), borderRadius: 2 },
      }}>
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

// ── Top bar ──────────────────────────────────────────────────────────────────

function TopBar({ onMenuClick, onSearchClick }: { onMenuClick: () => void; onSearchClick: () => void }) {
  const theme = useTheme();
  const navigate = useNavigate();
  const isDark = theme.palette.mode === "dark";
  const barBg = isDark ? "#0f1117" : "#003087";

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
          <Typography sx={{ color: "#fff", fontSize: "0.75rem", fontWeight: 800 }}>A</Typography>
        </Box>
        <Typography sx={{ color: "#fff", fontWeight: 700, fontSize: "0.95rem", letterSpacing: "-0.02em", whiteSpace: "nowrap" }}>
          Aegis
        </Typography>
      </Box>

      {/* Search bar — central, prominent */}
      <Box
        onClick={onSearchClick}
        sx={{
          flex: 1, maxWidth: 600, mx: "auto",
          display: "flex", alignItems: "center", gap: 1,
          bgcolor: alpha("#fff", 0.1),
          border: `1px solid ${alpha("#fff", 0.15)}`,
          borderRadius: 1, px: 1.5, py: 0.6,
          cursor: "text",
          transition: "all 0.15s",
          "&:hover": { bgcolor: alpha("#fff", 0.15), borderColor: alpha("#fff", 0.3) },
        }}
      >
        <Search sx={{ fontSize: 16, color: alpha("#fff", 0.6) }} />
        <Typography variant="body2" sx={{ color: alpha("#fff", 0.5), flex: 1, fontSize: "0.85rem" }}>
          Search resources, services, docs…
        </Typography>
        <Box sx={{ px: 0.75, py: 0.15, borderRadius: 0.5, bgcolor: alpha("#fff", 0.12), fontFamily: "monospace", fontSize: "0.65rem", color: alpha("#fff", 0.5), whiteSpace: "nowrap" }}>
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
          <Avatar sx={{ width: 30, height: 30, bgcolor: "#4285F4", fontSize: "0.8rem", cursor: "pointer", ml: 0.5 }}>
            D
          </Avatar>
        </Tooltip>
      </Box>
    </Box>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function SampleAzure() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [bladeExpanded, setBladeExpanded] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);

  // ⌘K shortcut
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") { e.preventDefault(); setPaletteOpen((v) => !v); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  const contentLeft = bladeExpanded ? BLADE_EXPANDED : BLADE_COLLAPSED;

  const activityColor = (type: string) => {
    if (type === "success") return "#66BB6A";
    if (type === "warning") return "#FFA726";
    if (type === "error")   return "#EF5350";
    return theme.palette.primary.main;
  };

  return (
    <Box sx={{ bgcolor: "background.default", minHeight: "100vh" }}>
      <TopBar onMenuClick={() => setBladeExpanded((v) => !v)} onSearchClick={() => setPaletteOpen(true)} />
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
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 0.5 }}>
          Good morning, Dheeraj
        </Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mb: 3 }}>
          Here's your security operations overview
        </Typography>

        {/* Security metrics row */}
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
                  border: `1px solid`,
                  borderColor: "divider",
                  borderTop: `3px solid ${m.color}`,
                  borderRadius: 1.5,
                  p: 1.5, cursor: "pointer",
                  transition: "box-shadow 0.15s",
                  "&:hover": { boxShadow: `0 4px 20px ${alpha(m.color, 0.2)}` },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                  <Icon sx={{ fontSize: 16, color: m.color }} />
                  <Typography variant="caption" sx={{ color: "text.secondary", fontSize: "0.72rem" }}>
                    {m.label}
                  </Typography>
                </Box>
                <Box sx={{ display: "flex", alignItems: "baseline", gap: 0.5 }}>
                  <Typography variant="h5" sx={{ fontWeight: 700, color: m.color, lineHeight: 1 }}>{m.value}</Typography>
                  <Typography variant="caption" sx={{ color: "text.disabled" }}>{m.unit}</Typography>
                </Box>
              </Box>
            );
          })}
        </Box>

        {/* Two-column layout: Recently visited + Activity */}
        <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap" }}>

          {/* Left column */}
          <Box sx={{ flex: "2 1 500px", minWidth: 280 }}>
            {/* Recently visited */}
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
                      border: `1px solid`,
                      borderColor: "divider",
                      borderRadius: 1.5,
                      p: 1.5, cursor: "pointer",
                      transition: "all 0.15s",
                      "&:hover": {
                        borderColor: r.color,
                        boxShadow: `0 2px 12px ${alpha(r.color, 0.15)}`,
                        transform: "translateY(-2px)",
                      },
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

            {/* Quick actions */}
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "text.secondary", fontSize: "0.78rem", letterSpacing: "0.06em" }}>
              QUICK ACTIONS
            </Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              {QUICK_ACTIONS.map((a) => {
                const { Icon } = a;
                return (
                  <Box
                    key={a.label}
                    onClick={() => navigate(a.path)}
                    sx={{
                      display: "flex", alignItems: "center", gap: 1,
                      px: 2, py: 1,
                      bgcolor: "background.paper",
                      border: `1px solid`,
                      borderColor: "divider",
                      borderRadius: 1.5,
                      cursor: "pointer",
                      transition: "all 0.15s",
                      "&:hover": { borderColor: a.color, bgcolor: alpha(a.color, 0.06) },
                    }}
                  >
                    <Icon sx={{ fontSize: 16, color: a.color }} />
                    <Typography variant="body2" sx={{ fontWeight: 500, fontSize: "0.82rem" }}>{a.label}</Typography>
                  </Box>
                );
              })}
            </Box>
          </Box>

          {/* Right column — Activity feed */}
          <Box sx={{ flex: "1 1 260px", minWidth: 240 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "text.secondary", fontSize: "0.78rem", letterSpacing: "0.06em" }}>
              RECENT ACTIVITY
            </Typography>
            <Box sx={{ bgcolor: "background.paper", border: `1px solid`, borderColor: "divider", borderRadius: 1.5, overflow: "hidden" }}>
              {ACTIVITY.map((a, idx) => (
                <Box
                  key={idx}
                  sx={{
                    display: "flex", alignItems: "flex-start", gap: 1.5,
                    px: 2, py: 1.25,
                    borderBottom: idx < ACTIVITY.length - 1 ? `1px solid` : "none",
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

            {/* All phases shortcut */}
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, mt: 3, color: "text.secondary", fontSize: "0.78rem", letterSpacing: "0.06em" }}>
              WORKFLOW PHASES
            </Typography>
            <Box sx={{ bgcolor: "background.paper", border: `1px solid`, borderColor: "divider", borderRadius: 1.5, overflow: "hidden" }}>
              {[
                { label: "1 · Setup",    color: "#42A5F5", path: "/connections" },
                { label: "2 · Design",   color: "#AB47BC", path: "/threat-models" },
                { label: "3 · Discover", color: "#26A69A", path: "/scans" },
                { label: "4 · Analyse",  color: "#FFA726", path: "/risk-overview" },
                { label: "5 · Respond",  color: "#EF5350", path: "/control-deficiencies" },
                { label: "6 · Report",   color: "#66BB6A", path: "/vapt/reports" },
                { label: "7 · Automate", color: "#5C6BC0", path: "/agents" },
                { label: "8 · Configure",color: "#78909C", path: "/settings" },
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

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </Box>
  );
}
