/**
 * OwletLayout — Azure-Portal-style shell for the Owlet build.
 * Selected at build time via REACT_APP_THEME=owlet.
 * Wraps all existing routes with a fixed TopBar + collapsible LeftBlade.
 */
import React, { useState, useEffect, useRef, useMemo } from "react";
import { Outlet, useNavigate, useLocation } from "react-router-dom";
import {
  Box, Typography, IconButton, Chip, Avatar,
  Tooltip, alpha, Badge, Dialog, DialogContent,
  List, ListItemButton, ListItemIcon, ListItemText,
  InputAdornment, TextField, Divider, Select, FormControl,
  MenuItem,
} from "@mui/material";
import {
  Menu as MenuIcon, Search, Notifications, Settings,
  Dashboard, Security, BugReport, Insights, Hub, Cable,
  Radar, GppGood, SmartToy, Policy, Storage,
  AutoStories, Psychology, Description, Assessment, GppBad,
  PlaylistAddCheck, TrendingUp, Engineering, GridView,
  People, LibraryAdd, AccountTree, Schedule, ChevronRight,
  ExpandMore, ExpandLess,
} from "@mui/icons-material";
import { useTheme } from "@mui/material/styles";
import { useMsal } from "@azure/msal-react";
import { useQuery } from "@tanstack/react-query";
import { clientsApi } from "../../services/api";
import { Client } from "../../types";
import { useActiveClient } from "../../contexts/ClientContext";
import AssistantWidget from "../AssistantWidget";
import NotificationBell from "./NotificationBell";

// ── Layout constants ─────────────────────────────────────────────────────────

const BLADE_COLLAPSED = 52;
const BLADE_EXPANDED  = 240;
const TOPBAR_HEIGHT   = 52;

// ── Nav definitions ──────────────────────────────────────────────────────────

interface NavItem { id: string; label: string; Icon: React.ElementType; path: string; section?: string; pinned?: boolean }

const NAV_ITEMS: NavItem[] = [
  { id: "dashboard",    label: "Dashboard",           Icon: Dashboard,        path: "/dashboard",             pinned: true },
  { id: "findings",     label: "Findings",            Icon: Security,         path: "/findings",              pinned: true },
  { id: "scans",        label: "Scans",               Icon: BugReport,        path: "/scans",                 pinned: true },
  { id: "risk",         label: "Risk Overview",       Icon: Insights,         path: "/risk-overview",         pinned: true },
  // Setup
  { id: "clients",      label: "Clients",             Icon: People,           path: "/clients",               section: "1 · Setup" },
  { id: "connections",  label: "Connections",         Icon: Cable,            path: "/connections",           section: "1 · Setup" },
  // Design
  { id: "threat-models",label: "Threat Models",       Icon: Hub,              path: "/threat-models",         section: "2 · Design" },
  { id: "frameworks",   label: "Frameworks",          Icon: Policy,           path: "/frameworks",            section: "2 · Design" },
  { id: "custom-policy",label: "Custom Policy",       Icon: LibraryAdd,       path: "/custom-frameworks",     section: "2 · Design" },
  // Discover
  { id: "ai-scan",      label: "AI Assisted Scan",    Icon: SmartToy,         path: "/ai-assisted-scan",      section: "3 · Discover" },
  { id: "assets",       label: "Assets",              Icon: Storage,          path: "/assets",                section: "3 · Discover" },
  // Analyse
  { id: "risk-register",label: "Risk Register",       Icon: Assessment,       path: "/risks",                 section: "4 · Analyse" },
  { id: "attack-paths", label: "Attack Paths",        Icon: AccountTree,      path: "/attack-paths",          section: "4 · Analyse" },
  { id: "cve-pivot",    label: "CVE Blast Radius",    Icon: BugReport,        path: "/cve-pivot",             section: "4 · Analyse" },
  { id: "heatmap",      label: "Compliance Heatmap",  Icon: GridView,         path: "/compliance-heatmap",    section: "4 · Analyse" },
  // Respond
  { id: "threat-intel", label: "Threat Intelligence", Icon: Radar,            path: "/threat-register",       section: "5 · Respond" },
  { id: "control-gaps", label: "Control Gaps",        Icon: GppBad,           path: "/control-deficiencies",  section: "5 · Respond" },
  { id: "remediation",  label: "Remediation",         Icon: PlaylistAddCheck, path: "/governance/remediation",section: "5 · Respond" },
  { id: "ctem",         label: "CTEM Programs",       Icon: Engineering,      path: "/governance/ctem",       section: "5 · Respond" },
  // Report
  { id: "vapt",         label: "VAPT Reports",        Icon: GppGood,          path: "/vapt/reports",          section: "6 · Report" },
  { id: "posture",      label: "Posture Trends",      Icon: TrendingUp,       path: "/posture-trends",        section: "6 · Report" },
  // Automate
  { id: "agents",       label: "AI Buddies",          Icon: SmartToy,         path: "/agents",                section: "7 · Automate" },
  { id: "workflows",    label: "Workflows",           Icon: Schedule,         path: "/missions",              section: "7 · Automate" },
  { id: "knowledge",    label: "Knowledge Base",      Icon: AutoStories,      path: "/knowledge",             section: "7 · Automate" },
  { id: "security-docs",label: "Security Docs",       Icon: Description,      path: "/security-docs",         section: "7 · Automate" },
  { id: "nl-query",     label: "Ask Your Data",       Icon: Psychology,       path: "/nl-query",              section: "7 · Automate" },
  // Configure
  { id: "settings",     label: "Settings",            Icon: Settings,         path: "/settings",              section: "8 · Configure" },
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
    if (!query.trim()) return NAV_ITEMS.slice(0, 12);
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

        {!query.trim() && (
          <Typography variant="caption" sx={{
            display: "block", px: 2, py: 0.75,
            color: "text.disabled", fontWeight: 700, letterSpacing: "0.08em", fontSize: "0.68rem",
            bgcolor: alpha(theme.palette.background.default, 0.6),
            borderBottom: `1px solid ${alpha(theme.palette.divider, 0.3)}`,
          }}>
            ALL SERVICES
          </Typography>
        )}

        <Box sx={{ maxHeight: 420, overflow: "auto" }}>
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

function LeftBlade({ expanded }: { expanded: boolean }) {
  const theme = useTheme();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const isDark = theme.palette.mode === "dark";
  const bladeBg = isDark ? "#141824" : "#1e3a5f";
  const hoverBg = alpha("#fff", 0.08);
  const activeBg = alpha("#fff", 0.14);

  const pinned  = NAV_ITEMS.filter((n) => n.pinned);
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({});

  const sections = useMemo(() => {
    const map = new Map<string, NavItem[]>();
    NAV_ITEMS.filter((n) => !n.pinned).forEach((n) => {
      const sec = n.section ?? "Other";
      if (!map.has(sec)) map.set(sec, []);
      map.get(sec)!.push(n);
    });
    return map;
  }, []);

  const isActive = (path: string) => pathname === path || pathname.startsWith(path + "/");

  const navItem = (nav: NavItem) => {
    const { Icon } = nav;
    const active = isActive(nav.path);
    return (
      <Tooltip key={nav.id} title={expanded ? "" : nav.label} placement="right" arrow>
        <Box
          onClick={() => navigate(nav.path)}
          sx={{
            display: "flex", alignItems: "center",
            gap: expanded ? 1.5 : 0,
            px: expanded ? 1.5 : 0,
            justifyContent: expanded ? "flex-start" : "center",
            height: 38, cursor: "pointer", borderRadius: 1,
            mx: 0.5, mb: 0.15,
            bgcolor: active ? activeBg : "transparent",
            borderLeft: active ? `3px solid #4285F4` : "3px solid transparent",
            transition: "background 0.12s",
            "&:hover": { bgcolor: active ? activeBg : hoverBg },
          }}
        >
          <Icon sx={{ fontSize: 17, color: active ? "#fff" : alpha("#fff", 0.65), flexShrink: 0 }} />
          {expanded && (
            <Typography variant="body2" sx={{
              color: active ? "#fff" : alpha("#fff", 0.8),
              fontSize: "0.82rem", whiteSpace: "nowrap",
              overflow: "hidden", textOverflow: "ellipsis",
              fontWeight: active ? 600 : 400,
            }}>
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
      boxShadow: "2px 0 12px rgba(0,0,0,0.25)",
    }}>
      {/* Pinned */}
      <Box sx={{ pt: 1, pb: 0.5 }}>
        {expanded && (
          <Typography variant="caption" sx={{
            display: "block", px: 1.5, pb: 0.5,
            color: alpha("#fff", 0.38), fontWeight: 700,
            letterSpacing: "0.08em", fontSize: "0.63rem",
          }}>
            FAVOURITES
          </Typography>
        )}
        {pinned.map(navItem)}
      </Box>

      <Divider sx={{ borderColor: alpha("#fff", 0.1), mx: 0.75 }} />

      {/* All services — collapsible sections */}
      <Box sx={{
        flex: 1, overflowY: "auto", overflowX: "hidden", pt: 0.75, pb: 2,
        "&::-webkit-scrollbar": { width: 3 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha("#fff", 0.15), borderRadius: 2 },
      }}>
        {expanded && (
          <Typography variant="caption" sx={{
            display: "block", px: 1.5, pb: 0.5,
            color: alpha("#fff", 0.38), fontWeight: 700,
            letterSpacing: "0.08em", fontSize: "0.63rem",
          }}>
            ALL SERVICES
          </Typography>
        )}

        {Array.from(sections.entries()).map(([section, items]) => {
          const sectionOpen = openSections[section] !== false; // default open
          const hasActive = items.some((n) => isActive(n.path));

          return (
            <Box key={section}>
              {expanded ? (
                <Box
                  onClick={() => setOpenSections((s) => ({ ...s, [section]: !sectionOpen }))}
                  sx={{
                    display: "flex", alignItems: "center", justifyContent: "space-between",
                    px: 1.5, py: 0.6, cursor: "pointer",
                    "&:hover": { bgcolor: hoverBg },
                  }}
                >
                  <Typography variant="caption" sx={{
                    color: hasActive ? alpha("#fff", 0.75) : alpha("#fff", 0.4),
                    fontSize: "0.7rem", fontWeight: hasActive ? 700 : 500,
                    letterSpacing: "0.04em",
                  }}>
                    {section}
                  </Typography>
                  {sectionOpen
                    ? <ExpandLess sx={{ fontSize: 13, color: alpha("#fff", 0.3) }} />
                    : <ExpandMore  sx={{ fontSize: 13, color: alpha("#fff", 0.3) }} />
                  }
                </Box>
              ) : (
                <Divider sx={{ borderColor: alpha("#fff", 0.06), mx: 0.5, my: 0.5 }} />
              )}
              {(sectionOpen || !expanded) && items.map(navItem)}
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}

// ── Top bar ──────────────────────────────────────────────────────────────────

function TopBar({
  onMenuClick,
  onSearchClick,
}: {
  onMenuClick: () => void;
  onSearchClick: () => void;
}) {
  const theme = useTheme();
  const navigate = useNavigate();
  const { instance, accounts } = useMsal();
  const { clientId, setClientId } = useActiveClient();
  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const isDark = theme.palette.mode === "dark";
  const barBg = isDark ? "#0d1117" : "#003087";
  const displayName = accounts[0]?.name?.split(" ")[0] ?? "User";
  const initials = (accounts[0]?.name ?? "U").split(" ").map((p) => p[0]).join("").slice(0, 2).toUpperCase();

  return (
    <Box sx={{
      position: "fixed", top: 0, left: 0, right: 0, height: TOPBAR_HEIGHT,
      bgcolor: barBg, zIndex: 1200,
      display: "flex", alignItems: "center", px: 1, gap: 1,
      boxShadow: "0 1px 6px rgba(0,0,0,0.4)",
    }}>
      {/* Hamburger */}
      <IconButton onClick={onMenuClick} size="small" sx={{ color: alpha("#fff", 0.8), "&:hover": { color: "#fff", bgcolor: alpha("#fff", 0.08) } }}>
        <MenuIcon fontSize="small" />
      </IconButton>

      {/* Logo */}
      <Box
        onClick={() => navigate("/dashboard")}
        sx={{ display: "flex", alignItems: "center", gap: 1, mr: 2, cursor: "pointer", flexShrink: 0 }}
      >
        <Box sx={{ width: 26, height: 26, borderRadius: "6px", bgcolor: "#4285F4", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Typography sx={{ color: "#fff", fontSize: "0.75rem", fontWeight: 800 }}>O</Typography>
        </Box>
        <Typography sx={{ color: "#fff", fontWeight: 700, fontSize: "0.95rem", letterSpacing: "-0.02em", display: { xs: "none", sm: "block" } }}>
          Owlet
        </Typography>
      </Box>

      {/* Central search */}
      <Box
        onClick={onSearchClick}
        sx={{
          flex: 1, maxWidth: 560, mx: "auto",
          display: "flex", alignItems: "center", gap: 1,
          bgcolor: alpha("#fff", 0.1),
          border: `1px solid ${alpha("#fff", 0.15)}`,
          borderRadius: 1, px: 1.5, py: 0.55,
          cursor: "text", transition: "all 0.15s",
          "&:hover": { bgcolor: alpha("#fff", 0.16), borderColor: alpha("#fff", 0.3) },
        }}
      >
        <Search sx={{ fontSize: 15, color: alpha("#fff", 0.55) }} />
        <Typography variant="body2" sx={{ color: alpha("#fff", 0.45), flex: 1, fontSize: "0.83rem" }}>
          Search resources, services, docs…
        </Typography>
        <Box sx={{ px: 0.75, py: 0.1, borderRadius: 0.5, bgcolor: alpha("#fff", 0.12), fontFamily: "monospace", fontSize: "0.62rem", color: alpha("#fff", 0.45), whiteSpace: "nowrap" }}>
          ⌘K
        </Box>
      </Box>

      {/* Client selector */}
      {clients.length > 0 && (
        <FormControl size="small" sx={{ minWidth: 130, flexShrink: 0, display: { xs: "none", md: "flex" } }}>
          <Select
            value={clientId ?? ""}
            onChange={(e) => setClientId(e.target.value)}
            displayEmpty
            sx={{
              color: alpha("#fff", 0.85),
              fontSize: "0.8rem",
              "& .MuiOutlinedInput-notchedOutline": { borderColor: alpha("#fff", 0.2) },
              "&:hover .MuiOutlinedInput-notchedOutline": { borderColor: alpha("#fff", 0.4) },
              "& .MuiSvgIcon-root": { color: alpha("#fff", 0.6) },
              height: 34,
            }}
          >
            <MenuItem value=""><em style={{ opacity: 0.5 }}>All Clients</em></MenuItem>
            {clients.map((c) => (
              <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>
            ))}
          </Select>
        </FormControl>
      )}

      {/* Utilities */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 0.25, ml: 0.5, flexShrink: 0 }}>
        <NotificationBell />
        <Tooltip title="Settings">
          <IconButton size="small" onClick={() => navigate("/settings")} sx={{ color: alpha("#fff", 0.7), "&:hover": { color: "#fff", bgcolor: alpha("#fff", 0.08) } }}>
            <Settings fontSize="small" />
          </IconButton>
        </Tooltip>
        <Tooltip title={displayName}>
          <Avatar sx={{ width: 28, height: 28, bgcolor: "#4285F4", fontSize: "0.72rem", cursor: "pointer", ml: 0.25, fontWeight: 700 }}>
            {initials}
          </Avatar>
        </Tooltip>
      </Box>
    </Box>
  );
}

// ── Shell ────────────────────────────────────────────────────────────────────

export default function OwletLayout() {
  const [bladeExpanded, setBladeExpanded] = useState(false);
  const [paletteOpen,   setPaletteOpen]   = useState(false);

  // ⌘K global shortcut
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
      <TopBar onMenuClick={() => setBladeExpanded((v) => !v)} onSearchClick={() => setPaletteOpen(true)} />
      <LeftBlade expanded={bladeExpanded} />

      {/* Page content */}
      <Box sx={{
        ml: `${contentLeft}px`,
        mt: `${TOPBAR_HEIGHT}px`,
        transition: "margin-left 0.2s ease",
        minHeight: `calc(100vh - ${TOPBAR_HEIGHT}px)`,
        overflow: "auto",
      }}>
        <Outlet />
      </Box>

      <AssistantWidget />
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </Box>
  );
}
