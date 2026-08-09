import React, { useState, useEffect } from "react";
import { Outlet, useNavigate, useLocation, Link } from "react-router-dom";
import {
  Box, Drawer, AppBar, Toolbar, Typography, List, ListItemButton,
  ListItemIcon, ListItemText, Divider, Avatar, Menu, MenuItem,
  IconButton, Chip, Tooltip, Collapse, ToggleButton, ToggleButtonGroup,
  Alert, Snackbar, Select, FormControl, Breadcrumbs,
} from "@mui/material";
import { NavigateNext } from "@mui/icons-material";
import {
  Dashboard, People, BugReport, Security, Policy,
  SmartToy, Assessment, Logout, AccountCircle,
  BarChart, Menu as MenuIcon, Storage, Insights, Apps,
  Schedule, AutoStories, MenuBook, Hub,
  ChevronLeft, ChevronRight, DarkMode, LightMode, Palette, Check, History,
  ExpandLess, ExpandMore, VisibilityOutlined, Engineering,
  Cable, Settings, Radar, GppBad, PlaylistAddCheck, LibraryAdd, GppGood,
  SyncAlt, AccountTree, Psychology, Description, AutoFixHigh,
  TrendingUp, GridView, CompareArrows, VpnKey, Webhook, Shield,
} from "@mui/icons-material";
import { useMsal } from "@azure/msal-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import NotificationBell from "./NotificationBell";
import AssistantWidget from "../AssistantWidget";
import { adminApi, clientsApi } from "../../services/api";
import { MyAccess, Client } from "../../types";
import { useActiveClient } from "../../contexts/ClientContext";
import { useThemeMode } from "../../theme/ThemeModeContext";
import { useViewMode } from "../../theme/ViewModeContext";
import GlobalSearch from "../GlobalSearch";

const DRAWER_WIDTH = 240;
const DRAWER_RAIL_WIDTH = 64;
const COLLAPSE_KEY = "nav-collapsed";

const SECTION_COLORS: Record<string, string> = {
  "Overview":      "#4285F4",
  "Foundation":    "#34A853",
  "Discover":      "#0f766e",
  "Analyse":       "#b45309",
  "Respond":       "#b91c1c",
  "Automate":      "#4338ca",
  "Scanning":      "#EA4335",
  "Threat & Risk": "#FF5722",
  "Compliance":    "#FF9800",
  "Automation":    "#9C27B0",
  "Intelligence":  "#00BCD4",
  "Governance":    "#FBBC04",
  "Configure":     "#607D8B",
};

type NavItem = { label: string; icon: React.ReactNode; path: string; adminOnly?: boolean; children?: NavItem[] };
type NavGroup = { section?: string; items: NavItem[] };

// Grouped navigation. Sections collapse into a small icon-rail when the
// sidebar is collapsed; when expanded the section label sits above each
// group. Order = importance to a security analyst's day.
const NAV_GROUPS: NavGroup[] = [
  {
    section: "Overview",
    items: [
      { label: "Dashboard", icon: <Dashboard />, path: "/dashboard" },
      { label: "Reports",   icon: <BarChart />,  path: "/reports" },
    ],
  },
  {
    section: "Foundation",
    items: [
      { label: "Accounts",    icon: <People />,  path: "/clients" },
      { label: "Connections", icon: <Cable />,   path: "/connections", children: [
        { label: "All Connections", icon: <Cable />,   path: "/connections" },
        { label: "Ticket Sync",     icon: <SyncAlt />, path: "/ticket-sync" },
      ] },
      { label: "Assets", icon: <Storage />, path: "/assets", children: [
        { label: "Asset Inventory", icon: <Storage />, path: "/assets" },
        { label: "Technologies",    icon: <Apps />,    path: "/assets/technologies" },
        { label: "Stale Assets",    icon: <History />, path: "/stale-assets" },
      ] },
      { label: "Frameworks",    icon: <Policy />,     path: "/frameworks" },
      { label: "Custom Policy", icon: <LibraryAdd />, path: "/custom-frameworks" },
    ],
  },
  {
    section: "Discover",
    items: [
      { label: "Discover",    icon: <BugReport />, path: "/discover" },
      { label: "Assessments", icon: <BugReport />, path: "/vulnerability/scans" },
      { label: "Findings",    icon: <Security />,  path: "/vulnerability/findings" },
      { label: "Assets",      icon: <Storage />,   path: "/platform/assets" },
      { label: "Posture Trends", icon: <TrendingUp />, path: "/vulnerability/posture" },
    ],
  },
  {
    section: "Analyse",
    items: [
      { label: "Analyse",        icon: <Insights />,   path: "/analyse" },
      { label: "Risk Register",  icon: <Assessment />, path: "/risk/register" },
      { label: "Risk Overview",  icon: <Insights />,   path: "/risk/overview" },
      { label: "Attack Paths",   icon: <AccountTree />, path: "/threat-intel/attack-paths" },
      { label: "Threat Models",  icon: <Hub />,        path: "/threat-intel/threat-models" },
      { label: "Ask Your Data",  icon: <Psychology />, path: "/intelligence/nl-query" },
    ],
  },
  {
    section: "Respond",
    items: [
      { label: "Respond",            icon: <Radar />,           path: "/respond" },
      { label: "Threat Register",    icon: <Radar />,           path: "/threat-intel/register" },
      { label: "Control Gaps",       icon: <GppBad />,          path: "/compliance/deficiencies" },
      { label: "Remediation",        icon: <PlaylistAddCheck />, path: "/governance/remediation" },
      { label: "CTEM Programs",      icon: <Radar />,           path: "/governance/ctem" },
      { label: "VAPT Reports",       icon: <GppGood />,         path: "/vapt/reports" },
    ],
  },
  {
    section: "Automate",
    items: [
      { label: "Automate",      icon: <SmartToy />,    path: "/automate" },
      { label: "AI Buddies",    icon: <SmartToy />,    path: "/ai-advisor/agents" },
      { label: "AI Workflows",  icon: <Schedule />,    path: "/ai-advisor/workflows" },
      { label: "Knowledge Base", icon: <AutoStories />, path: "/intelligence/knowledge" },
      { label: "API Keys",      icon: <VpnKey />,      path: "/api-keys" },
      { label: "Help",          icon: <MenuBook />,    path: "/help" },
    ],
  },
  {
    section: "Scanning",
    items: [
      { label: "Scans",        icon: <BugReport />, path: "/scans" },
      { label: "Findings",     icon: <Security />,  path: "/findings" },
      { label: "VAPT Reports", icon: <GppGood />,   path: "/vapt/reports" },
    ],
  },
  {
    section: "Threat & Risk",
    items: [
      { label: "Risk Overview",       icon: <Insights />,   path: "/risk-overview" },
      { label: "Threat Models",       icon: <Hub />,        path: "/threat-models" },
      { label: "Threat Intelligence", icon: <Radar />,      path: "/threat-register" },
      { label: "Risk Register",       icon: <Assessment />, path: "/risks" },
    ],
  },
  {
    section: "Compliance",
    items: [
      { label: "Compliance Gaps", icon: <GppBad />,          path: "/control-deficiencies" },
      { label: "Remediation",     icon: <PlaylistAddCheck />, path: "/governance/remediation" },
      { label: "AI Remediations", icon: <AutoFixHigh />,      path: "/governance/remediation-jobs" },
      { label: "CTEM Programs",   icon: <Radar />,            path: "/governance/ctem" },
    ],
  },
  {
    section: "Automation",
    items: [
      { label: "AI Buddies",     icon: <SmartToy />,    path: "/agents" },
      { label: "Workflows",      icon: <Schedule />,    path: "/missions" },
      { label: "Knowledge Base", icon: <AutoStories />, path: "/knowledge" },
    ],
  },
  {
    section: "Intelligence",
    items: [
      { label: "AI Assisted Scan",   icon: <SmartToy />,    path: "/ai-assisted-scan" },
      { label: "Attack Paths",       icon: <AccountTree />, path: "/attack-paths" },
      { label: "CVE Blast Radius",   icon: <BugReport />,   path: "/cve-pivot" },
      { label: "Ask Your Data",      icon: <Psychology />,  path: "/nl-query" },
      { label: "Security Docs",      icon: <Description />, path: "/security-docs" },
      { label: "Compliance Heatmap", icon: <GridView />,    path: "/compliance-heatmap" },
    ],
  },
  {
    section: "Governance",
    items: [
      { label: "Posture Trends",    icon: <TrendingUp />,    path: "/posture-trends" },
      { label: "Account Comparison", icon: <CompareArrows />, path: "/client-comparison" },
    ],
  },
  {
    // Bottom-pinned configure group — Settings, integrations, help
    section: "Configure",
    items: [
      { label: "Settings", icon: <Settings />, path: "/settings" },
      { label: "Webhooks",     icon: <Webhook />,  path: "/webhooks" },
      { label: "API Keys",     icon: <VpnKey />,   path: "/api-keys" },
      { label: "AI Guardrails", icon: <Shield />,   path: "/ai-guardrails" },
      { label: "Help",          icon: <MenuBook />, path: "/help" },
    ],
  },
];

// ── Breadcrumb ────────────────────────────────────────────────────────────────

// Build a flat path→{label, section} lookup from NAV_GROUPS
const PATH_META: Record<string, { label: string; section: string }> = {};
NAV_GROUPS.forEach((g) => {
  const section = g.section ?? "";
  g.items.forEach((item) => {
    PATH_META[item.path] = { label: item.label, section };
    (item.children || []).forEach((c) => {
      PATH_META[c.path] = { label: c.label, section };
    });
  });
});

function AppBreadcrumb() {
  const { pathname } = useLocation();

  // Try exact match first, then longest prefix match
  const meta = PATH_META[pathname] ?? (() => {
    const match = Object.keys(PATH_META)
      .filter((p) => p !== "/" && pathname.startsWith(p))
      .sort((a, b) => b.length - a.length)[0];
    return match ? PATH_META[match] : null;
  })();

  if (!meta) return null;

  return (
    <Box sx={{
      px: 3, py: 0.75,
      borderBottom: "1px solid",
      borderColor: "divider",
      bgcolor: "background.default",
    }}>
      <Breadcrumbs separator={<NavigateNext sx={{ fontSize: 14 }} />} sx={{ fontSize: 12 }}>
        <Link to="/" style={{ textDecoration: "none" }}>
          <Typography sx={{ fontSize: 12, color: "text.secondary", "&:hover": { color: "primary.main" }, cursor: "pointer" }}>
            Hub
          </Typography>
        </Link>
        <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
          {meta.section}
        </Typography>
        <Typography sx={{ fontSize: 12, color: "text.primary", fontWeight: 500 }}>
          {meta.label}
        </Typography>
      </Breadcrumbs>
    </Box>
  );
}

export default function AppLayout() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const { instance, accounts } = useMsal();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [themeAnchor, setThemeAnchor] = useState<null | HTMLElement>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const { mode, setMode, customPalette, setCustomPalette } = useThemeMode();
  const { mode: viewMode, setMode: setViewMode, readOnly, setReadOnly } = useViewMode();
  const { clientId, setClientId } = useActiveClient();
  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  // Default to collapsed (rail mode) — gives pages maximum width. User can
  // pin the expanded mode via the toggle, persisted in localStorage.
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    const v = typeof window !== "undefined" ? window.localStorage.getItem(COLLAPSE_KEY) : null;
    return v === null ? true : v === "1";
  });
  // When collapsed, hovering over the sidebar temporarily expands it so the
  // user can read labels without un-pinning.
  const [hovering, setHovering] = useState(false);
  const expanded = !collapsed || hovering;
  // Expand/collapse state for parent nav items with children (e.g. Assets).
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});

  // Active-route test. "/assets" must NOT light up for /assets/technologies
  // (that's its own leaf) but should for the asset-detail route /assets/:id.
  const isActive = (p: string) =>
    p === "/assets"
      ? pathname === "/assets" || /^\/assets\/(?!technologies)[^/]+$/.test(pathname)
      : pathname === p || pathname.startsWith(p + "/");

  // Show section mini-nav only when pathname EXACTLY matches a nav item —
  // detail pages (e.g. /clients/123) won't match any item exactly, so they
  // use their own PageDetailLayout sidebar instead.
  const activeSectionGroup = pathname === "/" ? null :
    NAV_GROUPS.find(g =>
      g.items.some(item =>
        pathname === item.path ||
        (item.children || []).some(c => pathname === c.path)
      )
    ) ?? null;
  const sectionColor = activeSectionGroup?.section
    ? SECTION_COLORS[activeSectionGroup.section] ?? "#4285F4"
    : "#4285F4";

  const renderLeaf = (item: NavItem, indented: boolean) => {
    const active = isActive(item.path);
    const button = (
      <ListItemButton
        key={item.path}
        onClick={() => navigate(item.path)}
        sx={{
          mx: 1, my: 0.3, borderRadius: 1, minHeight: 42,
          justifyContent: expanded ? "flex-start" : "center",
          px: expanded ? 1.5 : 1,
          pl: expanded && indented ? 4 : undefined,
          bgcolor: active ? "rgba(66,133,244,0.15)" : "transparent",
          "&:hover": { bgcolor: "action.hover" },
        }}
      >
        <ListItemIcon sx={{
          color: active ? "#4285F4" : "text.secondary",
          minWidth: expanded ? 36 : 0, justifyContent: "center",
        }}>
          {item.icon}
        </ListItemIcon>
        {expanded && (
          <ListItemText primary={item.label} slotProps={{ primary: { style: {
            fontSize: 13, fontWeight: active ? 600 : 400,
            color: active ? "#4285F4" : (mode === "light" ? "rgba(15,23,42,0.78)" : "rgba(255,255,255,0.8)"), whiteSpace: "nowrap",
          } } }} />
        )}
      </ListItemButton>
    );
    if (!expanded) {
      return <Tooltip key={item.path} title={item.label} placement="right">{button}</Tooltip>;
    }
    return button;
  };

  useEffect(() => {
    window.localStorage.setItem(COLLAPSE_KEY, collapsed ? "1" : "0");
  }, [collapsed]);

  const qc = useQueryClient();
  const { data: me } = useQuery<MyAccess>({
    queryKey: ["my-access"],
    queryFn: adminApi.me,
    retry: 0,
    staleTime: 60_000,
  });

  const [bootstrapSnack, setBootstrapSnack] = useState("");
  const bootstrapMutation = useMutation({
    mutationFn: adminApi.bootstrapAdmin,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["my-access"] });
      setBootstrapSnack("You are now a global admin. Welcome to Owlet!");
    },
    onError: () => setBootstrapSnack("An admin already exists — contact them for access."),
  });

  // RBAC binding: a user with no editor/admin grant anywhere is read-only,
  // so lock them to Executive mode (the backend enforces this on writes too).
  // When there are zero grants in the system (fresh install), auto-trigger
  // the bootstrap so the first user self-elevates to admin.
  useEffect(() => {
    if (me) {
      setReadOnly(!me.is_editor_anywhere);
      if (!me.is_editor_anywhere && me.grants.length === 0) {
        bootstrapMutation.mutate();
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me?.is_editor_anywhere]);

  const account = accounts[0];
  const userName = account?.name || account?.username || "User";
  const userInitial = userName.charAt(0).toUpperCase();

  const handleLogout = () => {
    instance.logoutRedirect({ postLogoutRedirectUri: "/" });
  };

  const drawer = (
    <Box
      sx={{
        height: "100%",
        bgcolor: "background.paper",
        color: "text.primary",
        overflowX: "hidden",
      }}
      onMouseEnter={() => collapsed && setHovering(true)}
      onMouseLeave={() => setHovering(false)}
    >
      {/* Brand + collapse toggle */}
      <Box sx={{
        p: expanded ? 2 : 1, display: "flex", alignItems: "center",
        gap: 1, justifyContent: expanded ? "space-between" : "center",
        borderBottom: "1px solid", borderColor: "divider", minHeight: 64,
      }}>
        <Box sx={{ display: "flex", alignItems: "center", overflow: "hidden" }}>
          {expanded ? (
            <Box
              component="img"
              src={"/aegis-logo.svg"}
              alt="Owlet AI"
              sx={{ height: 42, width: "auto", maxWidth: 190, flexShrink: 0 }}
            />
          ) : (
            <Box
              component="img"
              src={"/aegis-icon.svg"}
              alt="Owlet AI"
              sx={{ width: 36, height: 36, flexShrink: 0 }}
            />
          )}
        </Box>
        {expanded && (
          <Tooltip title={collapsed ? "Pin expanded" : "Collapse to icons"}>
            <IconButton
              size="small"
              onClick={() => setCollapsed((c) => !c)}
              sx={{ color: "text.secondary" }}
            >
              {collapsed ? <ChevronRight fontSize="small" /> : <ChevronLeft fontSize="small" />}
            </IconButton>
          </Tooltip>
        )}
      </Box>

      {/* When collapsed and not hovering, show a tiny expand-rail button just
          below the brand so the user has an obvious way to pin-open. */}
      {!expanded && (
        <Box sx={{ display: "flex", justifyContent: "center", py: 0.5 }}>
          <Tooltip title="Expand navigation" placement="right">
            <IconButton size="small" onClick={() => setCollapsed(false)} sx={{ color: "text.secondary" }}>
              <ChevronRight fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      )}

      <List sx={{ pt: 0.5 }}>
        {NAV_GROUPS.map((group, gi) => {
          const items = group.items.filter((i) => !i.adminOnly || me?.is_admin || me?.is_admin_anywhere);
          if (items.length === 0) return null;
          return (
            <React.Fragment key={gi}>
              {group.section && expanded && (
                <Typography
                  variant="caption"
                  sx={{
                    display: "block", color: "text.secondary", fontSize: 10,
                    fontWeight: 700, letterSpacing: 1, mt: gi === 0 ? 1 : 1.5, mb: 0.5, mx: 2.5,
                    textTransform: "uppercase",
                  }}
                >
                  {group.section}
                </Typography>
              )}
              {/* Group divider rail when collapsed — keeps visual grouping
                  even without section labels. Skip for first group. */}
              {!expanded && gi > 0 && (
                <Divider sx={{ mx: 1.5, my: 0.75, borderColor: "divider" }} />
              )}
              {items.map((item) => {
                if (item.children) {
                  // Collapsed rail: flatten children to individual icons so
                  // every destination stays one click away.
                  if (!expanded) {
                    return (
                      <React.Fragment key={item.path}>
                        {item.children.map((c) => renderLeaf(c, false))}
                      </React.Fragment>
                    );
                  }
                  const childActive = item.children.some((c) => isActive(c.path));
                  const open = openGroups[item.path] ?? childActive;
                  return (
                    <React.Fragment key={item.path}>
                      <ListItemButton
                        onClick={() => setOpenGroups((s) => ({ ...s, [item.path]: !(s[item.path] ?? childActive) }))}
                        sx={{
                          mx: 1, my: 0.3, borderRadius: 1, minHeight: 42, px: 1.5,
                          bgcolor: childActive ? "rgba(66,133,244,0.08)" : "transparent",
                          "&:hover": { bgcolor: "action.hover" },
                        }}
                      >
                        <ListItemIcon sx={{
                          color: childActive ? "#4285F4" : "text.secondary",
                          minWidth: 36, justifyContent: "center",
                        }}>
                          {item.icon}
                        </ListItemIcon>
                        <ListItemText primary={item.label} slotProps={{ primary: { style: {
                          fontSize: 13, fontWeight: childActive ? 600 : 500,
                          color: childActive ? "#4285F4" : (mode === "light" ? "rgba(15,23,42,0.78)" : "rgba(255,255,255,0.8)"), whiteSpace: "nowrap",
                        } } }} />
                        {open ? <ExpandLess sx={{ color: "text.secondary" }} />
                              : <ExpandMore sx={{ color: "text.secondary" }} />}
                      </ListItemButton>
                      <Collapse in={open} timeout="auto" unmountOnExit>
                        {item.children.map((c) => renderLeaf(c, true))}
                      </Collapse>
                    </React.Fragment>
                  );
                }
                return renderLeaf(item, false);
              })}
            </React.Fragment>
          );
        })}
      </List>
    </Box>
  );

  const effectiveWidth = collapsed ? DRAWER_RAIL_WIDTH : DRAWER_WIDTH;

  return (
    <Box sx={{ display: "flex", minHeight: "100vh", bgcolor: "background.default" }}>
      {/* Sidebar */}
      <Box component="nav" sx={{ width: { md: effectiveWidth }, flexShrink: 0, transition: "width 200ms ease" }}>
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={() => setMobileOpen(false)}
          ModalProps={{ keepMounted: true }}
          sx={{ display: { xs: "block", md: "none" }, "& .MuiDrawer-paper": { width: DRAWER_WIDTH, border: "none" } }}
        >
          {drawer}
        </Drawer>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: "none", md: "block" },
            "& .MuiDrawer-paper": {
              width: hovering ? DRAWER_WIDTH : effectiveWidth,
              border: "none",
              overflowX: "hidden",
              transition: "width 200ms ease",
              boxShadow: hovering ? "6px 0 24px rgba(0,0,0,0.45)" : "none",
            },
          }}
          open
        >
          {drawer}
        </Drawer>
      </Box>

      {/* Main content */}
      <Box sx={{ flexGrow: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        <AppBar
          position="sticky"
          elevation={0}
          sx={{
            bgcolor: "background.paper",
            color: "text.primary",
            borderBottom: "1px solid",
            borderColor: "divider",
          }}
        >
          <Toolbar>
            <IconButton color="inherit" onClick={() => setMobileOpen(true)} sx={{ mr: 1, display: { md: "none" } }}>
              <MenuIcon />
            </IconButton>
            <Tooltip title={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
              <IconButton
                color="inherit"
                onClick={() => setCollapsed((c) => !c)}
                sx={{ mr: 1, display: { xs: "none", md: "inline-flex" } }}
              >
                <MenuIcon />
              </IconButton>
            </Tooltip>
            <GlobalSearch />
            {/* Global client selector */}
            {clients.length > 0 && (
              <FormControl size="small" sx={{ mr: 2, minWidth: 160 }}>
                <Select
                  displayEmpty
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                  sx={{
                    fontSize: 12, height: 30,
                    color: clientId ? "text.primary" : "text.secondary",
                    "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" },
                    "& .MuiSelect-select": { py: 0.5, px: 1.5 },
                  }}
                  renderValue={(v) => {
                    if (!v) return <span style={{ color: "#888", fontSize: 12 }}>Select account…</span>;
                    const c = (clients as Client[]).find((x) => x.id === v);
                    return <span style={{ fontSize: 12 }}>{c?.name ?? v}</span>;
                  }}
                >
                  <MenuItem value="" sx={{ fontSize: 12, color: "text.secondary" }}>All accounts</MenuItem>
                  {(clients as Client[]).map((c) => (
                    <MenuItem key={c.id} value={c.id} sx={{ fontSize: 12 }}>{c.name}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            )}
            <Tooltip title={readOnly
              ? "Your access is read-only (reader role) — ask an admin for editor access to run jobs."
              : viewMode === "executive"
                ? "Executive — read-only: dashboards & reports. Switch to Analyst to run jobs."
                : "Analyst — full access: initiate scans, agents, threat models, syncs."}>
              <ToggleButtonGroup
                size="small" exclusive value={readOnly ? "executive" : viewMode}
                onChange={(_, v) => { if (v && !readOnly) setViewMode(v); }}
                sx={{
                  mr: 2,
                  "& .MuiToggleButton-root": {
                    textTransform: "none", py: 0.3, px: 1, fontSize: 12,
                    color: "text.secondary", borderColor: "divider",
                  },
                  "& .Mui-selected": { color: "#4285F4 !important", bgcolor: "rgba(66,133,244,0.12) !important" },
                }}
              >
                <ToggleButton value="executive"><VisibilityOutlined sx={{ fontSize: 15, mr: 0.5 }} />Executive</ToggleButton>
                <ToggleButton value="analyst" disabled={readOnly}><Engineering sx={{ fontSize: 16, mr: 0.5 }} />Analyst</ToggleButton>
              </ToggleButtonGroup>
            </Tooltip>
            <Typography
              sx={{
                fontFamily: '"Inter", sans-serif',
                fontSize: 16,
                fontWeight: 700,
                letterSpacing: "-0.02em",
                mr: 2,
                display: { xs: "none", sm: "block" },
              }}
            >
              <Box component="span" sx={{ color: "#4285F4" }}>Owlet</Box>
              <Box component="span" sx={{ color: "text.primary" }}> AI</Box>
            </Typography>
            <Chip
              label="LIVE"
              size="small"
              sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", mr: 2, fontSize: 10, height: 20, fontWeight: 700 }}
            />
            <NotificationBell />
            <Tooltip title="Theme">
              <IconButton onClick={(e) => setThemeAnchor(e.currentTarget)} sx={{ color: "text.secondary" }}>
                {mode === "light" ? <LightMode /> : mode === "custom" ? <Palette /> : <DarkMode />}
              </IconButton>
            </Tooltip>
            <Menu
              anchorEl={themeAnchor}
              open={Boolean(themeAnchor)}
              onClose={() => setThemeAnchor(null)}
              slotProps={{ paper: { sx: { minWidth: 220 } } }}
            >
              <MenuItem onClick={() => { setMode("dark"); setThemeAnchor(null); }}>
                <DarkMode fontSize="small" sx={{ mr: 1.25, color: "#4285F4" }} />
                Dark
                {mode === "dark" && <Check fontSize="small" sx={{ ml: "auto", color: "#34A853" }} />}
              </MenuItem>
              <MenuItem onClick={() => { setMode("light"); setThemeAnchor(null); }}>
                <LightMode fontSize="small" sx={{ mr: 1.25, color: "#F9AB00" }} />
                Light
                {mode === "light" && <Check fontSize="small" sx={{ ml: "auto", color: "#34A853" }} />}
              </MenuItem>
              <MenuItem onClick={() => { setMode("custom"); setThemeAnchor(null); }}>
                <Palette fontSize="small" sx={{ mr: 1.25, color: "#9C27B0" }} />
                Custom…
                {mode === "custom" && <Check fontSize="small" sx={{ ml: "auto", color: "#34A853" }} />}
              </MenuItem>
              {mode === "custom" && (
                <Box sx={{ px: 2, py: 1, borderTop: "1px solid", borderColor: "divider" }}>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 1, display: "block", mb: 0.5 }}>
                    PRIMARY ACCENT
                  </Typography>
                  <Box sx={{ display: "flex", gap: 0.5, mb: 1 }}>
                    {["#4285F4", "#34A853", "#EA4335", "#FBBC04", "#9C27B0", "#00B8D4"].map((c) => (
                      <Box
                        key={c}
                        onClick={() => setCustomPalette({ ...customPalette, primary: c })}
                        sx={{
                          width: 24, height: 24, borderRadius: "50%", bgcolor: c, cursor: "pointer",
                          border: customPalette.primary === c ? "2px solid white" : "2px solid transparent",
                        }}
                      />
                    ))}
                  </Box>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 1, display: "block", mb: 0.5 }}>
                    BACKGROUND
                  </Typography>
                  <Box sx={{ display: "flex", gap: 0.5 }}>
                    {[
                      { bg: "#0B1220", paper: "#141B2B", label: "Navy" },
                      { bg: "#000000", paper: "#121212", label: "Midnight" },
                      { bg: "#0F1A14", paper: "#142319", label: "Forest" },
                      { bg: "#1A0F1A", paper: "#231423", label: "Plum" },
                    ].map((b) => (
                      <Tooltip key={b.bg} title={b.label}>
                        <Box
                          onClick={() => setCustomPalette({ ...customPalette, background: b.bg, paper: b.paper })}
                          sx={{
                            width: 24, height: 24, borderRadius: 1, bgcolor: b.bg, cursor: "pointer",
                            border: customPalette.background === b.bg ? "2px solid white" : "2px solid rgba(255,255,255,0.15)",
                          }}
                        />
                      </Tooltip>
                    ))}
                  </Box>
                </Box>
              )}
            </Menu>
            <Tooltip title="Account">
              <IconButton onClick={(e) => setAnchorEl(e.currentTarget)}>
                <Avatar sx={{ bgcolor: "#4285F4", color: "#000", width: 32, height: 32, fontSize: 14, fontWeight: 700 }}>
                  {userInitial}
                </Avatar>
              </IconButton>
            </Tooltip>
            <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={() => setAnchorEl(null)}>
              <MenuItem disabled>
                <AccountCircle sx={{ mr: 1 }} /> {userName}
              </MenuItem>
              <Divider />
              <MenuItem onClick={() => { setAnchorEl(null); navigate("/account"); }}>
                <AccountCircle sx={{ mr: 1 }} fontSize="small" /> Account &amp; preferences
              </MenuItem>
              <Divider />
              <MenuItem onClick={handleLogout}>
                <Logout sx={{ mr: 1 }} fontSize="small" /> Logout
              </MenuItem>
            </Menu>
          </Toolbar>
        </AppBar>
        <AppBreadcrumb />
        {/* Section mini-nav + page content */}
        <Box component="main" sx={{ flexGrow: 1, display: "flex", overflow: "hidden" }}>
          {/* Context-aware section mini-nav — only on exact-match routes */}
          {activeSectionGroup && (
            <Box sx={{
              width: 178, flexShrink: 0,
              bgcolor: mode !== "light" ? "#0F1825" : "#F0F4FA",
              borderRight: "1px solid", borderColor: "divider",
              display: "flex", flexDirection: "column",
              overflowY: "auto",
            }}>
              {/* Section label */}
              <Box sx={{ px: 2, py: 1.5, borderBottom: "1px solid", borderColor: "divider" }}>
                <Box sx={{
                  display: "inline-flex", alignItems: "center", gap: 0.75,
                  px: 1.25, py: 0.5, borderRadius: 1,
                  bgcolor: `${sectionColor}22`,
                }}>
                  <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: sectionColor }} />
                  <Typography sx={{
                    fontSize: 9.5, fontWeight: 700, letterSpacing: 0.8,
                    textTransform: "uppercase", color: sectionColor, lineHeight: 1,
                  }}>
                    {activeSectionGroup.section}
                  </Typography>
                </Box>
              </Box>
              {/* Items */}
              <Box sx={{ pt: 0.5, pb: 2 }}>
                {activeSectionGroup.items
                  .filter(item => !item.adminOnly || me?.is_admin || me?.is_admin_anywhere)
                  .map(item => {
                    const active = isActive(item.path);
                    return (
                      <Box
                        key={item.path}
                        onClick={() => navigate(item.path)}
                        sx={{
                          display: "flex", alignItems: "center", gap: 1.25,
                          px: 1.5, py: 1, cursor: "pointer",
                          borderLeft: "3px solid",
                          borderColor: active ? sectionColor : "transparent",
                          bgcolor: active ? `${sectionColor}12` : "transparent",
                          "&:hover": {
                            bgcolor: active ? `${sectionColor}12`
                              : mode !== "light" ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.04)",
                          },
                          transition: "all .12s ease",
                        }}
                      >
                        <Box sx={{
                          width: 26, height: 26, borderRadius: 1.25,
                          bgcolor: `${sectionColor}22`,
                          display: "flex", alignItems: "center", justifyContent: "center",
                          flexShrink: 0,
                          color: sectionColor,
                          "& svg": { fontSize: "14px !important" },
                        }}>
                          {item.icon}
                        </Box>
                        <Typography sx={{
                          fontSize: 12.5,
                          color: active ? "text.primary" : "text.secondary",
                          fontWeight: active ? 600 : 400,
                          lineHeight: 1.3, flex: 1,
                          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                        }}>
                          {item.label}
                        </Typography>
                      </Box>
                    );
                  })}
              </Box>
            </Box>
          )}
          {/* Page content */}
          <Box sx={{ flex: 1, overflow: "auto", p: 3, minWidth: 0 }}>
            <Outlet />
          </Box>
        </Box>
      </Box>
      <Snackbar open={!!bootstrapSnack} autoHideDuration={6000} onClose={() => setBootstrapSnack("")}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}>
        <Alert severity="success" onClose={() => setBootstrapSnack("")}>{bootstrapSnack}</Alert>
      </Snackbar>
      <AssistantWidget />
    </Box>
  );
}
