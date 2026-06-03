import React, { useState, useEffect } from "react";
import { Outlet, useNavigate, useLocation } from "react-router-dom";
import {
  Box, Drawer, AppBar, Toolbar, Typography, List, ListItemButton,
  ListItemIcon, ListItemText, Divider, Avatar, Menu, MenuItem,
  IconButton, Chip, Tooltip,
} from "@mui/material";
import {
  Dashboard, People, BugReport, Security, Policy,
  SmartToy, Assessment, Logout, AccountCircle, Shield,
  BarChart, SettingsSuggest, Menu as MenuIcon, Storage, Insights, Apps,
  AdminPanelSettings, Schedule, AutoStories, GppMaybe, MenuBook, Hub,
  ChevronLeft, ChevronRight, DarkMode, LightMode, Palette, Check,
} from "@mui/icons-material";
import { useMsal } from "@azure/msal-react";
import { useQuery } from "@tanstack/react-query";
import NotificationBell from "./NotificationBell";
import { adminApi } from "../../services/api";
import { MyAccess } from "../../types";
import { useThemeMode } from "../../theme/ThemeModeContext";

const DRAWER_WIDTH = 240;
const DRAWER_RAIL_WIDTH = 64;
const COLLAPSE_KEY = "nav-collapsed";

type NavItem = { label: string; icon: React.ReactNode; path: string; adminOnly?: boolean };
type NavGroup = { section?: string; items: NavItem[] };

// Grouped navigation. Sections collapse into a small icon-rail when the
// sidebar is collapsed; when expanded the section label sits above each
// group. Order = importance to a security analyst's day.
const NAV_GROUPS: NavGroup[] = [
  {
    section: "Overview",
    items: [
      { label: "Dashboard",      icon: <Dashboard />,  path: "/dashboard" },
      { label: "Risk Overview",  icon: <Insights />,   path: "/risk-overview" },
      { label: "Reports",        icon: <BarChart />,   path: "/reports" },
    ],
  },
  {
    section: "Foundation",
    items: [
      { label: "Clients",         icon: <People />,   path: "/clients" },
      { label: "Asset Inventory", icon: <Storage />,  path: "/assets" },
      { label: "Technologies",    icon: <Apps />,     path: "/assets/technologies" },
      { label: "Frameworks",      icon: <Policy />,   path: "/frameworks" },
    ],
  },
  {
    section: "Assessments",
    items: [
      { label: "Assessments",   icon: <BugReport />, path: "/scans" },
      { label: "Findings",      icon: <Security />,  path: "/findings" },
      { label: "Threat Models", icon: <Hub />,       path: "/threat-models" },
      { label: "Risk Register", icon: <Assessment />, path: "/risks" },
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
    section: "Settings",
    items: [
      { label: "AI Settings",    icon: <SettingsSuggest />,    path: "/ai-settings" },
      { label: "Sync",           icon: <GppMaybe />,           path: "/sync", adminOnly: true },
      { label: "Administration", icon: <AdminPanelSettings />, path: "/admin", adminOnly: true },
      { label: "Help",           icon: <MenuBook />,           path: "/help" },
    ],
  },
];

export default function AppLayout() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const { instance, accounts } = useMsal();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [themeAnchor, setThemeAnchor] = useState<null | HTMLElement>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const { mode, setMode, customPalette, setCustomPalette } = useThemeMode();
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

  useEffect(() => {
    window.localStorage.setItem(COLLAPSE_KEY, collapsed ? "1" : "0");
  }, [collapsed]);

  const { data: me } = useQuery<MyAccess>({
    queryKey: ["my-access"],
    queryFn: adminApi.me,
    retry: 0,
    staleTime: 60_000,
  });

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
        bgcolor: mode === "light" ? "#0F172A" : "background.paper",
        color: "white",
        overflowX: "hidden",
      }}
      onMouseEnter={() => collapsed && setHovering(true)}
      onMouseLeave={() => setHovering(false)}
    >
      {/* Brand + collapse toggle */}
      <Box sx={{
        p: expanded ? 2 : 1, display: "flex", alignItems: "center",
        gap: 1, justifyContent: expanded ? "space-between" : "center",
        borderBottom: "1px solid rgba(255,255,255,0.1)", minHeight: 64,
      }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, overflow: "hidden" }}>
          <Shield sx={{ color: "#4285F4", fontSize: 32, flexShrink: 0 }} />
          {expanded && (
            <Box sx={{ whiteSpace: "nowrap" }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#4285F4", lineHeight: 1.1, letterSpacing: "-0.01em" }}>
                Aegis<span style={{ color: "#FFFFFF" }}>&nbsp;AI</span>
              </Typography>
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.6)", fontSize: 10, letterSpacing: 1, textTransform: "uppercase" }}>
                AI Security Posture
              </Typography>
            </Box>
          )}
        </Box>
        {expanded && (
          <Tooltip title={collapsed ? "Pin expanded" : "Collapse to icons"}>
            <IconButton
              size="small"
              onClick={() => setCollapsed((c) => !c)}
              sx={{ color: "rgba(255,255,255,0.6)" }}
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
            <IconButton size="small" onClick={() => setCollapsed(false)} sx={{ color: "rgba(255,255,255,0.6)" }}>
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
                    display: "block", color: "rgba(255,255,255,0.4)", fontSize: 10,
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
                <Divider sx={{ mx: 1.5, my: 0.75, borderColor: "rgba(255,255,255,0.08)" }} />
              )}
              {items.map((item) => {
                const active = item.path === "/assets"
                  ? pathname === "/assets" || /^\/assets\/[^/]+$/.test(pathname)
                  : pathname.startsWith(item.path);
                const button = (
                  <ListItemButton
                    key={item.path}
                    onClick={() => navigate(item.path)}
                    sx={{
                      mx: 1, my: 0.3, borderRadius: 1,
                      minHeight: 42,
                      justifyContent: expanded ? "flex-start" : "center",
                      px: expanded ? 1.5 : 1,
                      bgcolor: active ? "rgba(66,133,244,0.15)" : "transparent",
                      "&:hover": { bgcolor: "rgba(255,255,255,0.08)" },
                    }}
                  >
                    <ListItemIcon sx={{
                      color: active ? "#4285F4" : "rgba(255,255,255,0.6)",
                      minWidth: expanded ? 36 : 0,
                      justifyContent: "center",
                    }}>
                      {item.icon}
                    </ListItemIcon>
                    {expanded && (
                      <ListItemText
                        primary={item.label}
                        slotProps={{
                          primary: {
                            style: {
                              fontSize: 13,
                              fontWeight: active ? 600 : 400,
                              color: active ? "#4285F4" : "rgba(255,255,255,0.8)",
                              whiteSpace: "nowrap",
                            },
                          },
                        }}
                      />
                    )}
                  </ListItemButton>
                );
                // Tooltip only when collapsed-and-not-hovering — otherwise
                // labels are visible and tooltips would just add noise.
                if (!expanded) {
                  return (
                    <Tooltip key={item.path} title={item.label} placement="right">
                      {button}
                    </Tooltip>
                  );
                }
                return button;
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
            <Box sx={{ flexGrow: 1 }} />
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
              <Box component="span" sx={{ color: "#4285F4" }}>D</Box>
              <Box component="span" sx={{ color: "#EA4335" }}>R</Box>
              <Box component="span" sx={{ color: "#FBBC04" }}>J</Box>
            </Typography>
            <Chip
              label="LIVE"
              size="small"
              sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", mr: 2, fontSize: 10, height: 20, fontWeight: 700 }}
            />
            <NotificationBell />
            <Tooltip title="Theme">
              <IconButton onClick={(e) => setThemeAnchor(e.currentTarget)} sx={{ color: "rgba(255,255,255,0.75)" }}>
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
                <Box sx={{ px: 2, py: 1, borderTop: "1px solid rgba(255,255,255,0.08)" }}>
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontWeight: 700, letterSpacing: 1, display: "block", mb: 0.5 }}>
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
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontWeight: 700, letterSpacing: 1, display: "block", mb: 0.5 }}>
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
        <Box component="main" sx={{ flexGrow: 1, p: 3, overflow: "auto" }}>
          <Outlet />
        </Box>
      </Box>
    </Box>
  );
}
