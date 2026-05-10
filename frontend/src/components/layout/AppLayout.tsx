import React, { useState } from "react";
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
  AdminPanelSettings,
} from "@mui/icons-material";
import { useMsal } from "@azure/msal-react";
import { useQuery } from "@tanstack/react-query";
import NotificationBell from "./NotificationBell";
import { adminApi } from "../../services/api";
import { MyAccess } from "../../types";

const DRAWER_WIDTH = 240;

type NavItem = { label: string; icon: React.ReactNode; path: string; adminOnly?: boolean };
type NavGroup = { section?: string; items: NavItem[] };

// Top-level pages group "main workflow"; Settings group at the bottom holds
// admin/config items. Connectors + Projects no longer appear in main nav —
// they live as tabs inside the Client Detail page.
const NAV_GROUPS: NavGroup[] = [
  {
    items: [
      { label: "Dashboard",      icon: <Dashboard />,  path: "/dashboard" },
      { label: "Risk Overview",  icon: <Insights />,   path: "/risk-overview" },
      { label: "Clients",        icon: <People />,     path: "/clients" },
      { label: "Scans",          icon: <BugReport />,  path: "/scans" },
      { label: "Findings",       icon: <Security />,   path: "/findings" },
      { label: "Risk Register",  icon: <Assessment />, path: "/risks" },
      { label: "Asset Inventory", icon: <Storage />,   path: "/assets" },
      { label: "Technologies",   icon: <Apps />,       path: "/assets/technologies" },
      { label: "Frameworks",     icon: <Policy />,     path: "/frameworks" },
      { label: "AI Agents",      icon: <SmartToy />,   path: "/agents" },
      { label: "Reports",        icon: <BarChart />,   path: "/reports" },
    ],
  },
  {
    section: "Settings",
    items: [
      { label: "AI Settings",    icon: <SettingsSuggest />,    path: "/ai-settings" },
      { label: "Administration", icon: <AdminPanelSettings />, path: "/admin", adminOnly: true },
    ],
  },
];

export default function AppLayout() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const { instance, accounts } = useMsal();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [mobileOpen, setMobileOpen] = useState(false);

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
    <Box sx={{ height: "100%", bgcolor: "grey.900", color: "white" }}>
      <Box sx={{ p: 2, display: "flex", alignItems: "center", gap: 1, borderBottom: "1px solid rgba(255,255,255,0.1)" }}>
        <Shield sx={{ color: "#00e5ff", fontSize: 32 }} />
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 700, color: "#00e5ff", lineHeight: 1.1 }}>
            NexGen
          </Typography>
          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.6)", fontSize: 10 }}>
            CyberAI Platform
          </Typography>
        </Box>
      </Box>
      <List sx={{ pt: 1 }}>
        {NAV_GROUPS.map((group, gi) => {
          const items = group.items.filter((i) => !i.adminOnly || me?.is_admin || me?.is_admin_anywhere);
          if (items.length === 0) return null;
          return (
          <React.Fragment key={gi}>
            {group.section && (
              <Typography
                variant="caption"
                sx={{
                  display: "block", color: "rgba(255,255,255,0.4)", fontSize: 10,
                  fontWeight: 700, letterSpacing: 1, mt: 1.5, mb: 0.5, mx: 2.5,
                  textTransform: "uppercase",
                }}
              >
                {group.section}
              </Typography>
            )}
            {items.map((item) => {
              // Exact-match for /assets to avoid /assets/technologies highlighting both
              const active = item.path === "/assets"
                ? pathname === "/assets" || /^\/assets\/[^/]+$/.test(pathname)  // /assets and /assets/:id
                : pathname.startsWith(item.path);
              return (
                <ListItemButton
                  key={item.path}
                  onClick={() => navigate(item.path)}
                  sx={{
                    mx: 1, my: 0.3, borderRadius: 1,
                    bgcolor: active ? "rgba(0,229,255,0.15)" : "transparent",
                    "&:hover": { bgcolor: "rgba(255,255,255,0.08)" },
                  }}
                >
                  <ListItemIcon sx={{ color: active ? "#00e5ff" : "rgba(255,255,255,0.6)", minWidth: 36 }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.label}
                    slotProps={{
                      primary: {
                        style: {
                          fontSize: 13,
                          fontWeight: active ? 600 : 400,
                          color: active ? "#00e5ff" : "rgba(255,255,255,0.8)",
                        },
                      },
                    }}
                  />
                </ListItemButton>
              );
            })}
          </React.Fragment>
          );
        })}
      </List>
    </Box>
  );

  return (
    <Box sx={{ display: "flex", minHeight: "100vh", bgcolor: "#0f1117" }}>
      {/* Sidebar */}
      <Box component="nav" sx={{ width: { md: DRAWER_WIDTH }, flexShrink: 0 }}>
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
          sx={{ display: { xs: "none", md: "block" }, "& .MuiDrawer-paper": { width: DRAWER_WIDTH, border: "none" } }}
          open
        >
          {drawer}
        </Drawer>
      </Box>

      {/* Main content */}
      <Box sx={{ flexGrow: 1, display: "flex", flexDirection: "column" }}>
        <AppBar
          position="sticky"
          elevation={0}
          sx={{ bgcolor: "#161b22", borderBottom: "1px solid rgba(255,255,255,0.08)" }}
        >
          <Toolbar>
            <IconButton color="inherit" onClick={() => setMobileOpen(true)} sx={{ mr: 1, display: { md: "none" } }}>
              <MenuIcon />
            </IconButton>
            <Box sx={{ flexGrow: 1 }} />
            <Chip
              label="LIVE"
              size="small"
              sx={{ bgcolor: "rgba(0,229,255,0.1)", color: "#00e5ff", mr: 2, fontSize: 10, height: 20, fontWeight: 700 }}
            />
            <NotificationBell />
            <Tooltip title="Account">
              <IconButton onClick={(e) => setAnchorEl(e.currentTarget)}>
                <Avatar sx={{ bgcolor: "#00e5ff", color: "#000", width: 32, height: 32, fontSize: 14, fontWeight: 700 }}>
                  {userInitial}
                </Avatar>
              </IconButton>
            </Tooltip>
            <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={() => setAnchorEl(null)}>
              <MenuItem disabled>
                <AccountCircle sx={{ mr: 1 }} /> {userName}
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
