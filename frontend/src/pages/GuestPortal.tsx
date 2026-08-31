/**
 * GuestPortal — read-only portal shell for guest-link users.
 *
 * Overrides the global ClientContext to the guest's scoped client/project.
 * Hides all config pages (AI Settings, Connectors, Agents, Settings).
 * Shows a persistent banner with label + expiry countdown.
 * Any attempted navigation to a blocked route is redirected to /guest/portal.
 */
import React, { useEffect, useState, lazy, Suspense } from "react";
import { Routes, Route, Navigate, useNavigate, NavLink } from "react-router-dom";
import {
  Box, Typography, Chip, Drawer, List, ListItemButton, ListItemIcon,
  ListItemText, AppBar, Toolbar, CircularProgress, Tooltip, IconButton,
} from "@mui/material";
import {
  Dashboard, BugReport, Inventory2, Assessment, Shield,
  VerifiedUser, Timeline, AccountTree, Security, Logout, Warning,
} from "@mui/icons-material";
import { GUEST_JWT_KEY, GUEST_META_KEY } from "./GuestLanding";

// Lazy-loaded read-only page views
const Dashboard_ = lazy(() => import("./Dashboard"));
const Findings_  = lazy(() => import("./Findings"));
const Assets_    = lazy(() => import("./Assets"));
const Risks_     = lazy(() => import("./Risks"));
const Frameworks_ = lazy(() => import("./Frameworks"));
const PostureTrends_ = lazy(() => import("./PostureTrends"));
const AttackPaths_ = lazy(() => import("./AttackPaths"));
const VAPTReports_ = lazy(() => import("./VAPTReports"));

const SIDEBAR_W = 220;

const NAV = [
  { label: "Dashboard",      icon: <Dashboard sx={{ fontSize: 18 }} />,    path: "/guest/portal/dashboard" },
  { label: "Findings",       icon: <BugReport sx={{ fontSize: 18 }} />,    path: "/guest/portal/findings" },
  { label: "Assets",         icon: <Inventory2 sx={{ fontSize: 18 }} />,   path: "/guest/portal/assets" },
  { label: "Risks",          icon: <Security sx={{ fontSize: 18 }} />,     path: "/guest/portal/risks" },
  { label: "Frameworks",     icon: <VerifiedUser sx={{ fontSize: 18 }} />, path: "/guest/portal/frameworks" },
  { label: "Posture Trends", icon: <Timeline sx={{ fontSize: 18 }} />,     path: "/guest/portal/posture" },
  { label: "Attack Paths",   icon: <AccountTree sx={{ fontSize: 18 }} />,  path: "/guest/portal/attack-paths" },
  { label: "VAPT Reports",   icon: <Assessment sx={{ fontSize: 18 }} />,   path: "/guest/portal/vapt-reports" },
];

function GuestBanner({ meta, onExit }: { meta: any; onExit: () => void }) {
  const exp = meta?.expires_at ? new Date(meta.expires_at) : null;
  const hoursLeft = exp ? Math.max(0, Math.ceil((exp.getTime() - Date.now()) / 3600000)) : null;
  const label = hoursLeft !== null
    ? hoursLeft < 24 ? `${hoursLeft}h remaining` : `${Math.ceil(hoursLeft / 24)} days remaining`
    : "";

  return (
    <Box sx={{
      bgcolor: "rgba(251,188,4,0.12)", borderBottom: "1px solid rgba(251,188,4,0.3)",
      px: 2, py: 0.75, display: "flex", alignItems: "center", gap: 1.5, flexWrap: "wrap",
    }}>
      <Warning sx={{ fontSize: 14, color: "#FBBC04" }} />
      <Typography sx={{ fontSize: 12, color: "#FBBC04", fontWeight: 600 }}>
        Guest Access — Read Only
      </Typography>
      <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.5)" }}>
        {meta?.label}
      </Typography>
      {label && (
        <Chip label={label} size="small"
          sx={{ height: 18, fontSize: 10, bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04" }} />
      )}
      <Box sx={{ flex: 1 }} />
      <Tooltip title="Exit guest session">
        <IconButton size="small" onClick={onExit} sx={{ color: "rgba(255,255,255,0.4)" }}>
          <Logout sx={{ fontSize: 16 }} />
        </IconButton>
      </Tooltip>
    </Box>
  );
}

function Loader() {
  return (
    <Box sx={{ display: "flex", justifyContent: "center", pt: 8 }}>
      <CircularProgress size={32} sx={{ color: "#4285F4" }} />
    </Box>
  );
}

export default function GuestPortal() {
  const navigate = useNavigate();
  const [meta, setMeta] = useState<any>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const jwt = sessionStorage.getItem(GUEST_JWT_KEY);
    const raw = sessionStorage.getItem(GUEST_META_KEY);
    if (!jwt || !raw) { navigate("/", { replace: true }); return; }
    try { setMeta(JSON.parse(raw)); } catch { /* ignore */ }
    setReady(true);
  }, [navigate]);

  const exit = () => {
    sessionStorage.removeItem(GUEST_JWT_KEY);
    sessionStorage.removeItem(GUEST_META_KEY);
    navigate("/", { replace: true });
  };

  if (!ready) return <Loader />;

  return (
    <Box sx={{ display: "flex", flexDirection: "column", minHeight: "100vh", bgcolor: "background.default" }}>
      {/* Top bar */}
      <AppBar position="static" elevation={0}
        sx={{ bgcolor: "background.paper", borderBottom: "1px solid", borderColor: "divider", zIndex: 1200 }}>
        <Toolbar variant="dense" sx={{ gap: 1.5, minHeight: 48 }}>
          <Shield sx={{ color: "#4285F4", fontSize: 22 }} />
          <Typography sx={{ fontWeight: 800, fontSize: 16, color: "text.primary", flex: 1 }}>
            Owlet AI
          </Typography>
          <Chip label="READ ONLY" size="small"
            sx={{ bgcolor: "rgba(251,188,4,0.12)", color: "#FBBC04", fontSize: 10, fontWeight: 700 }} />
        </Toolbar>
      </AppBar>

      {/* Guest access banner */}
      <GuestBanner meta={meta} onExit={exit} />

      <Box sx={{ display: "flex", flex: 1 }}>
        {/* Sidebar */}
        <Drawer variant="permanent"
          sx={{
            width: SIDEBAR_W,
            flexShrink: 0,
            "& .MuiDrawer-paper": {
              width: SIDEBAR_W,
              boxSizing: "border-box",
              position: "relative",
              bgcolor: "background.paper",
              borderRight: "1px solid",
              borderColor: "divider",
            },
          }}
        >
          <List dense sx={{ pt: 1 }}>
            {NAV.map((item) => (
              <ListItemButton
                key={item.path}
                component={NavLink}
                to={item.path}
                sx={{
                  borderRadius: 1, mx: 0.5, mb: 0.25,
                  "&.active": { bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4" },
                  "&.active .MuiListItemIcon-root": { color: "#4285F4" },
                  color: "text.secondary",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, color: "inherit" }}>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label}
                  slotProps={{ primary: { sx: { fontSize: 13, fontWeight: 500 } } }} />
              </ListItemButton>
            ))}
          </List>
        </Drawer>

        {/* Main content */}
        <Box component="main" sx={{ flex: 1, p: 3, overflow: "auto" }}>
          <Suspense fallback={<Loader />}>
            <Routes>
              <Route index element={<Navigate to="dashboard" replace />} />
              <Route path="dashboard"    element={<Dashboard_ />} />
              <Route path="findings"     element={<Findings_ />} />
              <Route path="assets"       element={<Assets_ />} />
              <Route path="risks"        element={<Risks_ />} />
              <Route path="frameworks"   element={<Frameworks_ />} />
              <Route path="posture"      element={<PostureTrends_ />} />
              <Route path="attack-paths" element={<AttackPaths_ />} />
              <Route path="vapt-reports" element={<VAPTReports_ />} />
              <Route path="*"            element={<Navigate to="dashboard" replace />} />
            </Routes>
          </Suspense>
        </Box>
      </Box>
    </Box>
  );
}
