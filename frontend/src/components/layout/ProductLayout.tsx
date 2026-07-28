/**
 * ProductLayout — the inside-product shell for Monitara v2.
 *
 * Structure:
 *   TopBar (56px):  waffle → home | "Monitara" | product name | client selector | user
 *   Left sidebar (220px): product icon + name + sub-nav
 *   Main content: background.default, overflow auto, p 3
 *
 * Usage:
 *   <ProductLayout product={THREAT_INTEL_PRODUCT}>
 *     <Routes>...</Routes>
 *   </ProductLayout>
 */
import React, { useState } from "react";
import { Outlet, useNavigate, useLocation } from "react-router-dom";
import {
  Box, Typography, Avatar, IconButton, Divider,
  List, ListItemButton, ListItemIcon, ListItemText,
  Tooltip, Select, MenuItem, FormControl, Menu,
} from "@mui/material";
import {
  Apps as WaffleIcon, ChevronLeft, Restore,
  DarkMode, LightMode, Palette, Logout, Settings, AccountCircle,
} from "@mui/icons-material";
import { useMsal } from "@azure/msal-react";
import { useQuery } from "@tanstack/react-query";
import { clientsApi } from "../../services/api";
import { Client } from "../../types";
import { useActiveClient } from "../../contexts/ClientContext";
import { useThemeMode } from "../../theme/ThemeModeContext";
import NotificationBell from "./NotificationBell";

export interface ProductNavItem {
  label: string;
  icon: React.ReactNode;
  path: string; // relative to product root
}

export interface ProductDef {
  name: string;
  abbrev: string;
  icon: React.ReactNode;
  color: string;
  bgColor: string;
  basePath: string; // e.g. "/threat-intel"
  nav: ProductNavItem[];
}

interface Props {
  product: ProductDef;
}

// ── Client selector ───────────────────────────────────────────────────────────

function ClientSelector() {
  const { clientId, setClientId } = useActiveClient();
  const { data: clients = [], isLoading } = useQuery<Client[]>({
    queryKey: ["clients"],
    queryFn: () => clientsApi.list(),
    staleTime: 60_000,
  });

  return (
    <FormControl size="small" sx={{ minWidth: 180, maxWidth: 240 }}>
      <Select
        value={clientId || ""}
        onChange={(e) => setClientId(e.target.value as string)}
        displayEmpty
        disabled={isLoading}
        sx={{
          fontSize: 13, fontWeight: 500,
          bgcolor: "background.paper",
          "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" },
          "&:hover .MuiOutlinedInput-notchedOutline": { borderColor: "primary.main" },
        }}
      >
        <MenuItem value="" disabled>
          <em>{isLoading ? "Loading…" : clients.length === 0 ? "No clients" : "Select client…"}</em>
        </MenuItem>
        {clients.map((c) => (
          <MenuItem key={c.id} value={c.id} sx={{ fontSize: 13 }}>{c.name}</MenuItem>
        ))}
      </Select>
    </FormControl>
  );
}

// ── Main layout ───────────────────────────────────────────────────────────────

export default function ProductLayout({ product }: Props) {
  const navigate = useNavigate();
  const location = useLocation();
  const { instance, accounts } = useMsal();
  const { mode, setMode } = useThemeMode();
  const [userMenuAnchor, setUserMenuAnchor] = useState<null | HTMLElement>(null);
  const [themeMenuAnchor, setThemeMenuAnchor] = useState<null | HTMLElement>(null);

  const displayName = accounts[0]?.name || accounts[0]?.username || "User";
  const initials = displayName.split(" ").map((n: string) => n[0]).join("").slice(0, 2).toUpperCase();

  const isActive = (path: string) => {
    const full = `${product.basePath}${path}`;
    return location.pathname === full || location.pathname.startsWith(`${full}/`);
  };

  return (
    <Box sx={{ display: "flex", height: "100vh", flexDirection: "column", bgcolor: "background.default" }}>

      {/* ── Top bar ─────────────────────────────────────────────────────────── */}
      <Box sx={{
        height: 52, flexShrink: 0,
        bgcolor: "background.paper",
        borderBottom: "1px solid", borderColor: "divider",
        display: "flex", alignItems: "center",
        px: 1.5, gap: 1,
        zIndex: 1100,
      }}>
        {/* Waffle / home */}
        <Tooltip title="All products">
          <IconButton
            size="small"
            onClick={() => navigate("/hub")}
            sx={{
              color: "text.secondary",
              "&:hover": { bgcolor: "action.hover", color: "primary.main" },
            }}
          >
            <WaffleIcon fontSize="small" />
          </IconButton>
        </Tooltip>

        {/* Back label */}
        <Tooltip title="Back to product list">
          <Box
            onClick={() => navigate("/hub")}
            sx={{ display: "flex", alignItems: "center", gap: 0.25, cursor: "pointer", mr: 0.5 }}
          >
            <Typography sx={{ fontWeight: 800, fontSize: 14, color: "primary.main", userSelect: "none" }}>
              Monitara
            </Typography>
          </Box>
        </Tooltip>

        <Box sx={{ width: 1, height: 18, bgcolor: "divider" }} />

        {/* Product name */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
          <Box sx={{
            width: 22, height: 22, borderRadius: 0.75,
            bgcolor: product.bgColor,
            display: "flex", alignItems: "center", justifyContent: "center",
            color: product.color, "& svg": { fontSize: 14 },
          }}>
            {product.icon}
          </Box>
          <Typography sx={{ fontWeight: 700, fontSize: 13.5, color: "text.primary" }}>
            {product.name}
          </Typography>
        </Box>

        <Box sx={{ flexGrow: 1 }} />

        {/* Client selector */}
        <ClientSelector />

        {/* Notifications */}
        <NotificationBell />

        {/* Theme toggle */}
        <Tooltip title="Theme">
          <IconButton size="small" onClick={(e) => setThemeMenuAnchor(e.currentTarget)} sx={{ color: "text.secondary" }}>
            {mode === "light" ? <LightMode fontSize="small" /> : mode === "custom" ? <Palette fontSize="small" /> : <DarkMode fontSize="small" />}
          </IconButton>
        </Tooltip>
        <Menu anchorEl={themeMenuAnchor} open={Boolean(themeMenuAnchor)} onClose={() => setThemeMenuAnchor(null)}>
          <MenuItem onClick={() => { setMode("dark");   setThemeMenuAnchor(null); }}><DarkMode  fontSize="small" sx={{ mr: 1 }} />Dark</MenuItem>
          <MenuItem onClick={() => { setMode("light");  setThemeMenuAnchor(null); }}><LightMode fontSize="small" sx={{ mr: 1 }} />Light</MenuItem>
          <MenuItem onClick={() => { setMode("custom"); setThemeMenuAnchor(null); }}><Palette   fontSize="small" sx={{ mr: 1 }} />Custom</MenuItem>
        </Menu>

        {/* Settings shortcut */}
        <Tooltip title="Settings">
          <IconButton size="small" onClick={() => navigate("/settings")} sx={{ color: "text.secondary" }}>
            <Settings fontSize="small" />
          </IconButton>
        </Tooltip>

        {/* User menu */}
        <Tooltip title={displayName}>
          <Avatar
            onClick={(e) => setUserMenuAnchor(e.currentTarget)}
            sx={{ width: 30, height: 30, fontSize: 12, bgcolor: product.color, ml: 0.5, cursor: "pointer" }}
          >
            {initials}
          </Avatar>
        </Tooltip>
        <Menu anchorEl={userMenuAnchor} open={Boolean(userMenuAnchor)} onClose={() => setUserMenuAnchor(null)}>
          <MenuItem disabled><AccountCircle sx={{ mr: 1 }} fontSize="small" />{displayName}</MenuItem>
          <Divider />
          <MenuItem onClick={() => { setUserMenuAnchor(null); navigate("/settings"); }}>
            <Settings sx={{ mr: 1 }} fontSize="small" />Settings
          </MenuItem>
          <Divider />
          <MenuItem onClick={() => instance.logoutRedirect({ postLogoutRedirectUri: "/" })}>
            <Logout sx={{ mr: 1 }} fontSize="small" />Logout
          </MenuItem>
        </Menu>
      </Box>

      <Box sx={{ display: "flex", flexGrow: 1, overflow: "hidden" }}>

        {/* ── Left sidebar ──────────────────────────────────────────────────── */}
        <Box sx={{
          width: 220, flexShrink: 0,
          bgcolor: "background.paper",
          borderRight: "1px solid", borderColor: "divider",
          display: "flex", flexDirection: "column",
          py: 1,
          overflowY: "auto",
        }}>
          {/* Product header */}
          <Box sx={{ px: 2, py: 1.5, display: "flex", alignItems: "center", gap: 1.5 }}>
            <Box sx={{
              width: 34, height: 34, borderRadius: 1.5,
              bgcolor: product.bgColor,
              display: "flex", alignItems: "center", justifyContent: "center",
              color: product.color, "& svg": { fontSize: 18 },
            }}>
              {product.icon}
            </Box>
            <Box>
              <Typography sx={{ fontWeight: 700, fontSize: 13, color: "text.primary", lineHeight: 1.2 }}>
                {product.name}
              </Typography>
              <Typography sx={{ fontSize: 10.5, fontWeight: 700, color: product.color, textTransform: "uppercase", letterSpacing: 0.5 }}>
                {product.abbrev}
              </Typography>
            </Box>
          </Box>

          <Divider sx={{ mb: 0.5 }} />

          {/* Nav items */}
          <List dense disablePadding sx={{ px: 1, flexGrow: 1 }}>
            {product.nav.map((item) => {
              const active = isActive(item.path);
              return (
                <ListItemButton
                  key={item.path}
                  selected={active}
                  onClick={() => navigate(`${product.basePath}${item.path}`)}
                  sx={{
                    borderRadius: 1.5, mb: 0.25, gap: 0.5,
                    "&.Mui-selected": {
                      bgcolor: `${product.color}12`,
                      borderLeft: `3px solid ${product.color}`,
                      pl: "11px",
                    },
                  }}
                >
                  <ListItemIcon sx={{
                    minWidth: 32,
                    color: active ? product.color : "text.secondary",
                    "& svg": { fontSize: 18 },
                  }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.label}
                    slotProps={{ primary: { sx: {
                      fontSize: 13,
                      fontWeight: active ? 700 : 400,
                      color: active ? product.color : "text.primary",
                    } } }}
                  />
                </ListItemButton>
              );
            })}
          </List>

          {/* Back to all products / Classic View */}
          <Divider sx={{ mt: "auto", mb: 0.5 }} />
          <Box sx={{ px: 1 }}>
            <ListItemButton
              onClick={() => navigate("/hub")}
              sx={{ borderRadius: 1.5, gap: 0.5, color: "text.secondary" }}
            >
              <ListItemIcon sx={{ minWidth: 32, color: "text.secondary", "& svg": { fontSize: 18 } }}>
                <ChevronLeft />
              </ListItemIcon>
              <ListItemText primary="All Products" slotProps={{ primary: { sx: { fontSize: 12.5, color: "text.secondary" } } }} />
            </ListItemButton>
            <ListItemButton
              onClick={() => navigate("/dashboard")}
              sx={{ borderRadius: 1.5, gap: 0.5, opacity: 0.6, "&:hover": { opacity: 1 } }}
            >
              <ListItemIcon sx={{ minWidth: 32, color: "text.secondary", "& svg": { fontSize: 16 } }}>
                <Restore />
              </ListItemIcon>
              <ListItemText primary="Classic View" slotProps={{ primary: { sx: { fontSize: 12, color: "text.secondary" } } }} />
            </ListItemButton>
          </Box>
        </Box>

        {/* ── Main content ─────────────────────────────────────────────────── */}
        <Box sx={{ flexGrow: 1, overflow: "auto", p: 3 }}>
          <Outlet />
        </Box>

      </Box>
    </Box>
  );
}
