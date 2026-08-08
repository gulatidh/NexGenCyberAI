/**
 * Shared right-side topbar controls used by every layout
 * (Hub, ProductLayout). Keeps the trailing JSX identical everywhere.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Avatar, IconButton, Tooltip, Menu, MenuItem,
  Divider, FormControl, Select,
} from "@mui/material";
import {
  DarkMode, LightMode, Palette, Logout, Settings,
  AccountCircle,
} from "@mui/icons-material";
import { useMsal } from "@azure/msal-react";
import { useQuery } from "@tanstack/react-query";
import { clientsApi } from "../../services/api";
import { Client } from "../../types";
import { useActiveClient } from "../../contexts/ClientContext";
import { useThemeMode } from "../../theme/ThemeModeContext";
import NotificationBell from "./NotificationBell";
import GlobalSearch from "../GlobalSearch";

interface Props {
  avatarColor?: string;
}

function ClientSelector() {
  const { clientId, setClientId } = useActiveClient();
  const { data: clients = [], isLoading } = useQuery<Client[]>({
    queryKey: ["clients"], queryFn: clientsApi.list, staleTime: 60_000,
  });
  return (
    <FormControl size="small" sx={{ minWidth: 160, maxWidth: 220 }}>
      <Select
        value={clientId || ""} displayEmpty disabled={isLoading}
        onChange={(e) => setClientId(e.target.value as string)}
        sx={{ fontSize: 13, fontWeight: 500, bgcolor: "background.paper",
          "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" },
          "&:hover .MuiOutlinedInput-notchedOutline": { borderColor: "primary.main" } }}
      >
        <MenuItem value="" disabled>
          <em>{isLoading ? "Loading…" : clients.length === 0 ? "No accounts" : "Select account…"}</em>
        </MenuItem>
        {clients.map((c) => <MenuItem key={c.id} value={c.id} sx={{ fontSize: 13 }}>{c.name}</MenuItem>)}
      </Select>
    </FormControl>
  );
}

export default function AppControls({ avatarColor = "#1565C0" }: Props) {
  const navigate = useNavigate();
  const { instance, accounts } = useMsal();
  const { mode, setMode } = useThemeMode();
  const [userAnchor, setUserAnchor] = useState<null | HTMLElement>(null);
  const [themeAnchor, setThemeAnchor] = useState<null | HTMLElement>(null);

  const displayName = accounts[0]?.name || accounts[0]?.username || "User";
  const initials = displayName.split(" ").map((n: string) => n[0]).join("").slice(0, 2).toUpperCase();

  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
      <ClientSelector />

      <GlobalSearch />

      <NotificationBell />

      {/* Theme */}
      <Tooltip title="Theme">
        <IconButton size="small" onClick={(e) => setThemeAnchor(e.currentTarget)} sx={{ color: "text.secondary" }}>
          {mode === "light" ? <LightMode fontSize="small" /> : mode === "custom" ? <Palette fontSize="small" /> : <DarkMode fontSize="small" />}
        </IconButton>
      </Tooltip>
      <Menu anchorEl={themeAnchor} open={Boolean(themeAnchor)} onClose={() => setThemeAnchor(null)}>
        <MenuItem onClick={() => { setMode("dark");   setThemeAnchor(null); }}><DarkMode  fontSize="small" sx={{ mr: 1 }} />Dark</MenuItem>
        <MenuItem onClick={() => { setMode("light");  setThemeAnchor(null); }}><LightMode fontSize="small" sx={{ mr: 1 }} />Light</MenuItem>
        <MenuItem onClick={() => { setMode("custom"); setThemeAnchor(null); }}><Palette   fontSize="small" sx={{ mr: 1 }} />Custom</MenuItem>
      </Menu>

      {/* Settings */}
      <Tooltip title="Settings">
        <IconButton size="small" onClick={() => navigate("/platform/settings")} sx={{ color: "text.secondary" }}>
          <Settings fontSize="small" />
        </IconButton>
      </Tooltip>

      {/* User */}
      <Tooltip title={displayName}>
        <Avatar onClick={(e) => setUserAnchor(e.currentTarget)}
          sx={{ width: 30, height: 30, fontSize: 12, bgcolor: avatarColor, ml: 0.5, cursor: "pointer" }}>
          {initials}
        </Avatar>
      </Tooltip>
      <Menu anchorEl={userAnchor} open={Boolean(userAnchor)} onClose={() => setUserAnchor(null)}>
        <MenuItem disabled><AccountCircle sx={{ mr: 1 }} fontSize="small" />{displayName}</MenuItem>
        <Divider />
        <MenuItem onClick={() => { setUserAnchor(null); navigate("/platform/settings"); }}>
          <Settings sx={{ mr: 1 }} fontSize="small" />Settings
        </MenuItem>
        <Divider />
        <MenuItem onClick={() => instance.logoutRedirect({ postLogoutRedirectUri: "/" })}>
          <Logout sx={{ mr: 1 }} fontSize="small" />Logout
        </MenuItem>
      </Menu>
    </Box>
  );
}
