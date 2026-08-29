import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Grid, Switch,
  Select, MenuItem, FormControl, InputLabel, Button, Chip, Alert,
} from "@mui/material";
import { AccountCircle, AdminPanelSettings, NotificationsActive, Schedule } from "@mui/icons-material";
import { useMsal } from "@azure/msal-react";
import { useQuery } from "@tanstack/react-query";
import { adminApi } from "../services/api";

const TIMEZONES = [
  "UTC", "America/New_York", "America/Chicago", "America/Los_Angeles",
  "Europe/London", "Europe/Paris", "Europe/Berlin", "Asia/Dubai",
  "Asia/Kolkata", "Asia/Singapore", "Asia/Tokyo", "Australia/Sydney",
];

const NOTIF_KEYS = [
  { key: "critical_findings", label: "Critical Findings", desc: "Alert when a critical severity finding is discovered" },
  { key: "agent_completed",   label: "Agent Completed",   desc: "Notify when an AI agent run finishes" },
  { key: "scan_completed",    label: "Scan Completed",    desc: "Notify when a scan finishes successfully" },
  { key: "weekly_digest",     label: "Weekly Digest",     desc: "Weekly security posture summary" },
];

const NOTIF_KEY = "aegis-notif-prefs";
const TZ_KEY    = "aegis-timezone";

function loadNotifPrefs(): Record<string, boolean> {
  try { return JSON.parse(localStorage.getItem(NOTIF_KEY) || "{}"); } catch { return {}; }
}

export default function MyProfile() {
  const { accounts } = useMsal();
  const user = accounts[0];

  const [notifPrefs, setNotifPrefs] = useState<Record<string, boolean>>(loadNotifPrefs);
  const [timezone, setTimezone] = useState(() => localStorage.getItem(TZ_KEY) || "UTC");
  const [saved, setSaved] = useState(false);

  const { data: access } = useQuery({
    queryKey: ["admin-me"],
    queryFn: () => adminApi.me(),
    retry: false,
  });

  const toggleNotif = (key: string) => {
    const updated = { ...notifPrefs, [key]: !notifPrefs[key] };
    setNotifPrefs(updated);
    localStorage.setItem(NOTIF_KEY, JSON.stringify(updated));
  };

  const saveTimezone = () => {
    localStorage.setItem(TZ_KEY, timezone);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>My Profile</Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
          Personal preferences and account information.
        </Typography>
      </Box>

      <Grid container spacing={2}>
        {/* Identity */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <AccountCircle sx={{ color: "#4285F4" }} />
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Identity</Typography>
              </Box>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                <Box>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>Display Name</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>{user?.name || "—"}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>Email</Typography>
                  <Typography variant="body2">{user?.username || "—"}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>Tenant</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: 12 }}>
                    {user?.tenantId || "—"}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Role */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <AdminPanelSettings sx={{ color: "#FBBC04" }} />
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Role & Access</Typography>
              </Box>
              {access ? (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                  <Box>
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>Role</Typography>
                    <Box sx={{ mt: 0.5 }}>
                      <Chip label={(access as any).role || "user"} size="small"
                        sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontWeight: 700, textTransform: "capitalize" }} />
                    </Box>
                  </Box>
                  <Box>
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>Scope</Typography>
                    <Box sx={{ mt: 0.5 }}>
                      <Chip label={(access as any).scope || "global"} size="small"
                        sx={{ bgcolor: "rgba(52,168,83,0.15)", color: "#34A853", fontWeight: 700, textTransform: "capitalize" }} />
                    </Box>
                  </Box>
                </Box>
              ) : (
                <Typography variant="body2" sx={{ color: "text.secondary" }}>Loading access information…</Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Notification preferences */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <NotificationsActive sx={{ color: "#34A853" }} />
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Notification Preferences</Typography>
              </Box>
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 2 }}>
                Preferences are stored locally in your browser.
              </Typography>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                {NOTIF_KEYS.map(({ key, label, desc }) => (
                  <Box key={key} sx={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                    py: 1, borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                    <Box>
                      <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 13 }}>{label}</Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>{desc}</Typography>
                    </Box>
                    <Switch checked={!!notifPrefs[key]} onChange={() => toggleNotif(key)} size="small" />
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Timezone */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <Schedule sx={{ color: "#9C27B0" }} />
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Timezone</Typography>
              </Box>
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 2 }}>
                Used for all date and time display throughout the platform.
              </Typography>
              <FormControl fullWidth size="small" sx={{ mb: 2 }}>
                <InputLabel>Timezone</InputLabel>
                <Select value={timezone} label="Timezone" onChange={e => setTimezone(e.target.value as string)}>
                  {TIMEZONES.map(tz => (
                    <MenuItem key={tz} value={tz}>{tz.replace(/_/g, " ")}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              <Button variant="contained" size="small" onClick={saveTimezone}
                sx={{ bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" } }}>
                Save Timezone
              </Button>
              {saved && <Alert severity="success" sx={{ mt: 1.5, py: 0 }}>Saved successfully</Alert>}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
