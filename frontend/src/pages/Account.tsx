/**
 * Account / user settings page. Reachable from the avatar menu in AppLayout.
 *
 * Shows the signed-in user's profile from MSAL + their effective RBAC grants
 * from /admin/me, plus a timezone preference that's persisted in
 * localStorage. The tz pref drives all date formatting via utils/datetime.ts.
 */
import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Grid, Chip, Divider,
  Select, MenuItem, FormControl, InputLabel, Button, Alert, Tooltip,
} from "@mui/material";
import {
  AccountCircle, Schedule, Public, Save, RestartAlt,
} from "@mui/icons-material";
import { useMsal } from "@azure/msal-react";
import { useQuery } from "@tanstack/react-query";
import { adminApi } from "../services/api";
import { MyAccess } from "../types";
import {
  getUserTz, setUserTz, clearUserTz, fmt, TZ_OPTIONS,
} from "../utils/datetime";
import dayjs from "dayjs";

export default function Account() {
  const { accounts } = useMsal();
  const account = accounts[0];
  const [tz, setTz] = useState<string>(localStorage.getItem("user_tz") || "");
  const [saved, setSaved] = useState(false);

  const { data: me } = useQuery<MyAccess>({
    queryKey: ["my-access"],
    queryFn: adminApi.me,
    retry: 0,
  });

  const detectedTz = dayjs.tz.guess() || "UTC";
  const activeTz = getUserTz();
  const now = new Date().toISOString();

  const handleSave = () => {
    if (tz) setUserTz(tz);
    else clearUserTz();
    setSaved(true);
    // Force re-render across the SPA without a hard reload — invalidate by
    // bumping the URL hash. Most consumers re-read getUserTz() on every render.
    setTimeout(() => window.location.reload(), 600);
  };

  const handleReset = () => {
    setTz("");
    clearUserTz();
    setSaved(true);
    setTimeout(() => window.location.reload(), 600);
  };

  const userName = account?.name || account?.username || "Unknown";
  const upn = (account?.username || "").toLowerCase();
  const tenantId = (account?.tenantId as string | undefined) || "";

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
        <AccountCircle sx={{ color: "#A100FF", fontSize: 32 }} />
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Account</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            Profile, preferences, and access
          </Typography>
        </Box>
      </Box>

      <Grid container spacing={2}>
        {/* Profile */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ bgcolor: "#1A1A1A", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
            <CardContent>
              <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 700, mb: 2 }}>Profile</Typography>
              <Field label="Display name" value={userName} />
              <Field label="Email / UPN" value={upn || "—"} mono />
              <Field label="Tenant ID" value={tenantId || "—"} mono small />
              <Field label="Identity provider" value="Microsoft Entra ID" />
              {me?.is_admin && <Chip label="Global Admin" size="small" sx={{ mt: 1, bgcolor: "rgba(240,98,146,0.15)", color: "#f06292" }} />}
              {!me?.is_admin && me?.is_admin_anywhere && <Chip label="Scoped Admin" size="small" sx={{ mt: 1, bgcolor: "rgba(240,98,146,0.15)", color: "#f06292" }} />}
            </CardContent>
          </Card>
        </Grid>

        {/* Preferences */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ bgcolor: "#1A1A1A", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <Schedule sx={{ color: "#A100FF", fontSize: 20 }} />
                <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 700 }}>Timezone</Typography>
              </Box>
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 2 }}>
                Backend stores timestamps in UTC. Pick your timezone to control how dates render across the app.
              </Typography>

              <FormControl fullWidth size="small" sx={{ mb: 2 }}>
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Timezone</InputLabel>
                <Select value={tz} label="Timezone" onChange={(e) => { setTz(e.target.value); setSaved(false); }}
                  sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                  {TZ_OPTIONS.map((o) => (
                    <MenuItem key={o.value || "auto"} value={o.value}>
                      {o.label}{o.value === "" ? ` — currently ${detectedTz}` : ""}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <Box sx={{ p: 1.5, borderRadius: 1, bgcolor: "rgba(161,0,255,0.05)", border: "1px solid rgba(161,0,255,0.2)", mb: 2 }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 0.5 }}>
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.6)", fontSize: 11 }}>ACTIVE TIMEZONE</Typography>
                  <Tooltip title="Detected from browser if not overridden"><Public sx={{ color: "rgba(255,255,255,0.4)", fontSize: 14 }} /></Tooltip>
                </Box>
                <Typography sx={{ color: "#A100FF", fontFamily: "monospace", fontSize: 14 }}>{activeTz}</Typography>
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mt: 0.5 }}>
                  Now: {fmt(now, "YYYY-MM-DD HH:mm:ss")} · UTC: {dayjs.utc(now).format("YYYY-MM-DD HH:mm:ss")}
                </Typography>
              </Box>

              {saved && <Alert severity="success" sx={{ mb: 2, bgcolor: "rgba(0,230,118,0.1)", color: "white" }}>
                Saved. Reloading…
              </Alert>}

              <Box sx={{ display: "flex", gap: 1 }}>
                <Button variant="contained" startIcon={<Save />} onClick={handleSave}
                  sx={{ bgcolor: "#A100FF", color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}>
                  Save
                </Button>
                <Button variant="outlined" startIcon={<RestartAlt />} onClick={handleReset}
                  sx={{ color: "rgba(255,255,255,0.7)", borderColor: "rgba(255,255,255,0.2)" }}>
                  Reset to auto
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Access summary */}
        <Grid size={{ xs: 12 }}>
          <Card sx={{ bgcolor: "#1A1A1A", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 700, mb: 2 }}>Your access</Typography>
              {!me ? (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>Loading…</Typography>
              ) : (me.grants || []).length === 0 ? (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                  No grants assigned yet. Ask an administrator for access.
                </Typography>
              ) : (
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.75 }}>
                  {me.grants.map((g) => (
                    <Chip key={g.id} size="small"
                      label={`${g.role} · ${g.scope_label || g.scope_type}`}
                      sx={{ bgcolor: "rgba(161,0,255,0.1)", color: "#A100FF", fontSize: 11 }} />
                  ))}
                </Box>
              )}
              <Divider sx={{ borderColor: "rgba(255,255,255,0.08)", my: 2 }} />
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>
                Roles: <b>reader</b> (view), <b>editor</b> (read + write), <b>admin</b> (manage user access).
                Scopes: <b>global</b>, <b>client</b>, <b>project</b>.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

function Field({ label, value, mono = false, small = false }: {
  label: string; value: string; mono?: boolean; small?: boolean;
}) {
  return (
    <Box sx={{ mb: 1.5 }}>
      <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontSize: 11, display: "block" }}>{label}</Typography>
      <Typography sx={{
        color: "white",
        fontFamily: mono ? "monospace" : undefined,
        fontSize: small ? 11 : 13,
        wordBreak: "break-all",
      }}>{value}</Typography>
    </Box>
  );
}
