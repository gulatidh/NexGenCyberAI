/**
 * Email Settings Page
 * Admin configuration for outbound email (SMTP), including an Office 365
 * preset. Lets an admin point the platform at an SMTP relay and send a test
 * message. Analysts send report emails from the Reports page using this config.
 */
import React, { useState, useEffect } from "react";
import {
  Box, Typography, Card, CardContent, Grid, Button, Switch, FormControlLabel,
  Select, MenuItem, FormControl, InputLabel, TextField, Alert, Divider,
  IconButton, InputAdornment, Chip, CircularProgress,
} from "@mui/material";
import { Save, Send, Visibility, VisibilityOff, MarkEmailRead, CheckCircle } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";
import { emailApi, adminApi } from "../services/api";
import { MyAccess } from "../types";

const PROVIDER_PRESETS: Record<string, { smtp_host?: string; smtp_port?: number; smtp_security?: string }> = {
  office365: { smtp_host: "smtp.office365.com", smtp_port: 587, smtp_security: "starttls" },
  gmail: { smtp_host: "smtp.gmail.com", smtp_port: 587, smtp_security: "starttls" },
  smtp: {},
};

const ACCENT = "#4285F4";

export default function EmailSettings() {
  const qc = useQueryClient();
  const [form, setForm] = useState<Record<string, any>>({});
  const [password, setPassword] = useState<string | null>(null); // null = unchanged
  const [showPassword, setShowPassword] = useState(false);
  const [testTo, setTestTo] = useState("");

  const { data: me } = useQuery<MyAccess>({
    queryKey: ["my-access"], queryFn: adminApi.me, retry: 0, staleTime: 60_000,
  });
  const isAdmin = !!me?.is_admin;

  const { data: cfg, isLoading } = useQuery({
    queryKey: ["email-config"], queryFn: emailApi.getConfig,
  });

  useEffect(() => {
    if (cfg) {
      setForm({
        enabled: !!cfg.enabled,
        provider: cfg.provider || "office365",
        smtp_host: cfg.smtp_host || "",
        smtp_port: cfg.smtp_port || 587,
        smtp_username: cfg.smtp_username || "",
        smtp_security: cfg.smtp_security || "starttls",
        from_address: cfg.from_address || "",
        from_name: cfg.from_name || "NexGenCyberAI Reports",
      });
      if (!testTo) setTestTo(cfg.from_address || "");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cfg]);

  const set = (k: string, v: any) => setForm((f) => ({ ...f, [k]: v }));

  const onProviderChange = (provider: string) => {
    const preset = PROVIDER_PRESETS[provider] || {};
    setForm((f) => ({
      ...f,
      provider,
      ...(preset.smtp_host !== undefined ? { smtp_host: preset.smtp_host } : {}),
      ...(preset.smtp_port !== undefined ? { smtp_port: preset.smtp_port } : {}),
      ...(preset.smtp_security !== undefined ? { smtp_security: preset.smtp_security } : {}),
    }));
  };

  const saveMutation = useMutation({
    mutationFn: () => {
      const payload: Record<string, any> = { ...form };
      if (password !== null) payload.smtp_password = password; // "" clears, value sets
      return emailApi.updateConfig(payload);
    },
    onSuccess: () => {
      toast.success("Email settings saved");
      setPassword(null);
      qc.invalidateQueries({ queryKey: ["email-config"] });
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Save failed"),
  });

  const testMutation = useMutation({
    mutationFn: () => emailApi.test(testTo),
    onSuccess: (r: any) => {
      if (r?.success) toast.success(`Test email sent to ${testTo}`);
      else toast.error(r?.error || "Test failed");
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Test failed"),
  });

  if (isLoading) {
    return <Box sx={{ display: "flex", justifyContent: "center", p: 6 }}><CircularProgress sx={{ color: ACCENT }} /></Box>;
  }

  const pwConfigured = !!cfg?.smtp_password_configured;

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
          <MarkEmailRead sx={{ color: ACCENT }} /> Email Settings
        </Typography>
        <Typography variant="body2" sx={{ color: "text.secondary" }}>
          Configure outbound email (SMTP). Use the Office 365 preset, or any SMTP relay. Report emails are sent from the Reports page.
        </Typography>
      </Box>

      {!isAdmin && (
        <Alert severity="info" sx={{ mb: 2 }}>
          You can view the configuration, but only an administrator can change it.
        </Alert>
      )}

      <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
        <CardContent>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <FormControlLabel
              control={<Switch checked={!!form.enabled} disabled={!isAdmin}
                onChange={(e) => set("enabled", e.target.checked)} />}
              label={<Typography sx={{ color: "text.primary", fontWeight: 600 }}>Email enabled</Typography>}
            />
            {form.enabled
              ? <Chip size="small" icon={<CheckCircle />} label="On" sx={{ bgcolor: "rgba(52,168,83,0.15)", color: "#34A853" }} />
              : <Chip size="small" label="Off" sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />}
          </Box>
          <Divider sx={{ mb: 2, borderColor: "divider" }} />

          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 4 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "text.secondary" }}>Provider</InputLabel>
                <Select value={form.provider || "office365"} label="Provider" disabled={!isAdmin}
                  onChange={(e) => onProviderChange(e.target.value)} sx={{ color: "text.primary" }}>
                  <MenuItem value="office365">Office 365</MenuItem>
                  <MenuItem value="gmail">Gmail / Google Workspace</MenuItem>
                  <MenuItem value="smtp">Custom SMTP</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 5 }}>
              <TextField fullWidth size="small" label="SMTP Host" value={form.smtp_host || ""} disabled={!isAdmin}
                onChange={(e) => set("smtp_host", e.target.value)} placeholder="smtp.office365.com" />
            </Grid>
            <Grid size={{ xs: 6, sm: 3 }}>
              <TextField fullWidth size="small" type="number" label="Port" value={form.smtp_port ?? 587} disabled={!isAdmin}
                onChange={(e) => set("smtp_port", parseInt(e.target.value || "587", 10))} />
            </Grid>

            <Grid size={{ xs: 12, sm: 4 }}>
              <FormControl fullWidth size="small">
                <InputLabel sx={{ color: "text.secondary" }}>Security</InputLabel>
                <Select value={form.smtp_security || "starttls"} label="Security" disabled={!isAdmin}
                  onChange={(e) => set("smtp_security", e.target.value)} sx={{ color: "text.primary" }}>
                  <MenuItem value="starttls">STARTTLS (587)</MenuItem>
                  <MenuItem value="ssl">SSL / TLS (465)</MenuItem>
                  <MenuItem value="none">None</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 8 }}>
              <TextField fullWidth size="small" label="SMTP Username" value={form.smtp_username || ""} disabled={!isAdmin}
                onChange={(e) => set("smtp_username", e.target.value)} placeholder="reports@yourdomain.com" />
            </Grid>

            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" type={showPassword ? "text" : "password"}
                label="SMTP Password" disabled={!isAdmin}
                value={password ?? ""}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={pwConfigured ? "•••••••• (unchanged)" : "app password"}
                helperText={pwConfigured ? "A password is saved. Type to replace it; leave blank to keep." : "For Office 365 with MFA, use an app password."}
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton size="small" onClick={() => setShowPassword((s) => !s)} edge="end">
                        {showPassword ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="From Address" value={form.from_address || ""} disabled={!isAdmin}
                onChange={(e) => set("from_address", e.target.value)} placeholder="reports@yourdomain.com"
                helperText="Defaults to the SMTP username if left blank." />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="From Name" value={form.from_name || ""} disabled={!isAdmin}
                onChange={(e) => set("from_name", e.target.value)} placeholder="NexGenCyberAI Reports" />
            </Grid>
          </Grid>

          <Box sx={{ display: "flex", justifyContent: "flex-end", mt: 2 }}>
            <Button variant="contained" startIcon={<Save />} disabled={!isAdmin || saveMutation.isPending}
              onClick={() => saveMutation.mutate()}
              sx={{ bgcolor: ACCENT, color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}>
              {saveMutation.isPending ? "Saving…" : "Save"}
            </Button>
          </Box>
        </CardContent>
      </Card>

      <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
        <CardContent>
          <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 700, mb: 1 }}>Send a test email</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>
            Verify the relay works. Save your settings first.
          </Typography>
          <Box sx={{ display: "flex", gap: 1, alignItems: "flex-start" }}>
            <TextField size="small" label="Send to" value={testTo} disabled={!isAdmin}
              onChange={(e) => setTestTo(e.target.value)} placeholder="you@yourdomain.com" sx={{ flex: 1, maxWidth: 360 }} />
            <Button variant="outlined" startIcon={<Send />} disabled={!isAdmin || !testTo || testMutation.isPending}
              onClick={() => testMutation.mutate()}
              sx={{ color: ACCENT, borderColor: "rgba(66,133,244,0.5)" }}>
              {testMutation.isPending ? "Sending…" : "Send test"}
            </Button>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}
