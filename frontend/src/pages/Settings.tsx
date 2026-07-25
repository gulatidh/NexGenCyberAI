/**
 * Settings — unified hub for all platform configuration.
 *
 * Tabs (vertical sidebar):
 *   General     — platform info & current session
 *   Email       — SMTP / outbound email config
 *   SSO / Identity — Azure Entra ID / tenant connection
 *   Data Sync   — threat-intel & CVE feed sync (admin)
 *   Access Logs — audit trail (admin)
 *   Users       — user access management (admin)
 */
import React, { useState, useEffect } from "react";
import {
  Box, Typography, Tabs, Tab, Card, CardContent,
  TextField, Button, Switch, FormControlLabel, Alert,
  Chip, Divider, CircularProgress, IconButton, InputAdornment,
  Tooltip, Grid, Select, MenuItem, FormControl, InputLabel,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  Dialog, DialogTitle, DialogContent, DialogActions, Pagination,
  Drawer,
} from "@mui/material";
import {
  Settings as SettingsIcon, MarkEmailRead, Security, Sync as SyncIcon,
  History, AdminPanelSettings, Save, CheckCircle,
  Visibility, VisibilityOff, LinkOutlined,
  Refresh, Add, Delete, EditNote, Public, Apartment, FolderOpen,
  Close, Send, RestoreFromTrash, DeleteForever, DeleteSweep,
  NewReleases, Psychology, Webhook, VpnKey,
} from "@mui/icons-material";
import Skeleton from "@mui/material/Skeleton";
import LinearProgress from "@mui/material/LinearProgress";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";
import { emailApi, ssoApi, adminApi, clientsApi, projectsApi, changelogApi } from "../services/api";
import { MyAccess, AccessRole, AccessScope, Client, Project, UserAccessSummary } from "../types";
import AISettings from "./AISettings";
import Webhooks from "./Webhooks";
import APIKeysPage from "./APIKeysPage";
import { fmt, fromNow } from "../utils/datetime";

const ACCENT = "#4285F4";

// ── helpers ─────────────────────────────────────────────────────────────────
function TabPanel({ value, index, children }: { value: number; index: number; children: React.ReactNode }) {
  return value === index ? <Box sx={{ flexGrow: 1, overflow: "auto", p: 3 }}>{children}</Box> : null;
}

function SectionHeader({ icon, title, subtitle }: { icon: React.ReactNode; title: string; subtitle?: string }) {
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 3 }}>
      <Box sx={{ color: ACCENT }}>{icon}</Box>
      <Box>
        <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1 }}>{title}</Typography>
        {subtitle && <Typography variant="caption" sx={{ color: "text.secondary" }}>{subtitle}</Typography>}
      </Box>
    </Box>
  );
}

// ── General tab ──────────────────────────────────────────────────────────────
function GeneralTab({ me }: { me?: MyAccess }) {
  return (
    <Box>
      <SectionHeader icon={<SettingsIcon />} title="General" subtitle="Platform information and your current session" />
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle2" sx={{ color: "text.secondary", mb: 2, fontWeight: 700, textTransform: "uppercase", fontSize: 11, letterSpacing: 1 }}>Platform</Typography>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                {[
                  ["Application", "Monitara AI — NexGenCyberAI"],
                  ["Version", "1.0"],
                  ["Stack", "FastAPI + React + MUI v6"],
                  ["Auth", "Microsoft Entra ID (MSAL)"],
                ].map(([k, v]) => (
                  <Box key={k} sx={{ display: "flex", justifyContent: "space-between" }}>
                    <Typography variant="body2" sx={{ color: "text.secondary" }}>{k}</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>{v}</Typography>
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle2" sx={{ color: "text.secondary", mb: 2, fontWeight: 700, textTransform: "uppercase", fontSize: 11, letterSpacing: 1 }}>Your Session</Typography>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                {[
                  ["Email", me?.email || "—"],
                  ["Role", me?.is_admin ? "Admin" : me?.is_editor_anywhere ? "Editor" : "Reader"],
                  ["Admin", me?.is_admin ? "Yes" : "No"],
                  ["Editor anywhere", me?.is_editor_anywhere ? "Yes" : "No"],
                ].map(([k, v]) => (
                  <Box key={k} sx={{ display: "flex", justifyContent: "space-between" }}>
                    <Typography variant="body2" sx={{ color: "text.secondary" }}>{k}</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>{v as string}</Typography>
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

// ── Email tab ────────────────────────────────────────────────────────────────
const EMAIL_PRESETS: Record<string, any> = {
  office365: { smtp_host: "smtp.office365.com", smtp_port: 587, smtp_security: "starttls" },
  gmail:     { smtp_host: "smtp.gmail.com",     smtp_port: 587, smtp_security: "starttls" },
  smtp:      {},
};

function EmailTab({ isAdmin }: { isAdmin: boolean }) {
  const qc = useQueryClient();
  const [form, setForm] = useState<Record<string, any>>({});
  const [password, setPassword] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [testTo, setTestTo] = useState("");

  const { data: cfg, isLoading } = useQuery({ queryKey: ["email-config"], queryFn: emailApi.getConfig });

  useEffect(() => {
    if (cfg) setForm({ ...cfg });
  }, [cfg]);

  const save = useMutation({
    mutationFn: (d: any) => emailApi.updateConfig(d),
    onSuccess: () => { toast.success("Email settings saved"); qc.invalidateQueries({ queryKey: ["email-config"] }); setPassword(null); },
    onError: () => toast.error("Failed to save email settings"),
  });
  const testMut = useMutation({
    mutationFn: () => emailApi.test(testTo),
    onSuccess: (r: any) => r.success ? toast.success("Test email sent!") : toast.error(`Test failed: ${r.error}`),
    onError: () => toast.error("Test send failed"),
  });

  const set = (k: string, v: any) => setForm((f) => ({ ...f, [k]: v }));

  if (isLoading) return <CircularProgress size={24} />;

  return (
    <Box>
      <SectionHeader icon={<MarkEmailRead />} title="Email Settings" subtitle="SMTP / outbound email configuration" />
      {!isAdmin && <Alert severity="info" sx={{ mb: 2 }}>Read-only — admin access required to edit email settings.</Alert>}
      <Card variant="outlined">
        <CardContent>
          <FormControlLabel
            control={<Switch checked={!!form.enabled} onChange={(e) => set("enabled", e.target.checked)} disabled={!isAdmin} />}
            label={<Typography variant="body2" sx={{ fontWeight: 600 }}>Enable outbound email</Typography>}
            sx={{ mb: 2 }}
          />
          <Divider sx={{ mb: 2 }} />
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 6 }}>
              <FormControl fullWidth size="small">
                <InputLabel>Provider</InputLabel>
                <Select value={form.provider || "office365"} label="Provider" disabled={!isAdmin}
                  onChange={(e) => {
                    const p = e.target.value as string;
                    setForm((f) => ({ ...f, provider: p, ...EMAIL_PRESETS[p] }));
                  }}>
                  <MenuItem value="office365">Office 365</MenuItem>
                  <MenuItem value="gmail">Gmail</MenuItem>
                  <MenuItem value="smtp">Custom SMTP</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="SMTP Host" value={form.smtp_host || ""} disabled={!isAdmin} onChange={(e) => set("smtp_host", e.target.value)} />
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <TextField fullWidth size="small" label="Port" type="number" value={form.smtp_port || 587} disabled={!isAdmin} onChange={(e) => set("smtp_port", parseInt(e.target.value))} />
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <FormControl fullWidth size="small">
                <InputLabel>Security</InputLabel>
                <Select value={form.smtp_security || "starttls"} label="Security" disabled={!isAdmin} onChange={(e) => set("smtp_security", e.target.value)}>
                  <MenuItem value="starttls">STARTTLS</MenuItem>
                  <MenuItem value="ssl">SSL/TLS</MenuItem>
                  <MenuItem value="none">None</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <TextField fullWidth size="small" label="Username" value={form.smtp_username || ""} disabled={!isAdmin} onChange={(e) => set("smtp_username", e.target.value)} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label={form.smtp_password_configured ? "Password (set — leave blank to keep)" : "Password"} type={showPassword ? "text" : "password"}
                value={password ?? ""} disabled={!isAdmin}
                onChange={(e) => setPassword(e.target.value || null)}
                slotProps={{ input: { endAdornment: <InputAdornment position="end"><IconButton size="small" onClick={() => setShowPassword((s) => !s)}>{showPassword ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}</IconButton></InputAdornment> } }} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="From Address" value={form.from_address || ""} disabled={!isAdmin} onChange={(e) => set("from_address", e.target.value)} />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField fullWidth size="small" label="From Name" value={form.from_name || ""} disabled={!isAdmin} onChange={(e) => set("from_name", e.target.value)} />
            </Grid>
          </Grid>
          {isAdmin && (
            <Box sx={{ display: "flex", gap: 1.5, mt: 2, flexWrap: "wrap" }}>
              <Button variant="contained" size="small" startIcon={save.isPending ? <CircularProgress size={14} color="inherit" /> : <Save fontSize="small" />}
                onClick={() => save.mutate({ ...form, ...(password !== null ? { smtp_password: password } : {}) })} disabled={save.isPending}>
                Save
              </Button>
              <Box sx={{ display: "flex", gap: 1, alignItems: "center", ml: "auto" }}>
                <TextField size="small" label="Test recipient" value={testTo} onChange={(e) => setTestTo(e.target.value)} sx={{ width: 220 }} />
                <Button variant="outlined" size="small" startIcon={<Send fontSize="small" />} onClick={() => testMut.mutate()} disabled={!testTo || testMut.isPending}>
                  Send test
                </Button>
              </Box>
            </Box>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}

// ── SSO / Identity tab ───────────────────────────────────────────────────────
function SsoTab({ isAdmin }: { isAdmin: boolean }) {
  const qc = useQueryClient();
  const [form, setForm] = useState<Record<string, any>>({});
  const [secret, setSecret] = useState<string | null>(null);
  const [showSecret, setShowSecret] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const { data: cfg, isLoading } = useQuery({ queryKey: ["sso-config"], queryFn: ssoApi.getConfig });

  useEffect(() => {
    if (cfg) setForm({ ...cfg });
  }, [cfg]);

  const save = useMutation({
    mutationFn: (d: any) => ssoApi.updateConfig(d),
    onSuccess: () => { toast.success("SSO settings saved"); qc.invalidateQueries({ queryKey: ["sso-config"] }); setSecret(null); },
    onError: () => toast.error("Failed to save SSO settings"),
  });
  const testMut = useMutation({
    mutationFn: () => ssoApi.test(),
    onSuccess: (r: any) => setTestResult(r),
    onError: () => setTestResult({ success: false, message: "Connection test failed" }),
  });

  const set = (k: string, v: any) => setForm((f) => ({ ...f, [k]: v }));

  if (isLoading) return <CircularProgress size={24} />;

  return (
    <Box>
      <SectionHeader
        icon={<Security />}
        title="SSO / Identity"
        subtitle="Azure Entra ID (Azure AD) tenant connection"
      />
      <Alert severity="info" sx={{ mb: 2.5 }}>
        These settings control which Azure AD tenant Monitara authenticates against. Changes take effect after the application is restarted or redeployed.
      </Alert>

      <Card variant="outlined" sx={{ mb: 2 }}>
        <CardContent>
          <FormControlLabel
            control={<Switch checked={!!form.enabled} onChange={(e) => set("enabled", e.target.checked)} disabled={!isAdmin} />}
            label={<Box><Typography variant="body2" sx={{ fontWeight: 600 }}>Enable SSO</Typography><Typography variant="caption" sx={{ color: "text.secondary" }}>When disabled the app falls back to env-var MSAL config</Typography></Box>}
            sx={{ mb: 2 }}
          />
          <Divider sx={{ mb: 2 }} />
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="Tenant ID" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                value={form.tenant_id || ""} disabled={!isAdmin}
                helperText="Azure AD tenant (Directory) ID"
                onChange={(e) => {
                  const tid = e.target.value;
                  setForm((f) => ({ ...f, tenant_id: tid, authority: tid ? `https://login.microsoftonline.com/${tid}` : "" }));
                }} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="Client ID (App Registration)" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                value={form.client_id || ""} disabled={!isAdmin}
                helperText="Application (client) ID of the Monitara app registration"
                onChange={(e) => set("client_id", e.target.value)} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small"
                label={form.client_secret_configured ? "Client Secret (set — leave blank to keep)" : "Client Secret"}
                type={showSecret ? "text" : "password"}
                value={secret ?? ""} disabled={!isAdmin}
                helperText="App registration client secret value"
                onChange={(e) => setSecret(e.target.value || null)}
                slotProps={{ input: { endAdornment: <InputAdornment position="end"><IconButton size="small" onClick={() => setShowSecret((s) => !s)}>{showSecret ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}</IconButton></InputAdornment> } }} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField fullWidth size="small" label="Redirect URI"
                placeholder="https://your-app.azurewebsites.net"
                value={form.redirect_uri || ""} disabled={!isAdmin}
                helperText="Must match the redirect URI registered in Azure AD"
                onChange={(e) => set("redirect_uri", e.target.value)} />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField fullWidth size="small" label="Authority URL (auto-computed)"
                value={form.authority || ""} disabled
                helperText="https://login.microsoftonline.com/{tenant-id}" />
            </Grid>
          </Grid>

          {testResult && (
            <Alert severity={testResult.success ? "success" : "error"} sx={{ mt: 2 }} onClose={() => setTestResult(null)}>
              {testResult.message}
            </Alert>
          )}

          {isAdmin && (
            <Box sx={{ display: "flex", gap: 1.5, mt: 2, flexWrap: "wrap", alignItems: "center" }}>
              <Button variant="contained" size="small" startIcon={save.isPending ? <CircularProgress size={14} color="inherit" /> : <Save fontSize="small" />}
                onClick={() => save.mutate({ ...form, ...(secret !== null ? { client_secret: secret } : {}) })} disabled={save.isPending}>
                Save
              </Button>
              <Button variant="outlined" size="small"
                startIcon={testMut.isPending ? <CircularProgress size={14} color="inherit" /> : (testResult?.success ? <CheckCircle fontSize="small" sx={{ color: "#34A853" }} /> : <LinkOutlined fontSize="small" />)}
                onClick={() => testMut.mutate()} disabled={testMut.isPending || !form.tenant_id}>
                Test connection
              </Button>
              {cfg?.updated_at && (
                <Typography variant="caption" sx={{ color: "text.secondary", ml: "auto" }}>
                  Last updated {fromNow(cfg.updated_at)} {cfg.updated_by ? `by ${cfg.updated_by}` : ""}
                </Typography>
              )}
            </Box>
          )}
        </CardContent>
      </Card>

      <Card variant="outlined">
        <CardContent>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>App Registration Requirements</Typography>
          <Box component="ul" sx={{ m: 0, pl: 2, "& li": { typography: "body2", color: "text.secondary", mb: 0.5 } }}>
            <li>Platform: <strong>Single-page application (SPA)</strong></li>
            <li>Redirect URI must match the <strong>Redirect URI</strong> field above</li>
            <li>API permissions: <strong>User.Read</strong> (Microsoft Graph)</li>
            <li>Token type: <strong>Access tokens + ID tokens</strong> checked under Authentication</li>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}

// ── Sync tab ─────────────────────────────────────────────────────────────────
function SyncTab({ isAdmin }: { isAdmin: boolean }) {
  const [syncing, setSyncing] = useState<string | null>(null);
  const [drawerFeed, setDrawerFeed] = useState<any>(null);

  const { data: feeds = [], isLoading, refetch } = useQuery<any[]>({
    queryKey: ["sync-feeds"],
    queryFn: () => adminApi.listSyncFeeds(),
    enabled: isAdmin,
  });

  const doSync = async (id: string) => {
    setSyncing(id);
    try {
      await adminApi.refreshSyncFeed(id);
      toast.success("Sync started");
      setTimeout(() => { refetch(); setSyncing(null); }, 3000);
    } catch { toast.error("Sync failed"); setSyncing(null); }
  };
  const doSyncAll = async () => {
    setSyncing("all");
    try {
      await adminApi.refreshAllSyncFeeds();
      toast.success("All feeds synced");
      setTimeout(() => { refetch(); setSyncing(null); }, 3000);
    } catch { toast.error("Sync all failed"); setSyncing(null); }
  };

  if (!isAdmin) return <Alert severity="warning">Admin access required to manage data sync.</Alert>;
  if (isLoading) return <CircularProgress size={24} />;

  const CATEGORY_COLOR: Record<string, string> = {
    threat_intel: "#EA4335", cve: "#FBBC04", framework: "#4285F4", threat_library: "#34A853",
  };

  return (
    <Box>
      <SectionHeader icon={<SyncIcon />} title="Data Sync" subtitle="Threat intelligence, CVE, and framework feed synchronisation" />
      <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2 }}>
        <Button variant="contained" size="small" startIcon={syncing === "all" ? <CircularProgress size={14} color="inherit" /> : <SyncIcon fontSize="small" />}
          onClick={doSyncAll} disabled={syncing !== null}>Sync all</Button>
      </Box>
      <Grid container spacing={2}>
        {feeds.map((feed: any) => (
          <Grid key={feed.id} size={{ xs: 12, sm: 6, md: 4 }}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                  <Chip label={feed.category} size="small" sx={{ bgcolor: CATEGORY_COLOR[feed.category] + "22", color: CATEGORY_COLOR[feed.category], fontSize: 10 }} />
                  <Chip label={`${feed.count ?? 0} ${feed.item_label || "items"}`} size="small" variant="outlined" sx={{ fontSize: 10 }} />
                </Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>{feed.name}</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>{feed.description}</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  {feed.last_synced_at ? `Last synced ${fromNow(feed.last_synced_at)}` : "Never synced"}
                </Typography>
                <Box sx={{ display: "flex", gap: 1, mt: 1.5 }}>
                  <Button size="small" variant="outlined" startIcon={syncing === feed.id ? <CircularProgress size={12} color="inherit" /> : <SyncIcon fontSize="small" />}
                    onClick={() => doSync(feed.id)} disabled={syncing !== null} sx={{ fontSize: 11 }}>Sync</Button>
                  <Button size="small" variant="text" onClick={() => setDrawerFeed(feed)} sx={{ fontSize: 11 }}>Details</Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Drawer anchor="right" open={!!drawerFeed} onClose={() => setDrawerFeed(null)} slotProps={{ paper: { sx: { width: 400, p: 3 } } }}>
        {drawerFeed && (
          <>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 2 }}>
              <Typography variant="h6" sx={{ fontWeight: 700 }}>{drawerFeed.name}</Typography>
              <IconButton size="small" onClick={() => setDrawerFeed(null)}><Close fontSize="small" /></IconButton>
            </Box>
            <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>{drawerFeed.description}</Typography>
            {drawerFeed.source_url && <Typography variant="caption" sx={{ wordBreak: "break-all", color: ACCENT }}>{drawerFeed.source_url}</Typography>}
          </>
        )}
      </Drawer>
    </Box>
  );
}

// ── Access Logs tab ──────────────────────────────────────────────────────────
const PAGE_SIZE = 50;

function AccessLogsTab({ isAdmin }: { isAdmin: boolean }) {
  const [userEmail, setUserEmail] = useState("");
  const [method, setMethod] = useState("");
  const [sinceHours, setSinceHours] = useState<number | "">(24);
  const [page, setPage] = useState(1);

  const params = { user_email: userEmail || undefined, method: method || undefined, since_hours: sinceHours || undefined, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE };
  const { data, isLoading, refetch } = useQuery<any>({ queryKey: ["access-logs", params], queryFn: () => adminApi.accessLogs(params), enabled: isAdmin });

  function statusColor(s?: number) {
    if (!s) return "#9e9e9e";
    if (s >= 500) return "#EA4335";
    if (s >= 400) return "#FF7043";
    if (s >= 300) return "#FBBC04";
    return "#34A853";
  }

  if (!isAdmin) return <Alert severity="warning">Admin access required to view access logs.</Alert>;

  return (
    <Box>
      <SectionHeader icon={<History />} title="Access Logs" subtitle="Audit trail of authenticated API requests" />
      <Box sx={{ display: "flex", gap: 1.5, mb: 2, flexWrap: "wrap", alignItems: "center" }}>
        <TextField size="small" label="User email" value={userEmail} onChange={(e) => setUserEmail(e.target.value)} sx={{ width: 220 }} />
        <FormControl size="small" sx={{ width: 110 }}>
          <InputLabel>Method</InputLabel>
          <Select value={method} label="Method" onChange={(e) => setMethod(e.target.value)}>
            <MenuItem value="">All</MenuItem>
            {["GET", "POST", "PATCH", "PUT", "DELETE"].map((m) => <MenuItem key={m} value={m}>{m}</MenuItem>)}
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ width: 130 }}>
          <InputLabel>Time range</InputLabel>
          <Select value={sinceHours} label="Time range" onChange={(e) => setSinceHours(e.target.value as number)}>
            {[1, 6, 24, 48, 168].map((h) => <MenuItem key={h} value={h}>{h === 168 ? "7 days" : `${h}h`}</MenuItem>)}
          </Select>
        </FormControl>
        <IconButton size="small" onClick={() => refetch()}><Refresh /></IconButton>
      </Box>
      {isLoading ? <CircularProgress size={24} /> : (
        <>
          <TableContainer component={Card} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  {["Time", "User", "Method", "Path", "Status", "IP"].map((h) => (
                    <TableCell key={h} sx={{ fontWeight: 700, fontSize: 11 }}>{h}</TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {(data?.items || []).map((row: any) => (
                  <TableRow key={row.id} hover>
                    <TableCell sx={{ fontSize: 11, whiteSpace: "nowrap" }}>{fmt(row.created_at)}</TableCell>
                    <TableCell sx={{ fontSize: 11 }}>{row.user_email || "—"}</TableCell>
                    <TableCell><Chip label={row.method || "?"} size="small" sx={{ fontSize: 10, height: 18 }} /></TableCell>
                    <TableCell sx={{ fontSize: 11, maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.path}</TableCell>
                    <TableCell><Chip label={row.status_code || "?"} size="small" sx={{ bgcolor: statusColor(row.status_code) + "22", color: statusColor(row.status_code), fontSize: 10, height: 18 }} /></TableCell>
                    <TableCell sx={{ fontSize: 11 }}>{row.ip_address || "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          {data?.total > PAGE_SIZE && (
            <Box sx={{ display: "flex", justifyContent: "center", mt: 2 }}>
              <Pagination count={Math.ceil(data.total / PAGE_SIZE)} page={page} onChange={(_, p) => setPage(p)} size="small" />
            </Box>
          )}
        </>
      )}
    </Box>
  );
}

// ── Users tab ────────────────────────────────────────────────────────────────
const ROLE_COLOR: Record<AccessRole, string> = { admin: "#f06292", editor: "#4285F4", reader: "rgba(255,255,255,0.6)" };
const ROLE_ICON: Record<AccessRole, React.ReactNode> = {
  admin: <AdminPanelSettings sx={{ fontSize: 14 }} />,
  editor: <EditNote sx={{ fontSize: 14 }} />,
  reader: <Visibility sx={{ fontSize: 14 }} />,
};
const SCOPE_ICON: Record<AccessScope, React.ReactNode> = {
  global: <Public sx={{ fontSize: 14 }} />,
  client: <Apartment sx={{ fontSize: 14 }} />,
  project: <FolderOpen sx={{ fontSize: 14 }} />,
};

function UsersTab({ isAdmin }: { isAdmin: boolean }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<{ email: string; role: AccessRole; scope: AccessScope; client_id: string; project_id: string }>({ email: "", role: "reader", scope: "global", client_id: "", project_id: "" });

  const { data: users = [] } = useQuery<UserAccessSummary[]>({ queryKey: ["admin-users"], queryFn: adminApi.listUsers, enabled: isAdmin });
  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: () => clientsApi.list(), enabled: isAdmin && form.scope !== "global" });
  const { data: projects = [] } = useQuery<Project[]>({ queryKey: ["projects", form.client_id], queryFn: () => projectsApi.list(form.client_id), enabled: isAdmin && form.scope === "project" && !!form.client_id });

  const grant = useMutation({
    mutationFn: (d: any) => adminApi.createGrant(d),
    onSuccess: () => { toast.success("Access granted"); qc.invalidateQueries({ queryKey: ["admin-users"] }); setOpen(false); setForm({ email: "", role: "reader", scope: "global", client_id: "", project_id: "" }); },
    onError: () => toast.error("Failed to grant access"),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => adminApi.deleteGrant(id),
    onSuccess: () => { toast.success("Access revoked"); qc.invalidateQueries({ queryKey: ["admin-users"] }); },
    onError: () => toast.error("Failed to revoke access"),
  });

  if (!isAdmin) return <Alert severity="warning">Admin access required to manage users.</Alert>;

  return (
    <Box>
      <SectionHeader icon={<AdminPanelSettings />} title="User Management" subtitle="Grant and revoke platform access" />
      <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2 }}>
        <Button variant="contained" size="small" startIcon={<Add />} onClick={() => setOpen(true)}>Grant access</Button>
      </Box>
      <TableContainer component={Card} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              {["User", "Role", "Scope", "Target", "Granted", ""].map((h, i) => (
                <TableCell key={i} sx={{ fontWeight: 700, fontSize: 11 }}>{h}</TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {users.flatMap((u: UserAccessSummary) => u.grants.map((g: any) => (
              <TableRow key={g.id} hover>
                <TableCell sx={{ fontSize: 12 }}>{u.email}</TableCell>
                <TableCell>
                  <Chip icon={ROLE_ICON[g.role as AccessRole] as any} label={g.role}
                    size="small" sx={{ bgcolor: ROLE_COLOR[g.role as AccessRole] + "22", color: ROLE_COLOR[g.role as AccessRole], fontSize: 10, height: 20 }} />
                </TableCell>
                <TableCell>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, color: "text.secondary" }}>
                    {SCOPE_ICON[g.scope as AccessScope]}<Typography variant="caption">{g.scope}</Typography>
                  </Box>
                </TableCell>
                <TableCell sx={{ fontSize: 11 }}>{g.client_name || g.project_name || "—"}</TableCell>
                <TableCell sx={{ fontSize: 11 }}>{g.granted_at ? fmt(g.granted_at) : "—"}</TableCell>
                <TableCell>
                  <Tooltip title="Revoke">
                    <IconButton size="small" onClick={() => revoke.mutate(g.id)} sx={{ color: "#EA4335" }}><Delete fontSize="small" /></IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            )))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Grant access</DialogTitle>
        <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2, pt: 2 }}>
          <TextField size="small" label="Email" value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} fullWidth />
          <FormControl size="small" fullWidth>
            <InputLabel>Role</InputLabel>
            <Select value={form.role} label="Role" onChange={(e) => setForm((f) => ({ ...f, role: e.target.value as AccessRole }))}>
              <MenuItem value="reader">Reader</MenuItem>
              <MenuItem value="editor">Editor</MenuItem>
              <MenuItem value="admin">Admin</MenuItem>
            </Select>
          </FormControl>
          <FormControl size="small" fullWidth>
            <InputLabel>Scope</InputLabel>
            <Select value={form.scope} label="Scope" onChange={(e) => setForm((f) => ({ ...f, scope: e.target.value as AccessScope, client_id: "", project_id: "" }))}>
              <MenuItem value="global">Global</MenuItem>
              <MenuItem value="client">Client</MenuItem>
              <MenuItem value="project">Project</MenuItem>
            </Select>
          </FormControl>
          {form.scope === "client" && (
            <FormControl size="small" fullWidth>
              <InputLabel>Client</InputLabel>
              <Select value={form.client_id} label="Client" onChange={(e) => setForm((f) => ({ ...f, client_id: e.target.value }))}>
                {(clients as Client[]).map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
              </Select>
            </FormControl>
          )}
          {form.scope === "project" && (
            <FormControl size="small" fullWidth>
              <InputLabel>Project</InputLabel>
              <Select value={form.project_id} label="Project" onChange={(e) => setForm((f) => ({ ...f, project_id: e.target.value }))}>
                {(projects as Project[]).map((p: any) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
              </Select>
            </FormControl>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={() => grant.mutate(form)} disabled={!form.email || grant.isPending}>Grant</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

// ── Deleted Clients tab ──────────────────────────────────────────────────────
function DeletedClientsTab({ isAdmin }: { isAdmin: boolean }) {
  const qc = useQueryClient();
  const [confirmPerm, setConfirmPerm] = useState<any | null>(null);

  const { data: deletedClients = [], isLoading, refetch } = useQuery<any[]>({
    queryKey: ["admin-deleted-clients"],
    queryFn: adminApi.listDeletedClients,
    enabled: isAdmin,
    refetchInterval: 30_000,
  });

  const restoreMut = useMutation({
    mutationFn: (id: string) => adminApi.restoreClient(id),
    onSuccess: () => {
      toast.success("Client restored successfully");
      qc.invalidateQueries({ queryKey: ["admin-deleted-clients"] });
      qc.invalidateQueries({ queryKey: ["clients"] });
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Restore failed"),
  });

  const permDeleteMut = useMutation({
    mutationFn: (id: string) => adminApi.permanentlyDeleteClient(id),
    onSuccess: () => {
      toast.success("Client permanently deleted");
      qc.invalidateQueries({ queryKey: ["admin-deleted-clients"] });
      setConfirmPerm(null);
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Delete failed"),
  });

  const purgeMut = useMutation({
    mutationFn: adminApi.purgeExpiredClients,
    onSuccess: (r: any) => {
      toast.success(`Purged ${r.purged_count ?? 0} expired client(s)`);
      qc.invalidateQueries({ queryKey: ["admin-deleted-clients"] });
      qc.invalidateQueries({ queryKey: ["clients"] });
    },
    onError: () => toast.error("Purge failed"),
  });

  if (!isAdmin) return <Alert severity="warning">Admin access required to manage deleted clients.</Alert>;

  function retentionColor(daysRemaining: number): string {
    if (daysRemaining <= 3) return "#EA4335";
    if (daysRemaining <= 10) return "#FBBC04";
    return "#34A853";
  }

  const expiredCount = deletedClients.filter((c: any) => c.auto_purge_eligible).length;

  return (
    <Box>
      <SectionHeader
        icon={<DeleteSweep />}
        title="Deleted Clients"
        subtitle="Soft-deleted clients — restorable within 30 days, then auto-purged"
      />

      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="body2" sx={{ color: "text.secondary" }}>
          {deletedClients.length} client{deletedClients.length !== 1 ? "s" : ""} in trash
          {expiredCount > 0 && (
            <Chip label={`${expiredCount} expired`} size="small" sx={{ ml: 1, bgcolor: "#EA433522", color: "#EA4335", fontSize: 10 }} />
          )}
        </Typography>
        <Box sx={{ display: "flex", gap: 1 }}>
          <IconButton size="small" onClick={() => refetch()}><Refresh fontSize="small" /></IconButton>
          {expiredCount > 0 && (
            <Button size="small" variant="outlined" color="error"
              startIcon={purgeMut.isPending ? <CircularProgress size={12} color="inherit" /> : <DeleteForever fontSize="small" />}
              onClick={() => purgeMut.mutate()} disabled={purgeMut.isPending}>
              Purge {expiredCount} expired
            </Button>
          )}
        </Box>
      </Box>

      {isLoading ? (
        <CircularProgress size={24} />
      ) : deletedClients.length === 0 ? (
        <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
          <RestoreFromTrash sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>No deleted clients — the trash is empty.</Typography>
        </Card>
      ) : (
        <TableContainer component={Card} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                {["Client", "Deleted On", "Days Remaining", "Status", "Actions"].map((h) => (
                  <TableCell key={h} sx={{ fontWeight: 700, fontSize: 11 }}>{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {deletedClients.map((c: any) => {
                const pct = Math.max(0, Math.min(100, (c.days_remaining / 30) * 100));
                const color = retentionColor(c.days_remaining);
                const expired = c.auto_purge_eligible;
                return (
                  <TableRow key={c.id} hover sx={{ opacity: expired ? 0.7 : 1 }}>
                    <TableCell>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Box sx={{ width: 28, height: 28, borderRadius: "50%", bgcolor: "#4285F422", display: "flex", alignItems: "center", justifyContent: "center" }}>
                          <Typography sx={{ fontSize: 12, fontWeight: 700, color: "#4285F4" }}>{c.name?.charAt(0)}</Typography>
                        </Box>
                        <Box>
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>{c.name}</Typography>
                          {c.industry && <Typography variant="caption" sx={{ color: "text.secondary" }}>{c.industry}</Typography>}
                        </Box>
                      </Box>
                    </TableCell>
                    <TableCell sx={{ fontSize: 11, whiteSpace: "nowrap" }}>{fmt(c.deleted_at)}</TableCell>
                    <TableCell sx={{ minWidth: 140 }}>
                      {expired ? (
                        <Chip label="Expired — eligible for purge" size="small" sx={{ bgcolor: "#EA433522", color: "#EA4335", fontSize: 10 }} />
                      ) : (
                        <Box>
                          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
                            <Typography variant="caption" sx={{ color, fontWeight: 700 }}>{c.days_remaining}d left</Typography>
                            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>expires {fmt(c.expires_at)}</Typography>
                          </Box>
                          <LinearProgress variant="determinate" value={pct}
                            sx={{ height: 5, borderRadius: 3, bgcolor: "rgba(255,255,255,0.08)",
                              "& .MuiLinearProgress-bar": { bgcolor: color, borderRadius: 3 } }} />
                        </Box>
                      )}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={expired ? "Expired" : "Recoverable"}
                        size="small"
                        sx={{ fontSize: 10, height: 20,
                          bgcolor: expired ? "#EA433522" : "#34A85322",
                          color: expired ? "#EA4335" : "#34A853" }}
                      />
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: "flex", gap: 0.5 }}>
                        {!expired && (
                          <Tooltip title="Restore client">
                            <IconButton size="small" sx={{ color: "#34A853" }}
                              onClick={() => restoreMut.mutate(c.id)}
                              disabled={restoreMut.isPending}>
                              <RestoreFromTrash fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                        <Tooltip title="Permanently delete — cannot be undone">
                          <IconButton size="small" sx={{ color: "#EA4335" }}
                            onClick={() => setConfirmPerm(c)}>
                            <DeleteForever fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Permanent delete confirmation */}
      <Dialog open={Boolean(confirmPerm)} onClose={() => setConfirmPerm(null)}
        slotProps={{ paper: { sx: { bgcolor: "background.paper", minWidth: 440 } } }}>
        <DialogTitle sx={{ color: "#EA4335", display: "flex", alignItems: "center", gap: 1 }}>
          <DeleteForever /> Permanently Delete Client?
        </DialogTitle>
        <DialogContent>
          <Alert severity="error" sx={{ mb: 2 }}>
            This action is <strong>irreversible</strong>. All scans, findings, connectors, and risk data for this client will be permanently erased.
          </Alert>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            You are about to permanently delete <strong style={{ color: "white" }}>{confirmPerm?.name}</strong> and all its associated data.
            This cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setConfirmPerm(null)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button variant="contained"
            onClick={() => confirmPerm && permDeleteMut.mutate(confirmPerm.id)}
            disabled={permDeleteMut.isPending}
            sx={{ bgcolor: "#EA4335", color: "#fff", "&:hover": { bgcolor: "#c62828" } }}>
            {permDeleteMut.isPending ? <CircularProgress size={18} sx={{ color: "#fff" }} /> : "Delete Forever"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

// ── What's New tab ───────────────────────────────────────────────────────────
function WhatsNewTab() {
  const { data: entries = [], isLoading } = useQuery<any[]>({
    queryKey: ["changelog"],
    queryFn: changelogApi.list,
    staleTime: 5 * 60_000,
  });

  return (
    <Box>
      <SectionHeader
        icon={<NewReleases />}
        title="What's New"
        subtitle="Auto-generated on every deploy — AI summarises the latest changes"
      />

      {isLoading ? (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {[1, 2, 3].map((i) => (
            <Card key={i} variant="outlined">
              <CardContent>
                <Skeleton width="40%" height={24} sx={{ mb: 1 }} />
                <Skeleton width="100%" />
                <Skeleton width="90%" />
                <Skeleton width="95%" />
              </CardContent>
            </Card>
          ))}
        </Box>
      ) : entries.length === 0 ? (
        <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
          <NewReleases sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No updates recorded yet — deploys will appear here automatically.
          </Typography>
        </Card>
      ) : (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {entries.map((entry: any, idx: number) => {
            const bulletLines = (entry.summary || "")
              .split("\n")
              .map((l: string) => l.trim())
              .filter(Boolean);
            const commitCount = (entry.raw_commits || []).length;
            const shortSha = entry.commit_sha ? entry.commit_sha.slice(0, 7) : "unknown";
            const deployedDate = entry.deployed_at
              ? new Date(entry.deployed_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })
              : "—";

            const flowLabel = entry.flow_id && entry.flow_id !== "local"
              ? `Run #${entry.flow_id}`
              : (entry.flow_id || "local");

            return (
              <Card key={entry.id} variant="outlined" sx={{ borderLeft: idx === 0 ? `3px solid ${ACCENT}` : undefined }}>
                <CardContent>
                  {/* Header row: [Latest]  Flow: Run#xxx  •  Jul 4, 2026 */}
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5, flexWrap: "wrap" }}>
                    {idx === 0 && (
                      <Chip label="Latest" size="small" color="primary" sx={{ fontSize: 10, height: 20 }} />
                    )}
                    <Typography variant="body2" sx={{ fontWeight: 700, color: ACCENT }}>
                      Flow: {flowLabel}
                    </Typography>
                    <Typography variant="body2" sx={{ color: "text.disabled" }}>•</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      {deployedDate}
                    </Typography>
                  </Box>

                  {/* Description — LLM-generated bullet points */}
                  <Box sx={{ mb: 1.5 }}>
                    {bulletLines.length > 0 ? (
                      bulletLines.map((line: string, li: number) => (
                        <Typography
                          key={li}
                          variant="body2"
                          sx={{ color: "text.secondary", lineHeight: 1.7 }}
                        >
                          {line}
                        </Typography>
                      ))
                    ) : (
                      <Typography variant="body2" sx={{ color: "text.secondary", fontStyle: "italic" }}>
                        No summary available.
                      </Typography>
                    )}
                  </Box>

                  {/* Footer */}
                  <Divider sx={{ mb: 1 }} />
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>
                      {commitCount} commit{commitCount !== 1 ? "s" : ""}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>•</Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace" }}>
                      SHA: {shortSha}
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            );
          })}
        </Box>
      )}
    </Box>
  );
}

// ── Main Settings page ───────────────────────────────────────────────────────
const TABS = [
  { label: "General",          icon: <SettingsIcon fontSize="small" /> },
  { label: "What's New",       icon: <NewReleases fontSize="small" /> },
  { label: "Email",            icon: <MarkEmailRead fontSize="small" /> },
  { label: "SSO / Identity",   icon: <Security fontSize="small" /> },
  { label: "AI Providers",     icon: <Psychology fontSize="small" /> },
  { label: "Webhooks",         icon: <Webhook fontSize="small" /> },
  { label: "API Keys",         icon: <VpnKey fontSize="small" /> },
  { label: "Data Sync",        icon: <SyncIcon fontSize="small" />, adminOnly: true },
  { label: "Access Logs",      icon: <History fontSize="small" />, adminOnly: true },
  { label: "Users",            icon: <AdminPanelSettings fontSize="small" />, adminOnly: true },
  { label: "Deleted Clients",  icon: <DeleteSweep fontSize="small" />, adminOnly: true },
];

export default function Settings() {
  const [tab, setTab] = useState(0);

  const { data: me } = useQuery<MyAccess>({
    queryKey: ["my-access"], queryFn: adminApi.me, retry: 0, staleTime: 60_000,
  });
  const isAdmin = !!me?.is_admin;

  return (
    <Box sx={{ display: "flex", height: "100%", gap: 0 }}>
      {/* Vertical tab list */}
      <Box sx={{
        width: 200, flexShrink: 0, borderRight: "1px solid", borderColor: "divider",
        mr: 0, pr: 0,
      }}>
        <Typography variant="overline" sx={{ display: "block", px: 2, pt: 2, pb: 1, color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 1 }}>
          Settings
        </Typography>
        <Tabs
          orientation="vertical"
          value={tab}
          onChange={(_, v) => setTab(v)}
          sx={{
            "& .MuiTabs-indicator": { left: 0, width: 3 },
            "& .MuiTab-root": {
              alignItems: "flex-start", textAlign: "left", textTransform: "none",
              fontSize: 13, minHeight: 40, px: 2, py: 1,
              justifyContent: "flex-start",
            },
          }}
        >
          {TABS.map((t, i) => (
            <Tab
              key={t.label}
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  {t.icon}
                  <span>{t.label}</span>
                  {t.adminOnly && !isAdmin && (
                    <Chip label="Admin" size="small" sx={{ fontSize: 9, height: 16, ml: 0.5, opacity: 0.6 }} />
                  )}
                </Box>
              }
            />
          ))}
        </Tabs>
      </Box>

      {/* Tab panels */}
      <TabPanel value={tab} index={0}><GeneralTab me={me} /></TabPanel>
      <TabPanel value={tab} index={1}><WhatsNewTab /></TabPanel>
      <TabPanel value={tab} index={2}><EmailTab isAdmin={isAdmin} /></TabPanel>
      <TabPanel value={tab} index={3}><SsoTab isAdmin={isAdmin} /></TabPanel>
      <TabPanel value={tab} index={4}><AISettings /></TabPanel>
      <TabPanel value={tab} index={5}><Webhooks /></TabPanel>
      <TabPanel value={tab} index={6}><APIKeysPage /></TabPanel>
      <TabPanel value={tab} index={7}><SyncTab isAdmin={isAdmin} /></TabPanel>
      <TabPanel value={tab} index={8}><AccessLogsTab isAdmin={isAdmin} /></TabPanel>
      <TabPanel value={tab} index={9}><UsersTab isAdmin={isAdmin} /></TabPanel>
      <TabPanel value={tab} index={10}><DeletedClientsTab isAdmin={isAdmin} /></TabPanel>
    </Box>
  );
}
