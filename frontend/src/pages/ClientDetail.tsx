import React, { useState } from "react";
import {
  Box, Typography, Button, Card, CardContent, Chip, Grid, Avatar, IconButton,
  Table, TableHead, TableRow, TableCell, TableBody, CircularProgress, Divider,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField, Collapse,
  useTheme,
} from "@mui/material";
import {
  Cable, Scanner, FolderOpen, Storage as StorageIcon, OpenInNew, Add, Delete,
  BugReport, Dashboard as DashboardIcon, Edit, History, ExpandMore, MenuBook,
} from "@mui/icons-material";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip as ReTooltip, Cell, ResponsiveContainer, LabelList,
} from "recharts";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams, useNavigate, useSearchParams, useLocation } from "react-router-dom";
import { clientsApi, connectorsApi, scansApi, projectsApi, assetsApi } from "../services/api";
import { Client, Connector, Scan, Project, ProjectSummary, Asset } from "../types";
import { fromNow } from "../utils/datetime";

const CONNECTOR_COLOR: Record<string, string> = {
  entraid: "#4285F4", azure: "#0078d4", aws: "#ff9900", gcp: "#4285f4",
  onprem: "#9e9e9e", okta: "#007dc1", github: "#f0f6fc",
};

const STATUS_COLOR: Record<string, string> = {
  pending: "#ff9800", running: "#4285F4", completed: "#34A853",
  failed: "#f44336", cancelled: "rgba(255,255,255,0.3)",
  active: "#34A853", inactive: "#ff9800", error: "#f44336",
};

const ENV_COLOR: Record<string, string> = {
  production: "#f44336", staging: "#ff9800",
  development: "#4285F4", dr: "#34A853", other: "rgba(255,255,255,0.5)",
};

const NAV_ITEMS = [
  { id: "overview",    label: "Overview",    Icon: DashboardIcon, color: "#4285F4" },
  { id: "projects",    label: "Projects",    Icon: FolderOpen,    color: "#757575" },
  { id: "scans",       label: "Scans",       Icon: Scanner,       color: "#34A853" },
  { id: "connectors",  label: "Connections", Icon: Cable,         color: "#FF9800" },
  { id: "assets",      label: "Assets",      Icon: StorageIcon,   color: "#9C27B0" },
  { id: "findings",    label: "Findings",    Icon: BugReport,     color: "#EA4335" },
  { id: "help",        label: "Help",        Icon: MenuBook,      color: "#00BCD4" },
] as const;

type NavId = (typeof NAV_ITEMS)[number]["id"];

function ProjectCardCompact({ project, clientId, onDelete }: {
  project: Project; clientId: string; onDelete: () => void;
}) {
  const { data: summary } = useQuery<ProjectSummary>({
    queryKey: ["project-summary", clientId, project.id],
    queryFn: () => projectsApi.summary(clientId, project.id),
  });
  const isDefault = project.name === "Default";
  return (
    <Card sx={{ bgcolor: "background.paper", borderRadius: 2,
      transition: "border-color .15s", "&:hover": { borderColor: "primary.main" } }}>
      <CardContent sx={{ "&:last-child": { pb: 2 } }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
          <Box>
            <Typography variant="subtitle2" sx={{ color: "text.primary", fontWeight: 600 }}>{project.name}</Typography>
            {project.description && (
              <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.5 }}>
                {project.description}
              </Typography>
            )}
          </Box>
          {!isDefault && (
            <IconButton size="small" onClick={onDelete} sx={{ color: "text.secondary" }}>
              <Delete fontSize="small" />
            </IconButton>
          )}
        </Box>
        <Box sx={{ display: "flex", gap: 0.5, mb: 1.5 }}>
          {project.environment && (
            <Chip label={project.environment} size="small"
              sx={{ bgcolor: `${ENV_COLOR[project.environment] || "#888"}20`,
                color: ENV_COLOR[project.environment] || "#888", fontSize: 9, height: 18, textTransform: "capitalize" }} />
          )}
          {project.cloud_provider && (
            <Chip label={project.cloud_provider.toUpperCase()} size="small"
              sx={{ bgcolor: "action.hover", color: "text.secondary", fontSize: 9, height: 18 }} />
          )}
        </Box>
        <Grid container spacing={1}>
          {[
            ["Connectors", summary?.connector_count],
            ["Assets", summary?.asset_count],
            ["Scans", summary?.scan_count],
          ].map(([label, val]) => (
            <Grid key={label as string} size={4}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 9, fontWeight: 600 }}>
                {(label as string).toUpperCase()}
              </Typography>
              <Typography sx={{ color: "text.primary", fontSize: 16, fontWeight: 600 }}>
                {val == null ? "…" : val}
              </Typography>
            </Grid>
          ))}
        </Grid>
      </CardContent>
    </Card>
  );
}

export default function ClientDetail() {
  const { clientId } = useParams<{ clientId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const scansBase    = location.pathname.startsWith("/platform") ? "/vulnerability/scans" : "/scans";
  const assetsBase   = location.pathname.startsWith("/platform") ? "/platform/assets"     : "/assets";
  const clientsBase  = location.pathname.startsWith("/platform") ? "/platform/clients"    : "/clients";
  const findingsBase = location.pathname.startsWith("/platform") ? "/platform/findings"   : "/findings";

  const qc = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = (searchParams.get("tab") || "overview") as NavId;
  const setTab = (v: string) => setSearchParams((prev) => {
    const next = new URLSearchParams(prev);
    next.set("tab", v);
    return next;
  });

  const [essentialsOpen, setEssentialsOpen] = useState(true);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [renameOpen, setRenameOpen] = useState(false);
  const [renameValue, setRenameValue] = useState("");
  const [createProjectOpen, setCreateProjectOpen] = useState(false);
  const [projectForm, setProjectForm] = useState({ name: "", description: "" });

  const { data: client, isLoading: clientLoading } = useQuery<Client>({
    queryKey: ["client", clientId],
    queryFn: () => clientsApi.get(clientId!),
    enabled: !!clientId,
  });

  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", clientId],
    queryFn: () => projectsApi.list(clientId!),
    enabled: !!clientId,
  });

  const { data: connectors = [] } = useQuery<Connector[]>({
    queryKey: ["connectors", clientId],
    queryFn: () => connectorsApi.list(clientId!),
    enabled: !!clientId,
  });

  const { data: scans = [] } = useQuery<Scan[]>({
    queryKey: ["scans", clientId],
    queryFn: () => scansApi.list(clientId!),
    enabled: !!clientId,
  });

  const { data: assets = [] } = useQuery<Asset[]>({
    queryKey: ["assets", clientId],
    queryFn: () => assetsApi.list(clientId!),
    enabled: !!clientId,
  });

  const createProjectMutation = useMutation({
    mutationFn: (data: any) => projectsApi.create(clientId!, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects", clientId] });
      setCreateProjectOpen(false);
      setProjectForm({ name: "", description: "" });
    },
  });

  const deleteProjectMutation = useMutation({
    mutationFn: (id: string) => projectsApi.delete(clientId!, id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects", clientId] }),
  });

  const deleteConnectorMutation = useMutation({
    mutationFn: (id: string) => connectorsApi.delete(clientId!, id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["connectors", clientId] }),
  });

  const deleteClientMutation = useMutation({
    mutationFn: () => clientsApi.delete(clientId!),
    onSuccess: () => navigate(clientsBase),
  });

  const renameClientMutation = useMutation({
    mutationFn: (name: string) => clientsApi.update(clientId!, { name }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["client", clientId] });
      qc.invalidateQueries({ queryKey: ["clients"] });
      setRenameOpen(false);
    },
  });

  if (clientLoading) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
        <CircularProgress sx={{ color: "primary.main" }} />
      </Box>
    );
  }
  if (!client) {
    return <Box sx={{ color: "text.secondary", p: 4 }}>Account not found.</Box>;
  }

  const totalFindings = scans.reduce((acc, s) => acc + (s.summary?.total || 0), 0);
  const projectMap = new Map(projects.map((p) => [p.id, p.name]));

  const envData = [
    { name: "Projects",   value: projects.length,   fill: "#4285F4" },
    { name: "Connections", value: connectors.length,  fill: "#FF9800" },
    { name: "Assets",     value: assets.length,      fill: "#9C27B0" },
    { name: "Scans",      value: scans.length,       fill: "#34A853" },
  ];

  const navCounts: Record<string, number> = {
    projects: projects.length,
    scans: scans.length,
    connectors: connectors.length,
    assets: assets.length,
    findings: totalFindings,
  };

  const sidebarBg = isDark ? "#0F1825" : "#F0F4FA";
  const activeBg  = isDark ? "rgba(66,133,244,0.10)" : "rgba(26,115,232,0.08)";

  return (
    <Box sx={{ display: "flex", minHeight: "calc(100vh - 112px)", bgcolor: "background.default" }}>

      {/* ── Left mini sidebar ───────────────────────────────────────────── */}
      <Box sx={{
        width: 220, flexShrink: 0,
        bgcolor: sidebarBg,
        borderRight: "1px solid", borderColor: "divider",
        display: "flex", flexDirection: "column",
        position: "sticky", top: 0, alignSelf: "flex-start",
        maxHeight: "calc(100vh - 112px)", overflowY: "auto",
      }}>
        {/* Account mini-header */}
        <Box sx={{ p: 2, display: "flex", alignItems: "center", gap: 1.5 }}>
          <Avatar sx={{
            bgcolor: "#4285F4", width: 34, height: 34, fontSize: 15,
            fontWeight: 700, borderRadius: 1.5, flexShrink: 0,
          }}>
            {client.name.charAt(0).toUpperCase()}
          </Avatar>
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="body2" sx={{ fontWeight: 700, lineHeight: 1.2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {client.name}
            </Typography>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>Account</Typography>
          </Box>
        </Box>
        <Divider />

        {/* Nav items */}
        <Box sx={{ pt: 0.5, pb: 2 }}>
          {NAV_ITEMS.map(({ id, label, Icon, color }) => {
            const isActive = tab === id;
            const count = navCounts[id];
            return (
              <Box
                key={id}
                onClick={() => {
                  if (id === "findings") {
                    navigate(findingsBase);
                  } else if (id === "connectors") {
                    navigate("/connections");
                  } else if (id === "help") {
                    navigate("/help");
                  } else {
                    setTab(id);
                  }
                }}
                sx={{
                  display: "flex", alignItems: "center", gap: 1.5,
                  px: 2, py: 1.25, cursor: "pointer",
                  borderLeft: "3px solid",
                  borderColor: isActive ? color : "transparent",
                  bgcolor: isActive ? activeBg : "transparent",
                  "&:hover": { bgcolor: isActive ? activeBg : (isDark ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.04)") },
                  transition: "all .12s ease",
                }}
              >
                <Box sx={{
                  width: 28, height: 28, borderRadius: 1.5,
                  bgcolor: `${color}22`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  flexShrink: 0,
                }}>
                  <Icon sx={{ fontSize: 15, color }} />
                </Box>
                <Typography
                  variant="body2"
                  sx={{ flex: 1, color: isActive ? "text.primary" : "text.secondary", fontWeight: isActive ? 600 : 400, fontSize: 13 }}
                >
                  {label}
                </Typography>
                {count !== undefined && count > 0 && (
                  <Chip
                    label={count}
                    size="small"
                    sx={{
                      height: 18, fontSize: 10, minWidth: 24,
                      bgcolor: isActive ? `${color}22` : (isDark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.06)"),
                      color: isActive ? color : "text.secondary",
                    }}
                  />
                )}
              </Box>
            );
          })}
        </Box>
      </Box>

      {/* ── Right content panel ─────────────────────────────────────────── */}
      <Box sx={{ flex: 1, overflow: "auto", p: 3 }}>

        {/* ── OVERVIEW ─────────────────────────────────────────────────── */}
        {tab === "overview" && (
          <>
            {/* Header */}
            <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2.5, mb: 3 }}>
              <Avatar sx={{
                bgcolor: "#4285F4", width: 64, height: 64, fontSize: 28,
                fontWeight: 700, borderRadius: 2, flexShrink: 0,
              }}>
                {client.name.charAt(0).toUpperCase()}
              </Avatar>
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, flexWrap: "wrap" }}>
                  <Typography variant="h4" sx={{ fontWeight: 700 }}>{client.name}</Typography>
                  <Chip
                    label={client.is_active ? "Active" : "Inactive"} size="small"
                    sx={{
                      bgcolor: client.is_active ? "rgba(52,168,83,0.12)" : "rgba(234,67,53,0.12)",
                      color: client.is_active ? "#34A853" : "#EA4335", fontWeight: 600,
                    }}
                  />
                </Box>
                <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
                  Account · {[client.industry, client.country].filter(Boolean).join(", ") || "Global"}
                </Typography>
                <Box sx={{ display: "flex", gap: 0.5, mt: 1.5, flexWrap: "wrap" }}>
                  <Button
                    size="small"
                    startIcon={<Delete sx={{ fontSize: 13 }} />}
                    onClick={() => setDeleteOpen(true)}
                    sx={{ color: "error.main", fontSize: 12, px: 1.5, py: 0.5, borderRadius: 1 }}
                  >
                    Delete account
                  </Button>
                  <Button
                    size="small"
                    startIcon={<Edit sx={{ fontSize: 13 }} />}
                    onClick={() => { setRenameValue(client.name); setRenameOpen(true); }}
                    sx={{ color: "primary.main", fontSize: 12, px: 1.5, py: 0.5, borderRadius: 1 }}
                  >
                    Rename
                  </Button>
                  <Button
                    size="small"
                    startIcon={<History sx={{ fontSize: 13 }} />}
                    onClick={() => navigate(`/posture-trends`)}
                    sx={{ color: "primary.main", fontSize: 12, px: 1.5, py: 0.5, borderRadius: 1 }}
                  >
                    Activity log
                  </Button>
                </Box>
              </Box>
            </Box>

            <Divider sx={{ mb: 3 }} />

            {/* Essentials */}
            <Box sx={{ mb: 3 }}>
              <Box
                sx={{ display: "flex", alignItems: "center", gap: 0.5, mb: 1.5, cursor: "pointer", userSelect: "none" }}
                onClick={() => setEssentialsOpen(!essentialsOpen)}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Essentials</Typography>
                <ExpandMore sx={{
                  fontSize: 20, color: "text.secondary",
                  transform: essentialsOpen ? "rotate(0deg)" : "rotate(-90deg)",
                  transition: "transform .2s",
                }} />
              </Box>
              <Collapse in={essentialsOpen}>
                <Card>
                  <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr" }}>
                    {[
                      { label: "Account ID",    value: clientId, mono: true },
                      { label: "Account name",  value: client.name },
                      { label: "Industry",      value: client.industry || "—" },
                      { label: "Country",       value: client.country || "—" },
                      { label: "Contact email", value: client.contact_email || "—" },
                      { label: "Status",        value: client.is_active ? "Active" : "Inactive", dot: client.is_active ? "#34A853" : "#EA4335" },
                    ].map(({ label, value, mono, dot }, i) => (
                      <Box
                        key={label}
                        sx={{
                          px: 2.5, py: 1.75,
                          borderBottom: i < 4 ? "1px solid" : "none",
                          borderRight: i % 2 === 0 ? "1px solid" : "none",
                          borderColor: "divider",
                        }}
                      >
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.4, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>
                          {label}
                        </Typography>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                          {dot && (
                            <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: dot, flexShrink: 0 }} />
                          )}
                          <Typography
                            variant="body2"
                            sx={{
                              color: "text.primary",
                              fontFamily: mono ? "monospace" : undefined,
                              fontSize: mono ? 11 : 13,
                              wordBreak: "break-all",
                            }}
                          >
                            {value}
                          </Typography>
                        </Box>
                      </Box>
                    ))}
                  </Box>
                </Card>
              </Collapse>
            </Box>

            {/* Environment summary */}
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Environment</Typography>
                <ResponsiveContainer width="100%" height={160}>
                  <BarChart data={envData} layout="vertical" margin={{ top: 0, right: 40, left: 16, bottom: 0 }}>
                    <XAxis type="number" tick={{ fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="name" width={88} tick={{ fontSize: 12 }} axisLine={false} tickLine={false} />
                    <ReTooltip
                      contentStyle={{
                        backgroundColor: isDark ? "#1A2333" : "#fff",
                        border: "1px solid rgba(148,163,184,0.2)",
                        borderRadius: 8, fontSize: 12,
                      }}
                      cursor={{ fill: isDark ? "rgba(255,255,255,0.03)" : "rgba(0,0,0,0.03)" }}
                    />
                    <Bar dataKey="value" radius={[0, 6, 6, 0]} maxBarSize={28}>
                      {envData.map((entry, i) => (
                        <Cell key={i} fill={entry.fill} fillOpacity={0.9} />
                      ))}
                      <LabelList dataKey="value" position="right" style={{ fontSize: 12, fill: isDark ? "#94A3B8" : "#64748B" }} />
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Quick overview cards: recent connectors + recent scans */}
            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 6 }}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>Connections</Typography>
                      <Button size="small" onClick={() => navigate("/connections")} sx={{ color: "primary.main", fontSize: 11 }}>
                        Manage →
                      </Button>
                    </Box>
                    {connectors.length === 0 ? (
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>No connectors configured.</Typography>
                    ) : (
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
                        {connectors.slice(0, 5).map((c) => (
                          <Box key={c.id} sx={{
                            display: "flex", alignItems: "center", justifyContent: "space-between",
                            p: 1.25, bgcolor: "action.hover", borderRadius: 1.5,
                          }}>
                            <Box>
                              <Typography variant="body2" sx={{ fontWeight: 500, fontSize: 13 }}>{c.name}</Typography>
                              <Typography variant="caption" sx={{ color: CONNECTOR_COLOR[c.connector_type] || "text.secondary", fontSize: 10 }}>
                                {c.connector_type}
                              </Typography>
                            </Box>
                            <Chip label={c.status} size="small"
                              sx={{ bgcolor: `${STATUS_COLOR[c.status] || "#888"}18`, color: STATUS_COLOR[c.status] || "text.secondary", fontSize: 10, height: 20 }} />
                          </Box>
                        ))}
                      </Box>
                    )}
                  </CardContent>
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>Recent Scans</Typography>
                      <Button size="small" onClick={() => setTab("scans")} sx={{ color: "primary.main", fontSize: 11 }}>
                        View all →
                      </Button>
                    </Box>
                    {scans.length === 0 ? (
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>No scans yet.</Typography>
                    ) : (
                      <Table size="small">
                        <TableHead>
                          <TableRow sx={{ "& th": { borderColor: "divider", color: "text.secondary", fontSize: 10, pb: 0.5, fontWeight: 600 } }}>
                            <TableCell>TYPE</TableCell>
                            <TableCell>STATUS</TableCell>
                            <TableCell>FINDINGS</TableCell>
                            <TableCell>WHEN</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {scans.slice(0, 5).map((s) => (
                            <TableRow key={s.id} sx={{ "& td": { borderColor: "divider", fontSize: 12 } }}>
                              <TableCell><Chip label={s.scan_type} size="small" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", fontSize: 10, height: 18 }} /></TableCell>
                              <TableCell><Chip label={s.status} size="small"
                                sx={{ bgcolor: `${STATUS_COLOR[s.status]}18`, color: STATUS_COLOR[s.status], fontSize: 10, height: 18 }} /></TableCell>
                              <TableCell>{s.summary?.total ?? "—"}</TableCell>
                              <TableCell><Typography variant="caption" sx={{ color: "text.secondary" }}>{fromNow(s.started_at)}</Typography></TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </>
        )}

        {/* ── PROJECTS ──────────────────────────────────────────────────── */}
        {tab === "projects" && (
          <>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 700 }}>Projects</Typography>
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                  {projects.length} project{projects.length === 1 ? "" : "s"} in this account
                </Typography>
              </Box>
              <Button variant="contained" size="small" startIcon={<Add />} onClick={() => setCreateProjectOpen(true)}>
                New Project
              </Button>
            </Box>
            <Grid container spacing={2}>
              {projects.map((p) => (
                <Grid key={p.id} size={{ xs: 12, sm: 6, md: 4, lg: 3 }}>
                  <ProjectCardCompact project={p} clientId={clientId!}
                    onDelete={() => {
                      if (window.confirm(`Delete project "${p.name}"?`)) deleteProjectMutation.mutate(p.id);
                    }} />
                </Grid>
              ))}
            </Grid>
          </>
        )}

        {/* ── CONNECTORS ────────────────────────────────────────────────── */}
        {tab === "connectors" && (
          <>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 700 }}>Connectors</Typography>
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                  {connectors.length} connector{connectors.length === 1 ? "" : "s"} configured
                </Typography>
              </Box>
              <Button variant="contained" size="small" startIcon={<Add />}
                onClick={() => navigate(location.pathname.startsWith("/platform") ? "/platform/connections" : "/connections")}>
                Add Connector
              </Button>
            </Box>
            {connectors.length === 0 ? (
              <Card sx={{ border: "1px dashed", borderColor: "divider", p: 4, textAlign: "center" }}>
                <Cable sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                <Typography sx={{ color: "text.secondary" }}>No connectors yet.</Typography>
              </Card>
            ) : (
              <Grid container spacing={2}>
                {connectors.map((c) => (
                  <Grid key={c.id} size={{ xs: 12, sm: 6, md: 4, lg: 3 }}>
                    <Card>
                      <CardContent>
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                          <Box>
                            <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{c.name}</Typography>
                            <Typography variant="caption" sx={{ color: CONNECTOR_COLOR[c.connector_type] || "text.secondary", textTransform: "uppercase", fontSize: 10 }}>
                              {c.connector_type}
                            </Typography>
                          </Box>
                          <Chip label={c.status} size="small"
                            sx={{ bgcolor: `${STATUS_COLOR[c.status] || "#888"}18`, color: STATUS_COLOR[c.status] || "text.secondary", fontSize: 10, height: 18 }} />
                        </Box>
                        {c.project_id && projectMap.has(c.project_id) && (
                          <Chip label={`Project: ${projectMap.get(c.project_id)}`} size="small"
                            icon={<FolderOpen sx={{ fontSize: 12 }} />}
                            sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontSize: 10, height: 18, mt: 0.5 }} />
                        )}
                        {c.last_synced_at && (
                          <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1, fontSize: 10 }}>
                            Last synced {fromNow(c.last_synced_at)}
                          </Typography>
                        )}
                        <Box sx={{ display: "flex", gap: 0.75, mt: 1.5 }}>
                          <Button size="small" variant="outlined" startIcon={<OpenInNew sx={{ fontSize: 13 }} />}
                            onClick={() => navigate(location.pathname.startsWith("/platform") ? "/platform/connections" : "/connections")}
                            sx={{ borderColor: "divider", color: "text.secondary", fontSize: 11 }}>
                            Manage
                          </Button>
                          <Box sx={{ flex: 1 }} />
                          <IconButton size="small" sx={{ color: "error.main" }}
                            disabled={deleteConnectorMutation.isPending}
                            onClick={() => {
                              if (window.confirm(`Delete "${c.name}"? Linked assets stay but won't re-sync.`))
                                deleteConnectorMutation.mutate(c.id);
                            }}>
                            <Delete fontSize="small" />
                          </IconButton>
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            )}
          </>
        )}

        {/* ── ASSETS ────────────────────────────────────────────────────── */}
        {tab === "assets" && (
          <>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 700 }}>Assets</Typography>
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                  {assets.length} asset{assets.length === 1 ? "" : "s"} discovered
                </Typography>
              </Box>
              <Button size="small" endIcon={<OpenInNew sx={{ fontSize: 13 }} />}
                onClick={() => navigate(`${assetsBase}?clientId=${clientId}`)}
                sx={{ color: "primary.main", fontSize: 12 }}>
                Open Asset Inventory
              </Button>
            </Box>
            {assets.length === 0 ? (
              <Card sx={{ border: "1px dashed", borderColor: "divider", p: 4, textAlign: "center" }}>
                <StorageIcon sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                <Typography sx={{ color: "text.secondary" }}>No assets discovered yet. Trigger a connector sync to populate.</Typography>
              </Card>
            ) : (
              <Card>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 700, borderColor: "divider", textTransform: "uppercase" } }}>
                      <TableCell>Name</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Project</TableCell>
                      <TableCell>Region</TableCell>
                      <TableCell>Status</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {assets.slice(0, 50).map((a) => (
                      <TableRow key={a.id} hover sx={{ cursor: "pointer", "& td": { borderColor: "divider", fontSize: 12 } }}
                        onClick={() => navigate(`${assetsBase}/${a.id}`)}>
                        <TableCell sx={{ maxWidth: 280 }}>
                          <Typography variant="body2" noWrap>{a.name}</Typography>
                        </TableCell>
                        <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{a.asset_class || "—"}</TableCell>
                        <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{(a.project_id && projectMap.get(a.project_id)) || "—"}</TableCell>
                        <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{a.region || "—"}</TableCell>
                        <TableCell>
                          <Chip label={a.status} size="small"
                            sx={{ bgcolor: `${STATUS_COLOR[a.status] || "#888"}18`, color: STATUS_COLOR[a.status] || "text.secondary", fontSize: 9, height: 16 }} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {assets.length > 50 && (
                  <Box sx={{ p: 1.5, textAlign: "center", borderTop: "1px solid", borderColor: "divider" }}>
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>
                      Showing 50 of {assets.length}. Open full Asset Inventory for search and filtering.
                    </Typography>
                  </Box>
                )}
              </Card>
            )}
          </>
        )}

        {/* ── SCANS ─────────────────────────────────────────────────────── */}
        {tab === "scans" && (
          <>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 700 }}>Scans</Typography>
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                  {scans.length} scan{scans.length === 1 ? "" : "s"} for this account
                </Typography>
              </Box>
              <Button size="small" endIcon={<OpenInNew sx={{ fontSize: 13 }} />}
                onClick={() => navigate(`${scansBase}`)}
                sx={{ color: "primary.main", fontSize: 12 }}>
                Manage Scans
              </Button>
            </Box>
            {scans.length === 0 ? (
              <Card sx={{ border: "1px dashed", borderColor: "divider", p: 4, textAlign: "center" }}>
                <Scanner sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                <Typography sx={{ color: "text.secondary" }}>No scans yet for this account.</Typography>
              </Card>
            ) : (
              <Card>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 700, borderColor: "divider", textTransform: "uppercase" } }}>
                      <TableCell>Type</TableCell>
                      <TableCell>Framework</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Findings</TableCell>
                      <TableCell>Started</TableCell>
                      <TableCell>Duration</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {scans.map((s) => {
                      const dur = s.started_at && s.completed_at
                        ? `${Math.round((new Date(s.completed_at).getTime() - new Date(s.started_at).getTime()) / 1000)}s`
                        : s.status === "running" ? "Running…" : "—";
                      return (
                        <TableRow key={s.id} sx={{ "& td": { borderColor: "divider", fontSize: 12 } }}>
                          <TableCell><Chip label={s.scan_type} size="small" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", fontSize: 10, height: 18 }} /></TableCell>
                          <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{s.framework || "—"}</TableCell>
                          <TableCell>
                            <Chip label={s.status} size="small"
                              sx={{ bgcolor: `${STATUS_COLOR[s.status]}18`, color: STATUS_COLOR[s.status], fontSize: 10, height: 18 }} />
                          </TableCell>
                          <TableCell>{s.summary?.total ?? "—"}</TableCell>
                          <TableCell><Typography variant="caption" sx={{ color: "text.secondary" }}>{fromNow(s.started_at)}</Typography></TableCell>
                          <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{dur}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </Card>
            )}
          </>
        )}
      </Box>

      {/* ── Dialogs ─────────────────────────────────────────────────────── */}

      {/* Delete account */}
      <Dialog open={deleteOpen} onClose={() => setDeleteOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle sx={{ color: "error.main" }}>Delete Account?</DialogTitle>
        <DialogContent>
          <Typography sx={{ color: "text.secondary" }}>
            <strong>{client.name}</strong> will be moved to trash. It can be restored within 30 days
            from <strong>Settings → Deleted Accounts</strong>.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setDeleteOpen(false)} color="inherit">Cancel</Button>
          <Button variant="contained" color="error" onClick={() => deleteClientMutation.mutate()}
            disabled={deleteClientMutation.isPending}>
            {deleteClientMutation.isPending ? <CircularProgress size={18} sx={{ color: "#fff" }} /> : "Move to Trash"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Rename account */}
      <Dialog open={renameOpen} onClose={() => setRenameOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Rename Account</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth size="small" label="Account Name" sx={{ mt: 1 }}
            value={renameValue}
            onChange={(e) => setRenameValue(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && renameValue.trim()) renameClientMutation.mutate(renameValue.trim()); }}
          />
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setRenameOpen(false)} color="inherit">Cancel</Button>
          <Button variant="contained" disabled={!renameValue.trim() || renameClientMutation.isPending}
            onClick={() => renameClientMutation.mutate(renameValue.trim())}>
            {renameClientMutation.isPending ? <CircularProgress size={18} /> : "Save"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Create project */}
      <Dialog open={createProjectOpen} onClose={() => setCreateProjectOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>New Project</DialogTitle>
        <DialogContent>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
            <TextField fullWidth size="small" label="Project Name *"
              value={projectForm.name}
              onChange={(e) => setProjectForm({ ...projectForm, name: e.target.value })} />
            <TextField fullWidth size="small" label="Description" multiline rows={2}
              value={projectForm.description}
              onChange={(e) => setProjectForm({ ...projectForm, description: e.target.value })} />
          </Box>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setCreateProjectOpen(false)} color="inherit">Cancel</Button>
          <Button variant="contained" disabled={!projectForm.name || createProjectMutation.isPending}
            onClick={() => createProjectMutation.mutate(projectForm)}>
            {createProjectMutation.isPending ? <CircularProgress size={18} /> : "Create"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
