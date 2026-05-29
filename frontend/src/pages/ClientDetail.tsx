import React from "react";
import {
  Box, Typography, Button, Card, CardContent, Chip, Grid, Avatar, IconButton,
  Table, TableHead, TableRow, TableCell, TableBody, CircularProgress, Divider,
  Tabs, Tab,
} from "@mui/material";
import {
  ArrowBack, Cable, Scanner, Security, FolderOpen, Storage as StorageIcon,
  OpenInNew, Add, Delete,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams, useNavigate, useSearchParams } from "react-router-dom";
import { clientsApi, connectorsApi, scansApi, projectsApi, assetsApi } from "../services/api";
import { Client, Connector, Scan, Project, ProjectSummary, Asset } from "../types";
import { fromNow } from "../utils/datetime";

const CONNECTOR_COLOR: Record<string, string> = {
  entraid: "#4285F4", azure: "#0078d4", aws: "#ff9900", gcp: "#4285f4",
  onprem: "#9e9e9e", okta: "#007dc1", github: "#f0f6fc",
};

const STATUS_COLOR: Record<string, string> = {
  pending: "#ff9800", running: "#4285F4", completed: "#00e676",
  failed: "#f44336", cancelled: "rgba(255,255,255,0.3)",
  active: "#00e676", inactive: "#ff9800", error: "#f44336",
};

const ENV_COLOR: Record<string, string> = {
  production: "#f44336", staging: "#ff9800",
  development: "#4285F4", dr: "#34A853", other: "rgba(255,255,255,0.5)",
};


function ProjectCardCompact({ project, clientId, onDelete }: {
  project: Project; clientId: string; onDelete: () => void;
}) {
  const { data: summary } = useQuery<ProjectSummary>({
    queryKey: ["project-summary", clientId, project.id],
    queryFn: () => projectsApi.summary(clientId, project.id),
  });
  const isDefault = project.name === "Default";
  return (
    <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2,
      transition: "border-color .15s", "&:hover": { borderColor: "rgba(66,133,244,0.3)" } }}>
      <CardContent sx={{ "&:last-child": { pb: 2 } }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
          <Box>
            <Typography variant="subtitle2" sx={{ color: "white", fontWeight: 600 }}>{project.name}</Typography>
            {project.description && (
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mt: 0.5 }}>
                {project.description}
              </Typography>
            )}
          </Box>
          {!isDefault && (
            <IconButton size="small" onClick={onDelete} sx={{ color: "rgba(255,255,255,0.5)" }}>
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
              sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.7)", fontSize: 9, height: 18 }} />
          )}
        </Box>
        <Grid container spacing={1}>
          {[
            ["Connectors", summary?.connector_count],
            ["Assets", summary?.asset_count],
            ["Scans", summary?.scan_count],
          ].map(([label, val]) => (
            <Grid key={label as string} size={4}>
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", fontSize: 9, fontWeight: 600 }}>
                {(label as string).toUpperCase()}
              </Typography>
              <Typography sx={{ color: "white", fontSize: 16, fontWeight: 600 }}>
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
  const qc = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  const tab = searchParams.get("tab") || "overview";
  const setTab = (v: string) => setSearchParams((prev) => {
    const next = new URLSearchParams(prev);
    next.set("tab", v);
    return next;
  });

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
    enabled: !!clientId && tab === "assets",
  });

  const deleteProjectMutation = useMutation({
    mutationFn: (id: string) => projectsApi.delete(clientId!, id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects", clientId] }),
  });

  if (clientLoading) {
    return <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>;
  }
  if (!client) {
    return <Box sx={{ color: "rgba(255,255,255,0.5)", p: 4 }}>Client not found.</Box>;
  }

  const totalFindings = scans.reduce((acc, s) => acc + (s.summary?.total || 0), 0);
  const criticalFindings = scans.reduce((acc, s) => acc + (s.summary?.critical || 0), 0);
  const projectMap = new Map(projects.map((p) => [p.id, p.name]));

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
        <Button startIcon={<ArrowBack />} onClick={() => navigate("/clients")}
          sx={{ color: "rgba(255,255,255,0.5)", textTransform: "none", minWidth: 0 }}>
          Clients
        </Button>
        <Typography sx={{ color: "rgba(255,255,255,0.3)" }}>/</Typography>
        <Typography sx={{ color: "white", fontWeight: 600 }}>{client.name}</Typography>
      </Box>

      {/* Header */}
      <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
        <CardContent>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <Avatar sx={{ bgcolor: "#4285F4", color: "#000", width: 56, height: 56, fontSize: 24, fontWeight: 700 }}>
              {client.name.charAt(0)}
            </Avatar>
            <Box sx={{ flex: 1 }}>
              <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>{client.name}</Typography>
              <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
                {[client.industry, client.country].filter(Boolean).join(" · ")}
              </Typography>
              {client.contact_email && (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>{client.contact_email}</Typography>
              )}
            </Box>
            <Chip label={client.is_active ? "Active" : "Inactive"} size="small"
              sx={{ bgcolor: client.is_active ? "rgba(0,230,118,0.15)" : "rgba(244,67,54,0.15)",
                color: client.is_active ? "#00e676" : "#f44336" }} />
          </Box>

          <Divider sx={{ borderColor: "rgba(255,255,255,0.08)", my: 2 }} />

          <Grid container spacing={3}>
            {[
              { label: "Projects", value: projects.length, icon: <FolderOpen sx={{ color: "#4285F4" }} /> },
              { label: "Connectors", value: connectors.length, icon: <Cable sx={{ color: "#34A853" }} /> },
              { label: "Total Scans", value: scans.length, icon: <Scanner sx={{ color: "#ff9800" }} /> },
              { label: "Total Findings", value: totalFindings, icon: <Security sx={{ color: "#ffeb3b" }} /> },
              { label: "Critical Findings", value: criticalFindings, icon: <Security sx={{ color: "#f44336" }} /> },
            ].map(({ label, value, icon }) => (
              <Grid size={{ xs: 6, sm: 4, md: "auto" }} sx={{ flex: 1 }} key={label}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  {icon}
                  <Box>
                    <Typography variant="h6" sx={{ color: "white", fontWeight: 700, lineHeight: 1 }}>{value}</Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>{label}</Typography>
                  </Box>
                </Box>
              </Grid>
            ))}
          </Grid>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Tabs value={tab} onChange={(_, v) => setTab(v)}
        sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)", mb: 2,
          "& .MuiTab-root": { color: "rgba(255,255,255,0.5)", textTransform: "none", fontWeight: 500 },
          "& .Mui-selected": { color: "#4285F4" }, "& .MuiTabs-indicator": { backgroundColor: "#4285F4" } }}>
        <Tab label="Overview" value="overview" />
        <Tab label={`Projects (${projects.length})`} value="projects" />
        <Tab label={`Connectors (${connectors.length})`} value="connectors" />
        <Tab label="Assets" value="assets" />
        <Tab label={`Scans (${scans.length})`} value="scans" />
      </Tabs>

      {/* Overview tab */}
      {tab === "overview" && (
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, md: 6 }}>
            <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <CardContent>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                  <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>Connectors</Typography>
                  <Button size="small" onClick={() => setTab("connectors")} sx={{ color: "#4285F4", fontSize: 11 }}>
                    Manage
                  </Button>
                </Box>
                {connectors.length === 0 ? (
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>No connectors configured.</Typography>
                ) : (
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    {connectors.slice(0, 5).map((c) => (
                      <Box key={c.id} sx={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                        p: 1.5, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.06)" }}>
                        <Box>
                          <Typography variant="body2" sx={{ color: "white", fontWeight: 500 }}>{c.name}</Typography>
                          <Typography variant="caption" sx={{ color: CONNECTOR_COLOR[c.connector_type] || "#888" }}>
                            {c.connector_type}
                            {c.project_id && projectMap.has(c.project_id) && ` · ${projectMap.get(c.project_id)}`}
                          </Typography>
                        </Box>
                        <Chip label={c.status} size="small"
                          sx={{ bgcolor: `${STATUS_COLOR[c.status] || "#888"}20`, color: STATUS_COLOR[c.status] || "#888", fontSize: 10, height: 20 }} />
                      </Box>
                    ))}
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>
          <Grid size={{ xs: 12, md: 6 }}>
            <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <CardContent>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                  <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>Recent Scans</Typography>
                  <Button size="small" onClick={() => setTab("scans")} sx={{ color: "#4285F4", fontSize: 11 }}>
                    View All
                  </Button>
                </Box>
                {scans.length === 0 ? (
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>No scans yet.</Typography>
                ) : (
                  <Table size="small">
                    <TableHead>
                      <TableRow sx={{ "& th": { borderColor: "rgba(255,255,255,0.08)", color: "rgba(255,255,255,0.4)", fontSize: 11, pb: 0.5 } }}>
                        <TableCell>Type</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Findings</TableCell>
                        <TableCell>When</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {scans.slice(0, 5).map((s) => (
                        <TableRow key={s.id} sx={{ "& td": { borderColor: "rgba(255,255,255,0.05)", color: "white", fontSize: 12 } }}>
                          <TableCell><Chip label={s.scan_type} size="small" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", fontSize: 10, height: 18 }} /></TableCell>
                          <TableCell><Chip label={s.status} size="small"
                            sx={{ bgcolor: `${STATUS_COLOR[s.status]}20`, color: STATUS_COLOR[s.status], fontSize: 10, height: 18 }} /></TableCell>
                          <TableCell>{s.summary?.total ?? "—"}</TableCell>
                          <TableCell><Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>{fromNow(s.started_at)}</Typography></TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Projects tab */}
      {tab === "projects" && (
        <>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
            <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>
              {projects.length} project{projects.length === 1 ? "" : "s"}
            </Typography>
            <Button variant="contained" size="small" startIcon={<Add />}
              onClick={() => navigate(`/projects?clientId=${clientId}`)}
              sx={{ bgcolor: "#4285F4", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}>
              New Project
            </Button>
          </Box>
          <Grid container spacing={2}>
            {projects.map((p) => (
              <Grid key={p.id} size={{ xs: 12, sm: 6, md: 4 }}>
                <ProjectCardCompact project={p} clientId={clientId!}
                  onDelete={() => {
                    if (window.confirm(`Delete project "${p.name}"?`)) deleteProjectMutation.mutate(p.id);
                  }} />
              </Grid>
            ))}
          </Grid>
        </>
      )}

      {/* Connectors tab */}
      {tab === "connectors" && (
        <>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
            <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>
              {connectors.length} connector{connectors.length === 1 ? "" : "s"}
            </Typography>
            <Button variant="contained" size="small" startIcon={<Add />}
              onClick={() => navigate(`/connectors?clientId=${clientId}`)}
              sx={{ bgcolor: "#4285F4", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}>
              Add Connector
            </Button>
          </Box>
          {connectors.length === 0 ? (
            <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
              <Cable sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
              <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>No connectors yet.</Typography>
            </Card>
          ) : (
            <Grid container spacing={2}>
              {connectors.map((c) => (
                <Grid key={c.id} size={{ xs: 12, sm: 6, md: 4 }}>
                  <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
                    <CardContent>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                        <Box>
                          <Typography variant="subtitle2" sx={{ color: "white", fontWeight: 600 }}>{c.name}</Typography>
                          <Typography variant="caption" sx={{ color: CONNECTOR_COLOR[c.connector_type] || "#888", textTransform: "uppercase", fontSize: 10 }}>
                            {c.connector_type}
                          </Typography>
                        </Box>
                        <Chip label={c.status} size="small"
                          sx={{ bgcolor: `${STATUS_COLOR[c.status] || "#888"}20`, color: STATUS_COLOR[c.status] || "#888", fontSize: 10, height: 18 }} />
                      </Box>
                      {c.project_id && projectMap.has(c.project_id) && (
                        <Chip label={`Project: ${projectMap.get(c.project_id)}`} size="small"
                          icon={<FolderOpen sx={{ fontSize: 12 }} />}
                          sx={{ bgcolor: "rgba(124,77,255,0.15)", color: "#34A853", fontSize: 10, height: 18, mt: 0.5 }} />
                      )}
                      {c.last_synced_at && (
                        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", display: "block", mt: 1, fontSize: 10 }}>
                          Last synced {fromNow(c.last_synced_at)}
                        </Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          )}
        </>
      )}

      {/* Assets tab */}
      {tab === "assets" && (
        <>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
            <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>
              {assets.length} asset{assets.length === 1 ? "" : "s"} discovered
            </Typography>
            <Button size="small" endIcon={<OpenInNew sx={{ fontSize: 14 }} />}
              onClick={() => navigate(`/assets?clientId=${clientId}`)}
              sx={{ color: "#4285F4", fontSize: 11 }}>
              Open Asset Inventory
            </Button>
          </Box>
          {assets.length === 0 ? (
            <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
              <StorageIcon sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
              <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>
                No assets discovered yet. Trigger a connector sync to populate.
              </Typography>
            </Card>
          ) : (
            <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
                    <TableCell>NAME</TableCell>
                    <TableCell>TYPE</TableCell>
                    <TableCell>PROJECT</TableCell>
                    <TableCell>REGION</TableCell>
                    <TableCell>STATUS</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {assets.slice(0, 50).map((a) => (
                    <TableRow key={a.id} hover sx={{ cursor: "pointer", "& td": { color: "white", fontSize: 12, borderColor: "rgba(255,255,255,0.05)" } }}
                      onClick={() => navigate(`/assets/${a.id}`)}>
                      <TableCell sx={{ maxWidth: 280 }}>
                        <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {a.name}
                        </Typography>
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.6) !important", fontSize: 11 }}>
                        {a.asset_class || "—"}
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.6) !important", fontSize: 11 }}>
                        {(a.project_id && projectMap.get(a.project_id)) || "—"}
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.6) !important", fontSize: 11 }}>{a.region || "—"}</TableCell>
                      <TableCell><Chip label={a.status} size="small"
                        sx={{ bgcolor: `${STATUS_COLOR[a.status] || "#888"}20`, color: STATUS_COLOR[a.status] || "#888", fontSize: 9, height: 16 }} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {assets.length > 50 && (
                <Box sx={{ p: 1.5, textAlign: "center", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                    Showing 50 of {assets.length}. Open the full Asset Inventory for filtering and search.
                  </Typography>
                </Box>
              )}
            </Card>
          )}
        </>
      )}

      {/* Scans tab */}
      {tab === "scans" && (
        <>
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
            <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>
              {scans.length} scan{scans.length === 1 ? "" : "s"}
            </Typography>
            <Button size="small" endIcon={<OpenInNew sx={{ fontSize: 14 }} />}
              onClick={() => navigate(`/scans?clientId=${clientId}`)}
              sx={{ color: "#4285F4", fontSize: 11 }}>
              Manage Scans
            </Button>
          </Box>
          {scans.length === 0 ? (
            <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
              <Scanner sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
              <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>No scans yet for this client.</Typography>
            </Card>
          ) : (
            <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
                    <TableCell>TYPE</TableCell>
                    <TableCell>FRAMEWORK</TableCell>
                    <TableCell>STATUS</TableCell>
                    <TableCell>FINDINGS</TableCell>
                    <TableCell>STARTED</TableCell>
                    <TableCell>DURATION</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {scans.map((s) => {
                    const dur = s.started_at && s.completed_at
                      ? `${Math.round((new Date(s.completed_at).getTime() - new Date(s.started_at).getTime()) / 1000)}s`
                      : s.status === "running" ? "Running…" : "—";
                    return (
                      <TableRow key={s.id} sx={{ "& td": { color: "white", fontSize: 12, borderColor: "rgba(255,255,255,0.05)" } }}>
                        <TableCell><Chip label={s.scan_type} size="small" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", fontSize: 10, height: 18 }} /></TableCell>
                        <TableCell sx={{ color: "rgba(255,255,255,0.6) !important", fontSize: 11 }}>{s.framework || "—"}</TableCell>
                        <TableCell><Chip label={s.status} size="small"
                          sx={{ bgcolor: `${STATUS_COLOR[s.status]}20`, color: STATUS_COLOR[s.status], fontSize: 10, height: 18 }} /></TableCell>
                        <TableCell>{s.summary?.total ?? "—"}</TableCell>
                        <TableCell><Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                          {fromNow(s.started_at)}
                        </Typography></TableCell>
                        <TableCell sx={{ color: "rgba(255,255,255,0.6) !important", fontSize: 11 }}>{dur}</TableCell>
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
  );
}
