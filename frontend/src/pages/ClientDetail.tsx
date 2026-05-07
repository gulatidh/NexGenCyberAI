import React from "react";
import {
  Box, Typography, Button, Card, CardContent, Chip, Grid, Avatar,
  Table, TableHead, TableRow, TableCell, TableBody, CircularProgress, Divider,
} from "@mui/material";
import { ArrowBack, Cable, Scanner, Security } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useParams, useNavigate } from "react-router-dom";
import { clientsApi, connectorsApi, scansApi } from "../services/api";
import { Client, Connector, Scan } from "../types";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
dayjs.extend(relativeTime);

const CONNECTOR_COLOR: Record<string, string> = {
  entraid: "#00e5ff", azure: "#0078d4", aws: "#ff9900", gcp: "#4285f4",
  onprem: "#9e9e9e", okta: "#007dc1", github: "#f0f6fc",
};

const STATUS_COLOR: Record<string, string> = {
  pending: "#ff9800", running: "#00e5ff", completed: "#00e676",
  failed: "#f44336", cancelled: "rgba(255,255,255,0.3)",
  active: "#00e676", inactive: "#ff9800", error: "#f44336",
};

export default function ClientDetail() {
  const { clientId } = useParams<{ clientId: string }>();
  const navigate = useNavigate();

  const { data: client, isLoading: clientLoading } = useQuery<Client>({
    queryKey: ["client", clientId],
    queryFn: () => clientsApi.get(clientId!),
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

  if (clientLoading) {
    return <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#00e5ff" }} /></Box>;
  }

  if (!client) {
    return <Box sx={{ color: "rgba(255,255,255,0.5)", p: 4 }}>Client not found.</Box>;
  }

  const recentScans = scans.slice(0, 5);
  const totalFindings = scans.reduce((acc, s) => acc + (s.summary?.total || 0), 0);
  const criticalFindings = scans.reduce((acc, s) => acc + (s.summary?.critical || 0), 0);

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
      <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 3 }}>
        <CardContent>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <Avatar sx={{ bgcolor: "#00e5ff", color: "#000", width: 56, height: 56, fontSize: 24, fontWeight: 700 }}>
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
            <Box sx={{ display: "flex", gap: 1 }}>
              <Chip label={client.is_active ? "Active" : "Inactive"} size="small"
                sx={{ bgcolor: client.is_active ? "rgba(0,230,118,0.15)" : "rgba(244,67,54,0.15)",
                  color: client.is_active ? "#00e676" : "#f44336" }} />
            </Box>
          </Box>

          <Divider sx={{ borderColor: "rgba(255,255,255,0.08)", my: 2 }} />

          <Grid container spacing={3}>
            {[
              { label: "Connectors", value: connectors.length, icon: <Cable sx={{ color: "#00e5ff" }} /> },
              { label: "Total Scans", value: scans.length, icon: <Scanner sx={{ color: "#7c4dff" }} /> },
              { label: "Total Findings", value: totalFindings, icon: <Security sx={{ color: "#ff9800" }} /> },
              { label: "Critical Findings", value: criticalFindings, icon: <Security sx={{ color: "#f44336" }} /> },
            ].map(({ label, value, icon }) => (
              <Grid size={{ xs: 6, sm: 3 }} key={label}>
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

      <Grid container spacing={3}>
        {/* Connectors */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>Connectors</Typography>
                <Button size="small" onClick={() => navigate("/connectors")}
                  sx={{ color: "#00e5ff", fontSize: 11 }}>Manage</Button>
              </Box>
              {connectors.length === 0 ? (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>No connectors configured.</Typography>
              ) : (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {connectors.map((c) => (
                    <Box key={c.id} sx={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                      p: 1.5, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.06)" }}>
                      <Box>
                        <Typography variant="body2" sx={{ color: "white", fontWeight: 500 }}>{c.name}</Typography>
                        <Typography variant="caption" sx={{ color: CONNECTOR_COLOR[c.connector_type] || "#888" }}>
                          {c.connector_type}
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

        {/* Recent Scans */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>Recent Scans</Typography>
                <Button size="small" onClick={() => navigate("/scans")}
                  sx={{ color: "#00e5ff", fontSize: 11 }}>View All</Button>
              </Box>
              {recentScans.length === 0 ? (
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
                    {recentScans.map((s) => (
                      <TableRow key={s.id} sx={{ "& td": { borderColor: "rgba(255,255,255,0.05)", color: "white", fontSize: 12 } }}>
                        <TableCell><Chip label={s.scan_type} size="small" sx={{ bgcolor: "rgba(0,229,255,0.1)", color: "#00e5ff", fontSize: 10, height: 18 }} /></TableCell>
                        <TableCell><Chip label={s.status} size="small"
                          sx={{ bgcolor: `${STATUS_COLOR[s.status]}20`, color: STATUS_COLOR[s.status], fontSize: 10, height: 18 }} /></TableCell>
                        <TableCell>{s.summary?.total ?? "—"}</TableCell>
                        <TableCell><Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>{s.started_at ? dayjs(s.started_at).fromNow() : "—"}</Typography></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
