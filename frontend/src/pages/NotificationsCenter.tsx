import React from "react";
import {
  Box, Typography, Card, CardContent, Chip, Divider, Alert,
  List, ListItem, ListItemText, ListItemIcon, CircularProgress,
} from "@mui/material";
import { BugReport, SmartToy, RadioButtonUnchecked, CheckCircle, NotificationsNone } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useActiveClient } from "../contexts/ClientContext";
import { findingsApi, agentsApi } from "../services/api";
function SeverityChip({ severity }: { severity: string }) {
  const colors: Record<string, { bg: string; color: string }> = {
    critical: { bg: "rgba(234,67,53,0.15)",  color: "#EA4335" },
    high:     { bg: "rgba(251,188,4,0.15)",   color: "#FBBC04" },
    medium:   { bg: "rgba(66,133,244,0.15)",  color: "#4285F4" },
    low:      { bg: "rgba(52,168,83,0.15)",   color: "#34A853" },
  };
  const c = colors[severity] ?? colors.low;
  return (
    <Chip label={severity} size="small"
      sx={{ bgcolor: c.bg, color: c.color, fontWeight: 700, fontSize: 10, height: 20, textTransform: "capitalize" }} />
  );
}

function ts(s?: string) {
  if (!s) return "—";
  try {
    const d = new Date(s);
    return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })
      + " " + d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  } catch { return s; }
}

export default function NotificationsCenter() {
  const { clientId } = useActiveClient();

  const { data: findings, isLoading: loadF } = useQuery({
    queryKey: ["notifications-findings", clientId],
    queryFn: () => findingsApi.listAll(clientId, "critical", "open"),
    enabled: !!clientId,
  });

  const { data: agentRuns, isLoading: loadA } = useQuery({
    queryKey: ["notifications-agents", clientId],
    queryFn: () => agentsApi.listRuns(clientId),
    enabled: !!clientId,
  });

  if (!clientId) {
    return (
      <Alert severity="info" sx={{ mt: 2 }}>Select a client to view notifications.</Alert>
    );
  }

  const criticalFindings: any[] = Array.isArray(findings) ? findings : (findings as any)?.items ?? [];
  const runs: any[] = Array.isArray(agentRuns) ? agentRuns : (agentRuns as any)?.items ?? [];

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>Notifications</Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
          Critical findings and recent AI agent activity.
        </Typography>
      </Box>

      <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
        {/* Critical Findings */}
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
              <BugReport sx={{ color: "#EA4335" }} />
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Critical Open Findings</Typography>
              {!loadF && (
                <Chip label={criticalFindings.length} size="small"
                  sx={{ bgcolor: "rgba(234,67,53,0.15)", color: "#EA4335", fontWeight: 700, ml: "auto" }} />
              )}
            </Box>
            {loadF ? (
              <Box sx={{ display: "flex", justifyContent: "center", py: 3 }}><CircularProgress size={24} /></Box>
            ) : criticalFindings.length === 0 ? (
              <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 4, color: "text.secondary" }}>
                <CheckCircle sx={{ fontSize: 40, mb: 1, color: "#34A853" }} />
                <Typography variant="body2">No critical open findings</Typography>
              </Box>
            ) : (
              <List disablePadding>
                {criticalFindings.slice(0, 15).map((f: any, i: number) => (
                  <React.Fragment key={f.id}>
                    {i > 0 && <Divider sx={{ borderColor: "rgba(255,255,255,0.06)" }} />}
                    <ListItem disablePadding sx={{ py: 1, gap: 1 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <RadioButtonUnchecked sx={{ fontSize: 14, color: "#EA4335" }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 13, flex: 1 }}>{f.title}</Typography>
                          <SeverityChip severity={f.severity} />
                        </Box>}
                        secondary={
                          <Typography variant="caption" sx={{ color: "text.secondary" }}>
                            {f.resource_id || "—"} · {ts(f.created_at)}
                          </Typography>
                        }
                      />
                    </ListItem>
                  </React.Fragment>
                ))}
              </List>
            )}
          </CardContent>
        </Card>

        {/* Agent Runs */}
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
              <SmartToy sx={{ color: "#4285F4" }} />
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Recent Agent Activity</Typography>
            </Box>
            {loadA ? (
              <Box sx={{ display: "flex", justifyContent: "center", py: 3 }}><CircularProgress size={24} /></Box>
            ) : runs.length === 0 ? (
              <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 4, color: "text.secondary" }}>
                <NotificationsNone sx={{ fontSize: 40, mb: 1 }} />
                <Typography variant="body2">No agent runs yet</Typography>
              </Box>
            ) : (
              <List disablePadding>
                {runs.slice(0, 15).map((r: any, i: number) => {
                  const statusColor = r.status === "completed" ? "#34A853" : r.status === "failed" ? "#EA4335" : "#4285F4";
                  return (
                    <React.Fragment key={r.id}>
                      {i > 0 && <Divider sx={{ borderColor: "rgba(255,255,255,0.06)" }} />}
                      <ListItem disablePadding sx={{ py: 1, gap: 1 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <RadioButtonUnchecked sx={{ fontSize: 14, color: statusColor }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={<Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 13, flex: 1 }}>
                              {r.agent_type?.replace(/_/g, " ")}
                            </Typography>
                            <Chip label={r.status} size="small"
                              sx={{ bgcolor: `${statusColor}22`, color: statusColor, fontWeight: 700, fontSize: 10, height: 20, textTransform: "capitalize" }} />
                          </Box>}
                          secondary={
                            <Typography variant="caption" sx={{ color: "text.secondary" }}>
                              {r.scan_name || r.scan_id || "—"} · {ts(r.created_at)}
                            </Typography>
                          }
                        />
                      </ListItem>
                    </React.Fragment>
                  );
                })}
              </List>
            )}
          </CardContent>
        </Card>
      </Box>
    </Box>
  );
}
