import React, { useMemo, useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, Chip, Grid, Button, Alert,
  Dialog, DialogTitle, DialogContent, DialogActions,
  IconButton, Tooltip, Badge,
} from "@mui/material";
import { SmartToy, History, DeleteOutlined } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { agentsApi } from "../services/api";
import { fromNow } from "../utils/datetime";
import AgentInsightCard from "../components/AgentInsightCard";

const RISK_AGENT_TYPES = new Set(["risk_manager", "threat_intel", "remediation"]);

const AGENT_LABELS: Record<string, { label: string; color: string; description: string }> = {
  risk_manager: {
    label: "Risk Manager",
    color: "#EA4335",
    description: "FAIR-lite risk scoring, ALE calculations, and domain-level exposure analysis.",
  },
  threat_intel: {
    label: "Threat Intelligence",
    color: "#FF7043",
    description: "MITRE ATT&CK threat mapping, actor profiling, and technique correlation.",
  },
  remediation: {
    label: "Remediation Planner",
    color: "#34A853",
    description: "Prioritised remediation actions, effort estimates, and remediation roadmap.",
  },
};

export default function RiskAIAnalysis() {
  const { clientId } = useActiveClient();
  const qc = useQueryClient();

  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);
  const [historyOpenFor, setHistoryOpenFor] = useState<string | null>(null);
  const [viewVersion, setViewVersion] = useState<any | null>(null);
  const [pendingDeleteRun, setPendingDeleteRun] = useState<any | null>(null);

  const { data: allRuns = [], isLoading } = useQuery<any[]>({
    queryKey: ["agent-runs", clientId],
    queryFn: () => agentsApi.listRuns(clientId!),
    enabled: !!clientId,
    refetchInterval: 15000,
  });

  const riskRuns = useMemo(
    () => allRuns.filter((r) => RISK_AGENT_TYPES.has(r.agent_type)),
    [allRuns],
  );

  const { latestByType, historyByType } = useMemo(() => {
    const sorted = [...riskRuns].sort((a, b) => {
      const ad = new Date(a.started_at || 0).getTime();
      const bd = new Date(b.started_at || 0).getTime();
      return bd - ad;
    });
    const latest: Record<string, any> = {};
    const history: Record<string, any[]> = {};
    for (const r of sorted) {
      if (!latest[r.agent_type]) {
        latest[r.agent_type] = r;
      } else {
        (history[r.agent_type] = history[r.agent_type] || []).push(r);
      }
    }
    return { latestByType: latest, historyByType: history };
  }, [riskRuns]);

  const latestRuns = useMemo(() => Object.values(latestByType), [latestByType]);

  const deleteRunMutation = useMutation({
    mutationFn: (runId: string) => agentsApi.deleteRun(clientId!, runId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-runs", clientId] });
      if (expandedRunId === pendingDeleteRun?.id) setExpandedRunId(null);
      setPendingDeleteRun(null);
    },
  });

  if (!clientId) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="info">Select a client from the top bar to view AI risk analysis.</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: { xs: 2, md: 3 } }}>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 1 }}>
        <Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
            <SmartToy sx={{ color: "#4285F4", fontSize: 22 }} />
            <Typography variant="h5" sx={{ fontWeight: 700 }}>AI Risk Analysis</Typography>
            {riskRuns.length > 0 && (
              <Chip
                label={`${riskRuns.length} run${riskRuns.length !== 1 ? "s" : ""}`}
                size="small"
                sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontWeight: 700 }}
              />
            )}
          </Box>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            AI-generated risk intelligence from Risk Manager, Threat Intel, and Remediation agents.
            Run these agents from AI Advisor → AI Buddies to populate this page.
          </Typography>
        </Box>
        {expandedRunId && (
          <Button size="small" onClick={() => setExpandedRunId(null)}
            sx={{ color: "text.secondary", fontSize: 12, textTransform: "none", alignSelf: "center" }}>
            Collapse all
          </Button>
        )}
      </Box>

      {/* Agent type summary chips */}
      <Box sx={{ display: "flex", gap: 1.5, mb: 3, flexWrap: "wrap" }}>
        {Object.entries(AGENT_LABELS).map(([type, meta]) => {
          const run = latestByType[type];
          const hasRun = !!run;
          const status = run?.status?.toLowerCase();
          const isRunning = status === "running" || status === "pending";
          return (
            <Card
              key={type}
              sx={{
                px: 2, py: 1.5, minWidth: 180, flex: 1,
                bgcolor: hasRun ? `${meta.color}0D` : "rgba(255,255,255,0.03)",
                border: `1px solid ${hasRun ? `${meta.color}40` : "rgba(255,255,255,0.08)"}`,
                borderRadius: 2,
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: hasRun ? meta.color : "rgba(255,255,255,0.2)" }} />
                <Typography sx={{ fontWeight: 700, fontSize: "0.82rem", color: hasRun ? meta.color : "text.disabled" }}>
                  {meta.label}
                </Typography>
                {isRunning && (
                  <Chip label="Running" size="small"
                    sx={{ height: 16, fontSize: 9, bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04", ml: "auto" }} />
                )}
                {hasRun && !isRunning && (
                  <Chip label={`v${1 + (historyByType[type]?.length || 0)}`} size="small"
                    sx={{ height: 16, fontSize: 9, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", ml: "auto" }} />
                )}
              </Box>
              <Typography variant="caption" sx={{ color: "text.secondary", lineHeight: 1.3 }}>
                {hasRun
                  ? `Last run ${run.started_at ? fromNow(run.started_at) : "unknown"}`
                  : meta.description}
              </Typography>
            </Card>
          );
        })}
      </Box>

      {/* Agent run tiles */}
      {isLoading ? (
        <Typography sx={{ color: "text.secondary" }}>Loading agent runs…</Typography>
      ) : latestRuns.length === 0 ? (
        <Card sx={{
          bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.15)",
          borderRadius: 2, p: 4, textAlign: "center",
        }}>
          <SmartToy sx={{ fontSize: 40, color: "text.disabled", mb: 1.5 }} />
          <Typography variant="h6" sx={{ color: "text.secondary", mb: 0.5 }}>No risk analysis yet</Typography>
          <Typography variant="body2" sx={{ color: "text.disabled" }}>
            Go to AI Advisor → AI Buddies and run the Risk Manager, Threat Intel, or Remediation agent to populate this page.
          </Typography>
        </Card>
      ) : (
        <Grid container spacing={1.5}>
          {latestRuns.map((run: any) => {
            const isExpanded = expandedRunId === run.id;
            const versionCount = 1 + (historyByType[run.agent_type]?.length || 0);
            return (
              <Grid key={run.id} size={{ xs: 12, md: isExpanded ? 12 : 6 }}>
                <Box sx={{ position: "relative" }}>
                  <AgentInsightCard
                    run={run}
                    expanded={isExpanded}
                    onToggle={() => setExpandedRunId(isExpanded ? null : run.id)}
                    onDelete={() => setPendingDeleteRun(run)}
                  />
                  {versionCount > 1 && (
                    <Tooltip title={`${versionCount - 1} previous version${versionCount - 1 === 1 ? "" : "s"}`}>
                      <IconButton
                        size="small"
                        onClick={(e) => { e.stopPropagation(); setHistoryOpenFor(run.agent_type); }}
                        sx={{
                          position: "absolute", top: 10, right: 76,
                          color: "#FBBC04", bgcolor: "rgba(251,188,4,0.10)",
                          "&:hover": { bgcolor: "rgba(251,188,4,0.20)" },
                        }}
                      >
                        <Badge
                          badgeContent={versionCount - 1}
                          color="warning"
                          sx={{ "& .MuiBadge-badge": { fontSize: 9, height: 14, minWidth: 14, bgcolor: "#FBBC04", color: "#0d1117", fontWeight: 700 } }}
                        >
                          <History sx={{ fontSize: 18 }} />
                        </Badge>
                      </IconButton>
                    </Tooltip>
                  )}
                </Box>
              </Grid>
            );
          })}
        </Grid>
      )}

      {/* Version history dialog */}
      <Dialog open={!!historyOpenFor} onClose={() => setHistoryOpenFor(null)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <History sx={{ color: "#FBBC04" }} />
            <Typography component="span" sx={{ fontWeight: 700, textTransform: "capitalize" }}>
              {(historyOpenFor || "").replace(/_/g, " ")} — Version history
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          {historyOpenFor && (() => {
            const current = latestByType[historyOpenFor];
            const older = historyByType[historyOpenFor] || [];
            const allVersions = current ? [current, ...older] : older;
            return (
              <Box>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5 }}>
                  {allVersions.length} total version{allVersions.length === 1 ? "" : "s"}.
                  v{allVersions.length} is the latest.
                </Typography>
                {allVersions.map((r: any, idx: number) => {
                  const isCurrent = idx === 0;
                  const versionNum = allVersions.length - idx;
                  const status = (r.status || "").toLowerCase();
                  const statusColor = status === "completed" || status === "success" ? "#34A853"
                    : status === "failed" || status === "error" ? "#EA4335" : "#FBBC04";
                  return (
                    <Box key={r.id} sx={{
                      display: "flex", alignItems: "center", gap: 1.5, p: 1.25, mb: 0.75,
                      borderRadius: 1,
                      bgcolor: isCurrent ? "rgba(66,133,244,0.08)" : "rgba(255,255,255,0.03)",
                      border: `1px solid ${isCurrent ? "rgba(66,133,244,0.3)" : "rgba(255,255,255,0.06)"}`,
                    }}>
                      <Chip label={`v${versionNum}${isCurrent ? " · LIVE" : ""}`} size="small"
                        sx={{
                          height: 22, fontSize: 10, fontWeight: 700, letterSpacing: 0.5, minWidth: 76,
                          bgcolor: isCurrent ? "rgba(66,133,244,0.2)" : "rgba(255,255,255,0.06)",
                          color: isCurrent ? "#4285F4" : "text.secondary",
                        }} />
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography variant="body2" sx={{ fontSize: 13, fontWeight: 500 }}>
                          {r.started_at ? new Date(r.started_at).toLocaleString() : "—"}
                        </Typography>
                        <Typography variant="caption" sx={{ color: "text.secondary" }}>
                          {r.started_at ? fromNow(r.started_at) : ""}
                        </Typography>
                      </Box>
                      <Chip label={r.status || "unknown"} size="small"
                        sx={{ height: 18, fontSize: 10, fontWeight: 700, textTransform: "uppercase", bgcolor: `${statusColor}20`, color: statusColor }} />
                      <Tooltip title="View this version">
                        <IconButton size="small" onClick={() => setViewVersion(r)}
                          sx={{ color: "text.secondary", "&:hover": { color: "#4285F4", bgcolor: "rgba(66,133,244,0.08)" } }}>
                          <SmartToy sx={{ fontSize: 18 }} />
                        </IconButton>
                      </Tooltip>
                      {!isCurrent && (
                        <Tooltip title="Delete this version">
                          <IconButton size="small" onClick={() => setPendingDeleteRun(r)}
                            sx={{ color: "text.secondary", "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" } }}>
                            <DeleteOutlined sx={{ fontSize: 18 }} />
                          </IconButton>
                        </Tooltip>
                      )}
                    </Box>
                  );
                })}
              </Box>
            );
          })()}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setHistoryOpenFor(null)} sx={{ color: "text.secondary" }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* View single historical version */}
      <Dialog open={!!viewVersion} onClose={() => setViewVersion(null)} maxWidth="md" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SmartToy sx={{ color: "#4285F4" }} />
            <Typography component="span" sx={{ fontWeight: 700, textTransform: "capitalize" }}>
              {viewVersion ? (viewVersion.agent_type || "").replace(/_/g, " ") : ""}
            </Typography>
            {viewVersion?.started_at && (
              <Typography component="span" variant="caption" sx={{ color: "text.secondary", ml: 1 }}>
                {new Date(viewVersion.started_at).toLocaleString()}
              </Typography>
            )}
          </Box>
        </DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          {viewVersion && <AgentInsightCard run={viewVersion} expanded={true} onToggle={() => {}} />}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setViewVersion(null)} sx={{ color: "text.secondary" }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Confirm delete */}
      <Dialog open={!!pendingDeleteRun} onClose={() => setPendingDeleteRun(null)}
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>Delete risk analysis?</DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            This removes the agent run and its output. The risks created from this run stay — only the AI narrative is deleted.
          </Typography>
          {pendingDeleteRun && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ fontWeight: 600, textTransform: "capitalize" }}>
                {(pendingDeleteRun.agent_type || "").replace(/_/g, " ")}
              </Typography>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                Status: {pendingDeleteRun.status}
                {pendingDeleteRun.started_at ? ` · started ${fromNow(pendingDeleteRun.started_at)}` : ""}
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDeleteRun(null)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button variant="contained" disabled={deleteRunMutation.isPending}
            onClick={() => pendingDeleteRun && deleteRunMutation.mutate(pendingDeleteRun.id)}
            sx={{ bgcolor: "#EA4335", "&:hover": { bgcolor: "#c5362b" } }}>
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
