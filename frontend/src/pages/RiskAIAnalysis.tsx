import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, Chip, Grid, Button, Alert,
  Dialog, DialogTitle, DialogContent, DialogActions,
  IconButton, Tooltip, Badge, Divider,
} from "@mui/material";
import { SmartToy, History, DeleteOutlined, BugReport, OpenInNew } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { agentsApi, scansApi } from "../services/api";
import { fromNow } from "../utils/datetime";
import AgentInsightCard from "../components/AgentInsightCard";

const RISK_AGENT_TYPES = new Set(["risk_manager", "threat_intel", "remediation"]);

const SCAN_TYPE_LABELS: Record<string, string> = {
  web: "Web (ZAP)", nmap: "Nmap", semgrep: "Semgrep", codeql: "CodeQL",
  gitleaks: "Gitleaks", trufflehog: "TruffleHog", trivy: "Trivy",
  owasp_dc: "OWASP DC", nuclei: "Nuclei", checkov: "Checkov", sslyze: "SSLyze",
  ai_code_review: "AI Code Review", tenable: "Tenable", burp_enterprise: "Burp Enterprise",
  snyk: "Snyk", rapid7: "Rapid7", qualys: "Qualys", invicti: "Invicti",
  acunetix: "Acunetix", full: "Full", manual: "Manual",
};

function scanLabel(scan: any): string {
  if (scan.name) return scan.name;
  return SCAN_TYPE_LABELS[scan.scan_type] || scan.scan_type || "Scan";
}

function scanDate(scan: any): string {
  const d = scan.completed_at || scan.started_at || scan.created_at;
  if (!d) return "";
  return new Date(d).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}

export default function RiskAIAnalysis() {
  const { clientId } = useActiveClient();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);
  const [historyOpenFor, setHistoryOpenFor] = useState<{ scanId: string | null; agentType: string } | null>(null);
  const [viewVersion, setViewVersion] = useState<any | null>(null);
  const [pendingDeleteRun, setPendingDeleteRun] = useState<any | null>(null);

  const { data: allRuns = [], isLoading } = useQuery<any[]>({
    queryKey: ["agent-runs", clientId],
    queryFn: () => agentsApi.listRuns(clientId!),
    enabled: !!clientId,
    refetchInterval: 15000,
  });

  const { data: scans = [] } = useQuery<any[]>({
    queryKey: ["scans", clientId],
    queryFn: () => scansApi.list(clientId!),
    enabled: !!clientId,
  });

  const scanMap = useMemo(() => {
    const m: Record<string, any> = {};
    for (const s of scans) m[s.id] = s;
    return m;
  }, [scans]);

  const riskRuns = useMemo(
    () => allRuns.filter((r) => RISK_AGENT_TYPES.has(r.agent_type)),
    [allRuns],
  );

  // Group runs by scan_id; within each group keep all runs for history tracking
  const scanGroups = useMemo(() => {
    const groups = new Map<string | null, any[]>();
    for (const r of riskRuns) {
      const key = r.scan_id || null;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(r);
    }
    const entries = Array.from(groups.entries()) as [string | null, any[]][];
    for (const [, runs] of entries) {
      runs.sort((a: any, b: any) =>
        new Date(b.started_at || 0).getTime() - new Date(a.started_at || 0).getTime(),
      );
    }
    return entries.sort(([keyA, runsA], [keyB, runsB]) => {
      if (keyA === null) return 1;
      if (keyB === null) return -1;
      const latA = Math.max(...runsA.map((r: any) => new Date(r.started_at || 0).getTime()));
      const latB = Math.max(...runsB.map((r: any) => new Date(r.started_at || 0).getTime()));
      return latB - latA;
    });
  }, [riskRuns]);

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

  const totalScans = scanGroups.filter(([k]) => k !== null).length;

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
                label={`${riskRuns.length} run${riskRuns.length !== 1 ? "s" : ""} · ${totalScans} scan${totalScans !== 1 ? "s" : ""}`}
                size="small"
                sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontWeight: 700 }}
              />
            )}
          </Box>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            AI-generated risk intelligence grouped by the scan each agent analyzed.
            Run agents from AI Advisor → AI Buddies after selecting a scan.
          </Typography>
        </Box>
      </Box>

      {isLoading ? (
        <Typography sx={{ color: "text.secondary" }}>Loading agent runs…</Typography>
      ) : scanGroups.length === 0 ? (
        <Card sx={{
          bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.15)",
          borderRadius: 2, p: 4, textAlign: "center",
        }}>
          <SmartToy sx={{ fontSize: 40, color: "text.disabled", mb: 1.5 }} />
          <Typography variant="h6" sx={{ color: "text.secondary", mb: 0.5 }}>No risk analysis yet</Typography>
          <Typography variant="body2" sx={{ color: "text.disabled" }}>
            Go to AI Advisor → AI Buddies, select a scan, then run Risk Manager, Threat Intel, or Remediation agents.
          </Typography>
        </Card>
      ) : (
        <Box>
          {scanGroups.map(([scanId, runs]) => {
            const scan = scanId ? scanMap[scanId] : null;
            // Deduplicate: per agent_type, show latest + track older as history
            const latestByType: Record<string, any> = {};
            const historyByType: Record<string, any[]> = {};
            for (const r of runs) {
              if (!latestByType[r.agent_type]) {
                latestByType[r.agent_type] = r;
              } else {
                (historyByType[r.agent_type] = historyByType[r.agent_type] || []).push(r);
              }
            }
            const latestRuns = Object.values(latestByType);

            return (
              <Box key={scanId ?? "__no_scan__"} sx={{ mb: 4 }}>
                {/* Scan group header */}
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                  <BugReport sx={{ color: scanId ? "#4285F4" : "text.disabled", fontSize: 18 }} />
                  <Typography sx={{ fontWeight: 700, fontSize: "0.95rem" }}>
                    {scan ? scanLabel(scan) : "No scan context"}
                  </Typography>
                  {scan && (
                    <>
                      <Chip
                        label={SCAN_TYPE_LABELS[scan.scan_type] || scan.scan_type}
                        size="small"
                        sx={{ height: 20, fontSize: 10, bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4" }}
                      />
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        {scanDate(scan)}
                      </Typography>
                      <Tooltip title="View scan detail">
                        <IconButton
                          size="small"
                          onClick={() => navigate(`/vulnerability/scans/${scanId}`)}
                          sx={{ color: "text.secondary", "&:hover": { color: "#4285F4" } }}
                        >
                          <OpenInNew sx={{ fontSize: 16 }} />
                        </IconButton>
                      </Tooltip>
                    </>
                  )}
                  {!scan && scanId && (
                    <Typography variant="caption" sx={{ color: "text.disabled", fontStyle: "italic" }}>
                      scan no longer available
                    </Typography>
                  )}
                  <Box sx={{ flex: 1 }} />
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    {latestRuns.length} agent{latestRuns.length !== 1 ? "s" : ""}
                  </Typography>
                </Box>
                <Divider sx={{ borderColor: "divider", mb: 2 }} />

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
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setHistoryOpenFor({ scanId, agentType: run.agent_type });
                                }}
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
              </Box>
            );
          })}
        </Box>
      )}

      {/* Version history dialog */}
      <Dialog open={!!historyOpenFor} onClose={() => setHistoryOpenFor(null)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <History sx={{ color: "#FBBC04" }} />
            <Typography component="span" sx={{ fontWeight: 700, textTransform: "capitalize" }}>
              {(historyOpenFor?.agentType || "").replace(/_/g, " ")} — Version history
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          {historyOpenFor && (() => {
            const targetScanId = historyOpenFor.scanId;
            const targetType = historyOpenFor.agentType;
            const groupRuns = scanGroups.find(([k]) => k === targetScanId)?.[1] || [];
            const sorted = [...groupRuns]
              .filter((r: any) => r.agent_type === targetType)
              .sort((a: any, b: any) => new Date(b.started_at || 0).getTime() - new Date(a.started_at || 0).getTime());
            return (
              <Box>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5 }}>
                  {sorted.length} total version{sorted.length === 1 ? "" : "s"}. v{sorted.length} is the latest.
                </Typography>
                {sorted.map((r: any, idx: number) => {
                  const isCurrent = idx === 0;
                  const versionNum = sorted.length - idx;
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
            This removes the agent run and its output. Risks created from this run stay — only the AI narrative is deleted.
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
