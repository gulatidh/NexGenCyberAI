import React, { useMemo, useState } from "react";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  FormControl, InputLabel, Select, MenuItem, Button, Alert, Grid,
  Dialog, DialogTitle, DialogContent, DialogActions, LinearProgress,
  IconButton, Tooltip, Badge,
} from "@mui/material";
import { Warning, SmartToy, History, DeleteOutlined } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { clientsApi, risksApi, projectsApi, agentsApi } from "../services/api";
import { Client, Risk, Project } from "../types";
import { fromNow } from "../utils/datetime";
import AgentInsightCard from "../components/AgentInsightCard";

const LEVEL_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853",
};
const STATUS_COLOR: Record<string, string> = {
  open: "#FF7043", mitigated: "#34A853", accepted: "#4285F4", closed: "rgba(255,255,255,0.3)",
};

// Agent types whose outputs are risk-relevant — the panel filters to these.
const RISK_AGENT_TYPES = new Set(["risk_manager", "threat_intel", "remediation"]);

// ── Small chart components (SVG, no extra deps) ─────────────────────────────

function SeverityDonut({ counts, size = 140 }: { counts: Record<string, number>; size?: number }) {
  const order = ["critical", "high", "medium", "low"];
  const total = order.reduce((s, k) => s + (counts[k] || 0), 0);
  const r = (size - 24) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <Box sx={{ position: "relative", width: size, height: size }}>
      <svg width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={r} stroke="rgba(255,255,255,0.06)" strokeWidth={16} fill="none" />
        {total > 0 && order.map((k) => {
          const n = counts[k] || 0;
          if (n === 0) return null;
          const portion = n / total;
          const len = portion * c;
          const el = (
            <circle key={k} cx={size / 2} cy={size / 2} r={r}
              stroke={LEVEL_COLOR[k]} strokeWidth={16} fill="none"
              strokeDasharray={`${len} ${c - len}`} strokeDashoffset={-offset}
              transform={`rotate(-90 ${size / 2} ${size / 2})`} strokeLinecap="butt" />
          );
          offset += len;
          return el;
        })}
      </svg>
      <Box sx={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column" }}>
        <Typography sx={{ color: "text.primary", fontSize: 26, fontWeight: 700, lineHeight: 1 }}>{total}</Typography>
        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, textTransform: "uppercase", letterSpacing: 1 }}>Risks</Typography>
      </Box>
    </Box>
  );
}

function KpiCard({ label, value, sublabel, color = "#4285F4" }: {
  label: string; value: string | number; sublabel?: string; color?: string;
}) {
  return (
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
      <CardContent sx={{ "&:last-child": { pb: 2 } }}>
        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11, textTransform: "uppercase", letterSpacing: 1, fontWeight: 600 }}>
          {label}
        </Typography>
        <Typography sx={{ color, fontSize: 32, fontWeight: 700, lineHeight: 1.1, mt: 0.5 }}>{value}</Typography>
        {sublabel && (
          <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>{sublabel}</Typography>
        )}
      </CardContent>
    </Card>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function Risks() {
  const qc = useQueryClient();
  const [clientId, setClientId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [selected, setSelected] = useState<Risk | null>(null);

  // Multi-select slicers (Set)
  const [levelFilters, setLevelFilters] = useState<Set<string>>(new Set());
  const [statusFilters, setStatusFilters] = useState<Set<string>>(new Set());
  const [categoryFilters, setCategoryFilters] = useState<Set<string>>(new Set());
  // Only ONE agent insight tile is expanded at a time. null = all collapsed.
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);

  const toggle = (s: Set<string>, setter: (s: Set<string>) => void, v: string) => {
    const next = new Set(s);
    if (next.has(v)) next.delete(v); else next.add(v);
    setter(next);
  };

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", clientId], queryFn: () => projectsApi.list(clientId), enabled: !!clientId,
  });
  const { data: risks = [], isLoading } = useQuery<Risk[]>({
    queryKey: ["risks", clientId, projectId],
    queryFn: () => risksApi.list(clientId, projectId || undefined),
    enabled: !!clientId,
  });

  // AI Agent runs — filter client-side to risk-related types only
  const { data: allRuns = [] } = useQuery<any[]>({
    queryKey: ["agent-runs", clientId],
    queryFn: () => agentsApi.listRuns(clientId),
    enabled: !!clientId,
  });
  const riskRuns = useMemo(() => allRuns.filter((r) => RISK_AGENT_TYPES.has(r.agent_type)), [allRuns]);

  // Group runs by agent_type. Each new run for an agent supersedes the
  // previous, but the older runs stay accessible as a version history.
  // `latestByType` is what we render as the live tile; `historyByType`
  // is the list of older versions (newest-first) for the History dialog.
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
  const [historyOpenFor, setHistoryOpenFor] = useState<string | null>(null);
  const [viewVersion, setViewVersion] = useState<any | null>(null);

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: any) => risksApi.update(clientId, id, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["risks"] }); setSelected(null); },
  });

  const [pendingDeleteRun, setPendingDeleteRun] = useState<any | null>(null);
  const deleteRunMutation = useMutation({
    mutationFn: (runId: string) => agentsApi.deleteRun(clientId, runId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-runs", clientId] });
      if (expandedRunId === pendingDeleteRun?.id) setExpandedRunId(null);
      setPendingDeleteRun(null);
    },
  });

  const lvOf = (r: Risk) => (typeof r.risk_level === "object" ? (r.risk_level as any).value ?? r.risk_level : r.risk_level) as string;

  // KPI calculations
  const counts = useMemo(() => {
    const out: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    let mitigated = 0; let scoreSum = 0; let scoreCount = 0;
    const cats: Record<string, number> = {};
    for (const r of risks) {
      const lv = lvOf(r);
      if (lv in out) out[lv]++;
      if (r.status === "mitigated" || r.status === "closed") mitigated++;
      if (r.risk_score != null) { scoreSum += r.risk_score; scoreCount++; }
      if (r.category) cats[r.category] = (cats[r.category] || 0) + 1;
    }
    return {
      perLevel: out, mitigated, total: risks.length, scoreCount,
      avgScore: scoreCount ? scoreSum / scoreCount : 0,
      categories: Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 6),
    };
  }, [risks]);

  const topRisks = useMemo(
    () => [...risks].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0)).slice(0, 5),
    [risks],
  );

  const filtered = useMemo(() => risks.filter((r) => {
    if (levelFilters.size && !levelFilters.has(lvOf(r))) return false;
    if (statusFilters.size && !statusFilters.has((r.status || "open"))) return false;
    if (categoryFilters.size && !categoryFilters.has(r.category || "")) return false;
    return true;
  }), [risks, levelFilters, statusFilters, categoryFilters]);

  const mitigatedPct = counts.total ? Math.round((counts.mitigated / counts.total) * 100) : 0;
  const criticalHigh = counts.perLevel.critical + counts.perLevel.high;

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Risk Register</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Prioritised risks with AI-generated insights
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Client</InputLabel>
            <Select value={clientId} onChange={(e) => { setClientId(e.target.value); setProjectId(""); }} label="Client"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!clientId}>
            <InputLabel sx={{ color: "text.secondary" }}>Project</InputLabel>
            <Select value={projectId} onChange={(e) => setProjectId(e.target.value)} label="Project"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
            </Select>
          </FormControl>
        </Box>
      </Box>

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "text.primary" }}>Select a client to view the risk register.</Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>
      ) : risks.length === 0 ? (
        <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <Warning sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No risks yet. Run an AI risk assessment from the Agents page.
          </Typography>
        </Card>
      ) : (
        <>
          {/* KPI strip */}
          <Grid container spacing={2} sx={{ mb: 2 }}>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard label="Total Risks" value={counts.total} sublabel={`${filtered.length} after filter`} color="#4285F4" />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard label="Critical + High" value={criticalHigh}
                sublabel={`${counts.perLevel.critical} critical · ${counts.perLevel.high} high`}
                color={criticalHigh > 0 ? "#EA4335" : "#34A853"} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard label="Mitigated" value={`${mitigatedPct}%`}
                sublabel={`${counts.mitigated} of ${counts.total} closed or mitigated`}
                color={mitigatedPct >= 50 ? "#34A853" : "#FBBC04"} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard label="Avg Risk Score" value={counts.avgScore.toFixed(1)}
                sublabel="0 (low) → 10 (critical)"
                color={counts.avgScore >= 7 ? "#EA4335" : counts.avgScore >= 5 ? "#FF7043" : counts.avgScore >= 3 ? "#FBBC04" : "#34A853"} />
            </Grid>
          </Grid>

          {/* Charts row */}
          <Grid container spacing={2} sx={{ mb: 2 }}>
            <Grid size={{ xs: 12, md: 4 }}>
              <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
                <CardContent>
                  <Typography variant="subtitle2" sx={{ color: "text.secondary", fontWeight: 700, mb: 1.5 }}>Severity</Typography>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
                    <SeverityDonut counts={counts.perLevel} />
                    <Box sx={{ flex: 1, minWidth: 120 }}>
                      {["critical","high","medium","low"].map((k) => (
                        <Box key={k} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                          <Box sx={{ width: 10, height: 10, bgcolor: LEVEL_COLOR[k], borderRadius: 0.5 }} />
                          <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "capitalize", flex: 1 }}>{k}</Typography>
                          <Typography variant="caption" sx={{ color: "text.primary", fontWeight: 600 }}>{counts.perLevel[k]}</Typography>
                        </Box>
                      ))}
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, md: 8 }}>
              <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
                <CardContent>
                  <Typography variant="subtitle2" sx={{ color: "text.secondary", fontWeight: 700, mb: 1.5 }}>Top 5 Risks</Typography>
                  {topRisks.length === 0 ? (
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>No risks scored yet.</Typography>
                  ) : topRisks.map((r) => {
                    const lv = lvOf(r);
                    const sc = r.risk_score ?? 0;
                    return (
                      <Box key={r.id} sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1, cursor: "pointer" }}
                        onClick={() => setSelected(r)}>
                        <Chip label={lv} size="small"
                          sx={{ bgcolor: `${LEVEL_COLOR[lv]}25`, color: LEVEL_COLOR[lv], fontSize: 10, height: 18, minWidth: 64 }} />
                        <Typography variant="body2" sx={{ color: "text.primary", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13 }}>
                          {r.title}
                        </Typography>
                        <Box sx={{ width: 160 }}>
                          <LinearProgress variant="determinate" value={Math.min(sc * 10, 100)}
                            sx={{ height: 6, borderRadius: 3, bgcolor: "rgba(255,255,255,0.08)",
                              "& .MuiLinearProgress-bar": { bgcolor: LEVEL_COLOR[lv], borderRadius: 3 } }} />
                        </Box>
                        <Typography variant="caption" sx={{ color: LEVEL_COLOR[lv], fontWeight: 700, minWidth: 32, textAlign: "right" }}>
                          {sc.toFixed(1)}
                        </Typography>
                      </Box>
                    );
                  })}
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Slicer chips — multi-select filters */}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2, mb: 2 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, flexWrap: "wrap" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 1 }}>SEVERITY</Typography>
              {["critical","high","medium","low"].map((k) => (
                <Chip key={k} size="small" label={`${k.charAt(0).toUpperCase() + k.slice(1)}${counts.perLevel[k] ? ` · ${counts.perLevel[k]}` : ""}`}
                  onClick={() => toggle(levelFilters, setLevelFilters, k)}
                  sx={{
                    cursor: "pointer",
                    bgcolor: levelFilters.has(k) ? `${LEVEL_COLOR[k]}25` : "rgba(255,255,255,0.04)",
                    color: levelFilters.has(k) ? LEVEL_COLOR[k] : "text.secondary",
                    border: levelFilters.has(k) ? `1px solid ${LEVEL_COLOR[k]}` : "1px solid transparent",
                    fontWeight: levelFilters.has(k) ? 700 : 400,
                  }} />
              ))}
              <Box sx={{ width: 1, height: 18, bgcolor: "rgba(255,255,255,0.1)", mx: 1 }} />
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 1 }}>STATUS</Typography>
              {["open","mitigated","accepted","closed"].map((s) => (
                <Chip key={s} size="small" label={s.charAt(0).toUpperCase() + s.slice(1)}
                  onClick={() => toggle(statusFilters, setStatusFilters, s)}
                  sx={{
                    cursor: "pointer",
                    bgcolor: statusFilters.has(s) ? `${STATUS_COLOR[s]}25` : "rgba(255,255,255,0.04)",
                    color: statusFilters.has(s) ? STATUS_COLOR[s] : "text.secondary",
                    border: statusFilters.has(s) ? `1px solid ${STATUS_COLOR[s]}` : "1px solid transparent",
                    fontWeight: statusFilters.has(s) ? 700 : 400,
                  }} />
              ))}
              {counts.categories.length > 0 && (
                <>
                  <Box sx={{ width: 1, height: 18, bgcolor: "rgba(255,255,255,0.1)", mx: 1 }} />
                  <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 1 }}>CATEGORY</Typography>
                  {counts.categories.map(([cat, n]) => (
                    <Chip key={cat} size="small" label={`${cat} · ${n}`}
                      onClick={() => toggle(categoryFilters, setCategoryFilters, cat)}
                      sx={{
                        cursor: "pointer",
                        bgcolor: categoryFilters.has(cat) ? "rgba(66,133,244,0.2)" : "rgba(255,255,255,0.04)",
                        color: categoryFilters.has(cat) ? "#4285F4" : "text.secondary",
                        border: categoryFilters.has(cat) ? "1px solid #4285F4" : "1px solid transparent",
                        fontWeight: categoryFilters.has(cat) ? 700 : 400,
                      }} />
                  ))}
                </>
              )}
              {(levelFilters.size + statusFilters.size + categoryFilters.size > 0) && (
                <Button size="small" sx={{ ml: 1, color: "text.secondary", fontSize: 11 }}
                  onClick={() => { setLevelFilters(new Set()); setStatusFilters(new Set()); setCategoryFilters(new Set()); }}>
                  Clear filters
                </Button>
              )}
            </Box>
          </Card>

          {/* Filtered risk table */}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                    <TableCell>LEVEL</TableCell>
                    <TableCell>TITLE</TableCell>
                    <TableCell>SCORE</TableCell>
                    <TableCell>CATEGORY</TableCell>
                    <TableCell>L / I</TableCell>
                    <TableCell>STATUS</TableCell>
                    <TableCell>ADDED</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filtered.map((r) => {
                    const lv = lvOf(r);
                    const score = r.risk_score ?? 0;
                    return (
                      <TableRow key={r.id}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: "rgba(255,255,255,0.03)" },
                          "& td": { borderColor: "divider", py: 1 } }}
                        onClick={() => setSelected(r)}>
                        <TableCell>
                          <Chip label={lv} size="small"
                            sx={{ bgcolor: `${LEVEL_COLOR[lv] || "#888"}25`, color: LEVEL_COLOR[lv] || "#888", fontSize: 10, height: 18 }} />
                        </TableCell>
                        <TableCell sx={{ color: "text.primary", maxWidth: 320 }}>
                          <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {r.title}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Typography variant="body2" sx={{ color: LEVEL_COLOR[lv] || "white", fontWeight: 700, minWidth: 28 }}>
                              {score.toFixed(1)}
                            </Typography>
                            <LinearProgress variant="determinate" value={Math.min(score * 10, 100)}
                              sx={{ width: 50, height: 4, borderRadius: 2, bgcolor: "rgba(255,255,255,0.1)",
                                "& .MuiLinearProgress-bar": { bgcolor: LEVEL_COLOR[lv] || "#888", borderRadius: 2 } }} />
                          </Box>
                        </TableCell>
                        <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>{r.category || "—"}</TableCell>
                        <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>{r.likelihood ?? "—"} / {r.impact ?? "—"}</TableCell>
                        <TableCell>
                          <Chip label={r.status || "open"} size="small"
                            sx={{ bgcolor: `${STATUS_COLOR[r.status || "open"] || "#888"}25`,
                              color: STATUS_COLOR[r.status || "open"] || "#888", fontSize: 10, height: 18 }} />
                        </TableCell>
                        <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{fromNow(r.created_at)}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          </Card>

          {/* AI Agent Risk Analysis — one tile per run, only one expanded at a time */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, mt: 1 }}>
            <SmartToy sx={{ color: "#4285F4", fontSize: 18 }} />
            <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 700 }}>
              AI Agent Risk Analysis
            </Typography>
            <Chip label={riskRuns.length} size="small"
              sx={{ height: 18, fontSize: 10, fontWeight: 700, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4" }} />
            <Box sx={{ flex: 1 }} />
            {expandedRunId && (
              <Button size="small" onClick={() => setExpandedRunId(null)}
                sx={{ color: "text.secondary", fontSize: 11, textTransform: "none" }}>
                Collapse all
              </Button>
            )}
          </Box>
          <Typography variant="caption" sx={{ display: "block", color: "text.secondary", mb: 1.5 }}>
            Risk-focused agents only (Risk Manager, Threat Intel, Remediation). Click any tile to read the full analysis.
          </Typography>
          {latestRuns.length === 0 ? (
            <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 2, p: 3, textAlign: "center" }}>
              <Typography variant="body2" sx={{ color: "text.secondary" }}>
                No risk-related agent runs yet. Run Risk Manager / Threat Intel / Remediation from the Agents page.
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
                              color: "#FBBC04",
                              bgcolor: "rgba(251,188,4,0.10)",
                              "&:hover": { bgcolor: "rgba(251,188,4,0.20)" },
                            }}
                          >
                            <Badge
                              badgeContent={versionCount - 1}
                              color="warning"
                              sx={{
                                "& .MuiBadge-badge": {
                                  fontSize: 9, height: 14, minWidth: 14,
                                  bgcolor: "#FBBC04", color: "#0d1117", fontWeight: 700,
                                },
                              }}
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
        </>
      )}

      {/* Detail dialog */}
      <Dialog open={!!selected} onClose={() => setSelected(null)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        {selected && (() => {
          const lv = lvOf(selected);
          return (
            <>
              <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)", pb: 1.5 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Chip label={lv} size="small" sx={{ bgcolor: `${LEVEL_COLOR[lv]}25`, color: LEVEL_COLOR[lv], fontSize: 11 }} />
                  <Typography sx={{ fontWeight: 600 }}>{selected.title}</Typography>
                </Box>
              </DialogTitle>
              <DialogContent sx={{ mt: 1 }}>
                {selected.description && (
                  <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>{selected.description}</Typography>
                )}
                <Box sx={{ display: "flex", gap: 2, mb: 2 }}>
                  <Box sx={{ flex: 1, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, p: 1.5, textAlign: "center" }}>
                    <Typography variant="h5" sx={{ color: LEVEL_COLOR[lv] || "#ff9800", fontWeight: 700 }}>
                      {(selected.risk_score ?? 0).toFixed(1)}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>Risk Score</Typography>
                  </Box>
                  <Box sx={{ flex: 1, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, p: 1.5, textAlign: "center" }}>
                    <Typography variant="h6" sx={{ color: "text.primary" }}>{selected.likelihood ?? "—"} / {selected.impact ?? "—"}</Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>Likelihood / Impact</Typography>
                  </Box>
                </Box>
                <FormControl size="small" fullWidth>
                  <InputLabel sx={{ color: "text.secondary" }}>Status</InputLabel>
                  <Select value={selected.status || "open"} label="Status"
                    onChange={(e) => updateMutation.mutate({ id: selected.id, data: { status: e.target.value } })}
                    sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                    <MenuItem value="open">Open</MenuItem>
                    <MenuItem value="mitigated">Mitigated</MenuItem>
                    <MenuItem value="accepted">Accepted</MenuItem>
                    <MenuItem value="closed">Closed</MenuItem>
                  </Select>
                </FormControl>
              </DialogContent>
              <DialogActions>
                <Button onClick={() => setSelected(null)} sx={{ color: "text.secondary" }}>Close</Button>
              </DialogActions>
            </>
          );
        })()}
      </Dialog>

      {/* Version history — older runs for a given agent type */}
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
                  {allVersions.length} total version{allVersions.length === 1 ? "" : "s"}. v{allVersions.length} is the latest and currently shown on the tile; older versions are below.
                </Typography>
                {allVersions.map((r: any, idx: number) => {
                  const isCurrent = idx === 0;
                  const versionNum = allVersions.length - idx;
                  const status = (r.status || "").toLowerCase();
                  const statusColor =
                    status === "completed" || status === "success" ? "#34A853"
                      : status === "failed" || status === "error" ? "#EA4335"
                        : "#FBBC04";
                  return (
                    <Box
                      key={r.id}
                      sx={{
                        display: "flex", alignItems: "center", gap: 1.5,
                        p: 1.25, mb: 0.75, borderRadius: 1,
                        bgcolor: isCurrent ? "rgba(66,133,244,0.08)" : "rgba(255,255,255,0.03)",
                        border: `1px solid ${isCurrent ? "rgba(66,133,244,0.3)" : "rgba(255,255,255,0.06)"}`,
                      }}
                    >
                      <Chip
                        label={`v${versionNum}${isCurrent ? " · LIVE" : ""}`}
                        size="small"
                        sx={{
                          height: 22, fontSize: 10, fontWeight: 700, letterSpacing: 0.5,
                          bgcolor: isCurrent ? "rgba(66,133,244,0.2)" : "rgba(255,255,255,0.06)",
                          color: isCurrent ? "#4285F4" : "text.secondary",
                          minWidth: 76,
                        }} />
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography variant="body2" sx={{ color: "text.primary", fontSize: 13, fontWeight: 500 }}>
                          {r.started_at ? new Date(r.started_at).toLocaleString() : "—"}
                        </Typography>
                        <Typography variant="caption" sx={{ color: "text.secondary" }}>
                          {r.started_at ? fromNow(r.started_at) : ""}
                        </Typography>
                      </Box>
                      <Chip
                        label={r.status || "unknown"}
                        size="small"
                        sx={{
                          height: 18, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                          bgcolor: `${statusColor}20`, color: statusColor,
                        }} />
                      <Tooltip title="View this version">
                        <IconButton
                          size="small"
                          onClick={() => { setViewVersion(r); }}
                          sx={{
                            color: "text.secondary",
                            "&:hover": { color: "#4285F4", bgcolor: "rgba(66,133,244,0.08)" },
                          }}
                        >
                          <SmartToy sx={{ fontSize: 18 }} />
                        </IconButton>
                      </Tooltip>
                      {!isCurrent && (
                        <Tooltip title="Delete this version">
                          <IconButton
                            size="small"
                            onClick={() => setPendingDeleteRun(r)}
                            sx={{
                              color: "text.secondary",
                              "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" },
                            }}
                          >
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

      {/* View a single historical version's full output */}
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
          {viewVersion && (
            <AgentInsightCard
              run={viewVersion}
              expanded={true}
              onToggle={() => {}}
            />
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setViewVersion(null)} sx={{ color: "text.secondary" }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Confirm delete of an AI agent risk analysis run */}
      <Dialog open={!!pendingDeleteRun} onClose={() => setPendingDeleteRun(null)}
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          Delete risk analysis?
        </DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            This removes the agent run and its output from the Risk Register feed. The risks that were created from this run (in the table above) stay — only the agent narrative is deleted.
          </Typography>
          {pendingDeleteRun && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600, textTransform: "capitalize" }}>
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
          <Button
            variant="contained"
            disabled={deleteRunMutation.isPending}
            onClick={() => pendingDeleteRun && deleteRunMutation.mutate(pendingDeleteRun.id)}
            sx={{ bgcolor: "#EA4335", "&:hover": { bgcolor: "#c5362b" } }}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
