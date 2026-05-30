import React, { useMemo, useState } from "react";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  FormControl, InputLabel, Select, MenuItem, Button, Alert, Grid,
  Dialog, DialogTitle, DialogContent, DialogActions, LinearProgress,
} from "@mui/material";
import { Warning, SmartToy } from "@mui/icons-material";
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
        <Typography sx={{ color: "white", fontSize: 26, fontWeight: 700, lineHeight: 1 }}>{total}</Typography>
        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontSize: 10, textTransform: "uppercase", letterSpacing: 1 }}>Risks</Typography>
      </Box>
    </Box>
  );
}

function KpiCard({ label, value, sublabel, color = "#4285F4" }: {
  label: string; value: string | number; sublabel?: string; color?: string;
}) {
  return (
    <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
      <CardContent sx={{ "&:last-child": { pb: 2 } }}>
        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontSize: 11, textTransform: "uppercase", letterSpacing: 1, fontWeight: 600 }}>
          {label}
        </Typography>
        <Typography sx={{ color, fontSize: 32, fontWeight: 700, lineHeight: 1.1, mt: 0.5 }}>{value}</Typography>
        {sublabel && (
          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", fontSize: 11 }}>{sublabel}</Typography>
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
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Risk Register</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            Prioritised risks with AI-generated insights
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
            <Select value={clientId} onChange={(e) => { setClientId(e.target.value); setProjectId(""); }} label="Client"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!clientId}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Project</InputLabel>
            <Select value={projectId} onChange={(e) => setProjectId(e.target.value)} label="Project"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
            </Select>
          </FormControl>
        </Box>
      </Box>

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "white" }}>Select a client to view the risk register.</Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>
      ) : risks.length === 0 ? (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <Warning sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
          <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>
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
              <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
                <CardContent>
                  <Typography variant="subtitle2" sx={{ color: "rgba(255,255,255,0.85)", fontWeight: 700, mb: 1.5 }}>Severity</Typography>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
                    <SeverityDonut counts={counts.perLevel} />
                    <Box sx={{ flex: 1, minWidth: 120 }}>
                      {["critical","high","medium","low"].map((k) => (
                        <Box key={k} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                          <Box sx={{ width: 10, height: 10, bgcolor: LEVEL_COLOR[k], borderRadius: 0.5 }} />
                          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.7)", textTransform: "capitalize", flex: 1 }}>{k}</Typography>
                          <Typography variant="caption" sx={{ color: "white", fontWeight: 600 }}>{counts.perLevel[k]}</Typography>
                        </Box>
                      ))}
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, md: 8 }}>
              <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
                <CardContent>
                  <Typography variant="subtitle2" sx={{ color: "rgba(255,255,255,0.85)", fontWeight: 700, mb: 1.5 }}>Top 5 Risks</Typography>
                  {topRisks.length === 0 ? (
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>No risks scored yet.</Typography>
                  ) : topRisks.map((r) => {
                    const lv = lvOf(r);
                    const sc = r.risk_score ?? 0;
                    return (
                      <Box key={r.id} sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1, cursor: "pointer" }}
                        onClick={() => setSelected(r)}>
                        <Chip label={lv} size="small"
                          sx={{ bgcolor: `${LEVEL_COLOR[lv]}25`, color: LEVEL_COLOR[lv], fontSize: 10, height: 18, minWidth: 64 }} />
                        <Typography variant="body2" sx={{ color: "white", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13 }}>
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
          <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2, mb: 2 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, flexWrap: "wrap" }}>
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontWeight: 600, mr: 1 }}>SEVERITY</Typography>
              {["critical","high","medium","low"].map((k) => (
                <Chip key={k} size="small" label={`${k.charAt(0).toUpperCase() + k.slice(1)}${counts.perLevel[k] ? ` · ${counts.perLevel[k]}` : ""}`}
                  onClick={() => toggle(levelFilters, setLevelFilters, k)}
                  sx={{
                    cursor: "pointer",
                    bgcolor: levelFilters.has(k) ? `${LEVEL_COLOR[k]}25` : "rgba(255,255,255,0.04)",
                    color: levelFilters.has(k) ? LEVEL_COLOR[k] : "rgba(255,255,255,0.7)",
                    border: levelFilters.has(k) ? `1px solid ${LEVEL_COLOR[k]}` : "1px solid transparent",
                    fontWeight: levelFilters.has(k) ? 700 : 400,
                  }} />
              ))}
              <Box sx={{ width: 1, height: 18, bgcolor: "rgba(255,255,255,0.1)", mx: 1 }} />
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontWeight: 600, mr: 1 }}>STATUS</Typography>
              {["open","mitigated","accepted","closed"].map((s) => (
                <Chip key={s} size="small" label={s.charAt(0).toUpperCase() + s.slice(1)}
                  onClick={() => toggle(statusFilters, setStatusFilters, s)}
                  sx={{
                    cursor: "pointer",
                    bgcolor: statusFilters.has(s) ? `${STATUS_COLOR[s]}25` : "rgba(255,255,255,0.04)",
                    color: statusFilters.has(s) ? STATUS_COLOR[s] : "rgba(255,255,255,0.7)",
                    border: statusFilters.has(s) ? `1px solid ${STATUS_COLOR[s]}` : "1px solid transparent",
                    fontWeight: statusFilters.has(s) ? 700 : 400,
                  }} />
              ))}
              {counts.categories.length > 0 && (
                <>
                  <Box sx={{ width: 1, height: 18, bgcolor: "rgba(255,255,255,0.1)", mx: 1 }} />
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontWeight: 600, mr: 1 }}>CATEGORY</Typography>
                  {counts.categories.map(([cat, n]) => (
                    <Chip key={cat} size="small" label={`${cat} · ${n}`}
                      onClick={() => toggle(categoryFilters, setCategoryFilters, cat)}
                      sx={{
                        cursor: "pointer",
                        bgcolor: categoryFilters.has(cat) ? "rgba(66,133,244,0.2)" : "rgba(255,255,255,0.04)",
                        color: categoryFilters.has(cat) ? "#4285F4" : "rgba(255,255,255,0.7)",
                        border: categoryFilters.has(cat) ? "1px solid #4285F4" : "1px solid transparent",
                        fontWeight: categoryFilters.has(cat) ? 700 : 400,
                      }} />
                  ))}
                </>
              )}
              {(levelFilters.size + statusFilters.size + categoryFilters.size > 0) && (
                <Button size="small" sx={{ ml: 1, color: "rgba(255,255,255,0.5)", fontSize: 11 }}
                  onClick={() => { setLevelFilters(new Set()); setStatusFilters(new Set()); setCategoryFilters(new Set()); }}>
                  Clear filters
                </Button>
              )}
            </Box>
          </Card>

          {/* Filtered risk table */}
          <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
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
                          "& td": { borderColor: "rgba(255,255,255,0.05)", py: 1 } }}
                        onClick={() => setSelected(r)}>
                        <TableCell>
                          <Chip label={lv} size="small"
                            sx={{ bgcolor: `${LEVEL_COLOR[lv] || "#888"}25`, color: LEVEL_COLOR[lv] || "#888", fontSize: 10, height: 18 }} />
                        </TableCell>
                        <TableCell sx={{ color: "white", maxWidth: 320 }}>
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
                        <TableCell sx={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>{r.category || "—"}</TableCell>
                        <TableCell sx={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>{r.likelihood ?? "—"} / {r.impact ?? "—"}</TableCell>
                        <TableCell>
                          <Chip label={r.status || "open"} size="small"
                            sx={{ bgcolor: `${STATUS_COLOR[r.status || "open"] || "#888"}25`,
                              color: STATUS_COLOR[r.status || "open"] || "#888", fontSize: 10, height: 18 }} />
                        </TableCell>
                        <TableCell sx={{ color: "rgba(255,255,255,0.4)", fontSize: 11 }}>{fromNow(r.created_at)}</TableCell>
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
            <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 700 }}>
              AI Agent Risk Analysis
            </Typography>
            <Chip label={riskRuns.length} size="small"
              sx={{ height: 18, fontSize: 10, fontWeight: 700, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4" }} />
            <Box sx={{ flex: 1 }} />
            {expandedRunId && (
              <Button size="small" onClick={() => setExpandedRunId(null)}
                sx={{ color: "rgba(255,255,255,0.6)", fontSize: 11, textTransform: "none" }}>
                Collapse all
              </Button>
            )}
          </Box>
          <Typography variant="caption" sx={{ display: "block", color: "rgba(255,255,255,0.4)", mb: 1.5 }}>
            Risk-focused agents only (Risk Manager, Threat Intel, Remediation). Click any tile to read the full analysis.
          </Typography>
          {riskRuns.length === 0 ? (
            <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 2, p: 3, textAlign: "center" }}>
              <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
                No risk-related agent runs yet. Run Risk Manager / Threat Intel / Remediation from the Agents page.
              </Typography>
            </Card>
          ) : (
            <Grid container spacing={1.5}>
              {riskRuns.slice(0, 12).map((run: any) => {
                const isExpanded = expandedRunId === run.id;
                return (
                  <Grid key={run.id} size={{ xs: 12, md: isExpanded ? 12 : 6 }}>
                    <AgentInsightCard
                      run={run}
                      expanded={isExpanded}
                      onToggle={() => setExpandedRunId(isExpanded ? null : run.id)}
                      onDelete={() => setPendingDeleteRun(run)}
                    />
                  </Grid>
                );
              })}
            </Grid>
          )}
        </>
      )}

      {/* Detail dialog */}
      <Dialog open={!!selected} onClose={() => setSelected(null)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
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
                  <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.7)", mb: 2 }}>{selected.description}</Typography>
                )}
                <Box sx={{ display: "flex", gap: 2, mb: 2 }}>
                  <Box sx={{ flex: 1, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, p: 1.5, textAlign: "center" }}>
                    <Typography variant="h5" sx={{ color: LEVEL_COLOR[lv] || "#ff9800", fontWeight: 700 }}>
                      {(selected.risk_score ?? 0).toFixed(1)}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>Risk Score</Typography>
                  </Box>
                  <Box sx={{ flex: 1, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, p: 1.5, textAlign: "center" }}>
                    <Typography variant="h6" sx={{ color: "white" }}>{selected.likelihood ?? "—"} / {selected.impact ?? "—"}</Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>Likelihood / Impact</Typography>
                  </Box>
                </Box>
                <FormControl size="small" fullWidth>
                  <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Status</InputLabel>
                  <Select value={selected.status || "open"} label="Status"
                    onChange={(e) => updateMutation.mutate({ id: selected.id, data: { status: e.target.value } })}
                    sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                    <MenuItem value="open">Open</MenuItem>
                    <MenuItem value="mitigated">Mitigated</MenuItem>
                    <MenuItem value="accepted">Accepted</MenuItem>
                    <MenuItem value="closed">Closed</MenuItem>
                  </Select>
                </FormControl>
              </DialogContent>
              <DialogActions>
                <Button onClick={() => setSelected(null)} sx={{ color: "rgba(255,255,255,0.5)" }}>Close</Button>
              </DialogActions>
            </>
          );
        })()}
      </Dialog>

      {/* Confirm delete of an AI agent risk analysis run */}
      <Dialog open={!!pendingDeleteRun} onClose={() => setPendingDeleteRun(null)}
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          Delete risk analysis?
        </DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.75)" }}>
            This removes the agent run and its output from the Risk Register feed. The risks that were created from this run (in the table above) stay — only the agent narrative is deleted.
          </Typography>
          {pendingDeleteRun && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "white", fontWeight: 600, textTransform: "capitalize" }}>
                {(pendingDeleteRun.agent_type || "").replace(/_/g, " ")}
              </Typography>
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                Status: {pendingDeleteRun.status}
                {pendingDeleteRun.started_at ? ` · started ${fromNow(pendingDeleteRun.started_at)}` : ""}
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDeleteRun(null)} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
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
