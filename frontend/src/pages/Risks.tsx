import React, { useMemo, useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  FormControl, InputLabel, Select, MenuItem, Button, Alert, Grid,
  Dialog, DialogTitle, DialogContent, DialogActions, LinearProgress,
  Drawer, Tabs, Tab, Divider, ToggleButton, ToggleButtonGroup, Paper,
  Snackbar, IconButton, Tooltip,
} from "@mui/material";
import {
  Warning, ChevronRight, PictureAsPdf, Article, Replay,
  CheckCircle, Cancel, Schedule, AutoAwesome, Close, FileDownload,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { risksApi, projectsApi } from "../services/api";
import { Risk, Project } from "../types";
import { fromNow } from "../utils/datetime";

const LEVEL_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium_high: "#EF6C00",
  medium: "#FBBC04", low: "#34A853",
};
const STATUS_COLOR: Record<string, string> = {
  open: "#FF7043", mitigated: "#34A853", accepted: "#4285F4", closed: "rgba(255,255,255,0.3)",
};

const FACTOR_NAMES: [string, string][] = [
  ["accessibility", "Accessibility"],
  ["discoverability", "Discoverability"],
  ["exploitability", "Exploitability"],
  ["authentication_score", "Authentication"],
  ["repeatability", "Repeatability"],
];

const MEASURE_STATUS_CONFIG: Record<string, { label: string; color: string }> = {
  in_place:     { label: "In Place",     color: "#4CAF50" },
  not_possible: { label: "Not Possible", color: "#F44336" },
  pending:      { label: "Pending",      color: "#9E9E9E" },
};

// ── Small chart components ───────────────────────────────────────────────────

function SeverityDonut({ counts, size = 140 }: { counts: Record<string, number>; size?: number }) {
  const order = ["critical", "high", "medium", "low"];
  const total = order.reduce((s, k) => s + (counts[k] || 0), 0);
  const r = (size - 24) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <Box sx={{ position: "relative", width: size, height: size }}>
      <svg width={size} height={size}>
        <circle cx={size/2} cy={size/2} r={r} stroke="rgba(255,255,255,0.06)" strokeWidth={16} fill="none" />
        {total > 0 && order.map((k) => {
          const n = counts[k] || 0;
          if (n === 0) return null;
          const portion = n / total;
          const len = portion * c;
          const el = (
            <circle key={k} cx={size/2} cy={size/2} r={r}
              stroke={LEVEL_COLOR[k]} strokeWidth={16} fill="none"
              strokeDasharray={`${len} ${c - len}`} strokeDashoffset={-offset}
              transform={`rotate(-90 ${size/2} ${size/2})`} strokeLinecap="butt" />
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
        {sublabel && <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>{sublabel}</Typography>}
      </CardContent>
    </Card>
  );
}

// ── helpers ──────────────────────────────────────────────────────────────────

function lvOf(r: Risk): string {
  const lv = (typeof r.risk_level === "object" ? (r.risk_level as any).value ?? r.risk_level : r.risk_level) as string;
  // Also use residual_risk_level if present for display
  return (r as any).residual_risk_level || lv || "low";
}

function parseJson(val: any) {
  if (!val) return null;
  if (typeof val === "object") return val;
  try { return JSON.parse(val); } catch { return null; }
}

// ── Detail Drawer ─────────────────────────────────────────────────────────────

function RiskDetailDrawer({
  risk, open, onClose, onUpdated,
}: {
  risk: Risk | null; open: boolean; onClose: () => void; onUpdated: () => void;
}) {
  const { clientId } = useActiveClient();
  const [tab, setTab] = useState(0);
  const [reevalOpen, setReevalOpen] = useState(false);
  const [reevalMeasures, setReevalMeasures] = useState<any[]>([]);
  const [reevalWizard, setReevalWizard] = useState<any>({});
  const [reevalLoading, setReevalLoading] = useState(false);
  const [snack, setSnack] = useState("");

  // Populate re-eval state from risk when opening
  React.useEffect(() => {
    if (open && risk) {
      setTab(0);
      const measures = parseJson((risk as any).measures_json) || [];
      const wizard = parseJson((risk as any).wizard_data_json) || {
        accessibility: (risk as any).accessibility || 3,
        discoverability: (risk as any).discoverability || 3,
        exploitability: (risk as any).exploitability || 3,
        authentication_score: (risk as any).authentication_score || 3,
        repeatability: (risk as any).repeatability || 3,
        consequence: (risk as any).consequence || 3,
        treatment_option: (risk as any).treatment_option || "mitigate",
      };
      setReevalMeasures(measures.map((m: any) => ({ ...m })));
      setReevalWizard(wizard);
    }
  }, [open, risk?.id]);

  if (!risk) return null;

  const lv = lvOf(risk);
  const score = (risk as any).risk_matrix_score || 0;
  const aiData = parseJson((risk as any).ai_assessment_json) || {};
  const measures = parseJson((risk as any).measures_json) || [];
  const wizardData = parseJson((risk as any).wizard_data_json) || {};
  const lf = aiData.likelihood_factors || {};
  const workarounds: Record<string, string> = {};
  for (const w of aiData.workarounds || []) {
    workarounds[w.measure_id] = w.alternative;
  }

  const handleReeval = async () => {
    if (!clientId) return;
    setReevalLoading(true);
    try {
      await risksApi.reevaluate(clientId, risk.id, reevalWizard, reevalMeasures);
      setSnack("Risk re-evaluated and scores updated.");
      setReevalOpen(false);
      onUpdated();
    } catch {
      setSnack("Re-evaluation failed. Please try again.");
    } finally {
      setReevalLoading(false);
    }
  };

  const downloadExport = async (format: "pdf" | "docx") => {
    const token = localStorage.getItem("aegis-token") || sessionStorage.getItem("aegis-token") || "";
    const url = risksApi.exportSingleUrl(clientId!, risk.id, format);
    const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!resp.ok) { setSnack("Export failed."); return; }
    const blob = await resp.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `risk-${risk.id.slice(0, 8)}.${format}`;
    link.click();
  };

  return (
    <>
      <Drawer anchor="right" open={open} onClose={onClose}
        slotProps={{ paper: { sx: { width: { xs: "100%", sm: 640 }, bgcolor: "background.default" } } }}>
        {/* Header */}
        <Box sx={{ p: 2.5, borderBottom: "1px solid", borderColor: "divider" }}>
          <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 1 }}>
            <Box sx={{ flex: 1, mr: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                <Chip label={lv.toUpperCase().replace("_", "-")} size="small"
                  sx={{ bgcolor: `${LEVEL_COLOR[lv] || "#888"}25`, color: LEVEL_COLOR[lv] || "#888",
                    fontWeight: 700, fontSize: 10 }} />
                <Chip label={`Score: ${score}/25`} size="small" variant="outlined" sx={{ fontSize: 10 }} />
                {(risk as any).treatment_option && (
                  <Chip label={(risk as any).treatment_option} size="small"
                    sx={{ bgcolor: "rgba(255,255,255,0.06)", fontSize: 10 }} />
                )}
              </Box>
              <Typography sx={{ fontWeight: 700, fontSize: 15, lineHeight: 1.3 }}>{risk.title}</Typography>
            </Box>
            <IconButton size="small" onClick={onClose}><Close fontSize="small" /></IconButton>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Tooltip title="Re-evaluate with updated measures">
              <Button size="small" startIcon={<Replay />} variant="outlined"
                onClick={() => setReevalOpen(true)}
                sx={{ fontSize: 11, borderColor: "#7C3AED", color: "#7C3AED" }}>
                Re-evaluate
              </Button>
            </Tooltip>
            <Button size="small" startIcon={<PictureAsPdf />} variant="outlined"
              onClick={() => downloadExport("pdf")} sx={{ fontSize: 11 }}>
              PDF
            </Button>
            <Button size="small" startIcon={<Article />} variant="outlined"
              onClick={() => downloadExport("docx")} sx={{ fontSize: 11 }}>
              Word
            </Button>
          </Box>
        </Box>

        <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ px: 2, borderBottom: "1px solid", borderColor: "divider" }}>
          <Tab label="Assessment" sx={{ fontSize: 12 }} />
          <Tab label="Measures" sx={{ fontSize: 12 }} />
          <Tab label="AI Commentary" sx={{ fontSize: 12 }} />
        </Tabs>

        <Box sx={{ flex: 1, overflow: "auto", p: 2.5 }}>
          {/* Assessment tab */}
          {tab === 0 && (
            <Box>
              {risk.description && (
                <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>{risk.description}</Typography>
              )}
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "text.secondary",
                textTransform: "uppercase", fontSize: 11, letterSpacing: 0.8 }}>
                Likelihood Factors
              </Typography>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 1, mb: 3 }}>
                {FACTOR_NAMES.map(([key, label]) => {
                  const val = (lf as any)[key.replace("_score", "")] || (risk as any)[key] || wizardData[key] || 3;
                  const rationale = (lf as any)[`${key.replace("_score", "")}_rationale`] || "";
                  return (
                    <Box key={key} sx={{ p: 1.5, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1,
                      border: "1px solid", borderColor: "divider" }}>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: rationale ? 0.5 : 0 }}>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>{label}</Typography>
                        <Chip label={`${val}/5`} size="small"
                          sx={{ fontWeight: 700, bgcolor: `${LEVEL_COLOR.high}20`, color: LEVEL_COLOR.high }} />
                      </Box>
                      {rationale && (
                        <Typography variant="caption" sx={{ color: "text.secondary", fontStyle: "italic" }}>
                          {rationale}
                        </Typography>
                      )}
                    </Box>
                  );
                })}
              </Box>
              <Divider sx={{ mb: 2 }} />
              <Box sx={{ display: "flex", gap: 2 }}>
                <Box sx={{ flex: 1, p: 1.5, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1, border: "1px solid", borderColor: "divider", textAlign: "center" }}>
                  <Typography sx={{ fontWeight: 700, fontSize: 24, color: LEVEL_COLOR[lv] || "#ff9800" }}>{score}</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>Matrix Score /25</Typography>
                </Box>
                <Box sx={{ flex: 1, p: 1.5, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1, border: "1px solid", borderColor: "divider", textAlign: "center" }}>
                  <Typography sx={{ fontWeight: 700, fontSize: 18 }}>
                    {(risk as any).consequence || wizardData.consequence || "—"}/5
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>Consequence</Typography>
                </Box>
                <Box sx={{ flex: 1, p: 1.5, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1, border: "1px solid", borderColor: "divider", textAlign: "center" }}>
                  <Typography sx={{ fontWeight: 700, fontSize: 14, mt: 0.5, textTransform: "capitalize" }}>
                    {(risk as any).treatment_option || "—"}
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>Treatment</Typography>
                </Box>
              </Box>
            </Box>
          )}

          {/* Measures tab */}
          {tab === 1 && (
            <Box>
              {measures.length === 0 ? (
                <Alert severity="info">No measures recorded. Re-evaluate with measures data to populate this tab.</Alert>
              ) : (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                  {measures.map((m: any) => {
                    const cfg = MEASURE_STATUS_CONFIG[m.status] || MEASURE_STATUS_CONFIG.pending;
                    const wa = workarounds[m.id];
                    return (
                      <Paper key={m.id} variant="outlined" sx={{ p: 1.5, borderRadius: 1.5,
                        borderColor: m.status === "in_place" ? "rgba(76,175,80,0.3)"
                          : m.status === "not_possible" ? "rgba(244,67,54,0.3)" : "divider" }}>
                        <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 1 }}>
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="body2" sx={{ fontWeight: 500, mb: 0.25 }}>{m.text}</Typography>
                            {m.category && (
                              <Chip label={m.category} size="small"
                                sx={{ height: 14, fontSize: 9, bgcolor: "rgba(255,255,255,0.07)", mt: 0.5 }} />
                            )}
                            {wa && m.status === "not_possible" && (
                              <Box sx={{ mt: 1, p: 1, bgcolor: "rgba(255,152,0,0.08)", borderRadius: 1,
                                border: "1px solid rgba(255,152,0,0.25)" }}>
                                <Typography variant="caption" sx={{ color: "#FFB74D" }}>
                                  Workaround: {wa}
                                </Typography>
                              </Box>
                            )}
                          </Box>
                          <Chip label={cfg.label} size="small"
                            sx={{ bgcolor: `${cfg.color}20`, color: cfg.color, fontWeight: 600, fontSize: 10, flexShrink: 0 }} />
                        </Box>
                      </Paper>
                    );
                  })}
                </Box>
              )}
            </Box>
          )}

          {/* AI Commentary tab */}
          {tab === 2 && (
            <Box>
              {aiData.overall_commentary ? (
                <>
                  <Box sx={{ p: 2, bgcolor: "rgba(66,133,244,0.06)", borderRadius: 1,
                    border: "1px solid rgba(66,133,244,0.2)", mb: 2 }}>
                    <Box sx={{ display: "flex", gap: 1, mb: 1 }}>
                      <AutoAwesome sx={{ color: "#4285F4", fontSize: 16, mt: 0.1 }} />
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>AI Assessment</Typography>
                    </Box>
                    <Typography variant="body2" sx={{ color: "text.secondary", lineHeight: 1.6 }}>
                      {aiData.overall_commentary}
                    </Typography>
                  </Box>
                  {aiData.treatment_rationale && (
                    <Box sx={{ p: 1.5, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1, border: "1px solid", borderColor: "divider" }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, display: "block", mb: 0.5 }}>
                        Treatment Rationale
                      </Typography>
                      <Typography variant="body2">{aiData.treatment_rationale}</Typography>
                    </Box>
                  )}
                </>
              ) : (
                <Alert severity="info">No AI commentary available. Re-evaluate to generate AI analysis.</Alert>
              )}
            </Box>
          )}
        </Box>
      </Drawer>

      {/* Re-evaluate dialog */}
      <Dialog open={reevalOpen} onClose={() => setReevalOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ fontWeight: 700 }}>Re-evaluate Risk</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>
            Update measure statuses then click Re-assess. AI will recalculate likelihood scores
            and suggest workarounds for any "Not Possible" measures.
          </Typography>
          {reevalMeasures.length === 0 ? (
            <Alert severity="info">No measures to update. Submit through the Evaluation Wizard to add measures.</Alert>
          ) : (
            <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5, maxHeight: 400, overflowY: "auto" }}>
              {reevalMeasures.map((m: any) => (
                <Paper key={m.id} variant="outlined" sx={{ p: 1.5, borderRadius: 1 }}>
                  <Typography variant="body2" sx={{ mb: 1 }}>{m.text}</Typography>
                  <ToggleButtonGroup size="small" exclusive value={m.status}
                    onChange={(_, val) => {
                      if (!val) return;
                      setReevalMeasures((prev) => prev.map((x) => x.id === m.id ? { ...x, status: val } : x));
                    }}>
                    {["pending","in_place","not_possible"].map((s) => {
                      const cfg = MEASURE_STATUS_CONFIG[s];
                      return (
                        <ToggleButton key={s} value={s}
                          sx={{ fontSize: 10, py: 0.4, px: 1,
                            "&.Mui-selected": { bgcolor: `${cfg.color}20`, color: cfg.color, borderColor: `${cfg.color}60` } }}>
                          {cfg.label}
                        </ToggleButton>
                      );
                    })}
                  </ToggleButtonGroup>
                </Paper>
              ))}
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setReevalOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleReeval} disabled={reevalLoading || reevalMeasures.length === 0}
            startIcon={reevalLoading ? <CircularProgress size={16} /> : <Replay />}
            sx={{ bgcolor: "#7C3AED", "&:hover": { bgcolor: "#6d35d9" } }}>
            Re-assess with AI
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar open={!!snack} autoHideDuration={4000} onClose={() => setSnack("")}
        message={snack} anchorOrigin={{ vertical: "bottom", horizontal: "center" }} />
    </>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function Risks() {
  const qc = useQueryClient();
  const { clientId } = useActiveClient();
  const navigate = useNavigate();
  const [projectId, setProjectId] = useState("");
  const [selected, setSelected] = useState<Risk | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [snack, setSnack] = useState("");

  const [levelFilters, setLevelFilters] = useState<Set<string>>(new Set());
  const [statusFilters, setStatusFilters] = useState<Set<string>>(new Set());
  const [categoryFilters, setCategoryFilters] = useState<Set<string>>(new Set());
  const toggle = (s: Set<string>, setter: (s: Set<string>) => void, v: string) => {
    const next = new Set(s);
    if (next.has(v)) next.delete(v); else next.add(v);
    setter(next);
  };

  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", clientId], queryFn: () => projectsApi.list(clientId), enabled: !!clientId,
  });
  const { data: risks = [], isLoading } = useQuery<Risk[]>({
    queryKey: ["risks", clientId, projectId],
    queryFn: () => risksApi.list(clientId, projectId || undefined),
    enabled: !!clientId,
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: any) => risksApi.update(clientId, id, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["risks"] }); },
  });

  const counts = useMemo(() => {
    const out: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    let mitigated = 0; let scoreSum = 0; let scoreCount = 0;
    const cats: Record<string, number> = {};
    for (const r of risks) {
      const lv = lvOf(r);
      const simpleLevel = lv.replace("medium_high", "medium");
      if (simpleLevel in out) out[simpleLevel]++;
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
    () => [...risks].sort((a, b) => ((b as any).risk_matrix_score ?? b.risk_score ?? 0) - ((a as any).risk_matrix_score ?? a.risk_score ?? 0)).slice(0, 5),
    [risks],
  );

  const filtered = useMemo(() => risks.filter((r) => {
    const lv = lvOf(r).replace("medium_high", "medium");
    if (levelFilters.size && !levelFilters.has(lv)) return false;
    if (statusFilters.size && !statusFilters.has((r.status || "open"))) return false;
    if (categoryFilters.size && !categoryFilters.has(r.category || "")) return false;
    return true;
  }), [risks, levelFilters, statusFilters, categoryFilters]);

  const mitigatedPct = counts.total ? Math.round((counts.mitigated / counts.total) * 100) : 0;
  const criticalHigh = counts.perLevel.critical + counts.perLevel.high;

  const openDrawer = (r: Risk) => { setSelected(r); setDrawerOpen(true); };

  const downloadRegister = async (format: "pdf" | "docx") => {
    if (!clientId) return;
    const token = localStorage.getItem("aegis-token") || sessionStorage.getItem("aegis-token") || "";
    const url = risksApi.exportUrl(clientId, format);
    try {
      const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!resp.ok) { setSnack("Export failed."); return; }
      const blob = await resp.blob();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `risk-register.${format}`;
      link.click();
    } catch { setSnack("Export failed."); }
  };

  return (
    <Box>
      {/* Staging gateway banner */}
      <Box onClick={() => navigate("/analyse/risks/staging")}
        sx={{ display: "flex", alignItems: "center", justifyContent: "space-between",
          mb: 2.5, p: 1.5, px: 2, bgcolor: "rgba(234,179,8,0.08)", border: "1px solid rgba(234,179,8,0.3)",
          borderRadius: 1.5, cursor: "pointer", "&:hover": { bgcolor: "rgba(234,179,8,0.14)" }, transition: "background 0.15s" }}>
        <Typography variant="body2" sx={{ color: "#fde68a" }}>
          New risks go through <strong>Risk Staging</strong> before appearing here — review and evaluate proposals first.
        </Typography>
        <Button size="small" endIcon={<ChevronRight />} sx={{ color: "#fde68a", fontWeight: 600 }}>Open Staging</Button>
      </Box>

      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Risk Register</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Formally evaluated risks — GCC IM8 &amp; ISO 27001 schema
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", alignItems: "center" }}>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!clientId}>
            <InputLabel sx={{ color: "text.secondary" }}>Project</InputLabel>
            <Select value={projectId} onChange={(e) => setProjectId(e.target.value)} label="Project"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
            </Select>
          </FormControl>
          {risks.length > 0 && (
            <>
              <Tooltip title="Export full register as PDF">
                <Button size="small" variant="outlined" startIcon={<PictureAsPdf />}
                  onClick={() => downloadRegister("pdf")} sx={{ fontSize: 11 }}>
                  PDF
                </Button>
              </Tooltip>
              <Tooltip title="Export full register as Word">
                <Button size="small" variant="outlined" startIcon={<Article />}
                  onClick={() => downloadRegister("docx")} sx={{ fontSize: 11 }}>
                  Word
                </Button>
              </Tooltip>
            </>
          )}
        </Box>
      </Box>

      {!clientId ? (
        <Alert severity="info">Select a client to view the risk register.</Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress /></Box>
      ) : risks.length === 0 ? (
        <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <Warning sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No evaluated risks yet. Review proposals in Risk Staging and evaluate them.
          </Typography>
          <Button variant="outlined" sx={{ mt: 2 }} onClick={() => navigate("/analyse/risks/staging")}>
            Go to Risk Staging
          </Button>
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
                  {topRisks.map((r) => {
                    const lv = lvOf(r);
                    const simpleLevel = lv.replace("medium_high", "medium");
                    const sc = (r as any).risk_matrix_score || r.risk_score || 0;
                    return (
                      <Box key={r.id} sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1, cursor: "pointer" }}
                        onClick={() => openDrawer(r)}>
                        <Chip label={lv.replace("_", "-")} size="small"
                          sx={{ bgcolor: `${LEVEL_COLOR[simpleLevel] || "#888"}25`, color: LEVEL_COLOR[simpleLevel] || "#888",
                            fontSize: 10, height: 18, minWidth: 64 }} />
                        <Typography variant="body2" sx={{ color: "text.primary", flex: 1, overflow: "hidden",
                          textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13 }}>
                          {r.title}
                        </Typography>
                        <Box sx={{ width: 160 }}>
                          <LinearProgress variant="determinate" value={Math.min(sc * 4, 100)}
                            sx={{ height: 6, borderRadius: 3, bgcolor: "rgba(255,255,255,0.08)",
                              "& .MuiLinearProgress-bar": { bgcolor: LEVEL_COLOR[simpleLevel] || "#888", borderRadius: 3 } }} />
                        </Box>
                        <Typography variant="caption" sx={{ color: LEVEL_COLOR[simpleLevel] || "#888", fontWeight: 700, minWidth: 32, textAlign: "right" }}>
                          {sc}
                        </Typography>
                      </Box>
                    );
                  })}
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Filters */}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2, mb: 2 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, flexWrap: "wrap" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 1 }}>SEVERITY</Typography>
              {["critical","high","medium","low"].map((k) => (
                <Chip key={k} size="small" label={`${k.charAt(0).toUpperCase() + k.slice(1)}${counts.perLevel[k] ? ` · ${counts.perLevel[k]}` : ""}`}
                  onClick={() => toggle(levelFilters, setLevelFilters, k)}
                  sx={{ cursor: "pointer",
                    bgcolor: levelFilters.has(k) ? `${LEVEL_COLOR[k]}25` : "rgba(255,255,255,0.04)",
                    color: levelFilters.has(k) ? LEVEL_COLOR[k] : "text.secondary",
                    border: levelFilters.has(k) ? `1px solid ${LEVEL_COLOR[k]}` : "1px solid transparent",
                    fontWeight: levelFilters.has(k) ? 700 : 400 }} />
              ))}
              <Box sx={{ width: 1, height: 18, bgcolor: "rgba(255,255,255,0.1)", mx: 1 }} />
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 1 }}>STATUS</Typography>
              {["open","mitigated","accepted","closed"].map((s) => (
                <Chip key={s} size="small" label={s.charAt(0).toUpperCase() + s.slice(1)}
                  onClick={() => toggle(statusFilters, setStatusFilters, s)}
                  sx={{ cursor: "pointer",
                    bgcolor: statusFilters.has(s) ? `${STATUS_COLOR[s]}25` : "rgba(255,255,255,0.04)",
                    color: statusFilters.has(s) ? STATUS_COLOR[s] : "text.secondary",
                    border: statusFilters.has(s) ? `1px solid ${STATUS_COLOR[s]}` : "1px solid transparent",
                    fontWeight: statusFilters.has(s) ? 700 : 400 }} />
              ))}
              {(levelFilters.size + statusFilters.size + categoryFilters.size > 0) && (
                <Button size="small" sx={{ ml: 1, color: "text.secondary", fontSize: 11 }}
                  onClick={() => { setLevelFilters(new Set()); setStatusFilters(new Set()); setCategoryFilters(new Set()); }}>
                  Clear filters
                </Button>
              )}
            </Box>
          </Card>

          {/* Risk table */}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                    <TableCell>LEVEL</TableCell>
                    <TableCell>TITLE</TableCell>
                    <TableCell>SCORE</TableCell>
                    <TableCell>CATEGORY</TableCell>
                    <TableCell>TREATMENT</TableCell>
                    <TableCell>STATUS</TableCell>
                    <TableCell>ADDED</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filtered.map((r) => {
                    const lv = lvOf(r);
                    const simpleLevel = lv.replace("medium_high", "medium");
                    const score = (r as any).risk_matrix_score || r.risk_score || 0;
                    const measures = parseJson((r as any).measures_json) || [];
                    const inPlace = measures.filter((m: any) => m.status === "in_place").length;
                    return (
                      <TableRow key={r.id}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: "rgba(255,255,255,0.03)" },
                          "& td": { borderColor: "divider", py: 1 } }}
                        onClick={() => openDrawer(r)}>
                        <TableCell>
                          <Chip label={lv.replace("_", "-")} size="small"
                            sx={{ bgcolor: `${LEVEL_COLOR[simpleLevel] || "#888"}25`, color: LEVEL_COLOR[simpleLevel] || "#888",
                              fontSize: 10, height: 18 }} />
                        </TableCell>
                        <TableCell sx={{ color: "text.primary", maxWidth: 300 }}>
                          <Box>
                            <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              {r.title}
                            </Typography>
                            {inPlace > 0 && (
                              <Typography variant="caption" sx={{ color: "#4CAF50", fontSize: 10 }}>
                                {inPlace} control{inPlace > 1 ? "s" : ""} in place
                              </Typography>
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Typography variant="body2" sx={{ color: LEVEL_COLOR[simpleLevel] || "white", fontWeight: 700, minWidth: 28 }}>
                              {score}
                            </Typography>
                            <LinearProgress variant="determinate" value={Math.min(score * 4, 100)}
                              sx={{ width: 50, height: 4, borderRadius: 2, bgcolor: "rgba(255,255,255,0.1)",
                                "& .MuiLinearProgress-bar": { bgcolor: LEVEL_COLOR[simpleLevel] || "#888", borderRadius: 2 } }} />
                          </Box>
                        </TableCell>
                        <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>{r.category || "—"}</TableCell>
                        <TableCell sx={{ color: "text.secondary", fontSize: 12, textTransform: "capitalize" }}>
                          {(r as any).treatment_option || "—"}
                        </TableCell>
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
        </>
      )}

      <RiskDetailDrawer
        risk={selected}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onUpdated={() => { qc.invalidateQueries({ queryKey: ["risks"] }); }}
      />

      <Snackbar open={!!snack} autoHideDuration={4000} onClose={() => setSnack("")}
        message={snack} anchorOrigin={{ vertical: "bottom", horizontal: "center" }} />
    </Box>
  );
}
