import React, { useState } from "react";
import { useParams, useNavigate, useLocation } from "react-router-dom";
import {
  Box, Typography, Card, CardContent, Chip, Button, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer, Alert, Grid,
  Divider, LinearProgress, Tooltip, Collapse, IconButton, Dialog, DialogTitle,
  DialogContent, DialogActions, Menu, MenuItem as MuiMenuItem,
} from "@mui/material";
import {
  ArrowBack, AutoAwesome, BugReport, SmartToy, Refresh, ExpandMore, ExpandLess,
  CheckCircle, Error as ErrorIcon, Help, Print, DeleteOutlined, Close, MenuBook,
} from "@mui/icons-material";
import PageDetailLayout, { DetailNavItem } from "../components/layout/PageDetailLayout";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";
import { assessmentsApi, findingsApi, agentsApi } from "../services/api";
import { fromNow } from "../utils/datetime";
import RichOutput from "../components/RichOutput";
import { useActiveClient } from "../contexts/ClientContext";

// ── Constants ────────────────────────────────────────────────────────────────

const STATUS_COLOR: Record<string, string> = {
  completed: "#34A853", running: "#FBBC04", failed: "#EA4335",
  pending: "#FF7043", cancelled: "rgba(255,255,255,0.3)",
};
const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853", info: "#4285F4",
};
const SOURCE_COLOR: Record<string, string> = {
  evidenced: "#34A853", estimated: "#FBBC04", unknown: "rgba(255,255,255,0.4)",
};

// ── Types ────────────────────────────────────────────────────────────────────

interface Factor { value: number; source: "evidenced" | "estimated" | "unknown"; rationale: string; provider?: string; }
interface Rps { rps: number; factors: Record<string, Factor>; factors_used: number; low_confidence: boolean; }
interface Finding {
  id: string; title: string; description?: string; severity: string;
  resource_id?: string; resource_type?: string; control_id?: string;
  cve_id?: string; cvss_score?: number; remediation?: string;
  evidence?: any; rps?: Rps;
}
interface AgentRunRow {
  id: string; agent_type: string; status: string;
  started_at?: string; completed_at?: string;
  output_data?: any; input_data?: any; error_message?: string; tokens_used?: number;
}

// Prefer the catalog agent's friendly name (input_data.agent_name) when
// present — otherwise fall back to agent_type.
function agentLabel(ar: AgentRunRow): string {
  const fromInput = ar.input_data?.agent_name;
  const fromOutput = ar.output_data?.agent_name;
  return (fromInput || fromOutput || ar.agent_type || "agent").replace(/_/g, " ");
}
interface Verdict {
  generated_at: string;
  category: string; client_name: string;
  summary: { counts: Record<string, number>; total: number; unique_cves: number; unique_cwes: number; top_resources: any[] };
  verdict: string;
  what_we_found: string;
  why_it_matters: string;
  executive_summary: string;
  capability_gaps: { gap: string; recommendation: string }[];
  signal_coverage: { signal: string; coverage_pct: number; notes: string }[];
  attack_paths: { path: string; resource: string; evidence: string; finding_count: number }[];
  vendor_scorecard: { vendor: string; score: number; evidence_hits: number; notes: string }[];
  automation_opportunities: { title: string; description: string; estimated_effort: string }[];
  data_completeness: { evidenced_pct: number; estimated_pct: number; unknown_pct: number; counts: any; notes: string };
}
interface ScanDetailData {
  id: string; client_id: string; client_name: string;
  category: string; tile_name: string; name?: string;
  scan_type: string; framework?: string; status: string;
  started_at?: string; completed_at?: string; duration_seconds?: number;
  summary?: any; error_message?: string; progress_message?: string;
  findings: Finding[]; agent_runs: AgentRunRow[];
  ai_verdict?: Verdict;
  ai_verdict_generated_at?: string;
}

// ── Section components ───────────────────────────────────────────────────────

function SectionCard({ title, subtitle, icon, children, accent = "#4285F4" }: {
  title: string; subtitle?: string; icon?: React.ReactNode; children: React.ReactNode; accent?: string;
}) {
  return (
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: subtitle ? 0.25 : 1.5 }}>
          {icon}
          <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 700 }}>{title}</Typography>
          <Box sx={{ flex: 1 }} />
        </Box>
        {subtitle && (
          <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1.5 }}>
            {subtitle}
          </Typography>
        )}
        <Box sx={{ borderLeft: `2px solid ${accent}`, pl: 2 }}>{children}</Box>
      </CardContent>
    </Card>
  );
}

function VerdictHeadline({ verdict }: { verdict: Verdict }) {
  return (
    <Card sx={{
      background: "linear-gradient(135deg, rgba(66,133,244,0.18) 0%, rgba(124,77,255,0.18) 100%)",
      border: "1px solid rgba(66,133,244,0.4)", borderRadius: 2, mb: 2,
    }}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
          <AutoAwesome sx={{ color: "#FBBC04", fontSize: 20 }} />
          <Typography variant="caption" sx={{ color: "#FBBC04", fontWeight: 700, fontSize: 11, letterSpacing: 1.5, textTransform: "uppercase" }}>
            The Verdict
          </Typography>
        </Box>
        <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 20, lineHeight: 1.3 }}>
          {verdict.verdict}
        </Typography>
        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>
          Generated {fromNow(verdict.generated_at)} · {verdict.category} for {verdict.client_name}
        </Typography>
      </CardContent>
    </Card>
  );
}

function NarrativeBlock({ text }: { text: string }) {
  return <RichOutput value={text} />;
}

function CapabilityGaps({ gaps }: { gaps: Verdict["capability_gaps"] }) {
  return (
    <Box>
      {gaps.map((g, i) => (
        <Box key={i} sx={{ mb: 1.5, "&:last-child": { mb: 0 } }}>
          <Typography variant="body2" sx={{ color: "#FF7043", fontWeight: 600, mb: 0.25 }}>
            {g.gap}
          </Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            → {g.recommendation}
          </Typography>
        </Box>
      ))}
    </Box>
  );
}

function SignalCoverage({ rows }: { rows: Verdict["signal_coverage"] }) {
  return (
    <Box>
      {rows.map((r, i) => (
        <Box key={i} sx={{ mb: 1.5 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
            <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600, flex: 1 }}>{r.signal}</Typography>
            <Typography variant="caption" sx={{ color: r.coverage_pct >= 80 ? "#34A853" : r.coverage_pct >= 40 ? "#FBBC04" : "#EA4335", fontWeight: 700 }}>
              {r.coverage_pct}%
            </Typography>
          </Box>
          <LinearProgress variant="determinate" value={r.coverage_pct}
            sx={{ height: 6, borderRadius: 3, bgcolor: "rgba(255,255,255,0.06)",
              "& .MuiLinearProgress-bar": { bgcolor: r.coverage_pct >= 80 ? "#34A853" : r.coverage_pct >= 40 ? "#FBBC04" : "#EA4335", borderRadius: 3 } }} />
          <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.5 }}>{r.notes}</Typography>
        </Box>
      ))}
    </Box>
  );
}

function AttackPaths({ rows }: { rows: Verdict["attack_paths"] }) {
  if (rows.length === 0) {
    return (
      <Typography variant="body2" sx={{ color: "text.secondary" }}>
        No multi-finding chains detected on a single resource in this scan.
      </Typography>
    );
  }
  return (
    <Box>
      {rows.map((p, i) => (
        <Box key={i} sx={{ mb: 1.5, p: 1.25, bgcolor: "rgba(234,67,53,0.06)", borderRadius: 1, border: "1px solid rgba(234,67,53,0.2)" }}>
          <Typography variant="body2" sx={{ color: "#EA4335", fontWeight: 600, mb: 0.5 }}>
            {p.path}
          </Typography>
          <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
            <strong>Resource:</strong> <code style={{ color: "#FBBC04" }}>{p.resource}</code>
          </Typography>
          <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
            <strong>Evidence chain:</strong> {p.evidence}
          </Typography>
        </Box>
      ))}
    </Box>
  );
}

function VendorScorecard({ rows }: { rows: Verdict["vendor_scorecard"] }) {
  return (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
            <TableCell>VENDOR</TableCell>
            <TableCell align="right">SCORE</TableCell>
            <TableCell align="right">EVIDENCE HITS</TableCell>
            <TableCell>NOTES</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((r) => {
            const scoreColor = r.score >= 7 ? "#34A853" : r.score >= 4 ? "#FBBC04" : r.score > 0 ? "#FF7043" : "rgba(255,255,255,0.3)";
            return (
              <TableRow key={r.vendor} sx={{ "& td": { borderColor: "divider", color: "text.primary", py: 1 } }}>
                <TableCell sx={{ fontWeight: 600 }}>{r.vendor}</TableCell>
                <TableCell align="right">
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, justifyContent: "flex-end" }}>
                    <Typography variant="body2" sx={{ color: scoreColor, fontWeight: 700, minWidth: 28 }}>
                      {r.score.toFixed(1)}
                    </Typography>
                    <LinearProgress variant="determinate" value={Math.min(100, r.score * 10)}
                      sx={{ width: 60, height: 5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.06)",
                        "& .MuiLinearProgress-bar": { bgcolor: scoreColor, borderRadius: 2 } }} />
                  </Box>
                </TableCell>
                <TableCell align="right" sx={{ color: "text.secondary", fontSize: 12 }}>{r.evidence_hits}</TableCell>
                <TableCell sx={{ color: "text.secondary", fontSize: 11, maxWidth: 320 }}>{r.notes}</TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

function AutomationOpps({ rows }: { rows: Verdict["automation_opportunities"] }) {
  return (
    <Grid container spacing={1.5}>
      {rows.map((r, i) => (
        <Grid size={{ xs: 12, md: 4 }} key={i}>
          <Box sx={{ p: 1.5, border: "1px solid rgba(255,255,255,0.06)", borderRadius: 1.5, bgcolor: "rgba(255,255,255,0.02)", height: "100%" }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
              <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 700, flex: 1 }}>{r.title}</Typography>
              <Chip label={r.estimated_effort} size="small"
                sx={{ height: 18, fontSize: 10, bgcolor: "rgba(52,168,83,0.15)", color: "#34A853", fontWeight: 700 }} />
            </Box>
            <Typography variant="caption" sx={{ color: "text.secondary" }}>{r.description}</Typography>
          </Box>
        </Grid>
      ))}
    </Grid>
  );
}

function DataCompleteness({ dc }: { dc: Verdict["data_completeness"] }) {
  return (
    <Box>
      <Box sx={{ display: "flex", gap: 1, mb: 1.5 }}>
        <Box sx={{ flex: dc.evidenced_pct, minWidth: 0 }}>
          <Box sx={{ bgcolor: "#34A853", height: 8, borderRadius: "4px 0 0 4px" }} />
        </Box>
        <Box sx={{ flex: dc.estimated_pct, minWidth: 0 }}>
          <Box sx={{ bgcolor: "#FBBC04", height: 8 }} />
        </Box>
        <Box sx={{ flex: dc.unknown_pct, minWidth: 0 }}>
          <Box sx={{ bgcolor: "rgba(255,255,255,0.2)", height: 8, borderRadius: "0 4px 4px 0" }} />
        </Box>
      </Box>
      <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 1 }}>
        <Chip size="small" icon={<CheckCircle sx={{ fontSize: 14 }} />} label={`Evidenced ${dc.evidenced_pct}%`}
          sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontWeight: 700, "& .MuiChip-icon": { color: "#34A853" } }} />
        <Chip size="small" icon={<Help sx={{ fontSize: 14 }} />} label={`Estimated ${dc.estimated_pct}%`}
          sx={{ bgcolor: "rgba(251,188,4,0.12)", color: "#FBBC04", fontWeight: 700, "& .MuiChip-icon": { color: "#FBBC04" } }} />
        <Chip size="small" icon={<ErrorIcon sx={{ fontSize: 14 }} />} label={`Unknown ${dc.unknown_pct}%`}
          sx={{ bgcolor: "rgba(255,255,255,0.04)", color: "text.secondary", fontWeight: 700 }} />
      </Box>
      <Typography variant="caption" sx={{ color: "text.secondary" }}>{dc.notes}</Typography>
    </Box>
  );
}

function RpsFactorTable({ findings }: { findings: Finding[] }) {
  const [openId, setOpenId] = useState<string | null>(null);
  const sorted = [...findings].sort((a, b) => (b.rps?.rps || 0) - (a.rps?.rps || 0));
  if (sorted.length === 0) return <Typography variant="body2" sx={{ color: "text.secondary" }}>No findings yet.</Typography>;
  return (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
            <TableCell />
            <TableCell>FINDING</TableCell>
            <TableCell align="right">RPS</TableCell>
            <TableCell align="right">CVSS</TableCell>
            <TableCell align="right">EPSS</TableCell>
            <TableCell align="right">KEV</TableCell>
            <TableCell align="right">REACH</TableCell>
            <TableCell align="right">EXPL</TableCell>
            <TableCell align="right">ASSET</TableCell>
            <TableCell align="right">BIZ</TableCell>
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>
          {sorted.slice(0, 50).map((f) => {
            const r = f.rps;
            if (!r) return null;
            const isOpen = openId === f.id;
            const lowConf = r.low_confidence;
            return (
              <React.Fragment key={f.id}>
                <TableRow hover sx={{ "& td": { borderColor: "divider", color: "text.primary", py: 0.75 } }}>
                  <TableCell sx={{ width: 32 }}>
                    <IconButton size="small" onClick={() => setOpenId(isOpen ? null : f.id)}>
                      {isOpen ? <ExpandLess sx={{ fontSize: 16, color: "text.secondary" }} /> : <ExpandMore sx={{ fontSize: 16, color: "text.secondary" }} />}
                    </IconButton>
                  </TableCell>
                  <TableCell sx={{ maxWidth: 280 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                      <Chip label={f.severity} size="small"
                        sx={{ bgcolor: `${SEV_COLOR[f.severity] || "#888"}25`, color: SEV_COLOR[f.severity] || "#888", fontSize: 9, height: 16, textTransform: "uppercase", fontWeight: 700 }} />
                      <Typography variant="caption" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12 }}>{f.title}</Typography>
                    </Box>
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title={lowConf ? "Low confidence — most factors estimated" : "Confidence OK"}>
                      <Typography variant="body2" sx={{ color: lowConf ? "#FBBC04" : "#34A853", fontWeight: 700, fontSize: 13 }}>
                        {r.rps.toFixed(1)}
                      </Typography>
                    </Tooltip>
                  </TableCell>
                  {(["cvss","epss","kev_multiplier","reachability","exploitability","asset_criticality","business_context"] as const).map((k) => {
                    const fac = r.factors[k];
                    if (!fac) return <TableCell key={k} align="right" />;
                    return (
                      <TableCell key={k} align="right">
                        <Tooltip title={`${fac.source.toUpperCase()}: ${fac.rationale}`}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, justifyContent: "flex-end" }}>
                            <Typography variant="caption" sx={{ color: "text.primary", fontSize: 11 }}>
                              {typeof fac.value === "number" ? (Number.isInteger(fac.value) ? fac.value : fac.value.toFixed(2)) : "—"}
                            </Typography>
                            <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: SOURCE_COLOR[fac.source] }} />
                          </Box>
                        </Tooltip>
                      </TableCell>
                    );
                  })}
                  <TableCell />
                </TableRow>
                <TableRow>
                  <TableCell colSpan={11} sx={{ borderBottom: 0, p: 0 }}>
                    <Collapse in={isOpen}>
                      <Box sx={{ p: 2, bgcolor: "rgba(255,255,255,0.02)" }}>
                        {Object.entries(r.factors).map(([k, fac]) => (
                          <Box key={k} sx={{ mb: 0.75, display: "flex", gap: 1, alignItems: "flex-start" }}>
                            <Box sx={{ minWidth: 130, display: "flex", alignItems: "center", gap: 0.5 }}>
                              <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: SOURCE_COLOR[fac.source] }} />
                              <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "capitalize", fontWeight: 600 }}>
                                {k.replace(/_/g, " ")}
                              </Typography>
                            </Box>
                            <Typography variant="caption" sx={{ color: SOURCE_COLOR[fac.source], fontWeight: 700, minWidth: 70, textTransform: "uppercase", fontSize: 10 }}>
                              {fac.source}
                            </Typography>
                            <Typography variant="caption" sx={{ color: "text.secondary", flex: 1 }}>
                              {fac.rationale}
                            </Typography>
                          </Box>
                        ))}
                      </Box>
                    </Collapse>
                  </TableCell>
                </TableRow>
              </React.Fragment>
            );
          })}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

function FindingsTable({ findings, onDelete }: { findings: Finding[]; onDelete?: (f: Finding) => void }) {
  if (findings.length === 0) return <Typography variant="body2" sx={{ color: "text.secondary" }}>No findings recorded for this scan.</Typography>;
  return (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
            <TableCell>SEVERITY</TableCell>
            <TableCell>TITLE</TableCell>
            <TableCell>RESOURCE</TableCell>
            <TableCell>CVE</TableCell>
            <TableCell align="right">CVSS</TableCell>
            {onDelete && <TableCell align="right" sx={{ width: 44 }} />}
          </TableRow>
        </TableHead>
        <TableBody>
          {findings.map((f) => (
            <TableRow key={f.id} hover sx={{ "& td": { borderColor: "divider", color: "text.primary", py: 1 } }}>
              <TableCell>
                <Chip label={f.severity} size="small"
                  sx={{ bgcolor: `${SEV_COLOR[f.severity] || "#888"}25`, color: SEV_COLOR[f.severity] || "#888", fontSize: 10, height: 18, textTransform: "uppercase", fontWeight: 700 }} />
              </TableCell>
              <TableCell sx={{ maxWidth: 360 }}>
                <Typography variant="body2" sx={{ color: "text.primary", fontSize: 13, fontWeight: 500 }}>{f.title}</Typography>
                {f.description && (
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.25 }}>
                    {f.description.slice(0, 160)}{f.description.length > 160 ? "…" : ""}
                  </Typography>
                )}
              </TableCell>
              <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{f.resource_id || "—"}</TableCell>
              <TableCell sx={{ color: f.cve_id ? "#4285F4" : "text.secondary", fontSize: 12 }}>{f.cve_id || "—"}</TableCell>
              <TableCell align="right" sx={{ color: f.cvss_score && f.cvss_score >= 7 ? "#EA4335" : "text.secondary", fontSize: 12 }}>
                {f.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}
              </TableCell>
              {onDelete && (
                <TableCell align="right" sx={{ width: 44 }}>
                  <Tooltip title="Delete finding">
                    <IconButton
                      size="small"
                      onClick={(e) => { e.stopPropagation(); onDelete(f); }}
                      sx={{
                        color: "text.secondary",
                        "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" },
                      }}
                    >
                      <DeleteOutlined sx={{ fontSize: 18 }} />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              )}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

// ── Nav ──────────────────────────────────────────────────────────────────────

const BASE_NAV: DetailNavItem[] = [
  { id: "verdict",  label: "AI Verdict",  Icon: AutoAwesome, color: "#4285F4" },
  { id: "findings", label: "Findings",    Icon: BugReport,   color: "#EA4335" },
];

// ── Page ─────────────────────────────────────────────────────────────────────

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const scansBase = location.pathname.startsWith("/vulnerability") ? "/vulnerability/scans" : "/scans";
  const qc = useQueryClient();
  const [tab, setTab] = useState<string>("verdict");
  const [agentMenuAnchor, setAgentMenuAnchor] = useState<null | HTMLElement>(null);
  const { clientId } = useActiveClient();
  // When the browser triggers print (button or Ctrl+P), expand every tab
  // section so the whole assessment renders as a single document.
  const [printing, setPrinting] = useState<boolean>(false);
  React.useEffect(() => {
    const onBefore = () => setPrinting(true);
    const onAfter = () => setPrinting(false);
    window.addEventListener("beforeprint", onBefore);
    window.addEventListener("afterprint", onAfter);
    return () => {
      window.removeEventListener("beforeprint", onBefore);
      window.removeEventListener("afterprint", onAfter);
    };
  }, []);

  const { data, isLoading, error, refetch } = useQuery<ScanDetailData>({
    queryKey: ["scan-detail", scanId],
    queryFn: () => assessmentsApi.detail(scanId!),
    enabled: !!scanId,
    refetchInterval: (q) => {
      const d = q.state.data as ScanDetailData | undefined;
      return d?.status === "running" ? 5000 : false;
    },
  });

  const generateMutation = useMutation({
    mutationFn: () => assessmentsApi.generateVerdict(scanId!),
    onSuccess: () => {
      toast.success("Verdict queued — regenerating…");
      // Poll for the new verdict
      setTimeout(() => qc.invalidateQueries({ queryKey: ["scan-detail", scanId] }), 2000);
      setTimeout(() => qc.invalidateQueries({ queryKey: ["scan-detail", scanId] }), 8000);
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Failed to queue verdict"),
  });

  const runAgentMutation = useMutation({
    mutationFn: (agentType: string) => agentsApi.run(clientId!, {
      scan_id: scanId,
      agent_type: agentType,
      framework: data?.framework || "nist_csf",
    }),
    onSuccess: () => {
      toast.success("Agent queued — results will appear in AI Buddies");
      setAgentMenuAnchor(null);
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Failed to queue agent"),
  });

  const [bannerDismissed, setBannerDismissed] = useState(false);
  const [pendingDelete, setPendingDelete] = React.useState<Finding | null>(null);
  const deleteFinding = useMutation({
    mutationFn: ({ clientId, findingId }: { clientId: string; findingId: string }) =>
      findingsApi.delete(clientId, findingId),
    onSuccess: () => {
      toast.success("Finding deleted");
      setPendingDelete(null);
      qc.invalidateQueries({ queryKey: ["scan-detail", scanId] });
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Failed to delete finding"),
  });

  const verdict = data?.ai_verdict;
  const statusColor = data ? STATUS_COLOR[data.status] || "rgba(255,255,255,0.3)" : "rgba(255,255,255,0.3)";

  if (isLoading) {
    return <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>;
  }
  if (error || !data) {
    return <Alert severity="error" sx={{ mt: 2 }}>Scan not found or you don't have access.</Alert>;
  }

  return (
    <Box className="scan-detail-print-area">
      <PageDetailLayout
        entityName={data ? (data.name || `${data.scan_type} scan`) : "Assessment"}
        entityType="Assessment"
        avatarColor="#4285F4"
        navItems={[
          ...BASE_NAV.map((item: DetailNavItem) =>
            item.id === "findings"
              ? { ...item, label: `Findings (${data?.findings?.length ?? 0})` }
              : item
          ),
          ...(data?.agent_runs ?? []).map((ar: any) => ({
            id: `agent-${ar.id}`,
            label: ar.input_data?.agent_name || ar.output_data?.agent_name
              ? (ar.input_data?.agent_name || ar.output_data?.agent_name || ar.agent_type || "agent").replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())
              : ar.agent_type
                ? ar.agent_type.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())
                : "Agent",
            Icon: SmartToy,
            color: "#9C27B0",
          } as DetailNavItem)),
          { id: "help", label: "Help", Icon: MenuBook, color: "#00BCD4" } as DetailNavItem,
        ]}
        activeId={tab}
        onSelect={(id: string) => {
          if (id === "help") navigate("/help");
          else setTab(id);
        }}
        fullWidth={printing}
      >
      {/* Print stylesheet — flatten tabs into a single document, swap dark
          chrome for paper-friendly contrast, hide nav/buttons. Triggered
          by either the Print/PDF button or Ctrl+P. */}
      <style>{`
        @media print {
          @page { size: A4; margin: 12mm; }
          body { background: #fff !important; }
          .MuiDrawer-root, .MuiAppBar-root, .no-print { display: none !important; }
          .scan-detail-print-area { padding: 0 !important; max-width: 100% !important; color: #1a1a1a !important; }

          /* Print brand/severity colours instead of letting the browser drop backgrounds */
          .scan-detail-print-area, .scan-detail-print-area * {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
          }

          /* Paper-white surfaces (the portal canvas is dark) */
          .scan-detail-print-area .MuiCard-root,
          .scan-detail-print-area .MuiCardContent-root,
          .scan-detail-print-area .MuiPaper-root,
          .scan-detail-print-area .MuiTableContainer-root {
            background: #fff !important;
            box-shadow: none !important;
            border-color: #e0e0e0 !important;
          }
          .scan-detail-print-area .MuiTableCell-root { border-color: #e0e0e0 !important; }

          /* Legible dark body text — chips, charts and .keep-color brand values
             keep their portal colours (severity chips, status, progress, etc.) */
          .scan-detail-print-area .MuiTypography-root:not(.keep-color),
          .scan-detail-print-area .MuiTableCell-root:not(.keep-color) {
            color: #1a1a1a !important;
          }

          .scan-detail-print-area h6, .scan-detail-print-area .MuiTypography-h5 {
            page-break-after: avoid;
          }
          .scan-detail-print-area .MuiCard-root { page-break-inside: avoid; }
        }
      `}</style>

      <Box className="no-print" sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
        <Button startIcon={<ArrowBack />} size="small"
          onClick={() => navigate(scansBase)}
          sx={{ color: "text.secondary" }}>
          Assessments
        </Button>
      </Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>{data.tile_name}</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            {data.name || `${data.scan_type} scan`}
            {data.framework ? ` · ${data.framework}` : ""}
            {data.started_at ? ` · started ${fromNow(data.started_at)}` : ""}
            {data.duration_seconds != null ? ` · ${data.duration_seconds >= 60 ? `${Math.round(data.duration_seconds / 60)} min` : `${data.duration_seconds}s`}` : ""}
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1 }}>
          <Chip label={data.status} sx={{
            bgcolor: `${statusColor}20`, color: statusColor, fontWeight: 700,
            textTransform: "uppercase", fontSize: 11, height: 24,
          }} />
          <Button variant="outlined" startIcon={<Refresh />} onClick={() => refetch()}
            className="no-print"
            sx={{ borderColor: "divider", color: "text.secondary" }}>
            Refresh
          </Button>
          <Button variant="outlined" startIcon={<Print />} onClick={() => window.print()}
            className="no-print"
            sx={{ borderColor: "divider", color: "text.secondary",
              "&:hover": { borderColor: "#4285F4", color: "#4285F4" } }}>
            Print / PDF
          </Button>
          {data.status === "completed" && clientId && (
            <>
              <Button
                variant="outlined"
                startIcon={<SmartToy />}
                className="no-print"
                onClick={(e) => setAgentMenuAnchor(e.currentTarget)}
                sx={{ borderColor: "#7C4DFF", color: "#7C4DFF", "&:hover": { borderColor: "#7C4DFF", bgcolor: "rgba(124,77,255,0.08)" } }}
              >
                Analyse with AI
              </Button>
              <Menu anchorEl={agentMenuAnchor} open={Boolean(agentMenuAnchor)} onClose={() => setAgentMenuAnchor(null)}>
                {[
                  { type: "orchestrator", label: "Full Orchestrated Analysis" },
                  { type: "threat_intel", label: "Threat Intelligence" },
                  { type: "compliance_monitor", label: "Compliance Monitor" },
                  { type: "remediation", label: "Remediation Planner" },
                ].map(({ type, label }) => (
                  <MuiMenuItem key={type} onClick={() => runAgentMutation.mutate(type)} disabled={runAgentMutation.isPending}>
                    {label}
                  </MuiMenuItem>
                ))}
              </Menu>
            </>
          )}
          <Button variant="contained" startIcon={<AutoAwesome />}
            disabled={generateMutation.isPending}
            className="no-print"
            onClick={() => generateMutation.mutate()}>
            {verdict ? "Regenerate Verdict" : "Generate Verdict"}
          </Button>
        </Box>
      </Box>

      {/* Running-scan progress banner */}
      {data.status === "running" && !bannerDismissed && (
        <Box
          className="no-print"
          sx={{
            mb: 2,
            borderLeft: "3px solid #FBBC04",
            bgcolor: "rgba(251,188,4,0.06)",
            borderRadius: "0 8px 8px 0",
            overflow: "hidden",
          }}
        >
          <LinearProgress
            variant="indeterminate"
            sx={{
              height: 3,
              bgcolor: "rgba(251,188,4,0.15)",
              "& .MuiLinearProgress-bar": { bgcolor: "#FBBC04" },
            }}
          />
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, px: 2, py: 1 }}>
            <Chip
              label="Scanning…"
              size="small"
              sx={{
                bgcolor: "rgba(251,188,4,0.18)",
                color: "#FBBC04",
                fontWeight: 700,
                fontSize: 10,
                height: 20,
                letterSpacing: 0.5,
              }}
            />
            <Typography variant="body2" sx={{ color: "#FBBC04", fontWeight: 500, flex: 1 }}>
              {data.progress_message || "Scan in progress…"}
            </Typography>
            <IconButton
              size="small"
              onClick={() => setBannerDismissed(true)}
              sx={{ color: "rgba(251,188,4,0.6)", "&:hover": { color: "#FBBC04" } }}
            >
              <Close sx={{ fontSize: 16 }} />
            </IconButton>
          </Box>
        </Box>
      )}

      {/* AI Verdict tab */}
      {(tab === "verdict" || printing) && (
        verdict ? (
          <Box>
            <VerdictHeadline verdict={verdict} />
            <Grid container spacing={2}>
              <Grid size={{ xs: 12, md: 6 }}>
                <SectionCard title="What We Found" accent="#4285F4">
                  <NarrativeBlock text={verdict.what_we_found} />
                </SectionCard>
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <SectionCard title="Why It Matters" accent="#EA4335">
                  <NarrativeBlock text={verdict.why_it_matters} />
                </SectionCard>
              </Grid>
            </Grid>
            <SectionCard title="Executive Summary" accent="#9C27B0">
              <NarrativeBlock text={verdict.executive_summary} />
            </SectionCard>
            <SectionCard title="Capability Gap Recommendations" subtitle="Concrete remediation moves" accent="#FF7043">
              <CapabilityGaps gaps={verdict.capability_gaps} />
            </SectionCard>
            <SectionCard title="Signal Coverage Report" subtitle="What this assessment covered vs. what's missing" accent="#34A853">
              <SignalCoverage rows={verdict.signal_coverage} />
            </SectionCard>
            <SectionCard title="Attack Path Evidence" subtitle="Chained findings on a single resource" accent="#EA4335">
              <AttackPaths rows={verdict.attack_paths} />
            </SectionCard>
            <SectionCard title="Vendor Scorecard — Vulnerability Management" subtitle="Where each VM vendor appears in this scan's signal" accent="#00ACC1">
              <VendorScorecard rows={verdict.vendor_scorecard} />
            </SectionCard>
            <SectionCard title="Risk Priority Score (RPS)"
              subtitle="CVSS × EPSS × KEV × Reachability × Exploitability × Asset Criticality × Business Context. Source dot per factor: green=evidenced, yellow=estimated, grey=unknown (dropped from product)."
              accent="#FBBC04">
              <RpsFactorTable findings={data.findings} />
            </SectionCard>
            <SectionCard title="Data Completeness" subtitle="Honest accounting of what's evidenced vs estimated" accent="#34A853">
              <DataCompleteness dc={verdict.data_completeness} />
            </SectionCard>
            <SectionCard title="Automation Opportunities" subtitle="Quick wins to harden the next assessment" accent="#4285F4">
              <AutomationOpps rows={verdict.automation_opportunities} />
            </SectionCard>
          </Box>
        ) : (
          <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
            <AutoAwesome sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
            <Typography sx={{ color: "text.secondary", mb: 2 }}>
              No AI verdict yet. Verdicts auto-generate when a scan completes; if this scan finished before that hook landed, click below to generate now.
            </Typography>
            <Button variant="contained" startIcon={<AutoAwesome />}
              onClick={() => generateMutation.mutate()} disabled={generateMutation.isPending}>
              {generateMutation.isPending ? <CircularProgress size={18} /> : "Generate Verdict"}
            </Button>
          </Card>
        )
      )}

      {/* Findings tab */}
      {(tab === "findings" || printing) && (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <FindingsTable
              findings={data.findings}
              onDelete={printing ? undefined : (f) => setPendingDelete(f)}
            />
          </CardContent>
        </Card>
      )}

      {/* Per-agent run tabs */}
      {data.agent_runs.map((ar) => (tab === `agent-${ar.id}` || printing) && (
        <Card key={ar.id} sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
              <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 700, textTransform: "capitalize" }}>
                {agentLabel(ar)}
              </Typography>
              <Chip label={ar.status} size="small"
                sx={{
                  height: 20, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                  bgcolor: ar.status === "completed" ? "rgba(52,168,83,0.15)" : ar.status === "failed" ? "rgba(234,67,53,0.15)" : "rgba(251,188,4,0.15)",
                  color: ar.status === "completed" ? "#34A853" : ar.status === "failed" ? "#EA4335" : "#FBBC04",
                }} />
              <Box sx={{ flex: 1 }} />
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {ar.started_at ? fromNow(ar.started_at) : ""}{ar.tokens_used ? ` · ${ar.tokens_used} tokens` : ""}
              </Typography>
            </Box>
            <Divider sx={{ borderColor: "divider", mb: 1.5 }} />
            {ar.error_message && (
              <Alert severity="error" sx={{ mb: 1.5 }}>{ar.error_message}</Alert>
            )}
            <RichOutput value={ar.output_data} />
          </CardContent>
        </Card>
      ))}

      {/* Confirm delete dialog */}
      <Dialog open={!!pendingDelete} onClose={() => setPendingDelete(null)}
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>Delete finding?</DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            This permanently removes the finding. If the same issue is detected on the next scan it will be re-created.
          </Typography>
          {pendingDelete && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600 }}>{pendingDelete.title || "(no title)"}</Typography>
              {pendingDelete.resource_id && (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>{pendingDelete.resource_id}</Typography>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDelete(null)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button
            variant="contained"
            disabled={deleteFinding.isPending}
            onClick={() => pendingDelete && deleteFinding.mutate({ clientId: data.client_id, findingId: pendingDelete.id })}
            sx={{ bgcolor: "#EA4335", "&:hover": { bgcolor: "#c5362b" } }}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>
      </PageDetailLayout>
    </Box>
  );
}
