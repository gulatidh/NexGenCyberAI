import React, { useState, useMemo } from "react";
import {
  Box, Typography, Grid, Card, CardContent, Chip, Alert, Button,
  CircularProgress, Tooltip, LinearProgress, Divider,
} from "@mui/material";
import { OpenInNew, Assessment, ChevronRight } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { riskPortfolioApi } from "../services/api";
import { useActiveClient } from "../contexts/ClientContext";

// ── Types ────────────────────────────────────────────────────────────────────

interface DomainRow {
  domain: string;
  exposure: number;
  count: number;
  severity_counts?: Record<string, number>;
}

interface RiskRow {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  domain: string;
  category: string | null;
  impact: number;
  likelihood: number;
  risk_score: number;
  ale: number;
  ale_low: number;
  ale_high: number;
  net_ale: number;
  remediation_status: string;
  finding_ids: string[];
  finding_count: number;
  owner?: string | null;
  due_date?: string | null;
  likelihood_avg?: number;
  impact_avg?: number;
  risk_matrix_score?: number;
  treatment_option?: string;
  status_label?: string;
}

interface Portfolio {
  total_exposure: number;
  net_exposure: number;
  mitigated_pct: number;
  open_critical_high: number;
  open_critical: number;
  open_high: number;
  breach_probability_30d: number;
  annual_event_rate: number;
  by_domain: DomainRow[];
  risks: RiskRow[];
}

// ── Constants ────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853",
};

const RISK_STATUSES = [
  { value: "identified",           label: "Identified",           color: "#FF7043" },
  { value: "under_assessment",     label: "Under Assessment",     color: "#7C3AED" },
  { value: "treatment_planned",    label: "Treatment Planned",    color: "#1565C0" },
  { value: "accepted",             label: "Accepted",             color: "#4285F4" },
  { value: "transferred",          label: "Transferred",          color: "#00ACC1" },
  { value: "closed",               label: "Closed",               color: "#34A853" },
  { value: "no_longer_applicable", label: "No Longer Applicable", color: "#757575" },
  { value: "escalated",            label: "Escalated",            color: "#EA4335" },
  { value: "open",                 label: "Open",                 color: "#FF7043" },
  { value: "in_progress",          label: "In Progress",          color: "#FBBC04" },
  { value: "remediated",           label: "Remediated",           color: "#34A853" },
];

function matrixLevel(score: number): string {
  if (score <= 4) return "low";
  if (score <= 9) return "medium";
  if (score <= 12) return "medium_high";
  if (score <= 20) return "high";
  return "critical";
}

const LEVEL_COLOR: Record<string, string> = {
  low: "#34A853", medium: "#FBBC04", medium_high: "#FF7043", high: "#EA4335", critical: "#B71C1C",
};

function fmtCurrency(n: number): string {
  if (!n) return "$0";
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toFixed(0)}`;
}

// ── Sub-components ───────────────────────────────────────────────────────────

function StatusChip({ status }: { status: string }) {
  const def = RISK_STATUSES.find((s) => s.value === status)
    || { label: status.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()), color: "#888" };
  return (
    <Chip
      label={def.label}
      size="small"
      sx={{ bgcolor: `${def.color}20`, color: def.color, fontSize: 10, height: 20, fontWeight: 600 }}
    />
  );
}

function RiskMatrix({ risks }: { risks: RiskRow[] }) {
  const CELL = 52;
  const PAD = 36;
  const W = CELL * 5 + PAD;
  const H = CELL * 5 + PAD;

  type Cell = { lik: number; imp: number; items: RiskRow[] };
  const cellMap = new Map<string, Cell>();
  for (const r of risks) {
    const lik5 = Math.max(1, Math.min(5, Math.round((r.likelihood_avg ?? r.likelihood / 2))));
    const imp5 = Math.max(1, Math.min(5, Math.round((r.impact_avg ?? r.impact / 2))));
    const key = `${lik5},${imp5}`;
    if (!cellMap.has(key)) cellMap.set(key, { lik: lik5, imp: imp5, items: [] });
    cellMap.get(key)!.items.push(r);
  }

  const cx = (lik: number) => PAD + (lik - 1) * CELL + CELL / 2;
  const cy = (imp: number) => (5 - imp) * CELL + CELL / 2;

  const cellColors: Record<string, string> = {
    low: "#34A85318", medium: "#FBBC0425", medium_high: "#FF704335", high: "#EA433545", critical: "#B71C1C60",
  };

  return (
    <Box>
      <Typography variant="caption" sx={{ color: "text.secondary", mb: 1, display: "block" }}>
        5×5 GCC IM8 Risk Matrix — each dot represents one or more risks at that position
      </Typography>
      <Box sx={{ overflowX: "auto" }}>
        <svg width={W} height={H} style={{ display: "block" }}>
          {[1, 2, 3, 4, 5].map((imp) =>
            [1, 2, 3, 4, 5].map((lik) => {
              const level = matrixLevel(lik * imp);
              return (
                <rect
                  key={`cell_${lik},${imp}`}
                  x={PAD + (lik - 1) * CELL}
                  y={(5 - imp) * CELL}
                  width={CELL}
                  height={CELL}
                  fill={cellColors[level]}
                  stroke="rgba(255,255,255,0.06)"
                  strokeWidth={1}
                />
              );
            })
          )}
          {[1, 2, 3, 4, 5].map((imp) =>
            [1, 2, 3, 4, 5].map((lik) => (
              <text
                key={`score_${lik},${imp}`}
                x={PAD + (lik - 1) * CELL + CELL / 2}
                y={(5 - imp) * CELL + CELL / 2 + 3}
                textAnchor="middle"
                fontSize={9}
                fill="rgba(255,255,255,0.18)"
              >
                {lik * imp}
              </text>
            ))
          )}
          {[1, 2, 3, 4, 5].map((v) => (
            <React.Fragment key={`axis_${v}`}>
              <text
                x={PAD + (v - 1) * CELL + CELL / 2}
                y={H - 6}
                textAnchor="middle"
                fontSize={10}
                fill="rgba(255,255,255,0.4)"
              >
                {v}
              </text>
              <text
                x={14}
                y={(5 - v) * CELL + CELL / 2 + 4}
                textAnchor="middle"
                fontSize={10}
                fill="rgba(255,255,255,0.4)"
              >
                {v}
              </text>
            </React.Fragment>
          ))}
          <text x={PAD + (CELL * 5) / 2} y={H} textAnchor="middle" fontSize={10} fill="rgba(255,255,255,0.35)">
            Likelihood →
          </text>
          <text
            x={7}
            y={(CELL * 5) / 2}
            textAnchor="middle"
            fontSize={10}
            fill="rgba(255,255,255,0.35)"
            transform={`rotate(-90, 7, ${(CELL * 5) / 2})`}
          >
            ↑ Impact
          </text>
          {Array.from(cellMap.values()).map(({ lik, imp, items }) => {
            const primarySev =
              items.find((ri) => ri.severity === "critical")?.severity ||
              items.find((ri) => ri.severity === "high")?.severity ||
              items[0].severity;
            const color = SEV_COLOR[primarySev] || "#888";
            const dotX = cx(lik);
            const dotY = cy(imp);
            const radius = items.length > 1 ? 14 : 10;
            const titles = items.map((i) => i.title).join("\n");
            return (
              <Tooltip key={`dot_${lik},${imp}`} title={<span style={{ whiteSpace: "pre-line" }}>{titles}</span>} arrow>
                <g style={{ cursor: "pointer" }}>
                  <circle cx={dotX} cy={dotY} r={radius} fill={color} fillOpacity={0.85} stroke={color} strokeWidth={1.5} />
                  {items.length > 1 ? (
                    <text x={dotX} y={dotY + 4} textAnchor="middle" fontSize={11} fontWeight="700" fill="white">
                      {items.length}
                    </text>
                  ) : (
                    <circle cx={dotX} cy={dotY} r={3} fill="white" fillOpacity={0.6} />
                  )}
                </g>
              </Tooltip>
            );
          })}
        </svg>
      </Box>
      <Box sx={{ display: "flex", gap: 1.5, flexWrap: "wrap", mt: 1 }}>
        {(["critical", "high", "medium", "low"] as const).map((lv) => (
          <Box key={lv} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <Box sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: SEV_COLOR[lv] }} />
            <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "capitalize" }}>{lv}</Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

function DomainSeverityChart({ rows }: { rows: DomainRow[] }) {
  const maxCount = Math.max(1, ...rows.map((r) => r.count));
  const sevKeys = ["critical", "high", "medium", "low"] as const;
  return (
    <Box>
      {rows.length === 0 ? (
        <Typography variant="caption" sx={{ color: "text.secondary" }}>
          No domain data yet — categorise risks to populate this chart.
        </Typography>
      ) : (
        rows.map((row) => {
          const sc = row.severity_counts || {};
          return (
            <Box key={row.domain} sx={{ mb: 1.5 }}>
              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", mb: 0.4 }}>
                <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 13 }}>{row.domain}</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  {row.count} risk{row.count !== 1 ? "s" : ""}
                </Typography>
              </Box>
              <Box
                sx={{
                  display: "flex", height: 10, borderRadius: 5, overflow: "hidden",
                  bgcolor: "rgba(255,255,255,0.06)", width: "100%",
                }}
              >
                {sevKeys.map((sev) => {
                  const cnt = sc[sev] || 0;
                  if (!cnt) return null;
                  const pct = (cnt / maxCount) * 100;
                  return (
                    <Tooltip key={sev} title={`${cnt} ${sev}`}>
                      <Box sx={{ width: `${pct}%`, bgcolor: SEV_COLOR[sev], minWidth: 3 }} />
                    </Tooltip>
                  );
                })}
              </Box>
              <Box sx={{ display: "flex", gap: 0.75, mt: 0.5, flexWrap: "wrap" }}>
                {sevKeys.map((sev) => {
                  const cnt = sc[sev] || 0;
                  if (!cnt) return null;
                  return (
                    <Typography key={sev} variant="caption" sx={{ color: SEV_COLOR[sev], fontSize: 10, fontWeight: 700 }}>
                      {cnt} {sev}
                    </Typography>
                  );
                })}
              </Box>
            </Box>
          );
        })
      )}
    </Box>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function RiskOverview() {
  const navigate = useNavigate();
  const { clientId } = useActiveClient();
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [domainFilter, setDomainFilter] = useState("");

  const { data: portfolio, isLoading } = useQuery<Portfolio>({
    queryKey: ["risk-portfolio", clientId],
    queryFn: () => riskPortfolioApi.get(clientId),
    enabled: !!clientId,
  });

  const filteredRisks = useMemo(() => {
    const base = portfolio?.risks || [];
    const filtered = base.filter((r) => {
      if (severityFilter && r.severity !== severityFilter) return false;
      if (statusFilter && r.remediation_status !== statusFilter) return false;
      if (domainFilter && r.domain !== domainFilter) return false;
      return true;
    });
    return [...filtered].sort((a, b) => {
      const scoreA = a.risk_matrix_score || 0;
      const scoreB = b.risk_matrix_score || 0;
      return scoreB - scoreA || b.net_ale - a.net_ale;
    });
  }, [portfolio, severityFilter, statusFilter, domainFilter]);

  const sevCounts = useMemo(() => {
    const out: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const r of portfolio?.risks || []) {
      if (r.severity in out) out[r.severity]++;
    }
    return out;
  }, [portfolio]);

  const breachPct = Math.round((portfolio?.breach_probability_30d || 0) * 100);
  const breachColor =
    breachPct >= 70 ? "#EA4335" : breachPct >= 40 ? "#FF7043" : breachPct >= 15 ? "#FBBC04" : "#34A853";
  const breachLabel =
    breachPct >= 70 ? "Critical" : breachPct >= 40 ? "Elevated" : breachPct >= 15 ? "Moderate" : "Low";

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Risk Portfolio</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Risk posture, domain exposure, and FAIR-lite financial estimates across the risk register
          </Typography>
        </Box>
        <Button
          size="small"
          variant="outlined"
          endIcon={<ChevronRight />}
          onClick={() => navigate("/analyse/risks")}
          sx={{ fontSize: 12, mt: 0.5 }}
        >
          Risk Register
        </Button>
      </Box>

      {!clientId ? (
        <Alert severity="info">Select a client to load the risk portfolio.</Alert>
      ) : isLoading || !portfolio ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      ) : portfolio.risks.length === 0 ? (
        <Box sx={{ textAlign: "center", py: 8 }}>
          <Assessment sx={{ fontSize: 56, color: "text.disabled", mb: 2 }} />
          <Typography variant="h6" sx={{ color: "text.secondary", fontWeight: 700, mb: 1 }}>
            No risks in portfolio
          </Typography>
          <Typography variant="body2" sx={{ color: "text.secondary", maxWidth: 400, mx: "auto" }}>
            Evaluate proposals in Risk Staging or run the Risk Manager agent to populate the portfolio.
          </Typography>
          <Button variant="outlined" sx={{ mt: 2 }} onClick={() => navigate("/analyse/risks/staging")}>
            Open Risk Staging
          </Button>
        </Box>
      ) : (
        <>
          {/* KPI Strip */}
          <Grid container spacing={2} sx={{ mb: 2.5 }}>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
                <CardContent sx={{ "&:last-child": { pb: 2 } }}>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11, textTransform: "uppercase", letterSpacing: 1, fontWeight: 600 }}>
                    Portfolio Risks
                  </Typography>
                  <Typography sx={{ color: "text.primary", fontSize: 30, fontWeight: 700, lineHeight: 1.15, mt: 0.5 }}>
                    {portfolio.risks.length}
                  </Typography>
                  <Box sx={{ display: "flex", gap: 0.75, flexWrap: "wrap", mt: 0.75 }}>
                    {(["critical", "high", "medium", "low"] as const).map(
                      (sev) =>
                        sevCounts[sev] > 0 && (
                          <Chip
                            key={sev}
                            size="small"
                            label={`${sevCounts[sev]} ${sev}`}
                            sx={{ height: 18, fontSize: 10, bgcolor: `${SEV_COLOR[sev]}20`, color: SEV_COLOR[sev], fontWeight: 700 }}
                          />
                        )
                    )}
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
                <CardContent sx={{ "&:last-child": { pb: 2 } }}>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11, textTransform: "uppercase", letterSpacing: 1, fontWeight: 600 }}>
                    Critical + High
                  </Typography>
                  <Typography
                    sx={{ color: portfolio.open_critical > 0 ? "#EA4335" : "#FF7043", fontSize: 30, fontWeight: 700, lineHeight: 1.15, mt: 0.5 }}
                  >
                    {portfolio.open_critical_high}
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    <span style={{ color: "#EA4335" }}>{portfolio.open_critical} critical</span>
                    {" · "}
                    <span style={{ color: "#FF7043" }}>{portfolio.open_high} high</span>
                    {" requiring action"}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
                <CardContent sx={{ "&:last-child": { pb: 2 } }}>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11, textTransform: "uppercase", letterSpacing: 1, fontWeight: 600 }}>
                    Risk Reduction
                  </Typography>
                  <Typography
                    sx={{ color: portfolio.mitigated_pct >= 50 ? "#34A853" : "#FF7043", fontSize: 30, fontWeight: 700, lineHeight: 1.15, mt: 0.5 }}
                  >
                    {portfolio.mitigated_pct}%
                  </Typography>
                  <LinearProgress
                    variant="determinate"
                    value={portfolio.mitigated_pct}
                    sx={{
                      mt: 1, height: 5, borderRadius: 3, bgcolor: "rgba(255,255,255,0.08)",
                      "& .MuiLinearProgress-bar": { bgcolor: portfolio.mitigated_pct >= 50 ? "#34A853" : "#FF7043", borderRadius: 3 },
                    }}
                  />
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.5 }}>
                    Est. {fmtCurrency(portfolio.net_exposure)} net vs {fmtCurrency(portfolio.total_exposure)} gross
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
                <CardContent sx={{ "&:last-child": { pb: 2 } }}>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11, textTransform: "uppercase", letterSpacing: 1, fontWeight: 600 }}>
                    30-Day Breach Probability
                  </Typography>
                  <Typography sx={{ color: breachColor, fontSize: 30, fontWeight: 700, lineHeight: 1.15, mt: 0.5 }}>
                    {breachPct}%
                  </Typography>
                  <LinearProgress
                    variant="determinate"
                    value={breachPct}
                    sx={{
                      mt: 1, height: 5, borderRadius: 3, bgcolor: "rgba(255,255,255,0.08)",
                      "& .MuiLinearProgress-bar": { bgcolor: breachColor, borderRadius: 3 },
                    }}
                  />
                  <Typography variant="caption" sx={{ display: "block", mt: 0.5 }}>
                    <span style={{ color: breachColor, fontWeight: 700 }}>{breachLabel}</span>
                    <span style={{ color: "rgba(255,255,255,0.4)" }}> — Poisson model from open C/H risks</span>
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Matrix + Domain */}
          <Grid container spacing={2} sx={{ mb: 2.5 }}>
            <Grid size={{ xs: 12, md: 6 }}>
              <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
                <CardContent>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5 }}>Risk Matrix</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 2 }}>
                    Likelihood vs Impact — where your risks cluster
                  </Typography>
                  <RiskMatrix risks={portfolio.risks} />
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Risk by Domain</Typography>
                    <Chip
                      label={`${portfolio.by_domain.length} domains`}
                      size="small"
                      sx={{ height: 18, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 10, fontWeight: 700 }}
                    />
                  </Box>
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 2 }}>
                    Risk count by severity per domain
                  </Typography>
                  <DomainSeverityChart rows={portfolio.by_domain} />
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Filters */}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 1.5, mb: 2 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, flexWrap: "wrap" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 1 }}>SEVERITY</Typography>
              {["critical", "high", "medium", "low"].map((s) => (
                <Chip
                  key={s}
                  size="small"
                  label={s.charAt(0).toUpperCase() + s.slice(1)}
                  onClick={() => setSeverityFilter(severityFilter === s ? "" : s)}
                  sx={{
                    cursor: "pointer",
                    bgcolor: severityFilter === s ? `${SEV_COLOR[s]}25` : "rgba(255,255,255,0.04)",
                    color: severityFilter === s ? SEV_COLOR[s] : "text.secondary",
                    border: severityFilter === s ? `1px solid ${SEV_COLOR[s]}` : "1px solid transparent",
                    fontWeight: severityFilter === s ? 700 : 400,
                  }}
                />
              ))}
              <Divider orientation="vertical" flexItem sx={{ mx: 1 }} />
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 1 }}>STATUS</Typography>
              {RISK_STATUSES.slice(0, 8).map((rs) => (
                <Chip
                  key={rs.value}
                  size="small"
                  label={rs.label}
                  onClick={() => setStatusFilter(statusFilter === rs.value ? "" : rs.value)}
                  sx={{
                    cursor: "pointer",
                    bgcolor: statusFilter === rs.value ? `${rs.color}25` : "rgba(255,255,255,0.04)",
                    color: statusFilter === rs.value ? rs.color : "text.secondary",
                    border: statusFilter === rs.value ? `1px solid ${rs.color}` : "1px solid transparent",
                    fontWeight: statusFilter === rs.value ? 700 : 400,
                  }}
                />
              ))}
              {portfolio.by_domain.length > 0 && (
                <>
                  <Divider orientation="vertical" flexItem sx={{ mx: 1 }} />
                  <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 1 }}>DOMAIN</Typography>
                  {portfolio.by_domain.slice(0, 6).map((d) => (
                    <Chip
                      key={d.domain}
                      size="small"
                      label={d.domain}
                      onClick={() => setDomainFilter(domainFilter === d.domain ? "" : d.domain)}
                      sx={{
                        cursor: "pointer",
                        bgcolor: domainFilter === d.domain ? "rgba(66,133,244,0.2)" : "rgba(255,255,255,0.04)",
                        color: domainFilter === d.domain ? "#4285F4" : "text.secondary",
                        border: domainFilter === d.domain ? "1px solid #4285F4" : "1px solid transparent",
                        fontWeight: domainFilter === d.domain ? 700 : 400,
                      }}
                    />
                  ))}
                </>
              )}
              {(severityFilter || statusFilter || domainFilter) && (
                <Button
                  size="small"
                  sx={{ ml: 1, color: "text.secondary", fontSize: 11 }}
                  onClick={() => { setSeverityFilter(""); setStatusFilter(""); setDomainFilter(""); }}
                >
                  Clear
                </Button>
              )}
              <Box sx={{ flex: 1 }} />
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {filteredRisks.length} of {portfolio.risks.length} risks
              </Typography>
            </Box>
          </Card>

          {/* Risk rows */}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <Box sx={{ p: 2, borderBottom: "1px solid", borderColor: "divider" }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Risk Register</Typography>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                Click a row to view in the Risk Register · sorted by matrix score
              </Typography>
            </Box>
            <Box>
              {filteredRisks.map((r, idx) => {
                const lik5 = Math.max(1, Math.min(5, Math.round(r.likelihood_avg ?? r.likelihood / 2)));
                const imp5 = Math.max(1, Math.min(5, Math.round(r.impact_avg ?? r.impact / 2)));
                const matScore = r.risk_matrix_score || lik5 * imp5;
                const level = matrixLevel(matScore);
                const levColor = LEVEL_COLOR[level];
                return (
                  <Box
                    key={r.id}
                    onClick={() => navigate("/analyse/risks")}
                    sx={{
                      display: "flex",
                      alignItems: "center",
                      gap: 2,
                      px: 2,
                      py: 1.25,
                      borderBottom: idx < filteredRisks.length - 1 ? "1px solid" : "none",
                      borderColor: "divider",
                      cursor: "pointer",
                      "&:hover": { bgcolor: "rgba(255,255,255,0.025)" },
                      transition: "background 0.12s",
                    }}
                  >
                    {/* Level accent bar */}
                    <Box sx={{ width: 5, height: 36, borderRadius: 3, bgcolor: levColor, flexShrink: 0 }} />

                    {/* Title + domain */}
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Typography
                        variant="body2"
                        sx={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13 }}
                      >
                        {r.title}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        {r.domain}
                        {r.category && r.category !== r.domain ? ` · ${r.category}` : ""}
                      </Typography>
                    </Box>

                    {/* Matrix score bar */}
                    <Box sx={{ width: 100, flexShrink: 0 }}>
                      <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.25 }}>
                        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>Score</Typography>
                        <Typography variant="caption" sx={{ color: levColor, fontWeight: 700 }}>{matScore}/25</Typography>
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={(matScore / 25) * 100}
                        sx={{
                          height: 5, borderRadius: 3, bgcolor: "rgba(255,255,255,0.08)",
                          "& .MuiLinearProgress-bar": { bgcolor: levColor, borderRadius: 3 },
                        }}
                      />
                      <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, display: "block", mt: 0.25 }}>
                        L{lik5} · I{imp5}
                      </Typography>
                    </Box>

                    {/* Treatment */}
                    {r.treatment_option && (
                      <Chip
                        label={r.treatment_option}
                        size="small"
                        sx={{
                          height: 18, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary",
                          display: { xs: "none", md: "flex" }, textTransform: "capitalize", flexShrink: 0,
                        }}
                      />
                    )}

                    {/* Status */}
                    <Box sx={{ width: 140, flexShrink: 0, display: { xs: "none", sm: "block" } }}>
                      <StatusChip status={r.remediation_status} />
                    </Box>

                    {/* Net exposure */}
                    <Tooltip
                      title={`Gross: ${fmtCurrency(r.ale)} · Net (after mitigation): ${fmtCurrency(r.net_ale)} · Range: ${fmtCurrency(r.ale_low)}–${fmtCurrency(r.ale_high)}`}
                    >
                      <Box sx={{ width: 72, textAlign: "right", flexShrink: 0, display: { xs: "none", lg: "block" } }}>
                        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, display: "block" }}>
                          Est. exposure
                        </Typography>
                        <Typography variant="caption" sx={{ color: r.net_ale > 0 ? "#FF7043" : "#34A853", fontWeight: 700, fontSize: 12 }}>
                          {fmtCurrency(r.net_ale)}
                        </Typography>
                      </Box>
                    </Tooltip>

                    {/* Findings chip */}
                    {r.finding_count > 0 && (
                      <Tooltip title={`${r.finding_count} linked finding${r.finding_count > 1 ? "s" : ""}`}>
                        <Chip
                          label={r.finding_count}
                          size="small"
                          sx={{
                            height: 20, fontSize: 11, fontWeight: 700,
                            bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4",
                            flexShrink: 0, display: { xs: "none", md: "flex" },
                          }}
                        />
                      </Tooltip>
                    )}

                    <OpenInNew sx={{ fontSize: 14, color: "text.disabled", flexShrink: 0 }} />
                  </Box>
                );
              })}
            </Box>
          </Card>
        </>
      )}
    </Box>
  );
}
