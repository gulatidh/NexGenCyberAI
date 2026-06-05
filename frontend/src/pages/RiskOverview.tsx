import React, { useState } from "react";
import {
  Box, Typography, Grid, Card, CardContent, Chip, Alert, Button,
  CircularProgress, FormControl, InputLabel, Select, MenuItem,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  LinearProgress, Tooltip,
} from "@mui/material";
import { OpenInNew, TrendingUp } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { clientsApi, riskPortfolioApi } from "../services/api";
import { Client } from "../types";

// ── Types ────────────────────────────────────────────────────────────────────

interface DomainRow { domain: string; exposure: number; count: number; }

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

const REMEDIATION_STATUSES: { value: string; label: string; color: string }[] = [
  { value: "open",                  label: "Open",                  color: "#FF7043" },
  { value: "in_progress",           label: "In Progress",           color: "#FBBC04" },
  { value: "compensating_control",  label: "Compensating Control",  color: "#4285F4" },
  { value: "remediated",            label: "Remediated",            color: "#34A853" },
  { value: "accepted",              label: "Accepted",              color: "#9C27B0" },
  { value: "transferred",           label: "Transferred",           color: "#00ACC1" },
];

function fmtCurrency(n: number): string {
  if (!n) return "$0";
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000)     return `$${(n / 1_000).toFixed(1)}K`;
  return `$${n.toFixed(0)}`;
}

// ── Components ───────────────────────────────────────────────────────────────

function KpiCard({ label, value, sublabel, color = "#4285F4", progress }: {
  label: string; value: string; sublabel?: React.ReactNode; color?: string; progress?: number;
}) {
  return (
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
      <CardContent sx={{ "&:last-child": { pb: 2 } }}>
        <Typography variant="caption"
          sx={{ color: "text.secondary", fontSize: 11, textTransform: "uppercase", letterSpacing: 1, fontWeight: 600 }}>
          {label}
        </Typography>
        <Typography sx={{ color, fontSize: 30, fontWeight: 700, lineHeight: 1.15, mt: 0.5 }}>{value}</Typography>
        {progress !== undefined && (
          <LinearProgress variant="determinate" value={Math.min(100, Math.max(0, progress))}
            sx={{ mt: 1, height: 6, borderRadius: 3, bgcolor: "rgba(255,255,255,0.08)",
              "& .MuiLinearProgress-bar": { bgcolor: color, borderRadius: 3 } }} />
        )}
        {sublabel && (
          <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11, display: "block", mt: 0.5 }}>
            {sublabel}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

function RemediationChip({ value }: { value: string }) {
  const def = REMEDIATION_STATUSES.find((s) => s.value === value)
    || { value, label: value.replace(/_/g, " "), color: "text.secondary" };
  return (
    <Chip label={def.label} size="small"
      sx={{ bgcolor: `${def.color}20`, color: def.color, fontSize: 10, height: 20, textTransform: "capitalize", fontWeight: 600 }} />
  );
}

function DomainBar({ rows, total }: { rows: DomainRow[]; total: number }) {
  const max = Math.max(1, ...rows.map((r) => r.exposure));
  return (
    <Box>
      {rows.length === 0 ? (
        <Typography variant="caption" sx={{ color: "text.secondary" }}>
          No domain breakdown yet — categorise risks to populate this chart.
        </Typography>
      ) : rows.map((r) => {
        const pct = (r.exposure / max) * 100;
        const sharePct = total > 0 ? (r.exposure / total) * 100 : 0;
        return (
          <Box key={r.domain} sx={{ mb: 1.25 }}>
            <Box sx={{ display: "flex", alignItems: "baseline", gap: 1, mb: 0.25 }}>
              <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600, flex: 1, fontSize: 13 }}>{r.domain}</Typography>
              <Chip label={`${r.count} risk${r.count === 1 ? "" : "s"}`} size="small"
                sx={{ height: 18, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
              <Typography variant="caption" sx={{ color: "#EA4335", fontWeight: 700, minWidth: 70, textAlign: "right" }}>
                {fmtCurrency(r.exposure)}
              </Typography>
              <Typography variant="caption" sx={{ color: "text.secondary", minWidth: 42, textAlign: "right" }}>
                {sharePct.toFixed(0)}%
              </Typography>
            </Box>
            <LinearProgress variant="determinate" value={pct}
              sx={{ height: 8, borderRadius: 4, bgcolor: "rgba(255,255,255,0.06)",
                "& .MuiLinearProgress-bar": {
                  borderRadius: 4,
                  background: "linear-gradient(90deg, #EA4335 0%, #FF7043 100%)",
                } }} />
          </Box>
        );
      })}
    </Box>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function RiskOverview() {
  const navigate = useNavigate();
  const [clientId, setClientId] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [domainFilter, setDomainFilter] = useState<string>("");

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: portfolio, isLoading } = useQuery<Portfolio>({
    queryKey: ["risk-portfolio", clientId],
    queryFn: () => riskPortfolioApi.get(clientId),
    enabled: !!clientId,
  });

  const filteredRisks = (portfolio?.risks || []).filter((r) => {
    if (severityFilter && r.severity !== severityFilter) return false;
    if (statusFilter && r.remediation_status !== statusFilter) return false;
    if (domainFilter && r.domain !== domainFilter) return false;
    return true;
  });

  const breachPct = Math.round((portfolio?.breach_probability_30d || 0) * 100);
  const breachLabel =
    breachPct >= 70 ? "Critical" : breachPct >= 40 ? "Elevated" : breachPct >= 15 ? "Moderate" : "Low";
  const breachColor =
    breachPct >= 70 ? "#EA4335" : breachPct >= 40 ? "#FF7043" : breachPct >= 15 ? "#FBBC04" : "#34A853";

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Risk Portfolio</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Financial exposure, domain breakdown, and remediation status across the risk register
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Client</InputLabel>
            <Select value={clientId} onChange={(e) => setClientId(e.target.value)} label="Client"
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
        </Box>
      </Box>

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "text.primary" }}>
          Select a client to load the risk portfolio.
        </Alert>
      ) : isLoading || !portfolio ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      ) : portfolio.risks.length === 0 ? (
        <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <TrendingUp sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No risks yet. Run the Risk Manager agent from the Agents page to generate the portfolio.
          </Typography>
        </Card>
      ) : (
        <>
          {/* KPI strip */}
          <Grid container spacing={2} sx={{ mb: 2 }}>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard label="Total Exposure" value={fmtCurrency(portfolio.total_exposure)}
                sublabel={`${portfolio.risks.length} risks · before mitigation`}
                color="#EA4335" />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard label="Net Exposure" value={fmtCurrency(portfolio.net_exposure)}
                sublabel={`${portfolio.mitigated_pct}% mitigated`}
                progress={portfolio.mitigated_pct}
                color={portfolio.mitigated_pct >= 50 ? "#34A853" : "#FF7043"} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard label="Open Critical / High" value={String(portfolio.open_critical_high)}
                sublabel={
                  <span>
                    <span style={{ color: "#EA4335" }}>{portfolio.open_critical} critical</span>
                    {" · "}
                    <span style={{ color: "#FF7043" }}>{portfolio.open_high} high</span>
                  </span>
                }
                color={portfolio.open_critical > 0 ? "#EA4335" : "#FF7043"} />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard label="30-Day Breach Probability" value={`${breachPct}%`}
                sublabel={
                  <span style={{ color: breachColor, fontWeight: 700 }}>{breachLabel}</span>
                }
                progress={breachPct}
                color={breachColor} />
            </Grid>
          </Grid>

          {/* Risk by Domain */}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 700 }}>Risk by Domain</Typography>
                <Chip label={`${portfolio.by_domain.length} domains`} size="small"
                  sx={{ height: 18, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 11, fontWeight: 700 }} />
                <Box sx={{ flex: 1 }} />
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  Net exposure per domain
                </Typography>
              </Box>
              <DomainBar rows={portfolio.by_domain} total={portfolio.net_exposure} />
            </CardContent>
          </Card>

          {/* Filter chips */}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 1.5, mb: 2 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, flexWrap: "wrap" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 1 }}>SEVERITY</Typography>
              {["critical", "high", "medium", "low"].map((s) => (
                <Chip key={s} size="small" label={s.charAt(0).toUpperCase() + s.slice(1)}
                  onClick={() => setSeverityFilter(severityFilter === s ? "" : s)}
                  sx={{
                    cursor: "pointer",
                    bgcolor: severityFilter === s ? `${SEV_COLOR[s]}25` : "rgba(255,255,255,0.04)",
                    color: severityFilter === s ? SEV_COLOR[s] : "rgba(255,255,255,0.7)",
                    border: severityFilter === s ? `1px solid ${SEV_COLOR[s]}` : "1px solid transparent",
                    fontWeight: severityFilter === s ? 700 : 400,
                  }} />
              ))}
              <Box sx={{ width: 1, height: 18, bgcolor: "rgba(255,255,255,0.1)", mx: 1 }} />
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 1 }}>STATUS</Typography>
              {REMEDIATION_STATUSES.map((rs) => (
                <Chip key={rs.value} size="small" label={rs.label}
                  onClick={() => setStatusFilter(statusFilter === rs.value ? "" : rs.value)}
                  sx={{
                    cursor: "pointer",
                    bgcolor: statusFilter === rs.value ? `${rs.color}25` : "rgba(255,255,255,0.04)",
                    color: statusFilter === rs.value ? rs.color : "rgba(255,255,255,0.7)",
                    border: statusFilter === rs.value ? `1px solid ${rs.color}` : "1px solid transparent",
                    fontWeight: statusFilter === rs.value ? 700 : 400,
                  }} />
              ))}
              {portfolio.by_domain.length > 0 && (
                <>
                  <Box sx={{ width: 1, height: 18, bgcolor: "rgba(255,255,255,0.1)", mx: 1 }} />
                  <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mr: 1 }}>DOMAIN</Typography>
                  {portfolio.by_domain.map((d) => (
                    <Chip key={d.domain} size="small" label={`${d.domain} · ${d.count}`}
                      onClick={() => setDomainFilter(domainFilter === d.domain ? "" : d.domain)}
                      sx={{
                        cursor: "pointer",
                        bgcolor: domainFilter === d.domain ? "rgba(66,133,244,0.2)" : "rgba(255,255,255,0.04)",
                        color: domainFilter === d.domain ? "#4285F4" : "rgba(255,255,255,0.7)",
                        border: domainFilter === d.domain ? "1px solid #4285F4" : "1px solid transparent",
                        fontWeight: domainFilter === d.domain ? 700 : 400,
                      }} />
                  ))}
                </>
              )}
              {(severityFilter || statusFilter || domainFilter) && (
                <Button size="small" sx={{ ml: 1, color: "text.secondary", fontSize: 11 }}
                  onClick={() => { setSeverityFilter(""); setStatusFilter(""); setDomainFilter(""); }}>
                  Clear filters
                </Button>
              )}
              <Box sx={{ flex: 1 }} />
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                Showing {filteredRisks.length} of {portfolio.risks.length} risks
              </Typography>
            </Box>
          </Card>

          {/* Risk table */}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                    <TableCell>SEVERITY</TableCell>
                    <TableCell>TITLE</TableCell>
                    <TableCell align="center">FINDINGS</TableCell>
                    <TableCell>DOMAIN</TableCell>
                    <TableCell align="center">IMPACT</TableCell>
                    <TableCell align="center">LIKELIHOOD</TableCell>
                    <TableCell align="right">RISK SCORE</TableCell>
                    <TableCell align="right">ALE RANGE</TableCell>
                    <TableCell>REMEDIATION</TableCell>
                    <TableCell align="center">SOURCE</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredRisks.map((r) => (
                    <TableRow key={r.id} hover
                      sx={{ "& td": { borderColor: "divider", py: 1, color: "text.primary" } }}>
                      <TableCell>
                        <Chip label={r.severity} size="small"
                          sx={{ bgcolor: `${SEV_COLOR[r.severity] || "#888"}25`, color: SEV_COLOR[r.severity] || "#888", fontSize: 10, height: 18, textTransform: "capitalize" }} />
                      </TableCell>
                      <TableCell sx={{ maxWidth: 280 }}>
                        <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13 }}>
                          {r.title}
                        </Typography>
                      </TableCell>
                      <TableCell align="center">
                        {r.finding_count > 0 ? (
                          <Chip label={r.finding_count} size="small"
                            sx={{ height: 20, fontSize: 11, fontWeight: 700, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4" }} />
                        ) : (
                          <Typography variant="caption" sx={{ color: "text.secondary" }}>—</Typography>
                        )}
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>{r.domain}</TableCell>
                      <TableCell align="center" sx={{ fontSize: 12 }}>{r.impact}/5</TableCell>
                      <TableCell align="center" sx={{ fontSize: 12 }}>{r.likelihood}/5</TableCell>
                      <TableCell align="right">
                        <Typography variant="body2" sx={{ color: SEV_COLOR[r.severity] || "white", fontWeight: 700, fontSize: 13 }}>
                          {r.risk_score.toFixed(1)}
                        </Typography>
                      </TableCell>
                      <TableCell align="right" sx={{ color: "text.secondary", fontSize: 12, whiteSpace: "nowrap" }}>
                        <Tooltip title={`Point estimate ${fmtCurrency(r.ale)} · ${fmtCurrency(r.net_ale)} after mitigation`}>
                          <Box>
                            <Typography variant="caption" sx={{ color: "text.secondary" }}>{fmtCurrency(r.ale_low)}</Typography>
                            {" – "}
                            <Typography variant="caption" sx={{ color: "#EA4335", fontWeight: 700 }}>{fmtCurrency(r.ale_high)}</Typography>
                          </Box>
                        </Tooltip>
                      </TableCell>
                      <TableCell><RemediationChip value={r.remediation_status} /></TableCell>
                      <TableCell align="center">
                        {r.finding_count > 0 ? (
                          <Tooltip title="Open scan findings linked to this risk">
                            <Button size="small" startIcon={<OpenInNew sx={{ fontSize: 12 }} />}
                              onClick={() => navigate(`/findings?clientId=${clientId}&risk_id=${r.id}`)}
                              sx={{ color: "#4285F4", fontSize: 10, minWidth: 0, px: 1 }}>
                              Findings
                            </Button>
                          </Tooltip>
                        ) : (
                          <Typography variant="caption" sx={{ color: "text.secondary" }}>—</Typography>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Card>
        </>
      )}
    </Box>
  );
}
