import React, { useRef } from "react";
import {
  Box, Typography, Card, CardContent, Grid, Button, Divider, CircularProgress,
  Alert, Chip, LinearProgress,
} from "@mui/material";
import { Print, Summarize } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useActiveClient } from "../contexts/ClientContext";
import { dashboardApi, risksApi, findingsApi } from "../services/api";
function fmtMonth(d: Date) { return d.toLocaleDateString("en-GB", { month: "long", year: "numeric" }); }
function fmtFull(d: Date) { return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) + " " + d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }); }

function ScoreGauge({ score }: { score: number }) {
  const color = score >= 80 ? "#34A853" : score >= 60 ? "#FBBC04" : score >= 40 ? "#FF7043" : "#EA4335";
  const label = score >= 80 ? "Good" : score >= 60 ? "Fair" : score >= 40 ? "Poor" : "Critical";
  return (
    <Box sx={{ textAlign: "center" }}>
      <Box sx={{ position: "relative", display: "inline-flex" }}>
        <CircularProgress variant="determinate" value={score} size={120}
          sx={{ color, "& .MuiCircularProgress-circle": { strokeLinecap: "round" } }} />
        <Box sx={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column" }}>
          <Typography variant="h4" sx={{ fontWeight: 800, color, lineHeight: 1 }}>{score}</Typography>
          <Typography variant="caption" sx={{ color, fontWeight: 700, fontSize: 11 }}>{label}</Typography>
        </Box>
      </Box>
      <Typography variant="caption" sx={{ display: "block", color: "text.secondary", mt: 1 }}>Security Posture Score</Typography>
    </Box>
  );
}

export default function ExecutiveSummary() {
  const { clientId } = useActiveClient();
  const printRef = useRef<HTMLDivElement>(null);

  const { data: summary, isLoading: loadS } = useQuery({
    queryKey: ["exec-summary", clientId],
    queryFn: () => dashboardApi.summary(clientId),
    enabled: !!clientId,
  });

  const { data: risks, isLoading: loadR } = useQuery({
    queryKey: ["exec-risks", clientId],
    queryFn: () => risksApi.list(clientId),
    enabled: !!clientId,
  });

  if (!clientId) return <Alert severity="info" sx={{ mt: 2 }}>Select a client to view the executive summary.</Alert>;

  const isLoading = loadS || loadR;
  const s: any = summary ?? {};

  const sev         = s.findings_by_severity ?? {};
  const open        = s.open_findings ?? 0;
  const critical    = s.critical_findings ?? sev.critical ?? 0;
  const high        = sev.high ?? 0;
  const medium      = sev.medium ?? 0;
  const low         = sev.low ?? 0;
  const remediated  = s.remediated_findings ?? 0;
  const total       = open + remediated;
  const remPct      = total > 0 ? Math.round((remediated / total) * 100) : 0;
  const score       = s.posture_score ?? Math.max(0, 100 - critical * 10 - high * 3 - (medium + low));

  const riskList: any[] = Array.isArray(risks) ? risks : (risks as any)?.items ?? [];
  const critRisks = riskList.filter((r: any) => r.risk_level === "critical" || r.risk_level === "high");

  const handlePrint = () => window.print();

  return (
    <Box ref={printRef}>
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Executive Summary</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
            Non-technical leadership report — posture score, key risks, and remediation progress.
          </Typography>
        </Box>
        <Button variant="outlined" startIcon={<Print />} size="small" onClick={handlePrint}
          sx={{ borderColor: "rgba(255,255,255,0.2)", color: "text.secondary" }}>
          Print / PDF
        </Button>
      </Box>

      {isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", pt: 6 }}><CircularProgress /></Box>
      ) : (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
          {/* Header band */}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Grid container spacing={3} sx={{ alignItems: "center" }}>
                <Grid size={{ xs: 12, sm: 4 }} sx={{ display: "flex", justifyContent: "center" }}>
                  <ScoreGauge score={score} />
                </Grid>
                <Grid size={{ xs: 12, sm: 8 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                    Security Posture — {fmtMonth(new Date())}
                  </Typography>
                  <Grid container spacing={1.5}>
                    {[
                      { label: "Critical Findings", value: critical, color: "#EA4335" },
                      { label: "High Findings",     value: high,     color: "#FBBC04" },
                      { label: "Medium Findings",   value: medium,   color: "#4285F4" },
                      { label: "Low Findings",      value: low,      color: "#34A853" },
                    ].map(({ label, value, color }) => (
                      <Grid key={label} size={{ xs: 6 }}>
                        <Box sx={{ borderLeft: `3px solid ${color}`, pl: 1.5, py: 0.5 }}>
                          <Typography variant="h6" sx={{ fontWeight: 800, color, lineHeight: 1 }}>{value}</Typography>
                          <Typography variant="caption" sx={{ color: "text.secondary" }}>{label}</Typography>
                        </Box>
                      </Grid>
                    ))}
                  </Grid>
                </Grid>
              </Grid>
            </CardContent>
          </Card>

          {/* Remediation Progress */}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Remediation Progress</Typography>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <LinearProgress variant="determinate" value={remPct}
                  sx={{ flex: 1, height: 10, borderRadius: 5, bgcolor: "rgba(255,255,255,0.08)",
                    "& .MuiLinearProgress-bar": { bgcolor: remPct > 70 ? "#34A853" : remPct > 40 ? "#FBBC04" : "#EA4335" } }} />
                <Typography variant="body2" sx={{ fontWeight: 700, minWidth: 48 }}>{remPct}%</Typography>
              </Box>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {remediated} of {total} findings remediated
              </Typography>
            </CardContent>
          </Card>

          {/* Top Risks */}
          {critRisks.length > 0 && (
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <CardContent>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                  Critical & High Risks Requiring Leadership Attention
                </Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {critRisks.slice(0, 5).map((r: any) => {
                    const c = r.risk_level === "critical" ? "#EA4335" : "#FBBC04";
                    return (
                      <Box key={r.id} sx={{ display: "flex", alignItems: "flex-start", gap: 1.5, py: 1,
                        borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                        <Chip label={r.risk_level} size="small"
                          sx={{ bgcolor: c + "22", color: c, fontWeight: 700, fontSize: 10, textTransform: "capitalize", flexShrink: 0 }} />
                        <Box>
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>{r.risk_scenario ?? r.title}</Typography>
                          <Typography variant="caption" sx={{ color: "text.secondary" }}>{r.risk_domain ?? r.domain}</Typography>
                        </Box>
                      </Box>
                    );
                  })}
                </Box>
              </CardContent>
            </Card>
          )}

          {/* Footer note */}
          <Typography variant="caption" sx={{ color: "text.secondary", textAlign: "center" }}>
            Generated by Monitara · {fmtFull(new Date())} · Data sourced live from security registers
          </Typography>
        </Box>
      )}
    </Box>
  );
}
