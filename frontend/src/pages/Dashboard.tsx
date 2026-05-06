import React from "react";
import {
  Grid, Card, CardContent, Typography, Box, Chip,
  LinearProgress, CircularProgress,
} from "@mui/material";
import {
  BugReport, Security, Warning, CheckCircle,
  TrendingUp, People, Cable,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { dashboardApi } from "../services/api";
import { DashboardSummary } from "../types";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#2196f3",
};

const FRAMEWORK_COLORS = ["#00e5ff", "#7c4dff", "#ff6d00", "#00e676", "#ff4081"];

function StatCard({ title, value, icon, color, subtitle }: any) {
  return (
    <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%" }}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.6)" }}>{title}</Typography>
          <Box sx={{ color, opacity: 0.8 }}>{icon}</Box>
        </Box>
        <Typography variant="h4" sx={{ color, fontWeight: 700 }}>{value}</Typography>
        {subtitle && <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>{subtitle}</Typography>}
      </CardContent>
    </Card>
  );
}

export default function Dashboard() {
  const { data, isLoading } = useQuery<DashboardSummary>({
    queryKey: ["dashboard"],
    queryFn: dashboardApi.summary,
    refetchInterval: 30_000,
  });

  if (isLoading) return <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#00e5ff" }} /></Box>;
  if (!data) return null;

  const complianceData = Object.entries(data.compliance_scores).map(([k, v]) => ({
    name: k.replace("_", " ").toUpperCase(),
    score: Math.round(v),
  }));

  const findingBreakdown = [
    { name: "Critical", value: data.critical_findings, color: "#f44336" },
    { name: "Others", value: data.open_findings - data.critical_findings, color: "#ff9800" },
  ];

  return (
    <Box>
      <Typography variant="h5" sx={{ color: "white", fontWeight: 700, mb: 3 }}>
        Security Posture Overview
      </Typography>

      {/* KPI Row */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 6, md: 2 }}>
          <StatCard title="Clients" value={data.total_clients} icon={<People />} color="#00e5ff" />
        </Grid>
        <Grid size={{ xs: 6, md: 2 }}>
          <StatCard title="Active Connectors" value={data.active_connectors} icon={<Cable />} color="#7c4dff" />
        </Grid>
        <Grid size={{ xs: 6, md: 2 }}>
          <StatCard title="Open Findings" value={data.open_findings} icon={<BugReport />} color="#ff9800" />
        </Grid>
        <Grid size={{ xs: 6, md: 2 }}>
          <StatCard title="Critical Findings" value={data.critical_findings} icon={<Security />} color="#f44336" />
        </Grid>
        <Grid size={{ xs: 6, md: 2 }}>
          <StatCard title="Open Risks" value={data.risks_open} icon={<Warning />} color="#ffeb3b" />
        </Grid>
        <Grid size={{ xs: 6, md: 2 }}>
          <StatCard title="Scans (30d)" value={data.scans_last_30d} icon={<TrendingUp />} color="#00e676" />
        </Grid>
      </Grid>

      {/* Charts Row */}
      <Grid container spacing={2}>
        {/* Compliance Scores */}
        <Grid size={{ xs: 12, md: 8 }}>
          <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ color: "white", mb: 2 }}>Framework Compliance Scores</Typography>
              {complianceData.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={complianceData} barSize={40}>
                    <XAxis dataKey="name" tick={{ fill: "rgba(255,255,255,0.6)", fontSize: 11 }} />
                    <YAxis domain={[0, 100]} tick={{ fill: "rgba(255,255,255,0.6)", fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#1e232c", border: "none", borderRadius: 8 }}
                      formatter={(v: any) => [`${v}%`, "Score"]}
                    />
                    {complianceData.map((entry, i) => (
                      <Bar key={entry.name} dataKey="score" fill={FRAMEWORK_COLORS[i % FRAMEWORK_COLORS.length]} radius={[4, 4, 0, 0]} />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <Box sx={{ height: 220, display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Typography sx={{ color: "rgba(255,255,255,0.3)" }}>No compliance data yet — run a scan</Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Finding Breakdown */}
        <Grid size={{ xs: 12, md: 4 }}>
          <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ color: "white", mb: 2 }}>Finding Severity</Typography>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={findingBreakdown} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({ name, value }) => `${name}: ${value}`}>
                    {findingBreakdown.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: "#1e232c", border: "none" }} />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Risk Gauge */}
        <Grid size={{ xs: 12 }}>
          <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ color: "white", mb: 2 }}>Posture Health</Typography>
              <Grid container spacing={2}>
                {[
                  { label: "Vulnerability Management", value: 68, color: "#ff9800" },
                  { label: "Identity & Access", value: 82, color: "#00e676" },
                  { label: "Data Protection", value: 55, color: "#f44336" },
                  { label: "Threat Detection", value: 74, color: "#00e5ff" },
                ].map((item) => (
                  <Grid size={{ xs: 12, sm: 6, md: 3 }} key={item.label}>
                    <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.7)", mb: 0.5 }}>{item.label}</Typography>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <LinearProgress
                        variant="determinate"
                        value={item.value}
                        sx={{
                          flexGrow: 1, height: 8, borderRadius: 4, bgcolor: "rgba(255,255,255,0.1)",
                          "& .MuiLinearProgress-bar": { bgcolor: item.color, borderRadius: 4 },
                        }}
                      />
                      <Typography variant="body2" sx={{ color: item.color, fontWeight: 700, minWidth: 32 }}>{item.value}%</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
