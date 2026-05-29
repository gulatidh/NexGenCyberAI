import React from "react";
import {
  Grid, Card, CardContent, Typography, Box,
  LinearProgress, CircularProgress, Chip, Avatar,
  Button,
} from "@mui/material";
import {
  BugReport, Security, Warning,
  TrendingUp, People, Cable, SmartToy, ArrowForward,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { dashboardApi } from "../services/api";
import { DashboardSummary } from "../types";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts";
import { fromNow } from "../utils/datetime";

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#4285F4",
};
const RISK_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50",
};
const SCAN_STATUS_COLOR: Record<string, string> = {
  completed: "#00e676", running: "#4285F4", pending: "#ff9800", failed: "#f44336",
};
const FRAMEWORK_COLORS = ["#4285F4", "#34A853", "#ff6d00", "#00e676", "#ff4081"];

function StatCard({ title, value, icon, color, subtitle, onClick }: any) {
  return (
    <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%",
      cursor: onClick ? "pointer" : "default", "&:hover": onClick ? { borderColor: color } : {} }}
      onClick={onClick}>
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
  const navigate = useNavigate();
  const { data, isLoading } = useQuery<DashboardSummary>({
    queryKey: ["dashboard"],
    queryFn: dashboardApi.summary,
    refetchInterval: 30_000,
  });

  if (isLoading) return <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>;
  if (!data) return null;

  const complianceData = Object.entries(data.compliance_scores || {}).map(([k, v]) => ({
    name: k.replace(/_/g, " ").toUpperCase(),
    score: Math.round(v as number),
  }));

  const findingBreakdown = [
    { name: "Critical", value: data.critical_findings, color: "#f44336" },
    { name: "Others", value: Math.max(data.open_findings - data.critical_findings, 0), color: "#ff9800" },
  ].filter((d) => d.value > 0);

  const postureEntries = Object.entries(data.posture_health || {
    "Vulnerability Management": 50,
    "Identity & Access": 50,
    "Data Protection": 50,
    "Threat Detection": 50,
  });

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Security Posture Overview</Typography>
        <Box sx={{ display: "flex", gap: 1 }}>
          <Button variant="outlined" size="small" startIcon={<BugReport />} onClick={() => navigate("/scans")}
            sx={{ borderColor: "rgba(255,255,255,0.2)", color: "rgba(255,255,255,0.7)", fontSize: 12 }}>New Scan</Button>
          <Button variant="outlined" size="small" startIcon={<SmartToy />} onClick={() => navigate("/agents")}
            sx={{ borderColor: "rgba(255,255,255,0.2)", color: "rgba(255,255,255,0.7)", fontSize: 12 }}>Run Agent</Button>
        </Box>
      </Box>

      {/* KPI Row */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        {[
          { title: "Clients", value: data.total_clients, icon: <People />, color: "#4285F4", path: "/clients" },
          { title: "Active Connectors", value: data.active_connectors, icon: <Cable />, color: "#34A853", path: "/connectors" },
          { title: "Open Findings", value: data.open_findings, icon: <BugReport />, color: "#ff9800", path: "/findings" },
          { title: "Critical Findings", value: data.critical_findings, icon: <Security />, color: "#f44336", path: "/findings" },
          { title: "Open Risks", value: data.risks_open, icon: <Warning />, color: "#ffeb3b", path: "/risks" },
          { title: "Scans (30d)", value: data.scans_last_30d, icon: <TrendingUp />, color: "#00e676", path: "/scans" },
          { title: "Agent Runs", value: (data as any).agent_runs_total ?? 0, icon: <SmartToy />, color: "#ff6d00", path: "/agents" },
        ].map((item) => (
          <Grid size={{ xs: 6, sm: 4, md: "auto" }} sx={{ flex: 1 }} key={item.title}>
            <StatCard {...item} onClick={() => navigate(item.path)} />
          </Grid>
        ))}
      </Grid>

      {/* Charts Row */}
      <Grid container spacing={2} sx={{ mb: 2 }}>
        {/* Compliance Scores */}
        <Grid size={{ xs: 12, md: 7 }}>
          <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                <Typography variant="h6" sx={{ color: "white" }}>Framework Compliance Scores</Typography>
                <Button size="small" endIcon={<ArrowForward sx={{ fontSize: 12 }} />} onClick={() => navigate("/frameworks")}
                  sx={{ color: "#4285F4", fontSize: 11 }}>Browse controls</Button>
              </Box>
              {complianceData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={complianceData} barSize={36}>
                    <XAxis dataKey="name" tick={{ fill: "rgba(255,255,255,0.6)", fontSize: 10 }} />
                    <YAxis domain={[0, 100]} tick={{ fill: "rgba(255,255,255,0.6)", fontSize: 11 }} unit="%" />
                    <Tooltip contentStyle={{ backgroundColor: "#1e232c", border: "none", borderRadius: 8 }}
                      formatter={(v: any) => [`${v}%`, "Score"]} />
                    {complianceData.map((entry, i) => (
                      <Bar key={entry.name} dataKey="score" fill={FRAMEWORK_COLORS[i % FRAMEWORK_COLORS.length]} radius={[4, 4, 0, 0]} />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <Box sx={{ height: 200, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 1 }}>
                  <Typography sx={{ color: "rgba(255,255,255,0.3)" }}>No compliance data yet</Typography>
                  <Button variant="outlined" size="small" onClick={() => navigate("/scans")}
                    sx={{ borderColor: "rgba(255,255,255,0.2)", color: "rgba(255,255,255,0.5)", fontSize: 11 }}>Run a scan →</Button>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Finding Breakdown */}
        <Grid size={{ xs: 12, md: 5 }}>
          <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ color: "white", mb: 2 }}>Finding Severity</Typography>
              {findingBreakdown.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={findingBreakdown} cx="50%" cy="50%" outerRadius={70} dataKey="value">
                      {findingBreakdown.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: "#1e232c", border: "none" }} />
                    <Legend iconSize={10} wrapperStyle={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <Box sx={{ height: 200, display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Typography sx={{ color: "rgba(255,255,255,0.3)" }}>No open findings</Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Posture Health */}
      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 12 }}>
          <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ color: "white", mb: 2 }}>Posture Health</Typography>
              <Grid container spacing={2}>
                {postureEntries.map(([label, value], i) => {
                  const v = Math.round(value as number);
                  const color = v >= 70 ? "#00e676" : v >= 40 ? "#ff9800" : "#f44336";
                  return (
                    <Grid size={{ xs: 12, sm: 6, md: 3 }} key={label}>
                      <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.7)", mb: 0.5 }}>{label}</Typography>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <LinearProgress variant="determinate" value={v}
                          sx={{ flexGrow: 1, height: 8, borderRadius: 4, bgcolor: "rgba(255,255,255,0.1)",
                            "& .MuiLinearProgress-bar": { bgcolor: color, borderRadius: 4 } }} />
                        <Typography variant="body2" sx={{ color, fontWeight: 700, minWidth: 32 }}>{v}%</Typography>
                      </Box>
                    </Grid>
                  );
                })}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Activity Row */}
      <Grid container spacing={2}>
        {/* Recent Scans */}
        <Grid size={{ xs: 12, md: 4 }}>
          <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1.5 }}>
                <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>Recent Scans</Typography>
                <Button size="small" endIcon={<ArrowForward sx={{ fontSize: 12 }} />} onClick={() => navigate("/scans")}
                  sx={{ color: "#4285F4", fontSize: 11 }}>View All</Button>
              </Box>
              {((data as any).recent_scans || []).length === 0 ? (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.3)" }}>No scans yet.</Typography>
              ) : (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {((data as any).recent_scans || []).map((s: any) => (
                    <Box key={s.id} sx={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                      p: 1, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1 }}>
                      <Box>
                        <Typography variant="caption" sx={{ color: "white", display: "block" }}>{s.scan_type}</Typography>
                        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", fontSize: 10 }}>
                          {fromNow(s.created_at)}
                        </Typography>
                      </Box>
                      <Chip label={s.status} size="small"
                        sx={{ bgcolor: `${SCAN_STATUS_COLOR[s.status] || "#888"}20`, color: SCAN_STATUS_COLOR[s.status] || "#888", fontSize: 10, height: 18 }} />
                    </Box>
                  ))}
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Critical Findings */}
        <Grid size={{ xs: 12, md: 4 }}>
          <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1.5 }}>
                <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>Critical Findings</Typography>
                <Button size="small" endIcon={<ArrowForward sx={{ fontSize: 12 }} />} onClick={() => navigate("/findings")}
                  sx={{ color: "#f44336", fontSize: 11 }}>View All</Button>
              </Box>
              {((data as any).recent_findings || []).length === 0 ? (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.3)" }}>No critical findings.</Typography>
              ) : (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {((data as any).recent_findings || []).map((f: any) => (
                    <Box key={f.id} sx={{ display: "flex", alignItems: "center", gap: 1,
                      p: 1, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1 }}>
                      <Chip label={f.severity} size="small"
                        sx={{ bgcolor: `${SEV_COLOR[f.severity] || "#888"}20`, color: SEV_COLOR[f.severity] || "#888", fontSize: 9, height: 16, flexShrink: 0 }} />
                      <Typography variant="caption" sx={{ color: "white", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {f.title}
                      </Typography>
                    </Box>
                  ))}
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Risks */}
        <Grid size={{ xs: 12, md: 4 }}>
          <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1.5 }}>
                <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>Open Risks</Typography>
                <Button size="small" endIcon={<ArrowForward sx={{ fontSize: 12 }} />} onClick={() => navigate("/risks")}
                  sx={{ color: "#ffeb3b", fontSize: 11 }}>View All</Button>
              </Box>
              {((data as any).recent_risks || []).length === 0 ? (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.3)" }}>No open risks.</Typography>
              ) : (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {((data as any).recent_risks || []).map((r: any) => (
                    <Box key={r.id} sx={{ display: "flex", alignItems: "center", gap: 1,
                      p: 1, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1 }}>
                      <Avatar sx={{ width: 20, height: 20, bgcolor: `${RISK_COLOR[r.risk_level] || "#888"}30`, fontSize: 10 }}>
                        {(r.risk_score || 0).toFixed(0)}
                      </Avatar>
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography variant="caption" sx={{ color: "white", display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {r.title}
                        </Typography>
                        <Chip label={r.risk_level} size="small"
                          sx={{ bgcolor: `${RISK_COLOR[r.risk_level] || "#888"}20`, color: RISK_COLOR[r.risk_level] || "#888", fontSize: 9, height: 14 }} />
                      </Box>
                    </Box>
                  ))}
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
