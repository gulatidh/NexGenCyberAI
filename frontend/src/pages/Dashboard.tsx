import React from "react";
import {
  Grid, Card, CardContent, Typography, Box,
  LinearProgress, CircularProgress, Chip, Avatar,
  Button, useTheme,
} from "@mui/material";
import {
  BugReport, Security, Warning,
  TrendingUp, People, Cable, SmartToy, ArrowForward,
  Hub, Schedule, Bolt,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { dashboardApi } from "../services/api";
import { DashboardSummary } from "../types";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, Label,
} from "recharts";
import { fromNow } from "../utils/datetime";

// Finding-severity doughnut — Google brand palette.
const SEV_DONUT = [
  { key: "critical", name: "Critical", color: "#EA4335" },
  { key: "high",     name: "High",     color: "#FBBC05" },
  { key: "medium",   name: "Medium",   color: "#4285F4" },
  { key: "low",      name: "Low",      color: "#34A853" },
  { key: "info",     name: "Info",     color: "#94A3B8" },
];
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
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, height: "100%",
      cursor: onClick ? "pointer" : "default", "&:hover": onClick ? { borderColor: color } : {} }}
      onClick={onClick}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>{title}</Typography>
          <Box sx={{ color, opacity: 0.8 }}>{icon}</Box>
        </Box>
        <Typography variant="h4" sx={{ color, fontWeight: 700 }}>{value}</Typography>
        {subtitle && <Typography variant="caption" sx={{ color: "text.secondary" }}>{subtitle}</Typography>}
      </CardContent>
    </Card>
  );
}

const ACTIVITY_META: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
  scan:         { color: "#4285F4", icon: <BugReport sx={{ fontSize: 16 }} />, label: "Scans" },
  threat_model: { color: "#9C27B0", icon: <Hub sx={{ fontSize: 16 }} />,       label: "Threat Models" },
  workflow:     { color: "#34A853", icon: <Schedule sx={{ fontSize: 16 }} />,  label: "Workflows" },
  risk:         { color: "#EA4335", icon: <Warning sx={{ fontSize: 16 }} />,   label: "Risks" },
  agent:        { color: "#FF6D00", icon: <SmartToy sx={{ fontSize: 16 }} />,  label: "Agents" },
};

interface ActivityEvent {
  kind: string;
  label: string;
  target?: string | null;
  client_id?: string | null;
  client_name?: string;
  status?: string;
  when_iso: string;
  link?: string;
}

export default function Dashboard() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [activityFilter, setActivityFilter] = React.useState<string>("all");
  const { data, isLoading } = useQuery<DashboardSummary>({
    queryKey: ["dashboard"],
    queryFn: dashboardApi.summary,
    refetchInterval: 30_000,
  });
  const { data: activityResp } = useQuery<{ days: number; events: ActivityEvent[] }>({
    queryKey: ["dashboard-activity", 3],
    queryFn: () => dashboardApi.activity(3),
    refetchInterval: 60_000,
  });

  if (isLoading) return <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>;
  if (!data) return null;

  const complianceData = Object.entries(data.compliance_scores || {}).map(([k, v]) => ({
    name: k.replace(/_/g, " ").toUpperCase(),
    score: Math.round(v as number),
  }));

  const findingBreakdown = SEV_DONUT
    .map((s) => ({ name: s.name, value: (data.findings_by_severity?.[s.key]) ?? 0, color: s.color }))
    .filter((d) => d.value > 0);

  const postureEntries = Object.entries(data.posture_health || {
    "Vulnerability Management": 50,
    "Identity & Access": 50,
    "Data Protection": 50,
    "Threat Detection": 50,
  });

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Security Posture Overview</Typography>
        <Box sx={{ display: "flex", gap: 1 }}>
          <Button variant="outlined" size="small" startIcon={<BugReport />} onClick={() => navigate("/scans")}
            sx={{ borderColor: "divider", color: "text.secondary", fontSize: 12 }}>New Scan</Button>
          <Button variant="outlined" size="small" startIcon={<SmartToy />} onClick={() => navigate("/agents")}
            sx={{ borderColor: "divider", color: "text.secondary", fontSize: 12 }}>Run Agent</Button>
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
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                <Typography variant="h6" sx={{ color: "text.primary" }}>Framework Compliance Scores</Typography>
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
                  <Typography sx={{ color: "text.secondary" }}>No compliance data yet</Typography>
                  <Button variant="outlined" size="small" onClick={() => navigate("/scans")}
                    sx={{ borderColor: "divider", color: "text.secondary", fontSize: 11 }}>Run a scan →</Button>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Finding Breakdown */}
        <Grid size={{ xs: 12, md: 5 }}>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ color: "text.primary", mb: 2 }}>Finding Severity</Typography>
              {findingBreakdown.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={findingBreakdown} cx="50%" cy="50%" innerRadius={48} outerRadius={72}
                      paddingAngle={2} dataKey="value" stroke="none">
                      {findingBreakdown.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                      <Label content={({ viewBox }: any) => {
                        const { cx, cy } = viewBox || {};
                        return (
                          <g>
                            <text x={cx} y={cy - 4} textAnchor="middle" fill={theme.palette.text.primary}
                              style={{ fontSize: 26, fontWeight: 700 }}>{data.open_findings}</text>
                            <text x={cx} y={cy + 16} textAnchor="middle" fill={theme.palette.text.secondary}
                              style={{ fontSize: 11 }}>open</text>
                          </g>
                        );
                      }} />
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: "#1e232c", border: "none", borderRadius: 8 }}
                      formatter={(v: any, n: any) => [`${v}`, n]} />
                    <Legend iconSize={10} wrapperStyle={{ color: theme.palette.text.secondary, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <Box sx={{ height: 200, display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Typography sx={{ color: "text.secondary" }}>No open findings</Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Posture Health */}
      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 12 }}>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ color: "text.primary", mb: 2 }}>Posture Health</Typography>
              <Grid container spacing={2}>
                {postureEntries.map(([label, value], i) => {
                  const v = Math.round(value as number);
                  const color = v >= 70 ? "#00e676" : v >= 40 ? "#ff9800" : "#f44336";
                  return (
                    <Grid size={{ xs: 12, sm: 6, md: 3 }} key={label}>
                      <Typography variant="body2" sx={{ color: "text.secondary", mb: 0.5 }}>{label}</Typography>
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

      {/* Unified Activity Feed (last 3 days) */}
      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 12 }}>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1.5, flexWrap: "wrap", gap: 1 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Bolt sx={{ color: "#FBBC04", fontSize: 22 }} />
                  <Typography variant="h6" sx={{ color: "text.primary" }}>Activity Feed</Typography>
                  <Chip label="LAST 3 DAYS" size="small" sx={{ height: 18, fontSize: 10, fontWeight: 700, bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04", letterSpacing: 0.5 }} />
                </Box>
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                  {(["all", "scan", "threat_model", "workflow", "risk", "agent"]).map((k) => {
                    const active = activityFilter === k;
                    const meta = ACTIVITY_META[k];
                    return (
                      <Chip
                        key={k}
                        label={k === "all" ? "All" : (meta?.label || k)}
                        size="small"
                        onClick={() => setActivityFilter(k)}
                        sx={{
                          height: 22, fontSize: 11, fontWeight: 600, cursor: "pointer",
                          bgcolor: active ? (meta ? `${meta.color}25` : "rgba(255,255,255,0.12)") : "rgba(255,255,255,0.04)",
                          color: active ? (meta?.color || "white") : "text.secondary",
                          border: active ? `1px solid ${meta ? `${meta.color}80` : "rgba(255,255,255,0.3)"}` : "1px solid transparent",
                          "&:hover": { bgcolor: meta ? `${meta.color}15` : "rgba(255,255,255,0.08)" },
                        }}
                      />
                    );
                  })}
                </Box>
              </Box>
              {(() => {
                const events = (activityResp?.events || []).filter((e) => activityFilter === "all" || e.kind === activityFilter);
                if (!events.length) {
                  return (
                    <Typography variant="body2" sx={{ color: "text.secondary", textAlign: "center", py: 4 }}>
                      No activity in the last 3 days {activityFilter !== "all" ? `for ${ACTIVITY_META[activityFilter]?.label || activityFilter}` : ""}.
                    </Typography>
                  );
                }
                return (
                  <Box sx={{ maxHeight: 360, overflowY: "auto", pr: 0.5 }}>
                    {events.map((e, idx) => {
                      const meta = ACTIVITY_META[e.kind] || { color: "text.secondary", icon: <Bolt sx={{ fontSize: 16 }} />, label: e.kind };
                      const clickable = !!e.link;
                      return (
                        <Box
                          key={`${e.kind}-${idx}-${e.when_iso}`}
                          onClick={() => clickable && navigate(e.link!)}
                          sx={{
                            display: "flex", alignItems: "center", gap: 1.5,
                            p: 1.25, borderRadius: 1.5,
                            cursor: clickable ? "pointer" : "default",
                            bgcolor: "rgba(255,255,255,0.02)",
                            borderLeft: `3px solid ${meta.color}`,
                            mb: 0.75,
                            transition: "background-color .12s",
                            "&:hover": clickable ? { bgcolor: "rgba(255,255,255,0.05)" } : {},
                          }}
                        >
                          <Box sx={{ color: meta.color, display: "flex", alignItems: "center", justifyContent: "center", width: 24 }}>
                            {meta.icon}
                          </Box>
                          <Box sx={{ flex: 1, minWidth: 0 }}>
                            <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600, fontSize: 13, lineHeight: 1.3 }}>
                              {e.label}
                              {e.target && (
                                <Box component="span" sx={{ color: "text.secondary", fontWeight: 400, ml: 0.75 }}>· {e.target}</Box>
                              )}
                            </Typography>
                            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                              {e.client_name} · {fromNow(e.when_iso)}
                            </Typography>
                          </Box>
                          {e.status && (
                            <Chip
                              label={e.status}
                              size="small"
                              sx={{
                                height: 18, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                                bgcolor: `${meta.color}1A`,
                                color: meta.color,
                              }}
                            />
                          )}
                        </Box>
                      );
                    })}
                  </Box>
                );
              })()}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Activity Row */}
      <Grid container spacing={2}>
        {/* Recent Scans */}
        <Grid size={{ xs: 12, md: 4 }}>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1.5 }}>
                <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 600 }}>Recent Scans</Typography>
                <Button size="small" endIcon={<ArrowForward sx={{ fontSize: 12 }} />} onClick={() => navigate("/scans")}
                  sx={{ color: "#4285F4", fontSize: 11 }}>View All</Button>
              </Box>
              {((data as any).recent_scans || []).length === 0 ? (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>No scans yet.</Typography>
              ) : (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {((data as any).recent_scans || []).map((s: any) => (
                    <Box key={s.id} sx={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                      p: 1, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1 }}>
                      <Box>
                        <Typography variant="caption" sx={{ color: "text.primary", display: "block" }}>{s.scan_type}</Typography>
                        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>
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
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1.5 }}>
                <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 600 }}>Critical Findings</Typography>
                <Button size="small" endIcon={<ArrowForward sx={{ fontSize: 12 }} />} onClick={() => navigate("/findings")}
                  sx={{ color: "#f44336", fontSize: 11 }}>View All</Button>
              </Box>
              {((data as any).recent_findings || []).length === 0 ? (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>No critical findings.</Typography>
              ) : (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {((data as any).recent_findings || []).map((f: any) => (
                    <Box key={f.id} sx={{ display: "flex", alignItems: "center", gap: 1,
                      p: 1, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1 }}>
                      <Chip label={f.severity} size="small"
                        sx={{ bgcolor: `${SEV_COLOR[f.severity] || "#888"}20`, color: SEV_COLOR[f.severity] || "#888", fontSize: 9, height: 16, flexShrink: 0 }} />
                      <Typography variant="caption" sx={{ color: "text.primary", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
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
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1.5 }}>
                <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 600 }}>Open Risks</Typography>
                <Button size="small" endIcon={<ArrowForward sx={{ fontSize: 12 }} />} onClick={() => navigate("/risks")}
                  sx={{ color: "#ffeb3b", fontSize: 11 }}>View All</Button>
              </Box>
              {((data as any).recent_risks || []).length === 0 ? (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>No open risks.</Typography>
              ) : (
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {((data as any).recent_risks || []).map((r: any) => (
                    <Box key={r.id} sx={{ display: "flex", alignItems: "center", gap: 1,
                      p: 1, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1 }}>
                      <Avatar sx={{ width: 20, height: 20, bgcolor: `${RISK_COLOR[r.risk_level] || "#888"}30`, fontSize: 10 }}>
                        {(r.risk_score || 0).toFixed(0)}
                      </Avatar>
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography variant="caption" sx={{ color: "text.primary", display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
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
