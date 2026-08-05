/**
 * OwletHome — landing page for the Owlet build.
 * Renders inside OwletLayout (TopBar + LeftBlade already provided).
 * Shows security overview metrics, recently visited, quick actions,
 * activity feed, and workflow phase shortcuts.
 */
import React from "react";
import { useNavigate } from "react-router-dom";
import { Box, Typography, Chip, alpha } from "@mui/material";
import {
  Security, BugReport, Insights, Hub, SmartToy,
  GppGood, GppBad, TrendingUp, Add, PlayArrow, Psychology,
  AccountTree, AutoStories, ChevronRight,
} from "@mui/icons-material";
import { useTheme } from "@mui/material/styles";
import { useMsal } from "@azure/msal-react";

// ── Mock data (replace with real API queries as needed) ──────────────────────

const METRICS = [
  { label: "Posture Score",     value: "72",  unit: "/ 100",  Icon: TrendingUp,    color: "#FFA726", path: "/posture-trends" },
  { label: "Critical Findings", value: "12",  unit: "open",   Icon: Security,      color: "#EF5350", path: "/findings" },
  { label: "Active Scans",      value: "1",   unit: "running",Icon: BugReport,     color: "#26A69A", path: "/scans" },
  { label: "Risks Scored",      value: "47",  unit: "total",  Icon: Insights,      color: "#42A5F5", path: "/risk-overview" },
  { label: "Control Gaps",      value: "8",   unit: "open",   Icon: GppBad,        color: "#AB47BC", path: "/control-deficiencies" },
  { label: "VAPT Reports",      value: "3",   unit: "total",  Icon: GppGood,       color: "#66BB6A", path: "/vapt/reports" },
];

const RECENT = [
  { label: "Findings",        sub: "12 critical open",      Icon: Security,  color: "#EF5350", path: "/findings" },
  { label: "Risk Overview",   sub: "Score: 72 / 100",       Icon: Insights,  color: "#FFA726", path: "/risk-overview" },
  { label: "AI Buddies",      sub: "Last run: 2h ago",      Icon: SmartToy,  color: "#5C6BC0", path: "/agents" },
  { label: "Scans",           sub: "1 running now",         Icon: BugReport, color: "#26A69A", path: "/scans" },
  { label: "Threat Models",   sub: "2 models, 18 threats",  Icon: Hub,       color: "#AB47BC", path: "/threat-models" },
  { label: "VAPT Reports",    sub: "3 reports",             Icon: GppGood,   color: "#66BB6A", path: "/vapt/reports" },
];

const QUICK_ACTIONS = [
  { label: "New Scan",      Icon: Add,        color: "#42A5F5", path: "/scans" },
  { label: "Run Agent",     Icon: PlayArrow,  color: "#5C6BC0", path: "/agents" },
  { label: "VAPT Report",   Icon: GppGood,    color: "#66BB6A", path: "/vapt/reports" },
  { label: "Ask Your Data", Icon: Psychology, color: "#FFA726", path: "/nl-query" },
  { label: "Attack Paths",  Icon: AccountTree,color: "#EF5350", path: "/attack-paths" },
  { label: "Knowledge Base",Icon: AutoStories,color: "#26A69A", path: "/knowledge" },
];

const ACTIVITY = [
  { msg: "Orchestrator agent completed successfully",  time: "2 min ago",  type: "success" },
  { msg: "12 new findings from Azure cloud scan",      time: "18 min ago", type: "warning" },
  { msg: "VAPT Report generated — Acme Corp Q3",      time: "1 hr ago",   type: "success" },
  { msg: "Critical CVE CVE-2024-3094 detected",        time: "3 hr ago",   type: "error" },
  { msg: "Threat model updated — Customer Portal DFD", time: "Yesterday",  type: "info" },
];

const PHASES = [
  { label: "1 · Setup",    color: "#42A5F5", path: "/connections" },
  { label: "2 · Design",   color: "#AB47BC", path: "/threat-models" },
  { label: "3 · Discover", color: "#26A69A", path: "/scans" },
  { label: "4 · Analyse",  color: "#FFA726", path: "/risk-overview" },
  { label: "5 · Respond",  color: "#EF5350", path: "/control-deficiencies" },
  { label: "6 · Report",   color: "#66BB6A", path: "/vapt/reports" },
  { label: "7 · Automate", color: "#5C6BC0", path: "/agents" },
  { label: "8 · Configure",color: "#78909C", path: "/settings" },
];

// ── Section label ─────────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <Typography variant="subtitle2" sx={{
      fontWeight: 700, mb: 1.5,
      color: "text.secondary", fontSize: "0.75rem", letterSpacing: "0.07em",
    }}>
      {children}
    </Typography>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function OwletHome() {
  const theme = useTheme();
  const navigate = useNavigate();
  const { accounts } = useMsal();
  const firstName = accounts[0]?.name?.split(" ")[0] ?? "there";

  const activityColor = (type: string) =>
    type === "success" ? "#66BB6A" : type === "warning" ? "#FFA726" : type === "error" ? "#EF5350" : theme.palette.primary.main;

  return (
    <Box sx={{ p: { xs: 2, md: 3 }, maxWidth: 1400 }}>
      {/* Greeting */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 0.5 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>
          Good morning, {firstName}
        </Typography>
        <Chip label="Owlet" size="small" color="primary" variant="outlined" sx={{ fontSize: "0.68rem" }} />
      </Box>
      <Typography variant="body2" sx={{ color: "text.secondary", mb: 3 }}>
        Your security operations overview
      </Typography>

      {/* Metric tiles */}
      <Box sx={{ display: "flex", gap: 1.5, mb: 4, flexWrap: "wrap" }}>
        {METRICS.map((m) => {
          const { Icon } = m;
          return (
            <Box
              key={m.label}
              onClick={() => navigate(m.path)}
              sx={{
                flex: "1 1 130px", minWidth: 120,
                bgcolor: "background.paper",
                border: "1px solid", borderColor: "divider",
                borderTop: `3px solid ${m.color}`,
                borderRadius: 1.5, p: 1.5, cursor: "pointer",
                transition: "box-shadow 0.15s, transform 0.15s",
                "&:hover": {
                  boxShadow: `0 4px 20px ${alpha(m.color, 0.2)}`,
                  transform: "translateY(-2px)",
                },
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.75 }}>
                <Icon sx={{ fontSize: 15, color: m.color }} />
                <Typography variant="caption" sx={{ color: "text.secondary", fontSize: "0.7rem" }}>
                  {m.label}
                </Typography>
              </Box>
              <Box sx={{ display: "flex", alignItems: "baseline", gap: 0.5 }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color: m.color, lineHeight: 1 }}>
                  {m.value}
                </Typography>
                <Typography variant="caption" sx={{ color: "text.disabled" }}>{m.unit}</Typography>
              </Box>
            </Box>
          );
        })}
      </Box>

      {/* Main two-column layout */}
      <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap" }}>

        {/* Left: Recently visited + Quick actions */}
        <Box sx={{ flex: "2 1 480px", minWidth: 280 }}>
          <SectionLabel>RECENTLY VISITED</SectionLabel>
          <Box sx={{ display: "flex", gap: 1.5, flexWrap: "wrap", mb: 4 }}>
            {RECENT.map((r) => {
              const { Icon } = r;
              return (
                <Box
                  key={r.label}
                  onClick={() => navigate(r.path)}
                  sx={{
                    flex: "1 1 140px", minWidth: 130,
                    bgcolor: "background.paper",
                    border: "1px solid", borderColor: "divider",
                    borderRadius: 1.5, p: 1.5, cursor: "pointer",
                    transition: "all 0.15s",
                    "&:hover": {
                      borderColor: r.color,
                      boxShadow: `0 2px 12px ${alpha(r.color, 0.15)}`,
                      transform: "translateY(-2px)",
                    },
                  }}
                >
                  <Box sx={{
                    width: 36, height: 36, borderRadius: "8px",
                    bgcolor: alpha(r.color, 0.12),
                    display: "flex", alignItems: "center", justifyContent: "center",
                    mb: 1,
                  }}>
                    <Icon sx={{ fontSize: 18, color: r.color }} />
                  </Box>
                  <Typography variant="body2" sx={{ fontWeight: 600, fontSize: "0.82rem", mb: 0.25 }}>
                    {r.label}
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.disabled", fontSize: "0.72rem" }}>
                    {r.sub}
                  </Typography>
                </Box>
              );
            })}
          </Box>

          <SectionLabel>QUICK ACTIONS</SectionLabel>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            {QUICK_ACTIONS.map((a) => {
              const { Icon } = a;
              return (
                <Box
                  key={a.label}
                  onClick={() => navigate(a.path)}
                  sx={{
                    display: "flex", alignItems: "center", gap: 1,
                    px: 2, py: 0.9,
                    bgcolor: "background.paper",
                    border: "1px solid", borderColor: "divider",
                    borderRadius: 1.5, cursor: "pointer",
                    transition: "all 0.15s",
                    "&:hover": { borderColor: a.color, bgcolor: alpha(a.color, 0.06) },
                  }}
                >
                  <Icon sx={{ fontSize: 15, color: a.color }} />
                  <Typography variant="body2" sx={{ fontWeight: 500, fontSize: "0.82rem" }}>
                    {a.label}
                  </Typography>
                </Box>
              );
            })}
          </Box>
        </Box>

        {/* Right: Activity feed + Phase shortcuts */}
        <Box sx={{ flex: "1 1 240px", minWidth: 220 }}>
          <SectionLabel>RECENT ACTIVITY</SectionLabel>
          <Box sx={{
            bgcolor: "background.paper",
            border: "1px solid", borderColor: "divider",
            borderRadius: 1.5, overflow: "hidden", mb: 3,
          }}>
            {ACTIVITY.map((a, idx) => (
              <Box
                key={idx}
                sx={{
                  display: "flex", alignItems: "flex-start", gap: 1.5,
                  px: 2, py: 1.25,
                  borderBottom: idx < ACTIVITY.length - 1 ? "1px solid" : "none",
                  borderColor: "divider",
                  "&:hover": { bgcolor: "action.hover", cursor: "pointer" },
                }}
              >
                <Box sx={{ width: 7, height: 7, borderRadius: "50%", bgcolor: activityColor(a.type), mt: 0.65, flexShrink: 0 }} />
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Typography variant="body2" sx={{ fontSize: "0.79rem", lineHeight: 1.3 }}>{a.msg}</Typography>
                  <Typography variant="caption" sx={{ color: "text.disabled", fontSize: "0.69rem" }}>{a.time}</Typography>
                </Box>
              </Box>
            ))}
          </Box>

          <SectionLabel>WORKFLOW PHASES</SectionLabel>
          <Box sx={{
            bgcolor: "background.paper",
            border: "1px solid", borderColor: "divider",
            borderRadius: 1.5, overflow: "hidden",
          }}>
            {PHASES.map((p, idx) => (
              <Box
                key={p.label}
                onClick={() => navigate(p.path)}
                sx={{
                  display: "flex", alignItems: "center", gap: 1.5,
                  px: 2, py: 0.9,
                  borderBottom: idx < PHASES.length - 1 ? "1px solid" : "none",
                  borderColor: "divider",
                  cursor: "pointer",
                  "&:hover": { bgcolor: "action.hover" },
                }}
              >
                <Box sx={{ width: 7, height: 7, borderRadius: "50%", bgcolor: p.color, flexShrink: 0 }} />
                <Typography variant="body2" sx={{ flex: 1, fontSize: "0.8rem" }}>{p.label}</Typography>
                <ChevronRight sx={{ fontSize: 14, color: "text.disabled" }} />
              </Box>
            ))}
          </Box>
        </Box>
      </Box>
    </Box>
  );
}
