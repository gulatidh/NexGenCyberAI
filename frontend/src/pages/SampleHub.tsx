import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Card, CardContent, Chip, Stack, alpha,
} from "@mui/material";
import { Grid } from "@mui/material";
import {
  Cable, Hub, BugReport, Insights, Radar, GppGood, SmartToy,
  Settings, ArrowForward, People, Security, Policy,
} from "@mui/icons-material";
import { useTheme } from "@mui/material/styles";

const PHASES = [
  {
    num: 1, id: "setup", label: "Setup",
    color: "#42A5F5",
    Icon: Cable,
    tagline: "Connect your environment",
    items: ["Clients & Projects", "Scanner Connectors", "AI Providers", "Ticket Sync"],
    metric: "3 connectors active",
    path: "/connections",
  },
  {
    num: 2, id: "design", label: "Design",
    color: "#AB47BC",
    Icon: Hub,
    tagline: "Model threats before you scan",
    items: ["Threat Models (DFD + STRIDE)", "AI Detection Rules (Sigma)", "Compliance Frameworks", "Custom Policy"],
    metric: "2 threat models",
    path: "/threat-models",
  },
  {
    num: 3, id: "discover", label: "Discover",
    color: "#26A69A",
    Icon: BugReport,
    tagline: "Run assessments, build inventory",
    items: ["AI Assisted Scan (wizard)", "VA / DAST / SAST / Cloud Scans", "Asset Inventory", "Findings"],
    metric: "5 scans completed",
    path: "/scans",
  },
  {
    num: 4, id: "analyse", label: "Analyse",
    color: "#FFA726",
    Icon: Insights,
    tagline: "Understand exposure & risk",
    items: ["Risk Overview (FAIR ALE)", "Risk Register", "Attack Paths (MITRE)", "CVE Blast Radius", "Compliance Heatmap"],
    metric: "47 risks scored",
    path: "/risk-overview",
  },
  {
    num: 5, id: "respond", label: "Respond",
    color: "#EF5350",
    Icon: Radar,
    tagline: "Close gaps, manage exposure",
    items: ["Threat Intelligence (ATT&CK)", "Control Deficiencies", "Remediation Actions", "AI Remediations", "CTEM Programs"],
    metric: "12 open gaps",
    path: "/control-deficiencies",
  },
  {
    num: 6, id: "report", label: "Report",
    color: "#66BB6A",
    Icon: GppGood,
    tagline: "Deliver evidence & track posture",
    items: ["VAPT Reports (PDF / DOCX)", "Evidence Package (ZIP)", "Posture Trends", "Client Comparison"],
    metric: "3 VAPT reports",
    path: "/vapt/reports",
  },
  {
    num: 7, id: "automate", label: "Automate",
    color: "#5C6BC0",
    Icon: SmartToy,
    tagline: "AI-powered tools & knowledge",
    items: ["AI Buddies (6 agents)", "Automated Workflows", "Knowledge Base", "Security Docs (RAG)", "Ask Your Data (NL→SQL)"],
    metric: "4 workflows active",
    path: "/agents",
  },
  {
    num: 8, id: "configure", label: "Configure",
    color: "#78909C",
    Icon: Settings,
    tagline: "Integrations & platform settings",
    items: ["Settings & Notifications", "Webhooks (HMAC-signed)", "API Keys (M2M / CI-CD)", "Help & Documentation"],
    metric: "",
    path: "/settings",
  },
];

export default function SampleHub() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [hovered, setHovered] = useState<string | null>(null);

  return (
    <Box sx={{ p: { xs: 2, md: 4 }, maxWidth: 1440, mx: "auto" }}>
      {/* Header */}
      <Stack direction="row" alignItems="center" justifyContent="space-between" mb={0.5}>
        <Stack direction="row" alignItems="center" spacing={2}>
          <Typography variant="h4" fontWeight={700} letterSpacing="-0.5px">
            Security Operations Hub
          </Typography>
          <Chip label="Sample — Option 1" size="small" color="primary" variant="outlined" />
        </Stack>
      </Stack>
      <Typography color="text.secondary" mb={4} variant="body2">
        8-phase workflow from setup to automation — click any phase to enter it
      </Typography>

      {/* Phase grid */}
      <Grid container spacing={2.5}>
        {PHASES.map((phase) => {
          const { Icon } = phase;
          const isHovered = hovered === phase.id;

          return (
            <Grid key={phase.id} item xs={12} sm={6} md={3}>
              <Card
                onMouseEnter={() => setHovered(phase.id)}
                onMouseLeave={() => setHovered(null)}
                onClick={() => navigate(phase.path)}
                sx={{
                  height: "100%",
                  cursor: "pointer",
                  transition: "all 0.18s ease",
                  borderTop: `3px solid ${phase.color}`,
                  boxShadow: isHovered
                    ? `0 8px 32px ${alpha(phase.color, 0.28)}, 0 2px 8px rgba(0,0,0,0.2)`
                    : theme.shadows[2],
                  transform: isHovered ? "translateY(-4px)" : "none",
                  position: "relative",
                  overflow: "hidden",
                  "&::before": {
                    content: '""',
                    position: "absolute",
                    inset: 0,
                    background: isHovered
                      ? `linear-gradient(135deg, ${alpha(phase.color, 0.07)} 0%, transparent 55%)`
                      : "none",
                    pointerEvents: "none",
                    transition: "all 0.18s ease",
                  },
                }}
              >
                <CardContent sx={{ pb: "16px !important", height: "100%", display: "flex", flexDirection: "column" }}>
                  {/* Phase number + icon row */}
                  <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1.5}>
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <Box
                        sx={{
                          width: 34, height: 34, borderRadius: "9px",
                          bgcolor: alpha(phase.color, 0.14),
                          display: "flex", alignItems: "center", justifyContent: "center",
                        }}
                      >
                        <Icon sx={{ fontSize: 18, color: phase.color }} />
                      </Box>
                      <Typography
                        variant="caption"
                        sx={{ color: alpha(phase.color, 0.8), fontWeight: 700, letterSpacing: "0.08em" }}
                      >
                        PHASE {phase.num}
                      </Typography>
                    </Stack>
                    <ArrowForward
                      sx={{
                        fontSize: 15, color: phase.color,
                        opacity: isHovered ? 1 : 0,
                        transition: "opacity 0.15s",
                      }}
                    />
                  </Stack>

                  {/* Label + tagline */}
                  <Typography variant="h6" fontWeight={700} lineHeight={1.2} mb={0.4}>
                    {phase.label}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" display="block" mb={1.5} lineHeight={1.4}>
                    {phase.tagline}
                  </Typography>

                  {/* Feature list */}
                  <Stack spacing={0.5} mb={2} flex={1}>
                    {phase.items.map((item) => (
                      <Typography
                        key={item}
                        variant="body2"
                        color="text.secondary"
                        sx={{ display: "flex", alignItems: "center", gap: 1, fontSize: "0.775rem" }}
                      >
                        <Box
                          component="span"
                          sx={{
                            width: 5, height: 5, borderRadius: "50%",
                            bgcolor: phase.color, flexShrink: 0,
                            opacity: 0.7,
                          }}
                        />
                        {item}
                      </Typography>
                    ))}
                  </Stack>

                  {/* Metric chip */}
                  {phase.metric && (
                    <Chip
                      label={phase.metric}
                      size="small"
                      sx={{
                        bgcolor: alpha(phase.color, 0.12),
                        color: phase.color,
                        fontWeight: 600,
                        fontSize: "0.7rem",
                        height: 22,
                        alignSelf: "flex-start",
                      }}
                    />
                  )}
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>

      {/* Flow strip */}
      <Stack direction="row" alignItems="center" justifyContent="center" mt={4} spacing={0.5}>
        {PHASES.map((phase, idx) => (
          <React.Fragment key={phase.id}>
            <Box
              onClick={() => navigate(phase.path)}
              title={`Phase ${phase.num}: ${phase.label}`}
              sx={{
                width: 10, height: 10, borderRadius: "50%",
                bgcolor: phase.color, cursor: "pointer",
                transition: "transform 0.15s",
                "&:hover": { transform: "scale(1.5)" },
              }}
            />
            {idx < PHASES.length - 1 && (
              <Box sx={{ width: 28, height: 1, bgcolor: "divider" }} />
            )}
          </React.Fragment>
        ))}
      </Stack>
      <Typography variant="caption" color="text.disabled" textAlign="center" display="block" mt={1}>
        Phase 1 → 8 &nbsp;·&nbsp; Click any dot or card to navigate
      </Typography>
    </Box>
  );
}
