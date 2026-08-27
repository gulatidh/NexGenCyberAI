import React from "react";
import {
  Box, Typography, Chip, Grid, useTheme, alpha,
} from "@mui/material";
import {
  VerifiedUser, FindInPage, Gavel, TrendingUp, ManageSearch,
  Assessment, Analytics, Radar, Policy, Timeline, BarChart,
  TrackChanges, GppGood, Summarize,
} from "@mui/icons-material";

// ── Audit mapping table rows ───────────────────────────────────────────────────

const AUDIT_ROWS = [
  {
    icon: <VerifiedUser sx={{ fontSize: 18 }} />,
    color: "#4285F4",
    activity: "Control testing",
    feature: "Frameworks — NIST CSF, ISO 27001, CIS v8, PCI DSS, GDPR, IM8",
    change: "Live compliance status against every control, not just sampled ones. Custom frameworks for org-specific standards.",
  },
  {
    icon: <FindInPage sx={{ fontSize: 18 }} />,
    color: "#00BCD4",
    activity: "Gap identification",
    feature: "Control Deficiencies register",
    change: "AI-populated gaps mapped to specific control IDs with finding evidence — no manual gap analysis.",
  },
  {
    icon: <Gavel sx={{ fontSize: 18 }} />,
    color: "#FF9800",
    activity: "Evidence collection",
    feature: "Evidence Package (ZIP export)",
    change: "One click: findings CSV, control gaps JSON, remediation log, agent run trail — regulator-ready.",
  },
  {
    icon: <TrendingUp sx={{ fontSize: 18 }} />,
    color: "#10B981",
    activity: "Risk quantification",
    feature: "Risk Register — FAIR-lite ALE model",
    change: "Dollar-value risk per finding, not red/amber/green. Prioritisation grounded in financial exposure.",
  },
  {
    icon: <ManageSearch sx={{ fontSize: 18 }} />,
    color: "#7C3AED",
    activity: "Audit sampling & analytics",
    feature: "Ask Your Data — NL Query engine",
    change: "Query the full population in plain English. \"Show critical findings open > 30 days\" — no SQL needed.",
  },
  {
    icon: <Assessment sx={{ fontSize: 18 }} />,
    color: "#F472B6",
    activity: "Vulnerability review",
    feature: "Findings + VAPT Reports",
    change: "100% of scanned assets covered — not a 5% sample. AI writes executive summary and remediation plan.",
  },
  {
    icon: <Analytics sx={{ fontSize: 18 }} />,
    color: "#FF9800",
    activity: "Remediation tracking",
    feature: "MTTR + Remediation Tracker",
    change: "Auditable proof of fix timelines vs. SLA targets. Critical 24h, High 168h, Medium 720h.",
  },
  {
    icon: <Radar sx={{ fontSize: 18 }} />,
    color: "#EF4444",
    activity: "Threat landscape review",
    feature: "Threat Register — MITRE ATT&CK",
    change: "Structured TTP entries per finding. Auditor sees attacker profile, technique, and detection gap — not just CVE IDs.",
  },
  {
    icon: <Policy sx={{ fontSize: 18 }} />,
    color: "#10B981",
    activity: "Policy review",
    feature: "Security Docs — RAG engine",
    change: "Upload policies, ask questions. \"Does our policy cover MFA for privileged access?\" — grounded answers.",
  },
  {
    icon: <Timeline sx={{ fontSize: 18 }} />,
    color: "#00BCD4",
    activity: "Posture over time",
    feature: "Posture Trends — 90-day snapshots",
    change: "Proves improvement or deterioration over the audit period. Charts open findings by severity, audit readiness %.",
  },
];

// ── Risk management cards ──────────────────────────────────────────────────────

const RISK_CARDS = [
  {
    icon: <Radar sx={{ fontSize: 22 }} />,
    color: "#EF4444",
    phase: "01 · Identify",
    title: "Risk Identification",
    body: "15+ scanners surface vulnerabilities across code, infrastructure, dependencies, and secrets. AI agents classify each finding into Risk Domains — Identity, Cloud Security, Data Protection, Network, Logging.",
    tags: ["SAST · DAST · Network", "Risk Domain mapping"],
  },
  {
    icon: <BarChart sx={{ fontSize: 22 }} />,
    color: "#FF9800",
    phase: "02 · Assess",
    title: "Risk Quantification",
    body: "FAIR-lite ALE model assigns a dollar-value annualised loss expectancy to each risk. Likelihood and impact are derived from CVSS scores, asset criticality, and threat intel — not colour-coded gut feel.",
    tags: ["FAIR-lite ALE model", "CVSS + asset weighting"],
  },
  {
    icon: <VerifiedUser sx={{ fontSize: 22 }} />,
    color: "#4285F4",
    phase: "03 · Control",
    title: "Control Assessment",
    body: "Every finding auto-maps to NIST CSF, ISO 27001, CIS v8, PCI DSS, GDPR, and GCC IM8 controls. Compliance heatmap shows coverage by domain. Custom frameworks let you define your own control baseline.",
    tags: ["6 built-in frameworks", "Custom standards"],
  },
  {
    icon: <TrackChanges sx={{ fontSize: 22 }} />,
    color: "#7C3AED",
    phase: "04 · Treat",
    title: "Risk Treatment Tracking",
    body: "Remediation Tracker assigns priority bands (Immediate / High / Near-Term / Long-Term). MTTR is measured against SLA targets per severity. Accept risk with justification and expiry, or suppress false positives.",
    tags: ["Priority bands", "MTTR vs SLA", "Risk acceptance"],
  },
  {
    icon: <GppGood sx={{ fontSize: 22 }} />,
    color: "#10B981",
    phase: "05 · Monitor",
    title: "Continuous Monitoring",
    body: "Posture snapshots captured daily. 90-day trends chart open findings by severity, audit readiness %, and risk score. Webhooks fire on critical findings in real time — Slack, Teams, or any endpoint.",
    tags: ["Daily snapshots", "90-day trends", "Real-time alerts"],
  },
  {
    icon: <Summarize sx={{ fontSize: 22 }} />,
    color: "#00BCD4",
    phase: "06 · Report",
    title: "Board & Audit Reporting",
    body: "VAPT reports generated by AI — executive summary, scope, methodology, per-finding remediation — exported as PDF or DOCX. Embeddable scorecard for board decks. Evidence package ZIP for regulators.",
    tags: ["PDF · DOCX export", "Embeddable scorecard", "Regulator-ready ZIP"],
  },
];

// ── Component ──────────────────────────────────────────────────────────────────

export default function AuditIntelligence() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Box>
      {/* ── Header ── */}
      <Box sx={{ mb: 4 }}>
        <Chip
          label="ICS Audit & Risk Intelligence"
          size="small"
          sx={{ mb: 1.5, bgcolor: alpha("#00BCD4", 0.1), color: "#00BCD4", fontWeight: 700, border: `1px solid ${alpha("#00BCD4", 0.25)}` }}
        />
        <Typography variant="h5" sx={{ fontWeight: 800, letterSpacing: "-0.02em", mb: 0.75 }}>
          Built for the way auditors think
        </Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", maxWidth: 600 }}>
          Continuous, population-complete, evidence-automated — not point-in-time snapshots of a sample.
        </Typography>
      </Box>

      {/* ── Quote banner ── */}
      <Box sx={{
        mb: 5, borderRadius: 3, border: "1px solid", borderColor: "divider", overflow: "hidden",
        display: "flex", flexDirection: { xs: "column", md: "row" },
      }}>
        {[
          { text: "Don't sample\nwhat you can measure.", color: "#00BCD4" },
          { text: "Don't measure\nwhat you can query.", color: "#7C3AED" },
          { text: "Don't query\nwhat you can automate.", color: "#10B981" },
        ].map((part, i) => (
          <Box key={i} sx={{
            flex: 1, px: 3, py: 3,
            borderLeft: i > 0 ? { md: "1px solid" } : "none",
            borderTop: i > 0 ? { xs: "1px solid", md: "none" } : "none",
            borderColor: "divider",
            bgcolor: alpha(part.color, isDark ? 0.05 : 0.03),
          }}>
            <Box sx={{ width: 32, height: 3, borderRadius: 2, bgcolor: part.color, mb: 1.5 }} />
            <Typography sx={{
              fontSize: { xs: 15, md: 17 }, fontWeight: 800, lineHeight: 1.4,
              whiteSpace: "pre-line", color: "text.primary", letterSpacing: "-0.02em",
            }}>
              {part.text}
            </Typography>
          </Box>
        ))}
      </Box>

      {/* ── Audit mapping table ── */}
      <Box sx={{ mb: 5 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2.5 }}>
          <Box sx={{ width: 4, height: 28, borderRadius: 2, background: "linear-gradient(180deg, #00BCD4, #7C3AED)" }} />
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 800, letterSpacing: "-0.02em", lineHeight: 1.2 }}>
              How Aegis maps to ICS Audit activities
            </Typography>
            <Typography variant="caption" sx={{ color: "text.secondary" }}>
              Every audit step has a platform-native equivalent — no manual evidence gathering
            </Typography>
          </Box>
        </Box>

        {/* Column headers */}
        <Box sx={{
          display: { xs: "none", md: "grid" },
          gridTemplateColumns: "200px 1fr 1fr",
          px: 1.5, mb: 0.75,
        }}>
          {["ICS Audit Activity", "Aegis Feature", "What changes"].map((h) => (
            <Typography key={h} sx={{ fontSize: 10, fontWeight: 700, color: "text.disabled", textTransform: "uppercase", letterSpacing: 0.8 }}>
              {h}
            </Typography>
          ))}
        </Box>

        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
          {AUDIT_ROWS.map((row, i) => (
            <Box key={i} sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", md: "200px 1fr 1fr" },
              gap: { xs: 0.75, md: 0 },
              px: { xs: 2, md: 1.5 }, py: { xs: 2, md: 1.5 },
              borderRadius: 2,
              border: "1px solid", borderColor: "divider",
              bgcolor: i % 2 === 0 ? "background.paper" : alpha(theme.palette.action.hover, 0.3),
              transition: "all 0.15s",
              "&:hover": {
                borderColor: row.color,
                bgcolor: alpha(row.color, 0.04),
              },
              alignItems: "center",
            }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                <Box sx={{
                  width: 32, height: 32, borderRadius: 1.5, flexShrink: 0,
                  bgcolor: alpha(row.color, 0.12), border: `1px solid ${alpha(row.color, 0.25)}`,
                  display: "flex", alignItems: "center", justifyContent: "center", color: row.color,
                }}>
                  {row.icon}
                </Box>
                <Typography sx={{ fontSize: 13, fontWeight: 700 }}>{row.activity}</Typography>
              </Box>
              <Box sx={{ px: { md: 2 } }}>
                <Typography sx={{ fontSize: 13, color: row.color, fontWeight: 600 }}>{row.feature}</Typography>
              </Box>
              <Box sx={{ px: { md: 2 } }}>
                <Typography variant="caption" sx={{ color: "text.secondary", lineHeight: 1.6 }}>{row.change}</Typography>
              </Box>
            </Box>
          ))}
        </Box>
      </Box>

      {/* ── Risk management cards ── */}
      <Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2.5 }}>
          <Box sx={{ width: 4, height: 28, borderRadius: 2, background: "linear-gradient(180deg, #FF9800, #EF4444)" }} />
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 800, letterSpacing: "-0.02em", lineHeight: 1.2 }}>
              Risk management — end to end
            </Typography>
            <Typography variant="caption" sx={{ color: "text.secondary" }}>
              From identification to board-level reporting — all in one platform
            </Typography>
          </Box>
        </Box>

        <Grid container spacing={2}>
          {RISK_CARDS.map((card, i) => (
            <Grid key={i} size={{ xs: 12, sm: 6, md: 4 }}>
              <Box sx={{
                p: 2.5, borderRadius: 2.5, height: "100%",
                border: "1px solid", borderColor: "divider",
                bgcolor: "background.paper",
                transition: "all 0.2s",
                "&:hover": {
                  borderColor: card.color,
                  bgcolor: alpha(card.color, 0.04),
                  transform: "translateY(-3px)",
                  boxShadow: `0 12px 32px ${alpha(card.color, 0.12)}`,
                },
              }}>
                <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 2 }}>
                  <Box sx={{
                    width: 44, height: 44, borderRadius: 2,
                    bgcolor: alpha(card.color, 0.12), border: `1px solid ${alpha(card.color, 0.25)}`,
                    display: "flex", alignItems: "center", justifyContent: "center", color: card.color,
                  }}>
                    {card.icon}
                  </Box>
                  <Chip label={card.phase} size="small" sx={{
                    fontSize: 10, fontWeight: 700, height: 20,
                    bgcolor: alpha(card.color, 0.1), color: card.color,
                  }} />
                </Box>
                <Typography sx={{ fontWeight: 700, fontSize: 14, mb: 1 }}>{card.title}</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary", lineHeight: 1.65, display: "block", mb: 1.5 }}>
                  {card.body}
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.75 }}>
                  {card.tags.map((tag) => (
                    <Chip key={tag} label={tag} size="small" variant="outlined" sx={{
                      fontSize: 10, height: 18,
                      borderColor: alpha(card.color, 0.3), color: card.color,
                    }} />
                  ))}
                </Box>
              </Box>
            </Grid>
          ))}
        </Grid>
      </Box>
    </Box>
  );
}
