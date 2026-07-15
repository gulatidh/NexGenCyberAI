import React, { useState, useEffect } from "react";
import {
  Box, Container, Typography, Button, Grid, Chip,
  Accordion, AccordionSummary, AccordionDetails,
} from "@mui/material";
import {
  Code, Assessment, AccountTree, TrendingUp, VerifiedUser, SmartToy,
  ArrowForward, Shield, Hub, Lock, CheckCircle, Radar,
  Menu as MenuIcon, Close as CloseIcon, ExpandMore,
} from "@mui/icons-material";
import { useMsal } from "@azure/msal-react";
import { loginRequest } from "../auth/msalConfig";

const CYAN = "#00D4FF";
const PURPLE = "#7C3AED";
const GREEN = "#10B981";
const AMBER = "#F59E0B";
const DANGER = "#EF4444";
const BG = "#060810";
const CARD_BG = "rgba(255,255,255,0.035)";
const BORDER = "rgba(255,255,255,0.07)";

const FEATURES = [
  {
    icon: <Code sx={{ fontSize: 28 }} />,
    color: CYAN,
    title: "AI Code Review",
    subtitle: "SAST · LLM-powered",
    desc: "Connect your GitHub repo or upload a zip. A 4-phase pipeline — triage, chunk-level review, self-critique, and cross-file taint tracing — surfaces real, exploitable vulnerabilities with proof-of-exploit and remediation steps.",
    bullets: ["CWE-mapped findings", "Parallel LLM analysis", "False-positive pruning"],
  },
  {
    icon: <Assessment sx={{ fontSize: 28 }} />,
    color: AMBER,
    title: "AI-Powered VAPT",
    subtitle: "SAST · DAST · Network · Deps",
    desc: "Launch Semgrep, CodeQL, SonarQube, OWASP ZAP, Nmap, OpenVAS, Trivy, Gitleaks, and TruffleHog from one dashboard. AI agents enrich every finding with MITRE techniques, compliance mappings, and priority-banded remediation plans.",
    bullets: ["9 scanner integrations", "AI-enriched findings", "Unified finding schema"],
  },
  {
    icon: <AccountTree sx={{ fontSize: 28 }} />,
    color: PURPLE,
    title: "AI Threat Modeling",
    subtitle: "STRIDE · MITRE ATT&CK",
    desc: "Describe your system and Aegis generates comprehensive threat models in minutes. Threats are mapped to STRIDE categories, MITRE ATT&CK techniques, and compliance controls — with attacker profiles and detection gap analysis.",
    bullets: ["STRIDE taxonomy", "ATT&CK technique mapping", "Detection gap analysis"],
  },
  {
    icon: <Radar sx={{ fontSize: 28 }} />,
    color: "#00ACC1",
    title: "Security Registers",
    subtitle: "Threat · Control Gaps · Remediation",
    desc: "Three dedicated registers automatically populated by AI agents. The Threat Register tracks MITRE-mapped TTPs, Control Deficiencies captures compliance gaps, and the Remediation Tracker manages priority-banded action items.",
    bullets: ["Threat Register (MITRE ATT&CK)", "Control Deficiency gaps", "Remediation with bands"],
  },
  {
    icon: <TrendingUp sx={{ fontSize: 28 }} />,
    color: GREEN,
    title: "Risk Intelligence",
    subtitle: "FAIR-lite · Continuous scoring",
    desc: "A live risk score built from aggregated findings, asset criticality, and business context using a FAIR-lite ALE model. Risk Domains group findings for executive-grade reporting across clients.",
    bullets: ["FAIR-lite ALE model", "Risk Domain grouping", "Per-client dashboards"],
  },
  {
    icon: <VerifiedUser sx={{ fontSize: 28 }} />,
    color: "#F472B6",
    title: "Compliance Frameworks",
    subtitle: "NIST · PCI DSS · ISO 27001",
    desc: "Every finding is automatically mapped to one or more compliance controls. Track framework coverage, identify control gaps, and generate audit-ready reports. Build custom frameworks from any combination of controls.",
    bullets: ["5 built-in frameworks", "Custom standards builder", "Audit-ready exports"],
  },
  {
    icon: <SmartToy sx={{ fontSize: 28 }} />,
    color: "#FB923C",
    title: "AI Security Agents",
    subtitle: "60+ specialist advisors",
    desc: "Deploy AI agents that investigate alerts, run scheduled security missions, and answer security questions in natural language. Operational agents populate dedicated registers automatically from every scan.",
    bullets: ["60+ specialist agents", "Scheduled missions", "Register auto-population"],
  },
];

const STATS = [
  { value: "9+", label: "Scanner integrations" },
  { value: "60+", label: "AI security agents" },
  { value: "5", label: "Compliance frameworks" },
  { value: "Real-time", label: "Risk scoring" },
];

const SCANNER_GROUPS = [
  { label: "SAST", color: CYAN, items: ["Semgrep", "CodeQL", "SonarQube", "AI Code Review"] },
  { label: "DAST", color: PURPLE, items: ["OWASP ZAP"] },
  { label: "Network", color: GREEN, items: ["Nmap", "OpenVAS", "Trivy"] },
  { label: "Secrets", color: AMBER, items: ["Gitleaks", "TruffleHog"] },
  { label: "AI Providers", color: "#F472B6", items: ["Azure OpenAI", "OpenAI", "Anthropic", "Gemini", "AWS Bedrock"] },
  { label: "Ticketing", color: "#00ACC1", items: ["Jira", "ServiceNow"] },
];

const STEPS = [
  { n: "01", title: "Run scanners or submit code", desc: "Launch any of 9 scanners via GitHub Actions, paste a repo URL for AI code review, or upload a zip. All findings land in a unified normalised schema." },
  { n: "02", title: "AI agents enrich every finding", desc: "Threat Intel maps findings to MITRE ATT&CK. Risk Manager scores likelihood × impact. Compliance Monitor identifies control gaps. Remediation Agent generates priority-banded playbooks." },
  { n: "03", title: "Registers auto-populate", desc: "Agent outputs route to dedicated registers: Threat Register (TTPs), Control Deficiencies (compliance gaps), and Remediation Tracker (banded action items). No manual triage." },
  { n: "04", title: "Track to closure", desc: "Risk Domains group findings for executive reporting. Update remediation status, sync tickets to Jira or ServiceNow, generate VAPT reports, and run scheduled AI missions — all from one platform." },
];

const FAQS = [
  {
    q: "What scanners does Aegis integrate with?",
    a: "Aegis integrates with 9 open-source and commercial scanners across four categories: SAST (Semgrep, CodeQL, SonarQube), DAST (OWASP ZAP), Network (Nmap, OpenVAS, Trivy), and Dependency / Secrets scanning (Gitleaks, TruffleHog). Scans are dispatched via GitHub Actions — no extra infrastructure required.",
  },
  {
    q: "How do AI agents automatically populate the threat register?",
    a: "When you run the Threat Intel agent on a completed scan, it analyzes every finding against the MITRE ATT&CK framework and creates structured threat entries — technique IDs, attacker profiles, and detection gaps — directly in your Threat Register. The Orchestrator agent runs all four specialists (Threat Intel, Risk Manager, Compliance Monitor, Remediation) in a single call, populating all three registers at once.",
  },
  {
    q: "Can I bring my own AI provider?",
    a: "Yes. Aegis supports Azure OpenAI, OpenAI, Anthropic, Google Gemini, and AWS Bedrock. Configure one or more providers in AI Settings — Aegis automatically fails over to the next configured provider if the primary is unavailable. No vendor lock-in.",
  },
  {
    q: "Is my source code stored after an AI code review?",
    a: "No. Your repository is cloned or unzipped into a temporary directory, analyzed, and immediately deleted when the review completes. Only the structured findings — file paths, line numbers, vulnerability descriptions, and remediation steps — are persisted in the database.",
  },
  {
    q: "Which compliance frameworks does Aegis support?",
    a: "Out of the box: NIST CSF 2.0, CIS Controls v8, ISO 27001:2022, GDPR, and PCI DSS v4.0. You can also build custom compliance frameworks in the Custom Standards section — pick controls from any built-in framework, combine them, and AI agents will evaluate your findings against your custom standard.",
  },
  {
    q: "How does AI VAPT report generation work?",
    a: "Select a completed scan and choose 'Generate from Scan.' Aegis pulls all findings, infers the scope and testing methodology from the connector type, then uses an LLM to write an executive summary, per-finding detailed remediation, and a conclusion. Reports export as PDF or DOCX — full engagement report or remediation-only plan.",
  },
  {
    q: "Can I use Aegis across multiple clients or teams?",
    a: "Yes. Aegis supports multi-client workspaces — each client has isolated assets, scans, findings, threat entries, and risk scores. A global client selector in the top nav switches context instantly. Soft-delete lets you archive clients without losing historical data.",
  },
];

const NAV_LINKS = ["Features", "Process", "Integrations", "FAQ"];

const FOOTER_LINKS: Record<string, string[]> = {
  Product: ["Features", "Integrations", "Changelog"],
  Security: ["AI Code Review", "VAPT Reports", "Threat Modeling", "Compliance"],
  Company: ["About", "Blog", "Contact", "Careers"],
  Legal: ["Privacy Policy", "Terms of Service", "Security", "Cookie Policy"],
};

export default function LandingPage() {
  const { instance } = useMsal();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [faqOpen, setFaqOpen] = useState<string | false>(false);

  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", fn);
    return () => window.removeEventListener("scroll", fn);
  }, []);

  const signIn = () =>
    instance.loginRedirect({
      ...loginRequest,
      redirectStartPage: `${window.location.origin}/dashboard`,
    }).catch(() => {});


  return (
    <Box sx={{ bgcolor: BG, minHeight: "100vh", color: "white", fontFamily: "Inter, sans-serif", overflowX: "hidden" }}>

      {/* ── Navbar ─────────────────────────────────────────────────────────── */}
      <Box sx={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 100,
        backdropFilter: scrolled ? "blur(16px)" : "none",
        background: scrolled ? "rgba(6,8,16,0.92)" : "transparent",
        borderBottom: scrolled ? `1px solid ${BORDER}` : "none",
        transition: "all 0.3s",
      }}>
        <Container maxWidth="lg">
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", py: 2 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <img src={`${process.env.PUBLIC_URL}/aegis-logo.svg`} alt="Aegis" style={{ width: 32, height: 32 }} />
              <Typography sx={{ fontWeight: 800, fontSize: 20, letterSpacing: "-0.02em" }}>
                <Box component="span" sx={{ color: "#4285F4" }}>Aeg</Box>
                <Box component="span" sx={{ color: CYAN }}>is</Box>
                <Box component="span" sx={{ color: "rgba(255,255,255,0.45)", fontWeight: 400, fontSize: 14, ml: 0.75 }}>AI</Box>
              </Typography>
            </Box>

            <Box sx={{ display: { xs: "none", md: "flex" }, alignItems: "center", gap: 4 }}>
              {NAV_LINKS.map((item) => (
                <Typography key={item} component="a" href={`#${item.toLowerCase()}`} sx={{
                  color: "rgba(255,255,255,0.5)", fontSize: 14, textDecoration: "none", cursor: "pointer",
                  "&:hover": { color: "white" }, transition: "color 0.2s",
                }}>
                  {item}
                </Typography>
              ))}
            </Box>

            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <Button onClick={signIn} variant="outlined" size="small" sx={{
                color: "rgba(255,255,255,0.75)", borderColor: BORDER, textTransform: "none",
                fontSize: 13, fontWeight: 500, display: { xs: "none", md: "flex" },
                "&:hover": { borderColor: CYAN, color: CYAN, background: "rgba(0,212,255,0.05)" },
              }}>
                Sign In
              </Button>
              <Button onClick={signIn} variant="contained" size="small" sx={{
                background: CYAN, color: "#060810", fontWeight: 700, fontSize: 13,
                textTransform: "none", px: 2.5,
                "&:hover": { background: "#00B8E0" },
              }}>
                Get Started
              </Button>
              <Box sx={{ display: { xs: "flex", md: "none" }, cursor: "pointer" }}
                onClick={() => setMobileOpen(o => !o)}>
                {mobileOpen ? <CloseIcon /> : <MenuIcon />}
              </Box>
            </Box>
          </Box>
        </Container>

        {mobileOpen && (
          <Box sx={{ background: "rgba(6,8,16,0.97)", backdropFilter: "blur(16px)", py: 2, borderBottom: `1px solid ${BORDER}` }}>
            <Container>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
                {NAV_LINKS.map((item) => (
                  <Typography key={item} component="a" href={`#${item.toLowerCase()}`}
                    onClick={() => setMobileOpen(false)}
                    sx={{ color: "rgba(255,255,255,0.7)", fontSize: 15, textDecoration: "none" }}>
                    {item}
                  </Typography>
                ))}
                <Button onClick={signIn} variant="contained" sx={{ background: CYAN, color: "#060810", fontWeight: 700, textTransform: "none", mt: 1, alignSelf: "flex-start" }}>
                  Sign In
                </Button>
              </Box>
            </Container>
          </Box>
        )}
      </Box>

      {/* ── Hero ───────────────────────────────────────────────────────────── */}
      <Box sx={{ position: "relative", pt: { xs: 14, md: 18 }, pb: { xs: 8, md: 10 }, overflow: "hidden" }}>
        <Box sx={{ position: "absolute", top: "5%", left: "30%", width: 900, height: 600, borderRadius: "50%",
          background: `radial-gradient(ellipse, rgba(0,212,255,0.1) 0%, rgba(124,58,237,0.07) 40%, transparent 70%)`,
          pointerEvents: "none", transform: "translateX(-50%)" }} />
        <Box sx={{ position: "absolute", top: 0, right: "-5%", width: 450, height: 450, borderRadius: "50%",
          background: `radial-gradient(ellipse, rgba(124,58,237,0.12) 0%, transparent 65%)`,
          pointerEvents: "none" }} />

        <Container maxWidth="lg" sx={{ position: "relative" }}>
          <Grid container spacing={{ xs: 6, md: 8 }} sx={{ alignItems: "center" }}>
            {/* Left: text */}
            <Grid size={{ xs: 12, md: 6 }}>
              <Chip label="AI-Powered Security Platform" size="small" sx={{
                mb: 3, background: "rgba(0,212,255,0.08)", border: `1px solid rgba(0,212,255,0.25)`,
                color: CYAN, fontWeight: 600, fontSize: 12, letterSpacing: 0.5,
              }} />

              <Typography sx={{ fontSize: { xs: 38, sm: 50, md: 58 }, fontWeight: 800, lineHeight: 1.08, letterSpacing: "-0.03em", mb: 3 }}>
                Secure everything{" "}
                <Box component="span" sx={{
                  background: `linear-gradient(135deg, ${CYAN} 0%, ${PURPLE} 100%)`,
                  WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
                }}>
                  you build,
                </Box>
                <br />ship, and run.
              </Typography>

              <Typography sx={{ fontSize: { xs: 16, md: 18 }, color: "rgba(255,255,255,0.5)", lineHeight: 1.7, mb: 5, maxWidth: 500 }}>
                Aegis combines AI code review, VAPT, threat modeling, and autonomous security agents in one platform. AI agents auto-populate Threat, Control, and Remediation registers — so your team sees risk clearly and fixes what matters.
              </Typography>

              <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                <Button onClick={signIn} variant="contained" size="large" endIcon={<ArrowForward />} sx={{
                  background: CYAN, color: "#060810", fontWeight: 700, fontSize: 15,
                  textTransform: "none", px: 4, py: 1.5, borderRadius: 2,
                  "&:hover": { background: "#00B8E0", transform: "translateY(-1px)" }, transition: "all 0.2s",
                }}>
                  Sign In to Aegis
                </Button>
                <Button variant="outlined" size="large" href="#features" sx={{
                  color: "rgba(255,255,255,0.65)", borderColor: BORDER, fontWeight: 500,
                  fontSize: 15, textTransform: "none", px: 4, py: 1.5, borderRadius: 2,
                  "&:hover": { borderColor: "rgba(255,255,255,0.3)", color: "white", background: "rgba(255,255,255,0.03)" },
                }}>
                  Explore features
                </Button>
              </Box>

              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 3, mt: 5 }}>
                {[
                  { icon: <Shield sx={{ fontSize: 14 }} />, text: "SAST · DAST · Network" },
                  { icon: <Lock sx={{ fontSize: 14 }} />, text: "NIST · PCI DSS · ISO 27001" },
                  { icon: <Hub sx={{ fontSize: 14 }} />, text: "9+ scanners · 60+ AI agents" },
                ].map(({ icon, text }) => (
                  <Box key={text} sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                    <Box sx={{ color: "rgba(255,255,255,0.3)" }}>{icon}</Box>
                    <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.3)" }}>{text}</Typography>
                  </Box>
                ))}
              </Box>
            </Grid>

            {/* Right: dashboard mockup */}
            <Grid size={{ xs: 12, md: 6 }}>
              <Box sx={{
                background: "rgba(255,255,255,0.025)", border: `1px solid ${BORDER}`,
                borderRadius: 3, overflow: "hidden",
                boxShadow: "0 40px 100px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.05)",
                transform: { md: "perspective(1200px) rotateY(-6deg) rotateX(2deg)" },
                transition: "transform 0.4s",
                "&:hover": { transform: { md: "perspective(1200px) rotateY(-2deg) rotateX(1deg)" } },
              }}>
                {/* Window chrome */}
                <Box sx={{ borderBottom: `1px solid ${BORDER}`, px: 2.5, py: 1.5, display: "flex", alignItems: "center", gap: 1.5, background: "rgba(0,0,0,0.25)" }}>
                  <Box sx={{ width: 10, height: 10, borderRadius: "50%", background: "#FF5F57" }} />
                  <Box sx={{ width: 10, height: 10, borderRadius: "50%", background: "#FEBC2E" }} />
                  <Box sx={{ width: 10, height: 10, borderRadius: "50%", background: "#28C840" }} />
                  <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.25)", ml: 1, fontFamily: "monospace" }}>Aegis AI — Security Dashboard</Typography>
                </Box>

                <Box sx={{ p: 2.5 }}>
                  {/* Metric row */}
                  <Grid container spacing={1.5} sx={{ mb: 2 }}>
                    {[
                      { label: "Risk Score", value: "72", sub: "High risk", color: AMBER },
                      { label: "Open Findings", value: "84", sub: "↑ 12 new", color: DANGER },
                      { label: "Resolved", value: "231", sub: "Last 30 days", color: GREEN },
                    ].map(({ label, value, sub, color }) => (
                      <Grid key={label} size={{ xs: 4 }}>
                        <Box sx={{ p: 1.5, background: "rgba(0,0,0,0.2)", borderRadius: 2, border: `1px solid ${BORDER}` }}>
                          <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.38)", textTransform: "uppercase", letterSpacing: 0.8, mb: 0.5 }}>{label}</Typography>
                          <Typography sx={{ fontSize: 22, fontWeight: 800, color, lineHeight: 1 }}>{value}</Typography>
                          <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.28)", mt: 0.25 }}>{sub}</Typography>
                        </Box>
                      </Grid>
                    ))}
                  </Grid>

                  {/* Severity bars */}
                  <Box sx={{ mb: 2, p: 1.75, background: "rgba(0,0,0,0.15)", borderRadius: 2, border: `1px solid ${BORDER}` }}>
                    <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.32)", mb: 1.5, textTransform: "uppercase", letterSpacing: 0.8 }}>Severity breakdown</Typography>
                    {[
                      { label: "Critical", count: 3, color: DANGER, pct: 12 },
                      { label: "High", count: 19, color: "#F97316", pct: 35 },
                      { label: "Medium", count: 34, color: AMBER, pct: 58 },
                      { label: "Low", count: 28, color: GREEN, pct: 75 },
                    ].map(({ label, count, color, pct }) => (
                      <Box key={label} sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 0.8 }}>
                        <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.33)", width: 44, flexShrink: 0 }}>{label}</Typography>
                        <Box sx={{ flex: 1, height: 5, background: "rgba(255,255,255,0.04)", borderRadius: 3 }}>
                          <Box sx={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 3 }} />
                        </Box>
                        <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.38)", width: 18, textAlign: "right", flexShrink: 0 }}>{count}</Typography>
                      </Box>
                    ))}
                  </Box>

                  {/* Recent findings */}
                  <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.28)", textTransform: "uppercase", letterSpacing: 0.8, mb: 1 }}>Recent findings</Typography>
                  {[
                    { sev: "CRITICAL", cwe: "CWE-89", title: "SQL Injection in auth endpoint", file: "api/auth.py:127", color: DANGER },
                    { sev: "HIGH", cwe: "CWE-79", title: "Reflected XSS in search param", file: "frontend/search.js:48", color: "#F97316" },
                    { sev: "HIGH", cwe: "CWE-798", title: "Hardcoded API key in config", file: "config/settings.py:12", color: "#F97316" },
                  ].map(({ sev, cwe, title, file, color }, i) => (
                    <Box key={i} sx={{ mb: 1, p: 1.25, background: `${color}08`, border: `1px solid ${color}20`, borderRadius: 1.5 }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.4 }}>
                        <Chip label={sev} size="small" sx={{ background: `${color}20`, color, fontSize: 9, fontWeight: 700, height: 16, "& .MuiChip-label": { px: 0.75 } }} />
                        <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.32)", fontFamily: "monospace" }}>{cwe}</Typography>
                      </Box>
                      <Typography sx={{ fontSize: 11, color: "rgba(255,255,255,0.7)", fontWeight: 500 }}>{title}</Typography>
                      <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.26)", mt: 0.25, fontFamily: "monospace" }}>{file}</Typography>
                    </Box>
                  ))}

                  {/* Agent status pulse */}
                  <Box sx={{ mt: 1.5, p: 1.25, background: "rgba(0,212,255,0.06)", border: `1px solid rgba(0,212,255,0.18)`, borderRadius: 1.5, display: "flex", alignItems: "center", gap: 1.5 }}>
                    <Box sx={{ width: 6, height: 6, borderRadius: "50%", background: CYAN, flexShrink: 0,
                      boxShadow: `0 0 6px ${CYAN}` }} />
                    <Typography sx={{ fontSize: 11, color: "rgba(0,212,255,0.8)" }}>AI Threat Intel agent — mapping 84 findings to MITRE ATT&CK...</Typography>
                  </Box>
                </Box>
              </Box>
            </Grid>
          </Grid>
        </Container>
      </Box>

      {/* ── Stats bar ──────────────────────────────────────────────────────── */}
      <Box sx={{ borderTop: `1px solid ${BORDER}`, borderBottom: `1px solid ${BORDER}`, background: "rgba(255,255,255,0.015)", py: 5 }}>
        <Container maxWidth="lg">
          <Grid container spacing={2} sx={{ justifyContent: "center" }}>
            {STATS.map(({ value, label }) => (
              <Grid key={label} size={{ xs: 6, sm: 3 }} sx={{ textAlign: "center" }}>
                <Typography sx={{
                  fontSize: { xs: 30, md: 38 }, fontWeight: 800,
                  background: `linear-gradient(135deg, ${CYAN}, ${PURPLE})`,
                  WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
                }}>
                  {value}
                </Typography>
                <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.38)", mt: 0.5 }}>{label}</Typography>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>

      {/* ── Features grid ──────────────────────────────────────────────────── */}
      <Box id="features" sx={{ py: { xs: 10, md: 16 } }}>
        <Container maxWidth="lg">
          <Box sx={{ textAlign: "center", mb: 8 }}>
            <Chip label="Platform capabilities" size="small" sx={{ mb: 2.5, background: `rgba(124,58,237,0.1)`, border: `1px solid rgba(124,58,237,0.25)`, color: PURPLE, fontWeight: 600, fontSize: 12 }} />
            <Typography sx={{ fontSize: { xs: 28, md: 40 }, fontWeight: 800, letterSpacing: "-0.02em", mb: 2 }}>
              Everything your security team needs
            </Typography>
            <Typography sx={{ color: "rgba(255,255,255,0.42)", fontSize: 17, maxWidth: 580, mx: "auto" }}>
              Built on real scanners and large language models. AI agents populate dedicated registers — so findings become action.
            </Typography>
          </Box>

          <Grid container spacing={3}>
            {FEATURES.map((f) => (
              <Grid key={f.title} size={{ xs: 12, sm: 6, md: 4 }}>
                <Box sx={{
                  p: 3.5, borderRadius: 3, height: "100%",
                  background: CARD_BG, border: `1px solid ${BORDER}`,
                  transition: "all 0.25s",
                  "&:hover": {
                    background: "rgba(255,255,255,0.055)",
                    border: `1px solid rgba(255,255,255,0.12)`,
                    transform: "translateY(-4px)",
                    boxShadow: `0 20px 50px rgba(0,0,0,0.45), 0 0 0 1px ${f.color}15`,
                  },
                }}>
                  <Box sx={{
                    width: 52, height: 52, borderRadius: 2,
                    background: `${f.color}18`, border: `1px solid ${f.color}30`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    color: f.color, mb: 2.5,
                  }}>
                    {f.icon}
                  </Box>

                  <Chip label={f.subtitle} size="small" sx={{
                    mb: 1.5, background: `${f.color}10`, color: f.color,
                    fontSize: 11, fontWeight: 600, letterSpacing: 0.3, border: `1px solid ${f.color}22`,
                  }} />

                  <Typography sx={{ fontWeight: 700, fontSize: 18, mb: 1.5, letterSpacing: "-0.01em" }}>
                    {f.title}
                  </Typography>
                  <Typography sx={{ color: "rgba(255,255,255,0.46)", fontSize: 14, lineHeight: 1.65, mb: 2.5 }}>
                    {f.desc}
                  </Typography>

                  <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
                    {f.bullets.map((b) => (
                      <Box key={b} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <CheckCircle sx={{ fontSize: 14, color: f.color, flexShrink: 0 }} />
                        <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.48)" }}>{b}</Typography>
                      </Box>
                    ))}
                  </Box>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>

      {/* ── Process ────────────────────────────────────────────────────────── */}
      <Box id="process" sx={{ py: { xs: 8, md: 12 }, background: "rgba(255,255,255,0.012)", borderTop: `1px solid ${BORDER}`, borderBottom: `1px solid ${BORDER}` }}>
        <Container maxWidth="md">
          <Box sx={{ textAlign: "center", mb: 8 }}>
            <Chip label="How it works" size="small" sx={{ mb: 2.5, background: `rgba(0,212,255,0.08)`, border: `1px solid rgba(0,212,255,0.22)`, color: CYAN, fontWeight: 600, fontSize: 12 }} />
            <Typography sx={{ fontSize: { xs: 24, md: 36 }, fontWeight: 800, letterSpacing: "-0.02em", mb: 2 }}>
              Scan to closure — fully automated
            </Typography>
            <Typography sx={{ color: "rgba(255,255,255,0.38)", fontSize: 16 }}>
              AI agents handle enrichment, routing, and register population automatically
            </Typography>
          </Box>

          <Box sx={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {STEPS.map(({ n, title, desc }, i) => (
              <Box key={n} sx={{ display: "flex", gap: 3, position: "relative" }}>
                {i < STEPS.length - 1 && (
                  <Box sx={{ position: "absolute", left: 23, top: 56, width: 2, height: "calc(100% + 8px)",
                    background: `linear-gradient(180deg, rgba(0,212,255,0.3), transparent)` }} />
                )}
                <Box sx={{
                  flexShrink: 0, width: 48, height: 48, borderRadius: "50%",
                  background: `linear-gradient(135deg, rgba(0,212,255,0.15), rgba(124,58,237,0.15))`,
                  border: `1px solid rgba(0,212,255,0.3)`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  color: CYAN, fontSize: 12, fontWeight: 800,
                }}>
                  {n}
                </Box>
                <Box sx={{ pt: 0.5 }}>
                  <Typography sx={{ fontWeight: 700, fontSize: 17, mb: 0.75 }}>{title}</Typography>
                  <Typography sx={{ color: "rgba(255,255,255,0.46)", fontSize: 14, lineHeight: 1.7 }}>{desc}</Typography>
                </Box>
              </Box>
            ))}
          </Box>
        </Container>
      </Box>

      {/* ── Integrations ───────────────────────────────────────────────────── */}
      <Box id="integrations" sx={{ py: { xs: 8, md: 12 } }}>
        <Container maxWidth="lg">
          <Box sx={{ textAlign: "center", mb: 8 }}>
            <Chip label="Integrations" size="small" sx={{ mb: 2.5, background: `rgba(16,185,129,0.08)`, border: `1px solid rgba(16,185,129,0.22)`, color: GREEN, fontWeight: 600, fontSize: 12 }} />
            <Typography sx={{ fontSize: { xs: 24, md: 36 }, fontWeight: 800, letterSpacing: "-0.02em", mb: 2 }}>
              Works with your existing stack
            </Typography>
            <Typography sx={{ color: "rgba(255,255,255,0.38)", fontSize: 16 }}>
              Connect scanners, AI providers, and ticketing systems with zero infrastructure overhead
            </Typography>
          </Box>

          <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
            {SCANNER_GROUPS.map(({ label, color, items }) => (
              <Box key={label} sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
                <Chip label={label} size="small" sx={{
                  background: `${color}15`, color, border: `1px solid ${color}30`,
                  fontSize: 11, fontWeight: 700, letterSpacing: 0.5, minWidth: 86, flexShrink: 0,
                }} />
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {items.map((name) => (
                    <Box key={name} sx={{
                      px: 2, py: 0.75, borderRadius: 20, fontSize: 13, fontWeight: 500,
                      background: CARD_BG, border: `1px solid ${BORDER}`, color: "rgba(255,255,255,0.5)",
                      "&:hover": { color: "white", border: `1px solid rgba(255,255,255,0.15)`, background: "rgba(255,255,255,0.05)" },
                      transition: "all 0.2s", cursor: "default",
                    }}>
                      {name}
                    </Box>
                  ))}
                </Box>
              </Box>
            ))}
          </Box>
        </Container>
      </Box>

      {/* ── Private Deployment ─────────────────────────────────────────────── */}
      <Box id="deployment" sx={{ py: { xs: 10, md: 14 }, borderTop: `1px solid ${BORDER}` }}>
        <Container maxWidth="lg">
          <Box sx={{ textAlign: "center", mb: 8 }}>
            <Chip label="ENTERPRISE DEPLOYMENT" size="small" sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontWeight: 700, fontSize: 11, letterSpacing: 1, mb: 2 }} />
            <Typography sx={{ fontSize: { xs: 28, md: 38 }, fontWeight: 800, letterSpacing: "-0.02em", lineHeight: 1.15, mb: 2 }}>
              Deploy inside your{" "}
              <Box component="span" sx={{ background: `linear-gradient(135deg, #34A853, ${CYAN})`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
                own environment
              </Box>
            </Typography>
            <Typography sx={{ color: "rgba(255,255,255,0.45)", fontSize: 17, maxWidth: 620, mx: "auto", lineHeight: 1.65 }}>
              Aegis runs entirely inside your own cloud or on-premises infrastructure — Azure, AWS, GCP, or a private data centre. No internet exposure. No data leaving your boundary. Works wherever your workloads live.
            </Typography>
          </Box>

          <Grid container spacing={3} sx={{ mb: 6 }}>
            {[
              {
                icon: "🔒",
                title: "Private Network Only",
                body: "Deploy behind a private load balancer or app gateway — the portal is accessible only via your VPN, VNet, or private network. No public internet exposure required.",
              },
              {
                icon: "☁️",
                title: "Any Cloud or On-Premises",
                body: "Runs on Azure App Service, AWS Elastic Beanstalk, GCP Cloud Run, Kubernetes, or a plain VM in your own data centre. You own the infrastructure; we own none of it.",
              },
              {
                icon: "🔐",
                title: "Data Never Leaves",
                body: "All scan data, findings, AI analysis, and reports are stored in your own database. Nothing is sent to external services or third-party SaaS platforms.",
              },
              {
                icon: "🤖",
                title: "Your Own AI Models",
                body: "Connect to Azure OpenAI, AWS Bedrock, Google Vertex AI, or a self-hosted model. AI agents call your own deployment — no data touches a shared public LLM endpoint.",
              },
              {
                icon: "🌐",
                title: "Internal Access via VPN / ExpressRoute",
                body: "Integrate with your existing network topology. Route platform traffic through VPN Gateway, ExpressRoute, AWS Direct Connect, or GCP Interconnect — users access it like any internal app.",
              },
            ].map((card) => (
              <Grid key={card.title} size={{ xs: 12, sm: 6, md: 4 }}>
                <Box sx={{
                  p: 3, height: "100%",
                  border: `1px solid ${BORDER}`, borderRadius: 2,
                  background: "rgba(255,255,255,0.02)",
                  transition: "border-color 0.2s",
                  "&:hover": { borderColor: "rgba(52,168,83,0.4)", background: "rgba(52,168,83,0.03)" },
                }}>
                  <Typography sx={{ fontSize: 28, mb: 1.5 }}>{card.icon}</Typography>
                  <Typography sx={{ fontWeight: 700, fontSize: 15, mb: 1, color: "text.primary" }}>{card.title}</Typography>
                  <Typography sx={{ color: "rgba(255,255,255,0.45)", fontSize: 13.5, lineHeight: 1.65 }}>{card.body}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>

          {/* Azure Reference Architecture Diagram */}
          <Box sx={{ borderRadius: 2, border: `1px solid rgba(52,168,83,0.25)`, background: "rgba(52,168,83,0.04)", p: { xs: 2, md: 4 } }}>
            <Typography sx={{ fontWeight: 700, fontSize: 16, mb: 3, color: "#34A853", textAlign: "center" }}>
              Azure Reference Architecture (private deployment)
            </Typography>
            <Box sx={{ overflowX: "auto" }}>
              <svg viewBox="0 0 860 340" width="100%" style={{ display: "block", maxWidth: 860, margin: "0 auto" }} aria-label="Azure private deployment architecture diagram">
                <defs>
                  <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L8,3 z" fill="rgba(255,255,255,0.35)" />
                  </marker>
                  <marker id="arr-green" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L8,3 z" fill="#34A853" />
                  </marker>
                </defs>

                {/* ── User / Corp Network ── */}
                <rect x="10" y="120" width="130" height="100" rx="10" fill="rgba(66,133,244,0.08)" stroke="rgba(66,133,244,0.4)" strokeWidth="1.5" />
                <text x="75" y="145" textAnchor="middle" fill="#4285F4" fontSize="11" fontWeight="700">CORP NETWORK</text>
                <rect x="26" y="155" width="98" height="28" rx="6" fill="rgba(66,133,244,0.15)" stroke="rgba(66,133,244,0.3)" strokeWidth="1" />
                <text x="75" y="174" textAnchor="middle" fill="rgba(255,255,255,0.8)" fontSize="10">👤 Analyst / User</text>
                <rect x="26" y="189" width="98" height="22" rx="5" fill="rgba(66,133,244,0.1)" stroke="rgba(66,133,244,0.25)" strokeWidth="1" />
                <text x="75" y="204" textAnchor="middle" fill="rgba(255,255,255,0.55)" fontSize="9">VPN / ExpressRoute</text>

                {/* arrow corp → vnet */}
                <line x1="140" y1="170" x2="185" y2="170" stroke="rgba(255,255,255,0.35)" strokeWidth="1.5" markerEnd="url(#arr)" strokeDasharray="4 3" />

                {/* ── Azure VNet boundary ── */}
                <rect x="185" y="20" width="490" height="300" rx="14" fill="rgba(0,180,255,0.03)" stroke="rgba(0,180,255,0.2)" strokeWidth="1.5" strokeDasharray="6 4" />
                <text x="430" y="42" textAnchor="middle" fill="rgba(0,180,255,0.5)" fontSize="11" fontWeight="600">Azure Virtual Network (private subnet — no public IP)</text>

                {/* ── App Gateway / Private Endpoint ── */}
                <rect x="205" y="120" width="130" height="100" rx="10" fill="rgba(251,188,4,0.06)" stroke="rgba(251,188,4,0.35)" strokeWidth="1.5" />
                <text x="270" y="143" textAnchor="middle" fill="#FBBC04" fontSize="10" fontWeight="700">APP GATEWAY</text>
                <text x="270" y="158" textAnchor="middle" fill="rgba(255,255,255,0.45)" fontSize="9">Private Endpoint</text>
                <rect x="220" y="165" width="100" height="22" rx="5" fill="rgba(251,188,4,0.1)" stroke="rgba(251,188,4,0.25)" strokeWidth="1" />
                <text x="270" y="180" textAnchor="middle" fill="rgba(255,255,255,0.7)" fontSize="9">WAF + TLS Termination</text>
                <rect x="220" y="192" width="100" height="20" rx="5" fill="rgba(251,188,4,0.07)" stroke="rgba(251,188,4,0.2)" strokeWidth="1" />
                <text x="270" y="205" textAnchor="middle" fill="rgba(255,255,255,0.5)" fontSize="9">No public listener</text>

                {/* arrow gateway → app service */}
                <line x1="335" y1="170" x2="375" y2="170" stroke="#34A853" strokeWidth="1.5" markerEnd="url(#arr-green)" />

                {/* ── Aegis App Service ── */}
                <rect x="375" y="55" width="140" height="230" rx="10" fill="rgba(52,168,83,0.07)" stroke="rgba(52,168,83,0.45)" strokeWidth="2" />
                <text x="445" y="78" textAnchor="middle" fill="#34A853" fontSize="11" fontWeight="700">AEGIS</text>
                <text x="445" y="92" textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="9">Azure App Service</text>
                <rect x="388" y="100" width="114" height="22" rx="5" fill="rgba(52,168,83,0.12)" stroke="rgba(52,168,83,0.3)" strokeWidth="1" />
                <text x="445" y="115" textAnchor="middle" fill="rgba(255,255,255,0.75)" fontSize="9">⚡ FastAPI Backend</text>
                <rect x="388" y="128" width="114" height="22" rx="5" fill="rgba(52,168,83,0.12)" stroke="rgba(52,168,83,0.3)" strokeWidth="1" />
                <text x="445" y="143" textAnchor="middle" fill="rgba(255,255,255,0.75)" fontSize="9">⚛ React Frontend</text>
                <rect x="388" y="156" width="114" height="22" rx="5" fill="rgba(52,168,83,0.12)" stroke="rgba(52,168,83,0.3)" strokeWidth="1" />
                <text x="445" y="171" textAnchor="middle" fill="rgba(255,255,255,0.75)" fontSize="9">🗄 SQLite / Azure SQL</text>
                <rect x="388" y="184" width="114" height="22" rx="5" fill="rgba(52,168,83,0.12)" stroke="rgba(52,168,83,0.3)" strokeWidth="1" />
                <text x="445" y="199" textAnchor="middle" fill="rgba(255,255,255,0.75)" fontSize="9">🤖 AI Agent Runner</text>
                <rect x="388" y="212" width="114" height="22" rx="5" fill="rgba(52,168,83,0.12)" stroke="rgba(52,168,83,0.3)" strokeWidth="1" />
                <text x="445" y="227" textAnchor="middle" fill="rgba(255,255,255,0.75)" fontSize="9">🔐 Entra ID Auth</text>
                <rect x="388" y="240" width="114" height="22" rx="5" fill="rgba(52,168,83,0.12)" stroke="rgba(52,168,83,0.3)" strokeWidth="1" />
                <text x="445" y="255" textAnchor="middle" fill="rgba(255,255,255,0.75)" fontSize="9">📊 Scanner Connectors</text>

                {/* arrow app service → AI */}
                <line x1="515" y1="130" x2="555" y2="130" stroke="rgba(255,255,255,0.35)" strokeWidth="1.5" markerEnd="url(#arr)" strokeDasharray="4 3" />

                {/* ── Azure OpenAI (private endpoint) ── */}
                <rect x="555" y="60" width="105" height="60" rx="10" fill="rgba(124,58,237,0.08)" stroke="rgba(124,58,237,0.4)" strokeWidth="1.5" />
                <text x="607" y="82" textAnchor="middle" fill={PURPLE} fontSize="10" fontWeight="700">AZURE OpenAI</text>
                <text x="607" y="97" textAnchor="middle" fill="rgba(255,255,255,0.45)" fontSize="9">Private Endpoint</text>
                <text x="607" y="112" textAnchor="middle" fill="rgba(255,255,255,0.35)" fontSize="8">GPT-4o / Claude</text>

                {/* arrow app service → storage */}
                <line x1="515" y1="200" x2="555" y2="200" stroke="rgba(255,255,255,0.35)" strokeWidth="1.5" markerEnd="url(#arr)" strokeDasharray="4 3" />

                {/* ── Key Vault ── */}
                <rect x="555" y="150" width="105" height="45" rx="10" fill="rgba(234,67,53,0.07)" stroke="rgba(234,67,53,0.3)" strokeWidth="1.5" />
                <text x="607" y="170" textAnchor="middle" fill="#EA4335" fontSize="10" fontWeight="700">KEY VAULT</text>
                <text x="607" y="186" textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="9">Secrets / Certs</text>

                {/* ── Storage ── */}
                <rect x="555" y="210" width="105" height="45" rx="10" fill="rgba(251,188,4,0.07)" stroke="rgba(251,188,4,0.3)" strokeWidth="1.5" />
                <text x="607" y="230" textAnchor="middle" fill="#FBBC04" fontSize="10" fontWeight="700">BLOB STORAGE</text>
                <text x="607" y="246" textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="9">Reports / Exports</text>

                {/* ── Monitor ── */}
                <rect x="555" y="270" width="105" height="38" rx="10" fill="rgba(0,180,255,0.07)" stroke="rgba(0,180,255,0.3)" strokeWidth="1.5" />
                <text x="607" y="288" textAnchor="middle" fill={CYAN} fontSize="10" fontWeight="700">AZURE MONITOR</text>
                <text x="607" y="302" textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="9">Logs / Alerts</text>

                {/* ── Entra ID (outside VNet) ── */}
                <rect x="690" y="120" width="115" height="60" rx="10" fill="rgba(66,133,244,0.07)" stroke="rgba(66,133,244,0.35)" strokeWidth="1.5" />
                <text x="748" y="142" textAnchor="middle" fill="#4285F4" fontSize="10" fontWeight="700">ENTRA ID</text>
                <text x="748" y="157" textAnchor="middle" fill="rgba(255,255,255,0.45)" fontSize="9">Identity / SSO</text>
                <text x="748" y="171" textAnchor="middle" fill="rgba(255,255,255,0.35)" fontSize="8">Multi-tenant auth</text>
                <line x1="660" y1="213" x2="690" y2="150" stroke="rgba(66,133,244,0.4)" strokeWidth="1.2" markerEnd="url(#arr)" strokeDasharray="4 3" />

                {/* legend */}
                <line x1="205" y1="328" x2="235" y2="328" stroke="#34A853" strokeWidth="1.5" />
                <text x="240" y="332" fill="rgba(255,255,255,0.45)" fontSize="9">Internal traffic (private)</text>
                <line x1="360" y1="328" x2="390" y2="328" stroke="rgba(255,255,255,0.35)" strokeWidth="1.5" strokeDasharray="4 3" />
                <text x="395" y="332" fill="rgba(255,255,255,0.45)" fontSize="9">Service-to-service (VNet)</text>
              </svg>
            </Box>
            <Typography sx={{ textAlign: "center", color: "rgba(255,255,255,0.3)", fontSize: 11, mt: 2 }}>
              All components run inside your Azure subscription with no public internet exposure. AWS, GCP, and on-prem topologies follow the same private-network pattern.
            </Typography>
          </Box>
        </Container>
      </Box>

      {/* ── FAQ ────────────────────────────────────────────────────────────── */}
      <Box id="faq" sx={{ py: { xs: 8, md: 12 }, background: "rgba(255,255,255,0.012)", borderTop: `1px solid ${BORDER}`, borderBottom: `1px solid ${BORDER}` }}>
        <Container maxWidth="md">
          <Box sx={{ textAlign: "center", mb: 8 }}>
            <Chip label="FAQ" size="small" sx={{ mb: 2.5, background: `rgba(124,58,237,0.1)`, border: `1px solid rgba(124,58,237,0.25)`, color: PURPLE, fontWeight: 600, fontSize: 12 }} />
            <Typography sx={{ fontSize: { xs: 26, md: 38 }, fontWeight: 800, letterSpacing: "-0.02em" }}>
              Frequently asked questions
            </Typography>
          </Box>

          <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
            {FAQS.map(({ q, a }) => (
              <Accordion
                key={q}
                expanded={faqOpen === q}
                onChange={(_, open) => setFaqOpen(open ? q : false)}
                sx={{
                  background: CARD_BG, border: `1px solid ${BORDER}`,
                  borderRadius: "12px !important", boxShadow: "none", color: "white",
                  "&:before": { display: "none" },
                  "&.Mui-expanded": { border: `1px solid rgba(0,212,255,0.25)`, background: "rgba(0,212,255,0.04)" },
                }}
              >
                <AccordionSummary
                  expandIcon={<ExpandMore sx={{ color: "rgba(255,255,255,0.4)" }} />}
                  sx={{ px: 3, "& .MuiAccordionSummary-content": { my: 2 } }}
                >
                  <Typography sx={{ fontWeight: 600, fontSize: 15 }}>{q}</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ px: 3, pb: 3, pt: 0 }}>
                  <Typography sx={{ color: "rgba(255,255,255,0.48)", fontSize: 14, lineHeight: 1.78 }}>{a}</Typography>
                </AccordionDetails>
              </Accordion>
            ))}
          </Box>
        </Container>
      </Box>

      {/* ── CTA banner ─────────────────────────────────────────────────────── */}
      <Box sx={{ py: { xs: 10, md: 16 }, position: "relative", overflow: "hidden" }}>
        <Box sx={{ position: "absolute", inset: 0,
          background: `radial-gradient(ellipse at 50% 50%, rgba(0,212,255,0.1) 0%, rgba(124,58,237,0.07) 40%, transparent 70%)`,
          pointerEvents: "none" }} />
        <Container maxWidth="sm" sx={{ textAlign: "center", position: "relative" }}>
          <Typography sx={{ fontSize: { xs: 32, md: 46 }, fontWeight: 800, letterSpacing: "-0.025em", lineHeight: 1.1, mb: 2 }}>
            Ready to see your{" "}
            <Box component="span" sx={{ background: `linear-gradient(135deg, ${CYAN}, ${PURPLE})`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
              real risk?
            </Box>
          </Typography>
          <Typography sx={{ color: "rgba(255,255,255,0.42)", mb: 5, fontSize: 17, lineHeight: 1.65 }}>
            Sign in with your Microsoft work account and start your first AI security scan in under two minutes.
          </Typography>
          <Button onClick={signIn} variant="contained" size="large" endIcon={<ArrowForward />} sx={{
            background: CYAN, color: "#060810", fontWeight: 700, fontSize: 16,
            textTransform: "none", px: 5, py: 1.75, borderRadius: 2,
            boxShadow: "0 0 40px rgba(0,212,255,0.28)",
            "&:hover": { background: "#00B8E0", transform: "translateY(-2px)", boxShadow: "0 0 60px rgba(0,212,255,0.4)" },
            transition: "all 0.25s",
          }}>
            Sign In to Aegis
          </Button>
          <Typography sx={{ mt: 2.5, fontSize: 12, color: "rgba(255,255,255,0.2)" }}>
            Microsoft Entra ID · Work accounts only · No password required
          </Typography>
        </Container>
      </Box>

      {/* ── Footer ─────────────────────────────────────────────────────────── */}
      <Box sx={{ borderTop: `1px solid ${BORDER}`, background: "rgba(0,0,0,0.3)", pt: 10, pb: 5 }}>
        <Container maxWidth="lg">
          <Grid container spacing={6} sx={{ mb: 8 }}>
            {/* Brand column */}
            <Grid size={{ xs: 12, md: 4 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2.5 }}>
                <img src={`${process.env.PUBLIC_URL}/aegis-logo.svg`} alt="Aegis" style={{ width: 28, height: 28, opacity: 0.8 }} />
                <Typography sx={{ fontWeight: 800, fontSize: 18, letterSpacing: "-0.02em" }}>
                  <Box component="span" sx={{ color: "#4285F4" }}>Aeg</Box>
                  <Box component="span" sx={{ color: CYAN }}>is</Box>
                  <Box component="span" sx={{ color: "rgba(255,255,255,0.3)", fontWeight: 400, fontSize: 13, ml: 0.5 }}>AI</Box>
                </Typography>
              </Box>
              <Typography sx={{ fontSize: 14, color: "rgba(255,255,255,0.33)", lineHeight: 1.72, maxWidth: 260 }}>
                AI-powered security platform combining code review, VAPT, threat modeling, and autonomous security agents.
              </Typography>
              <Box sx={{ display: "flex", gap: 1, mt: 3, flexWrap: "wrap" }}>
                {["NIST CSF", "ISO 27001", "PCI DSS"].map((badge) => (
                  <Chip key={badge} label={badge} size="small" sx={{
                    background: "rgba(255,255,255,0.04)", border: `1px solid ${BORDER}`,
                    color: "rgba(255,255,255,0.28)", fontSize: 10, fontWeight: 600,
                  }} />
                ))}
              </Box>
            </Grid>

            {/* Link columns */}
            {Object.entries(FOOTER_LINKS).map(([group, links]) => (
              <Grid key={group} size={{ xs: 6, sm: 3, md: 2 }}>
                <Typography sx={{ fontSize: 12, fontWeight: 700, color: "rgba(255,255,255,0.5)", mb: 2.5, textTransform: "uppercase", letterSpacing: 1 }}>
                  {group}
                </Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                  {links.map((link) => (
                    <Typography key={link} sx={{
                      fontSize: 14, color: "rgba(255,255,255,0.32)", cursor: "pointer",
                      "&:hover": { color: "rgba(255,255,255,0.65)" }, transition: "color 0.2s",
                    }}>
                      {link}
                    </Typography>
                  ))}
                </Box>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ borderTop: `1px solid ${BORDER}`, pt: 4, display: "flex", flexDirection: { xs: "column", sm: "row" }, justifyContent: "space-between", alignItems: { sm: "center" }, gap: 2 }}>
            <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.2)" }}>
              © {new Date().getFullYear()} NexGenCyberAI · All rights reserved.
            </Typography>
            <Box sx={{ display: "flex", gap: 3 }}>
              {["Privacy", "Terms", "Security", "Contact"].map((item) => (
                <Typography key={item} sx={{
                  fontSize: 13, color: "rgba(255,255,255,0.22)", cursor: "pointer",
                  "&:hover": { color: "rgba(255,255,255,0.5)" }, transition: "color 0.2s",
                }}>
                  {item}
                </Typography>
              ))}
            </Box>
          </Box>
        </Container>
      </Box>
    </Box>
  );
}
