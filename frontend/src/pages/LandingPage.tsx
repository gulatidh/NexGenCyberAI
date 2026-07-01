import React, { useState, useEffect } from "react";
import { Box, Container, Typography, Button, Grid, Chip } from "@mui/material";
import { useMsal } from "@azure/msal-react";
import { loginRequest } from "../auth/msalConfig";
import {
  Code, Assessment, AccountTree, TrendingUp, VerifiedUser, SmartToy,
  ArrowForward, Shield, BugReport, Hub, Lock, CheckCircle,
  Menu as MenuIcon, Close as CloseIcon,
} from "@mui/icons-material";

const CYAN = "#00D4FF";
const PURPLE = "#7C3AED";
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
    color: "#F59E0B",
    title: "Multi-Scanner Assessments",
    subtitle: "SAST · DAST · Network · Dependencies",
    desc: "Launch Semgrep, CodeQL, SonarQube, OWASP ZAP, Nmap, OpenVAS, Trivy, Gitleaks, and TruffleHog from a single dashboard. All findings land in one normalised schema.",
    bullets: ["9 scanner integrations", "GitHub Actions dispatch", "Unified finding schema"],
  },
  {
    icon: <AccountTree sx={{ fontSize: 28 }} />,
    color: PURPLE,
    title: "AI Threat Modeling",
    subtitle: "STRIDE · MITRE ATT&CK",
    desc: "Describe your system and Aegis generates comprehensive threat models in minutes. Threats are automatically mapped to STRIDE categories, MITRE ATT&CK techniques, and your compliance frameworks.",
    bullets: ["STRIDE taxonomy", "Attack path analysis", "Framework auto-mapping"],
  },
  {
    icon: <TrendingUp sx={{ fontSize: 28 }} />,
    color: "#10B981",
    title: "Risk Intelligence",
    subtitle: "Continuous scoring",
    desc: "A live risk score built from aggregated findings, asset criticality, and business context. Prioritise remediation by real-world impact — not raw CVSS — so your team fixes what actually matters.",
    bullets: ["Impact-based prioritisation", "Risk trend tracking", "Executive dashboards"],
  },
  {
    icon: <VerifiedUser sx={{ fontSize: 28 }} />,
    color: "#F472B6",
    title: "Compliance Frameworks",
    subtitle: "NIST · SOC 2 · ISO 27001",
    desc: "Every finding is automatically mapped to one or more compliance controls. Track framework coverage, identify gaps, and generate audit-ready reports with a single click.",
    bullets: ["Multi-framework mapping", "Gap analysis", "Audit-ready exports"],
  },
  {
    icon: <SmartToy sx={{ fontSize: 28 }} />,
    color: "#FB923C",
    title: "Security Agents",
    subtitle: "Autonomous AI workflows",
    desc: "Deploy AI agents that investigate alerts, correlate findings across the estate, answer security questions in natural language, and run scheduled security missions without manual intervention.",
    bullets: ["Natural language Q&A", "Scheduled missions", "Cross-finding correlation"],
  },
];

const STATS = [
  { value: "9+", label: "Scanner integrations" },
  { value: "4-phase", label: "AI review pipeline" },
  { value: "126", label: "Findings on PyGoat" },
  { value: "Real-time", label: "Risk scoring" },
];

const SCANNERS = [
  "Semgrep", "CodeQL", "SonarQube", "OWASP ZAP",
  "Nmap", "OpenVAS", "Trivy", "Gitleaks", "TruffleHog",
];

const STEPS = [
  { n: "01", title: "Connect your repo", desc: "Paste a GitHub URL or upload a zip archive. No git binary, no agents, no configuration required." },
  { n: "02", title: "AI triage & chunking", desc: "Aegis triages files by security risk, chunks code to function-level granularity, and prioritises the highest-risk paths." },
  { n: "03", title: "Parallel LLM review", desc: "Each chunk is reviewed in parallel for real vulnerabilities — CWE-mapped, with proof-of-exploit and concrete remediation." },
  { n: "04", title: "Self-critique & taint tracing", desc: "A second LLM pass eliminates false positives. Cross-file taint flows are traced to surface injection chains spanning modules." },
];

export default function LandingPage() {
  const { instance } = useMsal();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

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
        background: scrolled ? "rgba(6,8,16,0.88)" : "transparent",
        borderBottom: scrolled ? `1px solid ${BORDER}` : "none",
        transition: "all 0.3s",
      }}>
        <Container maxWidth="lg">
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", py: 2 }}>

            {/* Logo */}
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <img src={`${process.env.PUBLIC_URL}/aegis-logo.svg`} alt="Aegis" style={{ width: 32, height: 32 }} />
              <Typography sx={{ fontWeight: 800, fontSize: 20, letterSpacing: "-0.02em" }}>
                <Box component="span" sx={{ color: "#4285F4" }}>Aeg</Box>
                <Box component="span" sx={{ color: CYAN }}>is</Box>
                <Box component="span" sx={{ color: "rgba(255,255,255,0.45)", fontWeight: 400, fontSize: 14, ml: 0.75 }}>AI</Box>
              </Typography>
            </Box>

            {/* Desktop nav links */}
            <Box sx={{ display: { xs: "none", md: "flex" }, alignItems: "center", gap: 4 }}>
              {["Features", "Capabilities", "Integrations"].map((item) => (
                <Typography key={item} component="a" href={`#${item.toLowerCase()}`} sx={{
                  color: "rgba(255,255,255,0.5)", fontSize: 14, textDecoration: "none", cursor: "pointer",
                  "&:hover": { color: "white" }, transition: "color 0.2s",
                }}>
                  {item}
                </Typography>
              ))}
            </Box>

            {/* CTAs */}
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

        {/* Mobile dropdown */}
        {mobileOpen && (
          <Box sx={{ background: "rgba(6,8,16,0.97)", backdropFilter: "blur(16px)", py: 2, borderBottom: `1px solid ${BORDER}` }}>
            <Container>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
                {["Features", "Capabilities", "Integrations"].map((item) => (
                  <Typography key={item} sx={{ color: "rgba(255,255,255,0.7)", fontSize: 15 }}>{item}</Typography>
                ))}
              </Box>
            </Container>
          </Box>
        )}
      </Box>

      {/* ── Hero ───────────────────────────────────────────────────────────── */}
      <Box sx={{ position: "relative", pt: { xs: 16, md: 22 }, pb: { xs: 10, md: 14 }, overflow: "hidden" }}>
        <Box sx={{ position: "absolute", top: "10%", left: "50%", transform: "translateX(-50%)",
          width: 800, height: 500, borderRadius: "50%",
          background: `radial-gradient(ellipse, rgba(0,212,255,0.12) 0%, rgba(124,58,237,0.08) 40%, transparent 70%)`,
          pointerEvents: "none" }} />
        <Box sx={{ position: "absolute", top: "5%", right: "-10%", width: 400, height: 400, borderRadius: "50%",
          background: `radial-gradient(ellipse, rgba(124,58,237,0.14) 0%, transparent 65%)`,
          pointerEvents: "none" }} />

        <Container maxWidth="lg" sx={{ position: "relative", textAlign: "center" }}>
          <Chip label="AI-Powered Security Platform" size="small" sx={{
            mb: 3, background: "rgba(0,212,255,0.08)", border: `1px solid rgba(0,212,255,0.25)`,
            color: CYAN, fontWeight: 600, fontSize: 12, letterSpacing: 0.5,
          }} />

          <Typography sx={{ fontSize: { xs: 38, sm: 52, md: 68 }, fontWeight: 800, lineHeight: 1.08, letterSpacing: "-0.03em", mb: 3 }}>
            Secure everything{" "}
            <Box component="span" sx={{
              background: `linear-gradient(135deg, ${CYAN} 0%, ${PURPLE} 100%)`,
              WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
            }}>
              you build,
            </Box>
            <br />ship, and run.
          </Typography>

          <Typography sx={{ fontSize: { xs: 16, md: 19 }, color: "rgba(255,255,255,0.5)", maxWidth: 620, mx: "auto", lineHeight: 1.65, mb: 5 }}>
            Aegis combines AI code review, threat modeling, multi-scanner assessments, and autonomous security agents into one platform — so your team sees risk clearly and fixes what matters.
          </Typography>

          <Box sx={{ display: "flex", flexDirection: { xs: "column", sm: "row" }, gap: 2, justifyContent: "center", alignItems: "center" }}>
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

          {/* Trust badges */}
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 3, justifyContent: "center", mt: 6 }}>
            {[
              { icon: <Shield sx={{ fontSize: 14 }} />, text: "SAST · DAST · Network" },
              { icon: <Lock sx={{ fontSize: 14 }} />, text: "NIST · SOC 2 · ISO 27001" },
              { icon: <BugReport sx={{ fontSize: 14 }} />, text: "126 findings on PyGoat" },
              { icon: <Hub sx={{ fontSize: 14 }} />, text: "9+ scanner integrations" },
            ].map(({ icon, text }) => (
              <Box key={text} sx={{ display: "flex", alignItems: "center", gap: 0.75, color: "rgba(255,255,255,0.35)" }}>
                {icon}
                <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.35)" }}>{text}</Typography>
              </Box>
            ))}
          </Box>
        </Container>
      </Box>

      {/* ── Stats bar ──────────────────────────────────────────────────────── */}
      <Box sx={{ borderTop: `1px solid ${BORDER}`, borderBottom: `1px solid ${BORDER}`, background: "rgba(255,255,255,0.02)", py: 4 }}>
        <Container maxWidth="lg">
          <Grid container spacing={2} sx={{ justifyContent: "center" }}>
            {STATS.map(({ value, label }) => (
              <Grid key={label} size={{ xs: 6, sm: 3 }} sx={{ textAlign: "center" }}>
                <Typography sx={{
                  fontSize: { xs: 28, md: 36 }, fontWeight: 800,
                  background: `linear-gradient(135deg, ${CYAN}, ${PURPLE})`,
                  WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
                }}>
                  {value}
                </Typography>
                <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.4)", mt: 0.5 }}>{label}</Typography>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>

      {/* ── Features grid ──────────────────────────────────────────────────── */}
      <Box id="features" sx={{ py: { xs: 10, md: 16 } }}>
        <Container maxWidth="lg">
          <Box sx={{ textAlign: "center", mb: 8 }}>
            <Typography sx={{ fontSize: { xs: 28, md: 40 }, fontWeight: 800, letterSpacing: "-0.02em", mb: 2 }}>
              Everything your security team needs
            </Typography>
            <Typography sx={{ color: "rgba(255,255,255,0.45)", fontSize: 17, maxWidth: 520, mx: "auto" }}>
              Built on real scanners and large language models — not just dashboards.
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
                    border: `1px solid rgba(255,255,255,0.13)`,
                    transform: "translateY(-3px)",
                    boxShadow: "0 16px 48px rgba(0,0,0,0.4)",
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
                    mb: 1.5, background: `${f.color}12`, color: f.color,
                    fontSize: 11, fontWeight: 600, letterSpacing: 0.3, border: `1px solid ${f.color}25`,
                  }} />

                  <Typography sx={{ fontWeight: 700, fontSize: 18, mb: 1.5, letterSpacing: "-0.01em" }}>
                    {f.title}
                  </Typography>
                  <Typography sx={{ color: "rgba(255,255,255,0.48)", fontSize: 14, lineHeight: 1.65, mb: 2.5 }}>
                    {f.desc}
                  </Typography>

                  <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
                    {f.bullets.map((b) => (
                      <Box key={b} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <CheckCircle sx={{ fontSize: 14, color: f.color, flexShrink: 0 }} />
                        <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.5)" }}>{b}</Typography>
                      </Box>
                    ))}
                  </Box>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>

      {/* ── How it works ───────────────────────────────────────────────────── */}
      <Box id="capabilities" sx={{ py: { xs: 8, md: 12 }, background: "rgba(255,255,255,0.015)", borderTop: `1px solid ${BORDER}`, borderBottom: `1px solid ${BORDER}` }}>
        <Container maxWidth="md">
          <Typography sx={{ textAlign: "center", fontSize: { xs: 24, md: 34 }, fontWeight: 800, letterSpacing: "-0.02em", mb: 2 }}>
            From repo to findings in minutes
          </Typography>
          <Typography sx={{ textAlign: "center", color: "rgba(255,255,255,0.4)", mb: 8, fontSize: 16 }}>
            The AI Code Review pipeline runs automatically in the cloud
          </Typography>

          <Box sx={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {STEPS.map(({ n, title, desc }) => (
              <Box key={n} sx={{ display: "flex", gap: 3 }}>
                <Box sx={{
                  flexShrink: 0, width: 48, height: 48, borderRadius: "50%",
                  background: `linear-gradient(135deg, rgba(0,212,255,0.15), rgba(124,58,237,0.15))`,
                  border: `1px solid rgba(0,212,255,0.35)`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  color: CYAN, fontSize: 13, fontWeight: 800,
                }}>
                  {n}
                </Box>
                <Box sx={{ pt: 0.5 }}>
                  <Typography sx={{ fontWeight: 700, fontSize: 17, mb: 0.75 }}>{title}</Typography>
                  <Typography sx={{ color: "rgba(255,255,255,0.48)", fontSize: 14, lineHeight: 1.65 }}>{desc}</Typography>
                </Box>
              </Box>
            ))}
          </Box>
        </Container>
      </Box>

      {/* ── Integrations ───────────────────────────────────────────────────── */}
      <Box id="integrations" sx={{ py: { xs: 6, md: 8 } }}>
        <Container maxWidth="lg">
          <Typography sx={{ textAlign: "center", color: "rgba(255,255,255,0.28)", fontSize: 12, letterSpacing: 2, textTransform: "uppercase", mb: 4, fontWeight: 600 }}>
            Scanner integrations
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1.5, justifyContent: "center" }}>
            {SCANNERS.map((name) => (
              <Box key={name} sx={{
                px: 2.5, py: 1, borderRadius: 20, fontSize: 13, fontWeight: 500,
                background: CARD_BG, border: `1px solid ${BORDER}`, color: "rgba(255,255,255,0.5)",
                "&:hover": { color: "white", border: `1px solid rgba(255,255,255,0.15)` },
                transition: "all 0.2s", cursor: "default",
              }}>
                {name}
              </Box>
            ))}
          </Box>
        </Container>
      </Box>

      {/* ── CTA ────────────────────────────────────────────────────────────── */}
      <Box sx={{ py: { xs: 10, md: 14 }, position: "relative", overflow: "hidden" }}>
        <Box sx={{ position: "absolute", inset: 0,
          background: `radial-gradient(ellipse at 50% 50%, rgba(0,212,255,0.09) 0%, rgba(124,58,237,0.07) 40%, transparent 70%)`,
          pointerEvents: "none" }} />
        <Container maxWidth="sm" sx={{ textAlign: "center", position: "relative" }}>
          <Typography sx={{ fontSize: { xs: 30, md: 44 }, fontWeight: 800, letterSpacing: "-0.025em", lineHeight: 1.1, mb: 2 }}>
            Ready to see your{" "}
            <Box component="span" sx={{
              background: `linear-gradient(135deg, ${CYAN}, ${PURPLE})`,
              WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
            }}>
              real risk?
            </Box>
          </Typography>
          <Typography sx={{ color: "rgba(255,255,255,0.45)", mb: 4, fontSize: 16, lineHeight: 1.6 }}>
            Sign in with your Microsoft account and start your first AI code review in under two minutes.
          </Typography>
          <Button onClick={signIn} variant="contained" size="large" endIcon={<ArrowForward />} sx={{
            background: CYAN, color: "#060810", fontWeight: 700, fontSize: 16,
            textTransform: "none", px: 5, py: 1.75, borderRadius: 2,
            boxShadow: "0 0 40px rgba(0,212,255,0.3)",
            "&:hover": { background: "#00B8E0", transform: "translateY(-2px)", boxShadow: "0 0 60px rgba(0,212,255,0.4)" },
            transition: "all 0.25s",
          }}>
            Sign In to Aegis
          </Button>
          <Typography sx={{ mt: 2, fontSize: 12, color: "rgba(255,255,255,0.22)" }}>
            Microsoft Entra ID authentication · No password required
          </Typography>
        </Container>
      </Box>

      {/* ── Footer ─────────────────────────────────────────────────────────── */}
      <Box sx={{ borderTop: `1px solid ${BORDER}`, py: 4, background: "rgba(0,0,0,0.2)" }}>
        <Container maxWidth="lg">
          <Box sx={{ display: "flex", flexDirection: { xs: "column", sm: "row" }, justifyContent: "space-between", alignItems: { xs: "flex-start", sm: "center" }, gap: 2 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <img src={`${process.env.PUBLIC_URL}/aegis-logo.svg`} alt="Aegis" style={{ width: 22, height: 22, opacity: 0.6 }} />
              <Typography sx={{ fontSize: 14, color: "rgba(255,255,255,0.3)", fontWeight: 500 }}>
                Aegis AI · NexGenCyberAI
              </Typography>
            </Box>
            <Box sx={{ display: "flex", gap: 3 }}>
              {["Privacy", "Terms", "Contact"].map((item) => (
                <Typography key={item} sx={{ fontSize: 13, color: "rgba(255,255,255,0.28)", cursor: "pointer", "&:hover": { color: "rgba(255,255,255,0.6)" } }}>
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
