import React, { useState, useEffect, useRef } from "react";
import {
  Box, Container, Typography, Button, Grid, Chip, IconButton,
  Accordion, AccordionSummary, AccordionDetails, Tab, Tabs,
} from "@mui/material";
import {
  Code, Assessment, AccountTree, TrendingUp, VerifiedUser, SmartToy,
  ArrowForward, Shield, Hub, Lock, CheckCircle, Radar,
  Menu as MenuIcon, Close as CloseIcon, ExpandMore,
  AltRoute, QuestionAnswer, Analytics, Webhook, VpnKey,
  Gavel, Campaign, AutoAwesome, Terminal, Person, Groups,
  BusinessCenter,
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
    desc: "Describe your system and Owlet generates comprehensive threat models in minutes. Threats are mapped to STRIDE categories, MITRE ATT&CK techniques, and compliance controls — with attacker profiles and detection gap analysis.",
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

const PRODUCT_TOUR_TABS = [
  "Dashboard",
  "Scan Progress",
  "Compliance Heatmap",
  "AI Playbook",
  "Account Comparison",
] as const;

const PRODUCT_TOUR_SCREENS: React.FC<{ color: string }>[] = [
  // 1 — Dashboard
  ({ color }) => (
    <Box sx={{ p: 2.5 }}>
      <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 1, mb: 2 }}>Security Dashboard</Typography>
      <Box sx={{ display: "flex", gap: 1.5, mb: 2, flexWrap: "wrap" }}>
        {[
          { label: "Critical", val: "12", color: DANGER },
          { label: "High", val: "47", color: "#F97316" },
          { label: "Risk Score", val: "73", color: AMBER },
          { label: "Compliance", val: "68%", color: "#4285F4" },
        ].map((m) => (
          <Box key={m.label} sx={{ flex: 1, minWidth: 80, p: 1.5, bgcolor: "rgba(0,0,0,0.25)", borderRadius: 2, border: `1px solid rgba(255,255,255,0.07)` }}>
            <Typography sx={{ fontSize: 9, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 0.7, mb: 0.25 }}>{m.label}</Typography>
            <Typography sx={{ fontSize: 22, fontWeight: 800, color: m.color, lineHeight: 1 }}>{m.val}</Typography>
          </Box>
        ))}
      </Box>
      <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.28)", textTransform: "uppercase", letterSpacing: 0.8, mb: 1 }}>Attack path count: 3 chains detected</Typography>
      {[
        { sev: "CRIT", title: "SQL Injection in auth endpoint", file: "api/auth.py:127", color: DANGER },
        { sev: "HIGH", title: "Reflected XSS in search param", file: "frontend/search.js:48", color: "#F97316" },
        { sev: "HIGH", title: "Hardcoded API key in config", file: "config/settings.py:12", color: "#F97316" },
      ].map((f, i) => (
        <Box key={i} sx={{ mb: 0.75, p: 1, bgcolor: `${f.color}08`, border: `1px solid ${f.color}20`, borderRadius: 1.5 }}>
          <Box sx={{ display: "flex", gap: 1, alignItems: "center", mb: 0.25 }}>
            <Chip label={f.sev} size="small" sx={{ bgcolor: `${f.color}25`, color: f.color, fontSize: 9, height: 15, "& .MuiChip-label": { px: 0.75 } }} />
            <Typography sx={{ fontSize: 11, color: "rgba(255,255,255,0.7)", fontWeight: 500, flex: 1 }}>{f.title}</Typography>
          </Box>
          <Typography sx={{ fontSize: 9, color: "rgba(255,255,255,0.28)", fontFamily: "monospace" }}>{f.file}</Typography>
        </Box>
      ))}
    </Box>
  ),
  // 2 — Scan + Live Progress
  ({ color }) => (
    <Box sx={{ p: 2.5 }}>
      <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 1, mb: 2 }}>Live Scan Progress</Typography>
      <Box sx={{ mb: 2, p: 1.75, bgcolor: "rgba(0,0,0,0.3)", borderRadius: 2, border: `1px solid rgba(255,255,255,0.07)`, fontFamily: "monospace" }}>
        {[
          { t: "$ aegis scan start --type ai_code_review --repo github.com/org/api", c: CYAN },
          { t: "", c: "" },
          { t: "[1/4] Triaging 847 files by risk score...", c: "rgba(255,255,255,0.55)" },
          { t: "[2/4] Reviewing 127 high-risk chunks with LLM...", c: "rgba(255,255,255,0.55)" },
          { t: "[3/4] Self-critique pass — pruning false positives...", c: AMBER },
          { t: "[4/4] Cross-file taint tracing (SQLi → XSS paths)...", c: AMBER },
          { t: "", c: "" },
          { t: "✅  127 findings · 12 critical · 34 high · AI enriched", c: GREEN },
          { t: "📋  Registers populated — MITRE ATT&CK mapped", c: GREEN },
        ].map((ln, i) => (
          <Typography key={i} sx={{ fontSize: 11, lineHeight: 1.7, color: ln.c || "transparent", fontFamily: "monospace" }}>
            {ln.t || " "}
          </Typography>
        ))}
        <Box sx={{ display: "inline-block", width: 7, height: 13, bgcolor: CYAN, animation: "blink 1s step-end infinite", "@keyframes blink": { "0%,100%": { opacity: 1 }, "50%": { opacity: 0 } } }} />
      </Box>
      <Box sx={{ p: 1.5, bgcolor: `${CYAN}08`, border: `1px solid ${CYAN}25`, borderRadius: 1.5 }}>
        <Typography sx={{ fontSize: 11, color: `${CYAN}CC` }}>Threat Intel agent — mapping 127 findings to MITRE ATT&CK...</Typography>
      </Box>
    </Box>
  ),
  // 3 — Compliance Heatmap
  ({ color }) => (
    <Box sx={{ p: 2.5, overflowX: "auto" }}>
      <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 1, mb: 2 }}>Compliance Heatmap</Typography>
      {/* Header row */}
      <Box sx={{ display: "flex", mb: 1, gap: 0.5 }}>
        <Box sx={{ minWidth: 110 }} />
        {["NIST CSF", "ISO 27001", "PCI DSS", "GDPR"].map((fw) => (
          <Box key={fw} sx={{ flex: 1, textAlign: "center" }}>
            <Typography sx={{ fontSize: 9, color: "#82b1ff", fontWeight: 700, textTransform: "uppercase" }}>{fw}</Typography>
          </Box>
        ))}
      </Box>
      {[
        { domain: "Identity", rates: [82, 74, 55, 88] },
        { domain: "Cloud Security", rates: [78, 61, 44, 70] },
        { domain: "Data Protection", rates: [91, 83, 67, 95] },
        { domain: "Network", rates: [65, 52, 38, 60] },
        { domain: "Logging", rates: [45, 39, 28, 52] },
      ].map(({ domain, rates }) => (
        <Box key={domain} sx={{ display: "flex", gap: 0.5, mb: 0.75, alignItems: "center" }}>
          <Typography sx={{ minWidth: 110, fontSize: 10, color: "rgba(255,255,255,0.55)", fontWeight: 500 }}>{domain}</Typography>
          {rates.map((r, i) => {
            const bg = r >= 80 ? "rgba(52,168,83,0.25)" : r >= 40 ? "rgba(251,188,4,0.25)" : "rgba(234,67,53,0.25)";
            const tc = r >= 80 ? "#34A853" : r >= 40 ? "#FBBC04" : "#EA4335";
            return (
              <Box key={i} sx={{ flex: 1, height: 28, borderRadius: 0.75, bgcolor: bg, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Typography sx={{ fontSize: 11, fontWeight: 700, color: tc }}>{r}%</Typography>
              </Box>
            );
          })}
        </Box>
      ))}
      <Box sx={{ display: "flex", gap: 0.5, mt: 1.5, borderTop: "1px solid rgba(255,255,255,0.07)", pt: 1 }}>
        <Typography sx={{ minWidth: 110, fontSize: 9, color: "rgba(255,255,255,0.35)", fontWeight: 700, textTransform: "uppercase" }}>Overall</Typography>
        {[72, 62, 46, 73].map((s, i) => {
          const sc = s >= 80 ? "#34A853" : s >= 40 ? "#FBBC04" : "#EA4335";
          return (
            <Box key={i} sx={{ flex: 1, textAlign: "center" }}>
              <Chip label={`${s}%`} size="small" sx={{ bgcolor: `${sc}20`, color: sc, fontWeight: 700, fontSize: 10, height: 18 }} />
            </Box>
          );
        })}
      </Box>
    </Box>
  ),
  // 4 — AI Remediation Playbook
  ({ color }) => (
    <Box sx={{ p: 2.5 }}>
      <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 1, mb: 2 }}>AI Remediation Playbook</Typography>
      <Box sx={{ mb: 2, p: 1.5, bgcolor: `${DANGER}08`, border: `1px solid ${DANGER}25`, borderRadius: 1.5 }}>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center", mb: 0.5 }}>
          <Chip label="CRITICAL" size="small" sx={{ bgcolor: `${DANGER}25`, color: DANGER, fontSize: 9, height: 16, fontWeight: 700 }} />
          <Typography sx={{ fontSize: 12, fontWeight: 700, color: "rgba(255,255,255,0.85)" }}>SQL Injection in auth endpoint</Typography>
        </Box>
        <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.38)", fontFamily: "monospace" }}>api/auth.py:127 · CWE-89 · CVSS 9.8</Typography>
      </Box>
      <Box sx={{ p: 1.5, bgcolor: "rgba(251,188,4,0.06)", border: "1px solid rgba(251,188,4,0.25)", borderRadius: 1.5 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, mb: 1 }}>
          <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: AMBER, boxShadow: `0 0 6px ${AMBER}` }} />
          <Typography sx={{ fontSize: 10, color: AMBER, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.8 }}>AI Remediation Playbook</Typography>
        </Box>
        {[
          "1. Use parameterised queries: replace string interpolation with db.execute(sql, params)",
          "2. Add input validation layer before the ORM call",
          "3. Enable WAF rule for SQLi patterns at API Gateway",
          "4. Rotate DB credentials — assume compromise",
          "5. Add regression test with malicious payloads to CI pipeline",
        ].map((step, i) => (
          <Typography key={i} sx={{ fontSize: 10, color: "rgba(255,255,255,0.55)", lineHeight: 1.65, mb: 0.25 }}>{step}</Typography>
        ))}
        <Box sx={{ mt: 1, display: "flex", gap: 1 }}>
          <Chip label="NIST SI-10" size="small" sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontSize: 9, height: 16 }} />
          <Chip label="PCI DSS 6.3.1" size="small" sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontSize: 9, height: 16 }} />
        </Box>
      </Box>
    </Box>
  ),
  // 5 — Account Comparison
  ({ color }) => (
    <Box sx={{ p: 2.5 }}>
      <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 1, mb: 2 }}>Account Comparison</Typography>
      <Box sx={{ display: "flex", gap: 1, mb: 1.5, pb: 0.75, borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
        <Typography sx={{ flex: 2, fontSize: 9, color: "rgba(255,255,255,0.4)", fontWeight: 700 }}>CLIENT</Typography>
        {["CRIT", "HIGH", "MED", "RISKS", "COMP"].map((h) => (
          <Typography key={h} sx={{ flex: 1, fontSize: 9, color: "rgba(255,255,255,0.4)", fontWeight: 700, textAlign: "center" }}>{h}</Typography>
        ))}
      </Box>
      {[
        { name: "Acme Corp", crit: 12, high: 47, med: 93, risks: 8, comp: "68%", compC: AMBER, border: DANGER },
        { name: "TechStart Ltd", crit: 3, high: 18, med: 41, risks: 3, comp: "79%", compC: AMBER, border: "transparent" },
        { name: "FinServ Group", crit: 0, high: 7, med: 22, risks: 1, comp: "91%", compC: GREEN, border: "transparent" },
      ].map((row) => (
        <Box key={row.name} sx={{ display: "flex", gap: 1, py: 1, borderLeft: `3px solid ${row.border}`, pl: row.border !== "transparent" ? 0.75 : 0, mb: 0.5, borderBottom: "1px solid rgba(255,255,255,0.04)", alignItems: "center" }}>
          <Box sx={{ flex: 2 }}>
            <Typography sx={{ fontSize: 11, color: "rgba(255,255,255,0.8)", fontWeight: 600 }}>{row.name}</Typography>
          </Box>
          {[
            { val: row.crit, color: DANGER },
            { val: row.high, color: "#F97316" },
            { val: row.med, color: AMBER },
            { val: row.risks, color: "#4285F4" },
          ].map(({ val, color: c }, i) => (
            <Box key={i} sx={{ flex: 1, textAlign: "center" }}>
              <Chip label={val} size="small" sx={{ bgcolor: val > 0 ? `${c}20` : "rgba(255,255,255,0.04)", color: val > 0 ? c : "rgba(255,255,255,0.2)", fontSize: 10, height: 18, fontWeight: 700 }} />
            </Box>
          ))}
          <Box sx={{ flex: 1, textAlign: "center" }}>
            <Chip label={row.comp} size="small" sx={{ bgcolor: `${row.compC}20`, color: row.compC, fontSize: 10, height: 18, fontWeight: 700 }} />
          </Box>
        </Box>
      ))}
    </Box>
  ),
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
    q: "What scanners does Owlet integrate with?",
    a: "Owlet integrates with 9 open-source and commercial scanners across four categories: SAST (Semgrep, CodeQL, SonarQube), DAST (OWASP ZAP), Network (Nmap, OpenVAS, Trivy), and Dependency / Secrets scanning (Gitleaks, TruffleHog). Scans are dispatched via GitHub Actions — no extra infrastructure required.",
  },
  {
    q: "How do AI agents automatically populate the threat register?",
    a: "When you run the Threat Intel agent on a completed scan, it analyzes every finding against the MITRE ATT&CK framework and creates structured threat entries — technique IDs, attacker profiles, and detection gaps — directly in your Threat Register. The Orchestrator agent runs all four specialists (Threat Intel, Risk Manager, Compliance Monitor, Remediation) in a single call, populating all three registers at once.",
  },
  {
    q: "Can I bring my own AI provider?",
    a: "Yes. Owlet supports Azure OpenAI, OpenAI, Anthropic, Google Gemini, and AWS Bedrock. Configure one or more providers in AI Settings — Owlet automatically fails over to the next configured provider if the primary is unavailable. No vendor lock-in.",
  },
  {
    q: "Is my source code stored after an AI code review?",
    a: "No. Your repository is cloned or unzipped into a temporary directory, analyzed, and immediately deleted when the review completes. Only the structured findings — file paths, line numbers, vulnerability descriptions, and remediation steps — are persisted in the database.",
  },
  {
    q: "Which compliance frameworks does Owlet support?",
    a: "Out of the box: NIST CSF 2.0, CIS Controls v8, ISO 27001:2022, GDPR, and PCI DSS v4.0. You can also build custom compliance frameworks in the Custom Standards section — pick controls from any built-in framework, combine them, and AI agents will evaluate your findings against your custom standard.",
  },
  {
    q: "How does AI VAPT report generation work?",
    a: "Select a completed scan and choose 'Generate from Scan.' Owlet pulls all findings, infers the scope and testing methodology from the connector type, then uses an LLM to write an executive summary, per-finding detailed remediation, and a conclusion. Reports export as PDF or DOCX — full engagement report or remediation-only plan.",
  },
  {
    q: "Can I use Owlet across multiple accounts or teams?",
    a: "Yes. Owlet supports multi-client workspaces — each client has isolated assets, scans, findings, threat entries, and risk scores. A global client selector in the top nav switches context instantly. Soft-delete lets you archive clients without losing historical data.",
  },
];

const NAV_LINKS = ["Features", "Process", "Integrations", "FAQ"];

const TERMINAL_LINES = [
  { text: "$ owlet agent run --orchestrator --scan-id a4f9bc12", color: CYAN, delay: 0 },
  { text: "", color: "", delay: 400 },
  { text: "⚡ Loading 84 open findings across 3 scans…", color: "rgba(255,255,255,0.6)", delay: 800 },
  { text: "", color: "", delay: 1100 },
  { text: "🔍  [CRITICAL] CWE-89 · SQL Injection · api/auth.py:127", color: DANGER, delay: 1400 },
  { text: "    ATT&CK: T1190 Exploit Public-Facing Application", color: "rgba(255,255,255,0.45)", delay: 1700 },
  { text: "    Gap: PCI DSS 6.3.1, NIST SI-10 → Priority: IMMEDIATE", color: AMBER, delay: 2000 },
  { text: "", color: "", delay: 2200 },
  { text: "🔍  [HIGH] CWE-798 · Hardcoded Key · config/settings.py:12", color: "#F97316", delay: 2500 },
  { text: "    ATT&CK: T1552.001 Credentials In Files", color: "rgba(255,255,255,0.45)", delay: 2800 },
  { text: "    Gap: NIST SC-28, ISO A.9.4.3 → Priority: HIGH", color: AMBER, delay: 3100 },
  { text: "", color: "", delay: 3300 },
  { text: "🔍  [HIGH] CWE-79 · Reflected XSS · frontend/search.js:48", color: "#F97316", delay: 3600 },
  { text: "    ATT&CK: T1059.007 JavaScript · CVSS 8.2", color: "rgba(255,255,255,0.45)", delay: 3900 },
  { text: "", color: "", delay: 4100 },
  { text: "✅  Threat Register:     12 new ATT&CK entries", color: GREEN, delay: 4400 },
  { text: "✅  Control Deficiencies: 8 framework gaps identified", color: GREEN, delay: 4700 },
  { text: "✅  Remediation Tracker: 19 priority-banded actions", color: GREEN, delay: 5000 },
  { text: "", color: "", delay: 5200 },
  { text: "📄  VAPT report generated — PDF ready for download", color: CYAN, delay: 5500 },
];

const USE_CASES = [
  {
    icon: <Person sx={{ fontSize: 22 }} />,
    persona: "CISO",
    headline: "Board-ready risk visibility in minutes",
    problem: "You're asked to present risk posture weekly but findings are buried in spreadsheets from five different tools.",
    solution: "Owlet aggregates every finding into a live risk score, attack path graph, and CTEM program — one number that means something.",
    points: ["Live risk score per client", "CTEM 5-phase program tracking", "Embeddable scorecard for board decks"],
    color: CYAN,
  },
  {
    icon: <Groups sx={{ fontSize: 22 }} />,
    persona: "AppSec Team",
    headline: "From commit to finding in one pipeline",
    problem: "Running 9 different scanners means 9 different UIs, 9 result formats, and no unified view of what's actually exploitable.",
    solution: "Submit a repo URL or zip — Owlet runs SAST, DAST, SCA, and secrets scanning, then an AI agent cross-traces taint paths and ranks by real exploitability.",
    points: ["9 scanners, one unified schema", "AI cross-file taint analysis", "Priority-banded remediation playbooks"],
    color: PURPLE,
  },
  {
    icon: <BusinessCenter sx={{ fontSize: 22 }} />,
    persona: "Compliance Officer",
    headline: "Continuous compliance, not point-in-time snapshots",
    problem: "Framework assessments take weeks of manual evidence gathering. By the time the report is done, the environment has changed.",
    solution: "Every finding is automatically mapped to NIST, ISO 27001, PCI DSS, and GDPR controls. One click generates an audit evidence package with findings, control gaps, and remediation status.",
    points: ["5 frameworks auto-mapped per finding", "Custom frameworks builder", "One-click evidence ZIP export"],
    color: GREEN,
  },
];

const NEW_CAPABILITIES = [
  {
    icon: <Radar sx={{ fontSize: 22 }} />,
    label: "New",
    title: "AI-Driven CTEM",
    desc: "5-phase exposure management — AI populates each phase from live findings, asset tags, and risk data. Phase-gated workflow unlocks as work is completed.",
    color: "#4285F4",
  },
  {
    icon: <AltRoute sx={{ fontSize: 22 }} />,
    label: "New",
    title: "Attack Path Visualisation",
    desc: "SVG attack chain graph automatically built from findings — maps initial access → lateral movement → exfiltration using MITRE ATT&CK phase classification.",
    color: DANGER,
  },
  {
    icon: <QuestionAnswer sx={{ fontSize: 22 }} />,
    label: "New",
    title: "Ask Your Data",
    desc: "Natural language queries over your findings. Type a question, get AI-generated SQL + a result table + a plain-English summary. No SQL knowledge required.",
    color: CYAN,
  },
  {
    icon: <Analytics sx={{ fontSize: 22 }} />,
    label: "New",
    title: "Posture Trends",
    desc: "Historical posture snapshots charted over time — open findings by severity, audit readiness %, and MTTR per severity vs. SLA targets.",
    color: PURPLE,
  },
  {
    icon: <Webhook sx={{ fontSize: 22 }} />,
    label: "New",
    title: "Slack & Teams Webhooks",
    desc: "Real-time notifications on critical findings, scan completions, and agent results. HMAC-SHA256 signed payloads for verified delivery.",
    color: "#FB923C",
  },
  {
    icon: <VpnKey sx={{ fontSize: 22 }} />,
    label: "New",
    title: "Embeddable Scorecard",
    desc: "Public no-auth scorecard endpoint with a token — embed a live security score widget in your customer portal, status page, or executive dashboard.",
    color: GREEN,
  },
  {
    icon: <Gavel sx={{ fontSize: 22 }} />,
    label: "New",
    title: "Compliance Evidence Package",
    desc: "One-click ZIP export: findings CSV, control deficiencies JSON, remediation log, and agent run history — everything an auditor needs, formatted.",
    color: AMBER,
  },
  {
    icon: <AutoAwesome sx={{ fontSize: 22 }} />,
    label: "New",
    title: "RAG over Security Docs",
    desc: "Upload your own security policies, procedures, or standards. Ask natural-language questions — AI answers grounded in your actual documents.",
    color: "#F472B6",
  },
];

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
  const [announcementDismissed, setAnnouncementDismissed] = useState(false);
  const [terminalLines, setTerminalLines] = useState<typeof TERMINAL_LINES>([]);
  const [terminalStarted, setTerminalStarted] = useState(false);
  const [useCaseTab, setUseCaseTab] = useState(0);
  const [tourTab, setTourTab] = useState(0);
  const [statCounts, setStatCounts] = useState([0, 0, 0]);
  const statsRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<HTMLDivElement>(null);
  const terminalBottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", fn);
    return () => window.removeEventListener("scroll", fn);
  }, []);

  // Terminal animation — starts when section scrolls into view
  useEffect(() => {
    if (terminalStarted) return;
    const el = terminalRef.current;
    if (!el) return;
    const obs = new IntersectionObserver(([e]) => {
      if (e.isIntersecting) {
        setTerminalStarted(true);
        obs.disconnect();
      }
    }, { threshold: 0.3 });
    obs.observe(el);
    return () => obs.disconnect();
  }, [terminalStarted]);

  useEffect(() => {
    if (!terminalStarted) return;
    let cancelled = false;
    TERMINAL_LINES.forEach((line, idx) => {
      setTimeout(() => {
        if (cancelled) return;
        setTerminalLines(prev => [...prev, line]);
        if (terminalBottomRef.current) {
          terminalBottomRef.current.scrollIntoView({ behavior: "smooth" });
        }
      }, line.delay);
    });
    return () => { cancelled = true; };
  }, [terminalStarted]);

  // Animated stat counters — trigger when stats section scrolls into view
  const STAT_TARGETS = [9, 60, 5];
  useEffect(() => {
    const el = statsRef.current;
    if (!el) return;
    const obs = new IntersectionObserver(([e]) => {
      if (!e.isIntersecting) return;
      obs.disconnect();
      const duration = 1400;
      const steps = 50;
      const interval = duration / steps;
      let step = 0;
      const timer = setInterval(() => {
        step++;
        const progress = Math.min(step / steps, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        setStatCounts(STAT_TARGETS.map(t => Math.round(t * eased)));
        if (step >= steps) clearInterval(timer);
      }, interval);
    }, { threshold: 0.5 });
    obs.observe(el);
    return () => obs.disconnect();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const signIn = () =>
    instance.loginRedirect({
      ...loginRequest,
      redirectStartPage: `${window.location.origin}/dashboard`,
    }).catch(() => {});


  return (
    <Box sx={{ bgcolor: BG, minHeight: "100vh", color: "white", fontFamily: "Inter, sans-serif", overflowX: "hidden" }}>

      {/* ── Announcement bar ───────────────────────────────────────────────── */}
      {!announcementDismissed && (
        <Box sx={{
          background: `linear-gradient(90deg, rgba(124,58,237,0.85) 0%, rgba(0,212,255,0.7) 100%)`,
          backdropFilter: "blur(8px)",
          py: 0.9, px: 2, display: "flex", alignItems: "center", justifyContent: "center",
          gap: 1.5, position: "relative", zIndex: 200,
        }}>
          <Campaign sx={{ fontSize: 15, color: "rgba(255,255,255,0.85)" }} />
          <Typography sx={{ fontSize: 13, fontWeight: 500, color: "rgba(255,255,255,0.9)", textAlign: "center" }}>
            <Box component="span" sx={{ fontWeight: 700 }}>New: </Box>
            AI-driven CTEM, Attack Paths, Natural Language Queries, and Embeddable Scorecards are now live.
          </Typography>
          <Button size="small" href="#new-capabilities"
            sx={{ color: "white", fontSize: 12, fontWeight: 700, textTransform: "none", textDecoration: "underline", p: 0, minWidth: 0 }}>
            See what's new →
          </Button>
          <IconButton size="small" onClick={() => setAnnouncementDismissed(true)}
            sx={{ position: "absolute", right: 8, color: "rgba(255,255,255,0.5)", "&:hover": { color: "white" } }}>
            <CloseIcon sx={{ fontSize: 16 }} />
          </IconButton>
        </Box>
      )}

      {/* ── Navbar ─────────────────────────────────────────────────────────── */}
      <Box sx={{
        position: "fixed", top: announcementDismissed ? 0 : 40, left: 0, right: 0, zIndex: 100,
        backdropFilter: scrolled ? "blur(16px)" : "none",
        background: scrolled ? "rgba(6,8,16,0.92)" : "transparent",
        borderBottom: scrolled ? `1px solid ${BORDER}` : "none",
        transition: "all 0.3s",
      }}>
        <Container maxWidth="lg">
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", py: 2 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <img src={`${process.env.PUBLIC_URL}/monitara-logo.svg`} alt="Owlet" style={{ width: 32, height: 32 }} />
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
      <Box sx={{ position: "relative", pt: { xs: announcementDismissed ? 14 : 18, md: announcementDismissed ? 18 : 22 }, pb: { xs: 8, md: 10 }, overflow: "hidden" }}>
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
                Owlet combines AI code review, VAPT, threat modeling, and autonomous security agents in one platform. AI agents auto-populate Threat, Control, and Remediation registers — so your team sees risk clearly and fixes what matters.
              </Typography>

              <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                <Button onClick={signIn} variant="contained" size="large" endIcon={<ArrowForward />} sx={{
                  background: CYAN, color: "#060810", fontWeight: 700, fontSize: 15,
                  textTransform: "none", px: 4, py: 1.5, borderRadius: 2,
                  "&:hover": { background: "#00B8E0", transform: "translateY(-1px)" }, transition: "all 0.2s",
                }}>
                  Sign In to Owlet
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
                  <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.25)", ml: 1, fontFamily: "monospace" }}>Owlet AI — Security Dashboard</Typography>
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
      <Box ref={statsRef} sx={{ borderTop: `1px solid ${BORDER}`, borderBottom: `1px solid ${BORDER}`, background: "rgba(255,255,255,0.015)", py: 5 }}>
        <Container maxWidth="lg">
          <Grid container spacing={2} sx={{ justifyContent: "center" }}>
            {[
              { value: `${statCounts[0]}+`, label: "Scanner integrations" },
              { value: `${statCounts[1]}+`, label: "AI security agents" },
              { value: `${statCounts[2]}`, label: "Compliance frameworks" },
              { value: "Real-time", label: "Risk scoring" },
            ].map(({ value, label }) => (
              <Grid key={label} size={{ xs: 6, sm: 3 }} sx={{ textAlign: "center" }}>
                <Typography sx={{
                  fontSize: { xs: 30, md: 38 }, fontWeight: 800,
                  background: `linear-gradient(135deg, ${CYAN}, ${PURPLE})`,
                  WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
                  transition: "all 0.1s",
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

      {/* ── Product Tour ───────────────────────────────────────────────────── */}
      <Box id="product-tour" sx={{ py: { xs: 8, md: 14 }, borderTop: `1px solid ${BORDER}` }}>
        <Container maxWidth="lg">
          <Box sx={{ textAlign: "center", mb: 6 }}>
            <Chip label="Product tour" size="small" sx={{ mb: 2.5, background: `rgba(0,212,255,0.08)`, border: `1px solid rgba(0,212,255,0.22)`, color: CYAN, fontWeight: 600, fontSize: 12 }} />
            <Typography sx={{ fontSize: { xs: 26, md: 38 }, fontWeight: 800, letterSpacing: "-0.02em", mb: 2 }}>
              See it in action
            </Typography>
            <Typography sx={{ color: "rgba(255,255,255,0.38)", fontSize: 16, maxWidth: 520, mx: "auto" }}>
              Explore the key views that security teams use every day — from finding triage to compliance coverage.
            </Typography>
          </Box>

          {/* Tab selector */}
          <Box sx={{ borderBottom: `1px solid ${BORDER}`, mb: 0 }}>
            <Tabs
              value={tourTab}
              onChange={(_, v) => setTourTab(v)}
              variant="scrollable"
              scrollButtons="auto"
              sx={{
                "& .MuiTab-root": { color: "rgba(255,255,255,0.38)", textTransform: "none", fontSize: 13, fontWeight: 600, minWidth: 0 },
                "& .Mui-selected": { color: CYAN },
                "& .MuiTabs-indicator": { background: `linear-gradient(90deg, ${CYAN}, ${PURPLE})`, height: 2 },
              }}
            >
              {PRODUCT_TOUR_TABS.map((label) => (
                <Tab key={label} label={label} />
              ))}
            </Tabs>
          </Box>

          {/* Screen mockup */}
          <Box
            sx={{
              background: "#0a0e1a",
              border: `1px solid rgba(255,255,255,0.08)`,
              borderTop: "none",
              borderRadius: "0 0 16px 16px",
              overflow: "hidden",
              boxShadow: "0 40px 80px rgba(0,0,0,0.5)",
              minHeight: 340,
            }}
          >
            {/* Window chrome */}
            <Box sx={{ px: 2.5, py: 1.25, display: "flex", alignItems: "center", gap: 1.5, background: "rgba(0,0,0,0.25)", borderBottom: `1px solid rgba(255,255,255,0.07)` }}>
              <Box sx={{ width: 10, height: 10, borderRadius: "50%", background: "#FF5F57" }} />
              <Box sx={{ width: 10, height: 10, borderRadius: "50%", background: "#FEBC2E" }} />
              <Box sx={{ width: 10, height: 10, borderRadius: "50%", background: "#28C840" }} />
              <Typography sx={{ fontSize: 11, color: "rgba(255,255,255,0.22)", ml: 1, fontFamily: "monospace" }}>
                Owlet AI — {PRODUCT_TOUR_TABS[tourTab]}
              </Typography>
            </Box>

            {/* Screen content */}
            {PRODUCT_TOUR_SCREENS.map((Screen, idx) => (
              <Box key={idx} sx={{ display: tourTab === idx ? "block" : "none" }}>
                <Screen color={CYAN} />
              </Box>
            ))}
          </Box>
        </Container>
      </Box>

      {/* ── Use Cases ──────────────────────────────────────────────────────── */}
      <Box sx={{ py: { xs: 8, md: 14 }, background: "rgba(255,255,255,0.012)", borderTop: `1px solid ${BORDER}`, borderBottom: `1px solid ${BORDER}` }}>
        <Container maxWidth="lg">
          <Box sx={{ textAlign: "center", mb: 6 }}>
            <Chip label="Built for security teams" size="small" sx={{ mb: 2.5, background: `rgba(0,212,255,0.08)`, border: `1px solid rgba(0,212,255,0.22)`, color: CYAN, fontWeight: 600, fontSize: 12 }} />
            <Typography sx={{ fontSize: { xs: 26, md: 38 }, fontWeight: 800, letterSpacing: "-0.02em", mb: 2 }}>
              One platform. Every security role.
            </Typography>
            <Typography sx={{ color: "rgba(255,255,255,0.38)", fontSize: 16, maxWidth: 520, mx: "auto" }}>
              Owlet adapts to how your team works — whether you're presenting to the board, hunting vulnerabilities, or preparing for an audit.
            </Typography>
          </Box>

          <Box sx={{ borderBottom: `1px solid ${BORDER}`, mb: 4 }}>
            <Tabs
              value={useCaseTab}
              onChange={(_, v) => setUseCaseTab(v)}
              centered
              sx={{
                "& .MuiTab-root": { color: "rgba(255,255,255,0.4)", textTransform: "none", fontSize: 14, fontWeight: 600 },
                "& .Mui-selected": { color: "white" },
                "& .MuiTabs-indicator": { background: `linear-gradient(90deg, ${CYAN}, ${PURPLE})`, height: 2 },
              }}
            >
              {USE_CASES.map((uc) => (
                <Tab key={uc.persona} label={
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Box sx={{ color: useCaseTab === USE_CASES.indexOf(uc) ? uc.color : "inherit" }}>{uc.icon}</Box>
                    {uc.persona}
                  </Box>
                } />
              ))}
            </Tabs>
          </Box>

          {USE_CASES.map((uc, idx) => (
            <Box key={uc.persona} sx={{ display: useCaseTab === idx ? "block" : "none" }}>
              <Grid container spacing={6} sx={{ alignItems: "center" }}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <Chip label={uc.persona} size="small" sx={{ mb: 2, background: `${uc.color}18`, color: uc.color, border: `1px solid ${uc.color}30`, fontWeight: 700 }} />
                  <Typography sx={{ fontSize: { xs: 24, md: 32 }, fontWeight: 800, letterSpacing: "-0.02em", lineHeight: 1.2, mb: 2 }}>
                    {uc.headline}
                  </Typography>

                  <Box sx={{ p: 2, mb: 3, borderRadius: 2, background: "rgba(234,67,53,0.07)", border: `1px solid rgba(234,67,53,0.2)` }}>
                    <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.55)", lineHeight: 1.65 }}>
                      <Box component="span" sx={{ color: DANGER, fontWeight: 700 }}>Challenge: </Box>
                      {uc.problem}
                    </Typography>
                  </Box>
                  <Box sx={{ p: 2, mb: 3, borderRadius: 2, background: `${uc.color}0A`, border: `1px solid ${uc.color}25` }}>
                    <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.55)", lineHeight: 1.65 }}>
                      <Box component="span" sx={{ color: uc.color, fontWeight: 700 }}>Owlet: </Box>
                      {uc.solution}
                    </Typography>
                  </Box>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    {uc.points.map((p) => (
                      <Box key={p} sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                        <CheckCircle sx={{ fontSize: 16, color: uc.color, flexShrink: 0 }} />
                        <Typography sx={{ fontSize: 14, color: "rgba(255,255,255,0.55)" }}>{p}</Typography>
                      </Box>
                    ))}
                  </Box>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  {/* Visual placeholder — mini dashboard preview tailored per persona */}
                  <Box sx={{
                    p: 3, borderRadius: 3, border: `1px solid ${uc.color}30`,
                    background: `${uc.color}07`,
                    boxShadow: `0 0 60px ${uc.color}0F`,
                  }}>
                    {idx === 0 && (
                      /* CISO view — risk score + CTEM progress */
                      <Box>
                        <Typography sx={{ fontSize: 11, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 1, mb: 2 }}>Security Posture Overview</Typography>
                        <Box sx={{ display: "flex", gap: 2, mb: 3 }}>
                          {[{ label: "Risk Score", val: "72", color: AMBER }, { label: "Open", val: "84", color: DANGER }, { label: "CTEM", val: "3/5", color: CYAN }].map(s => (
                            <Box key={s.label} sx={{ flex: 1, p: 1.5, borderRadius: 2, border: `1px solid ${BORDER}`, background: "rgba(0,0,0,0.2)", textAlign: "center" }}>
                              <Typography sx={{ fontSize: 22, fontWeight: 800, color: s.color }}>{s.val}</Typography>
                              <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.35)" }}>{s.label}</Typography>
                            </Box>
                          ))}
                        </Box>
                        <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.28)", mb: 1, textTransform: "uppercase", letterSpacing: 0.8 }}>Risk trend (30 days)</Typography>
                        <Box sx={{ height: 60, display: "flex", alignItems: "flex-end", gap: 1 }}>
                          {[55,58,62,60,65,68,70,69,72,71,74,72].map((v, i) => (
                            <Box key={i} sx={{ flex: 1, height: `${(v/80)*100}%`, borderRadius: "3px 3px 0 0", background: i === 11 ? AMBER : `${AMBER}55`, transition: "all 0.3s" }} />
                          ))}
                        </Box>
                      </Box>
                    )}
                    {idx === 1 && (
                      /* AppSec view — scan pipeline */
                      <Box>
                        <Typography sx={{ fontSize: 11, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 1, mb: 2 }}>Scan Pipeline</Typography>
                        {[
                          { name: "AI Code Review", status: "✅ Complete", findings: "23 findings", color: GREEN },
                          { name: "Semgrep SAST", status: "✅ Complete", findings: "11 findings", color: GREEN },
                          { name: "OWASP ZAP DAST", status: "⚡ Running", findings: "—", color: CYAN },
                          { name: "Gitleaks Secrets", status: "⏳ Queued", findings: "—", color: AMBER },
                        ].map((s, i) => (
                          <Box key={i} sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", py: 1, borderBottom: `1px solid ${BORDER}` }}>
                            <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.65)" }}>{s.name}</Typography>
                            <Box sx={{ display: "flex", gap: 2, alignItems: "center" }}>
                              <Typography sx={{ fontSize: 10, color: "rgba(255,255,255,0.35)" }}>{s.findings}</Typography>
                              <Typography sx={{ fontSize: 11, color: s.color }}>{s.status}</Typography>
                            </Box>
                          </Box>
                        ))}
                        <Box sx={{ mt: 2, p: 1.5, borderRadius: 1.5, background: "rgba(0,212,255,0.06)", border: `1px solid rgba(0,212,255,0.18)` }}>
                          <Typography sx={{ fontSize: 11, color: "rgba(0,212,255,0.8)" }}>⚡ AI taint tracer — cross-file analysis in progress…</Typography>
                        </Box>
                      </Box>
                    )}
                    {idx === 2 && (
                      /* Compliance view — framework coverage */
                      <Box>
                        <Typography sx={{ fontSize: 11, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 1, mb: 2 }}>Framework Coverage</Typography>
                        {[
                          { fw: "NIST CSF 2.0", pct: 78, color: GREEN },
                          { fw: "ISO 27001:2022", pct: 64, color: CYAN },
                          { fw: "PCI DSS v4.0", pct: 51, color: AMBER },
                          { fw: "GDPR", pct: 83, color: PURPLE },
                        ].map((f) => (
                          <Box key={f.fw} sx={{ mb: 1.5 }}>
                            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.4 }}>
                              <Typography sx={{ fontSize: 11, color: "rgba(255,255,255,0.55)" }}>{f.fw}</Typography>
                              <Typography sx={{ fontSize: 11, color: f.color, fontWeight: 700 }}>{f.pct}%</Typography>
                            </Box>
                            <Box sx={{ height: 5, borderRadius: 3, background: "rgba(255,255,255,0.06)" }}>
                              <Box sx={{ width: `${f.pct}%`, height: "100%", borderRadius: 3, background: f.color, transition: "width 0.8s" }} />
                            </Box>
                          </Box>
                        ))}
                        <Button size="small" variant="outlined" sx={{ mt: 1.5, fontSize: 11, color: GREEN, borderColor: `${GREEN}44`, textTransform: "none" }}>
                          Export evidence package →
                        </Button>
                      </Box>
                    )}
                  </Box>
                </Grid>
              </Grid>
            </Box>
          ))}
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

      {/* ── Live AI terminal ───────────────────────────────────────────────── */}
      <Box ref={terminalRef} sx={{ py: { xs: 8, md: 14 }, borderTop: `1px solid ${BORDER}` }}>
        <Container maxWidth="lg">
          <Grid container spacing={8} sx={{ alignItems: "center" }}>
            <Grid size={{ xs: 12, md: 5 }}>
              <Chip label="Watch it work" size="small" sx={{ mb: 2.5, background: `rgba(0,212,255,0.08)`, border: `1px solid rgba(0,212,255,0.22)`, color: CYAN, fontWeight: 600, fontSize: 12 }} />
              <Typography sx={{ fontSize: { xs: 26, md: 36 }, fontWeight: 800, letterSpacing: "-0.02em", lineHeight: 1.2, mb: 2.5 }}>
                AI agents turn findings into{" "}
                <Box component="span" sx={{ background: `linear-gradient(135deg, ${CYAN}, ${PURPLE})`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
                  action
                </Box>
                {" "}automatically.
              </Typography>
              <Typography sx={{ color: "rgba(255,255,255,0.42)", fontSize: 15, lineHeight: 1.75, mb: 3 }}>
                The Orchestrator agent runs all four specialists in one call — Threat Intel maps to MITRE ATT&CK, Risk Manager scores impact, Compliance Monitor identifies control gaps, and Remediation Agent writes priority-banded playbooks. All three registers populate without any manual triage.
              </Typography>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                {[
                  { label: "Threat Register", sub: "ATT&CK technique + attacker profile per finding", color: DANGER },
                  { label: "Control Deficiencies", sub: "Framework gaps across NIST, ISO, PCI, GDPR", color: AMBER },
                  { label: "Remediation Tracker", sub: "Banded action items: Quick Win / Near Term / Long", color: GREEN },
                ].map((r) => (
                  <Box key={r.label} sx={{ display: "flex", alignItems: "flex-start", gap: 1.5, p: 1.5, borderRadius: 2, border: `1px solid ${r.color}25`, background: `${r.color}07` }}>
                    <Box sx={{ width: 8, height: 8, borderRadius: "50%", background: r.color, mt: 0.5, flexShrink: 0, boxShadow: `0 0 6px ${r.color}` }} />
                    <Box>
                      <Typography sx={{ fontSize: 13, fontWeight: 700, color: "rgba(255,255,255,0.85)" }}>{r.label}</Typography>
                      <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.38)" }}>{r.sub}</Typography>
                    </Box>
                  </Box>
                ))}
              </Box>
            </Grid>
            <Grid size={{ xs: 12, md: 7 }}>
              <Box sx={{
                background: "#0a0e1a", border: `1px solid rgba(255,255,255,0.08)`, borderRadius: 3,
                overflow: "hidden", boxShadow: "0 40px 80px rgba(0,0,0,0.6)",
              }}>
                {/* Terminal chrome */}
                <Box sx={{ borderBottom: `1px solid rgba(255,255,255,0.07)`, px: 2.5, py: 1.5, display: "flex", alignItems: "center", gap: 1.5, background: "rgba(0,0,0,0.3)" }}>
                  <Box sx={{ width: 10, height: 10, borderRadius: "50%", background: "#FF5F57" }} />
                  <Box sx={{ width: 10, height: 10, borderRadius: "50%", background: "#FEBC2E" }} />
                  <Box sx={{ width: 10, height: 10, borderRadius: "50%", background: "#28C840" }} />
                  <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, ml: 1.5 }}>
                    <Terminal sx={{ fontSize: 12, color: "rgba(255,255,255,0.25)" }} />
                    <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.25)", fontFamily: "monospace" }}>owlet-cli — orchestrator</Typography>
                  </Box>
                </Box>
                {/* Terminal output */}
                <Box sx={{ p: 2.5, minHeight: 340, maxHeight: 400, overflowY: "auto", fontFamily: "monospace" }}>
                  {terminalLines.map((line, idx) => (
                    <Typography key={idx} sx={{
                      fontSize: 12, lineHeight: 1.8,
                      color: line.color || "rgba(255,255,255,0.35)",
                      fontFamily: "monospace",
                    }}>
                      {line.text || " "}
                    </Typography>
                  ))}
                  {terminalLines.length > 0 && terminalLines.length < TERMINAL_LINES.length && (
                    <Box sx={{ display: "inline-block", width: 8, height: 14, background: CYAN, ml: 0.25, animation: "blink 1s step-end infinite", "@keyframes blink": { "0%, 100%": { opacity: 1 }, "50%": { opacity: 0 } } }} />
                  )}
                  {terminalLines.length === 0 && (
                    <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.2)", fontFamily: "monospace" }}>
                      Scroll into view to watch the agent run…
                    </Typography>
                  )}
                  <div ref={terminalBottomRef} />
                </Box>
              </Box>
            </Grid>
          </Grid>
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

      {/* ── New capabilities ───────────────────────────────────────────────── */}
      <Box id="new-capabilities" sx={{ py: { xs: 8, md: 12 }, borderTop: `1px solid ${BORDER}` }}>
        <Container maxWidth="lg">
          <Box sx={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", mb: 5, flexWrap: "wrap", gap: 2 }}>
            <Box>
              <Chip label="Just shipped" size="small" sx={{ mb: 1.5, background: `rgba(251,188,4,0.1)`, border: `1px solid rgba(251,188,4,0.3)`, color: AMBER, fontWeight: 700, fontSize: 11 }} />
              <Typography sx={{ fontSize: { xs: 24, md: 34 }, fontWeight: 800, letterSpacing: "-0.02em" }}>
                New capabilities
              </Typography>
              <Typography sx={{ color: "rgba(255,255,255,0.38)", fontSize: 15, mt: 0.5 }}>
                Eight new features added to the platform
              </Typography>
            </Box>
          </Box>

          {/* Horizontal scroll cards */}
          <Box sx={{
            display: "flex", gap: 2, overflowX: "auto", pb: 2,
            scrollSnapType: "x mandatory",
            "&::-webkit-scrollbar": { height: 4 },
            "&::-webkit-scrollbar-track": { background: "rgba(255,255,255,0.04)", borderRadius: 2 },
            "&::-webkit-scrollbar-thumb": { background: "rgba(255,255,255,0.15)", borderRadius: 2 },
          }}>
            {NEW_CAPABILITIES.map((cap) => (
              <Box key={cap.title} sx={{
                flexShrink: 0, width: { xs: 260, md: 280 }, p: 2.5,
                scrollSnapAlign: "start",
                border: `1px solid ${BORDER}`, borderRadius: 2.5,
                background: CARD_BG,
                transition: "all 0.25s",
                "&:hover": {
                  border: `1px solid ${cap.color}35`,
                  background: `${cap.color}08`,
                  transform: "translateY(-3px)",
                  boxShadow: `0 16px 40px rgba(0,0,0,0.4)`,
                },
              }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                  <Box sx={{
                    width: 42, height: 42, borderRadius: 1.5,
                    background: `${cap.color}18`, border: `1px solid ${cap.color}30`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    color: cap.color,
                  }}>
                    {cap.icon}
                  </Box>
                  <Chip label={cap.label} size="small" sx={{
                    background: "rgba(251,188,4,0.12)", color: AMBER,
                    border: "1px solid rgba(251,188,4,0.25)", fontSize: 10, fontWeight: 700, height: 20,
                  }} />
                </Box>
                <Typography sx={{ fontWeight: 700, fontSize: 15, mb: 1, letterSpacing: "-0.01em" }}>{cap.title}</Typography>
                <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.42)", lineHeight: 1.65 }}>{cap.desc}</Typography>
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
              Owlet runs entirely inside your own cloud or on-premises infrastructure — Azure, AWS, GCP, or a private data centre. No internet exposure. No data leaving your boundary. Works wherever your workloads live.
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

                {/* ── Owlet App Service ── */}
                <rect x="375" y="55" width="140" height="230" rx="10" fill="rgba(52,168,83,0.07)" stroke="rgba(52,168,83,0.45)" strokeWidth="2" />
                <text x="445" y="78" textAnchor="middle" fill="#34A853" fontSize="11" fontWeight="700">MONITARA</text>
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
            Sign In to Owlet
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
                <img src={`${process.env.PUBLIC_URL}/monitara-logo.svg`} alt="Owlet" style={{ width: 28, height: 28, opacity: 0.8 }} />
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
