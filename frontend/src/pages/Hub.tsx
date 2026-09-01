import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Chip, CircularProgress,
  Divider, Tooltip, alpha, useTheme,
} from "@mui/material";
import { InfoOutlined } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import AssistantWidget from "../components/AssistantWidget";
import MegaMenuBar from "../components/layout/MegaMenuBar";
import AppControls from "../components/layout/AppControls";
import OwletLogo from "../components/OwletLogo";
import { dataModelApi } from "../services/api";
import { useActiveClient } from "../contexts/ClientContext";

// ── Types ─────────────────────────────────────────────────────────────────────

interface CardDef {
  name: string;
  desc: string;
  route: string;
  group?: string;
}

interface StageDef {
  num: string; id: string; label: string; color: string; path: string;
  title: string; sub: string; info: string;
  cards: CardDef[];
}

// ── Stage + card definitions ──────────────────────────────────────────────────

const STAGE_DEFS: StageDef[] = [
  {
    num: "01", id: "setup", label: "Setup", color: "#2563eb", path: "/platform",
    title: "Stand up the environment",
    sub: "Configure accounts, connectors, and AI providers before any scanning begins.",
    info: "Complete this stage first — every downstream scan depends on at least one connected account and a configured AI provider.",
    cards: [
      { name: "Accounts",            desc: "Client profiles, contact details, and security posture scoping.",          route: "/platform/clients",         group: "Environment" },
      { name: "Asset Inventory",     desc: "Discovered assets — servers, apps, containers, and cloud resources.",      route: "/platform/assets",          group: "Environment" },
      { name: "Connectors",          desc: "Scanner integrations, enterprise tools, and SIEM connectors.",             route: "/platform/connections",     group: "Environment" },
      { name: "AI Settings",         desc: "AI provider credentials, model selection, and automatic failover config.", route: "/platform/ai-settings",     group: "Environment" },
      { name: "AI Guardrails",       desc: "AI safety controls, prompt audit logs, and guardrail coverage.",           route: "/automate/ai-guardrails",   group: "Design" },
      { name: "Threat Models",       desc: "DFD diagrams, STRIDE analysis, and Sigma detection rule generation.",      route: "/analyse/threat-models",    group: "Design" },
      { name: "Framework Library",      desc: "Browse standard frameworks and manage custom compliance policies.",        route: "/report/frameworks",        group: "Design" },
      { name: "Compliance Evaluation", desc: "Evaluate posture and run targeted scans against any framework.",          route: "/report/compliance",        group: "Design" },
      { name: "Data Model",          desc: "Platform ontology — eleven entities, one interactive graph.",              route: "/data-model",               group: "Design" },
    ],
  },
  {
    num: "02", id: "discover", label: "Discover", color: "#0f766e", path: "/discover",
    title: "Find what's actually exposed",
    sub: "Scan the environment via inbuilt scanners, enterprise integrations, or an AI-guided conversation.",
    info: "CVE enrichment and severity scoring run automatically after each scan. Import results from external scanners via the Import tab in Assessments.",
    cards: [
      { name: "Assessments",          desc: "Launch scans, manage versions, and import external scan results.",              route: "/discover/scans",        group: "Scanning" },
      { name: "Findings",             desc: "All findings with severity, CVE enrichment, and remediation status.",           route: "/discover/findings",     group: "Scanning" },
      { name: "AI Assisted Scan",     desc: "Conversational guided assessment — describe the environment, AI configures.",   route: "/discover/ai-scan",      group: "Scanning" },
      { name: "Posture Trends",       desc: "Time-series charts of open findings and audit readiness score.",                route: "/discover/posture",      group: "Scanning" },
      { name: "Asset Inventory",      desc: "All discovered assets with compliance and CVE posture.",                        route: "/discover/assets",       group: "Assets & CVE" },
      { name: "Technology Inventory", desc: "Software and technology stack across all assets.",                              route: "/discover/technologies", group: "Assets & CVE" },
      { name: "CVE Blast Radius",     desc: "Map CVE exposure across assets — which assets are actually affected.",          route: "/discover/cve-pivot",    group: "Assets & CVE" },
    ],
  },
  {
    num: "03", id: "analyse", label: "Analyse", color: "#b45309", path: "/analyse",
    title: "Turn findings into insight",
    sub: "Score findings, apply FAIR-lite ALE modelling, and query your entire posture in plain language.",
    info: "Risk domains are automatically normalised. Attack paths are derived from finding combinations — no manual correlation needed.",
    cards: [
      { name: "Risk Staging",            desc: "Proposal staging gate — review, evaluate, and promote AI-generated risk proposals before they enter the register.", route: "/analyse/risks/staging", group: "Risk" },
      { name: "Risk Register",          desc: "FAIR-scored risk register with domain heatmap and financial ALE.",         route: "/analyse/risks",               group: "Risk" },
      { name: "Risk Overview",          desc: "Executive summary of ALE exposure, risk domains, and top risks.",          route: "/analyse/risk-overview",       group: "Risk" },
      { name: "AI Risk Analysis",       desc: "AI-generated risk narrative with actionable recommendations.",             route: "/analyse/ai-analysis",         group: "Risk" },
      { name: "Attack Paths",           desc: "MITRE-phased interactive attack chain graph derived from live findings.",  route: "/analyse/attack-paths",        group: "Risk" },
      { name: "AI Threat Intelligence", desc: "DFD diagrams, STRIDE threats, and Sigma detection rule generation.",       route: "/analyse/threat-models",       group: "Intelligence" },
      { name: "Compliance Heatmap",     desc: "Control coverage heatmap across all frameworks.",                          route: "/analyse/compliance-heatmap",  group: "Intelligence" },
      { name: "Ask Your Data",          desc: "Natural language SQL queries over findings, risks, and assets.",           route: "/analyse/nl-query",            group: "Intelligence" },
      { name: "Project Comparison",     desc: "Compare security posture across multiple accounts.",                       route: "/analyse/comparison",          group: "Intelligence" },
    ],
  },
  {
    num: "04", id: "respond", label: "Respond", color: "#b91c1c", path: "/respond",
    title: "Act on the picture",
    sub: "Map risk to real adversary behaviour, then track remediation through structured CTEM programs.",
    info: "Threat entries are mapped to MITRE ATT&CK automatically. CTEM programs progress through 5 phases: Scope → Discover → Prioritise → Validate → Mobilise.",
    cards: [
      { name: "Threat Register",      desc: "MITRE ATT&CK–mapped threat entries and IOCs from AI analysis.",              route: "/respond/threats",          group: "Threat Intelligence" },
      { name: "Control Deficiencies", desc: "Framework control gaps identified by the compliance monitor agent.",          route: "/respond/gaps",             group: "Threat Intelligence" },
      { name: "CTEM Programs",        desc: "5-phase continuous threat exposure management programs.",                     route: "/respond/ctem",             group: "Threat Intelligence" },
      { name: "Remediation",          desc: "Priority-banded remediation actions tracked to completion.",                  route: "/respond/remediation",      group: "Remediation" },
      { name: "AI Remediations",      desc: "AI-generated remediation plans dispatched as automated workflows.",           route: "/respond/remediation-jobs", group: "Remediation" },
      { name: "VAPT Reports",         desc: "Full engagement lifecycle with retest versioning and PDF/DOCX export.",       route: "/respond/vapt-reports",     group: "Remediation" },
      { name: "Security Docs",        desc: "Upload security policies and query them with AI via RAG.",                    route: "/respond/security-docs",    group: "Remediation" },
    ],
  },
  {
    num: "05", id: "report", label: "Audit", color: "#15803d", path: "/report",
    title: "Prove it happened",
    sub: "Close the loop with evidence the auditor — or the client — can actually use.",
    info: "VAPT reports are AI-generated from scan findings. Evidence packages are audit-ready ZIPs of findings, control deficiencies, remediation actions, and agent logs.",
    cards: [
      { name: "VAPT Reports",          desc: "Full engagement lifecycle with retest versioning and PDF/DOCX export.",       route: "/report/vapt-reports",        group: "Audit & Reporting" },
      { name: "Evidence Package",      desc: "Audit-ready ZIP of findings, deficiencies, and agent logs for auditors.",    route: "/report/evidence",            group: "Audit & Reporting" },
      { name: "Audit Intelligence",    desc: "ICS Audit & Risk — how every audit activity maps to the platform.",          route: "/report/audit",               group: "Audit & Reporting" },
      { name: "Audit Agents",          desc: "Wizard-driven AI agents for control testing, readiness reports, and evidence curation.", route: "/report/audit-agents", group: "Audit & Reporting" },
      { name: "Executive Summary",     desc: "Non-technical leadership report — posture score, key risks, and remediation progress.", route: "/report/executive-summary", group: "Audit & Reporting" },
      { name: "Reports",               desc: "AI-generated security posture and trend reports.",                           route: "/report/reports",             group: "Audit & Reporting" },
      { name: "Report Scheduler",      desc: "Schedule recurring report delivery to stakeholders via email.",              route: "/report/scheduler",           group: "Audit & Reporting" },
      { name: "Framework Library",     desc: "Browse standard frameworks and manage custom compliance policies.",          route: "/report/frameworks",          group: "Compliance" },
      { name: "Compliance Evaluation", desc: "Evaluate posture and run targeted scans against any framework.",             route: "/report/compliance",          group: "Compliance" },
      { name: "Control Gaps",          desc: "Framework control deficiencies identified by the compliance monitor.",       route: "/report/gaps",                group: "Compliance" },
    ],
  },
  {
    num: "06", id: "automate", label: "Automate", color: "#4338ca", path: "/automate",
    title: "Let AI carry the load",
    sub: "Agents run the full analysis loop — risk, intel, remediation, compliance — on demand or on repeat.",
    info: "AI Buddies output structured data directly into the Risk, Threat, Compliance, and Remediation registers. The Orchestrator runs all four in sequence from one trigger.",
    cards: [
      { name: "AI Buddies",       desc: "60+ AI agents — orchestrator, risk, threat intel, and remediation planner.",    route: "/automate/agents",        group: "AI Agents" },
      { name: "AI Workflows",     desc: "Multi-agent workflow missions and automated analysis pipelines.",                route: "/automate/workflows",     group: "AI Agents" },
      { name: "AI Assisted Scan", desc: "Conversational guided assessment — describe the environment, AI configures.",   route: "/automate/ai-scan",       group: "AI Agents" },
      { name: "Knowledge Base",   desc: "Platform knowledge base and Aegis reference documentation.",                   route: "/automate/knowledge",     group: "Knowledge" },
      { name: "Reports",          desc: "AI-generated security posture and trend reports.",                              route: "/automate/reports",       group: "Knowledge" },
      { name: "Ask Your Data",    desc: "SQL-backed natural language queries over all your data.",                       route: "/automate/nl-query",      group: "Knowledge" },
      { name: "AI Guardrails",    desc: "AI safety controls, prompt audit logs, and guardrail coverage.",                route: "/automate/ai-guardrails", group: "Knowledge" },
      { name: "Webhooks",         desc: "Event-driven alerts on critical findings and completed scans.",                 route: "/automate/webhooks",      group: "Knowledge" },
      { name: "API Keys",         desc: "M2M API keys for CI/CD pipelines and programmatic access.",                    route: "/automate/api-keys",      group: "Knowledge" },
    ],
  },
];

// ── HubCard ───────────────────────────────────────────────────────────────────

function HubCard({ card, color }: { card: CardDef; color: string }) {
  const navigate = useNavigate();
  return (
    <Box
      onClick={() => navigate(card.route)}
      sx={{
        bgcolor: "background.paper",
        border: "1px solid", borderColor: "divider",
        borderTop: `3px solid ${color}`,
        borderRadius: 2, p: 1.75, cursor: "pointer",
        display: "flex", flexDirection: "column", gap: 0.75,
        minHeight: 94,
        transition: "box-shadow .15s, transform .12s",
        "&:hover": {
          transform: "translateY(-1px)",
          boxShadow: `0 4px 14px rgba(0,0,0,0.08)`,
        },
      }}
    >
      <Typography sx={{ fontWeight: 700, fontSize: 13, lineHeight: 1.3, color: "text.primary" }}>
        {card.name}
      </Typography>
      <Typography sx={{ fontSize: 11.5, color: "text.secondary", lineHeight: 1.5, flex: 1 }}>
        {card.desc}
      </Typography>
      <Typography sx={{ fontSize: 11, color: "text.secondary", fontWeight: 600, textAlign: "right" }}>
        Manage →
      </Typography>
    </Box>
  );
}

// ── Stage TOC sidebar ─────────────────────────────────────────────────────────

function StageToc({ activeId }: { activeId: string | null }) {
  return (
    <Box sx={{ position: "sticky", top: 24, display: "flex", flexDirection: "column", gap: 0 }}>
      {STAGE_DEFS.map((stage, si) => {
        const isActive = stage.id === activeId;
        const isLast = si === STAGE_DEFS.length - 1;
        return (
          <Box key={stage.id}>
            <Box
              onClick={() => {
                const el = document.getElementById(`stage-${stage.id}`);
                el?.scrollIntoView({ behavior: "smooth", block: "start" });
              }}
              sx={{
                display: "flex", alignItems: "center", gap: 1.25,
                px: 1.25, py: 0.75, borderRadius: 2, cursor: "pointer",
                bgcolor: isActive ? "background.paper" : "transparent",
                boxShadow: isActive ? "0 1px 4px rgba(32,38,31,0.08), 0 4px 12px rgba(32,38,31,0.06)" : "none",
                transition: "background .15s, box-shadow .15s",
                "&:hover": { bgcolor: isActive ? "background.paper" : "rgba(32,38,31,0.04)" },
              }}
            >
              <Box sx={{
                width: 30, height: 30, borderRadius: 1.5, flexShrink: 0,
                bgcolor: stage.color, color: "#fff",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 13, fontWeight: 700,
              }}>
                {parseInt(stage.num, 10)}
              </Box>
              <Typography sx={{ fontWeight: 600, fontSize: 13, color: "text.primary", flex: 1, lineHeight: 1 }}>
                {stage.label}
              </Typography>
              <Typography sx={{ fontSize: 12, color: "text.secondary", fontWeight: 400, minWidth: 20, textAlign: "right" }}>
                {stage.cards.length}
              </Typography>
            </Box>
            {!isLast && (
              <Box sx={{ ml: "22px", width: 2, height: 10, borderLeft: "2px dashed", borderColor: "divider" }} />
            )}
          </Box>
        );
      })}
    </Box>
  );
}

// ── StageSection ──────────────────────────────────────────────────────────────

function StageSection({ stage, si }: { stage: StageDef; si: number }) {
  const navigate = useNavigate();
  return (
    <Box
      id={`stage-${stage.id}`}
      sx={{
        position: "relative", pl: "64px",
        mb: si < STAGE_DEFS.length - 1 ? 7 : 0,
        scrollMarginTop: 24,
        opacity: 0, transform: "translateY(12px)",
        animation: `hubrise 0.5s ease ${si * 0.07}s forwards`,
        "@keyframes hubrise": { to: { opacity: 1, transform: "translateY(0)" } },
      }}
    >
      {/* Circle node */}
      <Box sx={{
        position: "absolute", left: 0, top: 0,
        width: 48, height: 48, borderRadius: "50%",
        bgcolor: "background.default",
        border: `2px solid ${stage.color}`,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontFamily: "monospace", fontWeight: 700, fontSize: "1rem",
        color: stage.color,
        boxShadow: `0 0 18px -4px ${stage.color}60`,
        zIndex: 2,
      }}>
        {stage.num}
      </Box>

      {/* Stage header */}
      <Box sx={{ pt: "4px", mb: 2.5 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.75 }}>
          <Box sx={{ width: 4, height: 16, borderRadius: 2, bgcolor: stage.color }} />
          <Typography
            onClick={() => navigate(stage.path)}
            sx={{
              fontSize: "0.71rem", fontWeight: 700, color: stage.color,
              textTransform: "uppercase", letterSpacing: "0.1em",
              cursor: "pointer",
              "&:hover": { textDecoration: "underline" },
            }}
          >
            Stage {stage.num} · {stage.label}
          </Typography>
        </Box>
        <Typography sx={{
          fontFamily: "'Space Grotesk', sans-serif",
          fontSize: { xs: 20, md: 26 }, fontWeight: 700, letterSpacing: "-0.02em", mb: 0.75,
        }}>
          {stage.title}
        </Typography>
        <Typography sx={{ color: "text.secondary", fontSize: "0.88rem", maxWidth: 560, lineHeight: 1.6, mb: 2 }}>
          {stage.sub}
        </Typography>
        {/* Info callout */}
        <Box sx={{
          display: "flex", alignItems: "flex-start", gap: 1.5,
          bgcolor: alpha(stage.color, 0.06),
          border: "1px solid", borderColor: alpha(stage.color, 0.2),
          borderRadius: 1.5, px: 2, py: 1.25,
        }}>
          <InfoOutlined sx={{ color: stage.color, fontSize: 15, mt: "2px", flexShrink: 0 }} />
          <Typography sx={{ fontSize: 12.5, color: "text.secondary", lineHeight: 1.55 }}>{stage.info}</Typography>
        </Box>
      </Box>

      {/* Cards grouped with labeled dividers */}
      {(() => {
        const groups: Array<{ name: string; cards: CardDef[] }> = [];
        for (const card of stage.cards) {
          const g = card.group ?? "";
          if (groups.length === 0 || groups[groups.length - 1].name !== g) {
            groups.push({ name: g, cards: [] });
          }
          groups[groups.length - 1].cards.push(card);
        }
        return groups.map((g, gi) => (
          <Box key={g.name || gi}>
            {/* Group label + rule */}
            {g.name && (
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1.25, mt: gi > 0 ? 2.5 : 0 }}>
                <Typography sx={{
                  fontSize: 9.5, fontWeight: 700, letterSpacing: "0.12em",
                  textTransform: "uppercase", color: "text.disabled", whiteSpace: "nowrap",
                }}>
                  {g.name}
                </Typography>
                <Box sx={{ flex: 1, height: "1px", bgcolor: "divider" }} />
              </Box>
            )}
            <Box sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr", md: "repeat(4, 1fr)" },
              gap: 1.5,
            }}>
              {g.cards.map((card) => (
                <HubCard key={card.name} card={card} color={stage.color} />
              ))}
            </Box>
          </Box>
        ));
      })()}
    </Box>
  );
}

// ── Ontology mini-map ─────────────────────────────────────────────────────────

interface ONode { entity: string; label: string; cx: number; cy: number; labelX: number; labelW: number; color: string }
interface OEdge { from: string; to: string; x1: number; y1: number; x2: number; y2: number; dashed?: boolean }

const ONT_NODES: ONode[] = [
  { entity:"Account",     label:"Account",            cx: 70,  cy:300, labelX: 35,   labelW: 70,  color:"#2563eb" },
  { entity:"Asset",       label:"Asset",              cx:250,  cy:190, labelX:215,   labelW: 70,  color:"#2563eb" },
  { entity:"Control",     label:"Control",            cx:250,  cy:470, labelX:213.5, labelW: 73,  color:"#7c3aed" },
  { entity:"DataFlow",    label:"Data Flow",          cx:440,  cy: 90, labelX:396.5, labelW: 87,  color:"#7c3aed" },
  { entity:"Finding",     label:"Finding",            cx:440,  cy:280, labelX:403.5, labelW: 73,  color:"#0f766e" },
  { entity:"SmartIntel",  label:"Smart Intelligence", cx:440,  cy:560, labelX:365,   labelW:150,  color:"#4338ca" },
  { entity:"Risk",        label:"Risk",               cx:640,  cy:220, labelX:605,   labelW: 70,  color:"#b45309" },
  { entity:"Evidence",    label:"Evidence",           cx:640,  cy:470, labelX:600,   labelW: 80,  color:"#15803d" },
  { entity:"AttackPath",  label:"Attack Path",        cx:830,  cy:130, labelX:779.5, labelW:101,  color:"#b45309" },
  { entity:"Technique",   label:"MITRE Technique",    cx:830,  cy:300, labelX:765.5, labelW:129,  color:"#b91c1c" },
  { entity:"Remediation", label:"Remediation",        cx:830,  cy:420, labelX:779.5, labelW:101,  color:"#b91c1c" },
  { entity:"Audit",       label:"Audit",              cx:1020, cy:300, labelX:985,   labelW: 70,  color:"#15803d" },
];
const ONT_EDGES: OEdge[] = [
  { from:"Account",     to:"Asset",       x1: 70, y1:300, x2:250,  y2:190 },
  { from:"Asset",       to:"DataFlow",    x1:250, y1:190, x2:440,  y2: 90 },
  { from:"Asset",       to:"Finding",     x1:250, y1:190, x2:440,  y2:280 },
  { from:"Finding",     to:"Risk",        x1:440, y1:280, x2:640,  y2:220 },
  { from:"Risk",        to:"AttackPath",  x1:640, y1:220, x2:830,  y2:130 },
  { from:"DataFlow",    to:"Technique",   x1:440, y1: 90, x2:830,  y2:300 },
  { from:"AttackPath",  to:"Technique",   x1:830, y1:130, x2:830,  y2:300 },
  { from:"Risk",        to:"Remediation", x1:640, y1:220, x2:830,  y2:420 },
  { from:"Technique",   to:"Remediation", x1:830, y1:300, x2:830,  y2:420 },
  { from:"Control",     to:"Evidence",    x1:250, y1:470, x2:640,  y2:470 },
  { from:"Remediation", to:"Evidence",    x1:830, y1:420, x2:640,  y2:470 },
  { from:"Finding",     to:"Audit",      x1:440, y1:280, x2:1020, y2:300 },
  { from:"Remediation", to:"Audit",      x1:830, y1:420, x2:1020, y2:300 },
  { from:"Evidence",    to:"Audit",      x1:640, y1:470, x2:1020, y2:300 },
  { from:"SmartIntel",  to:"Asset",       x1:440, y1:560, x2:250,  y2:190, dashed:true },
  { from:"SmartIntel",  to:"Finding",     x1:440, y1:560, x2:440,  y2:280, dashed:true },
  { from:"SmartIntel",  to:"Risk",        x1:440, y1:560, x2:640,  y2:220, dashed:true },
  { from:"SmartIntel",  to:"Control",     x1:440, y1:560, x2:250,  y2:470, dashed:true },
];
const ONT_ROUTES: Record<string, string> = {
  Client:"platform/clients", Asset:"platform/assets", Control:"compliance/frameworks",
  DataFlow:"threat-intel/threat-models", Finding:"vulnerability/findings",
  SmartIntel:"intelligence/nl-query", Risk:"risk/register",
  Evidence:"compliance/evidence", AttackPath:"threat-intel/attack-paths",
  Technique:"threat-intel/register", Remediation:"governance/remediation",
  Report:"vapt/reports",
};

const SEV_COLOR: Record<string, string> = {
  critical: "#b91c1c", high: "#ea580c", medium: "#d97706",
  low: "#16a34a", info: "#0284c7",
  critical_risk: "#b91c1c", high_risk: "#ea580c", medium_risk: "#d97706", low_risk: "#16a34a",
};
function severityColor(k: string) { return SEV_COLOR[k] ?? "#6b7280"; }

interface StatData {
  total: number;
  breakdown: Record<string, number>;
  key: string;
  status?: Record<string, number>;
}

function OntologyStatPanel({ entity, stats, color, route }: {
  entity: string; stats: StatData; color: string; route: string;
}) {
  const navigate = useNavigate();
  const breakdownEntries = Object.entries(stats.breakdown).filter(([, v]) => v > 0).sort(([, a], [, b]) => b - a);
  const maxVal = Math.max(...breakdownEntries.map(([, v]) => v), 1);

  return (
    <Box sx={{
      width: 260, flexShrink: 0, border: "1px solid", borderColor: "divider",
      borderRadius: 2, bgcolor: "background.paper", p: 2,
      display: "flex", flexDirection: "column", gap: 1.5,
    }}>
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <Box sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: color }} />
          <Typography sx={{ fontWeight: 700, fontSize: 14, textTransform: "capitalize" }}>{entity}</Typography>
        </Box>
        <Typography sx={{ fontSize: 22, fontWeight: 800, color, lineHeight: 1 }}>{stats.total}</Typography>
      </Box>
      <Divider />
      {breakdownEntries.length > 0 ? (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
          {breakdownEntries.map(([k, v]) => (
            <Box key={k}>
              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.25 }}>
                <Typography sx={{ fontSize: 11, color: "text.secondary", textTransform: "capitalize" }}>{k}</Typography>
                <Typography sx={{ fontSize: 11, fontWeight: 600 }}>{v}</Typography>
              </Box>
              <Box sx={{ height: 5, borderRadius: 3, bgcolor: "action.hover", overflow: "hidden" }}>
                <Box sx={{ height: "100%", borderRadius: 3, bgcolor: severityColor(k), width: `${Math.round((v / maxVal) * 100)}%`, transition: "width 0.4s ease" }} />
              </Box>
            </Box>
          ))}
        </Box>
      ) : (
        <Typography sx={{ fontSize: 12, color: "text.disabled", textAlign: "center", py: 1 }}>No data</Typography>
      )}
      {stats.status && Object.keys(stats.status).length > 0 && (
        <>
          <Divider />
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
            {Object.entries(stats.status).filter(([, v]) => v > 0).map(([k, v]) => (
              <Chip key={k} label={`${k}: ${v}`} size="small" sx={{ fontSize: 10, height: 20, bgcolor: "action.hover" }} />
            ))}
          </Box>
        </>
      )}
      <Divider />
      <Box
        onClick={() => navigate(`/${route}`)}
        sx={{ fontSize: 12, color: "primary.main", cursor: "pointer", textAlign: "center", py: 0.5, borderRadius: 1, "&:hover": { bgcolor: alpha(color, 0.08) } }}
      >
        View all {entity}s →
      </Box>
    </Box>
  );
}

function OntologyMini() {
  const theme = useTheme();
  const navigate = useNavigate();
  const { clientId } = useActiveClient();
  const [sel, setSel] = useState<string | null>(null);
  const isDark = theme.palette.mode === "dark";
  const edgeCol  = isDark ? "#3a4250" : "#c3c9d4";
  const raisedBg = isDark ? "#141b25" : "#f2f4f8";
  const lineBdr  = isDark ? "#232b36" : "#e6e9ef";

  const { data: statsRaw, isLoading } = useQuery({
    queryKey: ["ontology-stats", clientId],
    queryFn: () => clientId ? dataModelApi.stats(clientId) : Promise.resolve(null),
    enabled: !!clientId,
    staleTime: 60_000,
  });

  const stats: Record<string, StatData> = statsRaw ?? {};

  const ENTITY_STAT_KEY: Record<string, string> = {
    Asset: "asset", Finding: "finding", Risk: "risk",
    Control: "control", Remediation: "remediation",
    Technique: "technique", Report: "report",
    SmartIntel: "finding", DataFlow: "asset", AttackPath: "risk", Evidence: "report",
    Client: "asset",
  };

  function nodeCount(entity: string): number | null {
    const key = ENTITY_STAT_KEY[entity];
    return key && stats[key] ? stats[key].total : null;
  }

  function edgeWeightFromStats(e: OEdge): number {
    const fk = ENTITY_STAT_KEY[e.from]; const tk = ENTITY_STAT_KEY[e.to];
    if (!fk || !tk) return 1.4;
    const fc = stats[fk] ? stats[fk].total : 0;
    const tc = stats[tk] ? stats[tk].total : 0;
    if (!fc && !tc) return 1.4;
    const allTotals = Object.values(stats).map((s: StatData) => s?.total ?? 0);
    const maxCount = Math.max(...allTotals, 1);
    const norm = Math.log1p(Math.min(fc || maxCount, tc || maxCount)) / Math.log1p(maxCount);
    return 1.4 + norm * 4.5;
  }

  function nodeHealthColorMini(entity: string): string | null {
    const key = ENTITY_STAT_KEY[entity];
    if (!key || !stats[key] || !stats[key].total) return null;
    const bd = (stats[key] as any).breakdown ?? {};
    if (key === "finding") {
      if ((bd.critical ?? 0) > 0) return "#ef4444";
      if ((bd.high ?? 0) > 0) return "#f97316";
      return "#22c55e";
    }
    if (key === "risk") {
      if ((bd.critical ?? 0) > 0) return "#ef4444";
      if ((bd.high ?? 0) > 0) return "#f97316";
      return "#22c55e";
    }
    if (key === "remediation") {
      return ((bd.open ?? 0) + (bd.in_progress ?? 0)) > 0 ? "#f59e0b" : "#22c55e";
    }
    if (key === "technique") {
      return (bd.critical ?? 0) + (bd.high ?? 0) > 0 ? "#ef4444" : "#f59e0b";
    }
    return stats[key].total > 0 ? "#22c55e" : null;
  }

  const eStyle = (e: OEdge) => {
    const hit = sel && (e.from === sel || e.to === sel);
    const dim = sel && !hit;
    return { stroke: hit ? "#4338ca" : edgeCol, strokeWidth: hit ? 2.4 : edgeWeightFromStats(e), opacity: dim ? 0.1 : 1, strokeDasharray: e.dashed ? "3 4" : undefined };
  };

  const selNode = ONT_NODES.find(n => n.entity === sel);
  const selStatKey = sel ? ENTITY_STAT_KEY[sel] : null;
  const selStats = selStatKey ? stats[selStatKey] : null;

  return (
    <Box sx={{ mt: 6, pt: 5, borderTop: "1px solid", borderColor: "divider" }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.75 }}>
        <Box sx={{ width: 4, height: 20, borderRadius: 2, bgcolor: "#4338ca" }} />
        <Typography sx={{ fontWeight: 700, fontSize: 15 }}>Data Ontology</Typography>
        {isLoading && <CircularProgress size={14} sx={{ ml: 1 }} />}
      </Box>
      <Typography sx={{ fontSize: 13, color: "text.secondary", mb: 2.5, maxWidth: 600 }}>
        Live entity counts across your security data. Click any node to see the breakdown.
      </Typography>

      <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
        <Box sx={{ flex: 1, bgcolor: "background.paper", border: "1px solid", borderColor: "divider", borderRadius: 2, p: 2.5, overflowX: "auto", minWidth: 0 }}>
          <svg viewBox="0 0 1120 640" style={{ width: "100%", minWidth: 480, height: "auto", display: "block" }}>
            <defs>
              <marker id="ont-a"   viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill={edgeCol}/></marker>
              <marker id="ont-lit" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#4338ca"/></marker>
            </defs>
            <g>
              {ONT_EDGES.map((e, i) => {
                const s = eStyle(e);
                const lit = sel && (e.from === sel || e.to === sel);
                return <line key={i} x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2} stroke={s.stroke} strokeWidth={s.strokeWidth} opacity={s.opacity} strokeDasharray={s.strokeDasharray} markerEnd={lit ? "url(#ont-lit)" : "url(#ont-a)"} style={{ transition: "stroke 0.2s, opacity 0.2s" }} />;
              })}
            </g>
            <g>
              {ONT_NODES.map((n) => {
                const lit = sel === n.entity;
                const dim = !!sel && !lit;
                const cnt = nodeCount(n.entity);
                return (
                  <Tooltip key={n.entity} title={cnt !== null ? `${n.label}: ${cnt} total` : n.label} placement="top">
                    <g style={{ cursor: "pointer", opacity: dim ? 0.2 : 1, transition: "opacity 0.18s" }}
                       onClick={() => setSel((p) => p === n.entity ? null : n.entity)}
                       onDoubleClick={() => navigate(`/${ONT_ROUTES[n.entity] ?? ""}`)}
                    >
                      {nodeHealthColorMini(n.entity) && (
                        <circle cx={n.cx} cy={n.cy} r={lit ? 18 : 14} fill="none"
                          stroke={nodeHealthColorMini(n.entity)!} strokeWidth={2.5} opacity={0.5}
                          style={{transition:"r 0.15s"}}/>
                      )}
                      <circle cx={n.cx} cy={n.cy} r={lit ? 12 : 9} fill={n.color} stroke={isDark ? "#0b0f14" : "#fff"} strokeWidth={2} style={{ transition: "r 0.15s" }} />
                      {cnt !== null && cnt > 0 && (
                        <text x={n.cx} y={n.cy} textAnchor="middle" dominantBaseline="middle"
                          fontFamily="monospace" fontSize={cnt > 99 ? 7 : 9} fontWeight={700} fill="#fff">
                          {cnt > 999 ? "999+" : cnt}
                        </text>
                      )}
                      <rect x={n.labelX} y={n.cy+14} width={n.labelW} height={22} rx={11} fill={lit ? n.color : raisedBg} stroke={lit ? n.color : lineBdr} strokeWidth={1} style={{ transition: "fill 0.15s" }} />
                      <text x={n.cx} y={n.cy+29} textAnchor="middle" dominantBaseline="middle" fontFamily="monospace" fontSize={11} fontWeight={lit ? 600 : 500} fill={lit ? "#fff" : theme.palette.text.primary} style={{ transition: "fill 0.15s" }}>
                        {n.label}
                      </text>
                    </g>
                  </Tooltip>
                );
              })}
            </g>
          </svg>

          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, mt: 2, pt: 2, borderTop: "1px solid", borderColor: "divider", alignItems: "center" }}>
            {STAGE_DEFS.map((s) => (
              <Box key={s.id} sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                <Box sx={{ width: 9, height: 9, borderRadius: "50%", bgcolor: s.color }} />
                <Typography sx={{ fontSize: 11, color: "text.secondary" }}>{s.label.toLowerCase()}</Typography>
              </Box>
            ))}
            <Box onClick={() => navigate("/data-model")} sx={{
              ml: "auto", fontSize: 12, color: "primary.main",
              border: "1px solid", borderColor: "divider", px: 1.5, py: 0.5, borderRadius: "20px", cursor: "pointer",
              "&:hover": { bgcolor: alpha("#1565C0", 0.06) },
            }}>
              Relationship Explorer →
            </Box>
          </Box>
        </Box>

        {sel && selNode && selStats && (
          <OntologyStatPanel entity={selStatKey ?? sel} stats={selStats} color={selNode.color} route={ONT_ROUTES[sel] ?? ""} />
        )}
      </Box>
    </Box>
  );
}

// ── Main Hub ──────────────────────────────────────────────────────────────────

export default function Hub() {

  const RAIL = "linear-gradient(180deg,#2563eb,#0f766e 25%,#b45309 50%,#b91c1c 65%,#15803d 80%,#4338ca)";

  const [activeTocId, setActiveTocId] = useState<string | null>(STAGE_DEFS[0]?.id ?? null);

  useEffect(() => {
    const observers: IntersectionObserver[] = [];
    STAGE_DEFS.forEach((stage) => {
      const el = document.getElementById(`stage-${stage.id}`);
      if (!el) return;
      const obs = new IntersectionObserver(
        ([entry]) => { if (entry.isIntersecting) setActiveTocId(stage.id); },
        { rootMargin: "-20% 0px -60% 0px", threshold: 0 }
      );
      obs.observe(el);
      observers.push(obs);
    });
    return () => observers.forEach(o => o.disconnect());
  }, []);

  return (
    <>
      <Box sx={{ display: "flex", flexDirection: "column", minHeight: "100vh", bgcolor: "background.default" }}>

        {/* Top bar */}
        <Box sx={{
          position: "sticky", top: 0, zIndex: 1200,
          bgcolor: "background.paper",
          borderBottom: "1px solid", borderColor: "divider",
          height: 52,
        }}>
          <MegaMenuBar brand={<OwletLogo height={32} />} trailing={<AppControls />} />
        </Box>

        {/* Main content */}
        <Box sx={{ flex: 1, overflow: "auto" }}>
          <Box sx={{ display: "flex", maxWidth: 1340, mx: "auto", px: { xs: 2, md: 4 }, py: { xs: 4, md: 6 }, gap: 4 }}>

            {/* Stage TOC sidebar — hidden on small screens */}
            <Box sx={{ width: 180, flexShrink: 0, display: { xs: "none", lg: "block" } }}>
              <StageToc activeId={activeTocId} />
            </Box>

            {/* Main pipeline content */}
            <Box sx={{ flex: 1, minWidth: 0, pb: 12 }}>

              {/* Hero */}
              <Box sx={{ mb: 7 }}>
                <Typography sx={{
                  fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700,
                  fontSize: { xs: 28, md: 42 }, letterSpacing: "-0.02em", lineHeight: 1.1, mb: 1.5,
                }}>
                  One{" "}
                  <Box component="span" sx={{ background: RAIL, WebkitBackgroundClip: "text", backgroundClip: "text", color: "transparent" }}>
                    signal path
                  </Box>
                  , from setup to evidence.
                </Typography>
                <Typography sx={{ color: "text.secondary", fontSize: "0.97rem", maxWidth: 560 }}>
                  Six stages run in order — each hands its output to the next. Hover the nav above to jump anywhere, or click a card below.
                </Typography>
              </Box>

              {/* Pipeline */}
              <Box sx={{ position: "relative" }}>
                {/* Vertical rail */}
                <Box sx={{ position: "absolute", left: 23, top: 14, bottom: 14, width: 2, background: RAIL, opacity: 0.35 }} />

                {STAGE_DEFS.map((stage, si) => (
                  <StageSection key={stage.id} stage={stage} si={si} />
                ))}
              </Box>

              {/* Ontology */}
              <OntologyMini />

              {/* Footer */}
              <Box sx={{ mt: 8, pt: 3, borderTop: "1px solid", borderColor: "divider", display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 1 }}>
                <Typography sx={{ fontSize: "0.72rem", color: "text.disabled", fontFamily: "monospace" }}>
                  SETUP · DISCOVER · ANALYSE · RESPOND · REPORT · AUTOMATE
                </Typography>
                <Typography sx={{ fontSize: "0.72rem", color: "text.disabled", fontFamily: "monospace" }}>
                  Owlet · NexGenAI
                </Typography>
              </Box>

            </Box>
          </Box>
        </Box>
      </Box>
      <AssistantWidget />
    </>
  );
}
