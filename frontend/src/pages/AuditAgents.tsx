import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Alert, Box, Button, Card, CardContent, Chip, CircularProgress,
  Divider, LinearProgress, Paper,
  Step, StepLabel, Stepper, Table, TableBody, TableCell,
  TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import {
  Assignment, CheckCircle, ContentCopy, FindInPage, ManageSearch,
  PlayArrow, Psychology, VerifiedUser,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useActiveClient } from "../contexts/ClientContext";
import { auditAgentsApi, frameworksApi } from "../services/api";

// Standard frameworks always available — no API dependency
// API returns { framework, name } (FrameworkCatalogEntry shape)
const STATIC_FRAMEWORKS: { framework: string; name: string; is_custom?: boolean }[] = [
  { framework: "nist_csf",          name: "NIST CSF 2.0" },
  { framework: "nist_800_53",       name: "NIST 800-53" },
  { framework: "nist_ai_rmf",       name: "NIST AI RMF 1.0" },
  { framework: "nist_ai_200_1",     name: "NIST AI 200-1" },
  { framework: "nist_ai_200_2",     name: "NIST AI 200-2" },
  { framework: "iso_27001",         name: "ISO 27001:2022" },
  { framework: "pci_dss",           name: "PCI DSS 4.0" },
  { framework: "gdpr",              name: "GDPR" },
  { framework: "soc2",              name: "SOC 2" },
  { framework: "gcc_im8",           name: "GCC IM8 Reform 2025" },
  { framework: "mas_trm",           name: "MAS TRM" },
  { framework: "cis_v8",            name: "CIS Controls v8" },
  { framework: "hipaa",             name: "HIPAA" },
  { framework: "fedramp",           name: "FedRAMP" },
  { framework: "cyber_essentials",  name: "Cyber Essentials" },
  { framework: "cis_azure",         name: "CIS Azure" },
  { framework: "cis_aws",           name: "CIS AWS" },
  { framework: "cis_gcp",           name: "CIS GCP" },
];

// ── Agent definitions ──────────────────────────────────────────────────────────

type StepType = "chips" | "framework_select" | "domain_chips" | "free_text";

interface WizardStep {
  label: string;
  question: string;
  type: StepType;
  key: string;
  multi?: boolean;
  required?: boolean;
  options?: string[];
  placeholder?: string;
}

interface AgentDef {
  id: string;
  name: string;
  desc: string;
  color: string;
  icon: React.ReactNode;
  steps: WizardStep[];
}

const AGENTS: AgentDef[] = [
  {
    id: "control_tester",
    name: "Control Tester",
    desc: "Tests specific framework controls against your existing findings and deficiencies.",
    color: "#4285F4",
    icon: <FindInPage />,
    steps: [
      {
        label: "Purpose", question: "What is this assessment for?", type: "chips",
        key: "assessment_purpose", required: true,
        options: ["Internal Audit", "External Certification", "Regulatory Review", "Management Review", "Self-Assessment"],
      },
      {
        label: "Framework", question: "Select the compliance framework to test against",
        type: "framework_select", key: "framework", required: true,
      },
      {
        label: "Domains", question: "Which domains do you want to test?",
        type: "domain_chips", key: "domains", multi: true, required: false,
      },
      {
        label: "Depth", question: "How thorough should the testing be?", type: "chips",
        key: "depth", required: true,
        options: ["Quick Scan (key controls only)", "Standard (all controls)", "Deep Dive (with evidence tracing)"],
      },
    ],
  },
  {
    id: "readiness_report",
    name: "Readiness Report",
    desc: "Domain-level readiness score, gap analysis, and timeline risk rating.",
    color: "#34A853",
    icon: <VerifiedUser />,
    steps: [
      {
        label: "Framework", question: "Select the framework for the readiness assessment",
        type: "framework_select", key: "framework", required: true,
      },
      {
        label: "Timeline", question: "What is your audit timeline?", type: "chips",
        key: "timeline", required: true,
        options: ["Within 30 days", "1–3 months", "3–6 months", "6–12 months", "Planning ahead"],
      },
      {
        label: "Domains", question: "Which domains are in scope? (leave empty for all)",
        type: "domain_chips", key: "domains", multi: true, required: false,
      },
      {
        label: "Focus", question: "What should the report prioritise?", type: "chips",
        key: "focus", required: true,
        options: ["Critical gaps only", "All gaps with fixes", "Quick wins first", "Score + timeline view"],
      },
    ],
  },
  {
    id: "evidence_curator",
    name: "Evidence Curator",
    desc: "Organises findings, risks and deficiencies into a framework-mapped evidence pack.",
    color: "#FBBC04",
    icon: <Assignment />,
    steps: [
      {
        label: "Audit type", question: "What type of audit are you preparing evidence for?", type: "chips",
        key: "audit_type", required: true,
        options: ["Annual Compliance Review", "External Certification Audit", "Regulatory Inspection", "Incident Review", "Management Reporting"],
      },
      {
        label: "Framework", question: "Select the framework or standard",
        type: "framework_select", key: "framework", required: true,
      },
      {
        label: "Date range", question: "What date range should evidence cover?", type: "chips",
        key: "date_range", required: true,
        options: ["Last 30 days", "Last 90 days", "Last 6 months", "Last 12 months"],
      },
      {
        label: "Severities", question: "Which finding severities to include?", type: "chips",
        key: "severities", multi: true, required: true,
        options: ["Critical", "High", "Medium", "Low"],
      },
    ],
  },
  {
    id: "interview_prep",
    name: "Interview Prep",
    desc: "Prepares a structured response and evidence refs for an auditor question.",
    color: "#9C27B0",
    icon: <Psychology />,
    steps: [
      {
        label: "Domain", question: "What audit domain is the question about?", type: "chips",
        key: "domain_topic", required: true,
        options: [
          "Access Control & Identity", "Incident Response", "Data Protection & Privacy",
          "Network & Infrastructure", "Change Management", "Business Continuity",
          "Vulnerability Management", "Audit Logging & Monitoring", "Third-Party Risk", "Cloud Security",
        ],
      },
      {
        label: "Framework", question: "Framework being audited against?",
        type: "framework_select", key: "framework", required: true,
      },
      {
        label: "Question type", question: "What type of question will the auditor ask?", type: "chips",
        key: "question_type", required: true,
        options: [
          "Policy existence (\"Do you have a policy for X?\")",
          "Evidence request (\"Show me evidence of X\")",
          "Process walkthrough (\"Walk me through how you do X\")",
          "Gap / incident (\"What happened when X failed?\")",
          "Future plans (\"What are you doing about X?\")",
        ],
      },
      {
        label: "Focus", question: "Any specific aspect to focus on?", type: "free_text",
        key: "focus_aspect", required: false, placeholder: "e.g. privileged access, encryption at rest",
      },
    ],
  },
];

// ── Helpers ────────────────────────────────────────────────────────────────────

const VERDICT_COLORS: Record<string, string> = {
  pass: "#34A853", partial: "#FBBC04", fail: "#EA4335", no_data: "#9e9e9e",
};
const STRENGTH_COLORS: Record<string, string> = {
  strong: "#34A853", adequate: "#FBBC04", weak: "#FF7043", missing: "#EA4335",
};
const TIMELINE_COLORS: Record<string, string> = { low: "#34A853", medium: "#FBBC04", high: "#EA4335" };
const STATUS_COLORS: Record<string, string> = {
  "on-track": "#34A853", "at-risk": "#FBBC04", critical: "#EA4335",
};

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => undefined);
}

// ── Chip selector ──────────────────────────────────────────────────────────────

function ChipSelector({
  options, value, multi, color, onChange,
}: {
  options: string[];
  value: string | string[];
  multi?: boolean;
  color: string;
  onChange: (v: string | string[]) => void;
}) {
  const selected = Array.isArray(value) ? value : value ? [value] : [];

  const toggle = (opt: string) => {
    if (multi) {
      const next = selected.includes(opt) ? selected.filter((s) => s !== opt) : [...selected, opt];
      onChange(next);
    } else {
      onChange(selected.includes(opt) ? "" : opt);
    }
  };

  return (
    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1.5, mt: 1 }}>
      {options.map((opt) => {
        const active = selected.includes(opt);
        return (
          <Chip
            key={opt}
            label={opt}
            onClick={() => toggle(opt)}
            variant={active ? "filled" : "outlined"}
            sx={{
              fontSize: 13,
              px: 0.5,
              cursor: "pointer",
              bgcolor: active ? `${color}22` : "transparent",
              borderColor: active ? color : "rgba(255,255,255,0.2)",
              color: active ? color : "text.secondary",
              fontWeight: active ? 700 : 400,
              "&:hover": { borderColor: color, color },
            }}
          />
        );
      })}
    </Box>
  );
}

// ── Results renderers ──────────────────────────────────────────────────────────

function ControlTesterResults({ result }: { result: Record<string, unknown> }) {
  const summary = (result.summary || {}) as Record<string, unknown>;
  const controls = (result.controls || []) as Record<string, unknown>[];

  return (
    <Box>
      <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2 }}>
        {["pass", "partial", "fail", "no_data"].map((v) => (
          <Chip
            key={v}
            label={`${String(summary[v] || 0)} ${v.replace("_", " ")}`}
            sx={{ bgcolor: `${VERDICT_COLORS[v]}22`, color: VERDICT_COLORS[v], fontWeight: 700 }}
          />
        ))}
        <Chip label={`Total: ${String(summary.total || 0)}`} variant="outlined" />
      </Box>
      <Box sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              {["Domain", "Control", "Title", "Verdict", "Evidence", "Gaps", "Recommendation"].map((h) => (
                <TableCell key={h} sx={{ fontWeight: 700, whiteSpace: "nowrap" }}>{h}</TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {controls.map((c, i) => {
              const verdict = String(c.verdict || "no_data");
              return (
                <TableRow key={i} hover>
                  <TableCell sx={{ fontSize: 12, whiteSpace: "nowrap" }}>{String(c.domain || "")}</TableCell>
                  <TableCell sx={{ fontSize: 12, fontFamily: "monospace", whiteSpace: "nowrap" }}>{String(c.control_id || "")}</TableCell>
                  <TableCell sx={{ fontSize: 12, maxWidth: 200 }}>{String(c.title || "")}</TableCell>
                  <TableCell>
                    <Chip
                      label={verdict}
                      size="small"
                      sx={{ bgcolor: `${VERDICT_COLORS[verdict] || "#9e9e9e"}22`, color: VERDICT_COLORS[verdict] || "#9e9e9e", fontWeight: 700, fontSize: 11 }}
                    />
                  </TableCell>
                  <TableCell sx={{ fontSize: 12, maxWidth: 180 }}>{String(c.evidence_summary || "")}</TableCell>
                  <TableCell sx={{ fontSize: 12, maxWidth: 160 }}>
                    {Array.isArray(c.gaps) ? c.gaps.map((g, gi) => (
                      <Typography key={gi} sx={{ fontSize: 11, color: "text.secondary" }}>• {String(g)}</Typography>
                    )) : null}
                  </TableCell>
                  <TableCell sx={{ fontSize: 12, maxWidth: 200 }}>{String(c.recommendation || "")}</TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Box>
    </Box>
  );
}

function ReadinessResults({ result }: { result: Record<string, unknown> }) {
  const score = Number(result.overall_score || 0);
  const tlRisk = String(result.timeline_risk || "medium");
  const domains = (result.domains || []) as Record<string, unknown>[];
  const blockers = (result.critical_blockers || []) as string[];
  const wins = (result.quick_wins || []) as string[];

  const scoreColor = score >= 75 ? "#34A853" : score >= 50 ? "#FBBC04" : "#EA4335";

  return (
    <Box>
      <Box sx={{ display: "flex", gap: 3, alignItems: "center", mb: 3, flexWrap: "wrap" }}>
        <Box sx={{ textAlign: "center" }}>
          <Typography sx={{ fontSize: 56, fontWeight: 800, color: scoreColor, lineHeight: 1 }}>{score}</Typography>
          <Typography sx={{ fontSize: 12, color: "text.secondary" }}>Readiness %</Typography>
        </Box>
        <Box>
          <Typography sx={{ fontSize: 13, mb: 0.5 }}>{String(result.overall_assessment || "")}</Typography>
          <Chip
            label={`Timeline risk: ${tlRisk}`}
            size="small"
            sx={{ bgcolor: `${TIMELINE_COLORS[tlRisk] || "#9e9e9e"}22`, color: TIMELINE_COLORS[tlRisk] || "#9e9e9e", fontWeight: 700 }}
          />
        </Box>
      </Box>

      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, mb: 3 }}>
        {domains.map((d, i) => {
          const ds = String(d.status || "on-track");
          const dScore = Number(d.score || 0);
          return (
            <Paper key={i} elevation={0} sx={{ p: 2, border: "1px solid", borderColor: "divider", minWidth: 200, flex: "1 1 200px" }}>
              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
                <Typography sx={{ fontWeight: 700, fontSize: 13 }}>{String(d.domain || "")}</Typography>
                <Chip label={ds} size="small"
                  sx={{ bgcolor: `${STATUS_COLORS[ds] || "#9e9e9e"}22`, color: STATUS_COLORS[ds] || "#9e9e9e", fontWeight: 700, fontSize: 10 }} />
              </Box>
              <LinearProgress
                variant="determinate"
                value={dScore}
                sx={{ mb: 1, bgcolor: "rgba(255,255,255,0.08)",
                  "& .MuiLinearProgress-bar": { bgcolor: STATUS_COLORS[ds] || "#9e9e9e" } }}
              />
              <Typography sx={{ fontSize: 11, color: "text.secondary" }}>{dScore}% ready</Typography>
              {Array.isArray(d.gaps) && d.gaps.slice(0, 2).map((g, gi) => (
                <Typography key={gi} sx={{ fontSize: 11, color: "#EA4335" }}>• {String(g)}</Typography>
              ))}
            </Paper>
          );
        })}
      </Box>

      <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
        {blockers.length > 0 && (
          <Paper elevation={0} sx={{ p: 2, border: "1px solid #EA433544", flex: "1 1 280px" }}>
            <Typography sx={{ fontWeight: 700, fontSize: 13, color: "#EA4335", mb: 1 }}>Critical Blockers</Typography>
            {blockers.map((b, i) => <Typography key={i} sx={{ fontSize: 12 }}>• {b}</Typography>)}
          </Paper>
        )}
        {wins.length > 0 && (
          <Paper elevation={0} sx={{ p: 2, border: "1px solid #34A85344", flex: "1 1 280px" }}>
            <Typography sx={{ fontWeight: 700, fontSize: 13, color: "#34A853", mb: 1 }}>Quick Wins</Typography>
            {wins.map((w, i) => <Typography key={i} sx={{ fontSize: 12 }}>• {w}</Typography>)}
          </Paper>
        )}
      </Box>
    </Box>
  );
}

function EvidenceCuratorResults({ result }: { result: Record<string, unknown> }) {
  const coverageScore = Number(result.coverage_score || 0);
  const domains = (result.domains || []) as Record<string, unknown>[];
  const strengths = (result.strengths || []) as string[];
  const gaps = (result.evidence_gaps || []) as string[];
  const actions = (result.recommended_actions || []) as string[];

  const scoreColor = coverageScore >= 75 ? "#34A853" : coverageScore >= 50 ? "#FBBC04" : "#EA4335";

  return (
    <Box>
      <Box sx={{ display: "flex", gap: 3, mb: 2, alignItems: "flex-start", flexWrap: "wrap" }}>
        <Box sx={{ textAlign: "center" }}>
          <Typography sx={{ fontSize: 56, fontWeight: 800, color: scoreColor, lineHeight: 1 }}>{coverageScore}</Typography>
          <Typography sx={{ fontSize: 12, color: "text.secondary" }}>Coverage %</Typography>
        </Box>
        <Typography sx={{ fontSize: 13, flex: 1, pt: 1 }}>{String(result.executive_summary || "")}</Typography>
      </Box>

      <Box sx={{ overflowX: "auto", mb: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              {["Domain", "Coverage", "Strength", "Open", "Remediated", "Key Evidence", "Gaps"].map((h) => (
                <TableCell key={h} sx={{ fontWeight: 700, whiteSpace: "nowrap" }}>{h}</TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {domains.map((d, i) => {
              const str = String(d.evidence_strength || "missing");
              return (
                <TableRow key={i} hover>
                  <TableCell sx={{ fontSize: 12, whiteSpace: "nowrap" }}>{String(d.domain || "")}</TableCell>
                  <TableCell sx={{ fontSize: 12 }}>{String(d.coverage_pct || 0)}%</TableCell>
                  <TableCell>
                    <Chip label={str} size="small"
                      sx={{ bgcolor: `${STRENGTH_COLORS[str] || "#9e9e9e"}22`, color: STRENGTH_COLORS[str] || "#9e9e9e", fontWeight: 700, fontSize: 11 }} />
                  </TableCell>
                  <TableCell sx={{ fontSize: 12 }}>{String(d.open_count || 0)}</TableCell>
                  <TableCell sx={{ fontSize: 12 }}>{String(d.remediated_count || 0)}</TableCell>
                  <TableCell sx={{ fontSize: 12, maxWidth: 160 }}>
                    {Array.isArray(d.key_evidence) ? d.key_evidence.map((e, ei) => (
                      <Typography key={ei} sx={{ fontSize: 11 }}>• {String(e)}</Typography>
                    )) : null}
                  </TableCell>
                  <TableCell sx={{ fontSize: 12, maxWidth: 160 }}>
                    {Array.isArray(d.gaps) ? d.gaps.map((g, gi) => (
                      <Typography key={gi} sx={{ fontSize: 11, color: "text.secondary" }}>• {String(g)}</Typography>
                    )) : null}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Box>

      <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
        {strengths.length > 0 && (
          <Paper elevation={0} sx={{ p: 2, border: "1px solid #34A85344", flex: "1 1 220px" }}>
            <Typography sx={{ fontWeight: 700, fontSize: 13, color: "#34A853", mb: 1 }}>Strengths</Typography>
            {strengths.map((s, i) => <Typography key={i} sx={{ fontSize: 12 }}>• {s}</Typography>)}
          </Paper>
        )}
        {gaps.length > 0 && (
          <Paper elevation={0} sx={{ p: 2, border: "1px solid #EA433544", flex: "1 1 220px" }}>
            <Typography sx={{ fontWeight: 700, fontSize: 13, color: "#EA4335", mb: 1 }}>Evidence Gaps</Typography>
            {gaps.map((g, i) => <Typography key={i} sx={{ fontSize: 12 }}>• {g}</Typography>)}
          </Paper>
        )}
        {actions.length > 0 && (
          <Paper elevation={0} sx={{ p: 2, border: "1px solid #4285F444", flex: "1 1 220px" }}>
            <Typography sx={{ fontWeight: 700, fontSize: 13, color: "#4285F4", mb: 1 }}>Recommended Actions</Typography>
            {actions.map((a, i) => <Typography key={i} sx={{ fontSize: 12 }}>• {a}</Typography>)}
          </Paper>
        )}
      </Box>
    </Box>
  );
}

function InterviewPrepResults({ result }: { result: Record<string, unknown> }) {
  const evidence = (result.key_evidence_to_cite || []) as Record<string, unknown>[];
  const followUps = (result.likely_follow_up_questions || []) as string[];
  const watchOuts = (result.watch_outs || []) as string[];
  const checklist = (result.preparation_checklist || []) as string[];

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
      <Paper elevation={0} sx={{ p: 2, bgcolor: "rgba(251,188,4,0.08)", border: "1px solid rgba(251,188,4,0.3)" }}>
        <Typography sx={{ fontWeight: 700, fontSize: 13, color: "#FBBC04", mb: 1 }}>Situation Briefing</Typography>
        <Typography sx={{ fontSize: 13 }}>{String(result.situation_briefing || "")}</Typography>
      </Paper>

      <Paper elevation={0} sx={{ p: 2, border: "1px solid", borderColor: "divider" }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography sx={{ fontWeight: 700, fontSize: 13 }}>Suggested Response</Typography>
          <Tooltip title="Copy to clipboard">
            <Button size="small" startIcon={<ContentCopy sx={{ fontSize: 14 }} />}
              onClick={() => copyToClipboard(String(result.suggested_response || ""))}
              sx={{ fontSize: 11 }}>Copy</Button>
          </Tooltip>
        </Box>
        <Typography sx={{ fontSize: 13, lineHeight: 1.7 }}>{String(result.suggested_response || "")}</Typography>
      </Paper>

      {evidence.length > 0 && (
        <Box>
          <Typography sx={{ fontWeight: 700, fontSize: 13, mb: 1 }}>Evidence to Cite</Typography>
          <Table size="small">
            <TableHead>
              <TableRow>
                {["Evidence Item", "Where to Find It", "Strength"].map((h) => (
                  <TableCell key={h} sx={{ fontWeight: 700 }}>{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {evidence.map((e, i) => {
                const str = String(e.strength || "adequate");
                return (
                  <TableRow key={i} hover>
                    <TableCell sx={{ fontSize: 12 }}>{String(e.item || "")}</TableCell>
                    <TableCell sx={{ fontSize: 12 }}>{String(e.where || "")}</TableCell>
                    <TableCell>
                      <Chip label={str} size="small"
                        sx={{ bgcolor: `${STRENGTH_COLORS[str] || "#9e9e9e"}22`, color: STRENGTH_COLORS[str] || "#9e9e9e", fontWeight: 700, fontSize: 11 }} />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Box>
      )}

      <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
        {followUps.length > 0 && (
          <Paper elevation={0} sx={{ p: 2, border: "1px solid #4285F444", flex: "1 1 220px" }}>
            <Typography sx={{ fontWeight: 700, fontSize: 13, color: "#4285F4", mb: 1 }}>Likely Follow-up Questions</Typography>
            {followUps.map((q, i) => <Typography key={i} sx={{ fontSize: 12 }}>• {q}</Typography>)}
          </Paper>
        )}
        {watchOuts.length > 0 && (
          <Paper elevation={0} sx={{ p: 2, border: "1px solid #EA433544", flex: "1 1 220px" }}>
            <Typography sx={{ fontWeight: 700, fontSize: 13, color: "#EA4335", mb: 1 }}>Watch-Outs</Typography>
            {watchOuts.map((w, i) => <Typography key={i} sx={{ fontSize: 12 }}>• {w}</Typography>)}
          </Paper>
        )}
        {checklist.length > 0 && (
          <Paper elevation={0} sx={{ p: 2, border: "1px solid #34A85344", flex: "1 1 220px" }}>
            <Typography sx={{ fontWeight: 700, fontSize: 13, color: "#34A853", mb: 1 }}>Preparation Checklist</Typography>
            {checklist.map((c, i) => <Typography key={i} sx={{ fontSize: 12 }}>☐ {c}</Typography>)}
          </Paper>
        )}
      </Box>
    </Box>
  );
}

function ResultPanel({ agentType, result }: { agentType: string; result: Record<string, unknown> }) {
  if (result.raw) {
    return <Alert severity="warning">Agent returned unstructured output: {String(result.raw).slice(0, 500)}</Alert>;
  }
  if (result.error) {
    return <Alert severity="error">{String(result.error)}</Alert>;
  }
  if (agentType === "control_tester") return <ControlTesterResults result={result} />;
  if (agentType === "readiness_report") return <ReadinessResults result={result} />;
  if (agentType === "evidence_curator") return <EvidenceCuratorResults result={result} />;
  if (agentType === "interview_prep") return <InterviewPrepResults result={result} />;
  return <Typography>Unknown agent type</Typography>;
}

// ── Main page ──────────────────────────────────────────────────────────────────

const AGENT_TYPE_LABELS: Record<string, string> = {
  control_tester: "Control Tester",
  readiness_report: "Readiness Report",
  evidence_curator: "Evidence Curator",
  interview_prep: "Interview Prep",
};

export default function AuditAgents() {
  const { clientId } = useActiveClient();
  const [selectedAgent, setSelectedAgent] = useState<AgentDef | null>(null);
  const [step, setStep] = useState(0);
  const [inputs, setInputs] = useState<Record<string, unknown>>({});
  const [domains, setDomains] = useState<string[]>([]);
  const [domainsLoading, setDomainsLoading] = useState(false);
  const [runId, setRunId] = useState<string | null>(null);
  const [runStatus, setRunStatus] = useState<string | null>(null);
  const [runResult, setRunResult] = useState<Record<string, unknown> | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [viewingRun, setViewingRun] = useState<{ agentType: string; result: Record<string, unknown> } | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const { data: apiFrameworks } = useQuery<{ framework: string; name: string; is_custom?: boolean }[]>({
    queryKey: ["frameworks-all"],
    queryFn: () => frameworksApi.catalogAll(),
  });
  const frameworkList = apiFrameworks && apiFrameworks.length > 0
    ? apiFrameworks
    : STATIC_FRAMEWORKS;

  const { data: pastRuns = [], refetch: refetchRuns } = useQuery({
    queryKey: ["audit-runs", clientId],
    queryFn: () => auditAgentsApi.listRuns(clientId!),
    enabled: !!clientId,
    refetchInterval: runStatus === "running" ? 5000 : false,
  });

  const stopPoll = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  useEffect(() => () => stopPoll(), [stopPoll]);

  const startPolling = useCallback((id: string) => {
    stopPoll();
    let tries = 0;
    pollRef.current = setInterval(async () => {
      tries++;
      if (tries > 40) { stopPoll(); setRunStatus("failed"); return; }
      try {
        const r = await auditAgentsApi.getRun(clientId!, id);
        setRunStatus(r.status);
        if (r.status !== "running") {
          stopPoll();
          if (r.status === "completed") setRunResult(r.result || {});
          if (r.status === "failed") setRunError(r.error_message || "Agent failed.");
          refetchRuns();
        }
      } catch { /* keep polling */ }
    }, 3000);
  }, [clientId, stopPoll, refetchRuns]);

  const loadDomains = useCallback(async (framework: string) => {
    if (!clientId || !framework) return;
    setDomainsLoading(true);
    try {
      const d = await auditAgentsApi.frameworkDomains(clientId, framework);
      setDomains(d.domains || []);
    } catch {
      setDomains([]);
    } finally {
      setDomainsLoading(false);
    }
  }, [clientId]);

  const selectAgent = (agent: AgentDef) => {
    setSelectedAgent(agent);
    setStep(0);
    setInputs({});
    setDomains([]);
    setRunId(null);
    setRunStatus(null);
    setRunResult(null);
    setRunError(null);
    setViewingRun(null);
    stopPoll();
  };

  const currentStep = selectedAgent?.steps[step];

  const getValue = (key: string) => inputs[key] ?? (currentStep?.multi ? [] : "");

  const setValue = (key: string, val: unknown) => setInputs((prev) => ({ ...prev, [key]: val }));

  const isStepComplete = (s: WizardStep): boolean => {
    if (!s.required) return true;
    const v = inputs[s.key];
    if (Array.isArray(v)) return v.length > 0;
    return !!v;
  };

  const handleNext = () => {
    if (!selectedAgent || !currentStep) return;
    if (step < selectedAgent.steps.length - 1) {
      const nextStep = selectedAgent.steps[step + 1];
      if (nextStep.type === "domain_chips") {
        const fw = String(inputs["framework"] || "");
        if (fw) loadDomains(fw);
      }
      setStep((s) => s + 1);
    }
  };

  const handleBack = () => setStep((s) => Math.max(0, s - 1));

  const handleRun = async () => {
    if (!clientId || !selectedAgent) return;
    setSubmitting(true);
    setRunResult(null);
    setRunError(null);
    try {
      const resp = await auditAgentsApi.run(clientId, {
        agent_type: selectedAgent.id,
        wizard_inputs: inputs as Record<string, unknown>,
      });
      setRunId(resp.run_id);
      setRunStatus("running");
      startPolling(resp.run_id);
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } } };
      setRunError(err?.response?.data?.detail || "Failed to start agent.");
    } finally {
      setSubmitting(false);
    }
  };

  const isLastStep = selectedAgent ? step === selectedAgent.steps.length - 1 : false;

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: "auto" }}>
      <Typography variant="h5" sx={{ fontWeight: 800, mb: 0.5 }}>Audit Agents</Typography>
      <Typography sx={{ fontSize: 13, color: "text.secondary", mb: 3 }}>
        Wizard-driven AI agents for audit preparation — select an agent, answer a few questions, get structured results.
      </Typography>

      <Box sx={{ display: "flex", gap: 3, alignItems: "flex-start" }}>
        {/* Left: agent picker */}
        <Box sx={{ width: 260, flexShrink: 0 }}>
          <Typography sx={{ fontSize: 11, fontWeight: 700, color: "text.secondary", textTransform: "uppercase", letterSpacing: 1, mb: 1.5 }}>
            Select Agent
          </Typography>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
            {AGENTS.map((agent) => {
              const active = selectedAgent?.id === agent.id;
              return (
                <Card
                  key={agent.id}
                  onClick={() => selectAgent(agent)}
                  elevation={0}
                  sx={{
                    cursor: "pointer",
                    border: "1px solid",
                    borderColor: active ? agent.color : "divider",
                    bgcolor: active ? `${agent.color}0d` : "background.paper",
                    transition: "all 0.15s",
                    "&:hover": { borderColor: agent.color },
                  }}
                >
                  <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                    <Box sx={{ display: "flex", gap: 1.5, alignItems: "flex-start" }}>
                      <Box sx={{
                        width: 36, height: 36, borderRadius: 1.5, display: "flex", alignItems: "center",
                        justifyContent: "center", bgcolor: `${agent.color}22`, color: agent.color, flexShrink: 0,
                      }}>
                        {agent.icon}
                      </Box>
                      <Box>
                        <Typography sx={{ fontWeight: 700, fontSize: 13, color: active ? agent.color : "text.primary" }}>
                          {agent.name}
                        </Typography>
                        <Typography sx={{ fontSize: 11, color: "text.secondary", mt: 0.25 }}>
                          {agent.desc}
                        </Typography>
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              );
            })}
          </Box>
        </Box>

        {/* Right: wizard + results */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          {!selectedAgent ? (
            <Paper elevation={0} sx={{ border: "1px solid", borderColor: "divider", p: 6, textAlign: "center" }}>
              <ManageSearch sx={{ fontSize: 48, color: "text.disabled", mb: 2 }} />
              <Typography sx={{ fontSize: 15, color: "text.secondary" }}>Select an agent on the left to begin</Typography>
            </Paper>
          ) : (
            <Paper elevation={0} sx={{ border: "1px solid", borderColor: selectedAgent.color, p: 3 }}>
              {/* Agent header */}
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 3 }}>
                <Box sx={{
                  width: 40, height: 40, borderRadius: 2, display: "flex", alignItems: "center",
                  justifyContent: "center", bgcolor: `${selectedAgent.color}22`, color: selectedAgent.color,
                }}>
                  {selectedAgent.icon}
                </Box>
                <Box>
                  <Typography sx={{ fontWeight: 800, fontSize: 16, color: selectedAgent.color }}>
                    {selectedAgent.name}
                  </Typography>
                  <Typography sx={{ fontSize: 12, color: "text.secondary" }}>{selectedAgent.desc}</Typography>
                </Box>
              </Box>

              {/* Stepper */}
              <Stepper activeStep={step} sx={{ mb: 3 }}>
                {selectedAgent.steps.map((s, i) => (
                  <Step key={s.key} completed={i < step}>
                    <StepLabel>
                      <Typography sx={{ fontSize: 12 }}>{s.label}</Typography>
                    </StepLabel>
                  </Step>
                ))}
              </Stepper>

              {/* Breadcrumb of completed steps */}
              {step > 0 && (
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.75, mb: 2 }}>
                  {selectedAgent.steps.slice(0, step).map((s) => {
                    const v = inputs[s.key];
                    const label = Array.isArray(v) ? v.join(", ") : String(v || "");
                    return label ? (
                      <Chip key={s.key} size="small" label={`${s.label}: ${label}`}
                        sx={{ fontSize: 11, bgcolor: `${selectedAgent.color}15`, color: selectedAgent.color }} />
                    ) : null;
                  })}
                </Box>
              )}

              {/* Current step */}
              {currentStep && (
                <Box sx={{ mb: 3 }}>
                  <Typography sx={{ fontWeight: 700, fontSize: 15, mb: 1.5 }}>{currentStep.question}</Typography>

                  {currentStep.type === "chips" && (
                    <ChipSelector
                      options={currentStep.options || []}
                      value={getValue(currentStep.key) as string | string[]}
                      multi={currentStep.multi}
                      color={selectedAgent.color}
                      onChange={(v) => setValue(currentStep.key, v)}
                    />
                  )}

                  {currentStep.type === "framework_select" && (
                    <Box sx={{ mt: 1 }}>
                      <Typography sx={{ fontSize: 11, color: "text.secondary", mb: 1 }}>
                        {frameworkList.length} frameworks available — click one to select
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, maxHeight: 280, overflowY: "auto", pr: 1 }}>
                        {frameworkList.map((f) => {
                          const selected = inputs["framework"] === f.framework;
                          return (
                            <Box
                              key={f.framework}
                              onClick={() => setValue("framework", selected ? "" : f.framework)}
                              sx={{
                                px: 1.5, py: 0.75, borderRadius: 1, cursor: "pointer", fontSize: 13,
                                border: "1px solid",
                                borderColor: selected ? selectedAgent.color : "divider",
                                bgcolor: selected ? `${selectedAgent.color}18` : "background.paper",
                                color: selected ? selectedAgent.color : "text.primary",
                                fontWeight: selected ? 700 : 400,
                                userSelect: "none",
                                "&:hover": { borderColor: selectedAgent.color, color: selectedAgent.color },
                              }}
                            >
                              {f.name}
                              {f.is_custom && (
                                <Box component="span" sx={{ ml: 0.75, fontSize: 10, fontWeight: 700,
                                  color: "#9C27B0", bgcolor: "#9C27B018", px: 0.5, borderRadius: 0.5 }}>
                                  CUSTOM
                                </Box>
                              )}
                            </Box>
                          );
                        })}
                      </Box>
                    </Box>
                  )}

                  {currentStep.type === "domain_chips" && (
                    domainsLoading ? (
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 1 }}>
                        <CircularProgress size={16} />
                        <Typography sx={{ fontSize: 13, color: "text.secondary" }}>Loading domains…</Typography>
                      </Box>
                    ) : domains.length === 0 ? (
                      <Typography sx={{ fontSize: 13, color: "text.secondary", mt: 1 }}>
                        No domains found for this framework — all controls will be included.
                      </Typography>
                    ) : (
                      <>
                        <Typography sx={{ fontSize: 12, color: "text.secondary", mb: 1 }}>
                          Leave empty to include all domains
                        </Typography>
                        <ChipSelector
                          options={domains}
                          value={getValue(currentStep.key) as string[]}
                          multi
                          color={selectedAgent.color}
                          onChange={(v) => setValue(currentStep.key, v)}
                        />
                      </>
                    )
                  )}

                  {currentStep.type === "free_text" && (
                    <TextField
                      size="small"
                      fullWidth
                      placeholder={currentStep.placeholder}
                      value={String(inputs[currentStep.key] || "")}
                      onChange={(e) => setValue(currentStep.key, e.target.value)}
                      sx={{ mt: 1, maxWidth: 480 }}
                    />
                  )}
                </Box>
              )}

              {/* Navigation buttons */}
              <Box sx={{ display: "flex", gap: 1.5 }}>
                <Button variant="outlined" onClick={handleBack} disabled={step === 0} size="small">Back</Button>
                {!isLastStep ? (
                  <Button
                    variant="contained"
                    onClick={handleNext}
                    disabled={currentStep ? !isStepComplete(currentStep) : false}
                    size="small"
                    sx={{ bgcolor: selectedAgent.color, "&:hover": { bgcolor: selectedAgent.color } }}
                  >
                    Next
                  </Button>
                ) : (
                  <Button
                    variant="contained"
                    onClick={handleRun}
                    disabled={submitting || (currentStep ? (currentStep.required && !isStepComplete(currentStep)) : false)}
                    startIcon={submitting ? <CircularProgress size={14} color="inherit" /> : <PlayArrow />}
                    size="small"
                    sx={{ bgcolor: selectedAgent.color, "&:hover": { bgcolor: selectedAgent.color } }}
                  >
                    {submitting ? "Starting…" : "Run Agent"}
                  </Button>
                )}
              </Box>

              {/* Results */}
              {(runStatus || viewingRun) && (
                <>
                  <Divider sx={{ my: 3 }} />

                  {runStatus === "running" && !viewingRun && (
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <CircularProgress size={24} sx={{ color: selectedAgent.color }} />
                      <Typography sx={{ fontSize: 14 }}>Agent is analysing your data…</Typography>
                    </Box>
                  )}

                  {runError && !viewingRun && (
                    <Alert severity="error" sx={{ mt: 1 }}>{runError}</Alert>
                  )}

                  {(runResult || viewingRun?.result) && (
                    <Box>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                        <CheckCircle sx={{ color: selectedAgent.color, fontSize: 18 }} />
                        <Typography sx={{ fontWeight: 700, fontSize: 14 }}>
                          {viewingRun ? `${AGENT_TYPE_LABELS[viewingRun.agentType] || viewingRun.agentType} — Past Run` : "Results"}
                        </Typography>
                      </Box>
                      <ResultPanel
                        agentType={viewingRun?.agentType || selectedAgent.id}
                        result={viewingRun?.result || runResult || {}}
                      />
                    </Box>
                  )}
                </>
              )}
            </Paper>
          )}

          {/* Past runs */}
          {clientId && (pastRuns as unknown[]).length > 0 && (
            <Paper elevation={0} sx={{ border: "1px solid", borderColor: "divider", p: 2, mt: 2 }}>
              <Typography sx={{ fontWeight: 700, fontSize: 13, mb: 1.5 }}>Recent Runs</Typography>
              <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
                {(pastRuns as Record<string, unknown>[]).slice(0, 5).map((run) => {
                  const status = String(run.status || "");
                  return (
                    <Box key={String(run.id)} sx={{
                      display: "flex", alignItems: "center", gap: 2, p: 1.25,
                      borderRadius: 1, border: "1px solid", borderColor: "divider",
                    }}>
                      <Chip
                        label={AGENT_TYPE_LABELS[String(run.agent_type)] || String(run.agent_type)}
                        size="small"
                        sx={{ fontSize: 11, bgcolor: "rgba(255,255,255,0.06)", minWidth: 130 }}
                      />
                      <Typography sx={{ fontSize: 12, color: "text.secondary", flex: 1 }}>
                        {run.created_at ? new Date(String(run.created_at)).toLocaleString() : ""}
                      </Typography>
                      <Chip
                        label={status}
                        size="small"
                        sx={{
                          fontSize: 11, fontWeight: 700,
                          bgcolor: status === "completed" ? "#34A85322" : status === "failed" ? "#EA433522" : "#FBBC0422",
                          color: status === "completed" ? "#34A853" : status === "failed" ? "#EA4335" : "#FBBC04",
                        }}
                      />
                      {status === "completed" && (
                        <Button
                          size="small"
                          variant="outlined"
                          sx={{ fontSize: 11, minWidth: 60 }}
                          onClick={async () => {
                            const full = await auditAgentsApi.getRun(clientId, String(run.id));
                            const agent = AGENTS.find((a) => a.id === String(run.agent_type));
                            if (agent) selectAgent(agent);
                            setViewingRun({ agentType: String(run.agent_type), result: full.result || {} });
                            setRunStatus(null);
                          }}
                        >
                          View
                        </Button>
                      )}
                    </Box>
                  );
                })}
              </Box>
            </Paper>
          )}
        </Box>
      </Box>
    </Box>
  );
}
