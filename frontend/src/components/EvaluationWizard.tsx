import React, { useState, useCallback, useEffect } from "react";
import {
  Dialog, DialogTitle, DialogContent, DialogActions,
  Box, Typography, Button, TextField, Select, MenuItem,
  FormControl, InputLabel, Slider, Radio, RadioGroup,
  FormControlLabel, FormLabel, Chip, CircularProgress,
  Alert, LinearProgress, Grid, ToggleButton, ToggleButtonGroup,
  Snackbar, Paper,
} from "@mui/material";
import { AutoAwesome, CheckCircle, Cancel, Schedule, Replay } from "@mui/icons-material";
import { useActiveClient } from "../contexts/ClientContext";
import { riskProposalsApi } from "../services/api";
import { RiskProposal } from "../types";

// ── Constants ────────────────────────────────────────────────────────────────

const RISK_AREAS_SECURITY = [
  "Unauthorised Access", "Data Leakage / Breach", "Denial of Service",
  "Malware / Ransomware", "Supply Chain Risk", "Insider Threat",
  "Social Engineering / Phishing", "System Misconfiguration",
  "Vulnerability Exploitation", "Cryptographic Weakness",
  "Third-Party Vendor Risk", "Compliance & Regulatory",
];

const RISK_AREAS_PROJECT = [
  "Schedule Delay", "Resource / Budget Overrun", "Scope Creep",
  "Technology / Integration Risk", "Data Governance",
];

const FACTOR_LABELS: Record<string, string[]> = {
  accessibility: [
    "No remote access — physically isolated",
    "Limited access — specific network only",
    "Partially accessible — VPN or credential required",
    "Widely accessible — internet-facing with basic controls",
    "Fully open — no access restriction",
  ],
  discoverability: [
    "Cannot find it — deep internals, no exposure",
    "Requires dedicated research and expertise",
    "Findable with standard scanning tools",
    "Easy to discover — visible in public metadata",
    "Indexed / published — trivially discoverable",
  ],
  exploitability: [
    "No exploit exists — theoretical only",
    "Complex multi-step exploit requiring deep expertise",
    "Moderate skill required — known technique",
    "Easy exploit — widely available PoC",
    "Script kiddie — automated exploit tool exists",
  ],
  authentication_score: [
    "Strong MFA + device certificates + conditional access",
    "Multi-factor authentication enforced",
    "Password only — adequate length and complexity",
    "Weak or default credentials — easily guessed",
    "No authentication — fully open",
  ],
  repeatability: [
    "One-time only — exploit destroys access path",
    "Rarely repeatable — unstable conditions",
    "Sometimes repeatable — depends on system state",
    "Usually repeatable — reliable most of the time",
    "Always repeatable — deterministic, automated",
  ],
  data_impact: [
    "No data impact — no sensitive data at risk",
    "Limited exposure — internal non-sensitive data only",
    "Moderate — PII or business-critical data at risk",
    "Significant — confidential or regulated data breach",
    "Catastrophic — complete data loss or public breach",
  ],
  operational_impact: [
    "No disruption — system continues normally",
    "Minor disruption — degraded performance only",
    "Moderate — key processes affected or delayed",
    "Significant — major operations disrupted",
    "Catastrophic — complete operational failure",
  ],
  financial_impact: [
    "Negligible financial or regulatory cost",
    "Minor cost — easily absorbed within budget",
    "Moderate — material financial loss or regulatory fine",
    "Major — significant financial impact or formal regulatory action",
    "Catastrophic — existential financial or regulatory consequence",
  ],
};

const MATRIX_COLOURS: Record<string, string> = {
  low: "#2e7d32", medium: "#f57c00", medium_high: "#e65100",
  high: "#b71c1c", critical: "#4a0000",
};

function matrixLabel(score: number): string {
  if (score <= 4) return "low";
  if (score <= 9) return "medium";
  if (score <= 12) return "medium_high";
  if (score <= 20) return "high";
  return "critical";
}

function matrixLabelDisplay(score: number): string {
  const l = matrixLabel(score);
  return l === "medium_high" ? "MEDIUM-HIGH" : l.toUpperCase();
}

function scoreColor(val: number): string {
  return val <= 1 ? "#34A853" : val === 2 ? "#81C784" : val === 3 ? "#FBBC04" : val === 4 ? "#FF7043" : "#EA4335";
}

// ── Risk Matrix ──────────────────────────────────────────────────────────────

function RiskMatrix({ impact, likelihood }: { impact: number; likelihood: number }) {
  const likelihoodCol = Math.max(1, Math.min(5, Math.round(likelihood)));
  const impactRow = Math.max(1, Math.min(5, Math.round(impact)));
  return (
    <Box>
      <Typography variant="caption" sx={{ color: "text.secondary", mb: 1, display: "block" }}>
        5×5 Risk Matrix — GCC IM8 / ISO 27001
      </Typography>
      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 0.5 }}>
        <Box sx={{ display: "flex", flexDirection: "column", justifyContent: "center", mr: 0.5 }}>
          <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 9, writingMode: "vertical-rl",
            transform: "rotate(180deg)", whiteSpace: "nowrap", lineHeight: 1 }}>
            Impact ↑
          </Typography>
        </Box>
        <Box>
          <Box sx={{ display: "flex", mb: 0.5 }}>
            <Box sx={{ width: 32 }} />
            {[1,2,3,4,5].map((c) => (
              <Typography key={c} variant="caption"
                sx={{ width: 40, textAlign: "center", color: "text.secondary", fontSize: 10 }}>{c}</Typography>
            ))}
          </Box>
          {[5,4,3,2,1].map((imp) => (
            <Box key={imp} sx={{ display: "flex", alignItems: "center", mb: 0.5 }}>
              <Typography variant="caption"
                sx={{ width: 32, textAlign: "right", pr: 0.5, color: "text.secondary", fontSize: 10 }}>
                {imp}
              </Typography>
              {[1,2,3,4,5].map((lik) => {
                const score = imp * lik;
                const label = matrixLabel(score);
                const isActive = imp === impactRow && lik === likelihoodCol;
                return (
                  <Box key={lik} sx={{
                    width: 40, height: 28,
                    bgcolor: isActive ? MATRIX_COLOURS[label] : "rgba(255,255,255,0.06)",
                    border: isActive ? "2px solid white" : "1px solid rgba(255,255,255,0.08)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    borderRadius: 0.5, transition: "all 0.2s", mr: 0.5,
                  }}>
                    <Typography variant="caption" sx={{
                      fontSize: 9, fontWeight: isActive ? 800 : 400,
                      color: isActive ? "white" : "text.disabled",
                    }}>{score}</Typography>
                  </Box>
                );
              })}
            </Box>
          ))}
          <Box sx={{ display: "flex", pl: 4 }}>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 9 }}>Likelihood →</Typography>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

// ── Compact Factor Slider ─────────────────────────────────────────────────────

function CompactFactorSlider({
  factor, label, description, value, onChange, rationale,
}: {
  factor: string; label: string; description: string;
  value: number; onChange: (v: number) => void; rationale?: string;
}) {
  const labels = FACTOR_LABELS[factor] || [];
  const color = scoreColor(value);
  return (
    <Box sx={{ p: 1.5, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1,
      border: "1px solid", borderColor: "divider", mb: 1.5 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 0.75 }}>
        <Box>
          <Typography variant="body2" sx={{ fontWeight: 600 }}>{label}</Typography>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>{description}</Typography>
        </Box>
        <Chip label={`${value}/5`} size="small"
          sx={{ fontWeight: 700, bgcolor: `${color}20`, color, flexShrink: 0, ml: 1 }} />
      </Box>
      <Box sx={{ px: 1 }}>
        <Slider value={value} min={1} max={5} step={1}
          marks={[1,2,3,4,5].map((v) => ({ value: v, label: String(v) }))}
          onChange={(_, v) => onChange(v as number)}
          sx={{ color, "& .MuiSlider-mark": { bgcolor: "divider" } }} />
      </Box>
      <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.25 }}>
        Level {value}: {labels[value - 1] || `Score ${value}/5`}
      </Typography>
      {rationale && (
        <Box sx={{ mt: 1, p: 1, bgcolor: "rgba(66,133,244,0.06)", borderRadius: 1,
          borderLeft: "3px solid", borderColor: "#4285F4" }}>
          <Typography variant="caption" sx={{ color: "#90CAF9", fontStyle: "italic", display: "flex", alignItems: "flex-start", gap: 0.5 }}>
            <AutoAwesome sx={{ fontSize: 12, mt: 0.1, flexShrink: 0 }} />
            {rationale}
          </Typography>
        </Box>
      )}
    </Box>
  );
}

// ── Measure item type ─────────────────────────────────────────────────────────

interface MeasureItem {
  id: string;
  text: string;
  category?: string;
  status: "pending" | "in_place" | "not_possible";
}

interface WorkaroundMap {
  [measureId: string]: string;
}

// ── Measures Step ─────────────────────────────────────────────────────────────

function MeasuresStep({
  measures, onMeasureChange, workarounds, onReassess, reassessing, extraContext, onContextChange,
}: {
  measures: MeasureItem[];
  onMeasureChange: (id: string, status: "pending" | "in_place" | "not_possible") => void;
  workarounds: WorkaroundMap;
  onReassess: () => void;
  reassessing: boolean;
  extraContext: string;
  onContextChange: (v: string) => void;
}) {
  const STATUS_CONFIG = {
    pending:      { label: "Pending",      icon: <Schedule sx={{ fontSize: 14 }} />,      color: "#9E9E9E" },
    in_place:     { label: "In Place",     icon: <CheckCircle sx={{ fontSize: 14 }} />,   color: "#4CAF50" },
    not_possible: { label: "Not Possible", icon: <Cancel sx={{ fontSize: 14 }} />,        color: "#F44336" },
  };

  return (
    <Box>
      <Typography variant="h6" sx={{ fontWeight: 700, mb: 0.5 }}>Security Measures</Typography>
      <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>
        Mark each control as <strong>In Place</strong>, <strong>Not Possible</strong>, or <strong>Pending</strong>.
        Add context so AI adjusts scores when re-assessing.
      </Typography>

      <Box sx={{ mb: 3, p: 1.5, bgcolor: "rgba(124,58,237,0.06)", borderRadius: 1, border: "1px solid rgba(124,58,237,0.2)" }}>
        <Typography variant="caption" sx={{ fontWeight: 700, color: "#9C6AFF", display: "block", mb: 0.75 }}>
          Additional context for AI re-assessment (optional)
        </Typography>
        <TextField
          fullWidth multiline minRows={2} maxRows={4} size="small"
          placeholder='E.g. "Frontend and backend run on the same host so network interception is low risk" or "Service is internet-facing with no WAF"'
          value={extraContext}
          onChange={(e) => onContextChange(e.target.value)}
          sx={{ "& .MuiInputBase-root": { fontSize: 12, bgcolor: "transparent" } }}
        />
      </Box>

      {measures.length === 0 ? (
        <Alert severity="info">No measures generated yet. Go back to trigger the AI assessment.</Alert>
      ) : (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
          {measures.map((m) => {
            const cfg = STATUS_CONFIG[m.status];
            const wa = workarounds[m.id];
            return (
              <Paper key={m.id} variant="outlined" sx={{
                p: 2, borderRadius: 1.5,
                borderColor: m.status === "in_place" ? "rgba(76,175,80,0.4)"
                  : m.status === "not_possible" ? "rgba(244,67,54,0.4)"
                  : "divider",
              }}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, flexWrap: "wrap" }}>
                  <Box sx={{ flex: 1, minWidth: 200 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                      {m.category && (
                        <Chip label={m.category} size="small"
                          sx={{ height: 16, fontSize: 9, bgcolor: "rgba(255,255,255,0.07)" }} />
                      )}
                      <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace" }}>
                        {m.id}
                      </Typography>
                    </Box>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>{m.text}</Typography>
                    {m.status === "not_possible" && !wa && (
                      <Typography variant="caption" sx={{ color: "#FFC107", mt: 0.5, display: "block" }}>
                        Click "Re-assess with AI" — AI will suggest a workaround.
                      </Typography>
                    )}
                    {wa && (
                      <Box sx={{ mt: 1, p: 1, bgcolor: "rgba(255,152,0,0.08)", borderRadius: 1,
                        border: "1px solid rgba(255,152,0,0.25)" }}>
                        <Typography variant="caption" sx={{ color: "#FFB74D", display: "flex", alignItems: "flex-start", gap: 0.5 }}>
                          <AutoAwesome sx={{ fontSize: 12, mt: 0.1, flexShrink: 0 }} />
                          Workaround: {wa}
                        </Typography>
                      </Box>
                    )}
                  </Box>
                  <ToggleButtonGroup size="small" exclusive value={m.status}
                    onChange={(_, val) => { if (val) onMeasureChange(m.id, val); }}
                    sx={{ flexShrink: 0 }}>
                    {(["pending", "in_place", "not_possible"] as const).map((s) => {
                      const c = STATUS_CONFIG[s];
                      return (
                        <ToggleButton key={s} value={s}
                          sx={{ fontSize: 10, py: 0.4, px: 1,
                            "&.Mui-selected": { bgcolor: `${c.color}20`, color: c.color, borderColor: `${c.color}60` } }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 0.4 }}>
                            {c.icon}
                            <span>{c.label}</span>
                          </Box>
                        </ToggleButton>
                      );
                    })}
                  </ToggleButtonGroup>
                </Box>
              </Paper>
            );
          })}
        </Box>
      )}

      <Box sx={{ mt: 3, display: "flex", justifyContent: "flex-end" }}>
        <Button
          variant="outlined"
          startIcon={reassessing ? <CircularProgress size={16} /> : <Replay />}
          onClick={onReassess}
          disabled={reassessing || measures.length === 0}
          sx={{ borderColor: "#7C3AED", color: "#7C3AED",
            "&:hover": { borderColor: "#6d35d9", bgcolor: "rgba(124,58,237,0.06)" } }}>
          {reassessing ? "Re-assessing…" : "Re-assess with AI"}
        </Button>
      </Box>
    </Box>
  );
}

// ── Step config ───────────────────────────────────────────────────────────────

const STEPS = [
  "Basic Info",
  "Likelihood Factors",
  "Impact Factors",
  "Security Measures",
  "Review & Treatment",
];

interface FormData {
  title: string;
  description: string;
  risk_area: string;
  risk_type_gcim8: string;
  // Likelihood factors
  accessibility: number;
  discoverability: number;
  exploitability: number;
  authentication_score: number;
  repeatability: number;
  // Impact factors
  data_impact: number;
  operational_impact: number;
  financial_impact: number;
  // Treatment
  treatment_option: string;
  owner: string;
  assignee_email: string;
  due_date: string;
  mitigation_plan: string;
}

const DEFAULT_FORM: FormData = {
  title: "", description: "", risk_area: "", risk_type_gcim8: "Security",
  accessibility: 3, discoverability: 3, exploitability: 3,
  authentication_score: 3, repeatability: 3,
  data_impact: 3, operational_impact: 3, financial_impact: 3,
  treatment_option: "mitigate", owner: "", assignee_email: "", due_date: "", mitigation_plan: "",
};

interface Rationales {
  accessibility?: string;
  discoverability?: string;
  exploitability?: string;
  authentication?: string;
  repeatability?: string;
  data_impact?: string;
  operational_impact?: string;
  financial_impact?: string;
}

// ── Wizard ────────────────────────────────────────────────────────────────────

interface Props {
  open: boolean;
  onClose: () => void;
  proposal: RiskProposal | null;
  onEvaluated: () => void;
}

export default function EvaluationWizard({ open, onClose, proposal, onEvaluated }: Props) {
  const { clientId } = useActiveClient();
  const [step, setStep] = useState(0);
  const [form, setForm] = useState<FormData>(DEFAULT_FORM);
  const [rationales, setRationales] = useState<Rationales>({});
  const [measures, setMeasures] = useState<MeasureItem[]>([]);
  const [workarounds, setWorkarounds] = useState<WorkaroundMap>({});
  const [aiAssessment, setAiAssessment] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [reassessing, setReassessing] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [snackMsg, setSnackMsg] = useState("");
  const [extraContext, setExtraContext] = useState("");

  const set = useCallback(<K extends keyof FormData>(key: K, val: FormData[K]) => {
    setForm((f) => ({ ...f, [key]: val }));
  }, []);

  useEffect(() => {
    if (open && proposal && clientId) {
      setStep(0);
      setError("");
      setMeasures([]);
      setWorkarounds({});
      setAiAssessment(null);
      setRationales({});
      setForm({
        ...DEFAULT_FORM,
        title: proposal.title || "",
        description: proposal.description || "",
        risk_area: proposal.category || "",
        risk_type_gcim8: proposal.risk_type || "Security",
      });

      if (proposal.ai_draft_json) {
        try {
          const saved = JSON.parse(proposal.ai_draft_json);
          _applyAiResult(saved);
          setAiAssessment(saved);
          setSnackMsg("Restored previous AI assessment — adjust steps or Re-assess with AI.");
          return;
        } catch {
          // fall through to fresh AI call
        }
      }

      setAiLoading(true);
      riskProposalsApi.aiDraft(clientId, proposal.id)
        .then((result: any) => {
          _applyAiResult(result);
          setAiAssessment(result);
          setSnackMsg("AI pre-fill complete — all steps populated from risk description.");
        })
        .catch(() => { /* silently fall through */ })
        .finally(() => setAiLoading(false));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, proposal?.id]);

  const _applyAiResult = (result: any) => {
    const bi = result.basic_info || {};
    const lf = result.likelihood_factors || {};
    const impact = result.impact_factors || {};

    setForm((f) => ({
      ...f,
      description: bi.scenario || f.description,
      risk_area: bi.risk_area || f.risk_area,
      risk_type_gcim8: bi.risk_type || f.risk_type_gcim8,
      accessibility: lf.accessibility || f.accessibility,
      discoverability: lf.discoverability || f.discoverability,
      exploitability: lf.exploitability || f.exploitability,
      authentication_score: lf.authentication || f.authentication_score,
      repeatability: lf.repeatability || f.repeatability,
      // Impact factors — fall back to consequence for legacy AI responses
      data_impact: impact.data_impact || result.consequence || f.data_impact,
      operational_impact: impact.operational_impact || result.consequence || f.operational_impact,
      financial_impact: impact.financial_impact || result.consequence || f.financial_impact,
      treatment_option: ((result.treatment || f.treatment_option) as string).toLowerCase(),
    }));

    setRationales({
      accessibility: lf.accessibility_rationale,
      discoverability: lf.discoverability_rationale,
      exploitability: lf.exploitability_rationale,
      authentication: lf.authentication_rationale,
      repeatability: lf.repeatability_rationale,
      data_impact: impact.data_impact_rationale,
      operational_impact: impact.operational_impact_rationale,
      financial_impact: impact.financial_impact_rationale,
    });

    if (result.measures?.length) {
      setMeasures(result.measures.map((m: any) => ({ ...m, status: "pending" as const })));
    }

    if (result.workarounds?.length) {
      const wmap: WorkaroundMap = {};
      for (const w of result.workarounds) {
        wmap[w.measure_id] = w.alternative;
      }
      setWorkarounds(wmap);
    }
  };

  const handleReassess = async () => {
    if (!clientId || !proposal) return;
    setReassessing(true);
    try {
      const wizardData = {
        accessibility: form.accessibility,
        discoverability: form.discoverability,
        exploitability: form.exploitability,
        authentication_score: form.authentication_score,
        repeatability: form.repeatability,
        data_impact: form.data_impact,
        operational_impact: form.operational_impact,
        financial_impact: form.financial_impact,
        treatment_option: form.treatment_option,
      };
      const result = await riskProposalsApi.reevaluate(clientId, proposal.id, wizardData, measures, extraContext);
      _applyAiResult(result);
      setAiAssessment(result);
      setSnackMsg("AI has updated assessment based on your inputs.");
    } catch {
      setError("Re-assessment failed. Please try again.");
    } finally {
      setReassessing(false);
    }
  };

  const handleMeasureChange = (id: string, status: "pending" | "in_place" | "not_possible") => {
    setMeasures((prev) => prev.map((m) => m.id === id ? { ...m, status } : m));
  };

  const likelihood_avg = parseFloat(
    ((form.accessibility + form.discoverability + form.exploitability +
      form.authentication_score + form.repeatability) / 5).toFixed(2)
  );
  const impact_avg = parseFloat(
    ((form.data_impact + form.operational_impact + form.financial_impact) / 3).toFixed(2)
  );
  const matrix_score = Math.round(likelihood_avg * impact_avg);
  const risk_label = matrixLabel(matrix_score);
  const risk_display = matrixLabelDisplay(matrix_score);

  const handleSubmit = async () => {
    if (!clientId || !proposal) return;
    setSubmitting(true);
    setError("");
    try {
      const wizardData = {
        accessibility: form.accessibility,
        discoverability: form.discoverability,
        exploitability: form.exploitability,
        authentication_score: form.authentication_score,
        repeatability: form.repeatability,
        data_impact: form.data_impact,
        operational_impact: form.operational_impact,
        financial_impact: form.financial_impact,
        treatment_option: form.treatment_option,
        rationales,
      };
      await riskProposalsApi.evaluate(clientId, proposal.id, {
        title: form.title,
        description: form.description,
        category: form.risk_area,
        risk_area: form.risk_area,
        risk_type_gcim8: form.risk_type_gcim8,
        accessibility: form.accessibility,
        discoverability: form.discoverability,
        exploitability: form.exploitability,
        authentication_score: form.authentication_score,
        repeatability: form.repeatability,
        consequence: Math.round(impact_avg),
        data_impact: form.data_impact,
        operational_impact: form.operational_impact,
        financial_impact: form.financial_impact,
        treatment_option: form.treatment_option,
        owner: form.owner,
        assignee_email: form.assignee_email,
        mitigation_plan: form.mitigation_plan,
        wizard_data: wizardData,
        measures,
        ai_assessment: aiAssessment,
      });
      onEvaluated();
      onClose();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Evaluation failed. Please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  const isLastStep = step === STEPS.length - 1;
  const canProceed = step === 0 ? !!form.title.trim() : true;

  const renderStep = () => {
    if (aiLoading && step === 0) {
      return (
        <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 6, gap: 2 }}>
          <CircularProgress size={40} sx={{ color: "#7C3AED" }} />
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            AI is analysing the risk and pre-filling all 5 steps…
          </Typography>
        </Box>
      );
    }

    switch (step) {
      // ── Step 0: Basic Info ───────────────────────────────────────────────
      case 0:
        return (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2.5 }}>
            {aiAssessment && (
              <Alert severity="success" icon={<AutoAwesome />} sx={{ py: 0.5 }}>
                AI pre-fill complete. Review and adjust any fields — your changes are kept.
              </Alert>
            )}
            <TextField label="Risk Title *" fullWidth value={form.title}
              onChange={(e) => set("title", e.target.value)} />
            <TextField label="Scenario / Description" fullWidth multiline minRows={3}
              value={form.description} onChange={(e) => set("description", e.target.value)} />
            <FormControl fullWidth>
              <InputLabel>Risk Area</InputLabel>
              <Select value={form.risk_area} label="Risk Area"
                onChange={(e) => {
                  const v = e.target.value;
                  set("risk_area", v);
                  set("risk_type_gcim8", RISK_AREAS_PROJECT.includes(v) ? "Project" : "Security");
                }}>
                <MenuItem disabled><em>Security Risk</em></MenuItem>
                {RISK_AREAS_SECURITY.map((a) => <MenuItem key={a} value={a}>{a}</MenuItem>)}
                <MenuItem disabled><em>Project Risk</em></MenuItem>
                {RISK_AREAS_PROJECT.map((a) => <MenuItem key={a} value={a}>{a}</MenuItem>)}
              </Select>
            </FormControl>
            <FormControl>
              <FormLabel>Risk Type</FormLabel>
              <RadioGroup row value={form.risk_type_gcim8}
                onChange={(e) => set("risk_type_gcim8", e.target.value)}>
                <FormControlLabel value="Security" control={<Radio />} label="Security Risk" />
                <FormControlLabel value="Project" control={<Radio />} label="Project Risk" />
              </RadioGroup>
            </FormControl>
          </Box>
        );

      // ── Step 1: Likelihood Factors ──────────────────────────────────────
      case 1: {
        return (
          <Box>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1.5 }}>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 700 }}>Likelihood Factors</Typography>
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                  Rate how likely this risk can be triggered (1=lowest, 5=highest).
                </Typography>
              </Box>
              <Chip
                label={`Avg: ${likelihood_avg}/5`}
                size="small"
                sx={{ fontWeight: 700, bgcolor: `${scoreColor(Math.round(likelihood_avg))}20`, color: scoreColor(Math.round(likelihood_avg)) }}
              />
            </Box>
            <CompactFactorSlider factor="accessibility" label="Accessibility"
              description="How accessible is the system to a potential attacker?"
              value={form.accessibility} onChange={(v) => set("accessibility", v)}
              rationale={rationales.accessibility} />
            <CompactFactorSlider factor="discoverability" label="Discoverability"
              description="How easily can an attacker discover this vulnerability?"
              value={form.discoverability} onChange={(v) => set("discoverability", v)}
              rationale={rationales.discoverability} />
            <CompactFactorSlider factor="exploitability" label="Exploitability"
              description="How difficult is exploitation once discovered?"
              value={form.exploitability} onChange={(v) => set("exploitability", v)}
              rationale={rationales.exploitability} />
            <CompactFactorSlider factor="authentication_score" label="Authentication"
              description="Authentication strength protecting this resource (5=no auth, 1=strong MFA)."
              value={form.authentication_score} onChange={(v) => set("authentication_score", v)}
              rationale={rationales.authentication} />
            <CompactFactorSlider factor="repeatability" label="Repeatability"
              description="Can the attack be repeated reliably once exploited?"
              value={form.repeatability} onChange={(v) => set("repeatability", v)}
              rationale={rationales.repeatability} />
          </Box>
        );
      }

      // ── Step 2: Impact Factors ──────────────────────────────────────────
      case 2: {
        return (
          <Box>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1.5 }}>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 700 }}>Impact Factors</Typography>
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                  Rate the business impact if this risk materialises (1=lowest, 5=highest).
                </Typography>
              </Box>
              <Chip
                label={`Avg: ${impact_avg}/5`}
                size="small"
                sx={{ fontWeight: 700, bgcolor: `${scoreColor(Math.round(impact_avg))}20`, color: scoreColor(Math.round(impact_avg)) }}
              />
            </Box>
            <CompactFactorSlider factor="data_impact" label="Data Impact"
              description="What is the impact on data confidentiality and integrity?"
              value={form.data_impact} onChange={(v) => set("data_impact", v)}
              rationale={rationales.data_impact} />
            <CompactFactorSlider factor="operational_impact" label="Operational Impact"
              description="What is the impact on business operations and service availability?"
              value={form.operational_impact} onChange={(v) => set("operational_impact", v)}
              rationale={rationales.operational_impact} />
            <CompactFactorSlider factor="financial_impact" label="Financial & Regulatory Impact"
              description="What is the financial cost and regulatory consequence?"
              value={form.financial_impact} onChange={(v) => set("financial_impact", v)}
              rationale={rationales.financial_impact} />
          </Box>
        );
      }

      // ── Step 3: Security Measures ───────────────────────────────────────
      case 3:
        return (
          <MeasuresStep
            measures={measures}
            onMeasureChange={handleMeasureChange}
            workarounds={workarounds}
            onReassess={handleReassess}
            reassessing={reassessing}
            extraContext={extraContext}
            onContextChange={setExtraContext}
          />
        );

      // ── Step 4: Review & Treatment ──────────────────────────────────────
      case 4:
        return (
          <Box>
            <Grid container spacing={3}>
              <Grid size={{ xs: 12, md: 5 }}>
                <RiskMatrix impact={impact_avg} likelihood={likelihood_avg} />
                <Box sx={{ mt: 2, p: 2, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1 }}>
                  {[
                    ["Likelihood Avg", `${likelihood_avg} / 5`],
                    ["Impact Avg", `${impact_avg} / 5`],
                    ["Matrix Score", `${matrix_score} / 25`],
                  ].map(([k, v]) => (
                    <Box key={k} sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
                      <Typography variant="body2" sx={{ color: "text.secondary" }}>{k}</Typography>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{v}</Typography>
                    </Box>
                  ))}
                  <Box sx={{ mt: 1, display: "flex", alignItems: "center", gap: 1 }}>
                    <Typography variant="body2" sx={{ color: "text.secondary" }}>Risk Level</Typography>
                    <Chip label={risk_display} size="small"
                      sx={{ bgcolor: MATRIX_COLOURS[risk_label], color: "white", fontWeight: 700 }} />
                  </Box>
                  {measures.filter((m) => m.status === "in_place").length > 0 && (
                    <Chip size="small" icon={<CheckCircle sx={{ fontSize: 12 }} />}
                      label={`${measures.filter((m) => m.status === "in_place").length} controls in place`}
                      sx={{ mt: 1, bgcolor: "rgba(76,175,80,0.15)", color: "#4CAF50", fontSize: 10 }} />
                  )}
                </Box>
              </Grid>
              <Grid size={{ xs: 12, md: 7 }}>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
                  <FormControl fullWidth>
                    <FormLabel sx={{ mb: 1 }}>Treatment Option</FormLabel>
                    <RadioGroup row value={form.treatment_option}
                      onChange={(e) => set("treatment_option", e.target.value)}>
                      {["avoid","mitigate","transfer","accept"].map((t) => (
                        <FormControlLabel key={t} value={t} control={<Radio size="small" />}
                          label={t.charAt(0).toUpperCase() + t.slice(1)} />
                      ))}
                    </RadioGroup>
                  </FormControl>
                  <TextField label="Risk Owner" fullWidth value={form.owner}
                    onChange={(e) => set("owner", e.target.value)} />
                  <TextField label="Assignee Email" fullWidth value={form.assignee_email}
                    onChange={(e) => set("assignee_email", e.target.value)} />
                  <TextField label="Due Date" fullWidth type="date" value={form.due_date}
                    onChange={(e) => set("due_date", e.target.value)}
                    slotProps={{ inputLabel: { shrink: true } }} />
                  <TextField label="Mitigation Plan" fullWidth multiline minRows={3}
                    value={form.mitigation_plan}
                    onChange={(e) => set("mitigation_plan", e.target.value)} />
                  {aiAssessment?.overall_commentary && (
                    <Box sx={{ p: 1.5, bgcolor: "rgba(66,133,244,0.06)", borderRadius: 1,
                      border: "1px solid rgba(66,133,244,0.2)" }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", display: "flex", gap: 0.5 }}>
                        <AutoAwesome sx={{ fontSize: 13, mt: 0.1 }} />
                        {aiAssessment.overall_commentary}
                      </Typography>
                    </Box>
                  )}
                </Box>
              </Grid>
            </Grid>
          </Box>
        );

      default:
        return null;
    }
  };

  return (
    <>
      <Dialog open={open} onClose={onClose} fullWidth maxWidth="md"
        slotProps={{ paper: { sx: { minHeight: 560 } } }}>
        <DialogTitle sx={{ pb: 0 }}>
          <Typography variant="overline" sx={{ color: "text.secondary" }}>
            Step {step + 1} of {STEPS.length}
          </Typography>
          <Typography variant="h6" sx={{ fontWeight: 700, mt: 0.5 }}>
            {STEPS[step]}
          </Typography>
          <LinearProgress
            variant="determinate"
            value={((step + 1) / STEPS.length) * 100}
            sx={{ mt: 1.5, height: 3, borderRadius: 2 }} />
        </DialogTitle>

        <DialogContent sx={{ pt: 3 }}>
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
          {renderStep()}
        </DialogContent>

        <DialogActions sx={{ px: 3, py: 2, justifyContent: "space-between" }}>
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button onClick={onClose} variant="text">Cancel</Button>
            {step > 0 && (
              <Button onClick={() => setStep((s) => s - 1)} variant="outlined">Back</Button>
            )}
          </Box>
          <Box>
            {!isLastStep ? (
              <Button variant="contained" onClick={() => setStep((s) => s + 1)}
                disabled={!canProceed || aiLoading}>
                Next
              </Button>
            ) : (
              <Button variant="contained" onClick={handleSubmit} disabled={submitting}
                startIcon={submitting ? <CircularProgress size={16} /> : undefined}>
                Submit to Risk Register
              </Button>
            )}
          </Box>
        </DialogActions>
      </Dialog>

      <Snackbar open={!!snackMsg} autoHideDuration={4000} onClose={() => setSnackMsg("")}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
        message={snackMsg} />
    </>
  );
}
