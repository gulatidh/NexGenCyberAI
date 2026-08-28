import React, { useState, useCallback } from "react";
import {
  Dialog, DialogTitle, DialogContent, DialogActions,
  Box, Typography, Button, TextField, Select, MenuItem,
  FormControl, InputLabel, Slider, Radio, RadioGroup,
  FormControlLabel, FormLabel, Chip, CircularProgress,
  Accordion, AccordionSummary, AccordionDetails, Alert,
  LinearProgress, Grid,
} from "@mui/material";
import { ExpandMore, AutoAwesome } from "@mui/icons-material";
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

const ALL_RISK_AREAS = [...RISK_AREAS_SECURITY, ...RISK_AREAS_PROJECT];

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
  consequence: [
    "Negligible — no business impact",
    "Minor — limited impact, easily remediated",
    "Moderate — noticeable disruption, moderate cost",
    "Major — significant disruption, data loss, compliance breach",
    "Critical — catastrophic, existential business risk",
  ],
};

const MATRIX_COLOURS: Record<string, string> = {
  low: "#2e7d32",
  medium: "#f57c00",
  medium_high: "#e65100",
  high: "#b71c1c",
  critical: "#4a0000",
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

// ── Risk Matrix 5×5 ──────────────────────────────────────────────────────────

function RiskMatrix({ consequence, likelihood }: { consequence: number; likelihood: number }) {
  const likelihoodCol = Math.max(1, Math.min(5, Math.round(likelihood)));
  const consequenceRow = Math.max(1, Math.min(5, consequence));

  return (
    <Box>
      <Typography variant="caption" sx={{ color: "text.secondary", mb: 1, display: "block" }}>
        5×5 Risk Matrix — GCC IM8
      </Typography>
      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 0.5 }}>
        {/* Y-axis label */}
        <Box sx={{ display: "flex", flexDirection: "column", justifyContent: "center", mr: 0.5 }}>
          <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 9, writingMode: "vertical-rl",
            transform: "rotate(180deg)", whiteSpace: "nowrap", lineHeight: 1 }}>
            Consequence ↑
          </Typography>
        </Box>
        <Box>
          {/* Header row */}
          <Box sx={{ display: "flex", mb: 0.5 }}>
            <Box sx={{ width: 32 }} />
            {[1, 2, 3, 4, 5].map((c) => (
              <Typography key={c} variant="caption"
                sx={{ width: 40, textAlign: "center", color: "text.secondary", fontSize: 10 }}>
                {c}
              </Typography>
            ))}
          </Box>
          {/* Grid rows (consequence descending) */}
          {[5, 4, 3, 2, 1].map((cons) => (
            <Box key={cons} sx={{ display: "flex", alignItems: "center", mb: 0.5 }}>
              <Typography variant="caption"
                sx={{ width: 32, textAlign: "right", pr: 0.5, color: "text.secondary", fontSize: 10 }}>
                {cons}
              </Typography>
              {[1, 2, 3, 4, 5].map((lik) => {
                const score = cons * lik;
                const label = matrixLabel(score);
                const isActive = cons === consequenceRow && lik === likelihoodCol;
                return (
                  <Box key={lik} sx={{
                    width: 40, height: 28,
                    bgcolor: isActive ? MATRIX_COLOURS[label] : "rgba(255,255,255,0.06)",
                    border: isActive ? "2px solid white" : "1px solid rgba(255,255,255,0.08)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    borderRadius: 0.5,
                    transition: "all 0.2s",
                    mr: 0.5,
                  }}>
                    <Typography variant="caption" sx={{
                      fontSize: 9, fontWeight: isActive ? 800 : 400,
                      color: isActive ? "white" : "text.disabled",
                    }}>
                      {score}
                    </Typography>
                  </Box>
                );
              })}
            </Box>
          ))}
          {/* X-axis label */}
          <Box sx={{ display: "flex", pl: 4 }}>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 9 }}>
              Likelihood →
            </Typography>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

// ── Factor Slider Step ────────────────────────────────────────────────────────

function FactorStep({
  factor, label, description, value, onChange,
}: {
  factor: string; label: string; description: string;
  value: number; onChange: (v: number) => void;
}) {
  const labels = FACTOR_LABELS[factor] || [];
  return (
    <Box>
      <Typography variant="h6" sx={{ mb: 1, fontWeight: 700 }}>{label}</Typography>
      <Typography variant="body2" sx={{ color: "text.secondary", mb: 3 }}>{description}</Typography>
      <Box sx={{ px: 2 }}>
        <Slider
          value={value}
          min={1} max={5} step={1}
          marks={[1,2,3,4,5].map((v) => ({ value: v, label: String(v) }))}
          onChange={(_, v) => onChange(v as number)}
          sx={{ "& .MuiSlider-mark": { bgcolor: "divider" } }}
        />
      </Box>
      <Box sx={{ mt: 2, p: 2, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1,
        borderLeft: "3px solid", borderColor: "primary.main" }}>
        <Typography variant="body2" sx={{ fontWeight: 600 }}>
          Level {value}: {labels[value - 1] || `Score ${value}/5`}
        </Typography>
      </Box>
    </Box>
  );
}

// ── Step config ───────────────────────────────────────────────────────────────

const STEPS = [
  "Basic Info",
  "Accessibility",
  "Discoverability",
  "Exploitability",
  "Authentication",
  "Repeatability",
  "Consequence",
  "Review & Treatment",
];

interface FormData {
  title: string;
  description: string;
  risk_area: string;
  risk_type_gcim8: string;
  accessibility: number;
  discoverability: number;
  exploitability: number;
  authentication_score: number;
  repeatability: number;
  consequence: number;
  treatment_option: string;
  owner: string;
  assignee_email: string;
  due_date: string;
  mitigation_plan: string;
}

const DEFAULT_FORM: FormData = {
  title: "", description: "", risk_area: "", risk_type_gcim8: "Security",
  accessibility: 3, discoverability: 3, exploitability: 3,
  authentication_score: 3, repeatability: 3, consequence: 3,
  treatment_option: "mitigate", owner: "", assignee_email: "", due_date: "", mitigation_plan: "",
};

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
  const [aiResult, setAiResult] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  // Populate form from proposal when it opens
  React.useEffect(() => {
    if (open && proposal) {
      setStep(0);
      setAiResult(null);
      setError("");
      setForm({
        ...DEFAULT_FORM,
        title: proposal.title || "",
        description: proposal.description || "",
        risk_area: proposal.category || "",
        risk_type_gcim8: proposal.risk_type || "Security",
      });
    }
  }, [open, proposal]);

  const set = useCallback(<K extends keyof FormData>(key: K, val: FormData[K]) => {
    setForm((f) => ({ ...f, [key]: val }));
  }, []);

  const likelihood_avg = parseFloat(
    ((form.accessibility + form.discoverability + form.exploitability +
      form.authentication_score + form.repeatability) / 5
    ).toFixed(2)
  );
  const matrix_score = Math.round(form.consequence * likelihood_avg);
  const risk_label = matrixLabel(matrix_score);
  const risk_display = matrixLabelDisplay(matrix_score);

  const handleAiAssess = async () => {
    if (!clientId) return;
    setAiLoading(true);
    try {
      const result = await riskProposalsApi.analyse(clientId, {
        title: form.title,
        description: form.description,
        category: form.risk_area,
        risk_type: form.risk_type_gcim8,
        accessibility: form.accessibility,
        discoverability: form.discoverability,
        exploitability: form.exploitability,
        authentication_score: form.authentication_score,
        repeatability: form.repeatability,
        consequence: form.consequence,
      });
      setAiResult(result);
      if (result.recommended_treatment) {
        const t = result.recommended_treatment.split(" ")[0].toLowerCase();
        if (["avoid","mitigate","transfer","accept"].includes(t)) {
          set("treatment_option", t);
        }
      }
      if (result.mitigation_steps?.length && !form.mitigation_plan) {
        set("mitigation_plan", result.mitigation_steps.join("\n"));
      }
    } catch {
      // ignore
    } finally {
      setAiLoading(false);
    }
  };

  const handleSubmit = async () => {
    if (!clientId || !proposal) return;
    setSubmitting(true);
    setError("");
    try {
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
        consequence: form.consequence,
        treatment_option: form.treatment_option,
        owner: form.owner,
        assignee_email: form.assignee_email,
        mitigation_plan: form.mitigation_plan,
      });
      onEvaluated();
      onClose();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Evaluation failed. Please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  const isFirstStep = step === 0;
  const isLastStep = step === STEPS.length - 1;
  const canProceed = step === 0 ? !!form.title.trim() : true;

  const renderStep = () => {
    switch (step) {
      case 0:
        return (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2.5 }}>
            <TextField
              label="Risk Title *" fullWidth value={form.title}
              onChange={(e) => set("title", e.target.value)}
            />
            <TextField
              label="Description" fullWidth multiline minRows={3} value={form.description}
              onChange={(e) => set("description", e.target.value)}
            />
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
      case 1:
        return <FactorStep factor="accessibility" label="Accessibility"
          description="How accessible is the system or resource to a potential attacker?"
          value={form.accessibility} onChange={(v) => set("accessibility", v)} />;
      case 2:
        return <FactorStep factor="discoverability" label="Discoverability"
          description="How easily can an attacker discover this vulnerability or entry point?"
          value={form.discoverability} onChange={(v) => set("discoverability", v)} />;
      case 3:
        return <FactorStep factor="exploitability" label="Exploitability"
          description="How difficult is it to actually exploit this vulnerability once discovered?"
          value={form.exploitability} onChange={(v) => set("exploitability", v)} />;
      case 4:
        return <FactorStep factor="authentication_score" label="Authentication"
          description="How strong is the authentication protecting this resource? (5 = no auth, 1 = strong MFA)"
          value={form.authentication_score} onChange={(v) => set("authentication_score", v)} />;
      case 5:
        return <FactorStep factor="repeatability" label="Repeatability"
          description="If the vulnerability is exploited, can the attack be repeated reliably?"
          value={form.repeatability} onChange={(v) => set("repeatability", v)} />;
      case 6:
        return <FactorStep factor="consequence" label="Consequence"
          description="What is the business impact if this risk materialises?"
          value={form.consequence} onChange={(v) => set("consequence", v)} />;
      case 7:
        return (
          <Box>
            <Grid container spacing={3}>
              <Grid size={{ xs: 12, md: 5 }}>
                <RiskMatrix consequence={form.consequence} likelihood={likelihood_avg} />
                <Box sx={{ mt: 2, p: 2, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1 }}>
                  {[
                    ["Likelihood Avg", `${likelihood_avg} / 5`],
                    ["Consequence", `${form.consequence} / 5`],
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
                  <Button
                    variant="outlined" startIcon={aiLoading ? <CircularProgress size={16} /> : <AutoAwesome />}
                    onClick={handleAiAssess} disabled={aiLoading}
                    sx={{ alignSelf: "flex-start" }}>
                    AI Assess
                  </Button>
                  {aiResult && (
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMore />}>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>AI Assessment Result</Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Typography variant="body2" sx={{ mb: 1 }}>{aiResult.summary}</Typography>
                        {aiResult.key_controls?.length > 0 && (
                          <Box sx={{ mb: 1 }}>
                            <Typography variant="caption" sx={{ color: "text.secondary" }}>Key Controls</Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                              {aiResult.key_controls.map((c: string, i: number) => (
                                <Chip key={i} label={c} size="small" />
                              ))}
                            </Box>
                          </Box>
                        )}
                        {aiResult.residual_risk_after_controls && (
                          <Typography variant="caption" sx={{ color: "text.secondary" }}>
                            Residual: {aiResult.residual_risk_after_controls}
                          </Typography>
                        )}
                      </AccordionDetails>
                    </Accordion>
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
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md"
      slotProps={{ paper: { sx: { minHeight: 520 } } }}>
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
          sx={{ mt: 1.5, height: 3, borderRadius: 2 }}
        />
      </DialogTitle>

      <DialogContent sx={{ pt: 3 }}>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        {renderStep()}
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 2, justifyContent: "space-between" }}>
        <Box sx={{ display: "flex", gap: 1 }}>
          <Button onClick={onClose} variant="text">Cancel</Button>
          {!isFirstStep && (
            <Button onClick={() => setStep((s) => s - 1)} variant="outlined">Back</Button>
          )}
        </Box>
        <Box>
          {!isLastStep ? (
            <Button
              variant="contained"
              onClick={() => setStep((s) => s + 1)}
              disabled={!canProceed}>
              Next
            </Button>
          ) : (
            <Button
              variant="contained"
              onClick={handleSubmit}
              disabled={submitting}
              startIcon={submitting ? <CircularProgress size={16} /> : undefined}>
              Submit to Risk Register
            </Button>
          )}
        </Box>
      </DialogActions>
    </Dialog>
  );
}
