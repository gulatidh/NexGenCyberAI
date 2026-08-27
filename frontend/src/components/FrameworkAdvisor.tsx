import React, { useState } from "react";
import {
  Box, Typography, Chip, Button, Dialog, DialogContent,
  Fab, Tooltip, LinearProgress, CircularProgress, TextField,
  IconButton, Divider, Checkbox, Paper, alpha, useTheme,
} from "@mui/material";
import {
  AutoAwesome, Close, ArrowForward, RestartAlt, CheckCircle,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { frameworksApi } from "../services/api";

// ── Types ─────────────────────────────────────────────────────────────────────

interface WizardStep {
  id: string;
  question: string;
  hint: string;
  multi_select: boolean;
  options: string[];
}

interface Recommendation {
  framework: string;
  framework_key: string;
  priority: "mandatory" | "recommended" | "optional";
  rationale: string;
  applicable_because: string[];
  effort: "low" | "medium" | "high";
  estimated_controls: number;
  available_in_platform: boolean;
}

interface OverlapInsight {
  frameworks: string[];
  overlap_pct: number;
  insight: string;
}

interface AdvisorResult {
  recommendations: Recommendation[];
  overlap_insights: OverlapInsight[];
  adoption_sequence: string[];
  summary: string;
}

interface FrameworkAdvisorProps {
  onSelectFrameworks?: (frameworkKeys: string[]) => void;
}

// ── Colour helpers ─────────────────────────────────────────────────────────────

const PRIORITY_COLOR: Record<string, string> = {
  mandatory: "#ef4444",
  recommended: "#f59e0b",
  optional: "#4285F4",
};

const EFFORT_COLOR: Record<string, string> = {
  low: "#10b981",
  medium: "#f59e0b",
  high: "#ef4444",
};

// ── Sub-components ─────────────────────────────────────────────────────────────

function AnswerSummary({
  steps,
  answers,
}: {
  steps: WizardStep[];
  answers: Record<string, string | string[]>;
}) {
  const theme = useTheme();
  const entries = steps.filter((s) => answers[s.id] !== undefined && answers[s.id] !== "");
  if (entries.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: "center", color: "text.secondary" }}>
        <AutoAwesome sx={{ fontSize: 40, mb: 1, opacity: 0.3 }} />
        <Typography variant="body2">
          Your answers will appear here as you progress through the wizard.
        </Typography>
      </Box>
    );
  }
  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
      {entries.map((step) => {
        const val = answers[step.id];
        const display = Array.isArray(val) ? val.join(", ") : val;
        return (
          <Box key={step.id}>
            <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", letterSpacing: 0.5, fontSize: 10 }}>
              {step.question.replace(/\?$/, "")}
            </Typography>
            <Typography variant="body2" sx={{ fontWeight: 600, mt: 0.25 }}>
              {display}
            </Typography>
          </Box>
        );
      })}
    </Box>
  );
}

function RecommendationCard({
  rec,
  selected,
  onToggle,
}: {
  rec: Recommendation;
  selected: boolean;
  onToggle: () => void;
}) {
  const theme = useTheme();
  const priorityColor = PRIORITY_COLOR[rec.priority] ?? "#4285F4";
  const effortColor = EFFORT_COLOR[rec.effort] ?? "#f59e0b";

  return (
    <Paper
      variant="outlined"
      sx={{
        p: 2.5,
        borderRadius: 2,
        cursor: "pointer",
        border: selected
          ? `2px solid ${theme.palette.primary.main}`
          : `1px solid ${alpha(theme.palette.divider, 0.8)}`,
        background: selected ? alpha(theme.palette.primary.main, 0.06) : "transparent",
        transition: "all 0.2s",
        "&:hover": { borderColor: theme.palette.primary.main, background: alpha(theme.palette.primary.main, 0.04) },
      }}
      onClick={onToggle}
    >
      {/* Header row */}
      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1.5 }}>
        <Checkbox
          checked={selected}
          size="small"
          sx={{ mt: -0.5, ml: -0.5 }}
          onClick={(e) => e.stopPropagation()}
          onChange={onToggle}
        />
        <Box sx={{ flex: 1 }}>
          <Box sx={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 0.75, mb: 0.5 }}>
            <Typography sx={{ fontWeight: 800, fontSize: 15 }}>{rec.framework}</Typography>
            {rec.available_in_platform && (
              <Chip
                label="In Platform"
                size="small"
                icon={<CheckCircle sx={{ fontSize: "14px !important" }} />}
                sx={{ background: alpha("#10b981", 0.15), color: "#10b981", border: `1px solid ${alpha("#10b981", 0.3)}`, height: 20, fontSize: 11 }}
              />
            )}
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
            <Chip
              label={rec.priority.charAt(0).toUpperCase() + rec.priority.slice(1)}
              size="small"
              sx={{ background: alpha(priorityColor, 0.15), color: priorityColor, border: `1px solid ${alpha(priorityColor, 0.3)}`, height: 20, fontSize: 11, fontWeight: 700 }}
            />
            <Chip
              label={`Effort: ${rec.effort}`}
              size="small"
              sx={{ background: alpha(effortColor, 0.12), color: effortColor, height: 20, fontSize: 11 }}
            />
            <Chip
              label={`~${rec.estimated_controls} controls`}
              size="small"
              sx={{ background: alpha(theme.palette.text.secondary, 0.08), color: "text.secondary", height: 20, fontSize: 11 }}
            />
          </Box>
        </Box>
      </Box>

      {/* Rationale */}
      <Typography variant="body2" sx={{ color: "text.secondary", lineHeight: 1.6, mb: 1.25, fontSize: 13 }}>
        {rec.rationale}
      </Typography>

      {/* Applicable because */}
      {rec.applicable_because?.length > 0 && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.4 }}>
          {rec.applicable_because.map((reason, i) => (
            <Box key={i} sx={{ display: "flex", gap: 1, alignItems: "flex-start" }}>
              <Box sx={{ width: 4, height: 4, borderRadius: "50%", background: priorityColor, mt: "7px", flexShrink: 0 }} />
              <Typography variant="caption" sx={{ color: "text.secondary", lineHeight: 1.5 }}>{reason}</Typography>
            </Box>
          ))}
        </Box>
      )}
    </Paper>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function FrameworkAdvisor({ onSelectFrameworks }: FrameworkAdvisorProps) {
  const theme = useTheme();

  const [open, setOpen] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);
  const [answers, setAnswers] = useState<Record<string, string | string[]>>({});
  const [multiSelected, setMultiSelected] = useState<string[]>([]);
  const [customInputOpen, setCustomInputOpen] = useState(false);
  const [customText, setCustomText] = useState("");
  const [recommendations, setRecommendations] = useState<AdvisorResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedForCompare, setSelectedForCompare] = useState<Set<string>>(new Set());

  const { data: stepsData } = useQuery({
    queryKey: ["framework-advisor-steps"],
    queryFn: frameworksApi.advisorSteps,
    staleTime: Infinity,
  });

  const steps: WizardStep[] = stepsData?.steps ?? [];
  const currentStep = steps[stepIndex];
  const totalSteps = steps.length;
  const progress = totalSteps > 0 ? ((stepIndex) / totalSteps) * 100 : 0;
  const done = recommendations !== null;

  function resetWizard() {
    setStepIndex(0);
    setAnswers({});
    setMultiSelected([]);
    setCustomInputOpen(false);
    setCustomText("");
    setRecommendations(null);
    setLoading(false);
    setSelectedForCompare(new Set());
  }

  function handleClose() {
    setOpen(false);
  }

  async function submitAnswers(finalAnswers: Record<string, string | string[]>) {
    setLoading(true);
    try {
      const result = await frameworksApi.advisorRecommend(finalAnswers);
      setRecommendations(result as AdvisorResult);
    } catch {
      setRecommendations({
        recommendations: [],
        overlap_insights: [],
        adoption_sequence: [],
        summary: "Failed to get recommendations. Please check that an AI provider is configured.",
      });
    } finally {
      setLoading(false);
    }
  }

  function advance(newAnswers: Record<string, string | string[]>) {
    const nextIndex = stepIndex + 1;
    if (nextIndex >= totalSteps) {
      submitAnswers(newAnswers);
    } else {
      setStepIndex(nextIndex);
      setMultiSelected([]);
      setCustomInputOpen(false);
      setCustomText("");
    }
  }

  function handleSingleSelect(option: string) {
    const newAnswers = { ...answers, [currentStep.id]: option };
    setAnswers(newAnswers);
    advance(newAnswers);
  }

  function toggleMultiOption(option: string) {
    setMultiSelected((prev) =>
      prev.includes(option) ? prev.filter((o) => o !== option) : [...prev, option]
    );
  }

  function handleMultiNext() {
    const selected = multiSelected.length > 0 ? multiSelected : [];
    const newAnswers = { ...answers, [currentStep.id]: selected };
    setAnswers(newAnswers);
    advance(newAnswers);
  }

  function handleCustomAdd() {
    if (!customText.trim()) return;
    if (currentStep.multi_select) {
      const updated = [...multiSelected.filter((o) => !o.startsWith("__custom__")), `__custom__${customText.trim()}`];
      setMultiSelected(updated);
    } else {
      handleSingleSelect(customText.trim());
    }
    setCustomInputOpen(false);
    setCustomText("");
  }

  function toggleCompare(key: string) {
    setSelectedForCompare((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function handleCompare() {
    const keys = Array.from(selectedForCompare);
    onSelectFrameworks?.(keys);
    handleClose();
  }

  const platformKeys = recommendations?.recommendations
    .filter((r) => r.available_in_platform && selectedForCompare.has(r.framework_key))
    .map((r) => r.framework_key) ?? [];

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <>
      {/* Floating Fab */}
      <Tooltip title="Help me choose a framework" placement="left">
        <Fab
          color="primary"
          size="medium"
          onClick={() => setOpen(true)}
          sx={{
            position: "fixed",
            bottom: 32,
            right: 32,
            zIndex: 1200,
            background: "linear-gradient(135deg, #4285F4 0%, #7C3AED 100%)",
            "&:hover": { background: "linear-gradient(135deg, #3b77e3 0%, #6d35d9 100%)" },
            boxShadow: "0 8px 32px rgba(66,133,244,0.4)",
          }}
        >
          <AutoAwesome />
        </Fab>
      </Tooltip>

      {/* Dialog */}
      <Dialog
        open={open}
        onClose={handleClose}
        fullWidth
        maxWidth="lg"
        sx={{
          "& .MuiDialog-paper": {
            height: "88vh",
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          },
        }}
      >
        {/* Header */}
        <Box sx={{
          px: 3, py: 2,
          display: "flex", alignItems: "center", justifyContent: "space-between",
          borderBottom: `1px solid ${theme.palette.divider}`,
          flexShrink: 0,
        }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            <AutoAwesome sx={{ color: theme.palette.primary.main }} />
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1 }}>
                Framework Advisor
              </Typography>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {done ? "AI recommendation based on your profile" : `Step ${Math.min(stepIndex + 1, totalSteps)} of ${totalSteps}`}
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1 }}>
            {(stepIndex > 0 || done) && (
              <Button size="small" startIcon={<RestartAlt />} onClick={resetWizard} sx={{ color: "text.secondary" }}>
                Start over
              </Button>
            )}
            <IconButton size="small" onClick={handleClose}><Close /></IconButton>
          </Box>
        </Box>

        {/* Progress bar */}
        {!done && (
          <LinearProgress
            variant="determinate"
            value={progress}
            sx={{ height: 3, flexShrink: 0 }}
          />
        )}
        {done && <Box sx={{ height: 3, background: theme.palette.primary.main, flexShrink: 0 }} />}

        {/* Body */}
        <DialogContent sx={{ p: 0, display: "flex", flex: 1, overflow: "hidden" }}>
          {/* Left panel — wizard or results list */}
          <Box sx={{
            width: { xs: "100%", md: done ? "60%" : "58%" },
            display: "flex",
            flexDirection: "column",
            borderRight: { md: `1px solid ${theme.palette.divider}` },
            overflow: "hidden",
          }}>
            <Box sx={{ flex: 1, overflowY: "auto", p: 3 }}>
              {loading && (
                <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 2 }}>
                  <CircularProgress size={48} />
                  <Typography variant="body2" sx={{ color: "text.secondary" }}>
                    Analysing your profile and generating recommendations…
                  </Typography>
                </Box>
              )}

              {!loading && !done && currentStep && (
                <>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 0.75, lineHeight: 1.3 }}>
                    {currentStep.question}
                  </Typography>
                  <Typography variant="body2" sx={{ color: "text.secondary", mb: 3 }}>
                    {currentStep.hint}
                    {currentStep.multi_select && " — select all that apply"}
                  </Typography>

                  {/* Option chips */}
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
                    {currentStep.options.map((opt) => {
                      const isSelected = currentStep.multi_select
                        ? multiSelected.includes(opt)
                        : false;
                      return (
                        <Chip
                          key={opt}
                          label={opt}
                          clickable
                          variant={isSelected ? "filled" : "outlined"}
                          color={isSelected ? "primary" : "default"}
                          onClick={() => {
                            if (currentStep.multi_select) {
                              toggleMultiOption(opt);
                            } else {
                              handleSingleSelect(opt);
                            }
                          }}
                          sx={{
                            fontSize: 13,
                            height: 36,
                            borderRadius: 2,
                            fontWeight: isSelected ? 700 : 400,
                          }}
                        />
                      );
                    })}

                    {/* Something else chip */}
                    {!customInputOpen && (
                      <Chip
                        label="Something else…"
                        clickable
                        variant="outlined"
                        color="secondary"
                        onClick={() => setCustomInputOpen(true)}
                        sx={{ fontSize: 13, height: 36, borderRadius: 2, borderStyle: "dashed" }}
                      />
                    )}
                  </Box>

                  {/* Custom input */}
                  {customInputOpen && (
                    <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
                      <TextField
                        size="small"
                        autoFocus
                        placeholder="Describe your answer…"
                        value={customText}
                        onChange={(e) => setCustomText(e.target.value)}
                        onKeyDown={(e) => { if (e.key === "Enter") handleCustomAdd(); }}
                        sx={{ flex: 1 }}
                      />
                      <Button variant="contained" size="small" onClick={handleCustomAdd} disabled={!customText.trim()}>
                        Add
                      </Button>
                      <Button size="small" onClick={() => { setCustomInputOpen(false); setCustomText(""); }}>
                        Cancel
                      </Button>
                    </Box>
                  )}

                  {/* Show custom selections */}
                  {currentStep.multi_select && multiSelected.filter((o) => o.startsWith("__custom__")).map((o) => (
                    <Chip
                      key={o}
                      label={o.replace("__custom__", "")}
                      onDelete={() => setMultiSelected((prev) => prev.filter((x) => x !== o))}
                      color="secondary"
                      sx={{ mr: 1, mb: 1 }}
                    />
                  ))}

                  {/* Next button for multi-select */}
                  {currentStep.multi_select && (
                    <Box sx={{ mt: 3 }}>
                      <Button
                        variant="contained"
                        endIcon={<ArrowForward />}
                        disabled={multiSelected.length === 0}
                        onClick={handleMultiNext}
                        sx={{ borderRadius: 2 }}
                      >
                        {stepIndex === totalSteps - 1 ? "Get Recommendations" : "Next"}
                      </Button>
                    </Box>
                  )}
                </>
              )}

              {!loading && done && recommendations && (
                <>
                  {/* Summary */}
                  <Box sx={{
                    p: 2, mb: 3, borderRadius: 2,
                    background: alpha(theme.palette.primary.main, 0.08),
                    border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
                  }}>
                    <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
                      {recommendations.summary}
                    </Typography>
                  </Box>

                  {/* Recommendation cards */}
                  <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 700 }}>
                    Recommended Frameworks ({recommendations.recommendations.length})
                  </Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5, mb: 3 }}>
                    {recommendations.recommendations.map((rec) => (
                      <RecommendationCard
                        key={rec.framework_key}
                        rec={rec}
                        selected={selectedForCompare.has(rec.framework_key)}
                        onToggle={() => toggleCompare(rec.framework_key)}
                      />
                    ))}
                  </Box>

                  {/* Overlap insights */}
                  {recommendations.overlap_insights?.length > 0 && (
                    <>
                      <Divider sx={{ my: 2 }} />
                      <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 700 }}>
                        Control Overlap Insights
                      </Typography>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                        {recommendations.overlap_insights.map((ins, i) => (
                          <Box key={i} sx={{
                            p: 1.5, borderRadius: 1.5,
                            background: alpha("#f59e0b", 0.08),
                            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
                          }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, color: "#f59e0b" }}>
                              {ins.frameworks.join(" + ")} — {ins.overlap_pct}% overlap
                            </Typography>
                            <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.25, fontSize: 12 }}>
                              {ins.insight}
                            </Typography>
                          </Box>
                        ))}
                      </Box>
                    </>
                  )}
                </>
              )}
            </Box>

            {/* Bottom action bar — shown after recommendations */}
            {done && !loading && (
              <Box sx={{
                px: 3, py: 2,
                borderTop: `1px solid ${theme.palette.divider}`,
                display: "flex", gap: 1.5, alignItems: "center",
                flexShrink: 0,
              }}>
                <Button
                  variant="contained"
                  disabled={platformKeys.length === 0}
                  onClick={handleCompare}
                  sx={{ borderRadius: 2 }}
                >
                  {platformKeys.length > 0
                    ? `Compare in Platform (${platformKeys.length})`
                    : "Select a platform framework to compare"}
                </Button>
                <Button variant="outlined" startIcon={<RestartAlt />} onClick={resetWizard}>
                  Start over
                </Button>
              </Box>
            )}
          </Box>

          {/* Right panel — answer summary or adoption sequence */}
          <Box sx={{
            display: { xs: "none", md: "flex" },
            flexDirection: "column",
            width: done ? "40%" : "42%",
            overflow: "hidden",
          }}>
            <Box sx={{
              px: 2.5, py: 2,
              borderBottom: `1px solid ${theme.palette.divider}`,
              flexShrink: 0,
            }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.secondary", textTransform: "uppercase", letterSpacing: 0.5, fontSize: 11 }}>
                {done ? "Your Profile" : "Your answers so far"}
              </Typography>
            </Box>
            <Box sx={{ flex: 1, overflowY: "auto", p: 2.5 }}>
              <AnswerSummary steps={steps} answers={answers} />

              {done && recommendations?.adoption_sequence?.length > 0 && (
                <>
                  <Divider sx={{ my: 3 }} />
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>
                    Recommended Adoption Order
                  </Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    {recommendations.adoption_sequence.map((fw, i) => (
                      <Box key={fw} sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                        <Box sx={{
                          width: 28, height: 28, borderRadius: "50%", flexShrink: 0,
                          background: `linear-gradient(135deg, #4285F4, #7C3AED)`,
                          display: "flex", alignItems: "center", justifyContent: "center",
                        }}>
                          <Typography sx={{ fontSize: 12, fontWeight: 700, color: "white" }}>{i + 1}</Typography>
                        </Box>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>{fw}</Typography>
                      </Box>
                    ))}
                  </Box>
                </>
              )}
            </Box>
          </Box>
        </DialogContent>
      </Dialog>
    </>
  );
}
