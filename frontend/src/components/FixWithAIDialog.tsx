import React, { useState, useEffect, useCallback } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
  Typography,
  Button,
  LinearProgress,
  Chip,
  Alert,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Collapse,
  IconButton,
  Tooltip,
  useMediaQuery,
  useTheme,
  Divider,
} from "@mui/material";
import {
  AutoFixHigh,
  ContentCopy,
  CheckCircle,
  WarningAmber,
  Terminal,
  Cloud,
  Code,
  InfoOutlined,
  ExpandMore,
  CheckCircleOutlined,
  ErrorOutlined,
  Bolt,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { toast } from "react-toastify";
import { Finding, RemediationJob, FindingRemediationPlan, RemediationJobStatus } from "../types";
import { remediationJobsApi } from "../services/api";

// ─── Colour helpers ──────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: "#EA4335",
  high: "#FF6D00",
  medium: "#FBBC04",
  low: "#34A853",
  info: "#9AA0A6",
};

function confidenceColor(score: number): string {
  if (score >= 80) return "#34A853";
  if (score >= 50) return "#FBBC04";
  return "#EA4335";
}

const ARTIFACT_META: Record<
  FindingRemediationPlan["artifact_type"],
  { label: string; color: string; icon: React.ReactNode }
> = {
  bash:       { label: "Bash",       color: "#4285F4", icon: <Terminal fontSize="small" /> },
  powershell: { label: "PowerShell", color: "#9C27B0", icon: <Terminal fontSize="small" /> },
  aws_cli:    { label: "AWS CLI",    color: "#FF9900", icon: <Cloud fontSize="small" /> },
  azure_cli:  { label: "Azure CLI",  color: "#0089D6", icon: <Cloud fontSize="small" /> },
  terraform:  { label: "Terraform",  color: "#844FBA", icon: <Code fontSize="small" /> },
  code_patch: { label: "Code Patch", color: "#34A853", icon: <Code fontSize="small" /> },
  manual:     { label: "Manual",     color: "#9AA0A6", icon: <InfoOutlined fontSize="small" /> },
};

const DOWNTIME_META: Record<
  FindingRemediationPlan["estimated_downtime"],
  { label: string; color: string }
> = {
  none:               { label: "None",               color: "#34A853" },
  minimal:            { label: "Minimal",            color: "#FBBC04" },
  maintenance_window: { label: "Maintenance Window", color: "#EA4335" },
};

const RISK_COLORS: Record<string, string> = {
  low: "#34A853",
  medium: "#FBBC04",
  high: "#EA4335",
};

const AUTOMATABLE_META: Record<
  FindingRemediationPlan["automatable"],
  { label: string; color: string }
> = {
  yes:     { label: "Yes",     color: "#34A853" },
  partial: { label: "Partial", color: "#FBBC04" },
  no:      { label: "Manual",  color: "#9AA0A6" },
};

const CYCLING_SUBTITLES = [
  "Analysing findings...",
  "Generating remediation scripts...",
  "Evaluating risks & rollback paths...",
  "Preparing executable artifacts...",
];

const VERIFYING_SUBTITLE = "Running verification rescan...";

// ─── Props ────────────────────────────────────────────────────────────────────

export interface FixWithAIDialogProps {
  open: boolean;
  onClose: () => void;
  findings: Finding[];
  clientId: string;
  scanId?: string;
  preloadedJob?: RemediationJob;
}

// ─── Copy button ──────────────────────────────────────────────────────────────

interface CopyButtonProps {
  text: string;
}

function CopyButton({ text }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [text]);

  return (
    <Tooltip title={copied ? "Copied!" : "Copy"} placement="left">
      <IconButton
        size="small"
        onClick={handleCopy}
        sx={{
          position: "absolute",
          top: 8,
          right: 8,
          color: copied ? "#34A853" : "rgba(255,255,255,0.5)",
          "&:hover": { color: "#fff" },
        }}
      >
        <ContentCopy fontSize="small" />
      </IconButton>
    </Tooltip>
  );
}

// ─── Per-finding plan card ────────────────────────────────────────────────────

interface PlanCardProps {
  plan: FindingRemediationPlan;
  finding: Finding | undefined;
  verificationResult?: "resolved" | "unresolved";
  defaultExpanded?: boolean;
}

function PlanCard({ plan, finding, verificationResult, defaultExpanded = true }: PlanCardProps) {
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const artifactMeta = ARTIFACT_META[plan.artifact_type];
  const downtimeMeta = DOWNTIME_META[plan.estimated_downtime];

  const title = finding?.title ?? plan.finding_title ?? `Finding #${plan.finding_id.slice(-6)}`;
  const severity = finding?.severity ?? plan.finding_severity ?? "info";

  return (
    <Accordion defaultExpanded={defaultExpanded} sx={{ bgcolor: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)", mb: 1 }}>
      <AccordionSummary expandIcon={<ExpandMore />}>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, alignItems: "center", flex: 1, mr: 1 }}>
          <Chip
            label={severity.toUpperCase()}
            size="small"
            sx={{
              bgcolor: SEV_COLORS[severity] ?? "#9AA0A6",
              color: "#fff",
              fontWeight: 700,
              fontSize: 10,
            }}
          />
          <Typography variant="body2" sx={{ fontWeight: 600, flex: 1, minWidth: 120 }}>
            {title}
          </Typography>
          <Chip
            label={`${plan.confidence_score}%`}
            size="small"
            sx={{
              bgcolor: confidenceColor(plan.confidence_score),
              color: "#fff",
              fontWeight: 700,
              fontSize: 10,
            }}
          />
          <Chip
            label={AUTOMATABLE_META[plan.automatable].label}
            size="small"
            sx={{
              bgcolor: "transparent",
              border: `1px solid ${AUTOMATABLE_META[plan.automatable].color}`,
              color: AUTOMATABLE_META[plan.automatable].color,
              fontSize: 10,
            }}
          />
          <Chip
            label={plan.risk_level.toUpperCase()}
            size="small"
            sx={{
              bgcolor: "transparent",
              border: `1px solid ${RISK_COLORS[plan.risk_level] ?? "#9AA0A6"}`,
              color: RISK_COLORS[plan.risk_level] ?? "#9AA0A6",
              fontSize: 10,
            }}
          />
          {verificationResult && (
            <Chip
              icon={
                verificationResult === "resolved" ? (
                  <CheckCircle sx={{ fontSize: "14px !important", color: "#34A853 !important" }} />
                ) : (
                  <ErrorOutlined sx={{ fontSize: "14px !important", color: "#EA4335 !important" }} />
                )
              }
              label={verificationResult === "resolved" ? "Resolved" : "Unresolved"}
              size="small"
              sx={{
                bgcolor:
                  verificationResult === "resolved"
                    ? "rgba(52,168,83,0.12)"
                    : "rgba(234,67,53,0.12)",
                color: verificationResult === "resolved" ? "#34A853" : "#EA4335",
                border: `1px solid ${verificationResult === "resolved" ? "#34A853" : "#EA4335"}`,
                fontSize: 10,
              }}
            />
          )}
        </Box>
      </AccordionSummary>

      <AccordionDetails sx={{ pt: 0 }}>
        {/* Estimated downtime row */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
          <Typography variant="caption" color="text.secondary">
            Estimated downtime:
          </Typography>
          <Chip
            label={downtimeMeta.label}
            size="small"
            sx={{
              bgcolor: "transparent",
              border: `1px solid ${downtimeMeta.color}`,
              color: downtimeMeta.color,
              fontSize: 10,
            }}
          />
        </Box>

        <Divider sx={{ mb: 2, borderColor: "rgba(255,255,255,0.08)" }} />

        {/* Step-by-step plan */}
        <Typography
          variant="caption"
          sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "text.secondary" }}
        >
          Remediation Steps
        </Typography>
        <Box component="ol" sx={{ mt: 1, mb: 2, pl: 2.5 }}>
          {plan.step_by_step_plan.map((step, i) => (
            <Box
              component="li"
              key={i}
              sx={{
                mb: 1,
                p: 1,
                bgcolor: "rgba(255,255,255,0.07)",
                borderRadius: 1,
                border: "1px solid rgba(255,255,255,0.12)",
                fontSize: 13,
                lineHeight: 1.6,
                "& code": {
                  bgcolor: "rgba(255,255,255,0.08)",
                  px: 0.5,
                  borderRadius: 0.5,
                  fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                  fontSize: 12,
                },
                "& p": { m: 0 },
              }}
            >
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{step}</ReactMarkdown>
            </Box>
          ))}
        </Box>

        {/* Executable artifact */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
          <Typography
            variant="caption"
            sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "text.secondary" }}
          >
            Executable Artifact
          </Typography>
          <Chip
            icon={
              <Box sx={{ color: `${artifactMeta.color} !important`, display: "flex", alignItems: "center" }}>
                {artifactMeta.icon}
              </Box>
            }
            label={artifactMeta.label}
            size="small"
            sx={{
              bgcolor: "transparent",
              border: `1px solid ${artifactMeta.color}`,
              color: artifactMeta.color,
              fontSize: 10,
            }}
          />
        </Box>

        <Box sx={{ position: "relative", mb: 2 }}>
          <Box
            component="pre"
            sx={{
              bgcolor: "#0d1117",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 1,
              fontSize: 12,
              fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
              overflow: "auto",
              maxHeight: 320,
              p: 2,
              color: "#e6edf3",
              m: 0,
              whiteSpace: "pre",
              pr: 5,
            }}
          >
            {plan.artifact_content}
          </Box>
          <CopyButton text={plan.artifact_content} />
        </Box>

        {/* What could go wrong */}
        <Alert
          icon={<WarningAmber />}
          sx={{
            bgcolor: "rgba(251,188,4,0.08)",
            border: "1px solid rgba(251,188,4,0.3)",
            mb: 2,
            "& .MuiAlert-icon": { color: "#FBBC04" },
          }}
        >
          <Typography variant="caption" sx={{ fontWeight: 700, color: "#FBBC04", display: "block", mb: 0.5 }}>
            What could go wrong
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ fontSize: 13 }}>
            {plan.what_could_go_wrong}
          </Typography>
        </Alert>

        {/* Rollback steps */}
        <Box>
          <Button
            size="small"
            variant="text"
            onClick={() => setRollbackOpen((o) => !o)}
            sx={{ color: "text.secondary", textTransform: "none", mb: 0.5, fontSize: 12 }}
            endIcon={
              <ExpandMore
                sx={{ transform: rollbackOpen ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}
              />
            }
          >
            {rollbackOpen ? "Hide rollback steps" : "Show rollback steps"}
          </Button>
          <Collapse in={rollbackOpen}>
            <Box component="ol" sx={{ mt: 1, pl: 2.5, mb: 0 }}>
              {plan.rollback_steps.map((step, i) => (
                <Box
                  component="li"
                  key={i}
                  sx={{ mb: 0.75, fontSize: 13, color: "text.secondary", lineHeight: 1.5 }}
                >
                  {step}
                </Box>
              ))}
            </Box>
          </Collapse>
        </Box>
      </AccordionDetails>
    </Accordion>
  );
}

// ─── Main dialog ──────────────────────────────────────────────────────────────

export default function FixWithAIDialog({
  open,
  onClose,
  findings,
  clientId,
  scanId,
  preloadedJob,
}: FixWithAIDialogProps) {
  const theme = useTheme();
  const isSmall = useMediaQuery(theme.breakpoints.down("md"));

  const initialStep = preloadedJob ? 2 : 0;
  const [step, setStep] = useState<number>(initialStep);
  const [job, setJob] = useState<RemediationJob | null>(preloadedJob ?? null);
  const [subtitleIdx, setSubtitleIdx] = useState(0);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (open) {
      if (preloadedJob) {
        setJob(preloadedJob);
        setStep(2);
      } else {
        setStep(0);
        setJob(null);
      }
    }
  }, [open, preloadedJob]);

  useEffect(() => {
    if (step !== 1) return;
    const id = setInterval(() => {
      setSubtitleIdx((i) => (i + 1) % CYCLING_SUBTITLES.length);
    }, 2000);
    return () => clearInterval(id);
  }, [step]);

  const isPollingStatus = job
    ? (["pending", "analyzing", "verifying"] as RemediationJobStatus[]).includes(job.status)
    : false;

  useQuery({
    queryKey: ["remediation-job", clientId, job?.id],
    queryFn: async () => {
      if (!job) return null;
      const updated: RemediationJob = await remediationJobsApi.get(clientId, job.id);
      setJob(updated);
      if (updated.status === "failed") {
        toast.error(updated.error_message ?? "Remediation job failed");
        setStep(2);
      } else if (
        updated.status === "ready" ||
        updated.status === "verified" ||
        updated.status === "partial" ||
        updated.status === "unresolved"
      ) {
        setStep(2);
      }
      return updated;
    },
    refetchInterval: isPollingStatus ? 3000 : false,
    enabled: !!job && isPollingStatus,
  });

  const cappedFindings = findings.slice(0, 20);
  const overLimit = findings.length > 20;

  const handleAnalyse = async () => {
    setIsSubmitting(true);
    try {
      const ids = cappedFindings.map((f) => f.id);
      const newJob: RemediationJob = await remediationJobsApi.create(clientId, ids, scanId);
      setJob(newJob);
      setStep(1);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to start analysis";
      toast.error(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleVerify = async () => {
    if (!job) return;
    setStep(1);
    setSubtitleIdx(0);
    try {
      const updated: RemediationJob = await remediationJobsApi.verify(clientId, job.id);
      setJob(updated);
      if (
        updated.status !== "verifying" &&
        updated.status !== "pending" &&
        updated.status !== "analyzing"
      ) {
        setStep(2);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Verification failed";
      toast.error(message);
      setStep(2);
    }
  };

  const handleMarkApplied = () => {
    toast.success("Plan marked as applied. No verification scan available.");
  };

  const handleDownload = () => {
    if (!job?.plans) return;
    const lines: string[] = ["# AI Remediation Plan\n"];
    if (job.overall_summary) lines.push(`## Summary\n${job.overall_summary}\n`);
    job.plans.forEach((plan) => {
      const f = findings.find((x) => x.id === plan.finding_id);
      lines.push(`\n## ${f?.title ?? plan.finding_id}`);
      lines.push(`Confidence: ${plan.confidence_score}%`);
      lines.push(`Risk Level: ${plan.risk_level}`);
      lines.push(`Automatable: ${plan.automatable}`);
      lines.push(`Estimated Downtime: ${plan.estimated_downtime}`);
      lines.push(`\n### Steps`);
      plan.step_by_step_plan.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
      lines.push(
        `\n### ${plan.artifact_type.toUpperCase()} Artifact\n\`\`\`\n${plan.artifact_content}\n\`\`\``
      );
      lines.push(`\n### What Could Go Wrong\n${plan.what_could_go_wrong}`);
      lines.push(`\n### Rollback Steps`);
      plan.rollback_steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
    });

    const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `remediation-plan-${job.id}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  // ── Render helpers ───────────────────────────────────────────────────────────

  const renderStep0 = () => (
    <>
      <DialogContent dividers>
        {overLimit && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            Maximum 20 findings per job. Only the first 20 will be analysed.
          </Alert>
        )}
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>Severity</TableCell>
              <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>Title</TableCell>
              <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>Resource</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {cappedFindings.map((f) => (
              <TableRow key={f.id} sx={{ "&:last-child td": { border: 0 } }}>
                <TableCell>
                  <Chip
                    label={f.severity.toUpperCase()}
                    size="small"
                    sx={{
                      bgcolor: SEV_COLORS[f.severity] ?? "#9AA0A6",
                      color: "#fff",
                      fontWeight: 700,
                      fontSize: 10,
                    }}
                  />
                </TableCell>
                <TableCell sx={{ fontSize: 13 }}>{f.title}</TableCell>
                <TableCell
                  sx={{
                    fontSize: 12,
                    color: "text.secondary",
                    maxWidth: 200,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {f.resource_id ?? "—"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </DialogContent>
      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onClose} variant="outlined" sx={{ borderColor: "rgba(255,255,255,0.25)", color: "text.primary" }}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={handleAnalyse}
          disabled={isSubmitting || cappedFindings.length === 0}
          startIcon={<Bolt />}
          sx={{ bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" } }}
        >
          Analyse with AI →
        </Button>
      </DialogActions>
    </>
  );

  const subtitleText =
    job?.status === "verifying" ? VERIFYING_SUBTITLE : CYCLING_SUBTITLES[subtitleIdx];

  const renderStep1 = () => (
    <>
      <DialogContent>
        <Box sx={{ textAlign: "center", py: 6 }}>
          <Bolt sx={{ fontSize: 64, color: "#4285F4", mb: 2, opacity: 0.8 }} />
          <Typography variant="h6" gutterBottom>
            AI Analysis in Progress
          </Typography>
          <Typography
            variant="body2"
            color="text.secondary"
            sx={{ mb: 3, minHeight: 24, transition: "opacity 0.3s" }}
          >
            {subtitleText}
          </Typography>
          <Box sx={{ maxWidth: 400, mx: "auto" }}>
            <LinearProgress
              sx={{
                height: 4,
                borderRadius: 2,
                bgcolor: "rgba(66,133,244,0.15)",
                "& .MuiLinearProgress-bar": { bgcolor: "#4285F4" },
              }}
            />
          </Box>
          {job?.status === "failed" && (
            <Alert severity="error" sx={{ mt: 3, maxWidth: 400, mx: "auto" }}>
              {job.error_message ?? "Analysis failed. Please try again."}
            </Alert>
          )}
        </Box>
      </DialogContent>
      {job?.status === "failed" && (
        <DialogActions sx={{ px: 3, py: 2 }}>
          <Button onClick={onClose} color="inherit">
            Close
          </Button>
        </DialogActions>
      )}
    </>
  );

  const renderVerificationBanner = () => {
    if (!job) return null;
    if (job.status === "verified") {
      return (
        <Alert
          icon={<CheckCircle />}
          severity="success"
          sx={{ mb: 2, bgcolor: "rgba(52,168,83,0.1)", border: "1px solid rgba(52,168,83,0.3)" }}
        >
          <strong>All findings resolved!</strong> The verification rescan confirms no outstanding
          issues.
        </Alert>
      );
    }
    if (job.status === "partial") {
      const resolved = Object.values(job.verification_results ?? {}).filter(
        (v) => v === "resolved"
      ).length;
      const total = Object.keys(job.verification_results ?? {}).length;
      const remaining = total - resolved;
      return (
        <Alert
          severity="warning"
          sx={{ mb: 2, bgcolor: "rgba(251,188,4,0.08)", border: "1px solid rgba(251,188,4,0.3)" }}
        >
          <strong>Partially resolved</strong> — {resolved} finding{resolved !== 1 ? "s" : ""}{" "}
          fixed, {remaining} remain{remaining === 1 ? "s" : ""} open.
        </Alert>
      );
    }
    if (job.status === "unresolved") {
      return (
        <Alert
          severity="error"
          sx={{ mb: 2, bgcolor: "rgba(234,67,53,0.08)", border: "1px solid rgba(234,67,53,0.3)" }}
        >
          <strong>No findings were resolved.</strong> Review the remediation plan and try again.
        </Alert>
      );
    }
    return null;
  };

  const renderStep2 = () => {
    if (!job) return null;

    const conf = job.overall_confidence ?? 0;
    const confColor = confidenceColor(conf);

    return (
      <>
        <DialogContent dividers sx={{ pb: 2 }}>
          {renderVerificationBanner()}

          {/* Summary banner */}
          <Box
            sx={{
              display: "flex",
              flexWrap: "wrap",
              gap: 2,
              alignItems: "flex-start",
              p: 2,
              bgcolor: "rgba(255,255,255,0.07)",
              borderRadius: 1,
              border: "1px solid rgba(255,255,255,0.15)",
              mb: 3,
            }}
          >
            {/* Confidence number */}
            <Box sx={{ textAlign: "center", minWidth: 80 }}>
              <Typography variant="h3" sx={{ fontWeight: 800, color: confColor, lineHeight: 1 }}>
                {conf}%
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Confidence
              </Typography>
            </Box>

            <Divider
              orientation="vertical"
              flexItem
              sx={{ borderColor: "rgba(255,255,255,0.1)" }}
            />

            <Box sx={{ flex: 1, minWidth: 200 }}>
              <Box
                sx={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: 1,
                  alignItems: "center",
                  mb: 1,
                }}
              >
                {job.overall_risk_level && (
                  <Chip
                    label={`Risk: ${job.overall_risk_level.toUpperCase()}`}
                    size="small"
                    sx={{
                      bgcolor: RISK_COLORS[job.overall_risk_level] ?? "#9AA0A6",
                      color: "#fff",
                      fontWeight: 700,
                      fontSize: 10,
                    }}
                  />
                )}
                <Typography variant="caption" color="text.secondary">
                  {(job.plans ?? []).length} finding
                  {(job.plans ?? []).length !== 1 ? "s" : ""} analysed
                </Typography>
              </Box>
              {job.overall_summary && (
                <Box
                  sx={{
                    fontSize: 13,
                    color: "text.secondary",
                    lineHeight: 1.6,
                    "& p": { m: 0 },
                  }}
                >
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {job.overall_summary}
                  </ReactMarkdown>
                </Box>
              )}
            </Box>
          </Box>

          {/* Per-finding plan cards */}
          {(job.plans ?? []).map((plan) => {
            const f = findings.find((x) => x.id === plan.finding_id);
            const verResult = job.verification_results?.[plan.finding_id];
            return (
              <PlanCard
                key={plan.finding_id}
                plan={plan}
                finding={f}
                verificationResult={verResult}
                defaultExpanded={(job.plans?.length ?? 0) <= 3}
              />
            );
          })}
        </DialogContent>

        <DialogActions sx={{ px: 3, py: 2, gap: 1, flexWrap: "wrap" }}>
          <Button
            size="small"
            variant="outlined"
            onClick={handleDownload}
            sx={{ borderColor: "rgba(255,255,255,0.2)", color: "text.secondary" }}
          >
            Download Plan
          </Button>
          <Box sx={{ flex: 1 }} />
          <Button onClick={onClose} variant="outlined" size="small" sx={{ borderColor: "rgba(255,255,255,0.25)", color: "text.primary" }}>
            Close
          </Button>
          {scanId ? (
            <Button
              variant="contained"
              startIcon={<CheckCircle />}
              onClick={handleVerify}
              sx={{ bgcolor: "#34A853", "&:hover": { bgcolor: "#2D9248" } }}
            >
              Mark as Applied + Verify
            </Button>
          ) : (
            <Button
              variant="contained"
              startIcon={<CheckCircleOutlined />}
              onClick={handleMarkApplied}
              sx={{ bgcolor: "#34A853", "&:hover": { bgcolor: "#2D9248" } }}
            >
              Mark as Applied
            </Button>
          )}
        </DialogActions>
      </>
    );
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      fullScreen={isSmall}
      maxWidth="lg"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            bgcolor: "#1a1d2e",
            backgroundImage: "none",
            minHeight: isSmall ? undefined : 500,
          },
        },
      }}
    >
      <DialogTitle
        sx={{
          display: "flex",
          alignItems: "center",
          gap: 1,
          borderBottom: "1px solid rgba(255,255,255,0.08)",
        }}
      >
        <AutoFixHigh sx={{ color: "#4285F4" }} />
        <Typography variant="h6" component="span" sx={{ fontWeight: 700 }}>
          Fix with AI
        </Typography>
        {step === 0 && (
          <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
            — {cappedFindings.length} finding{cappedFindings.length !== 1 ? "s" : ""} selected
          </Typography>
        )}
      </DialogTitle>

      {step === 0 && renderStep0()}
      {step === 1 && renderStep1()}
      {step === 2 && renderStep2()}
    </Dialog>
  );
}
