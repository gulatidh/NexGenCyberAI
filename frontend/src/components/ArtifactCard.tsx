/**
 * ArtifactCard
 *
 * Renders the structured artifacts produced by a Phase 7A buddy run.
 * Each AgentRun.output_data.artifacts[] entry maps to one card with a
 * kind-specific preview (Risk draft / Ticket / Control mapping / Runbook
 * / Finding triage) and a one-click "Apply" button that POSTs to
 * /agents/catalog/runs/{run_id}/artifacts/{idx}/apply.
 *
 * Once applied, the card flips to a confirmation state showing the
 * created entity (Risk row, KB file, framework assessment, finding,
 * or — for ticket drafts — a copy-to-clipboard success state).
 */
import React from "react";
import {
  Box, Card, CardContent, Typography, Chip, Button,
  CircularProgress, Divider,
} from "@mui/material";
import {
  Warning, BugReport, Policy, MenuBook, ConfirmationNumber, Check,
  ContentCopy, OpenInNew, AddTask,
} from "@mui/icons-material";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";
import { useNavigate } from "react-router-dom";
import { agentCatalogApi } from "../services/api";

const KIND_META: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  risk_drafts:      { label: "Risk drafts",       icon: <Warning sx={{ fontSize: 18 }} />,          color: "#EA4335" },
  jira_drafts:      { label: "Ticket drafts",     icon: <ConfirmationNumber sx={{ fontSize: 18 }} />, color: "#4285F4" },
  control_mappings: { label: "Control mappings",  icon: <Policy sx={{ fontSize: 18 }} />,           color: "#9C27B0" },
  runbook:          { label: "Runbook",           icon: <MenuBook sx={{ fontSize: 18 }} />,         color: "#34A853" },
  finding_triage:   { label: "Finding triage",    icon: <BugReport sx={{ fontSize: 18 }} />,        color: "#FF7043" },
};

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853",
};

interface Artifact {
  applied?: boolean;
  applied_entity_kind?: string | null;
  applied_entity_id?: string | null;
  [k: string]: any;
}

interface Props {
  runId: string;
  kind: string;
  artifacts: Artifact[];
  clientId?: string;
}

export default function ArtifactCard({ runId, kind, artifacts, clientId }: Props) {
  const meta = KIND_META[kind];
  if (!meta || !artifacts?.length) return null;

  return (
    <Box sx={{ mt: 1.5 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
        <Box sx={{ color: meta.color, display: "flex", alignItems: "center" }}>{meta.icon}</Box>
        <Typography variant="caption" sx={{ color: meta.color, fontWeight: 700, fontSize: 11, letterSpacing: 0.5, textTransform: "uppercase" }}>
          {artifacts.length} {meta.label}
        </Typography>
      </Box>
      <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
        {artifacts.map((a, idx) => (
          <ArtifactRow key={idx} runId={runId} kind={kind} artifact={a} idx={idx} clientId={clientId} accent={meta.color} />
        ))}
      </Box>
    </Box>
  );
}

interface RowProps {
  runId: string;
  kind: string;
  artifact: Artifact;
  idx: number;
  clientId?: string;
  accent: string;
}

function ArtifactRow({ runId, kind, artifact, idx, clientId, accent }: RowProps) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [copied, setCopied] = React.useState(false);

  const applyMutation = useMutation({
    mutationFn: () => agentCatalogApi.applyArtifact(runId, idx),
    onSuccess: (resp) => {
      toast.success("Applied");
      qc.invalidateQueries({ queryKey: ["scan-detail"] });
      qc.invalidateQueries({ queryKey: ["scan-agent-runs"] });
      qc.invalidateQueries({ queryKey: ["risks"] });
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Apply failed"),
  });

  const isApplied = !!artifact.applied || applyMutation.data?.applied;
  const appliedEntityKind = artifact.applied_entity_kind ?? applyMutation.data?.entity_kind;

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast.success("Copied to clipboard");
      setTimeout(() => setCopied(false), 2500);
      // Mark as applied on the backend too (for the stats counter)
      if (!isApplied) applyMutation.mutate();
    } catch {
      toast.error("Couldn't access clipboard");
    }
  };

  const handleOpenEntity = () => {
    if (appliedEntityKind === "risk") {
      navigate(`/risks${clientId ? `?client=${clientId}` : ""}`);
    } else if (appliedEntityKind === "kb_file") {
      navigate(`/knowledge`);
    } else if (appliedEntityKind === "framework_assessment") {
      navigate(`/frameworks`);
    } else if (appliedEntityKind === "finding") {
      navigate(`/findings`);
    }
  };

  return (
    <Card sx={{
      bgcolor: "rgba(255,255,255,0.02)",
      border: `1px solid ${isApplied ? `${accent}55` : "rgba(255,255,255,0.08)"}`,
      borderLeft: `3px solid ${accent}`,
      borderRadius: 1.5,
      transition: "border-color .15s",
    }}>
      <CardContent sx={{ "&:last-child": { pb: 1.5 } }}>
        {/* Per-kind preview */}
        {kind === "risk_drafts" && <RiskDraftPreview artifact={artifact} />}
        {kind === "jira_drafts" && <JiraDraftPreview artifact={artifact} />}
        {kind === "control_mappings" && <ControlMappingPreview artifact={artifact} />}
        {kind === "runbook" && <RunbookPreview artifact={artifact} />}
        {kind === "finding_triage" && <FindingTriagePreview artifact={artifact} />}

        {/* Action row */}
        <Divider sx={{ borderColor: "divider", my: 1.5 }} />
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 1, flexWrap: "wrap" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            {isApplied ? (
              <>
                <Chip
                  icon={<Check sx={{ fontSize: 14, color: "#34A853 !important" }} />}
                  label={
                    appliedEntityKind === "jira_copy" ? "Copied" :
                    appliedEntityKind === "risk" ? "Risk added" :
                    appliedEntityKind === "kb_file" ? "Saved to Knowledge Base" :
                    appliedEntityKind === "framework_assessment" ? "Mapping applied" :
                    appliedEntityKind === "finding" ? "Finding updated" :
                    "Applied"
                  }
                  size="small"
                  sx={{
                    height: 22, fontSize: 11, fontWeight: 700,
                    bgcolor: "rgba(52,168,83,0.15)", color: "#34A853",
                  }}
                />
                {appliedEntityKind && appliedEntityKind !== "jira_copy" && (
                  <Button
                    size="small"
                    endIcon={<OpenInNew sx={{ fontSize: 14 }} />}
                    onClick={handleOpenEntity}
                    sx={{ color: accent, fontSize: 11, textTransform: "none" }}
                  >
                    View
                  </Button>
                )}
              </>
            ) : (
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                Buddy-drafted · review before applying
              </Typography>
            )}
          </Box>
          {!isApplied && (
            <Box sx={{ display: "flex", gap: 0.75 }}>
              {kind === "jira_drafts" ? (
                <Button
                  size="small"
                  variant="contained"
                  startIcon={copied ? <Check /> : <ContentCopy />}
                  onClick={() => handleCopy(formatJiraTicket(artifact))}
                  sx={{ bgcolor: accent, textTransform: "none", fontSize: 12 }}
                >
                  {copied ? "Copied" : "Copy ticket"}
                </Button>
              ) : (
                <Button
                  size="small"
                  variant="contained"
                  startIcon={applyMutation.isPending ? <CircularProgress size={14} sx={{ color: "text.primary" }} /> : <AddTask />}
                  onClick={() => applyMutation.mutate()}
                  disabled={applyMutation.isPending}
                  sx={{ bgcolor: accent, textTransform: "none", fontSize: 12, "&:hover": { bgcolor: accent, filter: "brightness(1.15)" } }}
                >
                  {kind === "risk_drafts" ? "Add to Risk Register" :
                   kind === "runbook" ? "Save to Knowledge Base" :
                   kind === "control_mappings" ? "Apply mapping" :
                   kind === "finding_triage" ? "Apply triage" :
                   "Apply"}
                </Button>
              )}
            </Box>
          )}
        </Box>
      </CardContent>
    </Card>
  );
}

// ── Per-kind previews ─────────────────────────────────────────────────────

function RiskDraftPreview({ artifact: a }: { artifact: Artifact }) {
  const sevColor = SEV_COLOR[a.severity] || "rgba(255,255,255,0.5)";
  return (
    <>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap", mb: 0.75 }}>
        <Chip label={a.severity} size="small" sx={{ height: 20, fontSize: 10, fontWeight: 700, textTransform: "uppercase", bgcolor: `${sevColor}25`, color: sevColor }} />
        {a.category && (
          <Chip label={a.category} size="small" sx={{ height: 20, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
        )}
        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
          L{a.likelihood} · I{a.impact}
        </Typography>
      </Box>
      <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 13.5, mb: 0.5 }}>{a.title}</Typography>
      {a.rationale && (
        <Typography variant="body2" sx={{ color: "text.secondary", fontSize: 12.5, lineHeight: 1.5 }}>{a.rationale}</Typography>
      )}
      {Array.isArray(a.control_refs) && a.control_refs.length > 0 && (
        <Box sx={{ mt: 1, display: "flex", gap: 0.5, flexWrap: "wrap" }}>
          {a.control_refs.map((r: string) => (
            <Chip key={r} label={r} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4" }} />
          ))}
        </Box>
      )}
    </>
  );
}

function JiraDraftPreview({ artifact: a }: { artifact: Artifact }) {
  return (
    <>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap", mb: 0.75 }}>
        <Chip label={a.project_key} size="small" sx={{ height: 20, fontSize: 10, fontWeight: 700, bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4" }} />
        <Chip label={a.issue_type} size="small" sx={{ height: 20, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
        <Chip label={a.priority} size="small" sx={{ height: 20, fontSize: 10, fontWeight: 700, bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04" }} />
      </Box>
      <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 13.5, mb: 0.5 }}>{a.summary}</Typography>
      {a.description_md && (
        <Typography variant="body2" sx={{ color: "text.secondary", fontSize: 12.5, lineHeight: 1.5, whiteSpace: "pre-wrap" }}>
          {a.description_md.slice(0, 240)}{a.description_md.length > 240 ? "…" : ""}
        </Typography>
      )}
    </>
  );
}

function ControlMappingPreview({ artifact: a }: { artifact: Artifact }) {
  const statusColor = a.status === "implemented" ? "#34A853"
    : a.status === "partially_implemented" ? "#FBBC04"
    : a.status === "not_implemented" ? "#EA4335" : "rgba(255,255,255,0.5)";
  return (
    <>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap", mb: 0.5 }}>
        <Chip label={a.framework} size="small" sx={{ height: 20, fontSize: 10, fontWeight: 700, bgcolor: "rgba(156,39,176,0.15)", color: "#CE93D8" }} />
        <Chip label={a.control_id} size="small" sx={{ height: 20, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.primary", fontFamily: "monospace" }} />
        <Chip label={(a.status || "").replace(/_/g, " ")} size="small" sx={{ height: 20, fontSize: 10, fontWeight: 700, textTransform: "uppercase", bgcolor: `${statusColor}25`, color: statusColor }} />
      </Box>
      {a.evidence && (
        <Typography variant="body2" sx={{ color: "text.secondary", fontSize: 12.5, lineHeight: 1.5, mt: 0.5 }}>{a.evidence}</Typography>
      )}
    </>
  );
}

function RunbookPreview({ artifact: a }: { artifact: Artifact }) {
  return (
    <>
      <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 13.5, mb: 0.5 }}>{a.title}</Typography>
      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 0.75 }}>
        {a.trigger && <Chip label={`Trigger: ${a.trigger}`} size="small" sx={{ height: 20, fontSize: 10, bgcolor: "rgba(251,188,4,0.12)", color: "#FBBC04" }} />}
        {a.audience && <Chip label={a.audience} size="small" sx={{ height: 20, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />}
      </Box>
      {Array.isArray(a.steps) && a.steps.length > 0 && (
        <Box sx={{ pl: 1.5, mt: 0.5 }}>
          {a.steps.slice(0, 5).map((s: any, i: number) => (
            <Typography key={i} variant="body2" sx={{ color: "text.secondary", fontSize: 12.5, lineHeight: 1.6 }}>
              <Box component="span" sx={{ color: "#34A853", fontWeight: 700, mr: 0.5 }}>{s.order || (i + 1)}.</Box>
              {s.action}
            </Typography>
          ))}
          {a.steps.length > 5 && (
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
              + {a.steps.length - 5} more steps
            </Typography>
          )}
        </Box>
      )}
    </>
  );
}

function FindingTriagePreview({ artifact: a }: { artifact: Artifact }) {
  return (
    <>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap", mb: 0.5 }}>
        <Chip label={`Finding ${(a.finding_id || "").slice(0, 8)}`} size="small" sx={{ height: 20, fontSize: 10, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontFamily: "monospace" }} />
        <Chip label={(a.recommended_status || "").replace(/_/g, " ")} size="small" sx={{ height: 20, fontSize: 10, fontWeight: 700, textTransform: "uppercase", bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04" }} />
        <Chip label={a.recommended_owner_role} size="small" sx={{ height: 20, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
          priority {(a.priority_score ?? 0).toFixed(2)}
        </Typography>
      </Box>
      {a.rationale && (
        <Typography variant="body2" sx={{ color: "text.secondary", fontSize: 12.5, lineHeight: 1.5, mt: 0.5 }}>{a.rationale}</Typography>
      )}
    </>
  );
}

function formatJiraTicket(a: Artifact): string {
  const lines = [
    `Project: ${a.project_key || "SEC"}`,
    `Issue Type: ${a.issue_type || "Task"}`,
    `Priority: ${a.priority || "Medium"}`,
    `Summary: ${a.summary || "(no summary)"}`,
  ];
  if (Array.isArray(a.labels) && a.labels.length) lines.push(`Labels: ${a.labels.join(", ")}`);
  lines.push("", a.description_md || "");
  return lines.join("\n");
}
