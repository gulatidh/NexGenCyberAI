import React, { useState } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  IconButton,
  Button,
  Snackbar,
  Alert,
  Tooltip,
  Divider,
} from "@mui/material";
import {
  AutoFixHigh,
  CheckCircleOutlined,
  CheckCircle,
  ErrorOutlined,
  Refresh,
  Delete,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";
import { useActiveClient } from "../contexts/ClientContext";
import { remediationJobsApi } from "../services/api";
import { RemediationJob, RemediationJobStatus } from "../types";
import { fromNow } from "../utils/datetime";
import FixWithAIDialog from "../components/FixWithAIDialog";

// ─── Status display helpers ───────────────────────────────────────────────────

interface StatusConfig {
  label: string;
  color: string;
  icon: React.ReactNode;
}

function getStatusConfig(status: RemediationJobStatus): StatusConfig {
  switch (status) {
    case "pending":
      return {
        label: "Pending",
        color: "#9AA0A6",
        icon: <CircularProgress size={14} sx={{ color: "#9AA0A6" }} />,
      };
    case "analyzing":
      return {
        label: "Analysing",
        color: "#4285F4",
        icon: <CircularProgress size={14} sx={{ color: "#4285F4" }} />,
      };
    case "ready":
      return {
        label: "Ready",
        color: "#34A853",
        icon: <CheckCircleOutlined sx={{ fontSize: 16, color: "#34A853" }} />,
      };
    case "verifying":
      return {
        label: "Verifying",
        color: "#4285F4",
        icon: <CircularProgress size={14} sx={{ color: "#4285F4" }} />,
      };
    case "verified":
      return {
        label: "Verified",
        color: "#34A853",
        icon: <CheckCircle sx={{ fontSize: 16, color: "#34A853" }} />,
      };
    case "partial":
      return {
        label: "Partial",
        color: "#FBBC04",
        icon: <CheckCircleOutlined sx={{ fontSize: 16, color: "#FBBC04" }} />,
      };
    case "unresolved":
      return {
        label: "Unresolved",
        color: "#EA4335",
        icon: <ErrorOutlined sx={{ fontSize: 16, color: "#EA4335" }} />,
      };
    case "failed":
      return {
        label: "Failed",
        color: "#EA4335",
        icon: <ErrorOutlined sx={{ fontSize: 16, color: "#EA4335" }} />,
      };
  }
}

function confidenceColor(score: number): string {
  if (score >= 80) return "#34A853";
  if (score >= 50) return "#FBBC04";
  return "#EA4335";
}

const RISK_COLORS: Record<string, string> = {
  low: "#34A853",
  medium: "#FBBC04",
  high: "#EA4335",
};

// ─── Job card ─────────────────────────────────────────────────────────────────

interface JobCardProps {
  job: RemediationJob;
  onView: (job: RemediationJob) => void;
  onDelete: (jobId: string) => void;
  deleteLoading: boolean;
}

function JobCard({ job, onView, onDelete, deleteLoading }: JobCardProps) {
  const statusConfig = getStatusConfig(job.status);
  const summary = job.overall_summary
    ? job.overall_summary.length > 100
      ? `${job.overall_summary.slice(0, 100)}…`
      : job.overall_summary
    : null;

  return (
    <Card
      sx={{
        bgcolor: "rgba(255,255,255,0.03)",
        border: "1px solid rgba(255,255,255,0.08)",
        mb: 1.5,
        "&:hover": { border: "1px solid rgba(66,133,244,0.3)" },
        transition: "border-color 0.2s",
      }}
    >
      <CardContent sx={{ p: "16px !important" }}>
        <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
          {/* Status icon */}
          <Box sx={{ pt: 0.25, flexShrink: 0 }}>{statusConfig.icon}</Box>

          {/* Main content */}
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, alignItems: "center", mb: 0.5 }}>
              <Chip
                label={statusConfig.label}
                size="small"
                sx={{
                  bgcolor: "transparent",
                  border: `1px solid ${statusConfig.color}`,
                  color: statusConfig.color,
                  fontWeight: 700,
                  fontSize: 10,
                }}
              />
              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                {job.finding_ids.length} finding{job.finding_ids.length !== 1 ? "s" : ""}
              </Typography>
              {job.overall_confidence !== undefined && job.overall_confidence !== null && (
                <Chip
                  label={`${job.overall_confidence}% confidence`}
                  size="small"
                  sx={{
                    bgcolor: "transparent",
                    border: `1px solid ${confidenceColor(job.overall_confidence)}`,
                    color: confidenceColor(job.overall_confidence),
                    fontSize: 10,
                  }}
                />
              )}
              {job.overall_risk_level && (
                <Chip
                  label={`Risk: ${job.overall_risk_level.toUpperCase()}`}
                  size="small"
                  sx={{
                    bgcolor: "transparent",
                    border: `1px solid ${RISK_COLORS[job.overall_risk_level] ?? "#9AA0A6"}`,
                    color: RISK_COLORS[job.overall_risk_level] ?? "#9AA0A6",
                    fontSize: 10,
                  }}
                />
              )}
            </Box>

            {summary && (
              <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12, mb: 0.5 }}>
                {summary}
              </Typography>
            )}

            <Typography variant="caption" color="text.disabled">
              Created {fromNow(job.created_at)}
              {job.created_by ? ` · by ${job.created_by}` : ""}
            </Typography>
          </Box>

          {/* Actions */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, flexShrink: 0 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={() => onView(job)}
              sx={{
                borderColor: "rgba(255,255,255,0.2)",
                color: "text.primary",
                fontSize: 12,
                "&:hover": { borderColor: "#4285F4", color: "#4285F4" },
              }}
            >
              View Plan
            </Button>
            <Tooltip title="Delete job">
              <span>
                <IconButton
                  size="small"
                  onClick={() => onDelete(job.id)}
                  disabled={deleteLoading}
                  sx={{ color: "text.disabled", "&:hover": { color: "#EA4335" } }}
                >
                  <Delete fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
}

// ─── Empty state ──────────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <Box
      sx={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        py: 10,
        px: 4,
        textAlign: "center",
      }}
    >
      <AutoFixHigh sx={{ fontSize: 72, color: "rgba(255,255,255,0.1)", mb: 2 }} />
      <Typography variant="h6" sx={{ fontWeight: 600, mb: 1 }}>
        No AI remediation jobs yet
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 420 }}>
        Select findings on the Findings page and click{" "}
        <strong>"Fix with AI"</strong> to generate an executable remediation plan with scripts,
        rollback steps, and confidence scores.
      </Typography>
    </Box>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function RemediationJobs() {
  const { clientId } = useActiveClient();
  const qc = useQueryClient();

  const [dialogJob, setDialogJob] = useState<RemediationJob | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: "info" | "warning" | "error";
  }>({ open: false, message: "", severity: "info" });

  const {
    data: jobs,
    isLoading,
    isError,
    refetch,
  } = useQuery<RemediationJob[]>({
    queryKey: ["remediation-jobs", clientId],
    queryFn: () => remediationJobsApi.list(clientId),
    enabled: !!clientId,
    refetchInterval: 30000,
  });

  const deleteMutation = useMutation({
    mutationFn: (jobId: string) => remediationJobsApi.delete(clientId, jobId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["remediation-jobs", clientId] });
      toast.success("Job deleted");
    },
    onError: () => {
      toast.error("Failed to delete job");
    },
  });

  const handleView = (job: RemediationJob) => {
    const viewableStatuses: RemediationJobStatus[] = [
      "ready",
      "verified",
      "partial",
      "unresolved",
      "analyzing",
      "verifying",
    ];
    if (viewableStatuses.includes(job.status)) {
      setDialogJob(job);
      setDialogOpen(true);
    } else {
      setSnackbar({
        open: true,
        message:
          job.status === "failed"
            ? `Job failed: ${job.error_message ?? "Unknown error"}`
            : "Job is pending and not yet started.",
        severity: job.status === "failed" ? "error" : "warning",
      });
    }
  };

  const handleDelete = (jobId: string) => {
    deleteMutation.mutate(jobId);
  };

  const handleCloseDialog = () => {
    setDialogOpen(false);
    setDialogJob(null);
    refetch();
  };

  return (
    <Box sx={{ p: 3, maxWidth: 900, mx: "auto" }}>
      {/* Page header */}
      <Box
        sx={{
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          mb: 3,
          gap: 2,
        }}
      >
        <Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            <AutoFixHigh sx={{ color: "#4285F4", fontSize: 28 }} />
            <Typography variant="h5" sx={{ fontWeight: 700 }}>
              AI Remediation Jobs
            </Typography>
          </Box>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Track AI-generated remediation plans and their verification status
          </Typography>
        </Box>
        <Tooltip title="Refresh">
          <IconButton
            onClick={() => refetch()}
            disabled={isLoading}
            sx={{ color: "text.secondary" }}
          >
            <Refresh />
          </IconButton>
        </Tooltip>
      </Box>

      <Divider sx={{ mb: 3, borderColor: "rgba(255,255,255,0.08)" }} />

      {/* Loading */}
      {isLoading && (
        <Box sx={{ display: "flex", justifyContent: "center", py: 8 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      )}

      {/* Error */}
      {isError && (
        <Alert
          severity="error"
          sx={{ bgcolor: "rgba(234,67,53,0.08)", border: "1px solid rgba(234,67,53,0.3)" }}
          action={
            <Button color="inherit" size="small" onClick={() => refetch()}>
              Retry
            </Button>
          }
        >
          Failed to load remediation jobs.
        </Alert>
      )}

      {/* Empty state */}
      {!isLoading && !isError && (!jobs || jobs.length === 0) && <EmptyState />}

      {/* Job list */}
      {!isLoading && !isError && jobs && jobs.length > 0 && (
        <Box>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.5 }}>
            {jobs.length} job{jobs.length !== 1 ? "s" : ""} · auto-refreshes every 30s
          </Typography>
          {jobs.map((job) => (
            <JobCard
              key={job.id}
              job={job}
              onView={handleView}
              onDelete={handleDelete}
              deleteLoading={deleteMutation.isPending}
            />
          ))}
        </Box>
      )}

      {/* FixWithAIDialog — opened from this page with a preloaded job */}
      {dialogOpen && dialogJob && (
        <FixWithAIDialog
          open={dialogOpen}
          onClose={handleCloseDialog}
          findings={[]}
          clientId={clientId}
          scanId={dialogJob.scan_id ?? undefined}
          preloadedJob={dialogJob}
        />
      )}

      {/* Snackbar for pending/failed quick feedback */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        <Alert
          onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
          severity={snackbar.severity}
          sx={{ width: "100%" }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}
