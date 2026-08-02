import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, CardContent, Chip, Button, Alert,
  Dialog, DialogTitle, DialogContent, DialogActions, IconButton, Tooltip,
} from "@mui/material";
import { Delete, RestoreFromTrash, ArrowBack, SmartToy } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { agentsApi } from "../services/api";
import { fromNow } from "../utils/datetime";

const RUN_STATUS_COLOR: Record<string, string> = {
  completed: "#34A853", failed: "#EA4335", running: "#FBBC04", pending: "#FBBC04",
};

export default function AgentRunTrash() {
  const { clientId } = useActiveClient();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [pendingPermanentDelete, setPendingPermanentDelete] = useState<any | null>(null);

  const { data: hiddenRuns = [], isLoading } = useQuery<any[]>({
    queryKey: ["agent-runs-hidden", clientId],
    queryFn: () => agentsApi.listHiddenRuns(clientId!),
    enabled: !!clientId,
  });

  const restoreMutation = useMutation({
    mutationFn: (runId: string) => agentsApi.restoreRun(clientId!, runId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-runs-hidden", clientId] });
      qc.invalidateQueries({ queryKey: ["agent-runs-list", clientId] });
      qc.invalidateQueries({ queryKey: ["agent-runs", clientId] });
    },
  });

  const permanentDeleteMutation = useMutation({
    mutationFn: (runId: string) => agentsApi.permanentDeleteRun(clientId!, runId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-runs-hidden", clientId] });
      setPendingPermanentDelete(null);
    },
  });

  if (!clientId) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="info">Select a client to view the agent run trash.</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: { xs: 2, md: 3 } }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 3 }}>
        <Tooltip title="Back to AI Buddies">
          <IconButton onClick={() => navigate("/ai-advisor/agents")} sx={{ color: "text.secondary" }}>
            <ArrowBack />
          </IconButton>
        </Tooltip>
        <Delete sx={{ color: "text.secondary", fontSize: 22 }} />
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700, lineHeight: 1.2 }}>Agent Run Trash</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Archived runs — restore to bring back or permanently delete to remove forever.
          </Typography>
        </Box>
        {hiddenRuns.length > 0 && (
          <Chip
            label={`${hiddenRuns.length} archived`}
            size="small"
            sx={{ ml: 1, bgcolor: "rgba(234,67,53,0.1)", color: "#EA4335", fontWeight: 700 }}
          />
        )}
      </Box>

      {isLoading ? (
        <Typography sx={{ color: "text.secondary" }}>Loading…</Typography>
      ) : hiddenRuns.length === 0 ? (
        <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 2, p: 4, textAlign: "center" }}>
          <Delete sx={{ fontSize: 40, color: "text.disabled", mb: 1.5 }} />
          <Typography variant="h6" sx={{ color: "text.secondary", mb: 0.5 }}>Trash is empty</Typography>
          <Typography variant="body2" sx={{ color: "text.disabled" }}>
            No archived agent runs. Archive runs from AI Buddies to see them here.
          </Typography>
        </Card>
      ) : (
        <Box>
          {hiddenRuns.map((run: any) => (
            <Card key={run.id} sx={{
              bgcolor: "background.paper",
              border: "1px solid rgba(255,255,255,0.06)",
              borderRadius: 1.5, mb: 1,
            }}>
              <CardContent sx={{ py: 1.5, "&:last-child": { pb: 1.5 } }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                  <SmartToy sx={{ color: "text.disabled", fontSize: 18 }} />
                  <Chip
                    label={(run.agent_type || "").replace(/_/g, " ")}
                    size="small"
                    sx={{ height: 20, fontSize: 10, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", textTransform: "capitalize" }}
                  />
                  <Chip
                    label={run.status || "unknown"}
                    size="small"
                    sx={{
                      height: 20, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                      bgcolor: `${RUN_STATUS_COLOR[run.status] || "#888"}20`,
                      color: RUN_STATUS_COLOR[run.status] || "#888",
                    }}
                  />
                  <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10 }}>
                    Run: {run.started_at ? new Date(run.started_at).toLocaleString() : "—"}
                  </Typography>
                  {run.hidden_at && (
                    <Typography variant="caption" sx={{ color: "text.disabled", fontSize: 10 }}>
                      · Archived {fromNow(run.hidden_at)}
                    </Typography>
                  )}
                  <Box sx={{ flex: 1 }} />
                  <Tooltip title="Restore run">
                    <Button
                      size="small"
                      startIcon={<RestoreFromTrash sx={{ fontSize: 15 }} />}
                      onClick={() => restoreMutation.mutate(run.id)}
                      disabled={restoreMutation.isPending}
                      sx={{ fontSize: 11, color: "#34A853", borderColor: "rgba(52,168,83,0.3)",
                        "&:hover": { bgcolor: "rgba(52,168,83,0.08)" } }}
                      variant="outlined"
                    >
                      Restore
                    </Button>
                  </Tooltip>
                  <Tooltip title="Permanently delete — cannot be undone">
                    <IconButton
                      size="small"
                      onClick={() => setPendingPermanentDelete(run)}
                      sx={{ color: "text.secondary", "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" } }}
                    >
                      <Delete sx={{ fontSize: 16 }} />
                    </IconButton>
                  </Tooltip>
                </Box>
              </CardContent>
            </Card>
          ))}
        </Box>
      )}

      {/* Permanent delete confirmation */}
      <Dialog
        open={!!pendingPermanentDelete}
        onClose={() => setPendingPermanentDelete(null)}
        slotProps={{ paper: { sx: { bgcolor: "background.paper", color: "text.primary" } } }}
      >
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          Permanently delete run?
        </DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            This cannot be undone. The run output will be removed permanently.
            Any risk entries, threat entries, or remediation actions created by this run are kept.
          </Typography>
          {pendingPermanentDelete && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ fontWeight: 600, textTransform: "capitalize" }}>
                {(pendingPermanentDelete.agent_type || "").replace(/_/g, " ")}
              </Typography>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {pendingPermanentDelete.started_at
                  ? `Run started ${fromNow(pendingPermanentDelete.started_at)}`
                  : ""}
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingPermanentDelete(null)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button
            variant="contained"
            disabled={permanentDeleteMutation.isPending}
            onClick={() => pendingPermanentDelete && permanentDeleteMutation.mutate(pendingPermanentDelete.id)}
            sx={{ bgcolor: "#EA4335", "&:hover": { bgcolor: "#c5362b" } }}
          >
            Delete Forever
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
