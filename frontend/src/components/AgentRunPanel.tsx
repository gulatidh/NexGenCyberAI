import React, { useState } from "react";
import {
  Box, Typography, Chip, IconButton, Skeleton, Collapse,
} from "@mui/material";
import { ExpandMore, ExpandLess, SmartToy } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { agentsApi } from "../services/api";
import { fromNow } from "../utils/datetime";

const AGENT_META: Record<string, { label: string; color: string }> = {
  va_scanner:           { label: "VA Scanner",          color: "#4285F4" },
  ai_code_review:       { label: "AI Code Review",      color: "#EA4335" },
  configuration_review: { label: "Config Review",       color: "#FF6D00" },
  risk_manager:         { label: "Risk Manager",        color: "#E65100" },
  orchestrator:         { label: "Orchestrator",        color: "#7C4DFF" },
  threat_intel:         { label: "Threat Intel",        color: "#00897B" },
  compliance_monitor:   { label: "Compliance Monitor",  color: "#1565C0" },
  framework_analyst:    { label: "Framework Analyst",   color: "#6A1B9A" },
  remediation:          { label: "Remediation",         color: "#2E7D32" },
};

function agentMeta(type: string) {
  return AGENT_META[type] ?? { label: type.replace(/_/g, " "), color: "#9e9e9e" };
}

interface AgentRunPanelProps {
  clientId: string;
  agentTypes: string[];
  scanId?: string;
  title?: string;
  emptyMessage?: string;
}

function RunCard({ run }: { run: any }) {
  const [open, setOpen] = useState(false);
  const meta = agentMeta(run.agent_type);
  const output: string = run.output_data?.output ?? "";

  return (
    <Box sx={{
      border: "1px solid", borderColor: "divider", borderRadius: 1.5,
      overflow: "hidden", bgcolor: "background.paper",
    }}>
      <Box sx={{
        display: "flex", alignItems: "center", gap: 1.5, px: 2, py: 1.25,
        cursor: "pointer", "&:hover": { bgcolor: "action.hover" },
      }} onClick={() => setOpen((v) => !v)}>
        <Chip
          label={meta.label}
          size="small"
          sx={{
            bgcolor: `${meta.color}18`, color: meta.color,
            fontWeight: 700, fontSize: 11, height: 20, flexShrink: 0,
          }}
        />
        {run.scan_id && (
          <Typography variant="caption" sx={{ color: "text.disabled", fontFamily: "monospace", fontSize: 11 }}>
            scan:{run.scan_id.slice(0, 8)}
          </Typography>
        )}
        <Typography variant="caption" sx={{ color: "text.secondary", ml: "auto", flexShrink: 0 }}>
          {fromNow(run.started_at)}
        </Typography>
        <IconButton size="small" sx={{ p: 0.25, color: "text.secondary" }}>
          {open ? <ExpandLess sx={{ fontSize: 18 }} /> : <ExpandMore sx={{ fontSize: 18 }} />}
        </IconButton>
      </Box>

      <Collapse in={open}>
        <Box sx={{
          mx: 2, mb: 2, fontFamily: "monospace", fontSize: 13,
          whiteSpace: "pre-wrap", color: "text.primary",
          bgcolor: "rgba(0,0,0,0.3)", p: 2, borderRadius: 1,
          overflow: "auto", maxHeight: 500,
          borderTop: "1px solid", borderColor: "divider",
        }}>
          {output || <Typography variant="caption" sx={{ color: "text.disabled" }}>No report output.</Typography>}
        </Box>
      </Collapse>
    </Box>
  );
}

export default function AgentRunPanel({
  clientId,
  agentTypes,
  scanId,
  title = "AI Reports",
  emptyMessage = "No agent reports yet.",
}: AgentRunPanelProps) {
  const { data: runs = [], isLoading } = useQuery({
    queryKey: ["agent-runs-filter", clientId, agentTypes.join(","), scanId],
    queryFn: () => agentsApi.filterRuns(clientId, {
      agent_type: agentTypes.join(","),
      scan_id: scanId,
      limit: 20,
    }),
    enabled: !!clientId,
  });

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
        <SmartToy sx={{ fontSize: 16, color: "text.secondary" }} />
        <Typography variant="caption" sx={{
          color: "text.secondary", fontWeight: 700, letterSpacing: 1,
          textTransform: "uppercase", fontSize: 11,
        }}>
          {title}
        </Typography>
        {runs.length > 0 && (
          <Chip label={runs.length} size="small" sx={{ height: 18, fontSize: 11, ml: "auto" }} />
        )}
      </Box>

      {isLoading ? (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
          {[1, 2].map((k) => <Skeleton key={k} variant="rounded" height={44} />)}
        </Box>
      ) : runs.length === 0 ? (
        <Typography variant="caption" sx={{ color: "text.disabled", fontStyle: "italic" }}>
          {emptyMessage}
        </Typography>
      ) : (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
          {runs.map((run: any) => <RunCard key={run.id} run={run} />)}
        </Box>
      )}
    </Box>
  );
}
