/**
 * AgentInsightCard
 *
 * Tile view (default) and expanded view of a single AI agent run. The parent
 * controls which tile is expanded via `expanded` + `onToggle`, so only one
 * card in a list is open at a time.
 *
 * The tile shows: agent name, status, when it ran, and a short summary
 * preview pulled from the agent's narrative output. Click the tile to expand
 * into the full RichOutput view; click again (or click another tile) to
 * collapse.
 */
import React from "react";
import { Avatar, Box, Card, CardContent, Chip, Collapse, IconButton, Tooltip, Typography } from "@mui/material";
import {
  ExpandMore, ExpandLess, SmartToy, ErrorOutlined, CheckCircleOutlined, HourglassEmpty,
  DeleteOutlined, AutoAwesome, Bolt,
} from "@mui/icons-material";
import { fromNow } from "../utils/datetime";
import RichOutput from "./RichOutput";
import ArtifactCard from "./ArtifactCard";

interface Props {
  run: {
    id: string;
    agent_type: string;
    status: string;
    started_at?: string;
    output_data?: any;
    error_message?: string | null;
  };
  expanded: boolean;
  onToggle: () => void;
  onDelete?: () => void;
}

const STATUS_STYLE: Record<string, { color: string; bg: string; Icon: any }> = {
  completed: { color: "#34A853", bg: "rgba(52,168,83,0.15)", Icon: CheckCircleOutlined },
  success:   { color: "#34A853", bg: "rgba(52,168,83,0.15)", Icon: CheckCircleOutlined },
  failed:    { color: "#EA4335", bg: "rgba(234,67,53,0.15)", Icon: ErrorOutlined },
  error:     { color: "#EA4335", bg: "rgba(234,67,53,0.15)", Icon: ErrorOutlined },
  running:   { color: "#FBBC04", bg: "rgba(251,188,4,0.15)", Icon: HourglassEmpty },
  queued:    { color: "#FBBC04", bg: "rgba(251,188,4,0.15)", Icon: HourglassEmpty },
};

const AGENT_LABEL: Record<string, string> = {
  risk_manager: "Risk Manager",
  threat_intel: "Threat Intel",
  remediation:  "Remediation",
  vulnerability: "Vulnerability Analysis",
  framework:    "Framework Mapping",
  compliance:   "Compliance",
  orchestrator: "Orchestrator",
};

const NARRATIVE_KEYS = ["summary", "text", "output", "result", "analysis", "report", "verdict"];

// Strip the same conversational closers RichOutput strips, so the tile
// preview doesn't show "If you want, I can also..."
const CONVERSATIONAL_PATTERNS: RegExp[] = [
  /\n*if you (would |'d )?like[\s\S]*?\?\s*$/i,
  /\n*shall i[\s\S]*?\?\s*$/i,
  /\n*do you want me to[\s\S]*?\?\s*$/i,
  /\n*would you like me to[\s\S]*?\?\s*$/i,
  /\n*let me know if[\s\S]*$/i,
  /\n*happy to[\s\S]*?\.\s*$/i,
];

function extractSummary(output: any, maxLen = 220): string {
  if (!output) return "";
  let raw = "";
  if (typeof output === "string") raw = output;
  else if (typeof output === "object") {
    for (const k of NARRATIVE_KEYS) {
      const v = output[k];
      if (typeof v === "string" && v.trim()) { raw = v; break; }
    }
  }
  if (!raw) return "";
  // Strip markdown noise + conversational closers
  let out = raw;
  for (const re of CONVERSATIONAL_PATTERNS) out = out.replace(re, "");
  // Strip markdown headings and bullets, collapse whitespace
  out = out
    .replace(/^#+\s*/gm, "")
    .replace(/^[-*]\s+/gm, "")
    .replace(/\*\*/g, "")
    .replace(/`/g, "")
    .replace(/\n+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (out.length <= maxLen) return out;
  // Trim at sentence boundary if possible
  const cut = out.slice(0, maxLen);
  const lastDot = cut.lastIndexOf(". ");
  return (lastDot > 80 ? cut.slice(0, lastDot + 1) : cut.trim() + "…");
}

export default function AgentInsightCard({ run, expanded, onToggle, onDelete }: Props) {
  const status = (run.status || "").toLowerCase();
  const style = STATUS_STYLE[status] || STATUS_STYLE.completed;
  // Catalog buddies persist their display name in input_data.agent_name —
  // prefer that over the generic AgentType label.
  const input = (run as any).input_data || {};
  const catalogName = typeof input?.agent_name === "string" ? input.agent_name : null;
  const label = catalogName || AGENT_LABEL[run.agent_type] || run.agent_type.replace(/_/g, " ");
  const summary = React.useMemo(() => extractSummary(run.output_data), [run.output_data]);
  const StatusIcon = style.Icon;

  // Phase 7A — structured artifacts produced by the buddy. Phase 7C —
  // avatar / accent / proactive marker.
  const output = (run.output_data as any) || {};
  const artifacts: any[] = Array.isArray(output.artifacts) ? output.artifacts : [];
  const outputKind: string = output.output_kind || "prose";
  const isProactive: boolean = !!output.proactive;
  const accent = (input.accent_color as string) || "#4285F4";
  const avatarUrl: string | undefined = input.avatar_url || undefined;

  return (
    <Card
      sx={{
        bgcolor: "background.paper",
        border: expanded ? "1px solid #4285F4" : "1px solid rgba(255,255,255,0.08)",
        borderRadius: 2,
        transition: "border-color .15s, background-color .15s",
        "&:hover": { borderColor: expanded ? "#4285F4" : "rgba(66,133,244,0.5)" },
      }}
    >
      {/* Tile header — always visible */}
      <Box
        onClick={onToggle}
        sx={{
          display: "flex", alignItems: "center", gap: 1.25, px: 2, py: 1.5, cursor: "pointer",
        }}
      >
        {avatarUrl ? (
          <Avatar src={avatarUrl} sx={{ width: 32, height: 32, flexShrink: 0 }} />
        ) : (
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
            <SmartToy sx={{ color: accent, fontSize: 24 }} />
          </Box>
        )}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
            <Typography sx={{ color: "text.primary", fontSize: 14, fontWeight: 700, textTransform: "capitalize" }}>
              {label}
            </Typography>
            <Chip
              icon={<StatusIcon sx={{ fontSize: 12, color: `${style.color} !important` }} />}
              label={status || "completed"}
              size="small"
              sx={{
                height: 18, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                bgcolor: style.bg, color: style.color,
                "& .MuiChip-icon": { ml: 0.5, mr: -0.25 },
              }}
            />
            {isProactive && (
              <Tooltip title="Buddy ran proactively in response to a platform event">
                <Chip icon={<Bolt sx={{ fontSize: 11, color: "#FBBC04 !important" }} />}
                  label="proactive" size="small"
                  sx={{ height: 18, fontSize: 10, fontWeight: 700, bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04" }} />
              </Tooltip>
            )}
            {artifacts.length > 0 && (
              <Chip icon={<AutoAwesome sx={{ fontSize: 11, color: `${accent} !important` }} />}
                label={`${artifacts.length} ${outputKind.replace(/_/g, " ")}`}
                size="small"
                sx={{ height: 18, fontSize: 10, fontWeight: 700, textTransform: "lowercase",
                  bgcolor: `${accent}1A`, color: accent }} />
            )}
            {run.started_at && (
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                {fromNow(run.started_at)}
              </Typography>
            )}
          </Box>
          {!expanded && summary && (
            <Typography
              variant="caption"
              sx={{
                color: "text.secondary", fontSize: 12.5, lineHeight: 1.45, mt: 0.5,
                display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical",
                overflow: "hidden",
              }}
            >
              {summary}
            </Typography>
          )}
          {!expanded && !summary && !run.error_message && (
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 12, fontStyle: "italic" }}>
              No narrative output captured for this run.
            </Typography>
          )}
        </Box>
        {onDelete && (
          <Tooltip title="Delete this analysis">
            <IconButton
              size="small"
              onClick={(e) => { e.stopPropagation(); onDelete(); }}
              sx={{
                color: "text.secondary",
                "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" },
              }}
            >
              <DeleteOutlined sx={{ fontSize: 18 }} />
            </IconButton>
          </Tooltip>
        )}
        <IconButton size="small" sx={{ color: "text.secondary" }} aria-label={expanded ? "Collapse" : "Expand"}>
          {expanded ? <ExpandLess /> : <ExpandMore />}
        </IconButton>
      </Box>

      {/* Expanded body */}
      <Collapse in={expanded} timeout="auto" unmountOnExit>
        <CardContent sx={{ pt: 0, borderTop: "1px solid rgba(255,255,255,0.06)" }}>
          {run.error_message && (
            <Typography variant="caption" sx={{ color: "#EA4335", display: "block", mb: 1 }}>
              Error: {run.error_message}
            </Typography>
          )}
          <RichOutput value={run.output_data} />
          {artifacts.length > 0 && (
            <ArtifactCard runId={run.id} kind={outputKind} artifacts={artifacts} clientId={(run as any).client_id} />
          )}
        </CardContent>
      </Collapse>
    </Card>
  );
}
