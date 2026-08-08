import React, { useState } from "react";
import {
  Box, Typography, Chip, Grid, Card, CardContent, Divider,
  Collapse, IconButton, Tooltip, LinearProgress, Alert,
} from "@mui/material";
import {
  CheckCircle, Schedule, Error, ExpandMore, ExpandLess,
  Shield, Security, VerifiedUser, GppGood,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { alpha, useTheme } from "@mui/material/styles";
import { apiClient } from "../services/api";

// ── Types ──────────────────────────────────────────────────────────────────────

interface EvidenceItem {
  label: string;
  detail: string;
}

interface GuardrailControl {
  id: string;
  name: string;
  category: string;
  status: "active" | "partial" | "pending";
  description: string;
  evidence: EvidenceItem[];
  pending: string[];
}

interface GuardrailsStatus {
  generated_at: string;
  controls: GuardrailControl[];
}

// ── Constants ──────────────────────────────────────────────────────────────────

const CATEGORY_COLORS: Record<string, string> = {
  "Input Safety":    "#4285F4",
  "Output Safety":   "#FBBC04",
  "Access Control":  "#00e676",
  "Compliance":      "#ce93d8",
  "Data Privacy":    "#f06292",
  "Availability":    "#34A853",
  "Abuse Prevention":"#ff9800",
};

const ALL_CATEGORIES = Object.keys(CATEGORY_COLORS);

const STATUS_CONFIG = {
  active:  { label: "ACTIVE",   color: "#00e676", bg: "rgba(0,230,118,0.10)" },
  partial: { label: "PARTIAL",  color: "#FBBC04", bg: "rgba(251,188,4,0.10)" },
  pending: { label: "PENDING",  color: "#9e9e9e", bg: "rgba(158,158,158,0.10)" },
};

// ── ControlCard ────────────────────────────────────────────────────────────────

function ControlCard({ control }: { control: GuardrailControl }) {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(control.status === "active");
  const isDark = theme.palette.mode === "dark";

  const sc = STATUS_CONFIG[control.status];
  const catColor = CATEGORY_COLORS[control.category] ?? "#4285F4";

  const hasEvidence = control.evidence.length > 0;
  const hasPending = control.pending.length > 0;

  return (
    <Card
      sx={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        position: "relative",
        borderTop: `3px solid ${sc.color}`,
        transition: "box-shadow 0.2s",
        "&:hover": {
          boxShadow: isDark
            ? `0 4px 24px rgba(0,0,0,0.5), 0 0 0 1px ${alpha(sc.color, 0.25)}`
            : `0 4px 24px rgba(0,0,0,0.10), 0 0 0 1px ${alpha(sc.color, 0.20)}`,
        },
      }}
    >
      <CardContent sx={{ flex: 1, pb: 1 }}>
        {/* Header row */}
        <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 1 }}>
          <Box sx={{ flex: 1, mr: 1 }}>
            <Typography variant="h6" sx={{ lineHeight: 1.3, mb: 0.5 }}>
              {control.name}
            </Typography>
            <Chip
              label={control.category}
              size="small"
              sx={{
                bgcolor: alpha(catColor, 0.12),
                color: catColor,
                fontWeight: 600,
                fontSize: 11,
                height: 20,
              }}
            />
          </Box>
          <Chip
            label={sc.label}
            size="small"
            sx={{
              bgcolor: sc.bg,
              color: sc.color,
              fontWeight: 700,
              fontSize: 11,
              border: `1px solid ${alpha(sc.color, 0.35)}`,
              flexShrink: 0,
            }}
          />
        </Box>

        <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, lineHeight: 1.6 }}>
          {control.description}
        </Typography>

        {/* Evidence / Pending toggle */}
        {(hasEvidence || hasPending) && (
          <Box
            onClick={() => setExpanded((e) => !e)}
            sx={{
              display: "flex",
              alignItems: "center",
              cursor: "pointer",
              color: "text.secondary",
              "&:hover": { color: "text.primary" },
              userSelect: "none",
              mt: "auto",
            }}
          >
            <Typography variant="caption" sx={{ fontWeight: 600, mr: 0.5 }}>
              {expanded ? "Hide" : "Show"} details
              {hasEvidence && ` · ${control.evidence.length} evidence item${control.evidence.length !== 1 ? "s" : ""}`}
              {hasPending && ` · ${control.pending.length} pending`}
            </Typography>
            {expanded ? <ExpandLess fontSize="small" /> : <ExpandMore fontSize="small" />}
          </Box>
        )}

        {control.status === "pending" && !hasEvidence && (
          <Alert
            severity="warning"
            icon={<Schedule fontSize="small" />}
            sx={{ mt: 1.5, py: 0.5, fontSize: 12 }}
          >
            Not yet implemented
          </Alert>
        )}
      </CardContent>

      <Collapse in={expanded} timeout="auto" unmountOnExit>
        <Divider />
        <CardContent sx={{ pt: 1.5, pb: "12px !important" }}>
          {/* Evidence items */}
          {hasEvidence && (
            <Box sx={{ mb: hasPending ? 2 : 0 }}>
              <Typography
                variant="caption"
                sx={{ fontWeight: 700, color: "#00e676", textTransform: "uppercase", letterSpacing: 1, display: "block", mb: 1 }}
              >
                Evidence
              </Typography>
              {control.evidence.map((ev, i) => (
                <Box key={i} sx={{ display: "flex", gap: 1, mb: 0.75, alignItems: "flex-start" }}>
                  <CheckCircle sx={{ color: "#00e676", fontSize: 14, mt: "2px", flexShrink: 0 }} />
                  <Box>
                    <Typography variant="caption" sx={{ fontWeight: 700, display: "block", lineHeight: 1.4 }}>
                      {ev.label}
                    </Typography>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ fontFamily: "monospace", fontSize: 11, lineHeight: 1.4 }}
                    >
                      {ev.detail}
                    </Typography>
                  </Box>
                </Box>
              ))}
            </Box>
          )}

          {/* Pending items */}
          {hasPending && (
            <Box>
              <Typography
                variant="caption"
                sx={{ fontWeight: 700, color: "#FBBC04", textTransform: "uppercase", letterSpacing: 1, display: "block", mb: 1 }}
              >
                Pending / Roadmap
              </Typography>
              {control.pending.map((item, i) => (
                <Box key={i} sx={{ display: "flex", gap: 1, mb: 0.5, alignItems: "flex-start" }}>
                  <Schedule sx={{ color: "#FBBC04", fontSize: 14, mt: "2px", flexShrink: 0 }} />
                  <Typography variant="caption" color="text.secondary" sx={{ lineHeight: 1.5 }}>
                    {item}
                  </Typography>
                </Box>
              ))}
            </Box>
          )}
        </CardContent>
      </Collapse>
    </Card>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function AIGuardrails() {
  const [activeCategory, setActiveCategory] = useState<string>("All");
  const theme = useTheme();

  const { data, isLoading } = useQuery<GuardrailsStatus>({
    queryKey: ["ai-guardrails"],
    queryFn: () => apiClient.get("/ai-guardrails/status").then((r: any) => r.data),
    staleTime: 60_000,
  });

  const controls = data?.controls ?? [];

  const filtered =
    activeCategory === "All"
      ? controls
      : controls.filter((c) => c.category === activeCategory);

  const counts = {
    active:  controls.filter((c) => c.status === "active").length,
    partial: controls.filter((c) => c.status === "partial").length,
    pending: controls.filter((c) => c.status === "pending").length,
  };

  const coveragePct = controls.length
    ? Math.round(((counts.active + counts.partial * 0.5) / controls.length) * 100)
    : 0;

  return (
    <Box sx={{ p: { xs: 2, md: 3 }, maxWidth: 1400, mx: "auto" }}>
      {/* Page header */}
      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, mb: 3 }}>
        <Box
          sx={{
            width: 48,
            height: 48,
            borderRadius: 2,
            bgcolor: alpha("#4285F4", 0.12),
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Shield sx={{ color: "#4285F4", fontSize: 26 }} />
        </Box>
        <Box>
          <Typography variant="h5" sx={{ mb: 0.5 }}>
            AI Guardrails
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Security controls governing every LLM call in Monitara AI — what's active, what's partially implemented, and what's on the roadmap.
          </Typography>
        </Box>
      </Box>

      {isLoading && <LinearProgress sx={{ mb: 2, borderRadius: 2 }} />}

      {/* Summary stats + coverage bar */}
      <Box
        sx={{
          display: "flex",
          flexWrap: "wrap",
          gap: 2,
          mb: 3,
          p: 2,
          borderRadius: 2,
          bgcolor: "background.paper",
          border: "1px solid",
          borderColor: "divider",
          alignItems: "center",
        }}
      >
        <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
          {(["active", "partial", "pending"] as const).map((s) => (
            <Box key={s} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <Box
                sx={{
                  width: 10,
                  height: 10,
                  borderRadius: "50%",
                  bgcolor: STATUS_CONFIG[s].color,
                }}
              />
              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                {counts[s]}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ textTransform: "capitalize" }}>
                {s}
              </Typography>
            </Box>
          ))}
        </Box>
        <Divider orientation="vertical" flexItem sx={{ display: { xs: "none", md: "block" } }} />
        <Box sx={{ flex: 1, minWidth: 200 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Guardrail coverage
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 700, color: coveragePct >= 70 ? "#00e676" : "#FBBC04" }}>
              {coveragePct}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={coveragePct}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha("#fff", 0.08),
              "& .MuiLinearProgress-bar": {
                bgcolor: coveragePct >= 70 ? "#00e676" : "#FBBC04",
                borderRadius: 3,
              },
            }}
          />
        </Box>
      </Box>

      {/* Category filter chips */}
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 3 }}>
        {["All", ...ALL_CATEGORIES].map((cat) => {
          const catColor = cat === "All" ? "#4285F4" : CATEGORY_COLORS[cat];
          const isActive = activeCategory === cat;
          return (
            <Chip
              key={cat}
              label={cat}
              onClick={() => setActiveCategory(cat)}
              sx={{
                fontWeight: isActive ? 700 : 500,
                bgcolor: isActive ? alpha(catColor, 0.18) : "transparent",
                color: isActive ? catColor : "text.secondary",
                border: `1px solid ${isActive ? alpha(catColor, 0.5) : "transparent"}`,
                "&:hover": {
                  bgcolor: alpha(catColor, 0.10),
                  color: catColor,
                },
                transition: "all 0.15s",
              }}
            />
          );
        })}
      </Box>

      {/* Cards grid */}
      <Grid container spacing={2}>
        {filtered.map((control) => (
          <Grid key={control.id} size={{ xs: 12, sm: 6, lg: 4 }}>
            <ControlCard control={control} />
          </Grid>
        ))}
        {filtered.length === 0 && !isLoading && (
          <Grid size={{ xs: 12 }}>
            <Typography color="text.secondary" sx={{ textAlign: "center", py: 6 }}>
              No controls in this category.
            </Typography>
          </Grid>
        )}
      </Grid>

      {/* Footer note */}
      {data && (
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 3, textAlign: "right" }}>
          Last refreshed: {new Date(data.generated_at).toLocaleString()}
        </Typography>
      )}
    </Box>
  );
}
