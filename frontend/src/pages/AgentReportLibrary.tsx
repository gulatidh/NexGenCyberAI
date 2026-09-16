import React, { useState, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Chip, TextField, InputAdornment, Skeleton,
  Collapse, IconButton, Alert,
} from "@mui/material";
import { Search, ExpandMore, ExpandLess, Psychology, SmartToy } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { agentsApi } from "../services/api";
import { fromNow, fmt } from "../utils/datetime";

// ── Agent metadata ────────────────────────────────────────────────────────────

const AGENT_META: Record<string, { label: string; color: string; category: string }> = {
  va_scanner:           { label: "VA Scanner",          color: "#4285F4", category: "scan" },
  ai_code_review:       { label: "AI Code Review",      color: "#EA4335", category: "scan" },
  configuration_review: { label: "Config Review",       color: "#FF6D00", category: "scan" },
  risk_manager:         { label: "Risk Manager",        color: "#E65100", category: "risk" },
  orchestrator:         { label: "Orchestrator",        color: "#7C4DFF", category: "risk" },
  threat_intel:         { label: "Threat Intel",        color: "#00897B", category: "threat" },
  compliance_monitor:   { label: "Compliance Monitor",  color: "#1565C0", category: "compliance" },
  framework_analyst:    { label: "Framework Analyst",   color: "#6A1B9A", category: "compliance" },
  remediation:          { label: "Remediation",         color: "#2E7D32", category: "remediation" },
};

function meta(type: string) {
  return AGENT_META[type] ?? { label: type.replace(/_/g, " "), color: "#9e9e9e", category: "other" };
}

const CATEGORIES = [
  { key: "all",         label: "All" },
  { key: "scan",        label: "Scan & Findings" },
  { key: "risk",        label: "Risk" },
  { key: "threat",      label: "Threat" },
  { key: "compliance",  label: "Compliance" },
  { key: "remediation", label: "Remediation" },
  { key: "other",       label: "Other" },
];

const DATE_RANGES = [
  { key: "all",   label: "All time",  days: 0 },
  { key: "today", label: "Today",     days: 1 },
  { key: "7d",    label: "7 days",    days: 7 },
  { key: "30d",   label: "30 days",   days: 30 },
];

// ── Run card ──────────────────────────────────────────────────────────────────

function RunCard({ run }: { run: any }) {
  const [open, setOpen] = useState(false);
  const m = meta(run.agent_type);
  const output: string = run.output_data?.output ?? "";

  return (
    <Box sx={{
      border: "1px solid", borderColor: "divider", borderRadius: 2,
      overflow: "hidden", bgcolor: "background.paper",
      transition: "border-color .15s",
      "&:hover": { borderColor: m.color + "60" },
    }}>
      {/* Header */}
      <Box
        sx={{ display: "flex", alignItems: "center", gap: 1.5, px: 2, py: 1.5, cursor: "pointer" }}
        onClick={() => setOpen((v) => !v)}
      >
        <Box sx={{
          width: 8, height: 8, borderRadius: "50%", bgcolor: m.color, flexShrink: 0,
        }} />
        <Chip
          label={m.label}
          size="small"
          sx={{ bgcolor: `${m.color}18`, color: m.color, fontWeight: 700, fontSize: 11, height: 20, flexShrink: 0 }}
        />
        {run.scan_id && (
          <Typography variant="caption" sx={{ color: "text.disabled", fontFamily: "monospace", fontSize: 11 }}>
            scan:{run.scan_id.slice(0, 8)}…
          </Typography>
        )}
        <Box sx={{ ml: "auto", display: "flex", alignItems: "center", gap: 1.5, flexShrink: 0 }}>
          <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
            {fromNow(run.started_at)}
          </Typography>
          <Typography variant="caption" sx={{ color: "text.disabled", fontSize: 10 }}>
            {fmt(run.started_at)}
          </Typography>
          <IconButton size="small" sx={{ p: 0.25 }}>
            {open ? <ExpandLess sx={{ fontSize: 18 }} /> : <ExpandMore sx={{ fontSize: 18 }} />}
          </IconButton>
        </Box>
      </Box>

      {/* Expanded output */}
      <Collapse in={open}>
        <Box sx={{
          mx: 2, mb: 2, fontFamily: "monospace", fontSize: 13, lineHeight: 1.7,
          whiteSpace: "pre-wrap", color: "text.primary",
          bgcolor: "rgba(0,0,0,0.35)", p: 2, borderRadius: 1.5,
          overflow: "auto", maxHeight: 600,
          borderTop: "1px solid", borderColor: "divider",
        }}>
          {output || (
            <Typography variant="caption" sx={{ color: "text.disabled" }}>
              No text output recorded for this run.
            </Typography>
          )}
        </Box>
      </Collapse>
    </Box>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AgentReportLibrary() {
  const { clientId } = useActiveClient();
  const [searchParams] = useSearchParams();
  const initialCategory = searchParams.get("category") ?? "all";

  const [category, setCategory] = useState(initialCategory);
  const [dateRange, setDateRange] = useState("all");
  const [search, setSearch] = useState("");

  const { data: runs = [], isLoading } = useQuery({
    queryKey: ["agent-runs-filter", clientId, "all"],
    queryFn: () => agentsApi.filterRuns(clientId!, { limit: 200 }),
    enabled: !!clientId,
  });

  const filtered = useMemo(() => {
    let list = runs as any[];

    // Category filter
    if (category !== "all") {
      list = list.filter((r) => meta(r.agent_type).category === category);
    }

    // Date range filter
    const range = DATE_RANGES.find((d) => d.key === dateRange);
    if (range && range.days > 0) {
      const cutoff = Date.now() - range.days * 86400_000;
      list = list.filter((r) => new Date(r.started_at).getTime() >= cutoff);
    }

    // Search
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (r) =>
          meta(r.agent_type).label.toLowerCase().includes(q) ||
          (r.output_data?.output ?? "").toLowerCase().includes(q) ||
          (r.scan_id ?? "").toLowerCase().includes(q),
      );
    }

    return list;
  }, [runs, category, dateRange, search]);

  if (!clientId) {
    return (
      <Box sx={{ p: 4 }}>
        <Alert severity="info">Select a client to view agent reports.</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: { xs: 2, md: 3 }, maxWidth: 1400, mx: "auto" }}>
      {/* Page header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 3 }}>
        <Psychology sx={{ color: "#7C4DFF", fontSize: 28 }} />
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.2 }}>
            Agent Reports
          </Typography>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            Full history of AI agent runs — intelligence, risk analysis, compliance assessments, and more.
          </Typography>
        </Box>
        {!isLoading && (
          <Chip
            label={`${filtered.length} / ${(runs as any[]).length} runs`}
            size="small"
            sx={{ ml: "auto", color: "text.secondary" }}
          />
        )}
      </Box>

      {/* Filters row */}
      <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 3, alignItems: "center" }}>
        <TextField
          size="small"
          placeholder="Search reports…"
          value={search}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearch(e.target.value)}
          slotProps={{ input: { startAdornment: <InputAdornment position="start"><Search sx={{ fontSize: 16, color: "text.secondary" }} /></InputAdornment> } }}
          sx={{ width: 240 }}
        />

        {/* Category chips */}
        <Box sx={{ display: "flex", gap: 0.75, flexWrap: "wrap" }}>
          {CATEGORIES.map((c) => (
            <Chip
              key={c.key}
              label={c.label}
              size="small"
              onClick={() => setCategory(c.key)}
              variant={category === c.key ? "filled" : "outlined"}
              sx={{
                cursor: "pointer",
                ...(category === c.key && { bgcolor: "#7C4DFF", color: "#fff" }),
              }}
            />
          ))}
        </Box>

        {/* Date range chips */}
        <Box sx={{ display: "flex", gap: 0.75, ml: "auto" }}>
          {DATE_RANGES.map((d) => (
            <Chip
              key={d.key}
              label={d.label}
              size="small"
              onClick={() => setDateRange(d.key)}
              variant={dateRange === d.key ? "filled" : "outlined"}
              sx={{
                cursor: "pointer",
                ...(dateRange === d.key && { bgcolor: "action.selected" }),
              }}
            />
          ))}
        </Box>
      </Box>

      {/* Results */}
      {isLoading ? (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
          {[1, 2, 3, 4].map((k) => <Skeleton key={k} variant="rounded" height={56} />)}
        </Box>
      ) : filtered.length === 0 ? (
        <Box sx={{
          textAlign: "center", py: 8, border: "1px dashed", borderColor: "divider",
          borderRadius: 3, bgcolor: "background.paper",
        }}>
          <SmartToy sx={{ fontSize: 48, color: "text.disabled", mb: 1.5 }} />
          <Typography variant="body2" sx={{ color: "text.secondary", mb: 0.5, fontWeight: 600 }}>
            {(runs as any[]).length === 0
              ? "No agent reports yet"
              : "No reports match your filters"}
          </Typography>
          <Typography variant="caption" sx={{ color: "text.disabled" }}>
            {(runs as any[]).length === 0
              ? "Run an AI agent from the Agents page to generate intelligence reports."
              : "Try adjusting the category or date range filters."}
          </Typography>
        </Box>
      ) : (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
          {filtered.map((run: any) => <RunCard key={run.id} run={run} />)}
        </Box>
      )}
    </Box>
  );
}
