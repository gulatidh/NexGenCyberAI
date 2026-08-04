import React, { useState, useEffect, useRef, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Card, CardContent, Chip, Stack, alpha,
  Dialog, DialogContent, TextField, List, ListItemButton,
  ListItemIcon, ListItemText, Divider, InputAdornment, Tooltip, Fab,
} from "@mui/material";
import { Grid } from "@mui/material";
import {
  Cable, Hub, BugReport, Insights, Radar, GppGood, SmartToy,
  Settings, ArrowForward, People, Security, Policy, Dashboard,
  Search, Keyboard, AutoStories, Description, Psychology, GppBad,
  PlaylistAddCheck, TrendingUp, AccountTree, Storage, LibraryAdd,
  Assessment, Engineering,
} from "@mui/icons-material";
import { useTheme } from "@mui/material/styles";

// ── Phase definitions ────────────────────────────────────────────────────────

const PHASES = [
  {
    num: 1, id: "setup", label: "Setup", color: "#42A5F5", Icon: Cable,
    tagline: "Connect your environment",
    items: ["Clients & Projects", "Scanner Connectors", "AI Providers", "Ticket Sync"],
    metric: "3 connectors active", path: "/connections",
  },
  {
    num: 2, id: "design", label: "Design", color: "#AB47BC", Icon: Hub,
    tagline: "Model threats before you scan",
    items: ["Threat Models (DFD + STRIDE)", "AI Detection Rules (Sigma)", "Compliance Frameworks", "Custom Policy"],
    metric: "2 threat models", path: "/threat-models",
  },
  {
    num: 3, id: "discover", label: "Discover", color: "#26A69A", Icon: BugReport,
    tagline: "Run assessments, build inventory",
    items: ["AI Assisted Scan (wizard)", "VA / DAST / SAST / Cloud Scans", "Asset Inventory", "Findings"],
    metric: "5 scans completed", path: "/scans",
  },
  {
    num: 4, id: "analyse", label: "Analyse", color: "#FFA726", Icon: Insights,
    tagline: "Understand exposure & risk",
    items: ["Risk Overview (FAIR ALE)", "Risk Register", "Attack Paths (MITRE)", "CVE Blast Radius", "Compliance Heatmap"],
    metric: "47 risks scored", path: "/risk-overview",
  },
  {
    num: 5, id: "respond", label: "Respond", color: "#EF5350", Icon: Radar,
    tagline: "Close gaps, manage exposure",
    items: ["Threat Intelligence (ATT&CK)", "Control Deficiencies", "Remediation Actions", "AI Remediations", "CTEM Programs"],
    metric: "12 open gaps", path: "/control-deficiencies",
  },
  {
    num: 6, id: "report", label: "Report", color: "#66BB6A", Icon: GppGood,
    tagline: "Deliver evidence & track posture",
    items: ["VAPT Reports (PDF / DOCX)", "Evidence Package (ZIP)", "Posture Trends", "Client Comparison"],
    metric: "3 VAPT reports", path: "/vapt/reports",
  },
  {
    num: 7, id: "automate", label: "Automate", color: "#5C6BC0", Icon: SmartToy,
    tagline: "AI-powered tools & knowledge",
    items: ["AI Buddies (6 agents)", "Automated Workflows", "Knowledge Base", "Security Docs (RAG)", "Ask Your Data (NL→SQL)"],
    metric: "4 workflows active", path: "/agents",
  },
  {
    num: 8, id: "configure", label: "Configure", color: "#78909C", Icon: Settings,
    tagline: "Integrations & platform settings",
    items: ["Settings & Notifications", "Webhooks (HMAC-signed)", "API Keys (M2M / CI-CD)", "Help & Documentation"],
    metric: "", path: "/settings",
  },
];

// ── Command palette items ────────────────────────────────────────────────────

interface CmdItem {
  label: string;
  sub?: string;
  path: string;
  section: string;
  Icon: React.ElementType;
}

const CMD_ITEMS: CmdItem[] = [
  // Recent (mock)
  { label: "Dashboard", path: "/dashboard", section: "Recent", Icon: Dashboard },
  { label: "Findings — 12 Critical", path: "/findings", section: "Recent", Icon: Security },
  { label: "Threat Models", path: "/threat-models", section: "Recent", Icon: Hub },
  // Setup
  { label: "Connections", sub: "Scanners, AI, Jira", path: "/connections", section: "Setup", Icon: Cable },
  { label: "Clients", path: "/clients", section: "Setup", Icon: People },
  // Design
  { label: "Threat Models", sub: "DFD + STRIDE + Sigma", path: "/threat-models", section: "Design", Icon: Hub },
  { label: "Frameworks", sub: "NIST CSF, CIS v8, ISO 27001…", path: "/frameworks", section: "Design", Icon: Policy },
  { label: "Custom Policy", path: "/custom-frameworks", section: "Design", Icon: LibraryAdd },
  // Discover
  { label: "AI Assisted Scan", sub: "Guided scan wizard", path: "/ai-assisted-scan", section: "Discover", Icon: SmartToy },
  { label: "Scans", path: "/scans", section: "Discover", Icon: BugReport },
  { label: "Assets", path: "/assets", section: "Discover", Icon: Storage },
  { label: "Findings", path: "/findings", section: "Discover", Icon: Security },
  // Analyse
  { label: "Risk Overview", sub: "FAIR ALE model", path: "/risk-overview", section: "Analyse", Icon: Insights },
  { label: "Risk Register", path: "/risks", section: "Analyse", Icon: Assessment },
  { label: "Attack Paths", sub: "MITRE kill-chain graph", path: "/attack-paths", section: "Analyse", Icon: AccountTree },
  { label: "CVE Blast Radius", path: "/cve-pivot", section: "Analyse", Icon: BugReport },
  // Respond
  { label: "Threat Intelligence", sub: "ATT&CK-mapped entries", path: "/threat-register", section: "Respond", Icon: Radar },
  { label: "Control Deficiencies", path: "/control-deficiencies", section: "Respond", Icon: GppBad },
  { label: "Remediation", path: "/governance/remediation", section: "Respond", Icon: PlaylistAddCheck },
  { label: "CTEM Programs", sub: "5-phase exposure management", path: "/governance/ctem", section: "Respond", Icon: Engineering },
  // Report
  { label: "VAPT Reports", sub: "PDF / DOCX export", path: "/vapt/reports", section: "Report", Icon: GppGood },
  { label: "Posture Trends", path: "/posture-trends", section: "Report", Icon: TrendingUp },
  // Automate
  { label: "AI Buddies", sub: "Orchestrator, Threat Intel, Compliance…", path: "/agents", section: "Automate", Icon: SmartToy },
  { label: "Knowledge Base", path: "/knowledge", section: "Automate", Icon: AutoStories },
  { label: "Security Docs", sub: "Upload policies, RAG Q&A", path: "/security-docs", section: "Automate", Icon: Description },
  { label: "Ask Your Data", sub: "Natural language → SQL", path: "/nl-query", section: "Automate", Icon: Psychology },
];

// ── Command palette component ────────────────────────────────────────────────

function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const theme = useTheme();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) { setQuery(""); setActiveIdx(0); setTimeout(() => inputRef.current?.focus(), 60); }
  }, [open]);

  const filtered = useMemo(() => {
    if (!query.trim()) return CMD_ITEMS;
    const q = query.toLowerCase();
    return CMD_ITEMS.filter(
      (c) => c.label.toLowerCase().includes(q) || (c.sub ?? "").toLowerCase().includes(q) || c.section.toLowerCase().includes(q)
    );
  }, [query]);

  // Group by section
  const grouped = useMemo(() => {
    const map = new Map<string, CmdItem[]>();
    const sections = query.trim() ? [] : ["Recent"];
    filtered.forEach((item) => {
      if (!map.has(item.section)) { map.set(item.section, []); }
      map.get(item.section)!.push(item);
    });
    return map;
  }, [filtered, query]);

  const flat = useMemo(() => filtered, [filtered]);

  const go = (item: CmdItem) => { onClose(); navigate(item.path); };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActiveIdx((i) => Math.min(i + 1, flat.length - 1)); }
    if (e.key === "ArrowUp")   { e.preventDefault(); setActiveIdx((i) => Math.max(i - 1, 0)); }
    if (e.key === "Enter" && flat[activeIdx]) go(flat[activeIdx]);
    if (e.key === "Escape") onClose();
  };

  let flatIdx = -1;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="sm"
      fullWidth
      PaperProps={{
        sx: {
          borderRadius: 3,
          overflow: "hidden",
          boxShadow: "0 24px 80px rgba(0,0,0,0.4)",
          border: `1px solid ${alpha(theme.palette.divider, 0.3)}`,
          mt: "8vh",
          verticalAlign: "top",
        },
      }}
      slotProps={{ backdrop: { sx: { backdropFilter: "blur(4px)", bgcolor: alpha("#000", 0.45) } } }}
    >
      <DialogContent sx={{ p: 0 }}>
        {/* Search input */}
        <TextField
          inputRef={inputRef}
          fullWidth
          placeholder="Search anything — features, pages, actions…"
          value={query}
          onChange={(e) => { setQuery(e.target.value); setActiveIdx(0); }}
          onKeyDown={handleKey}
          variant="outlined"
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <Search sx={{ color: "text.disabled", fontSize: 22 }} />
                </InputAdornment>
              ),
              sx: { fontSize: "1rem", px: 2, py: 1.5 },
            },
          }}
          sx={{
            "& .MuiOutlinedInput-root": {
              borderRadius: 0,
              borderBottom: `1px solid ${theme.palette.divider}`,
              "& fieldset": { border: "none" },
            },
          }}
        />

        {/* Results */}
        <Box sx={{ maxHeight: 420, overflow: "auto" }}>
          {grouped.size === 0 ? (
            <Typography color="text.disabled" textAlign="center" py={4} variant="body2">
              No results for "{query}"
            </Typography>
          ) : (
            Array.from(grouped.entries()).map(([section, items]) => (
              <Box key={section}>
                <Typography
                  variant="caption"
                  sx={{
                    display: "block", px: 2, py: 0.75,
                    color: "text.disabled", fontWeight: 700,
                    letterSpacing: "0.08em", fontSize: "0.68rem",
                    bgcolor: alpha(theme.palette.background.default, 0.5),
                    borderBottom: `1px solid ${alpha(theme.palette.divider, 0.3)}`,
                  }}
                >
                  {section.toUpperCase()}
                </Typography>
                <List dense disablePadding>
                  {items.map((item) => {
                    flatIdx++;
                    const idx = flatIdx;
                    const isActive = activeIdx === idx;
                    const phase = PHASES.find((p) => p.id === section.toLowerCase());
                    const accent = phase?.color ?? theme.palette.primary.main;
                    const { Icon } = item;
                    return (
                      <ListItemButton
                        key={`${section}-${item.label}`}
                        selected={isActive}
                        onClick={() => go(item)}
                        onMouseEnter={() => setActiveIdx(idx)}
                        sx={{
                          px: 2, py: 0.9,
                          "&.Mui-selected": {
                            bgcolor: alpha(accent, 0.1),
                            "& .cmd-label": { color: "text.primary" },
                          },
                          borderLeft: isActive ? `3px solid ${accent}` : "3px solid transparent",
                          transition: "all 0.1s",
                        }}
                      >
                        <ListItemIcon sx={{ minWidth: 36 }}>
                          <Icon sx={{ fontSize: 18, color: isActive ? accent : "text.disabled" }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Typography className="cmd-label" variant="body2" fontWeight={isActive ? 600 : 400} color="text.secondary">
                              {item.label}
                            </Typography>
                          }
                          secondary={item.sub && (
                            <Typography variant="caption" color="text.disabled">{item.sub}</Typography>
                          )}
                          sx={{ m: 0 }}
                        />
                        {isActive && (
                          <Typography variant="caption" color="text.disabled" sx={{ ml: 1, flexShrink: 0 }}>↵</Typography>
                        )}
                      </ListItemButton>
                    );
                  })}
                </List>
              </Box>
            ))
          )}
        </Box>

        {/* Footer */}
        <Box
          sx={{
            px: 2, py: 1,
            borderTop: `1px solid ${theme.palette.divider}`,
            display: "flex", gap: 2, alignItems: "center",
          }}
        >
          {[["↑↓", "navigate"], ["↵", "open"], ["esc", "close"]].map(([key, action]) => (
            <Stack key={key} direction="row" spacing={0.5} alignItems="center">
              <Chip
                label={key}
                size="small"
                sx={{ fontFamily: "monospace", fontSize: "0.65rem", height: 18, bgcolor: alpha(theme.palette.divider, 0.5) }}
              />
              <Typography variant="caption" color="text.disabled">{action}</Typography>
            </Stack>
          ))}
        </Box>
      </DialogContent>
    </Dialog>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function SampleHubCmd() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [hovered, setHovered] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);

  // Global Cmd+K / Ctrl+K shortcut
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return (
    <Box sx={{ p: { xs: 2, md: 4 }, maxWidth: 1440, mx: "auto", position: "relative" }}>
      {/* Header */}
      <Stack direction="row" alignItems="center" justifyContent="space-between" mb={0.5}>
        <Stack direction="row" alignItems="center" spacing={2}>
          <Typography variant="h4" fontWeight={700} letterSpacing="-0.5px">
            Security Operations Hub
          </Typography>
          <Chip label="Sample — Option 1+2" size="small" color="secondary" variant="outlined" />
        </Stack>

        {/* Cmd+K trigger button */}
        <Tooltip title="Press ⌘K anywhere">
          <Box
            onClick={() => setPaletteOpen(true)}
            sx={{
              display: "flex", alignItems: "center", gap: 1.5,
              px: 2, py: 0.9, borderRadius: 2,
              border: `1px solid ${theme.palette.divider}`,
              cursor: "pointer",
              bgcolor: alpha(theme.palette.background.paper, 0.6),
              transition: "all 0.15s",
              "&:hover": {
                bgcolor: theme.palette.action.hover,
                borderColor: theme.palette.primary.main,
              },
            }}
          >
            <Search sx={{ fontSize: 16, color: "text.disabled" }} />
            <Typography variant="body2" color="text.disabled">
              Search anything…
            </Typography>
            <Chip
              label="⌘K"
              size="small"
              sx={{
                fontFamily: "monospace", fontSize: "0.65rem", height: 20,
                bgcolor: alpha(theme.palette.divider, 0.5),
                ml: 1,
              }}
            />
          </Box>
        </Tooltip>
      </Stack>

      <Typography color="text.secondary" mb={4} variant="body2">
        8-phase workflow &nbsp;·&nbsp; Click any phase card or press ⌘K to jump anywhere instantly
      </Typography>

      {/* Phase grid — identical to SampleHub */}
      <Grid container spacing={2.5}>
        {PHASES.map((phase) => {
          const { Icon } = phase;
          const isHovered = hovered === phase.id;

          return (
            <Grid key={phase.id} item xs={12} sm={6} md={3}>
              <Card
                onMouseEnter={() => setHovered(phase.id)}
                onMouseLeave={() => setHovered(null)}
                onClick={() => navigate(phase.path)}
                sx={{
                  height: "100%",
                  cursor: "pointer",
                  transition: "all 0.18s ease",
                  borderTop: `3px solid ${phase.color}`,
                  boxShadow: isHovered
                    ? `0 8px 32px ${alpha(phase.color, 0.28)}, 0 2px 8px rgba(0,0,0,0.2)`
                    : theme.shadows[2],
                  transform: isHovered ? "translateY(-4px)" : "none",
                  position: "relative",
                  overflow: "hidden",
                  "&::before": {
                    content: '""',
                    position: "absolute", inset: 0,
                    background: isHovered
                      ? `linear-gradient(135deg, ${alpha(phase.color, 0.07)} 0%, transparent 55%)`
                      : "none",
                    pointerEvents: "none",
                    transition: "all 0.18s ease",
                  },
                }}
              >
                <CardContent sx={{ pb: "16px !important", height: "100%", display: "flex", flexDirection: "column" }}>
                  <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1.5}>
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <Box
                        sx={{
                          width: 34, height: 34, borderRadius: "9px",
                          bgcolor: alpha(phase.color, 0.14),
                          display: "flex", alignItems: "center", justifyContent: "center",
                        }}
                      >
                        <Icon sx={{ fontSize: 18, color: phase.color }} />
                      </Box>
                      <Typography
                        variant="caption"
                        sx={{ color: alpha(phase.color, 0.8), fontWeight: 700, letterSpacing: "0.08em" }}
                      >
                        PHASE {phase.num}
                      </Typography>
                    </Stack>
                    <ArrowForward
                      sx={{ fontSize: 15, color: phase.color, opacity: isHovered ? 1 : 0, transition: "opacity 0.15s" }}
                    />
                  </Stack>

                  <Typography variant="h6" fontWeight={700} lineHeight={1.2} mb={0.4}>
                    {phase.label}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" display="block" mb={1.5} lineHeight={1.4}>
                    {phase.tagline}
                  </Typography>

                  <Stack spacing={0.5} mb={2} flex={1}>
                    {phase.items.map((item) => (
                      <Typography
                        key={item}
                        variant="body2"
                        color="text.secondary"
                        sx={{ display: "flex", alignItems: "center", gap: 1, fontSize: "0.775rem" }}
                      >
                        <Box
                          component="span"
                          sx={{ width: 5, height: 5, borderRadius: "50%", bgcolor: phase.color, flexShrink: 0, opacity: 0.7 }}
                        />
                        {item}
                      </Typography>
                    ))}
                  </Stack>

                  {phase.metric && (
                    <Chip
                      label={phase.metric}
                      size="small"
                      sx={{
                        bgcolor: alpha(phase.color, 0.12), color: phase.color,
                        fontWeight: 600, fontSize: "0.7rem", height: 22,
                        alignSelf: "flex-start",
                      }}
                    />
                  )}
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>

      {/* Phase flow dots */}
      <Stack direction="row" alignItems="center" justifyContent="center" mt={4} spacing={0.5}>
        {PHASES.map((phase, idx) => (
          <React.Fragment key={phase.id}>
            <Box
              onClick={() => navigate(phase.path)}
              title={`Phase ${phase.num}: ${phase.label}`}
              sx={{
                width: 10, height: 10, borderRadius: "50%",
                bgcolor: phase.color, cursor: "pointer",
                transition: "transform 0.15s",
                "&:hover": { transform: "scale(1.5)" },
              }}
            />
            {idx < PHASES.length - 1 && <Box sx={{ width: 28, height: 1, bgcolor: "divider" }} />}
          </React.Fragment>
        ))}
      </Stack>
      <Typography variant="caption" color="text.disabled" textAlign="center" display="block" mt={1}>
        Phase 1 → 8 &nbsp;·&nbsp; Click any card, dot, or press <strong>⌘K</strong> to search
      </Typography>

      {/* Floating ⌘K FAB (visible on mobile) */}
      <Fab
        size="small"
        onClick={() => setPaletteOpen(true)}
        sx={{
          position: "fixed", bottom: 80, right: 24,
          bgcolor: theme.palette.background.paper,
          border: `1px solid ${theme.palette.divider}`,
          color: "text.secondary",
          boxShadow: theme.shadows[6],
          display: { xs: "flex", md: "none" },
          "&:hover": { bgcolor: theme.palette.action.hover },
        }}
      >
        <Keyboard sx={{ fontSize: 18 }} />
      </Fab>

      {/* Command palette */}
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </Box>
  );
}
