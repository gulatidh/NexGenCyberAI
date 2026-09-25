/**
 * Threat Model detail — four tabs:
 *
 *   Diagram      — Mermaid DFD rendered from threat_models.dfd_mermaid
 *   Components   — table of nodes (name, type, trust zone, criticality)
 *   Threats      — grouped by methodology category (STRIDE / PASTA / etc.)
 *   Mitigations  — proposed action per threat with framework control mapping
 *
 * Polls every 4s while the model is in pending/generating state.
 */
import React, { useState, useCallback, useRef } from "react";
import { useViewMode } from "../theme/ViewModeContext";
import { useParams, useSearchParams, useNavigate } from "react-router-dom";
import {
  Box, Typography, Card, CardContent, Chip, Button,
  CircularProgress, Alert, LinearProgress, Table, TableHead, TableRow, TableCell,
  TableBody, Divider, Tooltip, IconButton, Menu, MenuItem, Collapse,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField, Select,
  Tabs, Tab, Checkbox, FormControlLabel, InputBase,
} from "@mui/material";
import {
  ArrowBack, Hub, Replay, Print, PlaylistAddCheck, AddTask, Download, NoteAlt,
  KeyboardArrowUp, KeyboardArrowDown, AutoFixHigh, Add, DeleteOutlined, EditOutlined,
  Security, AccountTree, Verified, ExpandMore, ExpandLess,
  MenuBook, Group, VerifiedUser, Timeline, Article, UploadFile, ContentCopy,
} from "@mui/icons-material";
import { DetailNavItem } from "../components/layout/PageDetailLayout";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useMsal } from "@azure/msal-react";
import { loginRequest } from "../auth/msalConfig";
import { toast } from "react-toastify";
import { threatModelsApi } from "../services/api";
const API_BASE = import.meta.env.REACT_APP_API_URL || "http://localhost:8000/api/v1";

const EXPORT_SECTIONS = [
  { id: "cover",           label: "Cover & Summary" },
  { id: "exec_summary",    label: "Executive Summary" },
  { id: "architecture",    label: "Architecture (Components & Flows)" },
  { id: "boundaries",      label: "Trust Boundaries & Entry Points" },
  { id: "risk_matrix",     label: "Risk Heat Map" },
  { id: "coverage_matrix", label: "STRIDE Coverage Matrix" },
  { id: "maturity",        label: "Maturity Scores" },
  { id: "threats",         label: "Threats by Component" },
  { id: "mitigations",     label: "Mitigation Roadmap" },
  { id: "signoff",         label: "Sign-off Page" },
] as const;

import { fromNow } from "../utils/datetime";
import { AttackTree, AdversaryProfile, SigmaRule } from "../types";
import DfdReactFlow from "../components/DfdReactFlow";
import DfdDiagram from "../components/DfdDiagram";
import ThreatLibraryChip from "../components/ThreatLibraryChip";

const TM_NAV: DetailNavItem[] = [
  { id: "diagram",         label: "Diagram",          Icon: AccountTree,     color: "#4285F4" },
  { id: "components",      label: "Components",       Icon: Hub,             color: "#FF9800" },
  { id: "boundaries",      label: "Boundaries",       Icon: VerifiedUser,    color: "#00BCD4" },
  { id: "threats",         label: "Threats",          Icon: Security,        color: "#EA4335" },
  { id: "coverage",        label: "Coverage",         Icon: PlaylistAddCheck, color: "#34A853" },
  { id: "mitigations",     label: "Mitigations",      Icon: AddTask,         color: "#9C27B0" },
  { id: "attack_chains",   label: "Attack Chains",    Icon: AccountTree,     color: "#FF5722" },
  { id: "adversaries",     label: "Adversaries",      Icon: Group,           color: "#607D8B" },
  { id: "detection_rules", label: "Detection Rules",  Icon: VerifiedUser,    color: "#00BCD4" },
  { id: "maturity",        label: "Maturity",         Icon: Timeline,        color: "#757575" },
  { id: "help",            label: "Help",             Icon: MenuBook,        color: "#00BCD4" },
];

interface Component {
  id: string; name: string; type: string;
  platform?: string; trust_zone: string; criticality: string; notes?: string;
  environment?: string; datacenter?: string;
}
interface DataFlow { from: string; to: string; protocol: string; data: string; encrypted: boolean; notes?: string; }
interface EvidenceRef { kind: string; id: string; label?: string }
interface DetectionRuleRef { platform: string; rule_id: string }
interface Threat {
  id: string; category: string; asset_id: string; title: string; severity: string;
  evidence?: string; capec_refs?: string[]; attack_techniques?: string[]; rationale?: string;
  // Phase 8 additions
  evidence_refs?: EvidenceRef[];
  cwe_refs?: string[];
  attack_narrative?: string;
  blast_radius?: string[];
  owner_role?: string;
  is_grounded?: boolean;
  likelihood?: number;
  impact?: number;
  priority_score?: number;
  status?: string;
  decision_notes?: string;
  residual_severity?: string | null;
  residual_rationale?: string;
  linked_finding_ids?: string[];
  detection_status?: string;
  detection_rule_refs?: DetectionRuleRef[];
}
interface CoverageDecision {
  component_id: string;
  category: string;
  state: string;
  threat_id?: string | null;
  rationale?: string;
}
interface Mitigation {
  id: string; threat_id: string; action: string;
  control_id?: string; status: string; owner?: string;
}
interface ProgressStep {
  key: string; label: string;
  status: "pending" | "active" | "done" | "skipped" | "error";
  detail?: string;
}
interface GenerationProgress {
  current?: string; pct?: number; steps?: ProgressStep[];
}
interface ThreatModelDetailData {
  id: string; client_id: string; name?: string | null;
  scope_type: string; framework?: string | null; methodology: string; cloud_provider?: string | null;
  status: string; executive_summary?: string | null;
  component_count: number; threat_count: number; mitigation_count: number;
  components: Component[]; data_flows: DataFlow[]; threats: Threat[];
  mitigations: Mitigation[]; dfd_mermaid?: string | null;
  generated_at?: string | null; created_at?: string | null;
  ai_provider?: string | null; ai_model?: string | null;
  error_message?: string | null;
  converted_threat_ids?: string[];
  parent_threat_model_id?: string | null;
  progress?: GenerationProgress | null;
  analyst_notes?: string | null;
  // Phase 8
  trust_boundaries?: any[];
  entry_points?: any[];
  coverage_decisions?: CoverageDecision[];
  maturity_scores?: Record<string, number>;
  // Phase 9
  attack_trees_json?: AttackTree[];
  adversary_profiles_json?: AdversaryProfile[];
  sigma_rules_json?: SigmaRule[];
  auto_remodel?: boolean;
}

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853", info: "#4285F4",
};
const STATUS_COLOR: Record<string, string> = {
  open: "#FF7043", in_progress: "#FBBC04", accepted: "#4285F4",
  compensating_control: "#9C27B0", closed: "#34A853",
};
// Level 1 — Platform (where it lives)
const PLATFORMS = ["Azure", "AWS", "GCP", "Corporate", "Internet", "Third-Party"] as const;
type Platform = typeof PLATFORMS[number];

const PLATFORM_COLOR: Record<string, string> = {
  "Azure":       "#0078D4",
  "AWS":         "#FF9900",
  "GCP":         "#4285F4",
  "Corporate":   "#34A853",
  "Internet":    "#EA4335",
  "Third-Party": "#9C27B0",
};

function platformColor(p: string) { return PLATFORM_COLOR[p] ?? "#78909C"; }

function normPlatform(p: string): string {
  const l = (p || "").toLowerCase().trim();
  if (!l) return "Corporate";
  if (/^azure/.test(l)) return "Azure";
  if (/^aws/.test(l) || l.includes("amazon")) return "AWS";
  if (/^gcp/.test(l) || l.includes("google")) return "GCP";
  if (l === "internet" || l === "external") return "Internet";
  if (l === "third-party" || l === "third party" || l.includes("vendor")) return "Third-Party";
  return "Corporate";
}

// Level 2 — Security Tier (within the platform)
const ZONES = [
  "DMZ", "Web Tier", "API Tier", "Application Tier", "Report Server", "Data Tier", "Management Zone", "External",
] as const;
type Zone = typeof ZONES[number];

const ZONE_COLOR: Record<string, string> = {
  "DMZ":              "#F9AB00",
  "Web Tier":         "#FF7043",
  "API Tier":         "#0097A7",
  "Application Tier": "#1A73E8",
  "Report Server":    "#6D4C41",
  "Data Tier":        "#9C27B0",
  "Management Zone":  "#00897B",
  "External":         "#EA4335",
  // Legacy zone names
  "Internet":         "#EA4335",
  "Corporate Network":"#1A73E8",
  "Vendor Cloud":     "#FF7043",
  "Database Tier":    "#9C27B0",
  "public":           "#F9AB00",
  "private":          "#1A73E8",
  "data-tier":        "#9C27B0",
  "management":       "#00897B",
};

function zoneColor(z: string) { return ZONE_COLOR[z] ?? "#78909C"; }

// Normalize a stored trust_zone to a canonical tier name
function normZone(z: string): string {
  const l = (z || "").toLowerCase().trim();
  if (!l || l === "private" || l === "internal" || l === "corporate network") return "Application Tier";
  if (l === "internet" || l === "untrusted") return "External";
  if (l === "external") return "External";
  if (l === "public" || l === "dmz" || l === "perimeter") return "DMZ";
  if (l === "web tier" || l === "web") return "Web Tier";
  if (l === "api tier" || l === "api" || l === "api gateway" || l === "api layer") return "API Tier";
  if (l === "application tier" || l === "app tier") return "Application Tier";
  if (l === "report server" || l === "reporting" || l === "report tier" || l === "ssrs" || l === "bi server") return "Report Server";
  if (l === "data-tier" || l === "data tier" || l === "database tier" || l === "database") return "Data Tier";
  if (l === "management" || l === "management zone") return "Management Zone";
  if (l === "vendor" || l === "vendor cloud") return "Application Tier";
  return z;
}

function prettyCat(s: string): string {
  return (s || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

const TYPES = ["host", "application", "api", "database", "storage", "identity", "vm", "load_balancer", "firewall", "waf", "network", "user", "endpoint", "queue", "secret-store", "repo", "other"];
const ENVS = ["Prod", "Non-prod", "Dev", "SIT", "UAT", "DR"];
const CRITS = ["critical", "high", "medium", "low"];

const CRIT_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853",
};

function ComponentsEditor({ clientId, modelId, components, notes }: {
  clientId: string; modelId: string; components: Component[]; notes?: string | null;
}) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [rows, setRows] = useState<Component[]>(() =>
    components.map((c) => ({ ...c, platform: normPlatform(c.platform || ""), trust_zone: normZone(c.trust_zone) }))
  );
  const [noteText, setNoteText] = useState(notes || "");
  const [expandedNotes, setExpandedNotes] = useState<Set<string>>(new Set());
  // New-component form state
  const [nName, setNName] = useState("");
  const [nType, setNType] = useState("host");
  const [nPlatform, setNPlatform] = useState<Platform>("Corporate");
  const [nZone, setNZone] = useState<Zone>("Application Tier");
  const [nCrit, setNCrit] = useState("medium");
  const [nEnv, setNEnv] = useState("Prod");
  const [nDc, setNDc] = useState("");

  React.useEffect(() => {
    setRows(components.map((c) => ({ ...c, platform: normPlatform(c.platform || ""), trust_zone: normZone(c.trust_zone) })));
    setNoteText(notes || "");
  }, [components, notes]);

  const updateRow = (id: string, field: keyof Component, value: string) =>
    setRows((prev) => prev.map((r) => r.id === id ? { ...r, [field]: value } : r));

  const toggleNotes = (id: string) =>
    setExpandedNotes((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const csvFileRef = useRef<HTMLInputElement>(null);

  const CSV_HEADERS = ["name","type","platform","trust_zone","environment","datacenter","criticality","is_threat_actor","threat_actor_type","data_classification","bia_impact","notes"];

  const downloadTemplate = () => {
    const exampleRows = [
      ["Web Application","application","Azure","DMZ","Prod","Azure East US","high","false","","public","high","Internet-facing React frontend"],
      ["Auth Service API","api","Azure","Application Tier","Prod","Azure East US","critical","false","","internal","critical","OAuth2 token issuer"],
      ["SQL Database","database","Corporate","Data Tier","Prod","On-Premises DC1","critical","false","","confidential","critical","Primary customer data store"],
      ["External Attacker","user","Internet","External","","","medium","true","external_attacker","","",""],
    ];
    const lines = [CSV_HEADERS.join(","), ...exampleRows.map(r => r.map(v => `"${v}"`).join(","))].join("\n");
    const blob = new Blob([lines], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "threat-model-components-template.csv";
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const handleCsvUpload = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const text = (e.target?.result as string) || "";
        const lines = text.split(/\r?\n/).filter(Boolean);
        if (lines.length < 2) { toast.error("CSV must have a header row and at least one data row."); return; }
        const headers = lines[0].split(",").map(h => h.trim().replace(/^"|"$/g, "").toLowerCase());
        const nameIdx = headers.indexOf("name");
        if (nameIdx === -1) { toast.error("CSV missing required 'name' column."); return; }
        const get = (row: string[], col: string) => {
          const i = headers.indexOf(col);
          return i >= 0 && i < row.length ? row[i].trim().replace(/^"|"$/g, "") : "";
        };
        const newRows: Component[] = [];
        for (let li = 1; li < lines.length; li++) {
          const cols = lines[li].split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/);
          const name = get(cols, "name");
          if (!name) continue;
          const rawPlat = get(cols, "platform") || "Corporate";
          const rawZone = get(cols, "trust_zone") || "Application Tier";
          newRows.push({
            id: `csv${Date.now()}_${li}`,
            name,
            type: get(cols, "type") || "host",
            platform: normPlatform(rawPlat) as Platform,
            trust_zone: normZone(rawZone) as Zone,
            environment: get(cols, "environment") || "Prod",
            datacenter: get(cols, "datacenter"),
            criticality: get(cols, "criticality") || "medium",
            is_threat_actor: get(cols, "is_threat_actor").toLowerCase() === "true",
            threat_actor_type: get(cols, "threat_actor_type") || undefined,
            data_classification: get(cols, "data_classification") || undefined,
            bia_impact: get(cols, "bia_impact") || undefined,
            notes: get(cols, "notes"),
          } as any as Component);
        }
        if (newRows.length === 0) { toast.error("No valid rows found in CSV."); return; }
        setRows((prev) => {
          const existingIds = new Set(prev.map(r => r.name.toLowerCase()));
          const merged = [...prev, ...newRows.filter(r => !existingIds.has(r.name.toLowerCase()))];
          return merged;
        });
        toast.success(`Imported ${newRows.length} component${newRows.length === 1 ? "" : "s"} from CSV.`);
      } catch (err) {
        toast.error("Failed to parse CSV. Check the format matches the template.");
      }
    };
    reader.readAsText(file);
  };

  const addRow = () => {
    if (!nName.trim()) return;
    const newId = `c${Date.now()}`;
    setRows((prev) => [...prev, {
      id: newId, name: nName.trim(), type: nType,
      platform: nPlatform, trust_zone: nZone, criticality: nCrit,
      environment: nEnv, datacenter: nDc.trim(), notes: "",
    } as Component]);
    setNName("");
    setNDc("");
  };

  const remodel = useMutation({
    mutationFn: () => threatModelsApi.remodel(clientId, modelId, {
      components: rows.map((r) => ({
        id: r.id, name: r.name, type: r.type,
        platform: r.platform || "Corporate",
        trust_zone: r.trust_zone, criticality: r.criticality,
        environment: r.environment || "",
        datacenter: r.datacenter || "",
        notes: r.notes || "",
      })),
      analyst_notes: noteText.trim() || undefined,
    }),
    onSuccess: (created: any) => {
      toast.success("Re-modelling with your component set…");
      qc.invalidateQueries({ queryKey: ["threat-models"] });
      if (created?.id) navigate(`/threat-models/${created.id}?client=${clientId}`);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Re-model failed"),
  });

  const selectSx = {
    fontSize: 11, height: 26,
    "& .MuiSelect-select": { py: "3px !important", px: "8px !important" },
  };

  if (!open) {
    return (
      <Box className="no-print" sx={{ display: "flex", justifyContent: "flex-end", mb: 1.5 }}>
        <Button size="small" startIcon={<EditOutlined sx={{ fontSize: 16 }} />} onClick={() => setOpen(true)}
          sx={{ color: "text.secondary", textTransform: "none" }}>
          Edit components & re-model
        </Button>
      </Box>
    );
  }

  return (
    <Card className="no-print" sx={{ bgcolor: "background.paper", border: "1px solid rgba(66,133,244,0.3)", borderRadius: 2, mb: 2 }}>
      <CardContent>
        <Typography sx={{ color: "text.primary", fontWeight: 700, mb: 0.25 }}>Edit components</Typography>
        <Typography variant="caption" sx={{ color: "text.secondary", mb: 1.5, display: "block" }}>
          Set the correct trust zone and criticality for each component, add missing ones, remove irrelevant ones, then re-model.
          Your set is pinned — the AI keeps it verbatim and regenerates threats. Creates a new version (history preserved).
        </Typography>

        {/* Column headers */}
        <Box sx={{ display: "flex", gap: 1, px: 0.5, mb: 0.5 }}>
          <Typography variant="caption" sx={{ color: "text.disabled", flex: 1, fontSize: 10 }}>COMPONENT</Typography>
          <Typography variant="caption" sx={{ color: "text.disabled", width: 110, fontSize: 10 }}>TYPE</Typography>
          <Typography variant="caption" sx={{ color: "text.disabled", width: 120, fontSize: 10 }}>PLATFORM</Typography>
          <Typography variant="caption" sx={{ color: "text.disabled", width: 138, fontSize: 10 }}>SECURITY TIER</Typography>
          <Typography variant="caption" sx={{ color: "text.disabled", width: 90, fontSize: 10 }}>CRITICALITY</Typography>
          <Typography variant="caption" sx={{ color: "text.disabled", width: 80, fontSize: 10 }}>ENV</Typography>
          <Typography variant="caption" sx={{ color: "text.disabled", width: 120, fontSize: 10 }}>DATACENTER</Typography>
          <Box sx={{ width: 48 }} />
        </Box>

        <Box sx={{ maxHeight: 340, overflow: "auto", mb: 1.5, border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
          {rows.map((r) => (
            <Box key={r.id}>
              <Box sx={{
                display: "flex", alignItems: "center", gap: 1, px: 1, py: 0.75,
                borderBottom: "1px solid", borderColor: "divider",
                "&:last-child": { borderBottom: "none" },
                "&:hover": { bgcolor: "action.hover" },
              }}>
                {/* Name — inline editable */}
                <InputBase
                  value={r.name}
                  onChange={(e) => updateRow(r.id, "name", e.target.value)}
                  sx={{
                    flex: 1, minWidth: 0, fontSize: 12, fontWeight: 500,
                    "& input": { p: 0, color: "text.primary" },
                    "&:hover": { bgcolor: "action.hover", borderRadius: 0.5 },
                    "&.Mui-focused": { outline: "1px solid", outlineColor: "primary.main", borderRadius: 0.5, px: 0.5 },
                  }}
                />

                {/* Type */}
                <Select size="small" value={r.type || "other"} sx={{ ...selectSx, width: 110 }}
                  onChange={(e) => updateRow(r.id, "type", e.target.value)}>
                  {TYPES.map((t) => <MenuItem key={t} value={t} sx={{ fontSize: 11 }}>{t}</MenuItem>)}
                </Select>

                {/* Platform */}
                <Select size="small" value={normPlatform(r.platform || "")} sx={{ ...selectSx, width: 120 }}
                  onChange={(e) => updateRow(r.id, "platform", e.target.value)}
                  renderValue={(v) => (
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                      <Box sx={{ width: 8, height: 8, borderRadius: "2px", bgcolor: platformColor(v), flexShrink: 0 }} />
                      <Typography sx={{ fontSize: 11, color: platformColor(v), fontWeight: 700, lineHeight: 1 }}>{v}</Typography>
                    </Box>
                  )}>
                  {PLATFORMS.map((p) => (
                    <MenuItem key={p} value={p} sx={{ fontSize: 11 }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Box sx={{ width: 10, height: 10, borderRadius: "2px", bgcolor: platformColor(p), flexShrink: 0 }} />
                        {p}
                      </Box>
                    </MenuItem>
                  ))}
                </Select>

                {/* Security Tier */}
                <Select size="small" value={normZone(r.trust_zone)} sx={{ ...selectSx, width: 138 }}
                  onChange={(e) => updateRow(r.id, "trust_zone", e.target.value)}
                  renderValue={(v) => (
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                      <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: zoneColor(v), flexShrink: 0 }} />
                      <Typography sx={{ fontSize: 11, color: zoneColor(v), fontWeight: 600, lineHeight: 1 }}>{v}</Typography>
                    </Box>
                  )}>
                  {ZONES.map((z) => (
                    <MenuItem key={z} value={z} sx={{ fontSize: 11 }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Box sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: zoneColor(z), flexShrink: 0 }} />
                        {z}
                      </Box>
                    </MenuItem>
                  ))}
                </Select>

                {/* Criticality */}
                <Select size="small" value={r.criticality || "medium"} sx={{ ...selectSx, width: 90 }}
                  onChange={(e) => updateRow(r.id, "criticality", e.target.value)}
                  renderValue={(v) => (
                    <Typography sx={{ fontSize: 11, color: CRIT_COLOR[v] ?? "text.secondary", fontWeight: 600 }}>{v}</Typography>
                  )}>
                  {CRITS.map((c) => (
                    <MenuItem key={c} value={c} sx={{ fontSize: 11, color: CRIT_COLOR[c] }}>{c}</MenuItem>
                  ))}
                </Select>

                {/* Environment */}
                <Select size="small" value={r.environment || "Prod"} sx={{ ...selectSx, width: 80 }}
                  onChange={(e) => updateRow(r.id, "environment", e.target.value)}>
                  {ENVS.map((env) => <MenuItem key={env} value={env} sx={{ fontSize: 11 }}>{env}</MenuItem>)}
                </Select>

                {/* Datacenter */}
                <TextField size="small" placeholder="DC / Region"
                  value={r.datacenter || ""}
                  onChange={(e) => updateRow(r.id, "datacenter", e.target.value)}
                  sx={{ width: 120, "& .MuiInputBase-root": { fontSize: 11, height: 26 }, "& .MuiInputBase-input": { py: "3px", px: "8px" } }}
                />

                {/* Notes toggle */}
                <Tooltip title={expandedNotes.has(r.id) ? "Hide notes" : "Edit notes"}>
                  <IconButton size="small" onClick={() => toggleNotes(r.id)}
                    sx={{ color: r.notes ? "#4285F4" : "text.disabled", flexShrink: 0 }}>
                    <NoteAlt sx={{ fontSize: 15 }} />
                  </IconButton>
                </Tooltip>

                {/* Delete */}
                <IconButton size="small" onClick={() => setRows((prev) => prev.filter((x) => x.id !== r.id))}
                  sx={{ color: "text.secondary", flexShrink: 0, "&:hover": { color: "#EA4335" } }}>
                  <DeleteOutlined sx={{ fontSize: 15 }} />
                </IconButton>
              </Box>

              {/* Inline notes field */}
              {expandedNotes.has(r.id) && (
                <Box sx={{ px: 1, pb: 1, bgcolor: "action.hover" }}>
                  <TextField
                    fullWidth size="small" multiline minRows={1} maxRows={3}
                    placeholder="Notes / context for this component…"
                    value={r.notes || ""}
                    onChange={(e) => updateRow(r.id, "notes", e.target.value)}
                    sx={{ "& .MuiInputBase-root": { fontSize: 12 } }}
                  />
                </Box>
              )}
            </Box>
          ))}
          {rows.length === 0 && (
            <Typography variant="caption" sx={{ color: "text.secondary", display: "block", p: 2, textAlign: "center" }}>
              No components — add one below.
            </Typography>
          )}
        </Box>

        {/* Add new component */}
        <Box sx={{
          display: "flex", gap: 1, flexWrap: "wrap", alignItems: "center",
          mb: 1.5, p: 1, bgcolor: "action.hover", borderRadius: 1,
        }}>
          <Typography variant="caption" sx={{ color: "text.secondary", mr: 0.5 }}>Add:</Typography>
          <TextField size="small" placeholder="Component name" value={nName}
            onChange={(e) => setNName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addRow()}
            sx={{ minWidth: 180, flex: 1, "& .MuiInputBase-root": { fontSize: 12, height: 30 } }} />
          <Select size="small" value={nType} onChange={(e) => setNType(e.target.value)} sx={{ ...selectSx, width: 110 }}>
            {TYPES.map((t) => <MenuItem key={t} value={t} sx={{ fontSize: 11 }}>{t}</MenuItem>)}
          </Select>
          <Select size="small" value={nPlatform} onChange={(e) => setNPlatform(e.target.value as Platform)} sx={{ ...selectSx, width: 120 }}>
            {PLATFORMS.map((p) => (
              <MenuItem key={p} value={p} sx={{ fontSize: 11 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ width: 8, height: 8, borderRadius: "2px", bgcolor: platformColor(p) }} />
                  {p}
                </Box>
              </MenuItem>
            ))}
          </Select>
          <Select size="small" value={nZone} onChange={(e) => setNZone(e.target.value as Zone)} sx={{ ...selectSx, width: 138 }}>
            {ZONES.map((z) => (
              <MenuItem key={z} value={z} sx={{ fontSize: 11 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: zoneColor(z) }} />
                  {z}
                </Box>
              </MenuItem>
            ))}
          </Select>
          <Select size="small" value={nCrit} onChange={(e) => setNCrit(e.target.value)} sx={{ ...selectSx, width: 90 }}>
            {CRITS.map((c) => <MenuItem key={c} value={c} sx={{ fontSize: 11 }}>{c}</MenuItem>)}
          </Select>
          <Select size="small" value={nEnv} onChange={(e) => setNEnv(e.target.value)} sx={{ ...selectSx, width: 80 }}>
            {ENVS.map((env) => <MenuItem key={env} value={env} sx={{ fontSize: 11 }}>{env}</MenuItem>)}
          </Select>
          <TextField size="small" placeholder="DC / Region" value={nDc}
            onChange={(e) => setNDc(e.target.value)}
            sx={{ width: 120, "& .MuiInputBase-root": { fontSize: 12, height: 30 } }} />
          <Button size="small" startIcon={<Add sx={{ fontSize: 14 }} />} onClick={addRow}
            disabled={!nName.trim()}
            sx={{ textTransform: "none", height: 28, fontSize: 12, flexShrink: 0 }}>
            Add
          </Button>
        </Box>

        {/* CSV template download + upload */}
        <input
          ref={csvFileRef}
          type="file"
          accept=".csv"
          style={{ display: "none" }}
          onChange={(e) => { const f = e.target.files?.[0]; if (f) handleCsvUpload(f); e.target.value = ""; }}
        />
        <Box sx={{ display: "flex", gap: 1, mb: 1.5, alignItems: "center" }}>
          <Typography variant="caption" sx={{ color: "text.secondary", mr: 0.5 }}>Bulk add via CSV:</Typography>
          <Button size="small" startIcon={<Download sx={{ fontSize: 14 }} />}
            onClick={downloadTemplate}
            sx={{ textTransform: "none", height: 28, fontSize: 12, color: "text.secondary", borderColor: "divider", border: "1px solid" }}>
            Download template
          </Button>
          <Button size="small" startIcon={<UploadFile sx={{ fontSize: 14 }} />}
            onClick={() => csvFileRef.current?.click()}
            sx={{ textTransform: "none", height: 28, fontSize: 12, color: "primary.main", borderColor: "primary.main", border: "1px solid" }}>
            Upload CSV
          </Button>
          <Typography variant="caption" sx={{ color: "text.secondary", fontStyle: "italic" }}>
            Fill the template, save as CSV, upload — components merge into the list below.
          </Typography>
        </Box>

        <TextField fullWidth multiline minRows={2} size="small" label="Analyst notes / guidance for the AI"
          value={noteText} onChange={(e) => setNoteText(e.target.value)} sx={{ mb: 1.5 }} />

        <Box sx={{ display: "flex", gap: 1, justifyContent: "flex-end" }}>
          <Button size="small" onClick={() => setOpen(false)} sx={{ color: "text.secondary", textTransform: "none" }}>Cancel</Button>
          <Button size="small" variant="contained" disabled={remodel.isPending || rows.length === 0}
            startIcon={remodel.isPending ? <CircularProgress size={14} sx={{ color: "#fff" }} /> : <Replay sx={{ fontSize: 16 }} />}
            onClick={() => remodel.mutate()}
            sx={{ textTransform: "none" }}>
            {remodel.isPending ? "Re-modelling…" : "Re-model with these"}
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
}

export default function ThreatModelDetail() {
  const { canAct } = useViewMode();
  const { modelId } = useParams<{ modelId: string }>();
  const [search] = useSearchParams();
  const clientId = search.get("client") || "";
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { instance, accounts } = useMsal();

  const _getToken = useCallback(async () => {
    const account = accounts[0];
    if (!account) return "";
    try {
      const resp = await instance.acquireTokenSilent({ ...loginRequest, account });
      return resp.idToken || resp.accessToken;
    } catch { return ""; }
  }, [accounts, instance]);

  const downloadThreatModel = useCallback(async (format: "pdf" | "docx", sections?: string[]) => {
    try {
      const token = await _getToken();
      const path = format === "pdf"
        ? threatModelsApi.pdfUrl(clientId, modelId!, sections)
        : threatModelsApi.docxUrl(clientId, modelId!, sections);
      const url = API_BASE + path;
      const res = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!res.ok) throw new Error(`Export failed: ${res.status}`);
      const blob = await res.blob();
      const blobUrl = URL.createObjectURL(blob);
      if (format === "pdf") {
        const w = window.open(blobUrl, "_blank");
        if (!w) window.print();
        setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);
      } else {
        const a = document.createElement("a");
        a.href = blobUrl;
        a.download = `threat-model-${(modelId || "").slice(0, 8)}.docx`;
        a.click();
        URL.revokeObjectURL(blobUrl);
      }
    } catch (err: any) {
      toast.error("Export failed — check the console for details");
      console.error("Threat model export error:", err);
    }
  }, [clientId, modelId, _getToken]);

  const downloadDrawio = useCallback(async () => {
    try {
      const token = await _getToken();
      const url = API_BASE + threatModelsApi.drawioDownloadUrl(clientId, modelId!);
      const res = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!res.ok) throw new Error(`Download failed: ${res.status}`);
      const blob = await res.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl;
      a.download = `threat-model-${(modelId || "").slice(0, 8)}.drawio`;
      a.click();
      URL.revokeObjectURL(blobUrl);
    } catch (err: any) {
      toast.error("Draw.io download failed");
      console.error("Draw.io download error:", err);
    }
  }, [clientId, modelId, _getToken]);

  const downloadHtml = useCallback(async () => {
    try {
      const token = await _getToken();
      const url = API_BASE + threatModelsApi.htmlUrl(clientId, modelId!);
      const res = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!res.ok) throw new Error(`HTML export failed: ${res.status}`);
      const blob = await res.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl;
      a.download = `threat-model-${(modelId || "").slice(0, 8)}.html`;
      a.click();
      URL.revokeObjectURL(blobUrl);
    } catch (err: any) {
      toast.error("HTML export failed");
      console.error("HTML export error:", err);
    }
  }, [clientId, modelId, _getToken]);

  const [tab, setTab] = useState<string>("diagram");
  const [diagramMode, setDiagramMode] = useState<"interactive" | "mermaid">("interactive");
  const [diagramView, setDiagramView] = useState<"architecture" | "threat_heat" | "detection_coverage">("architecture");
  const [printing, setPrinting] = useState<boolean>(false);
  const [exportOpen, setExportOpen] = useState<boolean>(false);
  const [exportSections, setExportSections] = useState<Set<string>>(
    new Set(EXPORT_SECTIONS.map((s) => s.id))
  );
  React.useEffect(() => {
    const onBefore = () => setPrinting(true);
    const onAfter = () => setPrinting(false);
    window.addEventListener("beforeprint", onBefore);
    window.addEventListener("afterprint", onAfter);
    return () => {
      window.removeEventListener("beforeprint", onBefore);
      window.removeEventListener("afterprint", onAfter);
    };
  }, []);

  const { data, isLoading, error } = useQuery<ThreatModelDetailData>({
    queryKey: ["threat-model-detail", modelId],
    queryFn: () => threatModelsApi.get(clientId, modelId!),
    enabled: !!modelId && !!clientId,
    refetchInterval: (q) => {
      const dd = q.state.data as ThreatModelDetailData | undefined;
      return dd && (dd.status === "pending" || dd.status === "generating") ? 4000 : false;
    },
  });

  const styledDfdQuery = useQuery<{ view: string; mermaid: string }>({
    queryKey: ["threat-model-dfd", modelId, diagramView],
    queryFn: () => threatModelsApi.styledDfd(clientId, modelId!, diagramView),
    enabled: !!modelId && !!clientId && diagramMode === "mermaid"
             && diagramView !== "architecture" && data?.status === "completed",
    staleTime: 30_000,
  });

  const rescanMutation = useMutation({
    mutationFn: () => threatModelsApi.rescan(clientId, modelId!),
    onSuccess: (created: any) => {
      qc.invalidateQueries({ queryKey: ["threat-models", clientId] });
      toast.success("Re-modelling started");
      // Stay on this page; the user can navigate to the new version manually
      // (Phase 2 will surface a version history dropdown like Assessments).
      navigate(`/threat-models/${created.id}?client=${clientId}`);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to re-model"),
  });

  const cloneMutation = useMutation({
    mutationFn: () => threatModelsApi.clone(clientId, modelId!),
    onSuccess: (cloned: any) => {
      qc.invalidateQueries({ queryKey: ["threat-models", clientId] });
      toast.success("Threat model cloned");
      navigate(`/threat-models/${cloned.id}?client=${clientId}`);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to clone"),
  });

  const patchModelMutation = useMutation({
    mutationFn: (body: { name?: string; components_json?: any[]; data_flows_json?: any[] }) =>
      threatModelsApi.patchModel(clientId, modelId!, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["threat-model-detail", modelId] });
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Update failed"),
  });

  const convertOne = useMutation({
    mutationFn: (threatId: string) => threatModelsApi.convertThreat(clientId, modelId!, threatId),
    onSuccess: (resp: any) => {
      qc.invalidateQueries({ queryKey: ["threat-model-detail", modelId] });
      qc.invalidateQueries({ queryKey: ["risks", clientId] });
      toast.success(resp?.created ? "Risk created" : "Risk already exists for this threat");
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to convert"),
  });

  const patchThreatMutation = useMutation({
    mutationFn: ({ threatId, body }: { threatId: string; body: any }) =>
      threatModelsApi.patchThreat(clientId, modelId!, threatId, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["threat-model-detail", modelId] });
      toast.success("Threat updated");
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Update failed"),
  });

  const fillGapsMutation = useMutation({
    mutationFn: (cells?: { component_id: string; category: string }[]) =>
      threatModelsApi.fillGaps(clientId, modelId!, cells),
    onSuccess: (resp: any) => {
      qc.invalidateQueries({ queryKey: ["threat-model-detail", modelId] });
      toast.success(resp?.message || `Filled ${resp?.filled ?? 0} cells`);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Gap-fill failed"),
  });

  // Threat popup opened from a coverage-matrix 'threat' cell.
  const [threatPopup, setThreatPopup] = useState<Threat | null>(null);

  const startModelingMutation = useMutation({
    mutationFn: () => threatModelsApi.startModeling(clientId, modelId!, {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["threat-model-detail", modelId] });
      qc.invalidateQueries({ queryKey: ["threat-models", clientId] });
      toast.success("AI threat modelling started");
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Failed to start modelling"),
  });

  const convertAll = useMutation({
    mutationFn: () => threatModelsApi.convertAll(clientId, modelId!),
    onSuccess: (resp: any) => {
      qc.invalidateQueries({ queryKey: ["threat-model-detail", modelId] });
      qc.invalidateQueries({ queryKey: ["risks", clientId] });
      const created = resp?.created ?? 0;
      const skipped = resp?.skipped ?? 0;
      if (created === 0 && skipped > 0) {
        toast.info(`Every threat is already in the Risk Register (${skipped} skipped)`);
      } else if (created > 0 && skipped > 0) {
        toast.success(`Added ${created} new risk${created === 1 ? "" : "s"} · skipped ${skipped} duplicate${skipped === 1 ? "" : "s"}`);
      } else {
        toast.success(`Added ${created} risk${created === 1 ? "" : "s"} to the register`);
      }
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Bulk convert failed"),
  });

  if (isLoading) {
    return <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>;
  }
  if (error || !data) {
    return <Alert severity="error" sx={{ mt: 2 }}>Threat model not found or you don't have access.</Alert>;
  }

  const inFlight = data.status === "pending" || data.status === "generating";

  // Group threats by category for the Threats tab.
  const threatsByCat: Record<string, Threat[]> = {};
  for (const t of data.threats) {
    (threatsByCat[t.category] = threatsByCat[t.category] || []).push(t);
  }
  // Map threat_id → asset name for friendlier display.
  const compName = new Map(data.components.map((c) => [c.id, c.name]));
  // Map threat_id → mitigations.
  const mitigationsByThreat: Record<string, Mitigation[]> = {};
  for (const m of data.mitigations) {
    (mitigationsByThreat[m.threat_id] = mitigationsByThreat[m.threat_id] || []).push(m);
  }
  // IDs of threats already converted into Risk Register entries — disables
  // per-row Convert buttons and powers the bulk action's count badge.
  const convertedSet = new Set<string>(data.converted_threat_ids || []);
  const newCount = data.threats.filter((t) => !convertedSet.has(t.id)).length;

  return (
    <Box className="tm-print-area">
      <style>{`
        @media print {
          @page { size: A4 landscape; margin: 10mm; }
          body { background: #fff !important; }
          .MuiDrawer-root, .MuiAppBar-root, .no-print { display: none !important; }

          /* Print brand/severity colours instead of letting the browser drop backgrounds */
          .tm-print-area, .tm-print-area * {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
          }
          .tm-print-area { color: #1a1a1a !important; }

          /* Paper-white surfaces (the portal canvas is dark) */
          .tm-print-area .MuiCard-root, .tm-print-area .MuiCardContent-root,
          .tm-print-area .MuiPaper-root, .tm-print-area .MuiTableContainer-root {
            background: #fff !important;
            box-shadow: none !important;
            border-color: #e0e0e0 !important;
          }
          .tm-print-area .MuiTableCell-root { border-color: #e0e0e0 !important; }

          /* Legible dark body text — chips (criticality/status), charts and
             .keep-color brand values keep their portal colours. */
          .tm-print-area .MuiTypography-root:not(.keep-color),
          .tm-print-area .MuiTableCell-root:not(.keep-color) {
            color: #1a1a1a !important;
          }

          /* Mermaid SVG ships with inline fills — keep its own palette. */
          .tm-print-area svg, .tm-print-area svg * {
            background: transparent !important;
          }
          .tm-print-area .MuiCard-root { page-break-inside: avoid; }
          .tm-print-area .tm-print-section { page-break-before: always; }
          .tm-print-area .tm-print-section:first-of-type { page-break-before: auto; }
          .tm-print-area .tm-print-section-heading {
            font-size: 16px !important;
            font-weight: 700 !important;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            margin: 0 0 8px 0;
            border-bottom: 2px solid #1a73e8;
            padding-bottom: 4px;
          }
        }
      `}</style>

      <Box className="no-print" sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
        <Button startIcon={<ArrowBack />} size="small"
          onClick={() => navigate("/threat-models")}
          sx={{ color: "text.secondary" }}>
          Threat Models
        </Button>
        <Box sx={{ flex: 1 }} />
        <Tooltip title={!canAct ? "Read-only in Executive mode" : inFlight ? "Re-model disabled while generating" : "Re-model — keeps history"}>
          <span>
            <Button startIcon={<Replay />} size="small" disabled={inFlight || rescanMutation.isPending || !canAct}
              onClick={() => rescanMutation.mutate()}
              sx={{ color: "text.secondary" }}>
              Re-model
            </Button>
          </span>
        </Tooltip>
        <Button
          startIcon={<Download />}
          size="small"
          onClick={() => setExportOpen(true)}
          sx={{ color: "text.secondary" }}
        >
          Export Report
        </Button>
        <Tooltip title="Create a copy of this threat model">
          <span>
            <Button
              size="small"
              startIcon={cloneMutation.isPending ? <CircularProgress size={14} /> : <ContentCopy sx={{ fontSize: 16 }} />}
              onClick={() => cloneMutation.mutate()}
              disabled={cloneMutation.isPending}
              sx={{ color: "text.secondary" }}
            >
              Clone
            </Button>
          </span>
        </Tooltip>
      </Box>

      {/* ── Export Report Dialog ──────────────────────────────────────── */}
      <Dialog open={exportOpen} onClose={() => setExportOpen(false)} maxWidth="xs" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper" } } }}>
        <DialogTitle sx={{ color: "text.primary", fontSize: 16, fontWeight: 700 }}>
          Export Threat Model Report
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 1.5, color: "text.secondary" }}>
            Select sections to include:
          </Typography>
          {EXPORT_SECTIONS.map((s) => (
            <FormControlLabel
              key={s.id}
              control={
                <Checkbox
                  checked={exportSections.has(s.id)}
                  size="small"
                  onChange={(e) => {
                    setExportSections((prev) => {
                      const n = new Set(prev);
                      e.target.checked ? n.add(s.id) : n.delete(s.id);
                      return n;
                    });
                  }}
                  sx={{ color: "text.secondary", "&.Mui-checked": { color: "#4285F4" } }}
                />
              }
              label={<Typography variant="body2" sx={{ color: "text.primary" }}>{s.label}</Typography>}
              sx={{ display: "flex", mb: 0 }}
            />
          ))}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, gap: 1, flexWrap: "wrap" }}>
          <Button onClick={() => setExportOpen(false)} sx={{ color: "text.secondary" }}>Cancel</Button>
          <Button
            startIcon={<Download />}
            onClick={() => { setExportOpen(false); downloadHtml(); }}
            variant="outlined"
            sx={{ color: "#34A853", borderColor: "rgba(52,168,83,0.5)" }}
          >
            HTML
          </Button>
          <Button
            startIcon={<Print />}
            onClick={() => { setExportOpen(false); downloadThreatModel("pdf", Array.from(exportSections)); }}
            sx={{ color: "#4285F4", borderColor: "rgba(66,133,244,0.5)" }}
            variant="outlined"
          >
            Preview &amp; Print
          </Button>
          <Button
            startIcon={<Article />}
            variant="contained"
            onClick={() => { setExportOpen(false); downloadThreatModel("docx", Array.from(exportSections)); }}
            sx={{ bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" } }}
          >
            Word
          </Button>
        </DialogActions>
      </Dialog>

      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, mb: 2 }}>
        <Hub sx={{ color: "#4285F4", fontSize: 36, mt: 0.25 }} />
        <Box sx={{ flex: 1 }}>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>
            {data.name || `Threat Model · ${data.methodology.toUpperCase()}`}
          </Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 0.5 }}>
            <Chip label={data.methodology.toUpperCase()} size="small"
              sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", fontWeight: 700, fontSize: 10, height: 20, letterSpacing: 0.5 }} />
            <Chip label={data.status} size="small"
              sx={{
                bgcolor: `${(STATUS_COLOR[data.status] || "#4285F4")}20`,
                color: STATUS_COLOR[data.status] || "#4285F4",
                fontWeight: 700, fontSize: 10, height: 20, textTransform: "uppercase", letterSpacing: 0.5,
              }} />
            {data.framework && <Chip label={data.framework} size="small"
              sx={{ bgcolor: "rgba(124,77,255,0.15)", color: "#9C27B0", fontSize: 10, height: 20 }} />}
            <Typography variant="caption" sx={{ color: "text.secondary", alignSelf: "center", ml: 1 }}>
              {data.generated_at ? `Generated ${fromNow(data.generated_at)}` : data.created_at ? `Created ${fromNow(data.created_at)}` : ""}
              {data.ai_provider ? ` · ${data.ai_provider}${data.ai_model ? ` (${data.ai_model})` : ""}` : ""}
            </Typography>
          </Box>
        </Box>
      </Box>

      {inFlight && (
        <Card className="no-print" sx={{ mb: 2, bgcolor: "background.paper", border: "1px solid rgba(66,133,244,0.3)" }}>
          <CardContent>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
              <CircularProgress size={18} sx={{ color: "#4285F4" }} />
              <Typography variant="subtitle2" sx={{ color: "text.primary", fontWeight: 600 }}>
                {data.progress?.current || "Building threat model…"}
              </Typography>
              {typeof data.progress?.pct === "number" && (
                <Typography variant="caption" sx={{ color: "text.secondary", ml: "auto" }}>
                  {data.progress.pct}%
                </Typography>
              )}
            </Box>
            <LinearProgress
              variant={typeof data.progress?.pct === "number" ? "determinate" : "indeterminate"}
              value={data.progress?.pct ?? 0}
              sx={{ mb: 1.5, bgcolor: "rgba(66,133,244,0.1)", "& .MuiLinearProgress-bar": { bgcolor: "#4285F4" } }}
            />
            {(data.progress?.steps && data.progress.steps.length > 0) ? (
              <Box>
                {data.progress.steps.map((s) => {
                  const icon =
                    s.status === "done" ? "✓" :
                    s.status === "error" ? "✕" :
                    s.status === "skipped" ? "–" :
                    s.status === "active" ? "" : "○";
                  const color =
                    s.status === "done" ? "#34A853" :
                    s.status === "error" ? "#EA4335" :
                    s.status === "active" ? "#4285F4" :
                    "rgba(255,255,255,0.35)";
                  return (
                    <Box key={s.key} sx={{ display: "flex", alignItems: "center", gap: 1, py: 0.5 }}>
                      <Box sx={{ width: 18, textAlign: "center", color, fontWeight: 700, flexShrink: 0 }}>
                        {s.status === "active"
                          ? <CircularProgress size={12} sx={{ color: "#4285F4" }} />
                          : icon}
                      </Box>
                      <Typography variant="body2" sx={{
                        color: s.status === "pending" ? "rgba(255,255,255,0.4)" : "#fff",
                        fontWeight: s.status === "active" ? 600 : 400,
                      }}>
                        {s.label}
                      </Typography>
                      {s.detail && (
                        <Typography variant="caption" sx={{ color: "text.secondary", ml: 0.5 }}>
                          — {s.detail}
                        </Typography>
                      )}
                    </Box>
                  );
                })}
              </Box>
            ) : (
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                AI is producing the model — polling every 4 seconds.
              </Typography>
            )}
          </CardContent>
        </Card>
      )}
      {data.error_message && (
        <Alert severity="error" sx={{ mb: 2 }}>{data.error_message}</Alert>
      )}

      {data.status === "extracted_review" && (
        <Card className="no-print" sx={{
          bgcolor: "rgba(156,39,176,0.08)",
          border: "1px solid rgba(156,39,176,0.4)",
          borderRadius: 2, mb: 2,
        }}>
          <CardContent sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
            <Box sx={{ flex: 1, minWidth: 240 }}>
              <Typography sx={{ color: "#CE93D8", fontWeight: 700, fontSize: 13, mb: 0.5 }}>
                Diagram extracted · review before AI threat modelling
              </Typography>
              <Typography variant="body2" sx={{ color: "text.secondary", lineHeight: 1.5 }}>
                We pulled {data.component_count} component{data.component_count === 1 ? "" : "s"} and {data.data_flows.length} data flow{data.data_flows.length === 1 ? "" : "s"} from your uploaded file.
                Check the <strong>Diagram</strong> and <strong>Components</strong> tabs below — when it looks right, click <em>Start AI threat modelling</em>.
                Anything wrong? Delete this model and re-upload a cleaner diagram.
              </Typography>
            </Box>
            <Button
              variant="contained"
              disabled={startModelingMutation.isPending}
              onClick={() => startModelingMutation.mutate()}
              sx={{ bgcolor: "#9C27B0", "&:hover": { bgcolor: "#7B1FA2" } }}
            >
              {startModelingMutation.isPending ? <CircularProgress size={18} sx={{ color: "text.primary" }} /> : "Start AI threat modelling"}
            </Button>
          </CardContent>
        </Card>
      )}

      {data.executive_summary && (
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
          <CardContent>
            <Typography variant="caption" sx={{ color: "#4285F4", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", mb: 1 }}>
              Executive summary
            </Typography>
            <Typography variant="body2" sx={{ color: "text.secondary", lineHeight: 1.6 }}>
              {data.executive_summary}
            </Typography>
          </CardContent>
        </Card>
      )}

      {/* Horizontal tab bar — replaces PageDetailLayout left sidebar */}
      {!printing && (
        <Box sx={{ borderBottom: "1px solid", borderColor: "divider", mb: 2 }}>
          <Tabs
            value={tab}
            onChange={(_, v: string) => { if (v === "help") navigate("/help"); else setTab(v); }}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ minHeight: 40, "& .MuiTab-root": { minHeight: 40, fontSize: 12, py: 0, px: 1.5, textTransform: "none" } }}
          >
            {TM_NAV.map(item => {
              let label = item.label;
              if (data) {
                if (item.id === "components")      label = `Components (${data.component_count ?? 0})`;
                if (item.id === "boundaries")      label = `Boundaries (${(data.trust_boundaries?.length ?? 0) + (data.entry_points?.length ?? 0)})`;
                if (item.id === "threats")         label = `Threats (${data.threat_count ?? 0})`;
                if (item.id === "mitigations")     label = `Mitigations (${data.mitigation_count ?? 0})`;
                if (item.id === "attack_chains")   label = `Attack Chains (${(data.attack_trees_json || []).length})`;
                if (item.id === "adversaries")     label = `Adversaries (${(data.adversary_profiles_json || []).length})`;
                if (item.id === "detection_rules") label = `Detection Rules (${(data.sigma_rules_json || []).length})`;
              }
              return (
                <Tab
                  key={item.id}
                  value={item.id}
                  icon={<item.Icon sx={{ fontSize: "14px !important" }} />}
                  iconPosition="start"
                  label={label}
                />
              );
            })}
          </Tabs>
        </Box>
      )}
      {/* DIAGRAM */}
      {(tab === "diagram" || printing) && (
        <Box className="tm-print-section" sx={{ mb: printing ? 2 : 0 }}>
          {printing && <Typography className="tm-print-section-heading">Data Flow Diagram</Typography>}
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Box className="no-print" sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1.5, flexWrap: "wrap", gap: 1 }}>
              <Box sx={{ display: "flex", gap: 0.5, p: 0.5, bgcolor: "action.hover", borderRadius: 1.5 }}>
                {(
                  [
                    { key: "interactive", label: "Interactive", icon: <AccountTree sx={{ fontSize: 16 }} /> },
                    { key: "mermaid",     label: "Mermaid",     icon: <Hub sx={{ fontSize: 16 }} /> },
                  ] as Array<{ key: "interactive"|"mermaid"; label: string; icon: React.ReactNode }>
                ).map((opt) => (
                  <Button key={opt.key} size="small" startIcon={opt.icon} onClick={() => setDiagramMode(opt.key)}
                    sx={{
                      minWidth: 110, textTransform: "none", fontSize: 12, fontWeight: 600,
                      color: diagramMode === opt.key ? "#4285F4" : "text.secondary",
                      bgcolor: diagramMode === opt.key ? "rgba(66,133,244,0.12)" : "transparent",
                      border: diagramMode === opt.key ? "1px solid rgba(66,133,244,0.4)" : "1px solid transparent",
                      "&:hover": { bgcolor: "rgba(66,133,244,0.08)" },
                    }}
                  >{opt.label}</Button>
                ))}
              </Box>
              <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap" }}>
                {diagramMode === "mermaid" && data.status === "completed" && (
                  <Box sx={{ display: "flex", gap: 0.5, p: 0.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1.5 }}>
                    {(
                      [
                        { v: "architecture",        label: "Architecture", color: "#4285F4" },
                        { v: "threat_heat",         label: "Threat heat",  color: "#EA4335" },
                        { v: "detection_coverage",  label: "Detections",   color: "#34A853" },
                      ] as Array<{ v: typeof diagramView; label: string; color: string }>
                    ).map((opt) => {
                      const active = diagramView === opt.v;
                      return (
                        <Button key={opt.v} size="small" onClick={() => setDiagramView(opt.v)}
                          sx={{
                            minWidth: 102, textTransform: "none", fontSize: 11.5, fontWeight: 600,
                            color: active ? opt.color : "text.secondary",
                            bgcolor: active ? `${opt.color}18` : "transparent",
                            border: active ? `1px solid ${opt.color}` : "1px solid transparent",
                            "&:hover": { bgcolor: `${opt.color}10` },
                          }}
                        >{opt.label}</Button>
                      );
                    })}
                  </Box>
                )}
                <Button size="small" startIcon={<Download sx={{ fontSize: 16 }} />}
                  onClick={downloadDrawio} disabled={data.status !== "completed"}
                  sx={{
                    textTransform: "none", fontSize: 12, fontWeight: 600, color: "text.secondary",
                    border: "1px solid rgba(255,255,255,0.12)",
                    "&:hover": { bgcolor: "rgba(255,255,255,0.06)", borderColor: "divider" },
                  }}
                >Download .drawio</Button>
              </Box>
            </Box>
            {diagramMode === "interactive" && !printing ? (
              <DfdReactFlow
                components={data.components}
                dataFlows={data.data_flows}
                threats={data.threats}
                trustBoundaries={data.trust_boundaries ?? []}
                onRenameComponent={(compId, newName) => {
                  const updated = data.components.map((c: any) =>
                    c.id === compId ? { ...c, name: newName } : c,
                  );
                  patchModelMutation.mutate({ components_json: updated });
                }}
                onEditFlow={(flowIdx, update) => {
                  const updated = data.data_flows.map((f: any, i: number) =>
                    i === flowIdx ? { ...f, ...update } : f,
                  );
                  patchModelMutation.mutate({ data_flows_json: updated });
                }}
              />
            ) : (
              <DfdDiagram
                source={
                  diagramView !== "architecture" && styledDfdQuery.data?.mermaid
                    ? styledDfdQuery.data.mermaid
                    : (data.dfd_mermaid || "")
                }
              />
            )}
            {data.data_flows.length > 0 && (() => {
              const DataFlowsEditor = () => {
                const [flows, setFlows] = React.useState<any[]>(() => data.data_flows.map((f: any) => ({ ...f })));
                React.useEffect(() => { setFlows(data.data_flows.map((f: any) => ({ ...f }))); }, []);
                const save = (updated: any[]) => patchModelMutation.mutate({ data_flows_json: updated });
                const updateFlow = (idx: number, field: string, value: any) => {
                  const updated = flows.map((f, i) => i === idx ? { ...f, [field]: value } : f);
                  setFlows(updated);
                  return updated;
                };
                const PROTOCOLS = ["HTTPS", "HTTP", "TCP", "UDP", "JDBC", "AMQP", "gRPC", "SSH", "SFTP", "SMTP", "DNS", "Other"];
                const cellSx = { color: "text.primary", fontSize: 12.5, borderColor: "divider", py: 0.5 };
                const inputSx = { fontSize: 12.5, "& input": { p: "2px 4px" }, "&.Mui-focused": { outline: "1px solid", outlineColor: "primary.main", borderRadius: 0.5 } };
                return (
                  <>
                    <Divider sx={{ my: 2, borderColor: "divider" }} />
                    <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, mb: 1, display: "block" }}>
                      Data flows {canAct && <Typography component="span" variant="caption" sx={{ color: "text.disabled", fontWeight: 400, textTransform: "none" }}> — click cells to edit</Typography>}
                    </Typography>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                          <TableCell>FROM</TableCell><TableCell>TO</TableCell>
                          <TableCell>PROTOCOL</TableCell><TableCell>DATA / LABEL</TableCell>
                          <TableCell>ENCRYPTED</TableCell><TableCell>NOTES</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {flows.map((d, i) => (
                          <TableRow key={i} sx={{ "& td": { ...cellSx } }}>
                            <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>{compName.get(d.from) || d.from}</TableCell>
                            <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>{compName.get(d.to) || d.to}</TableCell>
                            <TableCell>
                              {canAct ? (
                                <Select size="small" value={d.protocol || "HTTPS"}
                                  onChange={(e) => save(updateFlow(i, "protocol", e.target.value))}
                                  sx={{ fontSize: 11, height: 24, "& .MuiSelect-select": { py: "2px", px: "6px" } }}>
                                  {PROTOCOLS.map((p) => <MenuItem key={p} value={p} sx={{ fontSize: 11 }}>{p}</MenuItem>)}
                                </Select>
                              ) : (
                                <Chip label={d.protocol} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
                              )}
                            </TableCell>
                            <TableCell>
                              {canAct ? (
                                <InputBase value={d.data || ""} sx={inputSx}
                                  onChange={(e) => setFlows(flows.map((f, j) => j === i ? { ...f, data: e.target.value } : f))}
                                  onBlur={(e) => save(flows.map((f, j) => j === i ? { ...f, data: e.target.value } : f))} />
                              ) : d.data}
                            </TableCell>
                            <TableCell>
                              {canAct ? (
                                <Chip label={d.encrypted ? "TLS" : "PLAIN"} size="small"
                                  onClick={() => save(updateFlow(i, "encrypted", !d.encrypted))}
                                  sx={{ height: 20, fontSize: 10, fontWeight: 700, cursor: "pointer",
                                    bgcolor: d.encrypted ? "rgba(52,168,83,0.15)" : "rgba(234,67,53,0.15)",
                                    color: d.encrypted ? "#34A853" : "#EA4335" }} />
                              ) : (
                                <Chip label={d.encrypted ? "TLS" : "PLAIN"} size="small"
                                  sx={{ height: 18, fontSize: 10, fontWeight: 700,
                                    bgcolor: d.encrypted ? "rgba(52,168,83,0.15)" : "rgba(234,67,53,0.15)",
                                    color: d.encrypted ? "#34A853" : "#EA4335" }} />
                              )}
                            </TableCell>
                            <TableCell>
                              {canAct ? (
                                <InputBase value={d.notes || ""} placeholder="—" sx={{ ...inputSx, minWidth: 80 }}
                                  onChange={(e) => setFlows(flows.map((f, j) => j === i ? { ...f, notes: e.target.value } : f))}
                                  onBlur={(e) => save(flows.map((f, j) => j === i ? { ...f, notes: e.target.value } : f))} />
                              ) : (d.notes || "—")}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </>
                );
              };
              return <DataFlowsEditor />;
            })()}
          </CardContent>
        </Card>
        </Box>
      )}

      {/* COMPONENTS */}
      {(tab === "components" || printing) && (() => {
        const threatenedIds = new Set(data.threats.map((t) => t.asset_id));
        return (
        <Box className="tm-print-section" sx={{ mb: printing ? 2 : 0 }}>
          {printing && <Typography className="tm-print-section-heading">Components ({data.component_count})</Typography>}
          {!printing && canAct && data.status !== "extracted_review" && (
            <ComponentsEditor clientId={clientId} modelId={modelId!} components={data.components} notes={data.analyst_notes} />
          )}
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                  <TableCell>ID</TableCell><TableCell>NAME</TableCell><TableCell>TYPE</TableCell>
                  <TableCell>PLATFORM</TableCell><TableCell>TRUST ZONE</TableCell>
                  <TableCell>ENV</TableCell><TableCell>DATACENTER</TableCell>
                  <TableCell>CRITICALITY</TableCell><TableCell>NOTES</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.components.map((c) => {
                  const zc = zoneColor(normZone(c.trust_zone));
                  const noThreats = data.status === "completed" && !threatenedIds.has(c.id);
                  return (
                    <TableRow key={c.id} sx={{ "& td": { color: "text.primary", fontSize: 12.5, borderColor: "divider", py: 1 } }}>
                      <TableCell sx={{ fontFamily: "monospace", color: "text.secondary" }}>{c.id}</TableCell>
                      <TableCell sx={{ fontWeight: 600 }}>
                        {c.name}
                        {noThreats && (
                          <Chip label="No threats — review" size="small"
                            sx={{ ml: 1, height: 18, fontSize: 10, fontWeight: 700,
                              bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04" }} />
                        )}
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary" }}>{c.type}</TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{(c as any).platform || "—"}</TableCell>
                      <TableCell>
                        <Chip label={c.trust_zone} size="small"
                          sx={{ bgcolor: `${zc}20`, color: zc, height: 18, fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5, fontWeight: 700 }} />
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{(c as any).environment || "—"}</TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 11 }}>{(c as any).datacenter || "—"}</TableCell>
                      <TableCell>
                        <Chip label={c.criticality} size="small"
                          sx={{ bgcolor: `${SEV_COLOR[c.criticality] || "#888"}20`,
                            color: SEV_COLOR[c.criticality] || "#888", height: 18, fontSize: 10, textTransform: "uppercase", fontWeight: 700 }} />
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary" }}>{c.notes || "—"}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            {data.components.length === 0 && (
              <Typography variant="body2" sx={{ color: "text.secondary", textAlign: "center", py: 4 }}>
                No components yet.
              </Typography>
            )}
          </CardContent>
        </Card>
        </Box>
        );
      })()}

      {/* BOUNDARIES */}
      {(tab === "boundaries" || printing) && (
        <Box className="tm-print-section" sx={{ mb: printing ? 2 : 0 }}>
          {printing && <Typography className="tm-print-section-heading">Trust Boundaries &amp; Entry Points</Typography>}
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
            <CardContent>
              <Typography variant="caption" sx={{ color: "#00BCD4", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", mb: 1 }}>
                Trust Boundaries ({(data.trust_boundaries ?? []).length})
              </Typography>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                    <TableCell>NAME</TableCell><TableCell>FROM ZONE</TableCell><TableCell>TO ZONE</TableCell>
                    <TableCell>DESCRIPTION</TableCell><TableCell>CROSSING FLOWS</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {(data.trust_boundaries ?? []).map((tb: any, i: number) => (
                    <TableRow key={i} sx={{ "& td": { color: "text.primary", fontSize: 12.5, borderColor: "divider", py: 1 } }}>
                      <TableCell sx={{ fontWeight: 600 }}>{tb.name}</TableCell>
                      <TableCell><Chip label={tb.from_zone} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(0,188,212,0.12)", color: "#00BCD4" }} /></TableCell>
                      <TableCell><Chip label={tb.to_zone} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(0,188,212,0.12)", color: "#00BCD4" }} /></TableCell>
                      <TableCell sx={{ color: "text.secondary" }}>{tb.description || "—"}</TableCell>
                      <TableCell sx={{ textAlign: "center" }}>{(tb.crossed_by_flow_ids || []).length}</TableCell>
                    </TableRow>
                  ))}
                  {(data.trust_boundaries ?? []).length === 0 && (
                    <TableRow><TableCell colSpan={5}><Typography variant="body2" sx={{ color: "text.secondary", py: 2, textAlign: "center" }}>No trust boundaries enumerated.</Typography></TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
            <CardContent>
              <Typography variant="caption" sx={{ color: "#FF9800", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", mb: 1 }}>
                Entry Points ({(data.entry_points ?? []).length})
              </Typography>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                    <TableCell>NAME</TableCell><TableCell>KIND</TableCell><TableCell>EXPOSURE</TableCell>
                    <TableCell>AUTH REQUIRED</TableCell><TableCell>COMPONENT</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {(data.entry_points ?? []).map((ep: any, i: number) => (
                    <TableRow key={i} sx={{ "& td": { color: "text.primary", fontSize: 12.5, borderColor: "divider", py: 1 } }}>
                      <TableCell sx={{ fontWeight: 600 }}>{ep.name}</TableCell>
                      <TableCell sx={{ color: "text.secondary" }}>{ep.kind}</TableCell>
                      <TableCell>
                        <Chip label={ep.exposure || "unknown"} size="small"
                          sx={{ height: 18, fontSize: 10, fontWeight: 700,
                            bgcolor: ep.exposure === "external" ? "rgba(234,67,53,0.15)" : "rgba(251,188,4,0.15)",
                            color: ep.exposure === "external" ? "#EA4335" : "#FBBC04" }} />
                      </TableCell>
                      <TableCell>
                        <Chip label={ep.auth_required ? "Yes" : "No"} size="small"
                          sx={{ height: 18, fontSize: 10, fontWeight: 700,
                            bgcolor: ep.auth_required ? "rgba(52,168,83,0.15)" : "rgba(234,67,53,0.15)",
                            color: ep.auth_required ? "#34A853" : "#EA4335" }} />
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontFamily: "monospace" }}>{ep.component_id}</TableCell>
                    </TableRow>
                  ))}
                  {(data.entry_points ?? []).length === 0 && (
                    <TableRow><TableCell colSpan={5}><Typography variant="body2" sx={{ color: "text.secondary", py: 2, textAlign: "center" }}>No entry points enumerated.</Typography></TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent>
              {(() => {
                const crossingFlows = (data.data_flows || []).filter((f: any) => f.trust_boundary_crossing);
                return (
                  <>
                    <Typography variant="caption" sx={{ color: "#EA4335", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", mb: 1 }}>
                      Boundary-Crossing Flows ({crossingFlows.length})
                    </Typography>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                          <TableCell>FROM</TableCell><TableCell>TO</TableCell><TableCell>PROTOCOL</TableCell><TableCell>DATA</TableCell><TableCell>ENCRYPTED</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {crossingFlows.map((f: any, i: number) => (
                          <TableRow key={i} sx={{ "& td": { color: "text.primary", fontSize: 12.5, borderColor: "divider", py: 1 } }}>
                            <TableCell>{compName.get(f.from) || f.from}</TableCell>
                            <TableCell>{compName.get(f.to) || f.to}</TableCell>
                            <TableCell><Chip label={f.protocol} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} /></TableCell>
                            <TableCell>{f.data}</TableCell>
                            <TableCell>
                              <Chip label={f.encrypted ? "TLS" : "PLAIN"} size="small"
                                sx={{ height: 18, fontSize: 10, fontWeight: 700,
                                  bgcolor: f.encrypted ? "rgba(52,168,83,0.15)" : "rgba(234,67,53,0.15)",
                                  color: f.encrypted ? "#34A853" : "#EA4335" }} />
                            </TableCell>
                          </TableRow>
                        ))}
                        {crossingFlows.length === 0 && (
                          <TableRow><TableCell colSpan={5}><Typography variant="body2" sx={{ color: "text.secondary", py: 2, textAlign: "center" }}>No boundary-crossing flows.</Typography></TableCell></TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </>
                );
              })()}
            </CardContent>
          </Card>
        </Box>
      )}

      {/* THREATS — grouped by category */}
      {(tab === "threats" || printing) && (
        <Box className="tm-print-section" sx={{ mb: printing ? 2 : 0 }}>
          {printing && <Typography className="tm-print-section-heading">Threats ({data.threat_count})</Typography>}
          {/* Risk Heat Map */}
          {data.threats.length > 0 && !printing && (() => {
            const cellCounts: Record<string, { count: number; maxSev: string }> = {};
            const SEV_ORDER = ["critical", "high", "medium", "low"];
            for (const t of data.threats) {
              const rawLi = Number(t.likelihood) || 0;
              const rawIm = Number(t.impact) || 0;
              // Threats use 1-10 scale; normalize to 1-5 bands for the grid
              const li = rawLi >= 1 ? Math.min(5, Math.ceil(rawLi / 2)) : 0;
              const im = rawIm >= 1 ? Math.min(5, Math.ceil(rawIm / 2)) : 0;
              if (li >= 1 && li <= 5 && im >= 1 && im <= 5) {
                const key = `${li},${im}`;
                const prev = cellCounts[key] || { count: 0, maxSev: "low" };
                const sev = (t.severity || "low").toLowerCase();
                const winner = SEV_ORDER.indexOf(sev) < SEV_ORDER.indexOf(prev.maxSev) ? sev : prev.maxSev;
                cellCounts[key] = { count: prev.count + 1, maxSev: winner };
              }
            }
            const CELL_COLOR: Record<string, [string, string]> = {
              critical: ["rgba(234,67,53,0.18)", "#EA4335"],
              high:     ["rgba(251,188,4,0.18)", "#FBBC04"],
              medium:   ["rgba(234,128,0,0.18)", "#E07800"],
              low:      ["rgba(52,168,83,0.18)", "#34A853"],
            };
            const bgDefault = "rgba(255,255,255,0.04)";
            return (
              <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
                <CardContent sx={{ pb: "12px !important" }}>
                  <Typography variant="caption" sx={{ color: "#4285F4", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", mb: 1.5 }}>
                    Risk Heat Map — likelihood × impact
                  </Typography>
                  <Box sx={{ display: "grid", gridTemplateColumns: "28px repeat(5, 1fr)", gap: "3px" }}>
                    {/* header */}
                    <Box />
                    {[1,2,3,4,5].map((li) => (
                      <Box key={li} sx={{ textAlign: "center", fontSize: 10, fontWeight: 700, color: "text.secondary", pb: 0.5 }}>L{li}</Box>
                    ))}
                    {[5,4,3,2,1].map((im) => (
                      <React.Fragment key={im}>
                        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, color: "text.secondary" }}>I{im}</Box>
                        {[1,2,3,4,5].map((li) => {
                          const key = `${li},${im}`;
                          const cell = cellCounts[key];
                          const score = li * im;
                          const sev = cell ? cell.maxSev : (score >= 16 ? "critical" : score >= 9 ? "high" : score >= 4 ? "medium" : "low");
                          const [bg, fg] = cell ? CELL_COLOR[cell.maxSev] : ["rgba(255,255,255,0.04)", "rgba(255,255,255,0.2)"];
                          return (
                            <Box key={li} sx={{
                              height: 44, borderRadius: 1,
                              bgcolor: bg,
                              display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
                              border: cell ? `1px solid ${fg}40` : "1px solid rgba(255,255,255,0.06)",
                            }}>
                              {cell ? (
                                <>
                                  <Typography sx={{ fontSize: 14, fontWeight: 700, color: fg, lineHeight: 1 }}>{cell.count}</Typography>
                                  <Typography sx={{ fontSize: 9, color: fg, opacity: 0.8 }}>{score}</Typography>
                                </>
                              ) : (
                                <Typography sx={{ fontSize: 9, color: "rgba(255,255,255,0.2)" }}>{score}</Typography>
                              )}
                            </Box>
                          );
                        })}
                      </React.Fragment>
                    ))}
                  </Box>
                  <Typography variant="caption" sx={{ color: "text.secondary", mt: 1, display: "block" }}>
                    Cell score = L×I (1–10 scale mapped to L1–L5 / I1–I5 bands). Cells show threat count coloured by highest severity.
                  </Typography>
                </CardContent>
              </Card>
            );
          })()}
          {data.threats.length > 0 && (
            <Box className="no-print" sx={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 1, mb: 1.5 }}>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {convertedSet.size > 0
                  ? `${convertedSet.size} of ${data.threats.length} already in Risk Register`
                  : "Convert threats into trackable Risk Register entries"}
              </Typography>
              <Tooltip title={newCount === 0 ? "Every threat is already in the Risk Register" : `Create ${newCount} new risk${newCount === 1 ? "" : "s"}; skip ${convertedSet.size} duplicate${convertedSet.size === 1 ? "" : "s"}`}>
                <span>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={convertAll.isPending ? <CircularProgress size={14} sx={{ color: "#34A853" }} /> : <PlaylistAddCheck />}
                    disabled={newCount === 0 || convertAll.isPending}
                    onClick={() => convertAll.mutate()}
                    sx={{
                      color: "#34A853", borderColor: "rgba(52,168,83,0.5)", textTransform: "none", fontWeight: 600,
                      "&:hover": { borderColor: "#34A853", bgcolor: "rgba(52,168,83,0.08)" },
                      "&.Mui-disabled": { color: "rgba(52,168,83,0.4)", borderColor: "rgba(52,168,83,0.2)" },
                    }}
                  >
                    {newCount === 0 ? "All converted" : `Convert ${newCount} to Risk Register`}
                  </Button>
                </span>
              </Tooltip>
            </Box>
          )}
          {Object.keys(threatsByCat).length === 0 ? (
            <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 2, p: 4, textAlign: "center" }}>
              <Typography variant="body2" sx={{ color: "text.secondary" }}>
                No threats produced yet.
              </Typography>
            </Card>
          ) : (
            Object.entries(threatsByCat).map(([cat, list]) => (
              <Card key={cat} sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 1.5 }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                    <Typography sx={{ color: "text.primary", fontSize: 14, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5 }}>
                      {prettyCat(cat)}
                    </Typography>
                    <Chip label={list.length} size="small" sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", height: 18, fontSize: 10, fontWeight: 700 }} />
                  </Box>
                  {list.map((t) => {
                    const sc = SEV_COLOR[t.severity] || "rgba(255,255,255,0.4)";
                    const ms = mitigationsByThreat[t.id] || [];
                    return (
                      <ThreatRow
                        key={t.id}
                        threat={t}
                        sc={sc}
                        compName={compName.get(t.asset_id) || t.asset_id || "—"}
                        converted={convertedSet.has(t.id)}
                        onConvert={() => convertOne.mutate(t.id)}
                        convertPending={convertOne.isPending && convertOne.variables === t.id}
                        onPatch={(body) => patchThreatMutation.mutate({ threatId: t.id, body })}
                        patching={patchThreatMutation.isPending && patchThreatMutation.variables?.threatId === t.id}
                        mitigations={ms}
                      />
                    );
                  })}
                </CardContent>
              </Card>
            ))
          )}
        </Box>
      )}
      {/* COVERAGE — STRIDE matrix */}
      {(tab === "coverage" || printing) && (
        <Box className="tm-print-section" sx={{ mb: printing ? 2 : 0 }}>
          {printing && <Typography className="tm-print-section-heading">STRIDE Coverage Matrix</Typography>}
          <CoverageMatrixView
            data={data}
            onFillGaps={canAct ? () => fillGapsMutation.mutate(undefined) : undefined}
            onFillCells={canAct ? (cells) => fillGapsMutation.mutate(cells) : undefined}
            onThreatClick={(tid) => {
              const t = (data.threats || []).find((x) => x.id === tid);
              if (t) setThreatPopup(t);
            }}
            filling={fillGapsMutation.isPending}
          />
        </Box>
      )}

      {/* Threat popup — opened from a coverage-matrix threat cell */}
      <Dialog open={!!threatPopup} onClose={() => setThreatPopup(null)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "background.paper" } } }}>
        {threatPopup && (
          <>
            <DialogTitle sx={{ color: "text.primary", display: "flex", alignItems: "center", gap: 1 }}>
              <Chip label={(threatPopup.severity || "").toUpperCase()} size="small"
                sx={{ bgcolor: `${SEV_COLOR[threatPopup.severity] || "#888"}22`, color: SEV_COLOR[threatPopup.severity] || "#888", fontWeight: 700 }} />
              <span>{threatPopup.title}</span>
            </DialogTitle>
            <DialogContent dividers>
              <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", letterSpacing: 0.5 }}>
                {(threatPopup.category || "").replace(/_/g, " ")} · target {threatPopup.asset_id || "—"}
              </Typography>
              {threatPopup.rationale && (
                <Typography variant="body2" sx={{ color: "text.primary", mt: 1.5, whiteSpace: "pre-wrap" }}>
                  {threatPopup.rationale}
                </Typography>
              )}
              {threatPopup.attack_narrative && (
                <Typography variant="body2" sx={{ color: "text.secondary", mt: 1.5, whiteSpace: "pre-wrap" }}>
                  {threatPopup.attack_narrative}
                </Typography>
              )}
              {(threatPopup.capec_refs?.length || threatPopup.attack_techniques?.length) ? (
                <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 2 }}>
                  {(threatPopup.capec_refs || []).map((r) => <ThreatLibraryChip key={r} source="capec" sourceId={r} />)}
                  {(threatPopup.attack_techniques || []).map((r) => <ThreatLibraryChip key={r} source="attack" sourceId={r} />)}
                </Box>
              ) : null}
            </DialogContent>
          </>
        )}
      </Dialog>

      {/* MATURITY radar */}
      {(tab === "maturity" || printing) && (
        <Box className="tm-print-section" sx={{ mb: printing ? 2 : 0 }}>
          {printing && <Typography className="tm-print-section-heading">Maturity by Category</Typography>}
          <MaturityView data={data} />
        </Box>
      )}

      {/* MITIGATIONS */}
      {(tab === "mitigations" || printing) && (
        <Box className="tm-print-section" sx={{ mb: printing ? 2 : 0 }}>
          {printing && <Typography className="tm-print-section-heading">Mitigations ({data.mitigation_count})</Typography>}
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                  <TableCell>ID</TableCell>
                  <TableCell>THREAT</TableCell>
                  <TableCell>ACTION</TableCell>
                  <TableCell>CONTROL</TableCell>
                  <TableCell>STATUS</TableCell>
                  <TableCell>OWNER</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.mitigations.map((m) => {
                  const st = STATUS_COLOR[m.status] || "rgba(255,255,255,0.4)";
                  return (
                    <TableRow key={m.id} sx={{ "& td": { color: "text.primary", fontSize: 12.5, borderColor: "divider", py: 1 } }}>
                      <TableCell sx={{ fontFamily: "monospace", color: "text.secondary" }}>{m.id}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", color: "text.secondary" }}>{m.threat_id}</TableCell>
                      <TableCell sx={{ maxWidth: 420 }}>{m.action}</TableCell>
                      <TableCell>{m.control_id ? <Chip label={m.control_id} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(124,77,255,0.15)", color: "#9C27B0" }} /> : "—"}</TableCell>
                      <TableCell>
                        <Chip label={m.status.replace(/_/g, " ")} size="small"
                          sx={{ bgcolor: `${st}20`, color: st, height: 18, fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5, fontWeight: 700 }} />
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary" }}>{m.owner || "—"}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            {data.mitigations.length === 0 && (
              <Typography variant="body2" sx={{ color: "text.secondary", textAlign: "center", py: 4 }}>
                No mitigations yet.
              </Typography>
            )}
          </CardContent>
        </Card>
        </Box>
      )}

      {/* ATTACK CHAINS */}
      {tab === "attack_chains" && (
        <AttackChainsView attackTrees={data.attack_trees_json || []} />
      )}

      {/* ADVERSARIES */}
      {tab === "adversaries" && (
        <AdversariesView profiles={data.adversary_profiles_json || []} />
      )}

      {/* DETECTION RULES */}
      {tab === "detection_rules" && (
        <DetectionRulesView
          rules={data.sigma_rules_json || []}
          clientId={clientId}
          modelId={modelId!}
          onValidated={() => qc.invalidateQueries({ queryKey: ["threat-model-detail", modelId] })}
        />
      )}
    </Box>
  );
}


// ── Phase 8 sub-views ─────────────────────────────────────────────────────────

const STATE_STYLE: Record<string, { bg: string; fg: string; label: string }> = {
  threat:          { bg: "rgba(234,67,53,0.15)",  fg: "#EA4335", label: "Threat" },
  considered:      { bg: "rgba(66,133,244,0.15)", fg: "#4285F4", label: "Considered" },
  not_applicable:  { bg: "rgba(255,255,255,0.04)", fg: "rgba(255,255,255,0.5)", label: "N/A" },
  missing:         { bg: "rgba(251,188,4,0.15)",  fg: "#FBBC04", label: "Missing" },
};

function CoverageMatrixView({ data, onFillGaps, onFillCells, onThreatClick, filling }: {
  data: ThreatModelDetailData;
  onFillGaps?: () => void;
  onFillCells?: (cells: { component_id: string; category: string }[]) => void;
  onThreatClick?: (threatId: string) => void;
  filling?: boolean;
}) {
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const toggleCell = (key: string) => setSelected((prev) => {
    const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n;
  });
  const decisions = data.coverage_decisions || [];
  const components = data.components || [];
  // Distinct categories
  const categories = Array.from(new Set(decisions.map((d) => d.category))).sort();
  // Quick lookup
  const cellMap = new Map<string, CoverageDecision>();
  for (const d of decisions) cellMap.set(`${d.component_id}|${d.category}`, d);
  const total = decisions.length;
  const missing = decisions.filter((d) => d.state === "missing").length;
  const threatCells = decisions.filter((d) => d.state === "threat").length;
  const pct = total === 0 ? 0 : Math.round(((total - missing) / total) * 100);
  return (
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2, flexWrap: "wrap" }}>
          <Typography variant="h6" sx={{ color: "text.primary", fontWeight: 700 }}>
            Coverage Matrix
          </Typography>
          <Chip label={`${pct}% covered`} sx={{ bgcolor: pct >= 80 ? "rgba(52,168,83,0.18)" : "rgba(251,188,4,0.18)", color: pct >= 80 ? "#34A853" : "#FBBC04", fontWeight: 700, height: 22, fontSize: 11 }} />
          <Chip label={`${threatCells} threats`} sx={{ bgcolor: "rgba(234,67,53,0.12)", color: "#EA4335", fontWeight: 700, height: 22, fontSize: 11 }} />
          <Chip label={`${missing} missing`} sx={{ bgcolor: missing > 0 ? "rgba(251,188,4,0.18)" : "rgba(255,255,255,0.04)", color: missing > 0 ? "#FBBC04" : "text.secondary", fontWeight: 700, height: 22, fontSize: 11 }} />
          {missing > 0 && selected.size > 0 && onFillCells && (
            <Button
              size="small" variant="contained" className="no-print"
              startIcon={filling ? <CircularProgress size={14} sx={{ color: "#1A1A1A" }} /> : <AutoFixHigh sx={{ fontSize: 16 }} />}
              disabled={filling}
              onClick={() => {
                const cells = Array.from(selected).map((k) => {
                  const [component_id, category] = k.split("|");
                  return { component_id, category };
                });
                onFillCells(cells);
                setSelected(new Set());
              }}
              sx={{ bgcolor: "#4285F4", color: "#fff", textTransform: "none", fontWeight: 700, fontSize: 11, height: 26,
                "&:hover": { bgcolor: "#5B9CFF" } }}
            >
              {filling ? "Filling…" : `Fill selected (${selected.size})`}
            </Button>
          )}
          {missing > 0 && onFillGaps && (
            <Tooltip title={`Resolve all ${missing} missing cells in one LLM pass. To do a few, click the missing cells to select them, then "Fill selected".`}>
              <span>
                <Button
                  size="small"
                  variant={selected.size > 0 ? "outlined" : "contained"}
                  className="no-print"
                  startIcon={filling ? <CircularProgress size={14} sx={{ color: "text.primary" }} /> : <AutoFixHigh sx={{ fontSize: 16 }} />}
                  disabled={filling}
                  onClick={onFillGaps}
                  sx={selected.size > 0
                    ? { color: "#FBBC04", borderColor: "rgba(251,188,4,0.5)", textTransform: "none", fontWeight: 700, fontSize: 11, height: 26 }
                    : { bgcolor: "#FBBC04", color: "#1A1A1A", textTransform: "none", fontWeight: 700, fontSize: 11, height: 26, "&:hover": { bgcolor: "#FFC53D" } }}
                >
                  {filling ? "Filling…" : `Fill all ${missing} gap${missing === 1 ? "" : "s"}`}
                </Button>
              </span>
            </Tooltip>
          )}
          <Typography variant="caption" sx={{ color: "text.secondary", ml: "auto" }}>
            Critical &amp; High components get full STRIDE; Medium gets applicable categories; Low only where surface exists.
          </Typography>
        </Box>
        {decisions.length === 0 ? (
          <Typography variant="body2" sx={{ color: "text.secondary", textAlign: "center", py: 4 }}>
            No coverage decisions yet. Re-generate this model to populate the matrix.
          </Typography>
        ) : (
          <Box sx={{
            display: "grid",
            gridTemplateColumns: `minmax(180px, 1fr) repeat(${categories.length}, minmax(120px, 1fr))`,
            gap: 0.5,
            overflowX: "auto",
          }}>
            <Box sx={{ p: 1, fontSize: 11, fontWeight: 700, color: "text.secondary", textTransform: "uppercase", letterSpacing: 0.5 }}>Component</Box>
            {categories.map((c) => (
              <Box key={c} sx={{ p: 1, fontSize: 11, fontWeight: 700, color: "text.secondary", textTransform: "uppercase", letterSpacing: 0.5 }}>
                {c.replace(/_/g, " ")}
              </Box>
            ))}
            {components.map((comp) => (
              <React.Fragment key={comp.id}>
                <Box sx={{ p: 1, color: "text.primary", fontWeight: 600, fontSize: 12.5, bgcolor: "rgba(255,255,255,0.02)", borderRadius: 1 }}>
                  {comp.name}
                  <Box sx={{ fontSize: 10, color: "text.secondary", fontWeight: 400, mt: 0.25 }}>{comp.criticality}</Box>
                </Box>
                {categories.map((cat) => {
                  const d = cellMap.get(`${comp.id}|${cat}`);
                  if (!d) {
                    return <Box key={cat} sx={{ p: 1, bgcolor: "rgba(255,255,255,0.02)", borderRadius: 1, fontSize: 10, color: "text.secondary" }}>—</Box>;
                  }
                  const style = STATE_STYLE[d.state] || STATE_STYLE.missing;
                  const cellKey = `${comp.id}|${cat}`;
                  const isMissing = d.state === "missing";
                  const isThreat = d.state === "threat" && !!d.threat_id;
                  const sel = selected.has(cellKey);
                  const clickable = isMissing || isThreat;
                  const tip = isMissing
                    ? (sel ? "Selected — click to deselect" : "Click to select for targeted fill")
                    : (isThreat ? "Click to view the threat" : (d.rationale || style.label));
                  return (
                    <Tooltip key={cat} title={tip}>
                      <Box
                        onClick={() => {
                          if (isMissing) toggleCell(cellKey);
                          else if (isThreat && onThreatClick) onThreatClick(d.threat_id as string);
                        }}
                        sx={{ p: 1, bgcolor: style.bg, borderRadius: 1, minHeight: 50,
                          cursor: clickable ? "pointer" : "default",
                          outline: sel ? "2px solid #FBBC04" : "none", outlineOffset: "-2px",
                          "&:hover": clickable ? { filter: "brightness(1.18)" } : {} }}>
                        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                          <Typography variant="caption" sx={{ color: style.fg, fontWeight: 700, fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5 }}>
                            {style.label}
                          </Typography>
                          {isMissing && sel && <Box component="span" sx={{ color: "#FBBC04", fontSize: 12, fontWeight: 700 }}>✓</Box>}
                          {isThreat && <Box component="span" sx={{ color: style.fg, fontSize: 11 }}>↗</Box>}
                        </Box>
                        {d.rationale && (
                          <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10.5, lineHeight: 1.3, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>
                            {d.rationale}
                          </Typography>
                        )}
                      </Box>
                    </Tooltip>
                  );
                })}
              </React.Fragment>
            ))}
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

function MaturityView({ data }: { data: ThreatModelDetailData }) {
  const scores = data.maturity_scores || {};
  const entries = Object.entries(scores).sort();
  if (entries.length === 0) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
        <CardContent>
          <Typography variant="h6" sx={{ color: "text.primary" }}>Maturity by Category</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary", textAlign: "center", py: 4 }}>
            No maturity scores yet — generate or re-model to populate.
          </Typography>
        </CardContent>
      </Card>
    );
  }
  const avg = entries.reduce((s, [, v]) => s + v, 0) / entries.length;
  return (
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2, flexWrap: "wrap" }}>
          <Typography variant="h6" sx={{ color: "text.primary", fontWeight: 700 }}>Maturity by Category</Typography>
          <Chip label={`avg ${avg.toFixed(2)} / 5.0`} sx={{ bgcolor: "rgba(66,133,244,0.18)", color: "#4285F4", fontWeight: 700, height: 22, fontSize: 11 }} />
          <Typography variant="caption" sx={{ color: "text.secondary", ml: "auto" }}>
            Score = (mitigated×2 + detected×1.2 + closed-evidence×0.8 + grounded×0.5) − unmitigated-critical×1
          </Typography>
        </Box>
        <Box sx={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 1.5 }}>
          {entries.map(([cat, score]) => {
            const pct = Math.max(0, Math.min(1, score / 5));
            const color = score >= 3.5 ? "#34A853" : score >= 2 ? "#FBBC04" : "#EA4335";
            return (
              <Box key={cat} sx={{ p: 1.5, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1.5, border: "1px solid rgba(255,255,255,0.06)" }}>
                <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", display: "block" }}>
                  {cat.replace(/_/g, " ")}
                </Typography>
                <Box sx={{ display: "flex", alignItems: "baseline", gap: 0.5, mt: 0.5 }}>
                  <Typography sx={{ color, fontWeight: 700, fontSize: 22, lineHeight: 1 }}>{score.toFixed(1)}</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>/ 5.0</Typography>
                </Box>
                <Box sx={{ mt: 1, height: 6, bgcolor: "rgba(255,255,255,0.08)", borderRadius: 3, overflow: "hidden" }}>
                  <Box sx={{ width: `${pct * 100}%`, height: "100%", bgcolor: color }} />
                </Box>
              </Box>
            );
          })}
        </Box>
      </CardContent>
    </Card>
  );
}


// ── Phase 8 — enriched threat row ────────────────────────────────────────────

const THREAT_STATUS_COLOR: Record<string, string> = {
  identified: "#FBBC04",
  mitigated: "#34A853",
  accepted: "#4285F4",
  transferred: "#9C27B0",
  compensated: "#00B8D4",
  not_applicable: "rgba(255,255,255,0.45)",
};

const THREAT_STATUS_OPTIONS = [
  "identified", "mitigated", "accepted", "transferred", "compensated", "not_applicable",
];

interface ThreatRowProps {
  threat: Threat;
  sc: string;
  compName: string;
  converted: boolean;
  onConvert: () => void;
  convertPending: boolean;
  onPatch: (body: any) => void;
  patching: boolean;
  mitigations: Mitigation[];
}

function ThreatRow({ threat: t, sc, compName, converted, onConvert, convertPending, onPatch, patching, mitigations: ms }: ThreatRowProps) {
  const [expanded, setExpanded] = React.useState(false);
  const [statusAnchor, setStatusAnchor] = React.useState<null | HTMLElement>(null);
  const status = t.status || "identified";
  const statusColor = THREAT_STATUS_COLOR[status] || "rgba(255,255,255,0.5)";
  const detection = t.detection_status || "gap";
  const detColor = detection === "detected" ? "#34A853" : detection === "not_applicable" ? "rgba(255,255,255,0.5)" : "#EA4335";
  const grounded = t.is_grounded !== false;
  const evidenceRefs = t.evidence_refs || [];

  return (
    <Box sx={{ borderTop: "1px solid rgba(255,255,255,0.06)", py: 1.25 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5, flexWrap: "wrap" }}>
        <Typography sx={{ color: "text.secondary", fontSize: 11, fontFamily: "monospace", minWidth: 40 }}>{t.id}</Typography>
        <Chip label={t.severity} size="small"
          sx={{ bgcolor: `${sc}20`, color: sc, height: 18, fontSize: 10, textTransform: "uppercase", fontWeight: 700 }} />
        {typeof t.priority_score === "number" && (
          <Chip label={`P ${t.priority_score}`} size="small"
            sx={{ bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4", height: 18, fontSize: 10, fontWeight: 700 }} />
        )}
        {(typeof t.likelihood === "number" && typeof t.impact === "number") && (
          <Chip label={`L${t.likelihood}·I${t.impact}`} size="small"
            sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", height: 18, fontSize: 10 }} />
        )}
        <Tooltip title={detection === "detected" ? "SOC rule named" : detection === "gap" ? "No detection in place" : "Detection not applicable"}>
          <Chip label={`Detection: ${detection}`} size="small"
            sx={{ bgcolor: `${detColor}20`, color: detColor, height: 18, fontSize: 10, fontWeight: 700 }} />
        </Tooltip>
        {!grounded && (
          <Tooltip title="No evidence_refs cited — consultant should validate or discard">
            <Chip label="UNGROUNDED" size="small"
              sx={{ bgcolor: "rgba(234,67,53,0.15)", color: "#EA4335", height: 18, fontSize: 10, fontWeight: 700 }} />
          </Tooltip>
        )}
        <Typography sx={{ color: "text.primary", fontSize: 13.5, fontWeight: 600, flex: 1, minWidth: 200 }}>{t.title}</Typography>
        <Typography variant="caption" sx={{ color: "text.secondary" }}>
          on <b>{compName}</b>
        </Typography>
        {/* Status menu (workshop mode) */}
        <Tooltip title="Change threat status (workshop mode)">
          <Chip
            className="no-print"
            label={status}
            size="small"
            onClick={(e) => setStatusAnchor(e.currentTarget)}
            sx={{
              bgcolor: `${statusColor}25`, color: statusColor, height: 20, fontSize: 10, fontWeight: 700,
              textTransform: "uppercase", letterSpacing: 0.3, cursor: "pointer",
              "&:hover": { bgcolor: `${statusColor}40` },
            }}
          />
        </Tooltip>
        <Menu anchorEl={statusAnchor} open={Boolean(statusAnchor)} onClose={() => setStatusAnchor(null)}>
          {THREAT_STATUS_OPTIONS.map((s) => (
            <MenuItem
              key={s}
              selected={s === status}
              onClick={() => { setStatusAnchor(null); if (s !== status) onPatch({ status: s }); }}
              sx={{ fontSize: 13 }}
            >
              <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: THREAT_STATUS_COLOR[s], mr: 1 }} />
              {s.replace(/_/g, " ")}
            </MenuItem>
          ))}
        </Menu>
        <Tooltip title={converted ? "Already in Risk Register" : "Convert this threat to a Risk Register entry"}>
          <span>
            <IconButton
              size="small"
              className="no-print"
              disabled={converted || convertPending}
              onClick={onConvert}
              sx={{
                color: converted ? "rgba(52,168,83,0.5)" : "#34A853",
                "&:hover": { bgcolor: "rgba(52,168,83,0.12)" },
                "&.Mui-disabled": { color: "rgba(52,168,83,0.4)" },
              }}
            >
              {convertPending ? <CircularProgress size={14} sx={{ color: "#34A853" }} /> : <AddTask sx={{ fontSize: 18 }} />}
            </IconButton>
          </span>
        </Tooltip>
        <IconButton size="small" className="no-print" onClick={() => setExpanded((x) => !x)} sx={{ color: "text.secondary" }}>
          {expanded ? <KeyboardArrowUp fontSize="small" /> : <KeyboardArrowDown fontSize="small" />}
        </IconButton>
      </Box>
      {t.rationale && (
        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", lineHeight: 1.5, mb: 0.75 }}>
          {t.rationale}
        </Typography>
      )}
      <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
        {(t.capec_refs || []).map((c) => (
          <ThreatLibraryChip key={c} source="capec" sourceId={c} />
        ))}
        {(t.attack_techniques || []).map((a) => (
          <ThreatLibraryChip key={a} source="attack" sourceId={a} label={`ATT&CK ${a}`} />
        ))}
        {(t.cwe_refs || []).map((c) => (
          <Chip key={c} label={c} size="small" sx={{ height: 16, fontSize: 9.5, bgcolor: "rgba(234,67,53,0.12)", color: "#EA4335", fontWeight: 700 }} />
        ))}
        {evidenceRefs.map((ref, i) => (
          <Tooltip key={i} title={ref.label || `${ref.kind}: ${ref.id}`}>
            <Chip
              label={`${ref.kind}:${ref.id.slice(0, 12)}`}
              size="small"
              sx={{ height: 16, fontSize: 9, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontFamily: "monospace" }}
            />
          </Tooltip>
        ))}
        {evidenceRefs.length === 0 && t.evidence && (
          <Chip label={`Evidence: ${t.evidence.slice(0, 80)}`} size="small" sx={{ height: 16, fontSize: 9.5, bgcolor: "rgba(251,188,4,0.12)", color: "#FBBC04" }} />
        )}
      </Box>
      <Collapse in={expanded} unmountOnExit>
        <Box sx={{ mt: 1, p: 1.25, bgcolor: "rgba(255,255,255,0.02)", borderRadius: 1.5, borderLeft: "2px solid rgba(66,133,244,0.5)" }}>
          {t.attack_narrative && (
            <Box sx={{ mb: 1.25 }}>
              <Typography variant="caption" sx={{ color: "#4285F4", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", display: "block", mb: 0.5 }}>
                Attack narrative
              </Typography>
              <Typography variant="body2" sx={{ color: "text.secondary", fontSize: 12.5, lineHeight: 1.5 }}>
                {t.attack_narrative}
              </Typography>
            </Box>
          )}
          {Array.isArray(t.blast_radius) && t.blast_radius.length > 0 && (
            <Box sx={{ mb: 1.25 }}>
              <Typography variant="caption" sx={{ color: "#EA4335", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", display: "block", mb: 0.5 }}>
                Blast radius
              </Typography>
              <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                {t.blast_radius.map((b) => (
                  <Chip key={b} label={b} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(234,67,53,0.1)", color: "#EA4335", fontFamily: "monospace" }} />
                ))}
              </Box>
            </Box>
          )}
          {t.owner_role && (
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase" }}>Owner</Typography>
              <Chip label={t.owner_role} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
            </Box>
          )}
          {t.decision_notes && (
            <Box sx={{ mt: 0.5 }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", display: "block", mb: 0.25 }}>Decision notes</Typography>
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 12 }}>{t.decision_notes}</Typography>
            </Box>
          )}
          {t.residual_severity && (
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 0.5 }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase" }}>Residual</Typography>
              <Chip label={t.residual_severity} size="small" sx={{ height: 18, fontSize: 10, bgcolor: `${SEV_COLOR[t.residual_severity] || "rgba(255,255,255,0.3)"}25`, color: SEV_COLOR[t.residual_severity] || "rgba(255,255,255,0.5)", fontWeight: 700 }} />
              {t.residual_rationale && (
                <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11.5 }}>{t.residual_rationale}</Typography>
              )}
            </Box>
          )}
        </Box>
      </Collapse>
      {ms.length > 0 && (
        <Box sx={{ mt: 0.75, ml: 1, borderLeft: "2px solid rgba(52,168,83,0.4)", pl: 1.25 }}>
          {ms.map((m: any) => (
            <Box key={m.id} sx={{ mb: 0.25 }}>
              <Typography variant="caption" sx={{ color: "#34A853", fontWeight: 700 }}>
                {m.id}: </Typography>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>{m.action}</Typography>
              {(m.control_refs || []).map((r: any, i: number) => (
                <Chip key={i} label={`${r.framework || "ctrl"}:${r.control_id}`} size="small" sx={{ ml: 0.75, height: 14, fontSize: 9, bgcolor: "rgba(124,77,255,0.15)", color: "#9C27B0" }} />
              ))}
              {!(m.control_refs && m.control_refs.length) && m.control_id && (
                <Chip label={m.control_id} size="small" sx={{ ml: 1, height: 14, fontSize: 9, bgcolor: "rgba(124,77,255,0.15)", color: "#9C27B0" }} />
              )}
              {patching && <span> </span>}
            </Box>
          ))}
        </Box>
      )}
    </Box>
  );
}


// ── Phase 9 sub-views ─────────────────────────────────────────────────────────

const ADVERSARY_TYPE_COLOR: Record<string, string> = {
  nation_state: "#EA4335",
  criminal: "#FF7043",
  hacktivist: "#FBBC04",
  insider: "#9C27B0",
  opportunistic: "#4285F4",
};

// Attack Chains ───────────────────────────────────────────────────────────────

function AttackChainsView({ attackTrees }: { attackTrees: AttackTree[] }) {
  if (attackTrees.length === 0) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 2, p: 4, textAlign: "center" }}>
        <AccountTree sx={{ fontSize: 40, color: "text.secondary", mb: 1 }} />
        <Typography variant="body2" sx={{ color: "text.secondary" }}>
          No attack chains yet — re-generate this model to produce attack trees.
        </Typography>
      </Card>
    );
  }
  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
      {attackTrees.map((tree) => (
        <AttackTreeCard key={tree.id} tree={tree} />
      ))}
    </Box>
  );
}

function AttackTreeCard({ tree }: { tree: AttackTree }) {
  const impactColor = SEV_COLOR[tree.impact] || "rgba(255,255,255,0.4)";
  const probPct = Math.round(tree.combined_probability * 100);
  return (
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
      <CardContent>
        {/* Header */}
        <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5, mb: 2, flexWrap: "wrap" }}>
          <AccountTree sx={{ color: "#4285F4", fontSize: 22, mt: 0.25, flexShrink: 0 }} />
          <Box sx={{ flex: 1, minWidth: 200 }}>
            <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 15, lineHeight: 1.4, mb: 0.5 }}>
              {tree.root_goal}
            </Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", alignItems: "center" }}>
              <Chip label={`Chain probability: ${probPct}%`}
                sx={{ bgcolor: probPct >= 60 ? "rgba(234,67,53,0.15)" : probPct >= 30 ? "rgba(251,188,4,0.15)" : "rgba(52,168,83,0.15)",
                  color: probPct >= 60 ? "#EA4335" : probPct >= 30 ? "#FBBC04" : "#34A853",
                  fontWeight: 700, height: 20, fontSize: 11 }} />
              <Chip label={`Impact: ${tree.impact}`}
                sx={{ bgcolor: `${impactColor}20`, color: impactColor, fontWeight: 700, height: 20, fontSize: 11, textTransform: "uppercase" }} />
              <Chip label={`ID: ${tree.id}`}
                sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", height: 20, fontSize: 10, fontFamily: "monospace" }} />
            </Box>
          </Box>
        </Box>

        {/* Step chain */}
        <Box sx={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
          {tree.steps.map((step, idx) => {
            const sc = SEV_COLOR[step.severity] || "rgba(255,255,255,0.4)";
            const likPct = Math.round(step.likelihood * 10);
            return (
              <React.Fragment key={step.step}>
                <Box sx={{
                  border: `1.5px solid ${sc}`,
                  borderRadius: 1.5,
                  p: 1, px: 1.5,
                  bgcolor: `${sc}12`,
                  minWidth: 120,
                  maxWidth: 200,
                }}>
                  <Typography sx={{ color: "text.secondary", fontSize: 9, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", mb: 0.25 }}>
                    Step {step.step}
                  </Typography>
                  <Typography sx={{ color: "text.primary", fontSize: 12.5, fontWeight: 600, lineHeight: 1.3, mb: 0.5 }}>
                    {step.title}
                  </Typography>
                  <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                    <Chip label={step.severity.toUpperCase()} size="small"
                      sx={{ height: 16, fontSize: 9, fontWeight: 700, bgcolor: `${sc}25`, color: sc }} />
                    <Chip label={`${likPct}%`} size="small"
                      sx={{ height: 16, fontSize: 9, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} />
                  </Box>
                </Box>
                {idx < tree.steps.length - 1 && (
                  <Typography sx={{ color: "text.secondary", fontSize: 18, fontWeight: 300, px: 0.25 }}>→</Typography>
                )}
              </React.Fragment>
            );
          })}
        </Box>

        {/* MITRE chain */}
        {tree.mitre_chain.length > 0 && (
          <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", alignItems: "center" }}>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", mr: 0.5 }}>
              MITRE chain
            </Typography>
            {tree.mitre_chain.map((tid) => (
              <Chip key={tid} label={tid} size="small"
                sx={{ height: 18, fontSize: 10, fontFamily: "monospace", fontWeight: 700,
                  bgcolor: "rgba(234,67,53,0.12)", color: "#EA4335" }} />
            ))}
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

// Adversaries ─────────────────────────────────────────────────────────────────

function AdversariesView({ profiles }: { profiles: AdversaryProfile[] }) {
  if (profiles.length === 0) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 2, p: 4, textAlign: "center" }}>
        <Security sx={{ fontSize: 40, color: "text.secondary", mb: 1 }} />
        <Typography variant="body2" sx={{ color: "text.secondary" }}>
          No adversary profiles yet — re-generate this model to produce adversary analysis.
        </Typography>
      </Card>
    );
  }
  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
      {profiles.map((profile) => (
        <AdversaryCard key={profile.id} profile={profile} />
      ))}
    </Box>
  );
}

function AdversaryCard({ profile }: { profile: AdversaryProfile }) {
  const typeColor = ADVERSARY_TYPE_COLOR[profile.type] || "#4285F4";
  return (
    <Card sx={{ bgcolor: "background.paper", border: `1px solid ${typeColor}30`, borderRadius: 2 }}>
      <CardContent>
        {/* Header */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1.5, flexWrap: "wrap" }}>
          <Security sx={{ color: typeColor, fontSize: 22, flexShrink: 0 }} />
          <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 15, flex: 1 }}>
            {profile.name}
          </Typography>
          <Chip label={profile.type.replace(/_/g, " ")} size="small"
            sx={{ bgcolor: `${typeColor}22`, color: typeColor, fontWeight: 700, height: 22, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.5 }} />
        </Box>

        {/* Key attributes row */}
        <Box sx={{ display: "flex", gap: 2, mb: 1.5, flexWrap: "wrap" }}>
          <Box>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", display: "block" }}>
              Motivation
            </Typography>
            <Typography variant="body2" sx={{ color: "text.primary", fontSize: 13, fontWeight: 600, textTransform: "capitalize" }}>
              {profile.motivation}
            </Typography>
          </Box>
          <Box>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", display: "block" }}>
              Sophistication
            </Typography>
            <Chip label={profile.sophistication} size="small"
              sx={{ height: 20, fontSize: 11, fontWeight: 700,
                bgcolor: profile.sophistication === "high" ? "rgba(234,67,53,0.15)" : profile.sophistication === "medium" ? "rgba(251,188,4,0.15)" : "rgba(52,168,83,0.15)",
                color: profile.sophistication === "high" ? "#EA4335" : profile.sophistication === "medium" ? "#FBBC04" : "#34A853",
                textTransform: "capitalize" }} />
          </Box>
          <Box>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", display: "block" }}>
              Likelihood
            </Typography>
            <Typography variant="body2" sx={{ color: "text.primary", fontSize: 13, fontWeight: 600 }}>
              {profile.likelihood} / 10
            </Typography>
          </Box>
        </Box>

        {/* Techniques */}
        {profile.likely_techniques.length > 0 && (
          <Box sx={{ mb: 1.25 }}>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", display: "block", mb: 0.5 }}>
              Likely Techniques
            </Typography>
            <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
              {profile.likely_techniques.map((t) => (
                <Chip key={t} label={t} size="small"
                  sx={{ height: 18, fontSize: 10, fontFamily: "monospace", fontWeight: 700,
                    bgcolor: "rgba(234,67,53,0.12)", color: "#EA4335" }} />
              ))}
            </Box>
          </Box>
        )}

        {/* Targeted assets */}
        {profile.targeted_assets.length > 0 && (
          <Box sx={{ mb: 1.25 }}>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", display: "block", mb: 0.5 }}>
              Targeted Assets
            </Typography>
            <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
              {profile.targeted_assets.map((a) => (
                <Chip key={a} label={a} size="small"
                  sx={{ height: 18, fontSize: 10, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4" }} />
              ))}
            </Box>
          </Box>
        )}

        {/* Threat IDs */}
        {profile.threat_ids.length > 0 && (
          <Box sx={{ mb: 1.25 }}>
            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 0.5, textTransform: "uppercase", display: "block", mb: 0.5 }}>
              Related Threats
            </Typography>
            <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
              {profile.threat_ids.map((tid) => (
                <Chip key={tid} label={tid} size="small"
                  sx={{ height: 18, fontSize: 10, fontFamily: "monospace", bgcolor: "rgba(251,188,4,0.12)", color: "#FBBC04" }} />
              ))}
            </Box>
          </Box>
        )}

        {/* Rationale */}
        {profile.rationale && (
          <Box sx={{ p: 1.25, bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.06)" }}>
            <Typography variant="body2" sx={{ color: "text.secondary", fontSize: 12.5, lineHeight: 1.55 }}>
              {profile.rationale}
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

// Detection Rules ─────────────────────────────────────────────────────────────

function DetectionRulesView({
  rules, clientId, modelId, onValidated,
}: {
  rules: SigmaRule[];
  clientId: string;
  modelId: string;
  onValidated: () => void;
}) {
  const qc = useQueryClient();
  const [expandedIdx, setExpandedIdx] = React.useState<Set<number>>(new Set());

  const toggleExpand = (idx: number) => {
    setExpandedIdx((prev) => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  };

  const suggestMutation = useMutation({
    mutationFn: () => threatModelsApi.suggestDetections(clientId, modelId),
    onSuccess: (res: any) => {
      qc.invalidateQueries({ queryKey: ["threat-model-detail", modelId] });
      toast.success(`Generated ${res.count ?? 0} detection rule stubs`);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Detection rule generation failed"),
  });

  const validateMutation = useMutation({
    mutationFn: (index: number) =>
      threatModelsApi.validateSigmaRule(clientId, modelId, index),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["threat-model-detail", modelId] });
      onValidated();
      toast.success("Rule marked as validated");
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Validation failed"),
  });

  const downloadSigmaRules = () => {
    threatModelsApi.downloadSigmaRules(clientId, modelId);
  };

  if (rules.length === 0) {
    return (
      <Card sx={{ bgcolor: "background.paper", border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 2, p: 4, textAlign: "center" }}>
        <Verified sx={{ fontSize: 40, color: "text.secondary", mb: 1 }} />
        <Typography variant="body2" sx={{ color: "text.secondary", mb: 2.5 }}>
          No detection rules yet. Let AI suggest Sigma rule stubs based on the threats in this model.
        </Typography>
        <Button
          variant="contained"
          size="small"
          disabled={suggestMutation.isPending}
          startIcon={suggestMutation.isPending
            ? <CircularProgress size={14} sx={{ color: "inherit" }} />
            : <AutoFixHigh sx={{ fontSize: 16 }} />}
          onClick={() => suggestMutation.mutate()}
          sx={{ textTransform: "none", bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" } }}
        >
          {suggestMutation.isPending ? "Generating…" : "Suggest Detection Rules with AI"}
        </Button>
      </Card>
    );
  }

  const validated = rules.filter((r) => r.status === "validated").length;
  const advisory = rules.filter((r) => r.status === "advisory").length;

  return (
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
      <CardContent>
        {/* Summary row */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2, flexWrap: "wrap" }}>
          <Verified sx={{ color: "#34A853", fontSize: 22 }} />
          <Typography sx={{ color: "text.primary", fontWeight: 700 }}>
            {rules.length} rule{rules.length === 1 ? "" : "s"}
          </Typography>
          <Chip label={`${validated} validated`}
            sx={{ bgcolor: "rgba(52,168,83,0.15)", color: "#34A853", fontWeight: 700, height: 20, fontSize: 11 }} />
          <Chip label={`${advisory} advisory`}
            sx={{ bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04", fontWeight: 700, height: 20, fontSize: 11 }} />
          <Box sx={{ flex: 1 }} />
          <Button
            size="small"
            variant="outlined"
            disabled={suggestMutation.isPending}
            startIcon={suggestMutation.isPending
              ? <CircularProgress size={13} sx={{ color: "inherit" }} />
              : <AutoFixHigh sx={{ fontSize: 15 }} />}
            onClick={() => suggestMutation.mutate()}
            sx={{
              color: "text.secondary",
              borderColor: "divider",
              textTransform: "none",
              fontWeight: 600,
              "&:hover": { borderColor: "#4285F4", color: "#4285F4", bgcolor: "rgba(66,133,244,0.06)" },
            }}
          >
            {suggestMutation.isPending ? "Generating…" : "Re-generate with AI"}
          </Button>
          <Button
            size="small"
            variant="outlined"
            startIcon={<Download sx={{ fontSize: 16 }} />}
            onClick={downloadSigmaRules}
            sx={{
              color: "text.secondary",
              borderColor: "divider",
              textTransform: "none",
              fontWeight: 600,
              "&:hover": { borderColor: "#4285F4", color: "#4285F4", bgcolor: "rgba(66,133,244,0.06)" },
            }}
          >
            Download YAML
          </Button>
        </Box>

        {/* Rules list */}
        <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
          {rules.map((rule, idx) => {
            const sc = SEV_COLOR[rule.severity] || "rgba(255,255,255,0.4)";
            const isValidated = rule.status === "validated";
            const isExpanded = expandedIdx.has(idx);
            return (
              <Box key={`${rule.rule_id}-${idx}`} sx={{
                border: `1px solid ${isValidated ? "rgba(52,168,83,0.3)" : "rgba(255,255,255,0.08)"}`,
                borderRadius: 1.5,
                overflow: "hidden",
              }}>
                {/* Rule header row */}
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, p: 1.25, flexWrap: "wrap",
                  bgcolor: isValidated ? "rgba(52,168,83,0.05)" : "rgba(255,255,255,0.02)" }}>
                  <Chip label={rule.platform} size="small"
                    sx={{ height: 18, fontSize: 10, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontFamily: "monospace", fontWeight: 700 }} />
                  <Chip label={rule.severity} size="small"
                    sx={{ height: 18, fontSize: 10, bgcolor: `${sc}20`, color: sc, fontWeight: 700, textTransform: "uppercase" }} />
                  <Typography sx={{ color: "text.primary", fontSize: 12.5, fontWeight: 600, flex: 1, minWidth: 160 }}>
                    {rule.threat_title || rule.rule_id}
                  </Typography>
                  <Typography sx={{ color: "text.secondary", fontSize: 10.5, fontFamily: "monospace" }}>
                    {rule.rule_id}
                  </Typography>
                  <Chip
                    label={isValidated ? "Validated" : "Advisory"}
                    size="small"
                    sx={{
                      height: 18, fontSize: 10, fontWeight: 700,
                      bgcolor: isValidated ? "rgba(52,168,83,0.18)" : "rgba(251,188,4,0.18)",
                      color: isValidated ? "#34A853" : "#FBBC04",
                      textTransform: "uppercase", letterSpacing: 0.3,
                    }}
                  />
                  {!isValidated && (
                    <Tooltip title="Mark this rule as validated — confirms the detection logic has been reviewed">
                      <span>
                        <Button
                          size="small"
                          variant="outlined"
                          disabled={validateMutation.isPending}
                          onClick={() => validateMutation.mutate(idx)}
                          startIcon={validateMutation.isPending && validateMutation.variables === idx
                            ? <CircularProgress size={12} sx={{ color: "#34A853" }} />
                            : <Verified sx={{ fontSize: 14 }} />}
                          sx={{
                            color: "#34A853", borderColor: "rgba(52,168,83,0.4)", textTransform: "none",
                            fontSize: 11, fontWeight: 700, height: 24, px: 1,
                            "&:hover": { borderColor: "#34A853", bgcolor: "rgba(52,168,83,0.08)" },
                          }}
                        >
                          Validate
                        </Button>
                      </span>
                    </Tooltip>
                  )}
                  <IconButton size="small" onClick={() => toggleExpand(idx)} sx={{ color: "text.secondary" }}>
                    {isExpanded ? <ExpandLess sx={{ fontSize: 18 }} /> : <ExpandMore sx={{ fontSize: 18 }} />}
                  </IconButton>
                </Box>

                {/* Description (from LLM-generated rules) */}
                {rule.description && (
                  <Box sx={{ px: 1.5, pb: 0.75 }}>
                    <Typography sx={{ fontSize: 11.5, color: "text.secondary", lineHeight: 1.5 }}>
                      {rule.description}
                    </Typography>
                  </Box>
                )}

                {/* Collapsible YAML */}
                <Collapse in={isExpanded} unmountOnExit>
                  <Box sx={{ borderTop: "1px solid rgba(255,255,255,0.10)", bgcolor: "#0d1117", p: 0 }}>
                    <Box
                      component="pre"
                      sx={{
                        m: 0,
                        p: 2,
                        fontSize: 11.5,
                        fontFamily: "'Fira Code', 'Cascadia Code', 'Consolas', monospace",
                        color: "#e6edf3",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-word",
                        overflowX: "auto",
                        maxHeight: 400,
                        overflowY: "auto",
                        lineHeight: 1.6,
                      }}
                    >
                      {rule.sigma_yaml}
                    </Box>
                  </Box>
                </Collapse>
              </Box>
            );
          })}
        </Box>
      </CardContent>
    </Card>
  );
}
