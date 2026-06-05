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
import React, { useState } from "react";
import { useParams, useSearchParams, useNavigate } from "react-router-dom";
import {
  Box, Typography, Card, CardContent, Tabs, Tab, Chip, Button,
  CircularProgress, Alert, LinearProgress, Table, TableHead, TableRow, TableCell,
  TableBody, Divider, Tooltip, IconButton, Menu, MenuItem, Collapse,
} from "@mui/material";
import {
  ArrowBack, Hub, Replay, Print, PlaylistAddCheck, AddTask, Download, Schema,
  KeyboardArrowUp, KeyboardArrowDown, AutoFixHigh,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";
import { threatModelsApi } from "../services/api";
import { fromNow } from "../utils/datetime";
import DfdDiagram from "../components/DfdDiagram";
import DrawioDiagram from "../components/DrawioDiagram";
import ThreatLibraryChip from "../components/ThreatLibraryChip";

interface Component {
  id: string; name: string; type: string;
  trust_zone: string; criticality: string; notes?: string;
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
  scope_type: string; framework?: string | null; methodology: string;
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
  // Phase 8
  trust_boundaries?: any[];
  entry_points?: any[];
  coverage_decisions?: CoverageDecision[];
  maturity_scores?: Record<string, number>;
}

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853", info: "#4285F4",
};
const STATUS_COLOR: Record<string, string> = {
  open: "#FF7043", in_progress: "#FBBC04", accepted: "#4285F4",
  compensating_control: "#9C27B0", closed: "#34A853",
};
const ZONE_COLOR: Record<string, string> = {
  public: "#EA4335", dmz: "#FF7043", private: "#4285F4",
  "data-tier": "#9C27B0", management: "#34A853",
};

function prettyCat(s: string): string {
  return (s || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function ThreatModelDetail() {
  const { modelId } = useParams<{ modelId: string }>();
  const [search] = useSearchParams();
  const clientId = search.get("client") || "";
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [tab, setTab] = useState<string>("diagram");
  // Diagram-renderer toggle: 'mermaid' (built-in, fast) | 'drawio' (rich, editable)
  const [diagramMode, setDiagramMode] = useState<"mermaid" | "drawio">("mermaid");
  // Phase 9B — diagram VIEW (overlay lens for the Mermaid renderer).
  const [diagramView, setDiagramView] = useState<"architecture" | "threat_heat" | "detection_coverage">("architecture");
  // When the browser triggers print (button or Ctrl+P), expand every tab
  // section so the whole threat model — Diagram + Components + Threats +
  // Mitigations — renders as a single paginated PDF.
  const [printing, setPrinting] = useState<boolean>(false);
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

  // Lazy-load draw.io XML only when the user picks that diagram mode — the
  // server-side render is cheap but we don't want to ship it for every
  // page load.
  const drawioQuery = useQuery<{ xml: string; filename: string }>({
    queryKey: ["threat-model-drawio", modelId],
    queryFn: () => threatModelsApi.drawioXml(clientId, modelId!),
    enabled: !!modelId && !!clientId && diagramMode === "drawio" && data?.status === "completed",
    staleTime: 60_000,
  });

  // Phase 9B — styled Mermaid for the selected view lens. The architecture
  // view falls back to the canonical dfd_mermaid; threat_heat and
  // detection_coverage hit the server endpoint that appends style overlays.
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
    mutationFn: () => threatModelsApi.fillGaps(clientId, modelId!),
    onSuccess: (resp: any) => {
      qc.invalidateQueries({ queryKey: ["threat-model-detail", modelId] });
      toast.success(resp?.message || `Filled ${resp?.filled ?? 0} cells`);
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || "Gap-fill failed"),
  });

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
          body { background: white !important; color: black !important; }
          .MuiDrawer-root, .MuiAppBar-root, .no-print { display: none !important; }
          .tm-print-area, .tm-print-area * { color: #1a1a1a !important; background: white !important;
            border-color: rgba(0,0,0,0.15) !important; box-shadow: none !important; }
          .tm-print-area .MuiCard-root,
          .tm-print-area .MuiCardContent-root { background: white !important; }
          .tm-print-area .MuiChip-root {
            background: rgba(0,0,0,0.05) !important;
            color: #1a1a1a !important;
            border: 1px solid rgba(0,0,0,0.1) !important;
          }
          /* Mermaid SVG ships with inline fills — let it render in its own
             palette instead of being washed out by the global * { background:
             white } rule above. */
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
        <Tooltip title={inFlight ? "Re-model disabled while generating" : "Re-model — keeps history"}>
          <span>
            <Button startIcon={<Replay />} size="small" disabled={inFlight || rescanMutation.isPending}
              onClick={() => rescanMutation.mutate()}
              sx={{ color: "text.secondary" }}>
              Re-model
            </Button>
          </span>
        </Tooltip>
        <Button
          startIcon={<Print />}
          size="small"
          onClick={() => {
            // Open the server-rendered deliverable in a new tab; it auto-prints.
            const w = window.open(threatModelsApi.pdfUrl(clientId, modelId!), "_blank");
            if (!w) window.print();
          }}
          sx={{ color: "text.secondary" }}
        >
          Print / PDF
        </Button>
      </Box>

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

      <Tabs value={tab} onChange={(_, v) => setTab(v)}
        className="no-print"
        sx={{
          borderBottom: "1px solid rgba(255,255,255,0.08)", mb: 2,
          "& .MuiTab-root": { color: "text.secondary", textTransform: "none", fontWeight: 600 },
          "& .Mui-selected": { color: "#4285F4" },
          "& .MuiTabs-indicator": { backgroundColor: "#4285F4" },
        }}>
        <Tab value="diagram" label="Diagram" />
        <Tab value="components" label={`Components (${data.component_count})`} />
        <Tab value="threats" label={`Threats (${data.threat_count})`} />
        <Tab value="coverage" label="Coverage" />
        <Tab value="maturity" label="Maturity" />
        <Tab value="mitigations" label={`Mitigations (${data.mitigation_count})`} />
      </Tabs>

      {/* DIAGRAM */}
      {(tab === "diagram" || printing) && (
        <Box className="tm-print-section" sx={{ mb: printing ? 2 : 0 }}>
          {printing && <Typography className="tm-print-section-heading">Data Flow Diagram</Typography>}
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Box className="no-print" sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1.5, flexWrap: "wrap", gap: 1 }}>
              <Box sx={{ display: "flex", gap: 0.5, p: 0.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1.5 }}>
                <Button
                  size="small"
                  startIcon={<Hub sx={{ fontSize: 16 }} />}
                  onClick={() => setDiagramMode("mermaid")}
                  sx={{
                    minWidth: 120, color: diagramMode === "mermaid" ? "white" : "rgba(255,255,255,0.55)",
                    bgcolor: diagramMode === "mermaid" ? "rgba(66,133,244,0.18)" : "transparent",
                    textTransform: "none", fontSize: 12, fontWeight: 600,
                    "&:hover": { bgcolor: diagramMode === "mermaid" ? "rgba(66,133,244,0.25)" : "rgba(255,255,255,0.06)" },
                  }}
                >Mermaid</Button>
                <Button
                  size="small"
                  startIcon={<Schema sx={{ fontSize: 16 }} />}
                  onClick={() => setDiagramMode("drawio")}
                  disabled={data.status !== "completed"}
                  sx={{
                    minWidth: 120, color: diagramMode === "drawio" ? "white" : "rgba(255,255,255,0.55)",
                    bgcolor: diagramMode === "drawio" ? "rgba(66,133,244,0.18)" : "transparent",
                    textTransform: "none", fontSize: 12, fontWeight: 600,
                    "&:hover": { bgcolor: diagramMode === "drawio" ? "rgba(66,133,244,0.25)" : "rgba(255,255,255,0.06)" },
                  }}
                >draw.io</Button>
              </Box>
              <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap" }}>
                {/* Phase 9B — view-lens toggle, only meaningful in Mermaid mode */}
                {diagramMode === "mermaid" && data.status === "completed" && (
                  <Box sx={{ display: "flex", gap: 0.5, p: 0.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1.5 }}>
                    {(
                      [
                        { v: "architecture", label: "Architecture", color: "#4285F4" },
                        { v: "threat_heat", label: "Threat heat", color: "#EA4335" },
                        { v: "detection_coverage", label: "Detections", color: "#34A853" },
                      ] as Array<{ v: typeof diagramView; label: string; color: string }>
                    ).map((opt) => {
                      const active = diagramView === opt.v;
                      return (
                        <Button
                          key={opt.v}
                          size="small"
                          onClick={() => setDiagramView(opt.v)}
                          sx={{
                            minWidth: 102, color: active ? "white" : "rgba(255,255,255,0.55)",
                            bgcolor: active ? `${opt.color}33` : "transparent",
                            border: active ? `1px solid ${opt.color}` : "1px solid transparent",
                            textTransform: "none", fontSize: 11.5, fontWeight: 600,
                            "&:hover": { bgcolor: active ? `${opt.color}44` : "rgba(255,255,255,0.06)" },
                          }}
                        >{opt.label}</Button>
                      );
                    })}
                  </Box>
                )}
                <Button
                  size="small"
                  startIcon={<Download sx={{ fontSize: 16 }} />}
                  href={threatModelsApi.drawioDownloadUrl(clientId, modelId!)}
                  disabled={data.status !== "completed"}
                  sx={{
                    textTransform: "none", fontSize: 12, fontWeight: 600,
                    color: "text.secondary",
                    border: "1px solid rgba(255,255,255,0.12)",
                    "&:hover": { bgcolor: "rgba(255,255,255,0.06)", borderColor: "divider" },
                  }}
                >Download .drawio</Button>
              </Box>
            </Box>
            {(diagramMode === "mermaid" || printing) ? (
              <DfdDiagram
                source={
                  diagramView !== "architecture" && styledDfdQuery.data?.mermaid
                    ? styledDfdQuery.data.mermaid
                    : (data.dfd_mermaid || "")
                }
              />
            ) : drawioQuery.isLoading ? (
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", py: 6, gap: 1.5, color: "text.secondary" }}>
                <CircularProgress size={20} sx={{ color: "#4285F4" }} />
                <Typography variant="body2">Rendering draw.io diagram…</Typography>
              </Box>
            ) : drawioQuery.data ? (
              <DrawioDiagram xml={drawioQuery.data.xml} />
            ) : (
              <Typography variant="body2" sx={{ color: "text.secondary", py: 4, textAlign: "center" }}>
                draw.io view unavailable.
              </Typography>
            )}
            {data.data_flows.length > 0 && (
              <>
                <Divider sx={{ my: 2, borderColor: "divider" }} />
                <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, mb: 1, display: "block" }}>
                  Data flows
                </Typography>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                      <TableCell>FROM</TableCell><TableCell>TO</TableCell>
                      <TableCell>PROTOCOL</TableCell><TableCell>DATA</TableCell><TableCell>ENCRYPTED</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {data.data_flows.map((d, i) => (
                      <TableRow key={i} sx={{ "& td": { color: "text.primary", fontSize: 12.5, borderColor: "divider", py: 1 } }}>
                        <TableCell>{compName.get(d.from) || d.from}</TableCell>
                        <TableCell>{compName.get(d.to) || d.to}</TableCell>
                        <TableCell><Chip label={d.protocol} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary" }} /></TableCell>
                        <TableCell>{d.data}</TableCell>
                        <TableCell>
                          <Chip label={d.encrypted ? "TLS" : "PLAIN"} size="small"
                            sx={{ height: 18, fontSize: 10, fontWeight: 700,
                              bgcolor: d.encrypted ? "rgba(52,168,83,0.15)" : "rgba(234,67,53,0.15)",
                              color: d.encrypted ? "#34A853" : "#EA4335" }} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </>
            )}
          </CardContent>
        </Card>
        </Box>
      )}

      {/* COMPONENTS */}
      {(tab === "components" || printing) && (
        <Box className="tm-print-section" sx={{ mb: printing ? 2 : 0 }}>
          {printing && <Typography className="tm-print-section-heading">Components ({data.component_count})</Typography>}
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                  <TableCell>ID</TableCell><TableCell>NAME</TableCell><TableCell>TYPE</TableCell>
                  <TableCell>TRUST ZONE</TableCell><TableCell>CRITICALITY</TableCell><TableCell>NOTES</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.components.map((c) => {
                  const zc = ZONE_COLOR[c.trust_zone] || "rgba(255,255,255,0.4)";
                  return (
                    <TableRow key={c.id} sx={{ "& td": { color: "text.primary", fontSize: 12.5, borderColor: "divider", py: 1 } }}>
                      <TableCell sx={{ fontFamily: "monospace", color: "text.secondary" }}>{c.id}</TableCell>
                      <TableCell sx={{ fontWeight: 600 }}>{c.name}</TableCell>
                      <TableCell sx={{ color: "text.secondary" }}>{c.type}</TableCell>
                      <TableCell>
                        <Chip label={c.trust_zone} size="small"
                          sx={{ bgcolor: `${zc}20`, color: zc, height: 18, fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5, fontWeight: 700 }} />
                      </TableCell>
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
      )}

      {/* THREATS — grouped by category */}
      {(tab === "threats" || printing) && (
        <Box className="tm-print-section" sx={{ mb: printing ? 2 : 0 }}>
          {printing && <Typography className="tm-print-section-heading">Threats ({data.threat_count})</Typography>}
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
            onFillGaps={() => fillGapsMutation.mutate()}
            filling={fillGapsMutation.isPending}
          />
        </Box>
      )}

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

function CoverageMatrixView({ data, onFillGaps, filling }: { data: ThreatModelDetailData; onFillGaps?: () => void; filling?: boolean }) {
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
          <Chip label={`${missing} missing`} sx={{ bgcolor: missing > 0 ? "rgba(251,188,4,0.18)" : "rgba(255,255,255,0.04)", color: missing > 0 ? "#FBBC04" : "rgba(255,255,255,0.5)", fontWeight: 700, height: 22, fontSize: 11 }} />
          {missing > 0 && onFillGaps && (
            <Tooltip title={`Run a targeted LLM call against the ${missing} missing cells — each one resolves to either a threat or a 'considered' decision.`}>
              <span>
                <Button
                  size="small"
                  variant="contained"
                  className="no-print"
                  startIcon={filling ? <CircularProgress size={14} sx={{ color: "text.primary" }} /> : <AutoFixHigh sx={{ fontSize: 16 }} />}
                  disabled={filling}
                  onClick={onFillGaps}
                  sx={{ bgcolor: "#FBBC04", color: "#1A1A1A", textTransform: "none", fontWeight: 700, fontSize: 11, height: 26,
                    "&:hover": { bgcolor: "#FFC53D" } }}
                >
                  {filling ? "Filling…" : `Fill ${missing} gap${missing === 1 ? "" : "s"}`}
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
                  return (
                    <Tooltip key={cat} title={d.rationale || (d.state === "threat" ? `Threat ${d.threat_id}` : style.label)}>
                      <Box sx={{ p: 1, bgcolor: style.bg, borderRadius: 1, cursor: "default", minHeight: 50 }}>
                        <Typography variant="caption" sx={{ color: style.fg, fontWeight: 700, fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5, display: "block" }}>
                          {style.label}
                        </Typography>
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
