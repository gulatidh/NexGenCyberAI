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
  TableBody, Divider, Tooltip,
} from "@mui/material";
import { ArrowBack, Hub, Replay, Print } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";
import { threatModelsApi } from "../services/api";
import { fromNow } from "../utils/datetime";
import DfdDiagram from "../components/DfdDiagram";

interface Component {
  id: string; name: string; type: string;
  trust_zone: string; criticality: string; notes?: string;
}
interface DataFlow { from: string; to: string; protocol: string; data: string; encrypted: boolean; notes?: string; }
interface Threat {
  id: string; category: string; asset_id: string; title: string; severity: string;
  evidence?: string; capec_refs?: string[]; attack_techniques?: string[]; rationale?: string;
}
interface Mitigation {
  id: string; threat_id: string; action: string;
  control_id?: string; status: string; owner?: string;
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

  const { data, isLoading, error } = useQuery<ThreatModelDetailData>({
    queryKey: ["threat-model-detail", modelId],
    queryFn: () => threatModelsApi.get(clientId, modelId!),
    enabled: !!modelId && !!clientId,
    refetchInterval: (q) => {
      const dd = q.state.data as ThreatModelDetailData | undefined;
      return dd && (dd.status === "pending" || dd.status === "generating") ? 4000 : false;
    },
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

  return (
    <Box className="tm-print-area">
      <style>{`
        @media print {
          @page { size: A4 landscape; margin: 10mm; }
          body { background: white !important; color: black !important; }
          .MuiDrawer-root, .MuiAppBar-root, .no-print { display: none !important; }
          .tm-print-area, .tm-print-area * { color: #1a1a1a !important; background: white !important;
            border-color: rgba(0,0,0,0.15) !important; box-shadow: none !important; }
          .tm-print-area .MuiCard-root { page-break-inside: avoid; }
        }
      `}</style>

      <Box className="no-print" sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
        <Button startIcon={<ArrowBack />} size="small"
          onClick={() => navigate("/threat-models")}
          sx={{ color: "rgba(255,255,255,0.6)" }}>
          Threat Models
        </Button>
        <Box sx={{ flex: 1 }} />
        <Tooltip title={inFlight ? "Re-model disabled while generating" : "Re-model — keeps history"}>
          <span>
            <Button startIcon={<Replay />} size="small" disabled={inFlight || rescanMutation.isPending}
              onClick={() => rescanMutation.mutate()}
              sx={{ color: "rgba(255,255,255,0.6)" }}>
              Re-model
            </Button>
          </span>
        </Tooltip>
        <Button startIcon={<Print />} size="small" onClick={() => window.print()}
          sx={{ color: "rgba(255,255,255,0.6)" }}>
          Print / PDF
        </Button>
      </Box>

      <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, mb: 2 }}>
        <Hub sx={{ color: "#4285F4", fontSize: 36, mt: 0.25 }} />
        <Box sx={{ flex: 1 }}>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>
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
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", alignSelf: "center", ml: 1 }}>
              {data.generated_at ? `Generated ${fromNow(data.generated_at)}` : data.created_at ? `Created ${fromNow(data.created_at)}` : ""}
              {data.ai_provider ? ` · ${data.ai_provider}${data.ai_model ? ` (${data.ai_model})` : ""}` : ""}
            </Typography>
          </Box>
        </Box>
      </Box>

      {inFlight && (
        <Box sx={{ mb: 2 }}>
          <LinearProgress sx={{ bgcolor: "rgba(66,133,244,0.1)", "& .MuiLinearProgress-bar": { bgcolor: "#4285F4" } }} />
          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", mt: 0.5, display: "block" }}>
            AI is producing the model — polling every 4 seconds.
          </Typography>
        </Box>
      )}
      {data.error_message && (
        <Alert severity="error" sx={{ mb: 2 }}>{data.error_message}</Alert>
      )}

      {data.executive_summary && (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
          <CardContent>
            <Typography variant="caption" sx={{ color: "#4285F4", fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase", display: "block", mb: 1 }}>
              Executive summary
            </Typography>
            <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.88)", lineHeight: 1.6 }}>
              {data.executive_summary}
            </Typography>
          </CardContent>
        </Card>
      )}

      <Tabs value={tab} onChange={(_, v) => setTab(v)}
        sx={{
          borderBottom: "1px solid rgba(255,255,255,0.08)", mb: 2,
          "& .MuiTab-root": { color: "rgba(255,255,255,0.6)", textTransform: "none", fontWeight: 600 },
          "& .Mui-selected": { color: "#4285F4" },
          "& .MuiTabs-indicator": { backgroundColor: "#4285F4" },
        }}>
        <Tab value="diagram" label="Diagram" />
        <Tab value="components" label={`Components (${data.component_count})`} />
        <Tab value="threats" label={`Threats (${data.threat_count})`} />
        <Tab value="mitigations" label={`Mitigations (${data.mitigation_count})`} />
      </Tabs>

      {/* DIAGRAM */}
      {tab === "diagram" && (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <DfdDiagram source={data.dfd_mermaid || ""} />
            {data.data_flows.length > 0 && (
              <>
                <Divider sx={{ my: 2, borderColor: "rgba(255,255,255,0.06)" }} />
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.55)", fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, mb: 1, display: "block" }}>
                  Data flows
                </Typography>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.06)" } }}>
                      <TableCell>FROM</TableCell><TableCell>TO</TableCell>
                      <TableCell>PROTOCOL</TableCell><TableCell>DATA</TableCell><TableCell>ENCRYPTED</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {data.data_flows.map((d, i) => (
                      <TableRow key={i} sx={{ "& td": { color: "white", fontSize: 12.5, borderColor: "rgba(255,255,255,0.05)", py: 1 } }}>
                        <TableCell>{compName.get(d.from) || d.from}</TableCell>
                        <TableCell>{compName.get(d.to) || d.to}</TableCell>
                        <TableCell><Chip label={d.protocol} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.75)" }} /></TableCell>
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
      )}

      {/* COMPONENTS */}
      {tab === "components" && (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.06)" } }}>
                  <TableCell>ID</TableCell><TableCell>NAME</TableCell><TableCell>TYPE</TableCell>
                  <TableCell>TRUST ZONE</TableCell><TableCell>CRITICALITY</TableCell><TableCell>NOTES</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.components.map((c) => {
                  const zc = ZONE_COLOR[c.trust_zone] || "rgba(255,255,255,0.4)";
                  return (
                    <TableRow key={c.id} sx={{ "& td": { color: "white", fontSize: 12.5, borderColor: "rgba(255,255,255,0.05)", py: 1 } }}>
                      <TableCell sx={{ fontFamily: "monospace", color: "rgba(255,255,255,0.6)" }}>{c.id}</TableCell>
                      <TableCell sx={{ fontWeight: 600 }}>{c.name}</TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.7)" }}>{c.type}</TableCell>
                      <TableCell>
                        <Chip label={c.trust_zone} size="small"
                          sx={{ bgcolor: `${zc}20`, color: zc, height: 18, fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5, fontWeight: 700 }} />
                      </TableCell>
                      <TableCell>
                        <Chip label={c.criticality} size="small"
                          sx={{ bgcolor: `${SEV_COLOR[c.criticality] || "#888"}20`,
                            color: SEV_COLOR[c.criticality] || "#888", height: 18, fontSize: 10, textTransform: "uppercase", fontWeight: 700 }} />
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.6)" }}>{c.notes || "—"}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            {data.components.length === 0 && (
              <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.4)", textAlign: "center", py: 4 }}>
                No components yet.
              </Typography>
            )}
          </CardContent>
        </Card>
      )}

      {/* THREATS — grouped by category */}
      {tab === "threats" && (
        <>
          {Object.keys(threatsByCat).length === 0 ? (
            <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.15)", borderRadius: 2, p: 4, textAlign: "center" }}>
              <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
                No threats produced yet.
              </Typography>
            </Card>
          ) : (
            Object.entries(threatsByCat).map(([cat, list]) => (
              <Card key={cat} sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 1.5 }}>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                    <Typography sx={{ color: "white", fontSize: 14, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5 }}>
                      {prettyCat(cat)}
                    </Typography>
                    <Chip label={list.length} size="small" sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", height: 18, fontSize: 10, fontWeight: 700 }} />
                  </Box>
                  {list.map((t) => {
                    const sc = SEV_COLOR[t.severity] || "rgba(255,255,255,0.4)";
                    const ms = mitigationsByThreat[t.id] || [];
                    return (
                      <Box key={t.id} sx={{ borderTop: "1px solid rgba(255,255,255,0.06)", py: 1.25 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5, flexWrap: "wrap" }}>
                          <Typography sx={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontFamily: "monospace", minWidth: 40 }}>{t.id}</Typography>
                          <Chip label={t.severity} size="small"
                            sx={{ bgcolor: `${sc}20`, color: sc, height: 18, fontSize: 10, textTransform: "uppercase", fontWeight: 700 }} />
                          <Typography sx={{ color: "white", fontSize: 13.5, fontWeight: 600, flex: 1 }}>{t.title}</Typography>
                          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.45)" }}>
                            on <b>{compName.get(t.asset_id) || t.asset_id || "—"}</b>
                          </Typography>
                        </Box>
                        {t.rationale && (
                          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.7)", display: "block", lineHeight: 1.5, mb: 0.75 }}>
                            {t.rationale}
                          </Typography>
                        )}
                        <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                          {(t.capec_refs || []).map((c) => (
                            <Chip key={c} label={c} size="small" sx={{ height: 16, fontSize: 9.5, bgcolor: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.7)" }} />
                          ))}
                          {(t.attack_techniques || []).map((a) => (
                            <Chip key={a} label={`ATT&CK ${a}`} size="small" sx={{ height: 16, fontSize: 9.5, bgcolor: "rgba(124,77,255,0.15)", color: "#9C27B0" }} />
                          ))}
                          {t.evidence && (
                            <Chip label={`Evidence: ${t.evidence}`} size="small" sx={{ height: 16, fontSize: 9.5, bgcolor: "rgba(251,188,4,0.12)", color: "#FBBC04" }} />
                          )}
                        </Box>
                        {ms.length > 0 && (
                          <Box sx={{ mt: 0.75, ml: 1, borderLeft: "2px solid rgba(52,168,83,0.4)", pl: 1.25 }}>
                            {ms.map((m) => (
                              <Box key={m.id} sx={{ mb: 0.25 }}>
                                <Typography variant="caption" sx={{ color: "#34A853", fontWeight: 700 }}>
                                  {m.id}: </Typography>
                                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.85)" }}>{m.action}</Typography>
                                {m.control_id && (
                                  <Chip label={m.control_id} size="small" sx={{ ml: 1, height: 14, fontSize: 9, bgcolor: "rgba(124,77,255,0.15)", color: "#9C27B0" }} />
                                )}
                              </Box>
                            ))}
                          </Box>
                        )}
                      </Box>
                    );
                  })}
                </CardContent>
              </Card>
            ))
          )}
        </>
      )}

      {/* MITIGATIONS */}
      {tab === "mitigations" && (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.06)" } }}>
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
                    <TableRow key={m.id} sx={{ "& td": { color: "white", fontSize: 12.5, borderColor: "rgba(255,255,255,0.05)", py: 1 } }}>
                      <TableCell sx={{ fontFamily: "monospace", color: "rgba(255,255,255,0.6)" }}>{m.id}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", color: "rgba(255,255,255,0.6)" }}>{m.threat_id}</TableCell>
                      <TableCell sx={{ maxWidth: 420 }}>{m.action}</TableCell>
                      <TableCell>{m.control_id ? <Chip label={m.control_id} size="small" sx={{ height: 18, fontSize: 10, bgcolor: "rgba(124,77,255,0.15)", color: "#9C27B0" }} /> : "—"}</TableCell>
                      <TableCell>
                        <Chip label={m.status.replace(/_/g, " ")} size="small"
                          sx={{ bgcolor: `${st}20`, color: st, height: 18, fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5, fontWeight: 700 }} />
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.7)" }}>{m.owner || "—"}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            {data.mitigations.length === 0 && (
              <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.4)", textAlign: "center", py: 4 }}>
                No mitigations yet.
              </Typography>
            )}
          </CardContent>
        </Card>
      )}
    </Box>
  );
}
