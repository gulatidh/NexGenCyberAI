import React, { useMemo, useRef, useState } from "react";
import {
  Box, Typography, Card, Chip, CircularProgress, Button,
  FormControl, InputLabel, Select, MenuItem, Alert, TextField,
  Drawer, IconButton, Accordion, AccordionSummary, AccordionDetails,
  Table, TableHead, TableRow, TableCell, TableBody, Divider, Tooltip,
  Dialog, DialogTitle, DialogContent, DialogActions, Radio, RadioGroup,
  FormControlLabel, Checkbox, Tabs, Tab,
} from "@mui/material";
import { ExpandMore, Refresh, Close, RestartAlt, UploadFile, PlayArrow } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { clientsApi, connectorsApi, frameworksApi, projectsApi, scansApi } from "../services/api";
import {
  Client, Connector, ControlStatus, ControlStatusEntry, FrameworkCatalogEntry,
  FrameworkDetail, Project,
} from "../types";
import { fromNow } from "../utils/datetime";

const STATUS_COLOR: Record<ControlStatus, string> = {
  compliant: "#00e676",
  non_compliant: "#f44336",
  partial: "#ff9800",
  not_applicable: "rgba(255,255,255,0.4)",
};
const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#4285F4",
};
const STATUS_LABEL: Record<ControlStatus, string> = {
  compliant: "Compliant",
  non_compliant: "Non-compliant",
  partial: "Partial",
  not_applicable: "N/A",
};
const STATUS_ORDER: ControlStatus[] = ["compliant", "non_compliant", "partial", "not_applicable"];

// Framework families — derived from framework key/name so the list scales as we add benchmarks.
// New families fall under "Other" automatically.
const FAMILY_ORDER = ["CIS", "NIST", "OWASP", "Standards", "Other"] as const;
type FrameworkFamily = typeof FAMILY_ORDER[number];

function getFrameworkFamily(key: string, name?: string): FrameworkFamily {
  const k = key.toLowerCase();
  const n = (name || "").toLowerCase();
  if (k.startsWith("cis_") || k === "cis_v8" || n.startsWith("cis ")) return "CIS";
  if (k.startsWith("nist_") || n.startsWith("nist")) return "NIST";
  if (k.startsWith("zap_") || n.includes("owasp") || n.includes("zap")) return "OWASP";
  if (["gdpr", "iso_27001", "soc2", "pci_dss"].includes(k)) return "Standards";
  return "Other";
}

function ScoreDonut({ score, size = 110 }: { score: number; size?: number }) {
  const r = (size - 12) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (score / 100) * c;
  const color = score >= 80 ? "#00e676" : score >= 50 ? "#ff9800" : "#f44336";
  return (
    <Box sx={{ position: "relative", width: size, height: size }}>
      <svg width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={r} stroke="rgba(255,255,255,0.08)" strokeWidth={10} fill="none" />
        <circle cx={size / 2} cy={size / 2} r={r} stroke={color} strokeWidth={10} fill="none"
          strokeDasharray={c} strokeDashoffset={offset} strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`} />
      </svg>
      <Box sx={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column" }}>
        <Typography sx={{ color: "white", fontSize: 22, fontWeight: 700, lineHeight: 1 }}>{score.toFixed(0)}</Typography>
        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontSize: 10 }}>SCORE</Typography>
      </Box>
    </Box>
  );
}

export default function Frameworks() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [clientId, setClientId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [framework, setFramework] = useState("");
  const [family, setFamily] = useState<FrameworkFamily>("CIS");
  const [statusFilter, setStatusFilter] = useState<ControlStatus | "">("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<ControlStatusEntry | null>(null);
  const [evidenceDraft, setEvidenceDraft] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Scan dialog state
  const [scanOpen, setScanOpen] = useState(false);
  const [scanConnectorId, setScanConnectorId] = useState("");
  const [scanScope, setScanScope] = useState<"full" | "selected" | "failing" | "custom">("full");
  const [scanCustomIds, setScanCustomIds] = useState("");

  // Row-multiselect state — control_ids the user has ticked
  const [selectedControlIds, setSelectedControlIds] = useState<Set<string>>(new Set());

  // Reset selection when client or framework changes
  React.useEffect(() => { setSelectedControlIds(new Set()); }, [clientId, framework]);

  const toggleControl = (controlId: string) => {
    setSelectedControlIds((prev) => {
      const next = new Set(prev);
      if (next.has(controlId)) next.delete(controlId); else next.add(controlId);
      return next;
    });
  };

  const toggleDomain = (items: ControlStatusEntry[], allChecked: boolean) => {
    setSelectedControlIds((prev) => {
      const next = new Set(prev);
      for (const i of items) {
        if (allChecked) next.delete(i.control.control_id);
        else next.add(i.control.control_id);
      }
      return next;
    });
  };

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", clientId],
    queryFn: () => projectsApi.list(clientId),
    enabled: !!clientId,
  });
  const { data: catalog = [] } = useQuery<FrameworkCatalogEntry[]>({
    queryKey: ["framework-catalog"],
    queryFn: frameworksApi.catalog,
  });
  const { data: detail, isLoading } = useQuery<FrameworkDetail>({
    queryKey: ["framework-detail", clientId, framework],
    queryFn: () => frameworksApi.forClient(clientId, framework),
    enabled: !!clientId && !!framework,
  });

  const recomputeMutation = useMutation({
    mutationFn: () => frameworksApi.recompute(clientId, framework),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["framework-detail", clientId, framework] }),
  });

  const overrideMutation = useMutation({
    mutationFn: ({ controlId, body }: { controlId: string; body: any }) =>
      frameworksApi.override(clientId, framework, controlId, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["framework-detail", clientId, framework] });
      setSelected(null);
    },
  });

  const resetOverrideMutation = useMutation({
    mutationFn: (controlId: string) => frameworksApi.resetOverride(clientId, framework, controlId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["framework-detail", clientId, framework] });
      setSelected(null);
    },
  });

  const importMutation = useMutation({
    mutationFn: (file: File) => frameworksApi.importControls(framework, file),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["framework-detail", clientId, framework] });
      qc.invalidateQueries({ queryKey: ["framework-catalog"] });
    },
  });

  const { data: connectors = [] } = useQuery<Connector[]>({
    queryKey: ["connectors", clientId, projectId],
    queryFn: () => connectorsApi.list(clientId, projectId || undefined),
    enabled: !!clientId,
  });

  const scanMutation = useMutation({
    mutationFn: (body: { connector_id?: string; framework: string; control_ids?: string[] }) =>
      scansApi.startFrameworkScan(clientId, body),
    onSuccess: () => {
      // Compliance recompute fires once the scan finishes; refetch a few times.
      [4000, 12000, 30000].forEach((ms) =>
        setTimeout(() => qc.invalidateQueries({ queryKey: ["framework-detail", clientId, framework] }), ms),
      );
      setScanOpen(false);
    },
  });

  const failingControlIds = useMemo(() => {
    if (!detail) return [];
    return detail.controls
      .filter((c) => c.control.weight > 0 && (c.status === "non_compliant" || c.status === "partial"))
      .map((c) => c.control.control_id);
  }, [detail]);

  const submitScan = () => {
    let control_ids: string[] | undefined;
    if (scanScope === "failing") {
      control_ids = failingControlIds;
    } else if (scanScope === "selected") {
      control_ids = Array.from(selectedControlIds);
    } else if (scanScope === "custom") {
      control_ids = scanCustomIds
        .split(/[\s,;\n]+/)
        .map((s) => s.trim())
        .filter(Boolean);
    }
    scanMutation.mutate({
      framework,
      connector_id: scanConnectorId || undefined,
      control_ids,
    });
  };

  const openScanForSelected = () => {
    setScanScope("selected");
    setScanConnectorId("");
    setScanCustomIds("");
    setScanOpen(true);
  };

  // Group catalog entries by family — used to render family tabs and to filter
  // the framework dropdown to the active family. Empty families are hidden.
  const familyCounts = useMemo(() => {
    const counts = new Map<FrameworkFamily, number>();
    for (const entry of catalog) {
      const fam = getFrameworkFamily(entry.framework, entry.name);
      counts.set(fam, (counts.get(fam) || 0) + 1);
    }
    return counts;
  }, [catalog]);

  const availableFamilies = useMemo(
    () => FAMILY_ORDER.filter((f) => (familyCounts.get(f) || 0) > 0),
    [familyCounts],
  );

  const filteredCatalog = useMemo(
    () => catalog.filter((f) => getFrameworkFamily(f.framework, f.name) === family),
    [catalog, family],
  );

  // If the catalog loads and the default family ("CIS") has no entries, fall
  // back to the first available family. Also reset framework when family
  // changes so the dropdown doesn't show a value from a hidden family.
  React.useEffect(() => {
    if (availableFamilies.length === 0) return;
    if (!availableFamilies.includes(family)) {
      setFamily(availableFamilies[0]);
      setFramework("");
    }
  }, [availableFamilies, family]);

  React.useEffect(() => {
    if (framework && !filteredCatalog.some((f) => f.framework === framework)) {
      setFramework("");
    }
  }, [filteredCatalog, framework]);

  const grouped = useMemo(() => {
    if (!detail) return new Map<string, ControlStatusEntry[]>();
    const out = new Map<string, ControlStatusEntry[]>();
    for (const item of detail.controls) {
      // Skip top-level (functions/families/control 1-18) headers in the table — they're the group keys
      if (item.control.weight === 0) continue;
      // Filter
      if (statusFilter && item.status !== statusFilter) continue;
      if (search) {
        const s = search.toLowerCase();
        const hay = `${item.control.control_id} ${item.control.title} ${item.control.description || ""}`.toLowerCase();
        if (!hay.includes(s)) continue;
      }
      const domain = item.control.domain || "Other";
      if (!out.has(domain)) out.set(domain, []);
      out.get(domain)!.push(item);
    }
    return out;
  }, [detail, statusFilter, search]);

  const summary = detail?.summary;

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Frameworks</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            Compliance posture against industry frameworks
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
            <Select value={clientId} onChange={(e) => { setClientId(e.target.value); setProjectId(""); }} label="Client"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!clientId}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Project</InputLabel>
            <Select value={projectId} onChange={(e) => setProjectId(e.target.value)} label="Project"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 240 }} disabled={!clientId}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Framework</InputLabel>
            <Select value={framework} onChange={(e) => setFramework(e.target.value)} label="Framework"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {filteredCatalog.map((f) => (
                <MenuItem key={f.framework} value={f.framework}>
                  {f.name} ({f.total_controls})
                </MenuItem>
              ))}
              {filteredCatalog.length === 0 && (
                <MenuItem disabled value="">
                  No frameworks in this family
                </MenuItem>
              )}
            </Select>
          </FormControl>
          <Button variant="contained" startIcon={<PlayArrow />}
            disabled={!clientId || !framework || scanMutation.isPending}
            onClick={() => { setScanOpen(true); setScanConnectorId(""); setScanScope("full"); setScanCustomIds(""); }}
            sx={{ bgcolor: "#4285F4", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}>
            Scan
          </Button>
          <Button variant="outlined" startIcon={<Refresh />}
            disabled={!clientId || !framework || recomputeMutation.isPending}
            onClick={() => recomputeMutation.mutate()}
            sx={{ borderColor: "#4285F4", color: "#4285F4" }}>
            Recompute
          </Button>
          <Tooltip title="Upload CSV/JSON of controls (e.g. CIS XLSX export converted to CSV)">
            <span>
              <Button variant="outlined" startIcon={importMutation.isPending ? <CircularProgress size={14} sx={{ color: "#34A853" }} /> : <UploadFile />}
                disabled={!framework || importMutation.isPending}
                onClick={() => fileInputRef.current?.click()}
                sx={{ borderColor: "#34A853", color: "#34A853" }}>
                Upload Controls
              </Button>
            </span>
          </Tooltip>
          <input ref={fileInputRef} type="file" hidden accept=".csv,.json"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) importMutation.mutate(f);
              if (fileInputRef.current) fileInputRef.current.value = "";
            }} />
        </Box>
      </Box>

      {/* Family tabs — keeps the framework dropdown short by grouping benchmarks
          (CIS, NIST, etc.) into their own tabs. New families auto-appear. */}
      {availableFamilies.length > 1 && (
        <Box sx={{ mb: 2, borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          <Tabs
            value={family}
            onChange={(_, v) => setFamily(v as FrameworkFamily)}
            textColor="inherit"
            indicatorColor="primary"
            sx={{
              "& .MuiTab-root": { color: "rgba(255,255,255,0.6)", textTransform: "none", fontWeight: 600 },
              "& .Mui-selected": { color: "#4285F4" },
            }}
          >
            {availableFamilies.map((f) => (
              <Tab
                key={f}
                value={f}
                label={
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    {f}
                    <Chip
                      size="small"
                      label={familyCounts.get(f) || 0}
                      sx={{
                        height: 18,
                        fontSize: 10,
                        fontWeight: 700,
                        bgcolor: family === f ? "rgba(66,133,244,0.15)" : "rgba(255,255,255,0.08)",
                        color: family === f ? "#4285F4" : "rgba(255,255,255,0.7)",
                      }}
                    />
                  </Box>
                }
              />
            ))}
          </Tabs>
        </Box>
      )}

      {importMutation.isSuccess && importMutation.data && (
        <Alert severity="success" sx={{ mb: 2, bgcolor: "rgba(0,230,118,0.1)", color: "white" }}
          onClose={() => importMutation.reset()}>
          Imported {importMutation.data.total_uploaded} rows ({importMutation.data.created} new, {importMutation.data.updated} updated).
        </Alert>
      )}
      {importMutation.isError && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => importMutation.reset()}>
          Import failed: {(importMutation.error as any)?.response?.data?.detail || (importMutation.error as any)?.message}
        </Alert>
      )}

      {!clientId || !framework ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "white" }}>
          Select a client and a framework to view the control catalog and compliance status.
        </Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>
      ) : summary ? (
        <>
          {/* Summary banner */}
          <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, p: 2, mb: 2,
            display: "flex", alignItems: "center", gap: 3, flexWrap: "wrap" }}>
            <ScoreDonut score={summary.score} />
            <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
              {STATUS_ORDER.map((s) => (
                <Box key={s}>
                  <Typography variant="caption" sx={{ color: STATUS_COLOR[s], fontSize: 11, fontWeight: 600 }}>
                    {STATUS_LABEL[s].toUpperCase()}
                  </Typography>
                  <Typography sx={{ color: "white", fontSize: 28, fontWeight: 700, lineHeight: 1 }}>
                    {summary[s as keyof typeof summary] as number}
                  </Typography>
                </Box>
              ))}
              <Box>
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600 }}>
                  TOTAL
                </Typography>
                <Typography sx={{ color: "white", fontSize: 28, fontWeight: 700, lineHeight: 1 }}>
                  {summary.total}
                </Typography>
              </Box>
            </Box>
            {summary.last_evaluated_at && (
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", ml: "auto" }}>
                Last evaluated {fromNow(summary.last_evaluated_at)}
              </Typography>
            )}
          </Card>

          {/* Filters */}
          <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap", alignItems: "center" }}>
            <Chip label={`All`} size="small" clickable
              onClick={() => setStatusFilter("")}
              sx={{ bgcolor: !statusFilter ? "rgba(66,133,244,0.2)" : "rgba(255,255,255,0.05)",
                color: "white", border: !statusFilter ? "1px solid #4285F4" : "none" }} />
            {STATUS_ORDER.map((s) => (
              <Chip key={s} label={STATUS_LABEL[s]} size="small" clickable
                onClick={() => setStatusFilter(statusFilter === s ? "" : s)}
                sx={{
                  bgcolor: `${STATUS_COLOR[s]}${statusFilter === s ? "40" : "20"}`,
                  color: STATUS_COLOR[s],
                  border: statusFilter === s ? `1px solid ${STATUS_COLOR[s]}` : "none",
                }} />
            ))}
            <TextField size="small" placeholder="Search controls…" value={search}
              onChange={(e) => setSearch(e.target.value)}
              sx={{ minWidth: 220, ml: "auto",
                "& .MuiOutlinedInput-root": { color: "white", "& fieldset": { borderColor: "rgba(255,255,255,0.2)" } },
                "& input::placeholder": { color: "rgba(255,255,255,0.4)" } }} />
          </Box>

          {/* Selection toolbar — appears when at least one row is ticked */}
          {selectedControlIds.size > 0 && (
            <Card sx={{ bgcolor: "rgba(66,133,244,0.08)", border: "1px solid rgba(66,133,244,0.3)", borderRadius: 2,
              p: 1.5, mb: 2, display: "flex", alignItems: "center", gap: 2 }}>
              <Typography sx={{ color: "#4285F4", fontWeight: 600 }}>
                {selectedControlIds.size} control{selectedControlIds.size === 1 ? "" : "s"} selected
              </Typography>
              <Box sx={{ flex: 1 }} />
              <Button size="small" onClick={() => setSelectedControlIds(new Set())}
                sx={{ color: "rgba(255,255,255,0.6)" }}>Clear</Button>
              <Button size="small" variant="contained" startIcon={<PlayArrow />}
                onClick={openScanForSelected}
                sx={{ bgcolor: "#4285F4", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}>
                Scan Selected
              </Button>
            </Card>
          )}

          {/* Grouped accordions */}
          {Array.from(grouped.entries()).length === 0 ? (
            <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
              <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>No controls match the current filters.</Typography>
            </Card>
          ) : (
            Array.from(grouped.entries()).map(([domain, items]) => {
              const compl = items.filter((i) => i.status === "compliant").length;
              const domainSelectedCount = items.filter((i) => selectedControlIds.has(i.control.control_id)).length;
              const allDomainSelected = domainSelectedCount === items.length && items.length > 0;
              const someDomainSelected = domainSelectedCount > 0 && !allDomainSelected;
              return (
                <Accordion key={domain} defaultExpanded
                  sx={{ bgcolor: "#1E1E1E", color: "white", border: "1px solid rgba(255,255,255,0.08)", mb: 1, "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMore sx={{ color: "rgba(255,255,255,0.5)" }} />}>
                    <Typography sx={{ flexGrow: 1, fontWeight: 600 }}>{domain}</Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", mr: 2 }}>
                      {compl}/{items.length} compliant
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ p: 0 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
                          <TableCell sx={{ width: 42, p: 0, pl: 1 }}>
                            <Checkbox size="small"
                              checked={allDomainSelected}
                              indeterminate={someDomainSelected}
                              onChange={() => toggleDomain(items, allDomainSelected)}
                              onClick={(e) => e.stopPropagation()}
                              sx={{ color: "rgba(255,255,255,0.4)", "&.Mui-checked": { color: "#4285F4" }, "&.MuiCheckbox-indeterminate": { color: "#4285F4" } }} />
                          </TableCell>
                          <TableCell sx={{ width: 110 }}>CONTROL</TableCell>
                          <TableCell>TITLE</TableCell>
                          <TableCell sx={{ width: 130 }}>STATUS</TableCell>
                          <TableCell sx={{ width: 90 }}>SOURCE</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {items.map((item) => {
                          const checked = selectedControlIds.has(item.control.control_id);
                          return (
                            <TableRow key={item.control.id}
                              sx={{ cursor: "pointer", "&:hover": { bgcolor: "rgba(255,255,255,0.03)" },
                                bgcolor: checked ? "rgba(66,133,244,0.06)" : "transparent",
                                "& td": { borderColor: "rgba(255,255,255,0.05)", py: 1 } }}
                              onClick={() => { setSelected(item); setEvidenceDraft(item.evidence || ""); }}>
                              <TableCell sx={{ p: 0, pl: 1 }} onClick={(e) => { e.stopPropagation(); toggleControl(item.control.control_id); }}>
                                <Checkbox size="small" checked={checked}
                                  sx={{ color: "rgba(255,255,255,0.4)", "&.Mui-checked": { color: "#4285F4" } }} />
                              </TableCell>
                              <TableCell sx={{ color: "#4285F4", fontFamily: "monospace", fontSize: 12 }}>
                                {item.control.control_id}
                              </TableCell>
                              <TableCell sx={{ color: "white", fontSize: 13, maxWidth: 600 }}>
                                <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                  {item.control.title}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                <Chip label={STATUS_LABEL[item.status]} size="small"
                                  sx={{ bgcolor: `${STATUS_COLOR[item.status]}20`, color: STATUS_COLOR[item.status],
                                    fontSize: 10, height: 18 }} />
                              </TableCell>
                              <TableCell sx={{ color: "rgba(255,255,255,0.4)", fontSize: 11 }}>
                                {item.derived ? "auto" : "override"}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </AccordionDetails>
                </Accordion>
              );
            })
          )}
        </>
      ) : null}

      {scanMutation.isSuccess && (
        <Alert severity="info" sx={{ mb: 2, bgcolor: "rgba(66,133,244,0.1)", color: "white" }}
          onClose={() => scanMutation.reset()}>
          Scan started. Compliance status will refresh automatically when it completes.
        </Alert>
      )}

      {/* Scan dialog */}
      <Dialog open={scanOpen} onClose={() => setScanOpen(false)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          Scan against framework
        </DialogTitle>
        <DialogContent sx={{ mt: 2 }}>
          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 2 }}>
            Run a connector scan and update compliance for {framework ? framework.replace(/_/g, " ").toUpperCase() : ""}.
          </Typography>

          <FormControl fullWidth size="small" sx={{ mb: 2 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Connector</InputLabel>
            <Select value={scanConnectorId} onChange={(e) => setScanConnectorId(e.target.value)} label="Connector"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {connectors.length === 0 && <MenuItem value="" disabled>No connectors configured</MenuItem>}
              {connectors.map((c) => (
                <MenuItem key={c.id} value={c.id}>{c.name} ({c.connector_type})</MenuItem>
              ))}
            </Select>
          </FormControl>

          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 1 }}>
            Scope
          </Typography>
          <RadioGroup value={scanScope} onChange={(e) => setScanScope(e.target.value as any)} sx={{ mb: 1 }}>
            <FormControlLabel value="full" control={<Radio sx={{ color: "rgba(255,255,255,0.5)" }} />}
              label={<span style={{ color: "white" }}>Full framework — every control in the catalog</span>} />
            <FormControlLabel value="selected" control={<Radio sx={{ color: "rgba(255,255,255,0.5)" }} />}
              label={<span style={{ color: "white" }}>
                Selected rows — re-scan the {selectedControlIds.size} control{selectedControlIds.size === 1 ? "" : "s"} ticked in the table
              </span>}
              disabled={selectedControlIds.size === 0} />
            <FormControlLabel value="failing" control={<Radio sx={{ color: "rgba(255,255,255,0.5)" }} />}
              label={<span style={{ color: "white" }}>Failing only — re-scan the {failingControlIds.length} non-compliant / partial controls</span>}
              disabled={failingControlIds.length === 0} />
            <FormControlLabel value="custom" control={<Radio sx={{ color: "rgba(255,255,255,0.5)" }} />}
              label={<span style={{ color: "white" }}>Custom — specific control IDs</span>} />
          </RadioGroup>

          {scanScope === "custom" && (
            <TextField multiline rows={3} fullWidth value={scanCustomIds}
              onChange={(e) => setScanCustomIds(e.target.value)}
              placeholder="e.g. 1.1.1, 3.5, 6.2  (comma, space, or newline separated)"
              sx={{
                "& .MuiOutlinedInput-root": { color: "white", "& fieldset": { borderColor: "rgba(255,255,255,0.2)" } },
                "& textarea::placeholder": { color: "rgba(255,255,255,0.4)" },
              }} />
          )}

          {scanMutation.isError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {(scanMutation.error as any)?.response?.data?.detail || (scanMutation.error as any)?.message || "Scan failed to start"}
            </Alert>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2, borderTop: "1px solid rgba(255,255,255,0.08)" }}>
          <Button onClick={() => setScanOpen(false)} sx={{ color: "rgba(255,255,255,0.6)" }}>Cancel</Button>
          <Button onClick={submitScan}
            variant="contained"
            disabled={!scanConnectorId || scanMutation.isPending ||
              (scanScope === "custom" && !scanCustomIds.trim()) ||
              (scanScope === "failing" && failingControlIds.length === 0) ||
              (scanScope === "selected" && selectedControlIds.size === 0)}
            startIcon={scanMutation.isPending ? <CircularProgress size={14} sx={{ color: "#0d1117" }} /> : <PlayArrow />}
            sx={{ bgcolor: "#4285F4", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}>
            Start Scan
          </Button>
        </DialogActions>
      </Dialog>

      {/* Detail drawer */}
      <Drawer anchor="right" open={!!selected} onClose={() => setSelected(null)}
        slotProps={{ paper: { sx: { bgcolor: "#0F0F0F", color: "white", width: { xs: "100%", sm: 480 }, p: 3 } } }}>
        {selected && (
          <Box>
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
              <Typography variant="caption" sx={{ color: "#4285F4", fontFamily: "monospace" }}>
                {selected.control.control_id}
              </Typography>
              <IconButton onClick={() => setSelected(null)} size="small" sx={{ color: "rgba(255,255,255,0.5)" }}>
                <Close />
              </IconButton>
            </Box>
            <Typography variant="h6" sx={{ color: "white", fontWeight: 600, mb: 1 }}>
              {selected.control.title}
            </Typography>
            <Chip label={selected.control.domain || "—"} size="small"
              sx={{ bgcolor: "rgba(124,77,255,0.2)", color: "#34A853", mb: 2 }} />

            {selected.control.description && (
              <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.7)", mb: 3, whiteSpace: "pre-wrap" }}>
                {selected.control.description}
              </Typography>
            )}

            <Divider sx={{ borderColor: "rgba(255,255,255,0.08)", my: 2 }} />

            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 1 }}>
              Status {selected.derived ? (
                selected.evidence?.startsWith("Verified by Microsoft Defender") ? "(Microsoft Defender for Cloud)" : "(auto-derived)"
              ) : "(manual override)"}
            </Typography>
            {selected.evidence?.startsWith("Verified by Microsoft Defender") && (
              <Chip label="Defender for Cloud" size="small"
                sx={{ bgcolor: "rgba(0,120,212,0.2)", color: "#0078d4", fontSize: 10, height: 18, mb: 1 }} />
            )}
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
              {STATUS_ORDER.map((s) => (
                <Chip key={s} label={STATUS_LABEL[s]} size="small" clickable
                  onClick={() => overrideMutation.mutate({
                    controlId: selected.control.control_id,
                    body: { status: s, evidence: evidenceDraft },
                  })}
                  sx={{
                    bgcolor: selected.status === s ? `${STATUS_COLOR[s]}40` : `${STATUS_COLOR[s]}15`,
                    color: STATUS_COLOR[s],
                    border: selected.status === s ? `1px solid ${STATUS_COLOR[s]}` : "none",
                  }} />
              ))}
            </Box>

            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 0.5 }}>
              Evidence / notes
            </Typography>
            <TextField multiline rows={4} fullWidth value={evidenceDraft}
              onChange={(e) => setEvidenceDraft(e.target.value)}
              placeholder="Link to runbook, ticket #, audit evidence, last attestation date, etc."
              sx={{ mb: 2,
                "& .MuiOutlinedInput-root": { color: "white", "& fieldset": { borderColor: "rgba(255,255,255,0.2)" } },
                "& textarea::placeholder": { color: "rgba(255,255,255,0.4)" } }} />

            {!selected.derived && (
              <Button startIcon={<RestartAlt />} size="small"
                onClick={() => resetOverrideMutation.mutate(selected.control.control_id)}
                sx={{ color: "rgba(255,255,255,0.7)", mb: 2 }}>
                Reset to auto-derived
              </Button>
            )}

            {selected.overridden_by && (
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", display: "block", mb: 2 }}>
                Overridden by {selected.overridden_by}
                {selected.overridden_at ? ` ${fromNow(selected.overridden_at)}` : ""}
              </Typography>
            )}

            {((selected.findings && selected.findings.length) || selected.finding_ids?.length) ? (
              <Box>
                <Divider sx={{ borderColor: "rgba(255,255,255,0.08)", my: 2 }} />
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 1 }}>
                  Linked findings ({(selected.findings || selected.finding_ids || []).length})
                </Typography>
                {selected.findings && selected.findings.length > 0 ? (
                  selected.findings.slice(0, 12).map((f) => {
                    const sev = (typeof f.severity === "object" ? (f.severity as any).value : f.severity) || "info";
                    return (
                      <Box key={f.id} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1, p: 1,
                        bgcolor: "rgba(255,255,255,0.03)", borderRadius: 1 }}>
                        <Chip label={sev} size="small"
                          sx={{ bgcolor: `${SEV_COLOR[sev] || "#888"}20`, color: SEV_COLOR[sev] || "#888",
                            fontSize: 9, height: 16, flexShrink: 0, mt: "2px" }} />
                        <Box sx={{ flex: 1, minWidth: 0 }}>
                          <Typography variant="body2" sx={{ color: "white", fontSize: 12, lineHeight: 1.3,
                            overflow: "hidden", textOverflow: "ellipsis", display: "-webkit-box",
                            WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
                            {f.title}
                          </Typography>
                          {f.asset_id ? (
                            <Typography variant="caption" component="span"
                              onClick={() => navigate(`/assets/${f.asset_id}`)}
                              sx={{ color: "#4285F4", fontSize: 11, cursor: "pointer",
                                "&:hover": { textDecoration: "underline" } }}>
                              {f.asset_name || f.resource_id} →
                            </Typography>
                          ) : (
                            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", fontSize: 11,
                              fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis",
                              whiteSpace: "nowrap", display: "block" }}>
                              {f.resource_id || "—"}
                            </Typography>
                          )}
                        </Box>
                      </Box>
                    );
                  })
                ) : (
                  (selected.finding_ids || []).slice(0, 8).map((fid) => (
                    <Typography key={fid} variant="caption" sx={{ display: "block", color: "rgba(255,255,255,0.5)", fontFamily: "monospace", fontSize: 11 }}>
                      {fid.slice(0, 8)}…
                    </Typography>
                  ))
                )}
              </Box>
            ) : null}
          </Box>
        )}
      </Drawer>
    </Box>
  );
}
