import React, { useState, useEffect, useRef } from "react";
import {
  Box, Typography, Button, Chip, IconButton, Table, TableHead, TableRow,
  TableCell, TableBody, Switch, Tooltip, Dialog, DialogTitle, DialogContent,
  DialogActions, TextField, MenuItem, Select, FormControl, InputLabel,
  CircularProgress, Drawer, Divider, Alert, InputAdornment,
  ToggleButtonGroup, ToggleButton, Card, Autocomplete, List, ListItem,
  ListItemButton, ListItemText, Collapse,
} from "@mui/material";
import {
  Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon,
  Search as SearchIcon, Close as CloseIcon, Policy as PolicyIcon,
  BugReport as BugIcon, Shield as ShieldIcon, CheckCircle as CheckCircleIcon,
  ExpandMore as ExpandMoreIcon, ExpandLess as ExpandLessIcon,
  AccountTree as AccountTreeIcon,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { controlPoliciesApi, frameworksApi } from "../services/api";
import { ControlPolicy, PolicyOptions, FrameworkControlEntry } from "../types";
import { useActiveClient } from "../contexts/ClientContext";

/** Extract a short, scannable keyword from an audit-language control title.
 *  CIS/NIST control titles use prescriptive language ("Ensure X is set to Y")
 *  while scanner findings use descriptive language ("Storage account permits outdated TLS").
 *  We extract the shortest distinctive noun phrase so at least "TLS" matches "outdated TLS". */
function extractMatchKeyword(title: string): string {
  let s = title
    .replace(/^(ensure\s+that|ensure|verify\s+that|verify|check\s+that|check|configure|enable|disable)\s+/i, "")
    .trim();

  // Grab noun phrase before the first verb clause ("is set", "are enabled", etc.)
  const verbM = s.match(/^(.+?)\s+(is\s|are\s|has\s|have\s|does\s|should\s|can\s)/i);
  if (verbM) s = verbM[1].trim();

  // Strip leading articles
  s = s.replace(/^(the|a|an|that)\s+/i, "").trim();

  // Strip trailing prepositional phrases ("for storage accounts", "on Azure AD", etc.)
  s = s.replace(/\s+(for|of|on|in|with|at|from|by)\s+.*/i, "").trim();

  // Remove quotes and backticks — framework controls quote resource names
  s = s.replace(/[`'"]/g, "").trim();

  // Max 3 words so the keyword is short enough to appear verbatim in scanner titles
  return s.split(/\s+/).slice(0, 3).join(" ");
}

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#4285F4",
};
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const RISK_TAG_LABELS: Record<string, string> = {
  lateral_movement: "Lateral Movement", data_exposure: "Data Exposure",
  privilege_escalation: "Privilege Escalation", initial_access: "Initial Access",
  credential_theft: "Credential Theft", network_exposure: "Network Exposure",
  misconfiguration: "Misconfiguration", vulnerable_software: "Vulnerable Software",
  identity_risk: "Identity Risk", supply_chain: "Supply Chain",
  ransomware_path: "Ransomware Path", exfiltration: "Exfiltration",
};

// ── Framework control picker ──────────────────────────────────────────────────

interface FrameworkPickerProps {
  onSelect: (ctrl: FrameworkControlEntry) => void;
  selected: FrameworkControlEntry | null;
  onClear: () => void;
}

function FrameworkPicker({ onSelect, selected, onClear }: FrameworkPickerProps) {
  const [fwKey, setFwKey] = useState("");
  const [domain, setDomain] = useState("");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState(true);

  const { data: catalogRaw } = useQuery<any[]>({
    queryKey: ["fw-catalog-all"],
    queryFn: () => frameworksApi.catalogAll(),
  });

  const frameworks = React.useMemo(() => {
    if (!catalogRaw) return [];
    return catalogRaw.filter((f: any) => !f.is_custom).map((f: any) => ({
      key: f.key ?? f.framework ?? f.name,
      name: f.name ?? f.key,
    }));
  }, [catalogRaw]);

  // Fetch ALL controls for the selected framework (no domain/search filter) to populate domain list
  const { data: allControls = [] } = useQuery<FrameworkControlEntry[]>({
    queryKey: ["fw-controls-all", fwKey],
    queryFn: () => controlPoliciesApi.frameworkControls({ framework: fwKey, limit: 2000 }),
    enabled: !!fwKey,
    staleTime: 5 * 60 * 1000,
  });

  // Filtered list for the visible picker list
  const { data: controls = [], isFetching } = useQuery<FrameworkControlEntry[]>({
    queryKey: ["fw-controls-picker", fwKey, domain, search],
    queryFn: () => controlPoliciesApi.frameworkControls({
      framework: fwKey,
      domain: domain || undefined,
      search: search || undefined,
      limit: 500,
    }),
    enabled: !!fwKey,
  });

  const domains = React.useMemo(() => {
    const d = new Set(allControls.map((c) => c.domain).filter(Boolean) as string[]);
    return Array.from(d).sort();
  }, [allControls]);

  if (selected && !expanded) {
    return (
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, p: 1.5, bgcolor: "rgba(52,168,83,0.08)", borderRadius: 1.5, border: "1px solid rgba(52,168,83,0.3)" }}>
        <CheckCircleIcon sx={{ color: "#34A853", fontSize: 18 }} />
        <Box sx={{ flex: 1 }}>
          <Typography variant="caption" color="text.secondary">Framework control selected</Typography>
          <Typography variant="body2" sx={{ fontWeight: 600 }}>
            [{selected.framework.toUpperCase()}] {selected.control_id} — {selected.title}
          </Typography>
        </Box>
        <IconButton size="small" onClick={() => { onClear(); setExpanded(true); }}>
          <CloseIcon fontSize="small" />
        </IconButton>
      </Box>
    );
  }

  return (
    <Box sx={{ border: "1px solid", borderColor: "divider", borderRadius: 1.5, overflow: "hidden" }}>
      <Box
        sx={{ px: 2, py: 1.5, bgcolor: "action.hover", display: "flex", alignItems: "center", gap: 1, cursor: "pointer" }}
        onClick={() => selected && setExpanded(!expanded)}
      >
        <AccountTreeIcon sx={{ fontSize: 16, color: "#4285F4" }} />
        <Typography variant="body2" sx={{ fontWeight: 600, flex: 1 }}>
          {selected ? `${selected.framework.toUpperCase()} · ${selected.control_id}` : "Search framework controls"}
        </Typography>
        {selected && (expanded ? <ExpandLessIcon fontSize="small" /> : <ExpandMoreIcon fontSize="small" />)}
      </Box>

      <Box sx={{ p: 2, display: "flex", flexDirection: "column", gap: 1.5 }}>
        {/* Row 1: framework + domain */}
        <Box sx={{ display: "flex", gap: 1.5 }}>
          <FormControl size="small" sx={{ flex: 1 }}>
            <InputLabel>Framework</InputLabel>
            <Select value={fwKey} label="Framework" onChange={(e) => { setFwKey(e.target.value); setDomain(""); }}>
              <MenuItem value=""><em>Select…</em></MenuItem>
              {frameworks.map((f) => (
                <MenuItem key={f.key} value={f.key}>{f.name}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ flex: 1 }} disabled={!fwKey || domains.length === 0}>
            <InputLabel>Domain</InputLabel>
            <Select value={domain} label="Domain" onChange={(e) => setDomain(e.target.value)}>
              <MenuItem value=""><em>All domains</em></MenuItem>
              {domains.map((d) => <MenuItem key={d} value={d}>{d}</MenuItem>)}
            </Select>
          </FormControl>
        </Box>

        {/* Row 2: search */}
        {fwKey && (
          <TextField
            size="small" fullWidth
            placeholder="Search control ID or title…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            slotProps={{ input: { startAdornment: <InputAdornment position="start"><SearchIcon sx={{ fontSize: 16, color: "text.secondary" }} /></InputAdornment> } }}
          />
        )}

        {/* Control list */}
        {fwKey && (
          isFetching ? (
            <Box sx={{ display: "flex", justifyContent: "center", py: 2 }}><CircularProgress size={20} /></Box>
          ) : controls.length === 0 ? (
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", textAlign: "center", py: 1 }}>
              No controls found
            </Typography>
          ) : (
            <>
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>
                {controls.length} control{controls.length !== 1 ? "s" : ""}
                {allControls.length > controls.length ? ` (${allControls.length} total — use domain filter or search to narrow)` : ""}
              </Typography>
            <List dense disablePadding sx={{ maxHeight: 260, overflow: "auto", border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
              {controls.map((ctrl) => (
                <ListItem key={ctrl.id} disablePadding divider>
                  <ListItemButton
                    onClick={() => { onSelect(ctrl); setExpanded(false); }}
                    selected={selected?.id === ctrl.id}
                    sx={{ py: 0.75, gap: 1 }}
                  >
                    <Chip label={ctrl.control_id} size="small"
                      sx={{ fontSize: 10, height: 18, bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", flexShrink: 0, fontFamily: "monospace" }} />
                    <ListItemText
                      primary={ctrl.title}
                      secondary={ctrl.domain}
                      slotProps={{
                        primary: { style: { fontSize: 12, fontWeight: 500 } },
                        secondary: { style: { fontSize: 11 } },
                      }}
                    />
                  </ListItemButton>
                </ListItem>
              ))}
            </List>
            </>
          )
        )}
      </Box>
    </Box>
  );
}


// ── Policy form ───────────────────────────────────────────────────────────────

interface PolicyFormProps {
  open: boolean;
  onClose: () => void;
  initial?: ControlPolicy;
  clientId: string;
  options: PolicyOptions;
}

const EMPTY_FORM = {
  name: "", description: "", severity: "high", category: "",
  match_title: "", match_severity: "", match_asset_class: "",
  match_cve: "", match_resource_types: [] as string[],
  match_connector_type: "", framework: "", framework_control_id: "",
  risk_tags: [] as string[],
};

function PolicyFormDialog({ open, onClose, initial, clientId, options }: PolicyFormProps) {
  const qc = useQueryClient();
  const isEdit = !!initial?.id;
  const [mode, setMode] = useState<"scratch" | "framework">("scratch");
  const [selectedCtrl, setSelectedCtrl] = useState<FrameworkControlEntry | null>(null);
  const [form, setForm] = useState({ ...EMPTY_FORM });

  React.useEffect(() => {
    if (open) {
      setMode("scratch");
      setSelectedCtrl(null);
      setForm(initial ? {
        name: initial.name ?? "",
        description: initial.description ?? "",
        severity: initial.severity ?? "high",
        category: initial.category ?? "",
        match_title: initial.match_title ?? "",
        match_severity: initial.match_severity ?? "",
        match_asset_class: initial.match_asset_class ?? "",
        match_cve: initial.match_cve ?? "",
        match_resource_types: initial.match_resource_types ?? [],
        match_connector_type: initial.match_connector_type ?? "",
        framework: initial.framework ?? "",
        framework_control_id: initial.framework_control_id ?? "",
        risk_tags: initial.risk_tags ?? [],
      } : { ...EMPTY_FORM });
    }
  }, [open, initial]);

  const set = (k: string, v: unknown) => setForm((f) => ({ ...f, [k]: v }));

  const toggleTag = (tag: string) =>
    set("risk_tags", form.risk_tags.includes(tag)
      ? form.risk_tags.filter((t) => t !== tag)
      : [...form.risk_tags, tag]);

  const handleCtrlSelect = (ctrl: FrameworkControlEntry) => {
    setSelectedCtrl(ctrl);
    setForm((f) => ({
      ...f,
      name: ctrl.title,
      description: ctrl.description ?? "",
      framework: ctrl.framework,
      framework_control_id: ctrl.control_id,
      // Auto-extract a specific keyword so the policy doesn't match every finding
      match_title: extractMatchKeyword(ctrl.title),
    }));
  };

  const buildBody = () => ({
    ...form,
    category: form.category || null,
    match_title: form.match_title || null,
    match_severity: form.match_severity || null,
    match_asset_class: form.match_asset_class || null,
    match_cve: form.match_cve || null,
    match_resource_types: form.match_resource_types,
    match_connector_type: form.match_connector_type || null,
    framework: form.framework || null,
    framework_control_id: form.framework_control_id || null,
  });

  const createMut = useMutation({
    mutationFn: () => controlPoliciesApi.create(clientId, buildBody()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["control-policies", clientId] }); onClose(); },
  });

  const updateMut = useMutation({
    mutationFn: () => controlPoliciesApi.update(clientId, initial!.id, buildBody()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["control-policies", clientId] }); onClose(); },
  });

  const busy = createMut.isPending || updateMut.isPending;
  const hasRule = form.match_title || form.match_severity || form.match_asset_class
    || form.match_cve || form.match_resource_types.length > 0 || form.match_connector_type;

  // Debounced live preview — shows matching finding count while user edits rules
  const [preview, setPreview] = useState<{ issue_count: number; affected_assets: number } | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!open || !clientId) return;
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(async () => {
      setPreviewLoading(true);
      try {
        const result = await controlPoliciesApi.preview(clientId, {
          name: form.name || "_preview_",
          match_title: form.match_title || null,
          match_severity: form.match_severity || null,
          match_asset_class: form.match_asset_class || null,
          match_cve: form.match_cve || null,
          match_resource_types: form.match_resource_types,
          match_connector_type: form.match_connector_type || null,
        });
        setPreview(result);
      } catch { /* ignore */ }
      finally { setPreviewLoading(false); }
    }, 600);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, clientId, form.match_title, form.match_severity, form.match_asset_class,
      form.match_cve, form.match_resource_types, form.match_connector_type]);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <PolicyIcon sx={{ color: "#4285F4" }} />
        {isEdit ? "Edit Security Policy" : "Create Security Policy"}
      </DialogTitle>

      <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2.5, pt: "16px !important" }}>

        {/* Mode toggle (only on create) */}
        {!isEdit && (
          <Box>
            <Typography variant="overline" color="text.secondary" sx={{ display: "block", mb: 1 }}>
              Starting point
            </Typography>
            <ToggleButtonGroup size="small" value={mode} exclusive onChange={(_, v) => v && setMode(v)} fullWidth>
              <ToggleButton value="scratch">
                From Scratch
              </ToggleButton>
              <ToggleButton value="framework">
                From Framework Control
              </ToggleButton>
            </ToggleButtonGroup>
          </Box>
        )}

        {/* Framework picker panel */}
        {mode === "framework" && !isEdit && (
          <>
            <Box>
              <Typography variant="overline" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                Pick a Framework Control
              </Typography>
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                Selecting a control auto-fills the policy name, description, and framework link. You can edit everything after.
              </Typography>
              <FrameworkPicker
                onSelect={handleCtrlSelect}
                selected={selectedCtrl}
                onClear={() => setSelectedCtrl(null)}
              />
            </Box>
            <Divider />
          </>
        )}

        {/* Policy identity */}
        <Box>
          <Typography variant="overline" color="text.secondary">Policy Identity</Typography>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5, mt: 1 }}>
            <TextField label="Policy Name" value={form.name} onChange={(e) => set("name", e.target.value)}
              required fullWidth placeholder="e.g. Critical CVEs on internet-facing VMs" />
            <TextField label="Description" value={form.description} onChange={(e) => set("description", e.target.value)}
              multiline rows={2} fullWidth placeholder="What security condition does this policy enforce?" />
            <Box sx={{ display: "flex", gap: 2 }}>
              <FormControl sx={{ flex: 1 }}>
                <InputLabel>Severity</InputLabel>
                <Select value={form.severity} label="Severity" onChange={(e) => set("severity", e.target.value)}>
                  {["critical", "high", "medium", "low"].map((s) => (
                    <MenuItem key={s} value={s}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Box sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: SEV_COLOR[s] }} />
                        {s.charAt(0).toUpperCase() + s.slice(1)}
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <FormControl sx={{ flex: 1 }}>
                <InputLabel>Category</InputLabel>
                <Select value={form.category} label="Category" onChange={(e) => set("category", e.target.value)}>
                  <MenuItem value=""><em>None</em></MenuItem>
                  {options.categories.map((c) => <MenuItem key={c} value={c}>{c}</MenuItem>)}
                </Select>
              </FormControl>
            </Box>
          </Box>
        </Box>

        <Divider />

        {/* Match rules */}
        <Box>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="overline" color="text.secondary">Match Rules</Typography>
            {/* Live preview badge */}
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
              {previewLoading && <CircularProgress size={12} />}
              {!previewLoading && preview !== null && (
                <Chip
                  label={preview.issue_count === 0
                    ? "0 findings match"
                    : `~${preview.issue_count} finding${preview.issue_count !== 1 ? "s" : ""} · ${preview.affected_assets} asset${preview.affected_assets !== 1 ? "s" : ""}`}
                  size="small"
                  sx={{
                    fontSize: 10, height: 20,
                    bgcolor: preview.issue_count === 0 ? "rgba(52,168,83,0.1)" : "rgba(66,133,244,0.12)",
                    color: preview.issue_count === 0 ? "#34A853" : "#4285F4",
                  }}
                />
              )}
            </Box>
          </Box>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.5 }}>
            All non-empty rules are AND-combined. The preview count updates as you type — use it to verify your rules match actual scanner findings.
          </Typography>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
            {/* Resource types — multi-select, prominent at top */}
            <Box>
              <Typography variant="caption" sx={{ fontWeight: 600, color: "text.secondary", display: "block", mb: 0.5 }}>
                Resource Types (scope)
              </Typography>
              <Autocomplete
                multiple
                freeSolo
                options={options.resource_types}
                value={form.match_resource_types}
                onChange={(_, v) => set("match_resource_types", v as string[])}
                renderInput={(params) => (
                  <TextField
                    {...params}
                    size="small"
                    label="Resource types"
                    placeholder={form.match_resource_types.length === 0 ? "Type or select resource types…" : ""}
                  />
                )}
                slotProps={{ chip: { size: "small" } } as any}
              />
              {form.match_resource_types.length === 0 && (
                <Alert severity="warning" sx={{ mt: 0.75, py: 0.5 }}>
                  No resource type scoping — this policy evaluates findings across all resource types.
                </Alert>
              )}
            </Box>

            <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1.5 }}>
              <Box>
                <TextField label="Title contains" value={form.match_title}
                  onChange={(e) => set("match_title", e.target.value)} size="small" fullWidth
                  placeholder="e.g. SSH password authentication" />
                {selectedCtrl && (
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
                    Auto-suggested from control title. Framework controls use prescriptive language ("Ensure X is set") but scanner findings use descriptive language ("permits outdated TLS"). Shorten to a key term that appears in your findings — check the preview count above.
                  </Typography>
                )}
              </Box>
              <FormControl size="small">
                <InputLabel>Finding severity</InputLabel>
                <Select value={form.match_severity} label="Finding severity"
                  onChange={(e) => set("match_severity", e.target.value)}>
                  <MenuItem value=""><em>Any</em></MenuItem>
                  {options.severities.map((s) => <MenuItem key={s} value={s}>{s}</MenuItem>)}
                </Select>
              </FormControl>
              <TextField label="CVE ID contains" value={form.match_cve}
                onChange={(e) => set("match_cve", e.target.value)} size="small"
                placeholder="e.g. CVE-2024" />
              <FormControl size="small">
                <InputLabel>Asset class</InputLabel>
                <Select value={form.match_asset_class} label="Asset class"
                  onChange={(e) => set("match_asset_class", e.target.value)}>
                  <MenuItem value=""><em>Any</em></MenuItem>
                  {options.asset_classes.map((c) => <MenuItem key={c} value={c}>{c}</MenuItem>)}
                </Select>
              </FormControl>
              <FormControl size="small">
                <InputLabel>Connector type</InputLabel>
                <Select value={form.match_connector_type} label="Connector type"
                  onChange={(e) => set("match_connector_type", e.target.value)}>
                  <MenuItem value=""><em>Any</em></MenuItem>
                  {options.connector_types.map((c) => <MenuItem key={c} value={c}>{c}</MenuItem>)}
                </Select>
              </FormControl>
            </Box>

            {!hasRule && (
              <Alert severity="warning">
                No match rules set — this policy will match all open findings (within scoped resource types).
              </Alert>
            )}
          </Box>
        </Box>

        <Divider />

        {/* Risk tags */}
        <Box>
          <Typography variant="overline" color="text.secondary">Risk Tags</Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.75, mt: 1 }}>
            {options.risk_tags.map((tag) => (
              <Chip
                key={tag}
                label={RISK_TAG_LABELS[tag] ?? tag}
                size="small"
                onClick={() => toggleTag(tag)}
                sx={{
                  cursor: "pointer",
                  bgcolor: form.risk_tags.includes(tag) ? "rgba(66,133,244,0.2)" : "action.selected",
                  color: form.risk_tags.includes(tag) ? "#4285F4" : "text.secondary",
                  border: form.risk_tags.includes(tag) ? "1px solid #4285F4" : "1px solid transparent",
                }}
              />
            ))}
          </Box>
        </Box>

        <Divider />

        {/* Framework link */}
        <Box>
          <Typography variant="overline" color="text.secondary">Framework Link</Typography>
          <Box sx={{ display: "flex", gap: 2, mt: 1 }}>
            <TextField label="Framework" value={form.framework} onChange={(e) => set("framework", e.target.value)}
              size="small" sx={{ flex: 1 }} placeholder="e.g. nist_csf" />
            <TextField label="Control ID" value={form.framework_control_id}
              onChange={(e) => set("framework_control_id", e.target.value)}
              size="small" sx={{ flex: 1 }} placeholder="e.g. PR.AC-1" />
          </Box>
        </Box>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button variant="contained" disabled={!form.name.trim() || busy}
          onClick={() => isEdit ? updateMut.mutate() : createMut.mutate()}>
          {busy ? <CircularProgress size={18} /> : isEdit ? "Save Changes" : "Create Policy"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}


// ── Issues drawer ─────────────────────────────────────────────────────────────

function IssuesDrawer({ policy, clientId, open, onClose }: {
  policy: ControlPolicy | null; clientId: string; open: boolean; onClose: () => void;
}) {
  const { data, isLoading } = useQuery({
    queryKey: ["policy-issues", clientId, policy?.id],
    queryFn: () => controlPoliciesApi.issues(clientId, policy!.id),
    enabled: open && !!policy,
  });

  return (
    <Drawer anchor="right" open={open} onClose={onClose} slotProps={{ paper: { sx: { width: 520, p: 0 } } }}>
      <Box sx={{ p: 3, borderBottom: 1, borderColor: "divider", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 0.5 }}>{policy?.name}</Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label={policy?.severity} size="small"
              sx={{ bgcolor: `${SEV_COLOR[policy?.severity ?? "high"]}22`, color: SEV_COLOR[policy?.severity ?? "high"] }} />
            {policy?.category && <Chip label={policy.category} size="small" variant="outlined" />}
            {(policy?.match_resource_types ?? []).length > 0 && (
              <Chip
                label={`${policy!.match_resource_types!.length} resource type${policy!.match_resource_types!.length > 1 ? "s" : ""}`}
                size="small"
                sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", fontFamily: "monospace" }}
              />
            )}
          </Box>
        </Box>
        <IconButton onClick={onClose} size="small"><CloseIcon /></IconButton>
      </Box>

      {/* Resource type scope pills */}
      {(policy?.match_resource_types ?? []).length > 0 && (
        <Box sx={{ px: 3, pt: 1.5, pb: 0.5 }}>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>Scoped to resource types</Typography>
          <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
            {policy!.match_resource_types!.map((rt) => (
              <Chip key={rt} label={rt} size="small" sx={{ fontFamily: "monospace", fontSize: 10, height: 20 }} />
            ))}
          </Box>
        </Box>
      )}

      <Box sx={{ p: 3, flex: 1, overflow: "auto" }}>
        {isLoading ? <CircularProgress size={24} /> : (
          <>
            {/* Warn if this policy has no meaningful match rules — results are unscoped */}
            {policy && !policy.match_title && !policy.match_severity && !policy.match_cve
              && !policy.match_asset_class && !policy.match_connector_type
              && !(policy.match_resource_types ?? []).length && (
              <Alert severity="warning" sx={{ mb: 2 }}>
                This policy has no match rules — it matches <strong>all</strong> open findings. Edit the policy to add a title keyword, resource type scope, or other filters so only relevant findings are counted.
              </Alert>
            )}

            <Box sx={{ display: "flex", gap: 3, mb: 3 }}>
              <Box sx={{ textAlign: "center" }}>
                <Typography variant="h4" sx={{ fontWeight: 700, color: SEV_COLOR[policy?.severity ?? "high"] }}>
                  {data?.total ?? 0}
                </Typography>
                <Typography variant="caption" color="text.secondary">Total Issues</Typography>
              </Box>
            </Box>

            {(data?.findings ?? []).length === 0 ? (
              <Alert severity="success">No open findings match this policy.</Alert>
            ) : (
              <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                {data.findings.map((f: any) => (
                  <Card key={f.id} variant="outlined" sx={{ p: 1.5, borderRadius: 1.5 }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 1 }}>
                      <Typography variant="body2" sx={{ fontWeight: 500, flex: 1 }}>{f.title}</Typography>
                      <Chip label={f.severity} size="small"
                        sx={{ bgcolor: `${SEV_COLOR[f.severity]}22`, color: SEV_COLOR[f.severity], flexShrink: 0, fontSize: 10, height: 20 }} />
                    </Box>
                    {f.resource_id && (
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5, fontFamily: "monospace" }}>
                        {f.resource_id}
                      </Typography>
                    )}
                    {f.resource_type && (
                      <Chip label={f.resource_type} size="small"
                        sx={{ mt: 0.5, fontSize: 10, height: 18, bgcolor: "action.selected", fontFamily: "monospace" }} />
                    )}
                    {f.cve_id && (
                      <Chip label={f.cve_id} size="small"
                        sx={{ mt: 0.5, ml: 0.5, fontSize: 10, height: 18, bgcolor: "rgba(244,67,54,0.1)", color: "#f44336" }} />
                    )}
                  </Card>
                ))}
                {data.total > data.findings.length && (
                  <Typography variant="caption" color="text.secondary" sx={{ textAlign: "center", py: 1 }}>
                    Showing {data.findings.length} of {data.total} issues
                  </Typography>
                )}
              </Box>
            )}
          </>
        )}
      </Box>
    </Drawer>
  );
}


// ── Main page ─────────────────────────────────────────────────────────────────

export default function SecurityPolicies() {
  const { clientId } = useActiveClient();
  const qc = useQueryClient();

  const [formOpen, setFormOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<ControlPolicy | undefined>(undefined);
  const [issuesPolicy, setIssuesPolicy] = useState<ControlPolicy | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [filterSev, setFilterSev] = useState("");
  const [filterStatus, setFilterStatus] = useState("active");

  const { data: policies = [], isLoading } = useQuery<ControlPolicy[]>({
    queryKey: ["control-policies", clientId, filterSev, filterStatus],
    queryFn: () => controlPoliciesApi.list(clientId, {
      severity: filterSev || undefined,
      status: filterStatus || undefined,
    }),
    enabled: !!clientId,
    refetchInterval: 30000,
  });

  const { data: options } = useQuery<PolicyOptions>({
    queryKey: ["policy-options", clientId],
    queryFn: () => controlPoliciesApi.options(clientId),
    enabled: !!clientId,
  });

  const toggleMut = useMutation({
    mutationFn: (id: string) => controlPoliciesApi.toggle(clientId, id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["control-policies", clientId] }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => controlPoliciesApi.delete(clientId, id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["control-policies", clientId] }); setDeleteConfirm(null); },
  });

  const blankOptions: PolicyOptions = options ?? {
    severities: ["critical", "high", "medium", "low", "info"],
    asset_classes: [], resource_types: [], connector_types: [],
    risk_tags: [], categories: ["Identity", "Network", "Data", "Compute", "Application", "Other"],
  };

  const filtered = policies.filter((p) =>
    !search || p.name.toLowerCase().includes(search.toLowerCase()) ||
    (p.description ?? "").toLowerCase().includes(search.toLowerCase())
  );

  const sorted = [...filtered].sort((a, b) =>
    (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) || a.name.localeCompare(b.name)
  );

  const totalIssues = filtered.reduce((s, p) => s + (p.issue_count ?? 0), 0);
  const activeCount = filtered.filter((p) => p.status === "active").length;
  const violatedCount = filtered.filter((p) => (p.issue_count ?? 0) > 0).length;

  return (
    <Box sx={{ p: 3, maxWidth: 1200 }}>
      {/* Header */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
            <ShieldIcon sx={{ color: "#4285F4" }} />
            <Typography variant="h5" sx={{ fontWeight: 700 }}>Security Policies</Typography>
          </Box>
          <Typography variant="body2" color="text.secondary">
            Define named security rules and see live compliance status against open findings.
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />}
          onClick={() => { setEditTarget(undefined); setFormOpen(true); }}
          disabled={!clientId}>
          Create Policy
        </Button>
      </Box>

      {/* Summary stats */}
      <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
        {[
          { label: "Total Policies", value: filtered.length, color: "#4285F4" },
          { label: "Active", value: activeCount, color: "#34A853" },
          { label: "Violated", value: violatedCount, color: "#f44336" },
          { label: "Open Issues", value: totalIssues, color: "#ff9800" },
        ].map((s) => (
          <Box key={s.label} sx={{
            px: 2.5, py: 1.5, borderRadius: 2, border: "1px solid", borderColor: "divider",
            bgcolor: "background.paper", minWidth: 120,
          }}>
            <Typography variant="h5" sx={{ fontWeight: 700, color: s.color }}>{s.value}</Typography>
            <Typography variant="caption" color="text.secondary">{s.label}</Typography>
          </Box>
        ))}
      </Box>

      {/* Filters */}
      <Box sx={{ display: "flex", gap: 1.5, mb: 2.5, flexWrap: "wrap", alignItems: "center" }}>
        <TextField size="small" placeholder="Search policies…" value={search}
          onChange={(e) => setSearch(e.target.value)}
          slotProps={{ input: { startAdornment: <InputAdornment position="start"><SearchIcon sx={{ fontSize: 18, color: "text.secondary" }} /></InputAdornment> } }}
          sx={{ minWidth: 240 }} />

        <ToggleButtonGroup size="small" value={filterStatus} exclusive onChange={(_, v) => v && setFilterStatus(v)}>
          <ToggleButton value="active">Active</ToggleButton>
          <ToggleButton value="">All</ToggleButton>
          <ToggleButton value="disabled">Disabled</ToggleButton>
        </ToggleButtonGroup>

        <FormControl size="small" sx={{ minWidth: 130 }}>
          <InputLabel>Severity</InputLabel>
          <Select value={filterSev} label="Severity" onChange={(e) => setFilterSev(e.target.value)}>
            <MenuItem value=""><em>All</em></MenuItem>
            {["critical", "high", "medium", "low"].map((s) => (
              <MenuItem key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>

      {/* Table */}
      {!clientId ? (
        <Alert severity="info">Select a client to view security policies.</Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", py: 8 }}><CircularProgress /></Box>
      ) : sorted.length === 0 ? (
        <Box sx={{ textAlign: "center", py: 10, border: "1px dashed", borderColor: "divider", borderRadius: 2 }}>
          <PolicyIcon sx={{ fontSize: 48, color: "text.disabled", mb: 2 }} />
          <Typography variant="h6" color="text.secondary" gutterBottom>No policies yet</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Create from scratch or pick a framework control to get started.
          </Typography>
          <Button variant="contained" startIcon={<AddIcon />}
            onClick={() => { setEditTarget(undefined); setFormOpen(true); }}>
            Create Policy
          </Button>
        </Box>
      ) : (
        <Box sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, overflow: "hidden" }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ "& th": { bgcolor: "background.paper", color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                <TableCell sx={{ pl: 2 }}>POLICY</TableCell>
                <TableCell sx={{ width: 180 }}>RESOURCE SCOPE</TableCell>
                <TableCell align="center" sx={{ width: 90 }}>ISSUES</TableCell>
                <TableCell sx={{ width: 110 }}>SEVERITY</TableCell>
                <TableCell sx={{ width: 130 }}>CATEGORY</TableCell>
                <TableCell sx={{ width: 180 }}>RISK TAGS</TableCell>
                <TableCell sx={{ width: 70 }}>STATUS</TableCell>
                <TableCell align="right" sx={{ width: 100, pr: 2 }}>ACTIONS</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {sorted.map((p) => (
                <TableRow key={p.id} hover
                  sx={{ "& td": { borderColor: "divider", py: 1 }, "&:hover": { bgcolor: "action.hover" } }}>
                  {/* Policy name */}
                  <TableCell sx={{ pl: 2, maxWidth: 280 }}>
                    <Typography variant="body2" sx={{ fontWeight: 500, lineHeight: 1.3 }}>{p.name}</Typography>
                    {p.description && (
                      <Typography variant="caption" color="text.secondary" sx={{
                        display: "-webkit-box", WebkitLineClamp: 1,
                        WebkitBoxOrient: "vertical", overflow: "hidden",
                      }}>
                        {p.description}
                      </Typography>
                    )}
                    {p.framework_control_id && (
                      <Tooltip title={p.framework ? `Framework: ${p.framework.toUpperCase().replace(/_/g, " ")}` : ""}>
                        <Chip
                          label={`${p.framework ? p.framework.replace(/_/g, " ").toUpperCase() + " · " : ""}${p.framework_control_id}`}
                          size="small"
                          sx={{ mt: 0.5, fontSize: 9, height: 16, bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", maxWidth: 200 }}
                        />
                      </Tooltip>
                    )}
                  </TableCell>

                  {/* Resource scope */}
                  <TableCell>
                    {(p.match_resource_types ?? []).length > 0 ? (
                      <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                        {p.match_resource_types!.slice(0, 2).map((rt) => (
                          <Chip key={rt} label={rt} size="small"
                            sx={{ fontSize: 9, height: 16, fontFamily: "monospace", bgcolor: "rgba(66,133,244,0.08)", color: "#4285F4" }} />
                        ))}
                        {p.match_resource_types!.length > 2 && (
                          <Typography variant="caption" color="text.secondary">+{p.match_resource_types!.length - 2}</Typography>
                        )}
                      </Box>
                    ) : (
                      <Typography variant="caption" color="text.disabled" sx={{ fontStyle: "italic" }}>All types</Typography>
                    )}
                  </TableCell>

                  {/* Issues count */}
                  <TableCell align="center">
                    {p.status === "disabled" ? (
                      <Typography variant="caption" color="text.disabled">—</Typography>
                    ) : (
                      <Tooltip title={`${p.issue_count} open findings · ${p.affected_assets} assets`}>
                        <Box
                          onClick={() => setIssuesPolicy(p)}
                          sx={{
                            display: "inline-flex", alignItems: "center", gap: 0.5,
                            cursor: "pointer",
                            color: (p.issue_count ?? 0) > 0 ? "#f44336" : "text.secondary",
                            fontWeight: (p.issue_count ?? 0) > 0 ? 700 : 400,
                          }}
                        >
                          <BugIcon sx={{ fontSize: 14 }} />
                          <Typography variant="body2" sx={{ fontWeight: "inherit", color: "inherit" }}>
                            {p.issue_count ?? 0}
                          </Typography>
                        </Box>
                      </Tooltip>
                    )}
                  </TableCell>

                  {/* Severity */}
                  <TableCell>
                    <Chip label={p.severity} size="small"
                      sx={{ bgcolor: `${SEV_COLOR[p.severity]}22`, color: SEV_COLOR[p.severity], fontSize: 10, height: 20, textTransform: "capitalize" }} />
                  </TableCell>

                  {/* Category */}
                  <TableCell>
                    <Typography variant="caption" color="text.secondary">{p.category ?? "—"}</Typography>
                  </TableCell>

                  {/* Risk tags */}
                  <TableCell>
                    <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                      {(p.risk_tags ?? []).slice(0, 2).map((tag) => (
                        <Chip key={tag} label={RISK_TAG_LABELS[tag] ?? tag} size="small"
                          sx={{ fontSize: 9, height: 16, bgcolor: "rgba(66,133,244,0.08)", color: "text.secondary" }} />
                      ))}
                      {(p.risk_tags ?? []).length > 2 && (
                        <Typography variant="caption" color="text.secondary">+{p.risk_tags.length - 2}</Typography>
                      )}
                    </Box>
                  </TableCell>

                  {/* Status toggle */}
                  <TableCell>
                    <Tooltip title={p.status === "active" ? "Disable policy" : "Enable policy"}>
                      <Switch
                        size="small"
                        checked={p.status === "active"}
                        onChange={() => toggleMut.mutate(p.id)}
                        sx={{
                          "& .MuiSwitch-switchBase.Mui-checked": { color: "#34A853" },
                          "& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track": { bgcolor: "#34A853" },
                        }}
                      />
                    </Tooltip>
                  </TableCell>

                  {/* Actions */}
                  <TableCell align="right" sx={{ pr: 1 }}>
                    <Tooltip title="Edit">
                      <IconButton size="small" onClick={() => { setEditTarget(p); setFormOpen(true); }}>
                        <EditIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton size="small" color="error" onClick={() => setDeleteConfirm(p.id)}>
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Box>
      )}

      {/* Dialogs */}
      <PolicyFormDialog
        open={formOpen}
        onClose={() => setFormOpen(false)}
        initial={editTarget}
        clientId={clientId}
        options={blankOptions}
      />

      <IssuesDrawer
        open={!!issuesPolicy}
        onClose={() => setIssuesPolicy(null)}
        policy={issuesPolicy}
        clientId={clientId}
      />

      <Dialog open={!!deleteConfirm} onClose={() => setDeleteConfirm(null)}>
        <DialogTitle>Delete Policy?</DialogTitle>
        <DialogContent>
          <Typography>This will permanently remove the policy. Open findings are not affected.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirm(null)}>Cancel</Button>
          <Button color="error" variant="contained" onClick={() => deleteMut.mutate(deleteConfirm!)}>Delete</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
