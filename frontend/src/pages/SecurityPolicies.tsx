import React, { useState } from "react";
import {
  Box, Typography, Button, Chip, IconButton, Table, TableHead, TableRow,
  TableCell, TableBody, Switch, Tooltip, Dialog, DialogTitle, DialogContent,
  DialogActions, TextField, MenuItem, Select, FormControl, InputLabel,
  CircularProgress, Drawer, Divider, Stack, Alert, Badge, InputAdornment,
  ToggleButtonGroup, ToggleButton, Card,
} from "@mui/material";
import {
  Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon,
  Search as SearchIcon, Close as CloseIcon, Policy as PolicyIcon,
  BugReport as BugIcon, FilterList as FilterIcon, Shield as ShieldIcon,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { controlPoliciesApi } from "../services/api";
import { ControlPolicy, PolicyOptions } from "../types";
import { useActiveClient } from "../contexts/ClientContext";
import { fromNow } from "../utils/datetime";

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
  match_cve: "", match_resource_type: "", match_connector_type: "",
  framework: "", framework_control_id: "", risk_tags: [] as string[],
};

function PolicyFormDialog({ open, onClose, initial, clientId, options }: PolicyFormProps) {
  const qc = useQueryClient();
  const isEdit = !!initial?.id;
  const [form, setForm] = useState({ ...EMPTY_FORM });

  React.useEffect(() => {
    if (open) {
      setForm(initial ? {
        name: initial.name ?? "",
        description: initial.description ?? "",
        severity: initial.severity ?? "high",
        category: initial.category ?? "",
        match_title: initial.match_title ?? "",
        match_severity: initial.match_severity ?? "",
        match_asset_class: initial.match_asset_class ?? "",
        match_cve: initial.match_cve ?? "",
        match_resource_type: initial.match_resource_type ?? "",
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

  const createMut = useMutation({
    mutationFn: () => controlPoliciesApi.create(clientId, {
      ...form,
      category: form.category || null,
      match_title: form.match_title || null,
      match_severity: form.match_severity || null,
      match_asset_class: form.match_asset_class || null,
      match_cve: form.match_cve || null,
      match_resource_type: form.match_resource_type || null,
      match_connector_type: form.match_connector_type || null,
      framework: form.framework || null,
      framework_control_id: form.framework_control_id || null,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["control-policies", clientId] }); onClose(); },
  });

  const updateMut = useMutation({
    mutationFn: () => controlPoliciesApi.update(clientId, initial!.id, {
      ...form,
      category: form.category || null,
      match_title: form.match_title || null,
      match_severity: form.match_severity || null,
      match_asset_class: form.match_asset_class || null,
      match_cve: form.match_cve || null,
      match_resource_type: form.match_resource_type || null,
      match_connector_type: form.match_connector_type || null,
      framework: form.framework || null,
      framework_control_id: form.framework_control_id || null,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["control-policies", clientId] }); onClose(); },
  });

  const busy = createMut.isPending || updateMut.isPending;
  const hasRule = form.match_title || form.match_severity || form.match_asset_class
    || form.match_cve || form.match_resource_type || form.match_connector_type;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <PolicyIcon sx={{ color: "#4285F4" }} />
        {isEdit ? "Edit Security Policy" : "Create Security Policy"}
      </DialogTitle>
      <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2.5, pt: "16px !important" }}>

        {/* Identity */}
        <Box>
          <Typography variant="overline" color="text.secondary">Policy Identity</Typography>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5, mt: 1 }}>
            <TextField label="Policy Name" value={form.name} onChange={(e) => set("name", e.target.value)} required fullWidth
              placeholder="e.g. Critical CVEs on internet-facing VMs" />
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
          <Typography variant="overline" color="text.secondary">Match Rules</Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.5 }}>
            All non-empty rules are AND-combined. Leave blank to match all findings on that dimension.
          </Typography>
          <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1.5 }}>
            <TextField label="Title contains" value={form.match_title}
              onChange={(e) => set("match_title", e.target.value)} fullWidth
              placeholder="e.g. SSH password" size="small" />
            <FormControl fullWidth size="small">
              <InputLabel>Finding severity</InputLabel>
              <Select value={form.match_severity} label="Finding severity" onChange={(e) => set("match_severity", e.target.value)}>
                <MenuItem value=""><em>Any</em></MenuItem>
                {options.severities.map((s) => <MenuItem key={s} value={s}>{s}</MenuItem>)}
              </Select>
            </FormControl>
            <TextField label="CVE ID contains" value={form.match_cve}
              onChange={(e) => set("match_cve", e.target.value)} fullWidth
              placeholder="e.g. CVE-2024" size="small" />
            <FormControl fullWidth size="small">
              <InputLabel>Asset class</InputLabel>
              <Select value={form.match_asset_class} label="Asset class" onChange={(e) => set("match_asset_class", e.target.value)}>
                <MenuItem value=""><em>Any</em></MenuItem>
                {options.asset_classes.map((c) => <MenuItem key={c} value={c}>{c}</MenuItem>)}
              </Select>
            </FormControl>
            <FormControl fullWidth size="small">
              <InputLabel>Connector type</InputLabel>
              <Select value={form.match_connector_type} label="Connector type" onChange={(e) => set("match_connector_type", e.target.value)}>
                <MenuItem value=""><em>Any</em></MenuItem>
                {options.connector_types.map((c) => <MenuItem key={c} value={c}>{c}</MenuItem>)}
              </Select>
            </FormControl>
            <TextField label="Resource type" value={form.match_resource_type}
              onChange={(e) => set("match_resource_type", e.target.value)} fullWidth
              placeholder="e.g. VirtualMachine" size="small" />
          </Box>
          {!hasRule && (
            <Alert severity="warning" sx={{ mt: 1.5 }}>
              No match rules set — this policy will match all open findings.
            </Alert>
          )}
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
          <Typography variant="overline" color="text.secondary">Framework Link (optional)</Typography>
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
          </Box>
        </Box>
        <IconButton onClick={onClose} size="small"><CloseIcon /></IconButton>
      </Box>

      <Box sx={{ p: 3, flex: 1, overflow: "auto" }}>
        {isLoading ? <CircularProgress size={24} /> : (
          <>
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
                    {f.cve_id && (
                      <Chip label={f.cve_id} size="small" sx={{ mt: 0.5, fontSize: 10, height: 18, bgcolor: "rgba(244,67,54,0.1)", color: "#f44336" }} />
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
            Create your first security policy to start monitoring compliance.
          </Typography>
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => { setEditTarget(undefined); setFormOpen(true); }}>
            Create Policy
          </Button>
        </Box>
      ) : (
        <Box sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, overflow: "hidden" }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ "& th": { bgcolor: "background.paper", color: "text.secondary", fontSize: 11, fontWeight: 600, borderColor: "divider" } }}>
                <TableCell sx={{ pl: 2 }}>POLICY</TableCell>
                <TableCell align="center" sx={{ width: 90 }}>ISSUES</TableCell>
                <TableCell sx={{ width: 110 }}>SEVERITY</TableCell>
                <TableCell sx={{ width: 130 }}>CATEGORY</TableCell>
                <TableCell sx={{ width: 200 }}>RISK TAGS</TableCell>
                <TableCell sx={{ width: 70 }}>STATUS</TableCell>
                <TableCell align="right" sx={{ width: 100, pr: 2 }}>ACTIONS</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {sorted.map((p) => (
                <TableRow key={p.id} hover
                  sx={{ "& td": { borderColor: "divider", py: 1 }, "&:hover": { bgcolor: "action.hover" } }}>
                  {/* Policy name + description */}
                  <TableCell sx={{ pl: 2, maxWidth: 340 }}>
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
                      <Chip label={`${p.framework ?? ""} ${p.framework_control_id}`} size="small"
                        sx={{ mt: 0.5, fontSize: 9, height: 16, bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4" }} />
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
                            cursor: "pointer", color: (p.issue_count ?? 0) > 0 ? "#f44336" : "text.secondary",
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
                      {(p.risk_tags ?? []).slice(0, 3).map((tag) => (
                        <Chip key={tag} label={RISK_TAG_LABELS[tag] ?? tag} size="small"
                          sx={{ fontSize: 9, height: 16, bgcolor: "rgba(66,133,244,0.08)", color: "text.secondary" }} />
                      ))}
                      {(p.risk_tags ?? []).length > 3 && (
                        <Typography variant="caption" color="text.secondary">+{p.risk_tags.length - 3}</Typography>
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
                        sx={{ "& .MuiSwitch-switchBase.Mui-checked": { color: "#34A853" }, "& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track": { bgcolor: "#34A853" } }}
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
