import React, { useState, useCallback } from "react";
import { alpha } from "@mui/material/styles";
import {
  Box, Typography, Button, Card, CardContent, IconButton, Chip,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  FormControl, InputLabel, Select, MenuItem, Checkbox, CircularProgress,
  Alert, Tooltip, LinearProgress, InputAdornment, Divider, Tabs, Tab,
} from "@mui/material";
import {
  Add, Delete, Edit, Refresh, Search, CheckBox, CheckBoxOutlineBlank,
  LibraryAdd, ArrowBack, Category, Build,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { customFrameworksApi } from "../services/api";
import { toast } from "react-toastify";

interface CustomFrameworkSummary {
  id: string;
  name: string;
  slug: string;
  description?: string;
  control_count: number;
}

interface PickerControl {
  id: string;
  framework: string;
  control_id: string;
  domain?: string;
  title: string;
  description?: string;
  weight: number;
}

interface DomainItem {
  id: string;
  name: string;
  description?: string;
  sort_order: number;
}

interface NativeControlItem {
  id: string;
  control_id: string;
  title: string;
  description?: string;
  weight: number;
  sort_order: number;
  domain_id?: string;
  domain_name?: string;
}

interface MappedControl extends PickerControl {
  reference_id?: string;
  control_domain?: string;
}

interface CustomFrameworkDetail {
  id: string;
  name: string;
  slug: string;
  description?: string;
  controls: MappedControl[];
  domains: DomainItem[];
  native_controls: NativeControlItem[];
}

const SOURCE_FRAMEWORKS = [
  { value: "nist_csf", label: "NIST CSF 2.0" },
  { value: "nist_800_53", label: "NIST 800-53" },
  { value: "iso_27001", label: "ISO 27001:2022" },
  { value: "pci_dss", label: "PCI DSS v4.0" },
  { value: "gdpr", label: "GDPR" },
  { value: "cis_v8", label: "CIS Controls v8" },
  { value: "cis_azure", label: "CIS Azure" },
  { value: "cis_aws", label: "CIS AWS" },
  { value: "cis_gcp", label: "CIS GCP" },
  { value: "cis_m365", label: "CIS M365" },
];

const WEIGHT_COLOR: Record<number, string> = { 3: "#EA4335", 2: "#FBBC04", 1: "#4285F4" };
const WEIGHT_LABEL: Record<number, string> = { 3: "Critical", 2: "Important", 1: "Standard" };

// ── Control Picker Dialog ─────────────────────────────────────────────────────

function ControlPickerDialog({
  cfId,
  existingIds,
  onClose,
}: {
  cfId: string;
  existingIds: Set<string>;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [sourceFramework, setSourceFramework] = useState("nist_csf");
  const [domain, setDomain] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const { data: controls = [], isFetching } = useQuery<PickerControl[]>({
    queryKey: ["picker-controls", sourceFramework, domain, search, page],
    queryFn: () => customFrameworksApi.pickerControls({
      framework: sourceFramework,
      domain: domain || undefined,
      search: search || undefined,
      page,
    }),
    staleTime: 60_000,
  });

  const domains = Array.from(new Set(controls.map((c) => c.domain).filter(Boolean))) as string[];

  const addMut = useMutation({
    mutationFn: () => customFrameworksApi.addControls(cfId, Array.from(selected)),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-framework", cfId] });
      qc.invalidateQueries({ queryKey: ["custom-frameworks"] });
      toast.success(`${selected.size} control${selected.size !== 1 ? "s" : ""} added`);
      onClose();
    },
    onError: () => toast.error("Failed to add controls"),
  });

  const toggleAll = () => {
    const addable = controls.filter((c) => !existingIds.has(c.id) && c.weight > 0);
    if (addable.every((c) => selected.has(c.id))) {
      setSelected((s) => { const n = new Set(s); addable.forEach((c) => n.delete(c.id)); return n; });
    } else {
      setSelected((s) => { const n = new Set(s); addable.forEach((c) => n.add(c.id)); return n; });
    }
  };

  const addable = controls.filter((c) => !existingIds.has(c.id) && c.weight > 0);
  const allChecked = addable.length > 0 && addable.every((c) => selected.has(c.id));

  return (
    <Dialog open fullWidth maxWidth="md" onClose={onClose}>
      <DialogTitle sx={{ pb: 1 }}>
        <Typography variant="h6" sx={{ fontWeight: 700 }}>Add Controls from Existing Frameworks</Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
          Browse and select controls from any loaded framework to include in your custom policy.
        </Typography>
      </DialogTitle>
      <DialogContent>
        <Box sx={{ display: "flex", gap: 1.5, mb: 2, flexWrap: "wrap", alignItems: "center" }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel>Source Framework</InputLabel>
            <Select value={sourceFramework} label="Source Framework"
              onChange={(e) => { setSourceFramework(e.target.value); setDomain(""); setPage(1); }}>
              {SOURCE_FRAMEWORKS.map((f) => (
                <MenuItem key={f.value} value={f.value}>{f.label}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 160 }}>
            <InputLabel>Domain</InputLabel>
            <Select value={domain} label="Domain"
              onChange={(e) => { setDomain(e.target.value); setPage(1); }}>
              <MenuItem value="">All domains</MenuItem>
              {domains.map((d) => <MenuItem key={d} value={d}>{d}</MenuItem>)}
            </Select>
          </FormControl>
          <TextField size="small" placeholder="Search controls…" value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            slotProps={{ input: { startAdornment: <InputAdornment position="start"><Search fontSize="small" /></InputAdornment> } }}
            sx={{ minWidth: 220 }} />
        </Box>

        {isFetching && <LinearProgress sx={{ mb: 1 }} />}

        {addable.length > 0 && (
          <Box sx={{ display: "flex", alignItems: "center", px: 1, py: 0.5, mb: 1,
            bgcolor: "action.hover", borderRadius: 1, cursor: "pointer" }}
            onClick={toggleAll}>
            <Checkbox size="small" checked={allChecked}
              icon={<CheckBoxOutlineBlank fontSize="small" />}
              checkedIcon={<CheckBox fontSize="small" />} />
            <Typography variant="caption" sx={{ fontWeight: 600, ml: 0.5 }}>
              Select all on this page ({addable.length} controls)
            </Typography>
            {selected.size > 0 && (
              <Chip label={`${selected.size} selected total`} size="small"
                sx={{ ml: "auto", bgcolor: "primary.main", color: "white", fontSize: 11 }} />
            )}
          </Box>
        )}

        <Box sx={{ maxHeight: 380, overflowY: "auto", display: "flex", flexDirection: "column", gap: 0.5 }}>
          {controls.length === 0 && !isFetching && (
            <Typography sx={{ color: "text.secondary", p: 2, textAlign: "center" }}>
              No controls found. Try a different framework or search term.
            </Typography>
          )}
          {controls.map((c) => {
            const alreadyAdded = existingIds.has(c.id);
            const isHeader = c.weight === 0;
            if (isHeader) return (
              <Typography key={c.id} variant="caption"
                sx={{ fontWeight: 700, color: "text.secondary", px: 1, pt: 1.5, pb: 0.5,
                  textTransform: "uppercase", letterSpacing: 0.5, fontSize: 10 }}>
                {c.domain || c.title}
              </Typography>
            );
            const isSelected = selected.has(c.id);
            return (
              <Box key={c.id}
                onClick={() => !alreadyAdded && setSelected((s) => { const n = new Set(s); isSelected ? n.delete(c.id) : n.add(c.id); return n; })}
                sx={{
                  display: "flex", alignItems: "flex-start", gap: 1, px: 1, py: 0.75,
                  borderRadius: 1, cursor: alreadyAdded ? "default" : "pointer",
                  opacity: alreadyAdded ? 0.45 : 1,
                  bgcolor: isSelected ? (theme: any) => alpha(theme.palette.primary.main, 0.094) : "transparent",
                  border: isSelected ? "1px solid" : "1px solid transparent",
                  borderColor: isSelected ? (theme: any) => alpha(theme.palette.primary.main, 0.25) : "transparent",
                  "&:hover": { bgcolor: alreadyAdded ? undefined : "action.hover" },
                }}>
                <Checkbox size="small" checked={isSelected || alreadyAdded} disabled={alreadyAdded}
                  icon={<CheckBoxOutlineBlank fontSize="small" />}
                  checkedIcon={<CheckBox fontSize="small" />}
                  sx={{ p: 0, mt: 0.2, flexShrink: 0 }} />
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Typography variant="caption" sx={{ fontWeight: 600, color: "text.secondary", flexShrink: 0 }}>
                      {c.control_id}
                    </Typography>
                    {c.weight >= 2 && (
                      <Chip label={WEIGHT_LABEL[c.weight] || ""} size="small"
                        sx={{ height: 16, fontSize: 9, bgcolor: `${WEIGHT_COLOR[c.weight]}22`,
                          color: WEIGHT_COLOR[c.weight], fontWeight: 700 }} />
                    )}
                    {alreadyAdded && <Chip label="Added" size="small" sx={{ height: 16, fontSize: 9 }} />}
                  </Box>
                  <Typography sx={{ fontSize: 12.5, fontWeight: 500, lineHeight: 1.3 }}>{c.title}</Typography>
                  {c.description && (
                    <Typography variant="caption" sx={{ color: "text.secondary", lineHeight: 1.4,
                      display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>
                      {c.description}
                    </Typography>
                  )}
                </Box>
              </Box>
            );
          })}
        </Box>

        {controls.length === 100 && (
          <Box sx={{ display: "flex", justifyContent: "center", gap: 1, mt: 1 }}>
            <Button size="small" disabled={page === 1} onClick={() => setPage((p) => p - 1)}>Prev</Button>
            <Typography sx={{ lineHeight: "30px", fontSize: 13 }}>Page {page}</Typography>
            <Button size="small" onClick={() => setPage((p) => p + 1)}>Next</Button>
          </Box>
        )}
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={selected.size === 0 || addMut.isPending}
          onClick={() => addMut.mutate()}
          startIcon={addMut.isPending ? <CircularProgress size={14} /> : <LibraryAdd />}>
          Add {selected.size > 0 ? `${selected.size} Control${selected.size !== 1 ? "s" : ""}` : "Controls"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ── Native control dialog ─────────────────────────────────────────────────────

function NativeControlDialog({
  cfId,
  domains,
  onClose,
}: {
  cfId: string;
  domains: DomainItem[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [controlId, setControlId] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [weight, setWeight] = useState(1);
  const [domainId, setDomainId] = useState("");

  const createMut = useMutation({
    mutationFn: () => customFrameworksApi.createNativeControl(cfId, {
      control_id: controlId.trim(),
      title: title.trim(),
      description: description.trim() || undefined,
      weight,
      domain_id: domainId || undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-framework", cfId] });
      qc.invalidateQueries({ queryKey: ["custom-frameworks"] });
      toast.success("Custom control added");
      onClose();
    },
    onError: () => toast.error("Failed to add control"),
  });

  return (
    <Dialog open fullWidth maxWidth="sm" onClose={onClose}>
      <DialogTitle sx={{ fontWeight: 700 }}>Add Custom Control</DialogTitle>
      <DialogContent>
        <Alert severity="info" sx={{ mb: 2, mt: 0.5 }}>
          Custom controls are standalone — not tied to any existing framework. Use them to represent
          requirements unique to your policy (e.g. MAS-specific timelines, internal SLAs).
        </Alert>
        <TextField fullWidth label="Control ID" value={controlId}
          onChange={(e) => setControlId(e.target.value)} autoFocus
          placeholder="e.g. MAS-7.1 or ORG-POL-01" sx={{ mb: 2 }} />
        <TextField fullWidth label="Title" value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Short name for this control" sx={{ mb: 2 }} />
        <TextField fullWidth label="Description (optional)" value={description}
          onChange={(e) => setDescription(e.target.value)} multiline rows={3}
          placeholder="Detail the requirement, acceptance criteria, or guidance" sx={{ mb: 2 }} />
        <Box sx={{ display: "flex", gap: 2 }}>
          <FormControl size="small" sx={{ minWidth: 140 }}>
            <InputLabel>Criticality</InputLabel>
            <Select label="Criticality" value={weight} onChange={(e) => setWeight(Number(e.target.value))}>
              <MenuItem value={1}>Standard</MenuItem>
              <MenuItem value={2}>Important</MenuItem>
              <MenuItem value={3}>Critical</MenuItem>
            </Select>
          </FormControl>
          {domains.length > 0 && (
            <FormControl size="small" sx={{ minWidth: 200 }}>
              <InputLabel>Domain (optional)</InputLabel>
              <Select label="Domain (optional)" value={domainId} onChange={(e) => setDomainId(e.target.value)}>
                <MenuItem value=""><em>No domain</em></MenuItem>
                {domains.map((d) => <MenuItem key={d.id} value={d.id}>{d.name}</MenuItem>)}
              </Select>
            </FormControl>
          )}
        </Box>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={!controlId.trim() || !title.trim() || createMut.isPending}
          onClick={() => createMut.mutate()}
          startIcon={createMut.isPending ? <CircularProgress size={14} /> : <Add />}>
          Add Control
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ── Domain manager dialog ─────────────────────────────────────────────────────

function DomainManagerDialog({
  cfId,
  domains,
  onClose,
}: {
  cfId: string;
  domains: DomainItem[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const createMut = useMutation({
    mutationFn: () => customFrameworksApi.createDomain(cfId, {
      name: name.trim(),
      description: description.trim() || undefined,
      sort_order: domains.length,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-framework", cfId] });
      toast.success("Domain added");
      setName("");
      setDescription("");
    },
    onError: () => toast.error("Failed to create domain"),
  });

  const deleteMut = useMutation({
    mutationFn: (domainId: string) => customFrameworksApi.deleteDomain(cfId, domainId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-framework", cfId] });
      toast.success("Domain removed");
    },
    onError: () => toast.error("Failed to remove domain"),
  });

  return (
    <Dialog open fullWidth maxWidth="sm" onClose={onClose}>
      <DialogTitle sx={{ fontWeight: 700 }}>Manage Domains</DialogTitle>
      <DialogContent>
        <Alert severity="info" sx={{ mb: 2, mt: 0.5 }}>
          Domains group controls into categories (e.g. Governance, Access Control). Custom controls
          can be assigned to a domain; mapped controls are grouped by their source framework domain.
        </Alert>

        {domains.length > 0 && (
          <Box sx={{ mb: 2 }}>
            {domains.map((d) => (
              <Box key={d.id} sx={{ display: "flex", alignItems: "center", gap: 1,
                py: 1, borderBottom: "1px solid", borderColor: "divider" }}>
                <Category sx={{ fontSize: 16, color: "primary.main" }} />
                <Box sx={{ flex: 1 }}>
                  <Typography sx={{ fontWeight: 600, fontSize: 13 }}>{d.name}</Typography>
                  {d.description && (
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>{d.description}</Typography>
                  )}
                </Box>
                <Tooltip title="Remove domain (does not delete controls)">
                  <IconButton size="small" sx={{ color: "error.main" }}
                    onClick={() => deleteMut.mutate(d.id)} disabled={deleteMut.isPending}>
                    <Delete fontSize="small" />
                  </IconButton>
                </Tooltip>
              </Box>
            ))}
          </Box>
        )}

        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Add New Domain</Typography>
        <TextField fullWidth label="Domain name" value={name}
          onChange={(e) => setName(e.target.value)} size="small"
          placeholder="e.g. Governance, Access Control, Cyber Hygiene" sx={{ mb: 1.5 }} />
        <TextField fullWidth label="Description (optional)" value={description}
          onChange={(e) => setDescription(e.target.value)} size="small"
          placeholder="What this domain covers" />
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose}>Close</Button>
        <Button variant="contained" disabled={!name.trim() || createMut.isPending}
          onClick={() => createMut.mutate()}
          startIcon={createMut.isPending ? <CircularProgress size={14} /> : <Add />}>
          Add Domain
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ── Detail view ───────────────────────────────────────────────────────────────

export function FrameworkDetail({ cfId, onBack }: { cfId: string; onBack: () => void }) {
  const qc = useQueryClient();
  const [pickerOpen, setPickerOpen] = useState(false);
  const [nativeOpen, setNativeOpen] = useState(false);
  const [domainOpen, setDomainOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [tab, setTab] = useState(0);

  const { data: cf, isLoading } = useQuery<CustomFrameworkDetail>({
    queryKey: ["custom-framework", cfId],
    queryFn: () => customFrameworksApi.get(cfId),
  });

  const renameMut = useMutation({
    mutationFn: () => customFrameworksApi.update(cfId, {
      name: editName.trim(),
      description: editDesc.trim() || undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-framework", cfId] });
      qc.invalidateQueries({ queryKey: ["custom-frameworks"] });
      toast.success("Policy updated");
      setEditOpen(false);
    },
    onError: () => toast.error("Failed to update policy"),
  });

  const removeMut = useMutation({
    mutationFn: (fkCtrlId: string) => customFrameworksApi.removeControl(cfId, fkCtrlId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-framework", cfId] });
      qc.invalidateQueries({ queryKey: ["custom-frameworks"] });
    },
    onError: () => toast.error("Failed to remove control"),
  });

  const removeNativeMut = useMutation({
    mutationFn: (ncId: string) => customFrameworksApi.deleteNativeControl(cfId, ncId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-framework", cfId] });
      qc.invalidateQueries({ queryKey: ["custom-frameworks"] });
    },
    onError: () => toast.error("Failed to remove control"),
  });

  if (isLoading) return <CircularProgress size={24} />;
  if (!cf) return null;

  const existingIds = new Set(cf.controls.map((c) => c.id));
  const totalControls = cf.controls.length + cf.native_controls.length;

  const byDomain = cf.controls.reduce<Record<string, MappedControl[]>>((acc, c) => {
    const d = c.control_domain || c.domain || "Uncategorized";
    if (!acc[d]) acc[d] = [];
    acc[d].push(c);
    return acc;
  }, {});

  const nativeByDomain = cf.native_controls.reduce<Record<string, NativeControlItem[]>>((acc, nc) => {
    const d = nc.domain_name || "Uncategorized";
    if (!acc[d]) acc[d] = [];
    acc[d].push(nc);
    return acc;
  }, {});

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
        <IconButton onClick={onBack} size="small"><ArrowBack /></IconButton>
        <Box sx={{ flex: 1 }}>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>{cf.name}</Typography>
          {cf.description && (
            <Typography variant="body2" sx={{ color: "text.secondary", maxWidth: 700 }}>{cf.description}</Typography>
          )}
        </Box>
        <Chip label={`${totalControls} controls`} size="small" sx={{ mr: 0.5 }} />
        {cf.domains.length > 0 && (
          <Chip label={`${cf.domains.length} domains`} size="small" color="primary" variant="outlined" sx={{ mr: 0.5 }} />
        )}
        <Chip label={cf.slug} size="small" variant="outlined" sx={{ fontFamily: "monospace" }} />
        <Tooltip title="Rename / edit policy">
          <IconButton size="small" onClick={() => { setEditName(cf.name); setEditDesc(cf.description || ""); setEditOpen(true); }}
            sx={{ color: "text.secondary" }}>
            <Edit fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>

      {/* Action buttons */}
      <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
        <Button variant="contained" startIcon={<LibraryAdd />} size="small"
          onClick={() => setPickerOpen(true)}>
          Add from Standards
        </Button>
        <Button variant="outlined" startIcon={<Build />} size="small"
          onClick={() => setNativeOpen(true)}>
          Add Custom Control
        </Button>
        <Button variant="outlined" startIcon={<Category />} size="small"
          onClick={() => setDomainOpen(true)}>
          {cf.domains.length > 0 ? `Domains (${cf.domains.length})` : "Add Domains"}
        </Button>
      </Box>

      {/* Tabs: Mapped controls | Custom controls */}
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2, borderBottom: "1px solid", borderColor: "divider" }}>
        <Tab label={`From Standards (${cf.controls.length})`} />
        <Tab label={`Custom Controls (${cf.native_controls.length})`} />
      </Tabs>

      {/* Tab 0: Mapped controls from existing frameworks */}
      {tab === 0 && (
        <>
          {cf.controls.length === 0 && (
            <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
              <LibraryAdd sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
              <Typography sx={{ color: "text.secondary" }}>
                No mapped controls yet. Click <strong>Add from Standards</strong> to pick from NIST, ISO 27001, PCI DSS, and more.
              </Typography>
            </Card>
          )}
          {Object.entries(byDomain).map(([domain, controls]) => (
            <Box key={domain} sx={{ mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.secondary",
                textTransform: "uppercase", letterSpacing: 0.5, fontSize: 11, mb: 1 }}>
                {domain} <Chip label={controls.length} size="small" sx={{ ml: 0.5, height: 16, fontSize: 10 }} />
              </Typography>
              <Card variant="outlined">
                {controls.map((c, idx) => (
                  <Box key={c.id}>
                    {idx > 0 && <Divider />}
                    <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5, px: 2, py: 1.5 }}>
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.25 }}>
                          <Typography variant="caption" sx={{ fontWeight: 700, color: "text.secondary", fontFamily: "monospace" }}>
                            {c.framework.toUpperCase()} · {c.control_id}
                          </Typography>
                          {c.reference_id && (
                            <Chip label={c.reference_id} size="small"
                              sx={{ height: 16, fontSize: 9, bgcolor: "#E3F2FD", color: "#1565C0", fontWeight: 700, fontFamily: "monospace" }} />
                          )}
                          {c.weight >= 2 && (
                            <Chip label={WEIGHT_LABEL[c.weight]} size="small"
                              sx={{ height: 16, fontSize: 9, bgcolor: `${WEIGHT_COLOR[c.weight]}22`,
                                color: WEIGHT_COLOR[c.weight], fontWeight: 700 }} />
                          )}
                        </Box>
                        <Typography sx={{ fontSize: 13, fontWeight: 600 }}>{c.title}</Typography>
                        {c.description && (
                          <Typography variant="caption" sx={{ color: "text.secondary" }}>{c.description}</Typography>
                        )}
                      </Box>
                      <Tooltip title="Remove from policy">
                        <IconButton size="small" onClick={() => removeMut.mutate(c.id)}
                          disabled={removeMut.isPending}
                          sx={{ color: "error.main", opacity: 0.6, "&:hover": { opacity: 1 } }}>
                          <Delete fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </Box>
                ))}
              </Card>
            </Box>
          ))}
        </>
      )}

      {/* Tab 1: Native custom controls */}
      {tab === 1 && (
        <>
          {cf.native_controls.length === 0 && (
            <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
              <Build sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
              <Typography sx={{ color: "text.secondary" }}>
                No custom controls yet. Click <strong>Add Custom Control</strong> to define requirements
                not covered by existing standards (e.g. specific RTO thresholds, regulator timelines).
              </Typography>
            </Card>
          )}
          {Object.entries(nativeByDomain).map(([domain, controls]) => (
            <Box key={domain} sx={{ mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.secondary",
                textTransform: "uppercase", letterSpacing: 0.5, fontSize: 11, mb: 1 }}>
                {domain} <Chip label={controls.length} size="small" sx={{ ml: 0.5, height: 16, fontSize: 10 }} />
              </Typography>
              <Card variant="outlined">
                {controls.map((nc, idx) => (
                  <Box key={nc.id}>
                    {idx > 0 && <Divider />}
                    <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5, px: 2, py: 1.5 }}>
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.25 }}>
                          <Typography variant="caption" sx={{ fontWeight: 700, color: "#6A1B9A", fontFamily: "monospace" }}>
                            {nc.control_id}
                          </Typography>
                          <Chip label="Custom" size="small"
                            sx={{ height: 16, fontSize: 9, bgcolor: "#F3E5F5", color: "#6A1B9A", fontWeight: 700 }} />
                          {nc.weight >= 2 && (
                            <Chip label={WEIGHT_LABEL[nc.weight]} size="small"
                              sx={{ height: 16, fontSize: 9, bgcolor: `${WEIGHT_COLOR[nc.weight]}22`,
                                color: WEIGHT_COLOR[nc.weight], fontWeight: 700 }} />
                          )}
                        </Box>
                        <Typography sx={{ fontSize: 13, fontWeight: 600 }}>{nc.title}</Typography>
                        {nc.description && (
                          <Typography variant="caption" sx={{ color: "text.secondary" }}>{nc.description}</Typography>
                        )}
                      </Box>
                      <Tooltip title="Remove control">
                        <IconButton size="small" onClick={() => removeNativeMut.mutate(nc.id)}
                          disabled={removeNativeMut.isPending}
                          sx={{ color: "error.main", opacity: 0.6, "&:hover": { opacity: 1 } }}>
                          <Delete fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </Box>
                ))}
              </Card>
            </Box>
          ))}
        </>
      )}

      {pickerOpen && (
        <ControlPickerDialog cfId={cfId} existingIds={existingIds}
          onClose={() => setPickerOpen(false)} />
      )}
      {nativeOpen && (
        <NativeControlDialog cfId={cfId} domains={cf.domains}
          onClose={() => setNativeOpen(false)} />
      )}
      {domainOpen && (
        <DomainManagerDialog cfId={cfId} domains={cf.domains}
          onClose={() => setDomainOpen(false)} />
      )}

      <Dialog open={editOpen} onClose={() => setEditOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ fontWeight: 700 }}>Edit Policy</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Policy name" value={editName}
            onChange={(e) => setEditName(e.target.value)} autoFocus sx={{ mb: 2, mt: 1 }} />
          <TextField fullWidth label="Description (optional)" value={editDesc}
            onChange={(e) => setEditDesc(e.target.value)} multiline rows={2}
            placeholder="Describe what this policy covers and who it applies to" />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setEditOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={!editName.trim() || renameMut.isPending}
            onClick={() => renameMut.mutate()}
            startIcon={renameMut.isPending ? <CircularProgress size={14} /> : <Edit />}>
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CustomFrameworks() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [selectedCf, setSelectedCf] = useState<string | null>(null);
  const [editOpen, setEditOpen] = useState(false);
  const [editId, setEditId] = useState<string>("");
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");

  const { data: frameworks = [], isLoading, refetch } = useQuery<CustomFrameworkSummary[]>({
    queryKey: ["custom-frameworks"],
    queryFn: () => customFrameworksApi.list(),
  });

  const createMut = useMutation({
    mutationFn: () => customFrameworksApi.create({ name: newName.trim(), description: newDesc.trim() || undefined }),
    onSuccess: (created) => {
      qc.invalidateQueries({ queryKey: ["custom-frameworks"] });
      toast.success(`"${created.name}" created`);
      setCreateOpen(false);
      setNewName("");
      setNewDesc("");
      setSelectedCf(created.id);
    },
    onError: () => toast.error("Failed to create policy"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => customFrameworksApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["custom-frameworks"] });
      toast.success("Policy deleted");
    },
    onError: () => toast.error("Failed to delete policy"),
  });

  const renameMut = useMutation({
    mutationFn: () => customFrameworksApi.update(editId, {
      name: editName.trim(),
      description: editDesc.trim() || undefined,
    }),
    onSuccess: (updated) => {
      qc.invalidateQueries({ queryKey: ["custom-frameworks"] });
      toast.success(`Renamed to "${updated.name}"`);
      setEditOpen(false);
    },
    onError: () => toast.error("Failed to rename policy"),
  });

  const handleDelete = useCallback((e: React.MouseEvent, id: string, name: string) => {
    e.stopPropagation();
    if (window.confirm(`Delete "${name}"? This cannot be undone.`)) deleteMut.mutate(id);
  }, [deleteMut]);

  const handleEditOpen = useCallback((e: React.MouseEvent, cf: CustomFrameworkSummary) => {
    e.stopPropagation();
    setEditId(cf.id);
    setEditName(cf.name);
    setEditDesc(cf.description || "");
    setEditOpen(true);
  }, []);

  if (selectedCf) {
    return (
      <Box>
        <FrameworkDetail cfId={selectedCf} onBack={() => setSelectedCf(null)} />
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Custom Policy</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Build custom compliance policies by combining controls from NIST, ISO 27001, CIS, PCI DSS, GDPR,
            and your own custom requirements with named domains.
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1 }}>
          <IconButton onClick={() => refetch()}><Refresh /></IconButton>
          <Button variant="contained" startIcon={<Add />} onClick={() => setCreateOpen(true)}>
            New Policy
          </Button>
        </Box>
      </Box>

      {isLoading && <CircularProgress size={24} />}

      {!isLoading && frameworks.length === 0 && (
        <Card variant="outlined" sx={{ p: 5, textAlign: "center" }}>
          <LibraryAdd sx={{ fontSize: 52, color: "text.secondary", mb: 1.5 }} />
          <Typography variant="h6" sx={{ fontWeight: 600, mb: 1 }}>No custom policies yet</Typography>
          <Typography sx={{ color: "text.secondary", mb: 2.5, maxWidth: 520, mx: "auto" }}>
            Create a named policy and pick controls from any loaded framework.
            Add your own domains and custom controls to fill gaps not covered by existing standards.
          </Typography>
          <Button variant="contained" startIcon={<Add />} onClick={() => setCreateOpen(true)}>
            Create Your First Policy
          </Button>
        </Card>
      )}

      <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
        {frameworks.map((cf) => (
          <Card key={cf.id} variant="outlined" sx={{ cursor: "pointer", transition: "all 0.15s",
            "&:hover": { boxShadow: 3, borderColor: "primary.main" } }}
            onClick={() => setSelectedCf(cf.id)}>
            <CardContent sx={{ display: "flex", alignItems: "center", gap: 2,
              py: 2, "&:last-child": { pb: 2 } }}>
              <LibraryAdd sx={{ color: "primary.main", fontSize: 28, flexShrink: 0 }} />
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Typography sx={{ fontWeight: 700, fontSize: 15 }}>{cf.name}</Typography>
                {cf.description && (
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>{cf.description}</Typography>
                )}
                <Box sx={{ display: "flex", gap: 1, mt: 0.5 }}>
                  <Chip label={`${cf.control_count} controls`} size="small" variant="outlined" />
                  <Chip label={cf.slug} size="small" sx={{ fontFamily: "monospace", fontSize: 10 }} />
                </Box>
              </Box>
              <Tooltip title="Rename / edit policy">
                <IconButton size="small" onClick={(e) => handleEditOpen(e, cf)}
                  sx={{ color: "text.secondary" }}>
                  <Edit fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title="Delete policy">
                <IconButton size="small" onClick={(e) => handleDelete(e, cf.id, cf.name)}
                  sx={{ color: "error.main" }}>
                  <Delete fontSize="small" />
                </IconButton>
              </Tooltip>
            </CardContent>
          </Card>
        ))}
      </Box>

      {/* Rename/edit dialog */}
      <Dialog open={editOpen} onClose={() => setEditOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ fontWeight: 700 }}>Rename Policy</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Policy name" value={editName}
            onChange={(e) => setEditName(e.target.value)} autoFocus sx={{ mb: 2, mt: 1 }} />
          <TextField fullWidth label="Description (optional)" value={editDesc}
            onChange={(e) => setEditDesc(e.target.value)} multiline rows={2}
            placeholder="Describe what this policy covers and who it applies to" />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setEditOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={!editName.trim() || renameMut.isPending}
            onClick={() => renameMut.mutate()}
            startIcon={renameMut.isPending ? <CircularProgress size={14} /> : <Edit />}>
            Save
          </Button>
        </DialogActions>
      </Dialog>

      {/* Create dialog */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ fontWeight: 700 }}>Create Custom Policy</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2, mt: 0.5 }}>
            After creating, you'll be taken to the builder to add domains, select controls from
            existing frameworks, and define your own custom controls.
          </Alert>
          <TextField fullWidth label="Policy name" value={newName}
            onChange={(e) => setNewName(e.target.value)} autoFocus
            placeholder="e.g. MAS TRM, Accenture Security Baseline" sx={{ mb: 2 }} />
          <TextField fullWidth label="Description (optional)" value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)} multiline rows={2}
            placeholder="Describe what this policy covers and who it applies to" />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={!newName.trim() || createMut.isPending}
            onClick={() => createMut.mutate()}
            startIcon={createMut.isPending ? <CircularProgress size={14} /> : <Add />}>
            Create & Build
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
