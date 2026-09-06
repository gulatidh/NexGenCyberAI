import React, { useState } from "react";
import {
  Box, Typography, Button, Tabs, Tab, Table, TableHead, TableRow,
  TableCell, TableBody, Chip, IconButton, Dialog, DialogTitle,
  DialogContent, DialogActions, TextField, MenuItem, Select,
  FormControl, InputLabel, CircularProgress, Tooltip, Stack,
} from "@mui/material";
import {
  Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon,
  LinkOff as UnlinkIcon,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { technologyRegistryApi } from "../services/api";
import { TechnologyType, AssetTypeMapping } from "../types";

const CATEGORIES = ["Compute", "Application", "Storage", "Network", "Security", "Identity", "Other"];

const DEFAULT_COLORS: Record<string, string> = {
  Compute: "#2563eb", Application: "#059669", Storage: "#6d28d9",
  Network: "#0369a1", Security: "#b45309", Identity: "#7e22ce", Other: "#6b7280",
};

// ── Type form dialog ──────────────────────────────────────────────────────────

interface TypeFormProps {
  open: boolean;
  onClose: () => void;
  initial?: Partial<TechnologyType>;
}

function TypeFormDialog({ open, onClose, initial }: TypeFormProps) {
  const qc = useQueryClient();
  const isEdit = !!initial?.id;
  const [name, setName] = useState(initial?.name ?? "");
  const [cat, setCat] = useState(initial?.category ?? "");
  const [sub, setSub] = useState(initial?.sub_category ?? "");
  const [color, setColor] = useState(initial?.color ?? "#6b7280");
  const [desc, setDesc] = useState(initial?.description ?? "");

  React.useEffect(() => {
    if (open) {
      setName(initial?.name ?? "");
      setCat(initial?.category ?? "");
      setSub(initial?.sub_category ?? "");
      setColor(initial?.color ?? "#6b7280");
      setDesc(initial?.description ?? "");
    }
  }, [open]);

  const createMut = useMutation({
    mutationFn: () => technologyRegistryApi.createType({ name, category: cat, sub_category: sub, color, description: desc }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["tech-types"] }); onClose(); },
  });
  const updateMut = useMutation({
    mutationFn: () => technologyRegistryApi.updateType(initial!.id!, { name, color, description: desc }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["tech-types"] }); onClose(); },
  });

  const busy = createMut.isPending || updateMut.isPending;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{isEdit ? "Edit Technology Type" : "New Technology Type"}</DialogTitle>
      <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2, pt: "16px !important" }}>
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} required fullWidth />
        <FormControl fullWidth disabled={isEdit && !!initial?.is_builtin}>
          <InputLabel>Category</InputLabel>
          <Select value={cat} label="Category" onChange={(e) => { setCat(e.target.value); setColor(DEFAULT_COLORS[e.target.value] ?? "#6b7280"); }}>
            {CATEGORIES.map((c) => <MenuItem key={c} value={c}>{c}</MenuItem>)}
          </Select>
        </FormControl>
        <TextField
          label="Sub-category"
          value={sub}
          onChange={(e) => setSub(e.target.value)}
          disabled={isEdit && !!initial?.is_builtin}
          fullWidth
          helperText="e.g. Serverless, WAF, Secret Manager"
        />
        <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
          <TextField label="Color" value={color} onChange={(e) => setColor(e.target.value)} sx={{ flex: 1 }} />
          <Box sx={{ width: 36, height: 36, borderRadius: 1, bgcolor: color, border: "1px solid #ccc" }} />
        </Stack>
        <TextField label="Description" value={desc} onChange={(e) => setDesc(e.target.value)} multiline rows={2} fullWidth />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button
          variant="contained"
          disabled={!name.trim() || busy}
          onClick={() => isEdit ? updateMut.mutate() : createMut.mutate()}
        >
          {busy ? <CircularProgress size={18} /> : isEdit ? "Save" : "Create"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ── Mapping form dialog ───────────────────────────────────────────────────────

interface MappingFormProps {
  open: boolean;
  onClose: () => void;
  types: TechnologyType[];
}

function MappingFormDialog({ open, onClose, types }: MappingFormProps) {
  const qc = useQueryClient();
  const [providerType, setProviderType] = useState("");
  const [typeId, setTypeId] = useState("");

  React.useEffect(() => { if (open) { setProviderType(""); setTypeId(""); } }, [open]);

  const mut = useMutation({
    mutationFn: () => technologyRegistryApi.upsertMapping({ provider_type: providerType.trim(), technology_type_id: typeId }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["tech-mappings"] }); onClose(); },
  });

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Add Provider Type Mapping</DialogTitle>
      <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2, pt: "16px !important" }}>
        <TextField
          label="Provider Resource Type"
          value={providerType}
          onChange={(e) => setProviderType(e.target.value)}
          fullWidth
          helperText="e.g. microsoft.compute/virtualmachines or aws::ec2::instance"
        />
        <FormControl fullWidth>
          <InputLabel>Maps to Technology Type</InputLabel>
          <Select value={typeId} label="Maps to Technology Type" onChange={(e) => setTypeId(e.target.value)}>
            {types.map((t) => (
              <MenuItem key={t.id} value={t.id}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Box sx={{ width: 12, height: 12, borderRadius: "50%", bgcolor: t.color ?? "#6b7280" }} />
                  {t.name}
                  {t.category && <Typography variant="caption" color="text.secondary">({t.category})</Typography>}
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={mut.isPending}>Cancel</Button>
        <Button
          variant="contained"
          disabled={!providerType.trim() || !typeId || mut.isPending}
          onClick={() => mut.mutate()}
        >
          {mut.isPending ? <CircularProgress size={18} /> : "Save Mapping"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function TechnologyRegistry() {
  const [tab, setTab] = useState(0);
  const [typeFormOpen, setTypeFormOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<TechnologyType | undefined>(undefined);
  const [mappingFormOpen, setMappingFormOpen] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const qc = useQueryClient();

  const { data: types = [], isLoading: typesLoading } = useQuery<TechnologyType[]>({
    queryKey: ["tech-types"],
    queryFn: () => technologyRegistryApi.listTypes(),
  });

  const { data: mappings = [], isLoading: mappingsLoading } = useQuery<AssetTypeMapping[]>({
    queryKey: ["tech-mappings"],
    queryFn: () => technologyRegistryApi.listMappings(),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => technologyRegistryApi.deleteType(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["tech-types"] }); setDeleteConfirm(null); },
  });

  const deleteMappingMut = useMutation({
    mutationFn: (id: string) => technologyRegistryApi.deleteMapping(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tech-mappings"] }),
  });

  const byCategory = types.reduce<Record<string, TechnologyType[]>>((acc, t) => {
    const k = t.category ?? "Other";
    (acc[k] = acc[k] ?? []).push(t);
    return acc;
  }, {});

  return (
    <Box sx={{ p: 3, maxWidth: 1100 }}>
      <Typography variant="h5" sx={{ fontWeight: 700 }} gutterBottom>Technology Registry</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Define your technology taxonomy and map provider resource types to technology categories.
        Use asset-level overrides on individual assets to correct auto-detected types.
      </Typography>

      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 3, borderBottom: 1, borderColor: "divider" }}>
        <Tab label={`Technology Types (${types.length})`} />
        <Tab label={`Provider Mappings (${mappings.length})`} />
      </Tabs>

      {/* ── Technology Types tab ── */}
      {tab === 0 && (
        <Box>
          <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2 }}>
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => { setEditTarget(undefined); setTypeFormOpen(true); }}>
              New Type
            </Button>
          </Box>

          {typesLoading ? <CircularProgress /> : (
            Object.entries(byCategory).sort().map(([cat, rows]) => (
              <Box key={cat} sx={{ mb: 3 }}>
                <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>{cat}</Typography>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Sub-category</TableCell>
                      <TableCell>Description</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {rows.map((t) => (
                      <TableRow key={t.id} hover>
                        <TableCell>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Box sx={{ width: 12, height: 12, borderRadius: "50%", bgcolor: t.color ?? "#6b7280", flexShrink: 0 }} />
                            <Typography variant="body2" sx={{ fontWeight: 500 }}>{t.name}</Typography>
                            {t.is_builtin && <Chip label="built-in" size="small" sx={{ fontSize: 10, height: 18 }} />}
                          </Box>
                        </TableCell>
                        <TableCell><Typography variant="body2" color="text.secondary">{t.sub_category ?? "—"}</Typography></TableCell>
                        <TableCell><Typography variant="body2" color="text.secondary" noWrap sx={{ maxWidth: 320 }}>{t.description ?? "—"}</Typography></TableCell>
                        <TableCell align="right">
                          <Tooltip title="Edit">
                            <IconButton size="small" onClick={() => { setEditTarget(t); setTypeFormOpen(true); }}>
                              <EditIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          {!t.is_builtin && (
                            <Tooltip title="Delete">
                              <IconButton size="small" color="error" onClick={() => setDeleteConfirm(t.id)}>
                                <DeleteIcon fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Box>
            ))
          )}
        </Box>
      )}

      {/* ── Mappings tab ── */}
      {tab === 1 && (
        <Box>
          <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2 }}>
            <Button variant="contained" startIcon={<AddIcon />} onClick={() => setMappingFormOpen(true)}>
              Add Mapping
            </Button>
          </Box>
          {mappingsLoading ? <CircularProgress /> : (
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Provider Resource Type</TableCell>
                  <TableCell>Maps to</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {mappings.map((m) => (
                  <TableRow key={m.id} hover>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{m.provider_type}</Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Box sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: m.technology_type_color ?? "#6b7280" }} />
                        <Typography variant="body2">{m.technology_type_name ?? "—"}</Typography>
                      </Box>
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Remove mapping">
                        <IconButton size="small" color="error" onClick={() => deleteMappingMut.mutate(m.id)}>
                          <UnlinkIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
                {mappings.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={3} align="center">
                      <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>No mappings yet</Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </Box>
      )}

      {/* Dialogs */}
      <TypeFormDialog open={typeFormOpen} onClose={() => setTypeFormOpen(false)} initial={editTarget} />
      <MappingFormDialog open={mappingFormOpen} onClose={() => setMappingFormOpen(false)} types={types} />

      <Dialog open={!!deleteConfirm} onClose={() => setDeleteConfirm(null)}>
        <DialogTitle>Delete Technology Type?</DialogTitle>
        <DialogContent>
          <Typography>This will remove the type and all its provider mappings. Assets using this type will revert to their auto-detected class.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirm(null)}>Cancel</Button>
          <Button color="error" variant="contained" onClick={() => deleteMut.mutate(deleteConfirm!)}>Delete</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
