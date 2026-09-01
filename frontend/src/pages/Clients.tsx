import React, { useState, useMemo, useCallback } from "react";
import { useIsGuest } from "../hooks/useIsGuest";
import {
  Box, Typography, Button, IconButton, Chip, Avatar,
  Table, TableHead, TableRow, TableCell, TableBody,
  Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, CircularProgress, Select, MenuItem, FormControl, InputLabel,
  Tooltip, InputAdornment, Collapse,
} from "@mui/material";
import {
  Add, Refresh, UnfoldMore, UnfoldLess, Download, History,
  People, VpnKey, ChevronRight, ExpandMore, Search,
  Edit, Delete, FolderSpecial,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useLocation } from "react-router-dom";
import { clientsApi, projectsApi } from "../services/api";
import { Client, Project } from "../types";
import { toast } from "react-toastify";

const FORM_FIELDS = [
  { key: "name",          label: "Account Name *" },
  { key: "slug",          label: "Slug (URL-safe) *" },
  { key: "industry",      label: "Industry" },
  { key: "country",       label: "Country" },
  { key: "contact_name",  label: "Contact Name" },
  { key: "contact_email", label: "Contact Email" },
];
const EMPTY_FORM = { name: "", slug: "", industry: "", country: "", contact_name: "", contact_email: "" };

function ClientForm({ form, onChange }: { form: typeof EMPTY_FORM; onChange: (f: typeof EMPTY_FORM) => void }) {
  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
      {FORM_FIELDS.map(({ key, label }) => (
        <TextField key={key} fullWidth size="small" label={label}
          value={(form as any)[key]}
          onChange={(e) => onChange({ ...form, [key]: e.target.value })} />
      ))}
    </Box>
  );
}

function ProjectRows({ clientId, expanded, searchQuery, navigate, clientBase, isGuest }: {
  clientId: string; expanded: boolean; searchQuery: string;
  navigate: (path: string) => void; clientBase: string; isGuest: boolean;
}) {
  const qc = useQueryClient();
  const { data: projects = [], isLoading } = useQuery<Project[]>({
    queryKey: ["projects", clientId],
    queryFn: () => projectsApi.list(clientId),
  });

  const deleteProjectMutation = useMutation({
    mutationFn: (projectId: string) => projectsApi.delete(clientId, projectId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects", clientId] });
      toast.success("Project deleted");
    },
  });

  const visible = searchQuery
    ? projects.filter((p) => p.name.toLowerCase().includes(searchQuery.toLowerCase()))
    : projects;

  if (!expanded) return null;
  if (isLoading) {
    return (
      <TableRow>
        <TableCell colSpan={5} sx={{ pl: 8, py: 1, borderColor: "divider" }}>
          <CircularProgress size={14} sx={{ mr: 1 }} />
          <Typography variant="caption" sx={{ color: "text.secondary" }}>Loading projects…</Typography>
        </TableCell>
      </TableRow>
    );
  }

  return (
    <>
      {visible.map((p) => (
        <TableRow key={p.id} sx={{
          bgcolor: "transparent",
          "&:hover": { bgcolor: "action.hover" },
          "& td": { borderColor: "divider", py: 1 },
        }}>
          <TableCell sx={{ pl: 7 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <Box sx={{ width: 4, height: 4, borderRadius: "50%", bgcolor: "divider", flexShrink: 0 }} />
              <Box sx={{
                width: 26, height: 26, borderRadius: 1,
                bgcolor: "rgba(251,188,4,0.15)",
                display: "flex", alignItems: "center", justifyContent: "center",
                flexShrink: 0,
              }}>
                <VpnKey sx={{ fontSize: 13, color: "#F9AB00" }} />
              </Box>
              <Typography
                variant="body2"
                sx={{ color: "primary.main", cursor: "pointer", fontWeight: 500, fontSize: 13,
                  "&:hover": { textDecoration: "underline" } }}
                onClick={() => navigate(`${clientBase}/${clientId}?tab=projects`)}
              >
                {p.name}
              </Typography>
              {p.environment && (
                <Chip label={p.environment} size="small"
                  sx={{ fontSize: 9, height: 16, bgcolor: "action.selected", color: "text.secondary", textTransform: "capitalize" }} />
              )}
            </Box>
          </TableCell>
          <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>Project</TableCell>
          <TableCell sx={{ fontFamily: "monospace", fontSize: 11, color: "text.disabled" }}>{p.id}</TableCell>
          <TableCell sx={{ color: "text.disabled", fontSize: 12 }}>—</TableCell>
          <TableCell>
            {!isGuest && (
              <IconButton size="small" sx={{ color: "text.disabled", "&:hover": { color: "error.main" } }}
                onClick={() => {
                  if (window.confirm(`Delete project "${p.name}"?`)) deleteProjectMutation.mutate(p.id);
                }}>
                <Delete sx={{ fontSize: 15 }} />
              </IconButton>
            )}
          </TableCell>
        </TableRow>
      ))}
    </>
  );
}

function useProjectCount(clientId: string) {
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", clientId],
    queryFn: () => projectsApi.list(clientId),
    staleTime: 60_000,
  });
  return projects.length;
}

function ProjectCountCell({ clientId }: { clientId: string }) {
  const count = useProjectCount(clientId);
  if (count === 0) return <Typography variant="body2" sx={{ color: "text.disabled" }}>—</Typography>;
  return <Typography variant="body2" sx={{ color: "primary.main", fontWeight: 700, fontSize: 14 }}>{count}</Typography>;
}

export default function Clients() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const isGuest = useIsGuest();
  const clientBase = location.pathname.startsWith("/platform") ? "/platform/clients" : "/clients";

  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState("");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState<typeof EMPTY_FORM>({ ...EMPTY_FORM });

  const [editClient, setEditClient] = useState<Client | null>(null);
  const [editForm, setEditForm] = useState<typeof EMPTY_FORM>({ ...EMPTY_FORM });

  const [pendingDelete, setPendingDelete] = useState<Client | null>(null);

  const [addProjectOpen, setAddProjectOpen] = useState(false);
  const [addProjectClientId, setAddProjectClientId] = useState("");
  const [addProjectForm, setAddProjectForm] = useState({ name: "", description: "", environment: "", cloud_provider: "" });

  const { data: clients = [], isLoading, refetch } = useQuery<Client[]>({
    queryKey: ["clients"],
    queryFn: clientsApi.list,
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => clientsApi.create(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["clients"] });
      setCreateOpen(false);
      setCreateForm({ ...EMPTY_FORM });
      toast.success("Account created");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error creating account"),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => clientsApi.update(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["clients"] });
      setEditClient(null);
      toast.success("Account updated");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error updating account"),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => clientsApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["clients"] });
      setPendingDelete(null);
      toast.success("Account moved to trash — restorable for 30 days from Settings → Deleted Accounts");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Delete failed"),
  });

  const addProjectMutation = useMutation({
    mutationFn: () => projectsApi.create(addProjectClientId, addProjectForm),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects", addProjectClientId] });
      setAddProjectOpen(false);
      setAddProjectForm({ name: "", description: "", environment: "", cloud_provider: "" });
      setAddProjectClientId("");
      toast.success("Project created");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error creating project"),
  });

  const filteredClients = useMemo(() => {
    let list = clients;
    if (searchQuery) {
      list = list.filter((c) =>
        c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.id.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }
    return [...list].sort((a, b) =>
      sortDir === "asc" ? a.name.localeCompare(b.name) : b.name.localeCompare(a.name)
    );
  }, [clients, searchQuery, sortDir]);

  const toggleExpanded = useCallback((id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }, []);

  const expandAll = () => setExpandedIds(new Set(filteredClients.map((c) => c.id)));
  const collapseAll = () => setExpandedIds(new Set());

  const exportCSV = () => {
    const header = ["Name", "Type", "ID", "Industry", "Country", "Status"];
    const rows = filteredClients.map((c) =>
      [c.name, "Account", c.id, c.industry || "", c.country || "", c.is_active ? "Active" : "Inactive"]
        .map((v) => `"${v}"`).join(",")
    );
    const csv = [header.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "accounts.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  const openEdit = (client: Client) => {
    setEditForm({ name: client.name || "", slug: client.slug || "", industry: client.industry || "",
      country: client.country || "", contact_name: client.contact_name || "", contact_email: client.contact_email || "" });
    setEditClient(client);
  };

  const totalExpanded = expandedIds.size;

  return (
    <Box sx={{ pb: 4 }}>
      {/* Page header */}
      <Box sx={{ mb: 2 }}>
        <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: "-0.02em" }}>Accounts</Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.25 }}>
          Manage accounts and the projects nested inside them
        </Typography>
      </Box>

      {/* Toolbar */}
      <Box sx={{
        display: "flex", alignItems: "center", gap: 0,
        borderTop: "1px solid", borderBottom: "1px solid", borderColor: "divider",
        py: 0.75, mb: 2, flexWrap: "wrap",
      }}>
        {[
          ...(!isGuest ? [
            { icon: <Add sx={{ fontSize: 15 }} />, label: "Create", onClick: () => setCreateOpen(true) },
            { icon: <FolderSpecial sx={{ fontSize: 15 }} />, label: "Add project", onClick: () => { setAddProjectOpen(true); setAddProjectClientId(clients[0]?.id || ""); } },
          ] : []),
          { icon: <Refresh sx={{ fontSize: 15 }} />, label: "Refresh", onClick: () => refetch() },
          { icon: expandedIds.size > 0 ? <UnfoldLess sx={{ fontSize: 15 }} /> : <UnfoldMore sx={{ fontSize: 15 }} />,
            label: expandedIds.size > 0 ? "Collapse all" : "Expand all",
            onClick: expandedIds.size > 0 ? collapseAll : expandAll },
          { icon: <Download sx={{ fontSize: 15 }} />, label: "Export to CSV", onClick: exportCSV },
          { icon: <History sx={{ fontSize: 15 }} />, label: "Activity logs", onClick: () => navigate("/posture-trends") },
        ].map(({ icon, label, onClick }) => (
          <Button
            key={label}
            startIcon={icon}
            onClick={onClick}
            size="small"
            sx={{
              color: "primary.main", fontWeight: 500, fontSize: 13,
              px: 1.5, py: 0.75, borderRadius: 1, mr: 0.5,
              "&:hover": { bgcolor: "action.hover" },
            }}
          >
            {label}
          </Button>
        ))}
      </Box>

      {/* Search */}
      <Box sx={{ mb: 2, maxWidth: 420 }}>
        <TextField
          fullWidth size="small"
          placeholder="Search by name or ID"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <Search sx={{ fontSize: 18, color: "text.disabled" }} />
                </InputAdornment>
              ),
            },
          }}
          sx={{ "& .MuiOutlinedInput-root": { borderRadius: 2 } }}
        />
      </Box>

      {/* Summary */}
      <Typography variant="body2" sx={{ color: "text.secondary", mb: 1.5, fontSize: 12 }}>
        {isLoading ? "Loading…" : `Showing ${filteredClients.length} account${filteredClients.length === 1 ? "" : "s"}${totalExpanded > 0 ? ` · ${totalExpanded} expanded` : ""}`}
      </Typography>

      {/* Tree table */}
      {isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 6 }}>
          <CircularProgress />
        </Box>
      ) : filteredClients.length === 0 ? (
        <Box sx={{ textAlign: "center", py: 8, color: "text.secondary" }}>
          <People sx={{ fontSize: 48, opacity: 0.3, mb: 1 }} />
          <Typography>
            {searchQuery ? `No accounts matching "${searchQuery}"` : "No accounts yet. Click Create to add the first account."}
          </Typography>
        </Box>
      ) : (
        <Box sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, overflow: "hidden" }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{
                bgcolor: "action.hover",
                "& th": { borderColor: "divider", color: "text.secondary", fontSize: 12, fontWeight: 700, py: 1.25 },
              }}>
                <TableCell sx={{ pl: 2, width: "40%" }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, cursor: "pointer", userSelect: "none" }}
                    onClick={() => setSortDir((d) => d === "asc" ? "desc" : "asc")}>
                    <Typography variant="caption" sx={{ fontWeight: 700, fontSize: 12 }}>Name</Typography>
                    <Box sx={{ display: "flex", flexDirection: "column", gap: 0 }}>
                      <Box sx={{ width: 0, height: 0, borderLeft: "4px solid transparent", borderRight: "4px solid transparent",
                        borderBottom: `5px solid ${sortDir === "asc" ? "currentColor" : "transparent"}`, mb: "1px" }} />
                      <Box sx={{ width: 0, height: 0, borderLeft: "4px solid transparent", borderRight: "4px solid transparent",
                        borderTop: `5px solid ${sortDir === "desc" ? "currentColor" : "transparent"}` }} />
                    </Box>
                  </Box>
                </TableCell>
                <TableCell sx={{ width: 100 }}>Type</TableCell>
                <TableCell sx={{ width: "32%" }}>ID</TableCell>
                <TableCell sx={{ width: 120 }}>Total projects</TableCell>
                <TableCell sx={{ width: 60 }} />
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredClients.map((client) => {
                const isExpanded = expandedIds.has(client.id);
                return (
                  <React.Fragment key={client.id}>
                    {/* Account row */}
                    <TableRow sx={{
                      bgcolor: "transparent",
                      "&:hover": { bgcolor: "action.hover" },
                      "& td": { borderColor: "divider", py: 1 },
                    }}>
                      <TableCell sx={{ pl: 1.5 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <IconButton
                            size="small"
                            onClick={() => toggleExpanded(client.id)}
                            sx={{ width: 22, height: 22, color: "text.secondary" }}
                          >
                            {isExpanded
                              ? <ExpandMore sx={{ fontSize: 16 }} />
                              : <ChevronRight sx={{ fontSize: 16 }} />}
                          </IconButton>
                          <Box sx={{
                            width: 26, height: 26, borderRadius: 1,
                            bgcolor: "rgba(66,133,244,0.15)",
                            display: "flex", alignItems: "center", justifyContent: "center",
                            flexShrink: 0,
                          }}>
                            <People sx={{ fontSize: 14, color: "#4285F4" }} />
                          </Box>
                          <Typography
                            variant="body2"
                            sx={{ color: "primary.main", cursor: "pointer", fontWeight: 600, fontSize: 14,
                              "&:hover": { textDecoration: "underline" } }}
                            onClick={() => navigate(`${clientBase}/${client.id}`)}
                          >
                            {client.name}
                          </Typography>
                          <Chip
                            label={client.is_active ? "Active" : "Inactive"}
                            size="small"
                            sx={{
                              height: 16, fontSize: 9, ml: 0.5,
                              bgcolor: client.is_active ? "rgba(52,168,83,0.12)" : "rgba(234,67,53,0.12)",
                              color: client.is_active ? "#34A853" : "#EA4335",
                            }}
                          />
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: "text.secondary", fontSize: 12 }}>Account</TableCell>
                      <TableCell>
                        <Tooltip title={client.id} placement="top">
                          <Typography variant="caption" sx={{
                            fontFamily: "monospace", fontSize: 11, color: "text.disabled",
                            display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 260,
                          }}>
                            {client.id}
                          </Typography>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <ProjectCountCell clientId={client.id} />
                      </TableCell>
                      <TableCell>
                        {!isGuest && (
                          <Box sx={{ display: "flex", gap: 0.25 }}>
                            <IconButton size="small" sx={{ color: "text.disabled", "&:hover": { color: "text.secondary" } }}
                              onClick={() => openEdit(client)}>
                              <Edit sx={{ fontSize: 15 }} />
                            </IconButton>
                            <IconButton size="small" sx={{ color: "text.disabled", "&:hover": { color: "error.main" } }}
                              onClick={() => setPendingDelete(client)}>
                              <Delete sx={{ fontSize: 15 }} />
                            </IconButton>
                          </Box>
                        )}
                      </TableCell>
                    </TableRow>

                    {/* Project rows */}
                    <ProjectRows
                      clientId={client.id}
                      expanded={isExpanded}
                      searchQuery={searchQuery}
                      navigate={navigate}
                      clientBase={clientBase}
                      isGuest={isGuest}
                    />
                  </React.Fragment>
                );
              })}
            </TableBody>
          </Table>
        </Box>
      )}

      {/* ── Create account dialog ──────────────────────────────────────── */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Add New Account</DialogTitle>
        <DialogContent>
          <ClientForm form={createForm} onChange={setCreateForm} />
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setCreateOpen(false)} color="inherit">Cancel</Button>
          <Button variant="contained"
            onClick={() => createMutation.mutate(createForm)}
            disabled={!createForm.name || !createForm.slug || createMutation.isPending}>
            {createMutation.isPending ? <CircularProgress size={18} /> : "Create"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Edit account dialog ────────────────────────────────────────── */}
      <Dialog open={Boolean(editClient)} onClose={() => setEditClient(null)} fullWidth maxWidth="sm">
        <DialogTitle>Edit Account — {editClient?.name}</DialogTitle>
        <DialogContent>
          <ClientForm form={editForm} onChange={setEditForm} />
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setEditClient(null)} color="inherit">Cancel</Button>
          <Button variant="contained"
            onClick={() => editClient && updateMutation.mutate({ id: editClient.id, data: editForm })}
            disabled={!editForm.name || !editForm.slug || updateMutation.isPending}>
            {updateMutation.isPending ? <CircularProgress size={18} /> : "Save Changes"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Delete confirmation ────────────────────────────────────────── */}
      <Dialog open={Boolean(pendingDelete)} onClose={() => setPendingDelete(null)} maxWidth="xs" fullWidth>
        <DialogTitle sx={{ color: "error.main" }}>Delete Account?</DialogTitle>
        <DialogContent>
          <Typography sx={{ color: "text.secondary" }}>
            <strong>{pendingDelete?.name}</strong> will be moved to trash.
            Restorable for 30 days from <strong>Settings → Deleted Accounts</strong>.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDelete(null)} color="inherit">Cancel</Button>
          <Button variant="contained" color="error"
            onClick={() => pendingDelete && deleteMutation.mutate(pendingDelete.id)}
            disabled={deleteMutation.isPending}>
            {deleteMutation.isPending ? <CircularProgress size={18} sx={{ color: "#fff" }} /> : "Move to Trash"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Add project dialog ─────────────────────────────────────────── */}
      <Dialog open={addProjectOpen} onClose={() => setAddProjectOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Add Project</DialogTitle>
        <DialogContent>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
            <FormControl fullWidth size="small">
              <InputLabel>Account *</InputLabel>
              <Select
                label="Account *"
                value={addProjectClientId}
                onChange={(e) => setAddProjectClientId(e.target.value)}
              >
                {clients.map((c) => (
                  <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>
                ))}
              </Select>
            </FormControl>
            <TextField fullWidth size="small" label="Project Name *"
              value={addProjectForm.name}
              onChange={(e) => setAddProjectForm({ ...addProjectForm, name: e.target.value })} />
            <TextField fullWidth size="small" label="Description" multiline rows={2}
              value={addProjectForm.description}
              onChange={(e) => setAddProjectForm({ ...addProjectForm, description: e.target.value })} />
            <FormControl fullWidth size="small">
              <InputLabel>Environment</InputLabel>
              <Select label="Environment" value={addProjectForm.environment}
                onChange={(e) => setAddProjectForm({ ...addProjectForm, environment: e.target.value })}>
                <MenuItem value="">— Not specified —</MenuItem>
                <MenuItem value="production">Production</MenuItem>
                <MenuItem value="staging">Staging</MenuItem>
                <MenuItem value="development">Development</MenuItem>
                <MenuItem value="dr">DR / Disaster Recovery</MenuItem>
                <MenuItem value="other">Other</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth size="small">
              <InputLabel>Cloud Provider</InputLabel>
              <Select label="Cloud Provider" value={addProjectForm.cloud_provider}
                onChange={(e) => setAddProjectForm({ ...addProjectForm, cloud_provider: e.target.value })}>
                <MenuItem value="">— Not specified —</MenuItem>
                <MenuItem value="azure">Azure</MenuItem>
                <MenuItem value="aws">AWS</MenuItem>
                <MenuItem value="gcp">GCP</MenuItem>
                <MenuItem value="multi">Multi-cloud</MenuItem>
                <MenuItem value="on-premises">On-Premises</MenuItem>
                <MenuItem value="other">Other</MenuItem>
              </Select>
            </FormControl>
          </Box>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setAddProjectOpen(false)} color="inherit">Cancel</Button>
          <Button variant="contained"
            disabled={!addProjectClientId || !addProjectForm.name || addProjectMutation.isPending}
            onClick={() => addProjectMutation.mutate()}>
            {addProjectMutation.isPending ? <CircularProgress size={18} /> : "Create Project"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
