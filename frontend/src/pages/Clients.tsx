import React, { useState } from "react";
import {
  Box, Typography, Button, Card, CardContent, Grid, Chip,
  Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, CircularProgress, Avatar, IconButton, Menu, MenuItem,
} from "@mui/material";
import { Add, MoreVert, Business, Edit, Delete } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useLocation } from "react-router-dom";
import { clientsApi } from "../services/api";
import { Client } from "../types";
import { toast } from "react-toastify";

const FORM_FIELDS = [
  { key: "name",          label: "Client Name *" },
  { key: "slug",          label: "Slug (URL-safe) *" },
  { key: "industry",      label: "Industry" },
  { key: "country",       label: "Country" },
  { key: "contact_name",  label: "Contact Name" },
  { key: "contact_email", label: "Contact Email" },
];

const EMPTY_FORM = { name: "", slug: "", industry: "", country: "", contact_name: "", contact_email: "" };

function ClientForm({
  form, onChange,
}: {
  form: typeof EMPTY_FORM;
  onChange: (f: typeof EMPTY_FORM) => void;
}) {
  return (
    <Grid container spacing={2} sx={{ mt: 0.5 }}>
      {FORM_FIELDS.map(({ key, label }) => (
        <Grid size={{ xs: 12 }} key={key}>
          <TextField
            fullWidth size="small" label={label}
            value={(form as any)[key]}
            onChange={(e) => onChange({ ...form, [key]: e.target.value })}
          />
        </Grid>
      ))}
    </Grid>
  );
}

function ClientCard({
  client, onEdit, onDelete,
}: {
  client: Client;
  onEdit: (c: Client) => void;
  onDelete: (c: Client) => void;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  const clientBase = location.pathname.startsWith("/platform") ? "/platform/clients" : "/clients";

  return (
    <Card
      sx={{
        bgcolor: "background.paper", border: "1px solid", borderColor: "divider",
        borderRadius: 2, cursor: "pointer", transition: "border-color 0.2s, box-shadow 0.2s",
        "&:hover": { borderColor: "primary.main", boxShadow: "0 2px 12px rgba(0,0,0,0.08)" },
      }}
      onClick={() => navigate(`${clientBase}/${client.id}`)}
    >
      <CardContent>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, minWidth: 0 }}>
            <Avatar sx={{ bgcolor: "primary.main", fontWeight: 700, flexShrink: 0 }}>
              {client.name.charAt(0).toUpperCase()}
            </Avatar>
            <Box sx={{ minWidth: 0 }}>
              <Typography noWrap sx={{ fontWeight: 600, color: "text.primary" }}>{client.name}</Typography>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {[client.industry, client.country].filter(Boolean).join(" · ") || "No details"}
              </Typography>
            </Box>
          </Box>
          <IconButton
            size="small"
            sx={{ color: "text.secondary", flexShrink: 0, ml: 1 }}
            onClick={(e) => { e.stopPropagation(); setAnchorEl(e.currentTarget); }}
          >
            <MoreVert fontSize="small" />
          </IconButton>
        </Box>

        <Box sx={{ mt: 1.5, display: "flex", gap: 1, flexWrap: "wrap" }}>
          <Chip
            label={client.is_active ? "Active" : "Inactive"} size="small"
            sx={{
              bgcolor: client.is_active ? "rgba(52,168,83,0.12)" : "rgba(234,67,53,0.12)",
              color: client.is_active ? "#2E7D32" : "#C62828",
              fontWeight: 600,
            }}
          />
          {client.contact_email && (
            <Chip
              label={client.contact_email} size="small"
              sx={{ bgcolor: "action.hover", color: "text.secondary", fontSize: 10 }}
            />
          )}
        </Box>
      </CardContent>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
        onClick={(e) => e.stopPropagation()}
      >
        <MenuItem onClick={() => { setAnchorEl(null); onEdit(client); }}>
          <Edit sx={{ mr: 1 }} fontSize="small" />Edit
        </MenuItem>
        <MenuItem
          onClick={() => { setAnchorEl(null); onDelete(client); }}
          sx={{ color: "error.main" }}
        >
          <Delete sx={{ mr: 1 }} fontSize="small" />Delete
        </MenuItem>
      </Menu>
    </Card>
  );
}

export default function Clients() {
  const qc = useQueryClient();

  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState<typeof EMPTY_FORM>({ ...EMPTY_FORM });

  const [editClient, setEditClient] = useState<Client | null>(null);
  const [editForm, setEditForm] = useState<typeof EMPTY_FORM>({ ...EMPTY_FORM });

  const [pendingDelete, setPendingDelete] = useState<Client | null>(null);

  const { data: clients = [], isLoading } = useQuery<Client[]>({
    queryKey: ["clients"],
    queryFn: clientsApi.list,
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => clientsApi.create(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["clients"] });
      setCreateOpen(false);
      setCreateForm({ ...EMPTY_FORM });
      toast.success("Client created");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error creating client"),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => clientsApi.update(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["clients"] });
      setEditClient(null);
      toast.success("Client updated");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error updating client"),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => clientsApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["clients"] });
      setPendingDelete(null);
      toast.success("Client moved to trash — restorable for 30 days from Settings → Deleted Clients");
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Delete failed"),
  });

  const openEdit = (client: Client) => {
    setEditForm({
      name: client.name || "",
      slug: client.slug || "",
      industry: client.industry || "",
      country: client.country || "",
      contact_name: client.contact_name || "",
      contact_email: client.contact_email || "",
    });
    setEditClient(client);
  };

  if (isLoading) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Clients</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Manage client profiles and their security posture
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<Add />} onClick={() => setCreateOpen(true)}>
          Add Client
        </Button>
      </Box>

      {clients.length === 0 ? (
        <Card sx={{ border: "1px dashed", borderColor: "divider", borderRadius: 2, p: 4, textAlign: "center" }}>
          <Business sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No clients yet. Add your first client to get started.
          </Typography>
        </Card>
      ) : (
        <Grid container spacing={2}>
          {clients.map((c) => (
            <Grid size={{ xs: 12, sm: 6, md: 4 }} key={c.id}>
              <ClientCard client={c} onEdit={openEdit} onDelete={(cl) => setPendingDelete(cl)} />
            </Grid>
          ))}
        </Grid>
      )}

      {/* ── Create dialog ──────────────────────────────────────────────── */}
      <Dialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        fullWidth maxWidth="sm"
      >
        <DialogTitle>Add New Client</DialogTitle>
        <DialogContent>
          <ClientForm form={createForm} onChange={setCreateForm} />
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setCreateOpen(false)} color="inherit">Cancel</Button>
          <Button
            variant="contained"
            onClick={() => createMutation.mutate(createForm)}
            disabled={!createForm.name || !createForm.slug || createMutation.isPending}
          >
            {createMutation.isPending ? <CircularProgress size={18} /> : "Create"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Edit dialog ────────────────────────────────────────────────── */}
      <Dialog
        open={Boolean(editClient)}
        onClose={() => setEditClient(null)}
        fullWidth maxWidth="sm"
      >
        <DialogTitle>Edit Client — {editClient?.name}</DialogTitle>
        <DialogContent>
          <ClientForm form={editForm} onChange={setEditForm} />
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setEditClient(null)} color="inherit">Cancel</Button>
          <Button
            variant="contained"
            onClick={() => editClient && updateMutation.mutate({ id: editClient.id, data: editForm })}
            disabled={!editForm.name || !editForm.slug || updateMutation.isPending}
          >
            {updateMutation.isPending ? <CircularProgress size={18} /> : "Save Changes"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Delete confirmation ────────────────────────────────────────── */}
      <Dialog
        open={Boolean(pendingDelete)}
        onClose={() => setPendingDelete(null)}
        maxWidth="xs" fullWidth
      >
        <DialogTitle sx={{ color: "error.main" }}>Delete Client?</DialogTitle>
        <DialogContent>
          <Typography sx={{ color: "text.secondary" }}>
            <strong>{pendingDelete?.name}</strong> will be moved to the trash.
            It can be restored within 30 days from <strong>Settings → Deleted Clients</strong>.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDelete(null)} color="inherit">Cancel</Button>
          <Button
            variant="contained" color="error"
            onClick={() => pendingDelete && deleteMutation.mutate(pendingDelete.id)}
            disabled={deleteMutation.isPending}
          >
            {deleteMutation.isPending ? <CircularProgress size={18} sx={{ color: "#fff" }} /> : "Move to Trash"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
