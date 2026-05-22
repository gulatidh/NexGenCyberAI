import React, { useState } from "react";
import {
  Box, Typography, Button, Card, CardContent, Grid, Chip,
  Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, CircularProgress, Avatar, IconButton, Menu, MenuItem,
} from "@mui/material";
import { Add, MoreVert, Business, Edit, Delete } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { clientsApi } from "../services/api";
import { Client } from "../types";
import { toast } from "react-toastify";

function ClientCard({ client, onEdit, onDelete }: { client: Client; onEdit: () => void; onDelete: () => void }) {
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  return (
    <Card
      sx={{
        bgcolor: "#1A1A1A", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2,
        cursor: "pointer", transition: "border-color 0.2s",
        "&:hover": { borderColor: "#A100FF" },
      }}
      onClick={() => navigate(`/clients/${client.id}`)}
    >
      <CardContent>
        <Box sx={{ display: "flex", justifyContent: "space-between" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            <Avatar sx={{ bgcolor: "#A100FF", color: "#000", fontWeight: 700 }}>
              {client.name.charAt(0)}
            </Avatar>
            <Box>
              <Typography sx={{ color: "white", fontWeight: 600 }}>{client.name}</Typography>
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                {client.industry} · {client.country}
              </Typography>
            </Box>
          </Box>
          <IconButton
            size="small"
            sx={{ color: "rgba(255,255,255,0.4)" }}
            onClick={(e) => { e.stopPropagation(); setAnchorEl(e.currentTarget); }}
          >
            <MoreVert />
          </IconButton>
        </Box>
        <Box sx={{ mt: 1.5, display: "flex", gap: 1 }}>
          <Chip label={client.is_active ? "Active" : "Inactive"} size="small"
            sx={{ bgcolor: client.is_active ? "rgba(0,230,118,0.15)" : "rgba(244,67,54,0.15)",
              color: client.is_active ? "#00e676" : "#f44336" }} />
          {client.contact_email && (
            <Chip label={client.contact_email} size="small"
              sx={{ bgcolor: "rgba(255,255,255,0.05)", color: "rgba(255,255,255,0.5)", fontSize: 10 }} />
          )}
        </Box>
      </CardContent>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={() => setAnchorEl(null)}>
        <MenuItem onClick={(e) => { e.stopPropagation(); setAnchorEl(null); onEdit(); }}><Edit sx={{ mr: 1 }} fontSize="small" />Edit</MenuItem>
        <MenuItem onClick={(e) => { e.stopPropagation(); setAnchorEl(null); onDelete(); }} sx={{ color: "#f44336" }}><Delete sx={{ mr: 1 }} fontSize="small" />Deactivate</MenuItem>
      </Menu>
    </Card>
  );
}

export default function Clients() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", slug: "", industry: "", country: "", contact_name: "", contact_email: "" });

  const { data: clients = [], isLoading } = useQuery<Client[]>({
    queryKey: ["clients"],
    queryFn: clientsApi.list,
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => clientsApi.create(data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["clients"] }); setOpen(false); toast.success("Client created"); },
    onError: (e: any) => toast.error(e.response?.data?.detail || "Error"),
  });

  if (isLoading) return <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#A100FF" }} /></Box>;

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Clients</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>Manage client profiles and their security posture</Typography>
        </Box>
        <Button variant="contained" startIcon={<Add />} onClick={() => setOpen(true)}
          sx={{ bgcolor: "#A100FF", color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}>
          Add Client
        </Button>
      </Box>

      {clients.length === 0 ? (
        <Card sx={{ bgcolor: "#1A1A1A", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 4, textAlign: "center" }}>
          <Business sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
          <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>No clients yet. Add your first client to get started.</Typography>
        </Card>
      ) : (
        <Grid container spacing={2}>
          {clients.map((c) => (
            <Grid size={{ xs: 12, sm: 6, md: 4 }} key={c.id}>
              <ClientCard client={c} onEdit={() => {}} onDelete={() => clientsApi.delete(c.id).then(() => qc.invalidateQueries({ queryKey: ["clients"] }))} />
            </Grid>
          ))}
        </Grid>
      )}

      <Dialog open={open} onClose={() => setOpen(false)} slotProps={{ paper: { sx: { bgcolor: "#1A1A1A", color: "white", minWidth: 480 } } }}>
        <DialogTitle>Add New Client</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 0.5 }}>
            {[
              { key: "name", label: "Client Name *" },
              { key: "slug", label: "Slug (URL-safe) *" },
              { key: "industry", label: "Industry" },
              { key: "country", label: "Country" },
              { key: "contact_name", label: "Contact Name" },
              { key: "contact_email", label: "Contact Email" },
            ].map(({ key, label }) => (
              <Grid size={{ xs: 12 }} key={key}>
                <TextField fullWidth size="small" label={label} value={(form as any)[key]}
                  onChange={(e) => setForm({ ...form, [key]: e.target.value })}
                  slotProps={{ inputLabel: { sx: { color: 'rgba(255,255,255,0.5)' } }, htmlInput: { style: { color: 'white' } } }}
                  sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}
                />
              </Grid>
            ))}
          </Grid>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setOpen(false)} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
          <Button variant="contained" onClick={() => createMutation.mutate(form)}
            disabled={!form.name || !form.slug || createMutation.isPending}
            sx={{ bgcolor: "#A100FF", color: "#000" }}>
            {createMutation.isPending ? <CircularProgress size={18} /> : "Create"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
