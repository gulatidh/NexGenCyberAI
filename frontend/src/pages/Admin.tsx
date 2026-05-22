import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Button, Chip, IconButton,
  Table, TableHead, TableRow, TableCell, TableBody,
  Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, FormControl, InputLabel, Select, MenuItem, Alert, Tooltip, CircularProgress,
} from "@mui/material";
import {
  Add, Delete, AdminPanelSettings, EditNote, Visibility, Public, Apartment, FolderOpen,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  AccessRole, AccessScope, Client, MyAccess, Project, UserAccessSummary,
} from "../types";
import { adminApi, clientsApi, projectsApi } from "../services/api";


const ROLE_COLOR: Record<AccessRole, string> = {
  admin: "#f06292",
  editor: "#A100FF",
  reader: "rgba(255,255,255,0.6)",
};
const ROLE_ICON: Record<AccessRole, React.ReactNode> = {
  admin: <AdminPanelSettings sx={{ fontSize: 14 }} />,
  editor: <EditNote sx={{ fontSize: 14 }} />,
  reader: <Visibility sx={{ fontSize: 14 }} />,
};
const SCOPE_ICON: Record<AccessScope, React.ReactNode> = {
  global: <Public sx={{ fontSize: 14 }} />,
  client: <Apartment sx={{ fontSize: 14 }} />,
  project: <FolderOpen sx={{ fontSize: 14 }} />,
};


export default function Admin() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<{
    email: string;
    role: AccessRole;
    scope_type: AccessScope;
    scope_client_id: string;
    scope_project_id: string;
  }>({
    email: "", role: "reader", scope_type: "client",
    scope_client_id: "", scope_project_id: "",
  });

  const { data: me, isLoading: meLoading } = useQuery<MyAccess>({
    queryKey: ["my-access"],
    queryFn: adminApi.me,
  });

  const canAdmin = !!(me?.is_admin || me?.is_admin_anywhere);
  const isGlobalAdmin = !!me?.is_admin;
  const manageable = me?.manageable_scopes;

  const { data: users = [], isLoading } = useQuery<UserAccessSummary[]>({
    queryKey: ["admin-users"],
    queryFn: adminApi.listUsers,
    enabled: canAdmin,
  });

  const { data: allClients = [] } = useQuery<Client[]>({
    queryKey: ["clients"],
    queryFn: clientsApi.list,
    enabled: canAdmin,
  });

  // Scoped admins only pick from clients they can manage (or whose projects they manage).
  const clients = isGlobalAdmin ? allClients : allClients.filter((c) =>
    manageable?.client_ids.includes(c.id)
    // Also include clients that have a manageable project under them
    // (resolved below by also showing the client when its projects appear)
  );

  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", form.scope_client_id],
    queryFn: () => projectsApi.list(form.scope_client_id),
    enabled: !!form.scope_client_id && form.scope_type === "project",
  });
  // Filter projects for non-global admins to only the ones they manage.
  const visibleProjects = isGlobalAdmin
    ? projects
    : projects.filter((p) => manageable?.project_ids.includes(p.id));

  const grantMutation = useMutation({
    mutationFn: (data: any) => adminApi.createGrant(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-users"] });
      qc.invalidateQueries({ queryKey: ["my-access"] });
      setOpen(false);
      setForm({ email: "", role: "reader", scope_type: "client", scope_client_id: "", scope_project_id: "" });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (grantId: string) => adminApi.deleteGrant(grantId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-users"] });
      qc.invalidateQueries({ queryKey: ["my-access"] });
    },
  });

  const submitGrant = () => {
    const payload: any = { email: form.email.trim(), role: form.role, scope_type: form.scope_type };
    if (form.scope_type === "client") payload.scope_id = form.scope_client_id;
    if (form.scope_type === "project") payload.scope_id = form.scope_project_id;
    grantMutation.mutate(payload);
  };

  if (meLoading) {
    return <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#A100FF" }} /></Box>;
  }

  if (!canAdmin) {
    return (
      <Box sx={{ maxWidth: 640, mx: "auto", mt: 6 }}>
        <Alert severity="warning" icon={<AdminPanelSettings />}
          sx={{ bgcolor: "rgba(255,152,0,0.08)", color: "white", border: "1px solid rgba(255,152,0,0.3)" }}>
          <Typography sx={{ fontWeight: 600, mb: 0.5 }}>Admin access required</Typography>
          You're signed in as <b>{me?.email || "unknown"}</b>. Ask a global or scoped admin
          to grant you the <b>admin</b> role.
        </Alert>
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3, flexWrap: "wrap", gap: 1 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Administration</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            User access and RBAC grants
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<Add />} onClick={() => setOpen(true)}
          sx={{ bgcolor: "#A100FF", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}>
          Grant access
        </Button>
      </Box>

      <Card sx={{ bgcolor: "#1A1A1A", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
        <CardContent sx={{ "&:last-child": { pb: 2 } }}>
          <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600, mb: 1.5 }}>
            Users with access ({users.length})
          </Typography>
          {isLoading ? (
            <CircularProgress sx={{ color: "#A100FF" }} />
          ) : users.length === 0 ? (
            <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.4)", textAlign: "center", py: 4 }}>
              No grants yet. Click "Grant access" to add the first user.
            </Typography>
          ) : (
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
                  <TableCell>USER</TableCell>
                  <TableCell>ROLE</TableCell>
                  <TableCell>SCOPE</TableCell>
                  <TableCell>GRANTED BY</TableCell>
                  <TableCell align="right">ACTION</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {users.flatMap((u) => u.grants.map((g, idx) => (
                  <TableRow key={g.id} sx={{ "& td": { color: "white", fontSize: 12, borderColor: "rgba(255,255,255,0.05)", py: 1 } }}>
                    <TableCell>
                      {idx === 0 ? (
                        <Typography variant="body2" sx={{ color: "white", fontFamily: "monospace", fontSize: 12 }}>
                          {u.email}
                        </Typography>
                      ) : (
                        <Box sx={{ pl: 1, color: "rgba(255,255,255,0.3)" }}>↳</Box>
                      )}
                    </TableCell>
                    <TableCell>
                      <Chip icon={ROLE_ICON[g.role] as any} label={g.role} size="small"
                        sx={{ bgcolor: `${ROLE_COLOR[g.role]}20`, color: ROLE_COLOR[g.role],
                          fontSize: 10, height: 20, textTransform: "capitalize",
                          "& .MuiChip-icon": { color: ROLE_COLOR[g.role] } }} />
                    </TableCell>
                    <TableCell>
                      <Chip icon={SCOPE_ICON[g.scope_type] as any}
                        label={g.scope_label || g.scope_type} size="small"
                        sx={{ bgcolor: "rgba(255,255,255,0.05)", color: "rgba(255,255,255,0.85)",
                          fontSize: 10, height: 20,
                          "& .MuiChip-icon": { color: "rgba(255,255,255,0.5)" } }} />
                    </TableCell>
                    <TableCell sx={{ color: "rgba(255,255,255,0.5) !important", fontFamily: "monospace", fontSize: 11 }}>
                      {g.granted_by || "—"}
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Revoke this grant">
                        <IconButton size="small"
                          onClick={() => {
                            if (window.confirm(`Revoke ${g.role} (${g.scope_label || g.scope_type}) from ${u.email}?`)) {
                              revokeMutation.mutate(g.id);
                            }
                          }}
                          sx={{ color: "rgba(255,255,255,0.4)", "&:hover": { color: "#f44336" } }}>
                          <Delete sx={{ fontSize: 16 }} />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Grant dialog */}
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "#1A1A1A", color: "white" } } }}>
        <DialogTitle>Grant access</DialogTitle>
        <DialogContent>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
            <TextField label="User email / UPN" size="small" value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              placeholder="user@yourcompany.com"
              sx={{ "& .MuiOutlinedInput-root": { color: "white", "& fieldset": { borderColor: "rgba(255,255,255,0.2)" } },
                "& .MuiInputLabel-root": { color: "rgba(255,255,255,0.5)" } }} />
            <FormControl size="small">
              <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Role</InputLabel>
              <Select label="Role" value={form.role}
                onChange={(e) => setForm({ ...form, role: e.target.value as AccessRole })}
                sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                <MenuItem value="reader">Reader — read-only access</MenuItem>
                <MenuItem value="editor">Editor — read, create, update, delete</MenuItem>
                <MenuItem value="admin">Admin — Editor + manage user access</MenuItem>
              </Select>
            </FormControl>
            <FormControl size="small">
              <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Scope</InputLabel>
              <Select label="Scope" value={form.scope_type}
                onChange={(e) => setForm({ ...form, scope_type: e.target.value as AccessScope, scope_client_id: "", scope_project_id: "" })}
                sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                <MenuItem value="global" disabled={!isGlobalAdmin}>
                  Global — applies everywhere {!isGlobalAdmin && "(global admin only)"}
                </MenuItem>
                <MenuItem value="client" disabled={!isGlobalAdmin && (manageable?.client_ids.length ?? 0) === 0}>
                  Specific client
                </MenuItem>
                <MenuItem value="project" disabled={!isGlobalAdmin && (manageable?.project_ids.length ?? 0) === 0}>
                  Specific project
                </MenuItem>
              </Select>
            </FormControl>
            {(form.scope_type === "client" || form.scope_type === "project") && (
              <FormControl size="small">
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
                <Select label="Client" value={form.scope_client_id}
                  onChange={(e) => setForm({ ...form, scope_client_id: e.target.value, scope_project_id: "" })}
                  sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                  {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
                </Select>
              </FormControl>
            )}
            {form.scope_type === "project" && form.scope_client_id && (
              <FormControl size="small">
                <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Project</InputLabel>
                <Select label="Project" value={form.scope_project_id}
                  onChange={(e) => setForm({ ...form, scope_project_id: e.target.value })}
                  sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                  {visibleProjects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
                </Select>
              </FormControl>
            )}

            {grantMutation.isError && (
              <Alert severity="error">
                {(grantMutation.error as any)?.response?.data?.detail || "Grant failed"}
              </Alert>
            )}
          </Box>
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setOpen(false)} sx={{ color: "rgba(255,255,255,0.6)" }}>Cancel</Button>
          <Button variant="contained" disabled={grantMutation.isPending || !form.email
            || (form.scope_type === "client" && !form.scope_client_id)
            || (form.scope_type === "project" && !form.scope_project_id)}
            onClick={submitGrant}
            sx={{ bgcolor: "#A100FF", color: "#0d1117", "&:hover": { bgcolor: "#00b3cc" } }}>
            {grantMutation.isPending ? <CircularProgress size={18} /> : "Grant"}
          </Button>
        </DialogActions>
      </Dialog>

      <Box sx={{ mt: 3 }}>
        <Card sx={{ bgcolor: "#1A1A1A", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Typography variant="subtitle2" sx={{ color: "rgba(255,255,255,0.7)", mb: 1 }}>
              Your effective access
            </Typography>
            <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
              {(me.grants || []).length === 0 ? (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>None.</Typography>
              ) : (
                me.grants.map((g) => (
                  <Chip key={g.id}
                    icon={ROLE_ICON[g.role] as any}
                    label={`${g.role} · ${g.scope_label || g.scope_type}`}
                    size="small"
                    sx={{ bgcolor: `${ROLE_COLOR[g.role]}20`, color: ROLE_COLOR[g.role],
                      fontSize: 10, height: 20,
                      "& .MuiChip-icon": { color: ROLE_COLOR[g.role] } }} />
                ))
              )}
            </Box>
          </CardContent>
        </Card>
      </Box>
    </Box>
  );
}
