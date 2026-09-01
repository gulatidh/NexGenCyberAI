import React, { useState } from "react";
import { useIsGuest } from "../hooks/useIsGuest";
import {
  Box, Typography, Card, Button, Alert, CircularProgress,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Chip, IconButton, Tooltip, Table, TableHead, TableRow, TableCell,
  TableBody, TableContainer, FormControlLabel, Checkbox, FormGroup,
  MenuItem, Select, FormControl, InputLabel, InputAdornment,
} from "@mui/material";
import {
  Add, Delete, ContentCopy, VpnKey, Warning,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiKeysApi, clientsApi } from "../services/api";
import { toast } from "react-toastify";
import { fmt } from "../utils/datetime";
import { Client } from "../types";

const ALL_SCOPES = ["read:findings", "read:risks", "read:dashboard", "read:scans"];
const EXPIRY_OPTIONS = [
  { label: "Never", value: 0 },
  { label: "30 days", value: 30 },
  { label: "90 days", value: 90 },
  { label: "365 days", value: 365 },
];

interface APIKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  client_id?: string;
  created_at?: string;
  last_used_at?: string;
  expires_at?: string;
}

interface CreatedKey {
  key: string;
  name: string;
}

export default function APIKeysPage() {
  const qc = useQueryClient();
  const isGuest = useIsGuest();
  const [createOpen, setCreateOpen] = useState(false);
  const [createdKey, setCreatedKey] = useState<CreatedKey | null>(null);
  const [form, setForm] = useState({
    name: "",
    client_id: "",
    scopes: [] as string[],
    expires_days: 0,
  });

  const { data: keys = [], isLoading } = useQuery<APIKey[]>({
    queryKey: ["api-keys"],
    queryFn: () => apiKeysApi.list(),
  });

  const { data: clients = [] } = useQuery<Client[]>({
    queryKey: ["clients"],
    queryFn: () => clientsApi.list(),
  });

  const createMut = useMutation({
    mutationFn: () => apiKeysApi.create({
      name: form.name.trim(),
      client_id: form.client_id || undefined,
      scopes: form.scopes,
      expires_days: form.expires_days || undefined,
    }),
    onSuccess: (data: any) => {
      qc.invalidateQueries({ queryKey: ["api-keys"] });
      setCreateOpen(false);
      setForm({ name: "", client_id: "", scopes: [], expires_days: 0 });
      setCreatedKey({ key: data.key || data.token || "", name: data.name || form.name });
    },
    onError: () => toast.error("Create failed"),
  });

  const revokeMut = useMutation({
    mutationFn: (id: string) => apiKeysApi.revoke(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["api-keys"] });
      toast.success("API key revoked");
    },
    onError: () => toast.error("Revoke failed"),
  });

  const toggleScope = (scope: string) => {
    setForm((f) => ({
      ...f,
      scopes: f.scopes.includes(scope)
        ? f.scopes.filter((s) => s !== scope)
        : [...f.scopes, scope],
    }));
  };

  const copyKey = () => {
    if (createdKey?.key) {
      navigator.clipboard.writeText(createdKey.key);
      toast.success("Copied to clipboard");
    }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>API Keys</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Manage programmatic access tokens for integrations and scripts
          </Typography>
        </Box>
        {!isGuest && (
          <Button variant="contained" startIcon={<Add />} onClick={() => setCreateOpen(true)}>
            Create API Key
          </Button>
        )}
      </Box>

      {isLoading && <CircularProgress size={24} />}

      {!isLoading && keys.length === 0 && (
        <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
          <VpnKey sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No API keys yet. Create one to enable programmatic access.
          </Typography>
        </Card>
      )}

      {!isLoading && keys.length > 0 && (
        <TableContainer component={Card} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                {["Name", "Prefix", "Scopes", "Created", "Last Used", "Expires", ""].map((h) => (
                  <TableCell key={h} sx={{ fontWeight: 700, fontSize: 11 }}>{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {keys.map((k) => (
                <TableRow key={k.id} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>{k.name}</Typography>
                    {k.client_id && (
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        {clients.find((c) => c.id === k.client_id)?.name ?? k.client_id}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#4285F4" }}>
                      {k.prefix}…
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                      {(k.scopes || []).map((s) => (
                        <Chip key={s} label={s} size="small" variant="outlined" sx={{ fontSize: 10, height: 18 }} />
                      ))}
                    </Box>
                  </TableCell>
                  <TableCell sx={{ fontSize: 11, color: "text.secondary" }}>
                    {k.created_at ? fmt(k.created_at) : "—"}
                  </TableCell>
                  <TableCell sx={{ fontSize: 11, color: "text.secondary" }}>
                    {k.last_used_at ? fmt(k.last_used_at) : "Never"}
                  </TableCell>
                  <TableCell sx={{ fontSize: 11, color: "text.secondary" }}>
                    {k.expires_at ? fmt(k.expires_at) : "Never"}
                  </TableCell>
                  <TableCell>
                    {!isGuest && (
                      <Tooltip title="Revoke key">
                        <IconButton size="small" color="error" onClick={() => revokeMut.mutate(k.id)}>
                          <Delete fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Create Dialog */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create API Key</DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <TextField
              label="Name" fullWidth size="small" required
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              placeholder="e.g. SIEM Integration"
            />
            <FormControl size="small" fullWidth>
              <InputLabel>Client scope (optional)</InputLabel>
              <Select
                label="Client scope (optional)"
                value={form.client_id}
                onChange={(e) => setForm((f) => ({ ...f, client_id: e.target.value }))}
              >
                <MenuItem value="">All accounts</MenuItem>
                {(clients as Client[]).map((c) => (
                  <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>
                ))}
              </Select>
            </FormControl>
            <Box>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, display: "block", mb: 0.5 }}>
                Permissions
              </Typography>
              <FormGroup row>
                {ALL_SCOPES.map((sc) => (
                  <FormControlLabel
                    key={sc}
                    control={
                      <Checkbox
                        size="small"
                        checked={form.scopes.includes(sc)}
                        onChange={() => toggleScope(sc)}
                      />
                    }
                    label={<Typography variant="caption">{sc}</Typography>}
                  />
                ))}
              </FormGroup>
            </Box>
            <FormControl size="small" fullWidth>
              <InputLabel>Expiry</InputLabel>
              <Select
                label="Expiry"
                value={form.expires_days}
                onChange={(e) => setForm((f) => ({ ...f, expires_days: Number(e.target.value) }))}
              >
                {EXPIRY_OPTIONS.map((o) => (
                  <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            disabled={!form.name.trim() || form.scopes.length === 0 || createMut.isPending}
            onClick={() => createMut.mutate()}
          >
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* Show created key — one-time reveal */}
      <Dialog open={!!createdKey} onClose={() => setCreatedKey(null)} maxWidth="sm" fullWidth>
        <DialogTitle>API Key Created</DialogTitle>
        <DialogContent>
          <Alert severity="warning" icon={<Warning />} sx={{ mb: 2 }}>
            This is the only time the full key will be shown. Copy it now and store it securely.
          </Alert>
          <TextField
            fullWidth size="small" label={createdKey?.name} value={createdKey?.key || ""}
            slotProps={{
              input: {
                readOnly: true,
                sx: { fontFamily: "monospace", fontSize: 13 },
                endAdornment: (
                  <InputAdornment position="end">
                    <Tooltip title="Copy to clipboard">
                      <IconButton edge="end" onClick={copyKey}><ContentCopy fontSize="small" /></IconButton>
                    </Tooltip>
                  </InputAdornment>
                ),
              },
            }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={copyKey} startIcon={<ContentCopy />}>Copy</Button>
          <Button variant="contained" onClick={() => setCreatedKey(null)}>Done</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
