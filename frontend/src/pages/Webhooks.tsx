import React, { useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import { useIsGuest } from "../hooks/useIsGuest";
import {
  Box, Typography, Card, CardContent, Button, CircularProgress,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Chip, IconButton, Switch, Tooltip, Collapse, Grid,
  FormGroup, FormControlLabel, Checkbox, Divider,
} from "@mui/material";
import {
  Add, Delete, ExpandMore, ExpandLess, Notifications, CheckCircle, Error as ErrorIcon,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { webhooksApi } from "../services/api";
import { toast } from "react-toastify";
import { fmt } from "../utils/datetime";

const ALL_EVENTS = ["finding.critical", "scan.completed", "agent.completed", "webhook.test"];

interface Webhook {
  id: string;
  name: string;
  url: string;
  secret?: string;
  events: string[];
  is_active: boolean;
  client_id?: string;
  created_at?: string;
}

interface Delivery {
  id: string;
  event: string;
  status: string;
  attempted_at?: string;
  response_status?: number;
}

function DeliveryList({ webhookId }: { webhookId: string }) {
  const { data: deliveries = [], isLoading } = useQuery<Delivery[]>({
    queryKey: ["webhook-deliveries", webhookId],
    queryFn: () => webhooksApi.deliveries(webhookId),
  });

  if (isLoading) return <CircularProgress size={16} sx={{ m: 1 }} />;

  return (
    <Box sx={{ p: 1.5, pt: 0 }}>
      <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, display: "block", mb: 1 }}>
        Recent Deliveries
      </Typography>
      {deliveries.length === 0 && (
        <Typography variant="caption" sx={{ color: "text.secondary" }}>No deliveries yet.</Typography>
      )}
      {deliveries.slice(0, 5).map((d) => {
        const ok = d.status === "success" || (d.response_status && d.response_status < 300);
        return (
          <Box key={d.id} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.75 }}>
            {ok
              ? <CheckCircle sx={{ fontSize: 14, color: "#34A853" }} />
              : <ErrorIcon sx={{ fontSize: 14, color: "#EA4335" }} />}
            <Chip label={d.event} size="small" sx={{ fontSize: 10, height: 16 }} />
            {d.response_status && (
              <Typography variant="caption" sx={{ color: "text.secondary" }}>HTTP {d.response_status}</Typography>
            )}
            {d.attempted_at && (
              <Typography variant="caption" sx={{ color: "text.secondary", ml: "auto" }}>{fmt(d.attempted_at)}</Typography>
            )}
          </Box>
        );
      })}
    </Box>
  );
}

function WebhookCard({ hook, onDelete }: { hook: Webhook; onDelete: () => void }) {
  const qc = useQueryClient();
  const isGuest = useIsGuest();
  const [showDeliveries, setShowDeliveries] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const toggleMut = useMutation({
    mutationFn: (active: boolean) => webhooksApi.toggle(hook.id, active),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
    onError: () => toast.error("Toggle failed"),
  });

  const testMut = useMutation({
    mutationFn: () => webhooksApi.test(hook.id),
    onSuccess: () => toast.success("Test event sent"),
    onError: () => toast.error("Test failed"),
  });

  return (
    <Card variant="outlined" sx={{ mb: 2 }}>
      <CardContent sx={{ pb: "12px !important" }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{hook.name}</Typography>
              <Chip
                label={hook.is_active ? "Active" : "Paused"}
                size="small"
                sx={{
                  fontSize: 10, height: 18,
                  bgcolor: hook.is_active ? "rgba(52,168,83,0.15)" : "rgba(158,158,158,0.15)",
                  color: hook.is_active ? "#34A853" : "#9e9e9e",
                }}
              />
            </Box>
            <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace",
              display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 400 }}>
              {hook.url}
            </Typography>
            <Box sx={{ display: "flex", gap: 0.75, mt: 1, flexWrap: "wrap" }}>
              {hook.events.map((ev) => (
                <Chip key={ev} label={ev} size="small" variant="outlined" sx={{ fontSize: 10, height: 18 }} />
              ))}
            </Box>
          </Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, ml: 1 }}>
            {!isGuest && (
              <>
                <Tooltip title={hook.is_active ? "Pause webhook" : "Activate webhook"}>
                  <Switch
                    size="small"
                    checked={hook.is_active}
                    onChange={(e) => toggleMut.mutate(e.target.checked)}
                  />
                </Tooltip>
                <Button size="small" onClick={() => testMut.mutate()} disabled={testMut.isPending}>Test</Button>
                <Tooltip title="Delete webhook">
                  <IconButton size="small" color="error" onClick={() => setConfirmDelete(true)}>
                    <Delete fontSize="small" />
                  </IconButton>
                </Tooltip>
              </>
            )}
          </Box>
        </Box>

        <Box sx={{ mt: 1, display: "flex", alignItems: "center", gap: 0.5 }}>
          <Button
            size="small"
            variant="text"
            sx={{ color: "text.secondary", fontSize: 11 }}
            endIcon={showDeliveries ? <ExpandLess fontSize="small" /> : <ExpandMore fontSize="small" />}
            onClick={() => setShowDeliveries((v) => !v)}
          >
            Recent Deliveries
          </Button>
        </Box>

        <Collapse in={showDeliveries}>
          <Divider sx={{ mt: 1, mb: 1 }} />
          <DeliveryList webhookId={hook.id} />
        </Collapse>
      </CardContent>

      <Dialog open={confirmDelete} onClose={() => setConfirmDelete(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Delete Webhook?</DialogTitle>
        <DialogContent>
          <Typography>Remove <strong>{hook.name}</strong>? This cannot be undone.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmDelete(false)}>Cancel</Button>
          <Button color="error" variant="contained" onClick={() => { setConfirmDelete(false); onDelete(); }}>Delete</Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
}

export default function Webhooks() {
  const qc = useQueryClient();
  const { clientId } = useActiveClient();
  const isGuest = useIsGuest();
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ name: "", url: "", secret: "", events: [] as string[] });

  const { data: hooks = [], isLoading } = useQuery<Webhook[]>({
    queryKey: ["webhooks", clientId],
    queryFn: () => webhooksApi.list(clientId || undefined),
  });

  const createMut = useMutation({
    mutationFn: () => webhooksApi.create({
      name: form.name.trim(),
      url: form.url.trim(),
      secret: form.secret.trim() || undefined,
      events: form.events,
      client_id: clientId || undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["webhooks"] });
      setCreateOpen(false);
      setForm({ name: "", url: "", secret: "", events: [] });
      toast.success("Webhook created");
    },
    onError: () => toast.error("Create failed"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => webhooksApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["webhooks"] });
      toast.success("Webhook deleted");
    },
    onError: () => toast.error("Delete failed"),
  });

  const toggleEvent = (ev: string) => {
    setForm((f) => ({
      ...f,
      events: f.events.includes(ev) ? f.events.filter((e) => e !== ev) : [...f.events, ev],
    }));
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Webhooks &amp; Notifications</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Push real-time security events to external systems
          </Typography>
        </Box>
        {!isGuest && (
          <Button variant="contained" startIcon={<Add />} onClick={() => setCreateOpen(true)}>
            Add Webhook
          </Button>
        )}
      </Box>

      {isLoading && <CircularProgress size={24} />}

      {!isLoading && hooks.length === 0 && (
        <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
          <Notifications sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No webhooks configured yet. Add one to start receiving real-time event notifications.
          </Typography>
        </Card>
      )}

      {hooks.map((hook) => (
        <WebhookCard key={hook.id} hook={hook} onDelete={() => deleteMut.mutate(hook.id)} />
      ))}

      {/* Create Dialog */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add Webhook</DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <TextField
                label="Name" fullWidth size="small" required
                value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="e.g. Slack Alerts"
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField
                label="URL" fullWidth size="small" required type="url"
                value={form.url} onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
                placeholder="https://hooks.example.com/..."
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField
                label="Secret (optional)" fullWidth size="small"
                value={form.secret} onChange={(e) => setForm((f) => ({ ...f, secret: e.target.value }))}
                placeholder="HMAC signing secret"
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700, display: "block", mb: 0.5 }}>
                EVENTS
              </Typography>
              <FormGroup row>
                {ALL_EVENTS.map((ev) => (
                  <FormControlLabel
                    key={ev}
                    control={
                      <Checkbox
                        size="small"
                        checked={form.events.includes(ev)}
                        onChange={() => toggleEvent(ev)}
                      />
                    }
                    label={<Typography variant="caption">{ev}</Typography>}
                  />
                ))}
              </FormGroup>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            disabled={!form.name.trim() || !form.url.trim() || form.events.length === 0 || createMut.isPending}
            onClick={() => createMut.mutate()}
          >
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
