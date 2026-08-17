import React, { useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress,
  FormControl, InputLabel, Select, MenuItem, IconButton, Alert,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  Tooltip, Menu, MenuItem as MuiMenuItem, LinearProgress,
  Dialog, DialogTitle, DialogContent, DialogActions, Button, TextField,
  Tabs, Tab, Link,
} from "@mui/material";
import { Refresh, Assignment, ConfirmationNumber, OpenInNew } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { remediationTrackerApi, ticketsApi } from "../services/api";
import { toast } from "react-toastify";
import { fmt } from "../utils/datetime";

const BAND_COLOR: Record<string, string> = {
  "Quick Win (0-30d)": "#34A853",
  "Near Term (30-90d)": "#4285F4",
  "Medium Term (90-180d)": "#FBBC04",
  "Strategic (180d+)": "#9C27B0",
};

const STATUS_COLOR: Record<string, string> = {
  open: "#FF7043", in_progress: "#FBBC04", completed: "#34A853", cancelled: "#9e9e9e",
};

const EFFORT_COLOR: Record<string, string> = { Low: "#34A853", Medium: "#FBBC04", High: "#EA4335" };
const IMPACT_COLOR: Record<string, string> = { Low: "#9e9e9e", Medium: "#4285F4", High: "#34A853" };

const BAND_ORDER = ["Quick Win (0-30d)", "Near Term (30-90d)", "Medium Term (90-180d)", "Strategic (180d+)"];

interface RemediationAction {
  id: string;
  client_id: string;
  agent_run_id?: string;
  scan_id?: string;
  title?: string;
  action: string;
  band?: string;
  priority?: number;
  effort?: string;
  impact?: string;
  status: string;
  assigned_to?: string;
  due_date?: string;
  notes?: string;
  completed_at?: string;
  created_at?: string;
}

interface TicketConnector {
  id: string;
  name: string;
  connector_type: string;
  status: string;
  config: Record<string, any>;
}

interface TicketSync {
  id: string;
  source_type: string;
  source_id: string;
  ticket_id: string;
  ticket_url: string;
  ticket_status: string;
  connector_type: string;
  created_at?: string;
}

function StatusMenu({ action, onUpdate }: { action: RemediationAction; onUpdate: (status: string) => void }) {
  const [anchor, setAnchor] = useState<null | HTMLElement>(null);
  return (
    <>
      <IconButton size="small" onClick={(e) => { e.stopPropagation(); setAnchor(e.currentTarget); }}>
        <Refresh fontSize="small" sx={{ fontSize: 16 }} />
      </IconButton>
      <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}>
        {["open", "in_progress", "completed", "cancelled"].map((s) => (
          <MuiMenuItem key={s} onClick={() => { onUpdate(s); setAnchor(null); }}
            selected={action.status === s} sx={{ textTransform: "capitalize", fontSize: 13 }}>
            {s.replace("_", " ")}
          </MuiMenuItem>
        ))}
      </Menu>
    </>
  );
}

/** Dialog: pick connector + optional group/project key, then create a ticket */
function CreateTicketDialog({
  open,
  action,
  connectors,
  clientId,
  onClose,
  onCreated,
}: {
  open: boolean;
  action: RemediationAction | null;
  connectors: TicketConnector[];
  clientId: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [connectorId, setConnectorId] = useState("");
  const [assignmentGroup, setAssignmentGroup] = useState("");
  const [projectKey, setProjectKey] = useState("");
  const [creating, setCreating] = useState(false);

  const selectedConnector = connectors.find((c) => c.id === connectorId);
  const isSN = selectedConnector?.connector_type === "servicenow";
  const isJira = selectedConnector?.connector_type === "jira";

  // Pre-fill project_key from connector config when Jira is selected
  React.useEffect(() => {
    if (selectedConnector?.connector_type === "jira") {
      setProjectKey(selectedConnector.config?.project_key || "");
    }
  }, [connectorId, selectedConnector]);

  const handleCreate = async () => {
    if (!action || !connectorId) return;
    setCreating(true);
    try {
      await ticketsApi.createFromRemediation(clientId, {
        remediation_action_id: action.id,
        connector_id: connectorId,
        assignment_group: assignmentGroup || undefined,
        project_key: projectKey || undefined,
      });
      toast.success("Ticket created successfully");
      onCreated();
      onClose();
    } catch (err: any) {
      const detail = err?.response?.data?.detail || "Failed to create ticket";
      toast.error(detail);
    } finally {
      setCreating(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Create Ticket</DialogTitle>
      <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2, pt: 2 }}>
        {connectors.length === 0 ? (
          <Alert severity="warning">
            No ServiceNow or Jira connectors configured for this client. Add one under Connections.
          </Alert>
        ) : (
          <>
            <Typography variant="body2" sx={{ color: "text.secondary" }}>
              Action: <strong>{action?.title || action?.action?.slice(0, 80)}</strong>
            </Typography>
            <FormControl size="small" fullWidth>
              <InputLabel>Ticketing System</InputLabel>
              <Select value={connectorId} label="Ticketing System" onChange={(e) => setConnectorId(e.target.value)}>
                {connectors.map((c) => (
                  <MenuItem key={c.id} value={c.id}>
                    {c.name} ({c.connector_type === "servicenow" ? "ServiceNow" : "Jira"})
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            {isSN && (
              <TextField
                size="small"
                label="Assignment Group (optional)"
                value={assignmentGroup}
                onChange={(e) => setAssignmentGroup(e.target.value)}
                fullWidth
              />
            )}
            {isJira && (
              <TextField
                size="small"
                label="Project Key"
                value={projectKey}
                onChange={(e) => setProjectKey(e.target.value)}
                fullWidth
                required
                error={isJira && !projectKey.trim()}
                helperText={isJira && !projectKey.trim() ? "Required — enter your Jira project key (e.g. KAN, SAM1)" : "The short key shown before every issue number (e.g. KAN-1)"}
              />
            )}
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          onClick={handleCreate}
          disabled={creating || !connectorId || connectors.length === 0 || (isJira && !projectKey.trim())}
        >
          {creating ? "Creating…" : "Create Ticket"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

const CONNECTOR_COLOR: Record<string, string> = { servicenow: "#7C3AED", jira: "#0052CC" };
const CONNECTOR_LABEL: Record<string, string> = { servicenow: "ServiceNow", jira: "Jira" };

export default function RemediationTracker() {
  const qc = useQueryClient();
  const { clientId } = useActiveClient();
  const [mainTab, setMainTab] = useState<"actions" | "tickets">("actions");
  const [filterStatus, setFilterStatus] = useState("open");
  const [filterBand, setFilterBand] = useState("");
  const [groupByBand, setGroupByBand] = useState(true);
  const [ticketDialogAction, setTicketDialogAction] = useState<RemediationAction | null>(null);

  const { data: actions = [], isLoading, refetch } = useQuery<RemediationAction[]>({
    queryKey: ["remediation-actions", clientId, filterStatus, filterBand],
    queryFn: () => remediationTrackerApi.list(clientId, {
      status: filterStatus || undefined,
      band: filterBand || undefined,
    }),
    enabled: !!clientId,
  });

  const { data: ticketConnectors = [] } = useQuery<TicketConnector[]>({
    queryKey: ["ticket-connectors", clientId],
    queryFn: () => ticketsApi.getConnectors(clientId),
    enabled: !!clientId,
  });

  const { data: ticketSyncs = [] } = useQuery<TicketSync[]>({
    queryKey: ["ticket-syncs", clientId],
    queryFn: () => ticketsApi.list(clientId),
    enabled: !!clientId,
  });

  // Build a lookup: source_id → TicketSync (latest per source_id)
  const ticketBySourceId = React.useMemo(() => {
    const map: Record<string, TicketSync> = {};
    for (const t of ticketSyncs) {
      if (t.source_type === "remediation_action") {
        map[t.source_id] = t;
      }
    }
    return map;
  }, [ticketSyncs]);

  const syncStatusMut = useMutation({
    mutationFn: (ticketSyncId: string) => ticketsApi.sync(clientId!, ticketSyncId),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["ticket-syncs", clientId] }); toast.success("Status synced"); },
    onError: () => toast.error("Sync failed"),
  });

  const updateMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      remediationTrackerApi.update(clientId, id, { status }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["remediation-actions", clientId] }); toast.success("Status updated"); },
    onError: () => toast.error("Update failed"),
  });

  const counts = { open: 0, in_progress: 0, completed: 0, cancelled: 0, total: actions.length };
  for (const a of actions) counts[a.status as keyof typeof counts]++;

  const completionPct = counts.total > 0
    ? Math.round(((counts.completed) / counts.total) * 100)
    : 0;

  // Group by band for grouped view
  const grouped = BAND_ORDER.map((band) => ({
    band,
    items: actions.filter((a) => a.band === band),
  })).filter((g) => g.items.length > 0);
  const ungrouped = actions.filter((a) => !BAND_ORDER.includes(a.band || ""));

  const renderRow = (a: RemediationAction) => {
    const existingTicket = ticketBySourceId[a.id];
    return (
      <TableRow key={a.id} hover
        sx={{ opacity: a.status === "cancelled" ? 0.5 : 1,
              textDecoration: a.status === "completed" ? "line-through" : "none" }}>
        <TableCell>
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <Typography sx={{ fontSize: 12, fontWeight: 700, color: BAND_COLOR[a.band || ""] || "#4285F4",
              width: 24, textAlign: "center" }}>
              {a.priority ?? "—"}
            </Typography>
          </Box>
        </TableCell>
        <TableCell sx={{ maxWidth: 340 }}>
          <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 12.5, lineHeight: 1.4 }}>{a.action}</Typography>
          {a.notes && (
            <Typography variant="caption" sx={{ color: "text.secondary" }}>{a.notes}</Typography>
          )}
          {existingTicket && (
            <Box sx={{ mt: 0.5 }}>
              <Chip
                label={`${existingTicket.connector_type === "servicenow" ? "SN" : "Jira"}: ${existingTicket.ticket_id}`}
                size="small"
                icon={<ConfirmationNumber sx={{ fontSize: "12px !important" }} />}
                onClick={() => existingTicket.ticket_url && window.open(existingTicket.ticket_url, "_blank")}
                sx={{
                  bgcolor: existingTicket.connector_type === "servicenow" ? "#7C3AED22" : "#0052CC22",
                  color: existingTicket.connector_type === "servicenow" ? "#7C3AED" : "#0052CC",
                  fontSize: 10, height: 18, cursor: existingTicket.ticket_url ? "pointer" : "default",
                }}
              />
            </Box>
          )}
        </TableCell>
        {!groupByBand && (
          <TableCell>
            {a.band ? (
              <Chip label={a.band} size="small"
                sx={{ bgcolor: `${BAND_COLOR[a.band] || "#4285F4"}22`,
                  color: BAND_COLOR[a.band] || "#4285F4", fontSize: 10, height: 18 }} />
            ) : <Typography variant="caption">—</Typography>}
          </TableCell>
        )}
        <TableCell>
          {a.effort ? (
            <Chip label={a.effort} size="small"
              sx={{ bgcolor: `${EFFORT_COLOR[a.effort] || "#9e9e9e"}22`,
                color: EFFORT_COLOR[a.effort] || "#9e9e9e", fontSize: 10, height: 18 }} />
          ) : <Typography variant="caption">—</Typography>}
        </TableCell>
        <TableCell>
          {a.impact ? (
            <Chip label={a.impact} size="small"
              sx={{ bgcolor: `${IMPACT_COLOR[a.impact] || "#9e9e9e"}22`,
                color: IMPACT_COLOR[a.impact] || "#9e9e9e", fontSize: 10, height: 18 }} />
          ) : <Typography variant="caption">—</Typography>}
        </TableCell>
        <TableCell>
          <Chip label={a.status.replace("_", " ")} size="small"
            sx={{ bgcolor: `${STATUS_COLOR[a.status] || "#9e9e9e"}22`,
              color: STATUS_COLOR[a.status] || "#9e9e9e",
              fontSize: 10, height: 18, textTransform: "capitalize" }} />
        </TableCell>
        <TableCell sx={{ fontSize: 11, whiteSpace: "nowrap" }}>{a.created_at ? fmt(a.created_at) : "—"}</TableCell>
        <TableCell>
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <StatusMenu action={a} onUpdate={(status) => updateMut.mutate({ id: a.id, status })} />
            <Tooltip title={existingTicket ? `Ticket: ${existingTicket.ticket_id}` : "Create Ticket"}>
              <IconButton
                size="small"
                onClick={(e) => { e.stopPropagation(); setTicketDialogAction(a); }}
                sx={{ color: existingTicket ? (existingTicket.connector_type === "servicenow" ? "#7C3AED" : "#0052CC") : "text.secondary" }}
              >
                <ConfirmationNumber sx={{ fontSize: 16 }} />
              </IconButton>
            </Tooltip>
          </Box>
        </TableCell>
      </TableRow>
    );
  };

  const colHeaders = ["#", "Action", ...(!groupByBand ? ["Band"] : []), "Effort", "Impact", "Status", "Created", ""];

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Remediation</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Priority-banded action items from the Remediation agent — track to closure
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1 }}>
          {mainTab === "actions" && (
            <Tooltip title={groupByBand ? "Show flat list" : "Group by band"}>
              <IconButton onClick={() => setGroupByBand((g) => !g)}>
                <Assignment fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
          <IconButton onClick={() => refetch()}><Refresh /></IconButton>
        </Box>
      </Box>

      <Tabs value={mainTab} onChange={(_, v) => setMainTab(v)}
        sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)", mb: 3,
          "& .MuiTab-root": { textTransform: "none", fontWeight: 600, color: "text.secondary" },
          "& .Mui-selected": { color: "#4285F4" },
          "& .MuiTabs-indicator": { backgroundColor: "#4285F4" } }}>
        <Tab value="actions" label={`Actions (${actions.length})`} icon={<Assignment sx={{ fontSize: 16 }} />} iconPosition="start" />
        <Tab value="tickets" label={`Tickets (${ticketSyncs.length})`} icon={<ConfirmationNumber sx={{ fontSize: 16 }} />} iconPosition="start" />
      </Tabs>

      {mainTab === "actions" && <Box sx={{ display: "flex", gap: 1.5, mb: 3, flexWrap: "wrap" }}>
        <FormControl size="small" sx={{ minWidth: 150 }}>
          <InputLabel>Status</InputLabel>
          <Select value={filterStatus} label="Status" onChange={(e) => setFilterStatus(e.target.value)}>
            <MenuItem value="">All</MenuItem>
            <MenuItem value="open">Open</MenuItem>
            <MenuItem value="in_progress">In Progress</MenuItem>
            <MenuItem value="completed">Completed</MenuItem>
            <MenuItem value="cancelled">Cancelled</MenuItem>
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel>Band</InputLabel>
          <Select value={filterBand} label="Band" onChange={(e) => setFilterBand(e.target.value)}>
            <MenuItem value="">All</MenuItem>
            {BAND_ORDER.map((b) => <MenuItem key={b} value={b}>{b}</MenuItem>)}
          </Select>
        </FormControl>
      </Box>}

      {mainTab === "actions" && <>{/* KPI strip */}
      {clientId && (
        <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
          {[
            { label: "Total", value: counts.total, color: "#4285F4" },
            { label: "Open", value: counts.open, color: "#FF7043" },
            { label: "In Progress", value: counts.in_progress, color: "#FBBC04" },
            { label: "Completed", value: counts.completed, color: "#34A853" },
          ].map(({ label, value, color }) => (
            <Card key={label} variant="outlined" sx={{ minWidth: 110 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color }}>{value}</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>{label}</Typography>
              </CardContent>
            </Card>
          ))}
          {counts.total > 0 && (
            <Card variant="outlined" sx={{ minWidth: 160 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color: completionPct >= 70 ? "#34A853" : "#FBBC04" }}>
                  {completionPct}%
                </Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>Complete</Typography>
                <LinearProgress variant="determinate" value={completionPct}
                  sx={{ mt: 0.5, height: 4, borderRadius: 2,
                    "& .MuiLinearProgress-bar": { bgcolor: completionPct >= 70 ? "#34A853" : "#FBBC04" }
                  }} />
              </CardContent>
            </Card>
          )}
        </Box>
      )}

      {!clientId && <Alert severity="info">Select a client to view their remediation tracker.</Alert>}
      {clientId && isLoading && <CircularProgress size={24} />}

      {clientId && !isLoading && actions.length === 0 && (
        <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
          <Assignment sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No remediation actions yet. Run the <strong>Remediation</strong> agent on a completed scan.
          </Typography>
        </Card>
      )}

      {clientId && !isLoading && actions.length > 0 && (
        groupByBand ? (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {grouped.map(({ band, items }) => {
              const bandColor = BAND_COLOR[band] || "#4285F4";
              const bandDone = items.filter((i) => i.status === "completed").length;
              return (
                <Box key={band}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                    <Box sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: bandColor }} />
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: bandColor }}>
                      {band}
                    </Typography>
                    <Chip label={`${bandDone}/${items.length} done`} size="small"
                      sx={{ bgcolor: `${bandColor}22`, color: bandColor, fontSize: 10, height: 18 }} />
                  </Box>
                  <TableContainer component={Card} variant="outlined">
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          {colHeaders.map((h) => (
                            <TableCell key={h} sx={{ fontWeight: 700, fontSize: 11 }}>{h}</TableCell>
                          ))}
                        </TableRow>
                      </TableHead>
                      <TableBody>{items.map(renderRow)}</TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              );
            })}
            {ungrouped.length > 0 && (
              <Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.secondary", mb: 1 }}>
                  Other Actions
                </Typography>
                <TableContainer component={Card} variant="outlined">
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        {colHeaders.map((h) => (
                          <TableCell key={h} sx={{ fontWeight: 700, fontSize: 11 }}>{h}</TableCell>
                        ))}
                      </TableRow>
                    </TableHead>
                    <TableBody>{ungrouped.map(renderRow)}</TableBody>
                  </Table>
                </TableContainer>
              </Box>
            )}
          </Box>
        ) : (
          <TableContainer component={Card} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  {colHeaders.map((h) => (
                    <TableCell key={h} sx={{ fontWeight: 700, fontSize: 11 }}>{h}</TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>{actions.map(renderRow)}</TableBody>
            </Table>
          </TableContainer>
        )
      )}

      </>}

      {/* Tickets tab */}
      {mainTab === "tickets" && (
        <Box>
          {!clientId && <Alert severity="info">Select a client to view their tickets.</Alert>}
          {clientId && ticketSyncs.length === 0 && (
            <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
              <ConfirmationNumber sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
              <Typography sx={{ color: "text.secondary" }}>
                No tickets yet. Use the <strong>Create Ticket</strong> button on an action above to push to ServiceNow or Jira.
              </Typography>
            </Card>
          )}
          {clientId && ticketSyncs.length > 0 && (
            <TableContainer component={Card} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    {["Source", "Ticket", "System", "Status", "Created", ""].map((h) => (
                      <TableCell key={h} sx={{ fontWeight: 700, fontSize: 11 }}>{h}</TableCell>
                    ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {ticketSyncs.map((sync) => {
                    const color = CONNECTOR_COLOR[sync.connector_type] || "#9e9e9e";
                    const label = CONNECTOR_LABEL[sync.connector_type] || sync.connector_type;
                    return (
                      <TableRow key={sync.id} hover>
                        <TableCell>
                          <Chip label={sync.source_type === "finding" ? "Finding" : "Remediation"}
                            size="small"
                            sx={{ bgcolor: sync.source_type === "finding" ? "#EA433522" : "#4285F422",
                              color: sync.source_type === "finding" ? "#EA4335" : "#4285F4",
                              fontSize: 10, height: 18 }} />
                        </TableCell>
                        <TableCell>
                          {sync.ticket_url ? (
                            <Link href={sync.ticket_url} target="_blank" rel="noopener noreferrer"
                              sx={{ display: "flex", alignItems: "center", gap: 0.5, fontSize: 12 }}>
                              {sync.ticket_id}<OpenInNew sx={{ fontSize: 12 }} />
                            </Link>
                          ) : (
                            <Typography variant="body2" sx={{ fontSize: 12 }}>{sync.ticket_id}</Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip label={label} size="small"
                            sx={{ bgcolor: `${color}22`, color, fontSize: 10, height: 18 }} />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontSize: 12, textTransform: "capitalize" }}>
                            {sync.ticket_status || "—"}
                          </Typography>
                        </TableCell>
                        <TableCell sx={{ fontSize: 11, whiteSpace: "nowrap" }}>
                          {sync.created_at ? fmt(sync.created_at) : "—"}
                        </TableCell>
                        <TableCell>
                          <Tooltip title="Sync status from ticketing system">
                            <IconButton size="small" onClick={() => syncStatusMut.mutate(sync.id)}
                              disabled={syncStatusMut.isPending}>
                              <Refresh sx={{ fontSize: 16 }} />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Box>
      )}

      {/* Create Ticket Dialog */}
      <CreateTicketDialog
        open={ticketDialogAction !== null}
        action={ticketDialogAction}
        connectors={ticketConnectors}
        clientId={clientId || ""}
        onClose={() => setTicketDialogAction(null)}
        onCreated={() => {
          qc.invalidateQueries({ queryKey: ["ticket-syncs", clientId] });
        }}
      />
    </Box>
  );
}
