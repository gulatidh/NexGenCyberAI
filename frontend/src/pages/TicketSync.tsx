import React, { useState } from "react";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer,
  IconButton, Alert, Tooltip, ToggleButtonGroup, ToggleButton, Link,
} from "@mui/material";
import { Refresh, ConfirmationNumber, OpenInNew } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ticketsApi } from "../services/api";
import { TicketSync as TicketSyncType } from "../types";
import { toast } from "react-toastify";
import { fmt } from "../utils/datetime";

const CONNECTOR_COLOR: Record<string, string> = {
  servicenow: "#7C3AED",
  jira: "#0052CC",
};

const CONNECTOR_LABEL: Record<string, string> = {
  servicenow: "ServiceNow",
  jira: "Jira",
};

export default function TicketSync() {
  const qc = useQueryClient();
  const { clientId } = useActiveClient();
  const [filterConnector, setFilterConnector] = useState<string>("all");

  const { data: syncs = [], isLoading, refetch } = useQuery<TicketSyncType[]>({
    queryKey: ["ticket-syncs", clientId],
    queryFn: () => ticketsApi.list(clientId!),
    enabled: !!clientId,
  });

  const syncMut = useMutation({
    mutationFn: (ticketSyncId: string) => ticketsApi.sync(clientId!, ticketSyncId),
    onSuccess: (updated: TicketSyncType) => {
      qc.invalidateQueries({ queryKey: ["ticket-syncs", clientId] });
      toast.success(`Status synced: ${updated.ticket_status}`);
    },
    onError: () => toast.error("Sync failed"),
  });

  const filtered = syncs.filter(
    (s) => filterConnector === "all" || s.connector_type === filterConnector,
  );

  const snCount = syncs.filter((s) => s.connector_type === "servicenow").length;
  const jiraCount = syncs.filter((s) => s.connector_type === "jira").length;

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Ticket Sync</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Tickets created in ServiceNow and Jira from findings and remediation actions
          </Typography>
        </Box>
        <IconButton onClick={() => refetch()}><Refresh /></IconButton>
      </Box>

      {/* KPI strip */}
      {clientId && (
        <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
          {[
            { label: "Total Tickets", value: syncs.length, color: "#4285F4" },
            { label: "ServiceNow", value: snCount, color: "#7C3AED" },
            { label: "Jira", value: jiraCount, color: "#0052CC" },
          ].map(({ label, value, color }) => (
            <Card key={label} variant="outlined" sx={{ minWidth: 130 }}>
              <CardContent sx={{ py: 1.5, px: 2, "&:last-child": { pb: 1.5 } }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color }}>{value}</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>{label}</Typography>
              </CardContent>
            </Card>
          ))}
        </Box>
      )}

      {/* Filter tabs */}
      {clientId && syncs.length > 0 && (
        <Box sx={{ mb: 2 }}>
          <ToggleButtonGroup
            size="small"
            exclusive
            value={filterConnector}
            onChange={(_, v) => v && setFilterConnector(v)}
          >
            <ToggleButton value="all">All</ToggleButton>
            <ToggleButton value="servicenow">ServiceNow</ToggleButton>
            <ToggleButton value="jira">Jira</ToggleButton>
          </ToggleButtonGroup>
        </Box>
      )}

      {!clientId && <Alert severity="info">Select a client to view their ticket syncs.</Alert>}
      {clientId && isLoading && <CircularProgress size={24} />}

      {clientId && !isLoading && syncs.length === 0 && (
        <Card variant="outlined" sx={{ p: 4, textAlign: "center" }}>
          <ConfirmationNumber sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography sx={{ color: "text.secondary" }}>
            No tickets created yet. Use the{" "}
            <strong>Create Ticket</strong> button on Remediation Tracker items to push them to
            ServiceNow or Jira.
          </Typography>
        </Card>
      )}

      {clientId && !isLoading && filtered.length > 0 && (
        <TableContainer component={Card} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Source</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Ticket</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>System</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Status</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: 11 }}>Created</TableCell>
                <TableCell sx={{ fontWeight: 700, fontSize: 11 }} />
              </TableRow>
            </TableHead>
            <TableBody>
              {filtered.map((sync) => {
                const color = CONNECTOR_COLOR[sync.connector_type] || "#9e9e9e";
                const label = CONNECTOR_LABEL[sync.connector_type] || sync.connector_type;
                return (
                  <TableRow key={sync.id} hover>
                    <TableCell>
                      <Chip
                        label={sync.source_type === "finding" ? "Finding" : "Remediation Action"}
                        size="small"
                        sx={{
                          bgcolor: sync.source_type === "finding" ? "#EA433522" : "#4285F422",
                          color: sync.source_type === "finding" ? "#EA4335" : "#4285F4",
                          fontSize: 10, height: 18,
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      {sync.ticket_url ? (
                        <Link
                          href={sync.ticket_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          sx={{ display: "flex", alignItems: "center", gap: 0.5, fontSize: 12 }}
                        >
                          {sync.ticket_id}
                          <OpenInNew sx={{ fontSize: 12 }} />
                        </Link>
                      ) : (
                        <Typography variant="body2" sx={{ fontSize: 12 }}>{sync.ticket_id}</Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={label}
                        size="small"
                        sx={{ bgcolor: `${color}22`, color, fontSize: 10, height: 18 }}
                      />
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
                        <IconButton
                          size="small"
                          onClick={() => syncMut.mutate(sync.id)}
                          disabled={syncMut.isPending}
                        >
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
  );
}
