import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Button, Chip, Alert,
  Table, TableBody, TableCell, TableHead, TableRow, Skeleton, Tooltip,
} from "@mui/material";
import { ReportProblem, Add } from "@mui/icons-material";
import { useActiveClient } from "../contexts/ClientContext";

const PLACEHOLDER_INCIDENTS = [
  { id: "INC-001", title: "Suspected lateral movement from LogSource VM", severity: "critical", status: "open",   owner: "dheeraj.gulati", opened: "2026-08-10" },
  { id: "INC-002", title: "Exposed S3 bucket with PII files",             severity: "high",     status: "open",   owner: "security-team",    opened: "2026-08-14" },
  { id: "INC-003", title: "Brute-force attempt on admin portal",           severity: "medium",   status: "closed", owner: "soc-analyst",       opened: "2026-08-01" },
];

const SEV_COLORS: Record<string, { bg: string; color: string }> = {
  critical: { bg: "rgba(234,67,53,0.15)",  color: "#EA4335" },
  high:     { bg: "rgba(251,188,4,0.15)",   color: "#FBBC04" },
  medium:   { bg: "rgba(66,133,244,0.15)", color: "#4285F4" },
  low:      { bg: "rgba(52,168,83,0.15)",  color: "#34A853" },
};

const STATUS_COLORS: Record<string, { bg: string; color: string }> = {
  open:         { bg: "rgba(234,67,53,0.12)",  color: "#EA4335" },
  investigating:{ bg: "rgba(251,188,4,0.12)",   color: "#FBBC04" },
  contained:    { bg: "rgba(66,133,244,0.12)", color: "#4285F4" },
  closed:       { bg: "rgba(52,168,83,0.12)",  color: "#34A853" },
};

export default function Incidents() {
  const { clientId } = useActiveClient();
  const [showPlaceholder] = useState(true);

  if (!clientId) {
    return <Alert severity="info" sx={{ mt: 2 }}>Select a client to view incidents.</Alert>;
  }

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>Incidents</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
            Security incident cases with timelines, owners, SLA tracking, and linked findings.
          </Typography>
        </Box>
        <Tooltip title="Incident management coming soon">
          <span>
            <Button variant="contained" startIcon={<Add />} disabled size="small"
              sx={{ bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" } }}>
              New Incident
            </Button>
          </span>
        </Tooltip>
      </Box>

      <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
        Full incident lifecycle management — timelines, communication logs, SLA tracking — is coming in a future release.
        The rows below are sample data to illustrate the intended layout.
      </Alert>

      <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
        <CardContent sx={{ p: 0 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ "& th": { fontWeight: 700, fontSize: 12, bgcolor: "rgba(255,255,255,0.03)", color: "text.secondary", borderBottom: "1px solid rgba(255,255,255,0.1)" } }}>
                <TableCell>ID</TableCell>
                <TableCell>Title</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Owner</TableCell>
                <TableCell>Opened</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {PLACEHOLDER_INCIDENTS.map(inc => {
                const sev = SEV_COLORS[inc.severity] ?? SEV_COLORS.low;
                const sta = STATUS_COLORS[inc.status] ?? STATUS_COLORS.open;
                return (
                  <TableRow key={inc.id} sx={{ "&:hover": { bgcolor: "rgba(255,255,255,0.03)" }, opacity: 0.7 }}>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: 12, color: "#4285F4" }}>{inc.id}</TableCell>
                    <TableCell sx={{ fontSize: 13 }}>{inc.title}</TableCell>
                    <TableCell>
                      <Chip label={inc.severity} size="small" sx={{ bgcolor: sev.bg, color: sev.color, fontWeight: 700, fontSize: 10, height: 20, textTransform: "capitalize" }} />
                    </TableCell>
                    <TableCell>
                      <Chip label={inc.status} size="small" sx={{ bgcolor: sta.bg, color: sta.color, fontWeight: 700, fontSize: 10, height: 20, textTransform: "capitalize" }} />
                    </TableCell>
                    <TableCell sx={{ fontSize: 12, color: "text.secondary" }}>{inc.owner}</TableCell>
                    <TableCell sx={{ fontSize: 12, color: "text.secondary" }}>{inc.opened}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </Box>
  );
}
