import React from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Box, Typography, Card, Chip, CircularProgress, Alert,
  Table, TableHead, TableRow, TableCell, TableBody,
  TableContainer, Tooltip,
} from "@mui/material";
import { CompareArrows } from "@mui/icons-material";
import { apiClient } from "../services/api";
import { fromNow } from "../utils/datetime";

// ── Types ────────────────────────────────────────────────────────────────────

interface ClientComparisonRow {
  client_id: string;
  client_name: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total_open: number;
  open_risks: number;
  compliance_score: number | null;
  last_scan_at: string | null;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: "#EA4335",
  high: "#FF7043",
  medium: "#FBBC04",
  low: "#34A853",
};

function SevChip({ count, sev }: { count: number; sev: string }) {
  const color = SEV_COLORS[sev] || "#888";
  return (
    <Chip
      label={count}
      size="small"
      sx={{
        bgcolor: count > 0 ? `${color}20` : "rgba(255,255,255,0.04)",
        color: count > 0 ? color : "rgba(255,255,255,0.25)",
        fontWeight: 700,
        fontSize: 12,
        minWidth: 36,
        height: 22,
        border: count > 0 ? `1px solid ${color}40` : "1px solid rgba(255,255,255,0.08)",
      }}
    />
  );
}

function scoreColor(score: number): string {
  if (score >= 80) return "#34A853";
  if (score >= 40) return "#FBBC04";
  return "#EA4335";
}

// ── Component ────────────────────────────────────────────────────────────────

export default function ClientComparison() {
  const { data: rows = [], isLoading, isError } = useQuery<ClientComparisonRow[]>({
    queryKey: ["client-comparison"],
    queryFn: () => apiClient.get("/clients/compare/").then((r) => r.data),
  });

  // The backend returns rows sorted by total_open descending.
  // The row with the most criticals gets a red left-border accent.
  const maxCriticalIdx = rows.reduce<number>(
    (maxIdx, row, idx) => (row.critical > (rows[maxIdx]?.critical ?? -1) ? idx : maxIdx),
    0,
  );

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 0.5 }}>
        <CompareArrows sx={{ color: "#4285F4", fontSize: 28 }} />
        <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>
          Client Comparison
        </Typography>
      </Box>
      <Typography variant="body2" sx={{ color: "text.secondary", mb: 3 }}>
        Side-by-side risk posture across all clients — sorted by total open
        findings.
      </Typography>

      {isLoading && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      )}

      {isError && (
        <Alert severity="error" sx={{ bgcolor: "rgba(234,67,53,0.1)", color: "text.primary" }}>
          Failed to load client comparison data.
        </Alert>
      )}

      {!isLoading && !isError && rows.length === 0 && (
        <Alert
          severity="info"
          sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "text.primary", border: "1px solid rgba(66,133,244,0.25)" }}
        >
          No client data available. Add clients and run scans to populate this
          view.
        </Alert>
      )}

      {rows.length > 0 && (
        <Card
          sx={{
            bgcolor: "background.paper",
            border: "1px solid rgba(255,255,255,0.08)",
            borderRadius: 2,
            overflow: "hidden",
          }}
        >
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow
                  sx={{
                    "& th": {
                      color: "text.secondary",
                      fontSize: 11,
                      fontWeight: 700,
                      borderColor: "divider",
                      bgcolor: "rgba(255,255,255,0.03)",
                    },
                  }}
                >
                  <TableCell sx={{ minWidth: 180 }}>CLIENT</TableCell>
                  <TableCell align="center" sx={{ minWidth: 80 }}>
                    <Chip
                      label="CRITICAL"
                      size="small"
                      sx={{ bgcolor: "rgba(234,67,53,0.15)", color: "#EA4335", fontSize: 10, fontWeight: 700, height: 18 }}
                    />
                  </TableCell>
                  <TableCell align="center" sx={{ minWidth: 80 }}>
                    <Chip
                      label="HIGH"
                      size="small"
                      sx={{ bgcolor: "rgba(255,112,67,0.15)", color: "#FF7043", fontSize: 10, fontWeight: 700, height: 18 }}
                    />
                  </TableCell>
                  <TableCell align="center" sx={{ minWidth: 80 }}>
                    <Chip
                      label="MEDIUM"
                      size="small"
                      sx={{ bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04", fontSize: 10, fontWeight: 700, height: 18 }}
                    />
                  </TableCell>
                  <TableCell align="center" sx={{ minWidth: 80 }}>
                    <Chip
                      label="LOW"
                      size="small"
                      sx={{ bgcolor: "rgba(52,168,83,0.15)", color: "#34A853", fontSize: 10, fontWeight: 700, height: 18 }}
                    />
                  </TableCell>
                  <TableCell align="center" sx={{ minWidth: 100 }}>OPEN RISKS</TableCell>
                  <TableCell align="center" sx={{ minWidth: 120 }}>COMPLIANCE</TableCell>
                  <TableCell align="right" sx={{ minWidth: 120 }}>LAST SCAN</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((row, idx) => {
                  const isTopCritical = idx === maxCriticalIdx && row.critical > 0;
                  return (
                    <TableRow
                      key={row.client_id}
                      sx={{
                        "& td": { borderColor: "divider", py: 1.25 },
                        "&:hover": { bgcolor: "rgba(255,255,255,0.025)" },
                        borderLeft: isTopCritical ? "3px solid #EA4335" : "3px solid transparent",
                      }}
                    >
                      {/* Client name */}
                      <TableCell>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <Typography
                            variant="body2"
                            sx={{ color: "text.primary", fontWeight: 600, fontSize: 13 }}
                          >
                            {row.client_name}
                          </Typography>
                          {isTopCritical && (
                            <Tooltip title="Highest critical finding count">
                              <Chip
                                label="Highest Risk"
                                size="small"
                                sx={{
                                  bgcolor: "rgba(234,67,53,0.15)",
                                  color: "#EA4335",
                                  fontSize: 10,
                                  height: 18,
                                  border: "1px solid rgba(234,67,53,0.3)",
                                }}
                              />
                            </Tooltip>
                          )}
                        </Box>
                        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                          {row.total_open} open findings total
                        </Typography>
                      </TableCell>

                      {/* Severity chips */}
                      <TableCell align="center">
                        <SevChip count={row.critical} sev="critical" />
                      </TableCell>
                      <TableCell align="center">
                        <SevChip count={row.high} sev="high" />
                      </TableCell>
                      <TableCell align="center">
                        <SevChip count={row.medium} sev="medium" />
                      </TableCell>
                      <TableCell align="center">
                        <SevChip count={row.low} sev="low" />
                      </TableCell>

                      {/* Open risks */}
                      <TableCell align="center">
                        <Chip
                          label={row.open_risks}
                          size="small"
                          sx={{
                            bgcolor:
                              row.open_risks > 0
                                ? "rgba(66,133,244,0.15)"
                                : "rgba(255,255,255,0.04)",
                            color:
                              row.open_risks > 0 ? "#4285F4" : "rgba(255,255,255,0.25)",
                            fontWeight: 700,
                            fontSize: 12,
                            height: 22,
                          }}
                        />
                      </TableCell>

                      {/* Compliance score */}
                      <TableCell align="center">
                        {row.compliance_score != null ? (
                          <Chip
                            label={`${Math.round(row.compliance_score)}%`}
                            size="small"
                            sx={{
                              bgcolor: `${scoreColor(row.compliance_score)}20`,
                              color: scoreColor(row.compliance_score),
                              fontWeight: 700,
                              fontSize: 12,
                              height: 22,
                              border: `1px solid ${scoreColor(row.compliance_score)}40`,
                            }}
                          />
                        ) : (
                          <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.25)" }}>—</Typography>
                        )}
                      </TableCell>

                      {/* Last scan */}
                      <TableCell align="right">
                        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                          {row.last_scan_at ? fromNow(row.last_scan_at) : "—"}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </Card>
      )}
    </Box>
  );
}
