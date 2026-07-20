import React from "react";
import { useActiveClient } from "../contexts/ClientContext";
import { useQuery } from "@tanstack/react-query";
import {
  Box, Typography, Alert, CircularProgress, Card,
  Table, TableHead, TableRow, TableCell, TableBody,
  TableContainer, Chip, Tooltip,
} from "@mui/material";
import { GridView } from "@mui/icons-material";
import { apiClient } from "../services/api";

// ── Types ────────────────────────────────────────────────────────────────────

interface FrameworkSummary {
  framework: string;
  overall_score: number;
  total_controls: number;
  passed: number;
}

interface MatrixCell {
  pass_rate: number | null;
  passed: number;
  total: number;
}

interface HeatmapData {
  frameworks: string[];
  domains: string[];
  matrix: Record<string, Record<string, MatrixCell>>;
  summary: FrameworkSummary[];
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function cellColor(rate: number | null): string {
  if (rate == null) return "rgba(255,255,255,0.04)";
  if (rate >= 80) return "rgba(52,168,83,0.25)";
  if (rate >= 40) return "rgba(251,188,4,0.25)";
  return "rgba(234,67,53,0.25)";
}

function cellBorder(rate: number | null): string {
  if (rate == null) return "rgba(255,255,255,0.08)";
  if (rate >= 80) return "rgba(52,168,83,0.5)";
  if (rate >= 40) return "rgba(251,188,4,0.5)";
  return "rgba(234,67,53,0.5)";
}

function cellTextColor(rate: number | null): string {
  if (rate == null) return "rgba(255,255,255,0.25)";
  if (rate >= 80) return "#34A853";
  if (rate >= 40) return "#FBBC04";
  return "#EA4335";
}

function scoreColor(score: number): string {
  if (score >= 80) return "#34A853";
  if (score >= 40) return "#FBBC04";
  return "#EA4335";
}

function fwLabel(fw: string): string {
  return fw.replace(/_/g, " ").toUpperCase();
}

// ── Component ────────────────────────────────────────────────────────────────

export default function ComplianceHeatmap() {
  const { clientId } = useActiveClient();

  const { data, isLoading, isError } = useQuery<HeatmapData>({
    queryKey: ["compliance-heatmap", clientId],
    queryFn: () =>
      apiClient.get(`/clients/${clientId}/compliance/heatmap/`).then((r) => r.data),
    enabled: !!clientId,
  });

  const isEmpty =
    !isLoading &&
    !isError &&
    data &&
    (data.frameworks.length === 0 || data.domains.length === 0);

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 0.5 }}>
        <GridView sx={{ color: "#4285F4", fontSize: 28 }} />
        <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>
          Compliance Heatmap
        </Typography>
      </Box>
      <Typography variant="body2" sx={{ color: "text.secondary", mb: 3 }}>
        Pass rates per security domain across all compliance frameworks — green
        &ge;80%, amber 40–79%, red &lt;40%.
      </Typography>

      {!clientId && (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "text.primary" }}>
          Select a client to view the compliance heatmap.
        </Alert>
      )}

      {clientId && isLoading && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      )}

      {clientId && isError && (
        <Alert severity="error" sx={{ bgcolor: "rgba(234,67,53,0.1)", color: "text.primary" }}>
          Failed to load heatmap data.
        </Alert>
      )}

      {clientId && isEmpty && (
        <Alert
          severity="info"
          sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "text.primary", border: "1px solid rgba(66,133,244,0.25)" }}
        >
          Run the <strong>Compliance Monitor</strong> AI agent on a scan to generate
          framework assessments.
        </Alert>
      )}

      {clientId && data && !isEmpty && (
        <>
          {/* Legend */}
          <Box sx={{ display: "flex", gap: 2, mb: 2.5, flexWrap: "wrap", alignItems: "center" }}>
            {[
              { label: "Pass rate ≥ 80%", color: "#34A853" },
              { label: "Pass rate 40–79%", color: "#FBBC04" },
              { label: "Pass rate < 40%", color: "#EA4335" },
            ].map(({ label, color }) => (
              <Box key={label} sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                <Box sx={{ width: 12, height: 12, borderRadius: 0.5, bgcolor: `${color}30`, border: `1px solid ${color}80` }} />
                <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                  {label}
                </Typography>
              </Box>
            ))}
          </Box>

          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, overflow: "hidden" }}>
            <TableContainer sx={{ overflowX: "auto" }}>
              <Table size="small" sx={{ minWidth: 600 }}>
                <TableHead>
                  <TableRow sx={{ "& th": { borderColor: "divider", bgcolor: "rgba(255,255,255,0.03)" } }}>
                    <TableCell
                      sx={{
                        color: "text.secondary", fontSize: 11, fontWeight: 700,
                        minWidth: 180, position: "sticky", left: 0,
                        bgcolor: "rgba(20,20,20,0.95)", zIndex: 2,
                        borderRight: "1px solid rgba(255,255,255,0.08)",
                      }}
                    >
                      DOMAIN
                    </TableCell>
                    {data.frameworks.map((fw) => (
                      <TableCell
                        key={fw}
                        align="center"
                        sx={{ color: "#82b1ff", fontSize: 11, fontWeight: 700, minWidth: 140 }}
                      >
                        {fwLabel(fw)}
                      </TableCell>
                    ))}
                  </TableRow>
                </TableHead>

                <TableBody>
                  {data.domains.map((domain) => (
                    <TableRow
                      key={domain}
                      sx={{ "& td": { borderColor: "divider" }, "&:hover": { bgcolor: "rgba(255,255,255,0.02)" } }}
                    >
                      {/* Domain name — sticky left */}
                      <TableCell
                        sx={{
                          color: "text.primary", fontWeight: 500, fontSize: 13,
                          position: "sticky", left: 0,
                          bgcolor: "rgba(20,20,20,0.95)", zIndex: 1,
                          borderRight: "1px solid rgba(255,255,255,0.08)",
                        }}
                      >
                        {domain}
                      </TableCell>

                      {data.frameworks.map((fw) => {
                        const cell: MatrixCell | undefined = data.matrix[domain]?.[fw];
                        const rate = cell?.pass_rate ?? null;
                        return (
                          <TableCell key={fw} align="center" sx={{ p: 1 }}>
                            {cell ? (
                              <Tooltip
                                title={`${domain} / ${fwLabel(fw)}: ${cell.passed} / ${cell.total} controls passed`}
                                placement="top"
                              >
                                <Box
                                  sx={{
                                    display: "inline-flex",
                                    alignItems: "center",
                                    justifyContent: "center",
                                    width: 72,
                                    height: 32,
                                    borderRadius: 1,
                                    bgcolor: cellColor(rate),
                                    border: `1px solid ${cellBorder(rate)}`,
                                    cursor: "default",
                                  }}
                                >
                                  <Typography
                                    sx={{
                                      fontSize: 13,
                                      fontWeight: 700,
                                      color: cellTextColor(rate),
                                    }}
                                  >
                                    {rate != null ? `${Math.round(rate)}%` : "—"}
                                  </Typography>
                                </Box>
                              </Tooltip>
                            ) : (
                              <Box
                                sx={{
                                  display: "inline-flex",
                                  alignItems: "center",
                                  justifyContent: "center",
                                  width: 72,
                                  height: 32,
                                  borderRadius: 1,
                                  bgcolor: "rgba(255,255,255,0.03)",
                                  border: "1px solid rgba(255,255,255,0.06)",
                                }}
                              >
                                <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.2)" }}>—</Typography>
                              </Box>
                            )}
                          </TableCell>
                        );
                      })}
                    </TableRow>
                  ))}

                  {/* Summary row */}
                  <TableRow
                    sx={{
                      "& td": { borderColor: "divider", borderTop: "2px solid rgba(255,255,255,0.12)" },
                      bgcolor: "rgba(255,255,255,0.02)",
                    }}
                  >
                    <TableCell
                      sx={{
                        color: "text.secondary", fontWeight: 700, fontSize: 11,
                        textTransform: "uppercase", letterSpacing: 0.5,
                        position: "sticky", left: 0,
                        bgcolor: "rgba(20,20,20,0.95)", zIndex: 1,
                        borderRight: "1px solid rgba(255,255,255,0.08)",
                      }}
                    >
                      Overall Score
                    </TableCell>
                    {data.frameworks.map((fw) => {
                      const summary = data.summary.find((s) => s.framework === fw);
                      const score = summary?.overall_score ?? null;
                      return (
                        <TableCell key={fw} align="center" sx={{ p: 1 }}>
                          {score != null ? (
                            <Chip
                              label={`${Math.round(score)}%`}
                              size="small"
                              sx={{
                                bgcolor: `${scoreColor(score)}20`,
                                color: scoreColor(score),
                                fontWeight: 700,
                                fontSize: 12,
                                border: `1px solid ${scoreColor(score)}50`,
                              }}
                            />
                          ) : (
                            <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.2)" }}>—</Typography>
                          )}
                        </TableCell>
                      );
                    })}
                  </TableRow>
                </TableBody>
              </Table>
            </TableContainer>
          </Card>

          {/* Per-framework summary chips */}
          {data.summary.length > 0 && (
            <Box sx={{ display: "flex", gap: 1.5, mt: 2.5, flexWrap: "wrap" }}>
              {data.summary.map((s) => (
                <Tooltip
                  key={s.framework}
                  title={`${s.passed} / ${s.total_controls} controls passed`}
                >
                  <Chip
                    label={`${fwLabel(s.framework)}: ${Math.round(s.overall_score)}%`}
                    size="small"
                    sx={{
                      bgcolor: `${scoreColor(s.overall_score)}15`,
                      color: scoreColor(s.overall_score),
                      border: `1px solid ${scoreColor(s.overall_score)}40`,
                      fontWeight: 600,
                      fontSize: 12,
                    }}
                  />
                </Tooltip>
              ))}
            </Box>
          )}
        </>
      )}
    </Box>
  );
}
