import React, { useCallback } from "react";
import {
  Box, Typography, Button, Chip, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Paper, Skeleton, Alert,
  Tabs, Tab,
} from "@mui/material";
import { ArrowBack, PictureAsPdf, CompareArrows, Language } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useLocation, useSearchParams } from "react-router-dom";
import { useMsal } from "@azure/msal-react";
import { loginRequest } from "../auth/msalConfig";
import { useActiveClient } from "../contexts/ClientContext";
import { vaptApi } from "../services/api";

const API_BASE = import.meta.env.REACT_APP_API_URL || "http://localhost:8000/api/v1";

const SEV_COLORS: Record<string, string> = {
  critical: "#C62828",
  high: "#E64A19",
  medium: "#F9A825",
  low: "#2E7D32",
  informational: "#1565C0",
  info: "#1565C0",
};

function SevChip({ severity }: { severity: string }) {
  const sev = (severity || "info").toLowerCase();
  const bg = SEV_COLORS[sev] ?? "#9e9e9e";
  return (
    <Chip
      label={sev.toUpperCase()}
      size="small"
      sx={{ bgcolor: bg, color: "#fff", fontWeight: 700, fontSize: "0.7rem", height: 20 }}
    />
  );
}

const SEV_ORDER = ["critical", "high", "medium", "low", "info", "informational"];

function sevRank(sev: string) {
  const idx = SEV_ORDER.indexOf((sev || "info").toLowerCase());
  return idx === -1 ? 99 : idx;
}

function sortBySev(arr: any[]) {
  return [...arr].sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
}

function ScoreDelta({ a, b }: { a: number; b: number }) {
  const delta = b - a;
  const sign = delta >= 0 ? "+" : "";
  const color = delta >= 0 ? "#2E7D32" : "#C62828";
  return (
    <Typography variant="h6" sx={{ fontWeight: 700, color }}>
      {a} → {b} <span style={{ fontSize: "0.9rem" }}>({sign}{delta})</span>
    </Typography>
  );
}

export default function VAPTCompare() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { clientId } = useActiveClient();
  const { instance, accounts } = useMsal();

  const a = searchParams.get("a") ?? "";
  const b = searchParams.get("b") ?? "";
  const vaptBase = location.pathname.startsWith("/report")
    ? "/report/vapt-reports"
    : "/respond/vapt-reports";

  const [tab, setTab] = React.useState(0);

  const { data, isLoading, error } = useQuery({
    queryKey: ["vapt-compare", clientId, a, b],
    queryFn: () => vaptApi.compare(clientId!, a, b),
    enabled: !!clientId && !!a && !!b,
  });

  const handleExport = useCallback(async (format: "pdf" | "html" = "pdf") => {
    let token = "";
    if (accounts.length > 0) {
      try {
        const resp = await instance.acquireTokenSilent({ ...loginRequest, account: accounts[0] });
        token = resp.idToken || resp.accessToken;
      } catch { }
    }
    const url = API_BASE + vaptApi.compareExportUrl(clientId!, a, b, format);
    const res = await fetch(url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) return;
    const blob = await res.blob();
    const blobUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = blobUrl;
    anchor.download = `vapt-compare-${a.slice(0, 8)}-vs-${b.slice(0, 8)}.${format}`;
    anchor.click();
    URL.revokeObjectURL(blobUrl);
  }, [clientId, a, b, instance, accounts]);

  if (!a || !b) {
    return (
      <Box sx={{ p: 4, textAlign: "center" }}>
        <Typography color="text.secondary">No reports selected for comparison.</Typography>
        <Button sx={{ mt: 2 }} onClick={() => navigate(vaptBase)}>Back to VAPT Reports</Button>
      </Box>
    );
  }

  const stats = data?.stats ?? {};
  const fixed: any[] = sortBySev(data?.fixed ?? []);
  const newFindings: any[] = sortBySev(data?.new_findings ?? []);
  const persisting: any[] = (data?.persisting ?? []).sort(
    (x: any, y: any) => sevRank(x.b?.severity) - sevRank(y.b?.severity)
  );

  const reportA = data?.report_a ?? {};
  const reportB = data?.report_b ?? {};

  return (
    <Box sx={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* Top bar */}
      <Box sx={{
        px: 3, py: 1.5, display: "flex", alignItems: "center", justifyContent: "space-between",
        borderBottom: "1px solid", borderColor: "divider", bgcolor: "background.paper",
        position: "sticky", top: 0, zIndex: 100,
      }}>
        <Button startIcon={<ArrowBack />} onClick={() => navigate(vaptBase)} size="small">
          VAPT Reports
        </Button>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <CompareArrows sx={{ color: "#1565C0" }} />
          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Comparison Report</Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1 }}>
          <Button
            variant="outlined"
            startIcon={<PictureAsPdf />}
            onClick={() => handleExport("pdf")}
            disabled={!data}
            size="small"
          >
            Export PDF
          </Button>
          <Button
            variant="outlined"
            startIcon={<Language />}
            onClick={() => handleExport("html")}
            disabled={!data}
            size="small"
            sx={{ borderColor: "#00897B", color: "#00897B", "&:hover": { borderColor: "#00695C", bgcolor: "rgba(0,137,123,.04)" } }}
          >
            Export HTML
          </Button>
        </Box>
      </Box>

      <Box sx={{ p: 3, flex: 1 }}>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            Failed to load comparison. Make sure both reports belong to this client.
          </Alert>
        )}

        {/* Report labels */}
        {isLoading ? (
          <Skeleton variant="rectangular" height={80} sx={{ borderRadius: 2, mb: 2 }} />
        ) : data && (
          <Paper variant="outlined" sx={{ p: 2, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ flex: 1, p: 1.5, borderRadius: 1, bgcolor: "#E3F2FD" }}>
              <Typography variant="caption" color="text.secondary">BASELINE (A)</Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{reportA.title ?? "—"}</Typography>
              <Typography variant="caption" color="text.secondary">
                v{reportA.version} · {reportA.report_date?.slice(0, 10) ?? "no date"}
              </Typography>
            </Box>
            <CompareArrows sx={{ fontSize: 28, color: "text.disabled" }} />
            <Box sx={{ flex: 1, p: 1.5, borderRadius: 1, bgcolor: "#E8F5E9" }}>
              <Typography variant="caption" color="text.secondary">CURRENT (B)</Typography>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{reportB.title ?? "—"}</Typography>
              <Typography variant="caption" color="text.secondary">
                v{reportB.version} · {reportB.report_date?.slice(0, 10) ?? "no date"}
              </Typography>
            </Box>
          </Paper>
        )}

        {/* Stat cards */}
        {isLoading ? (
          <Box sx={{ display: "flex", gap: 2, mb: 3 }}>
            {[1, 2, 3, 4].map((i) => <Skeleton key={i} variant="rectangular" width={140} height={80} sx={{ borderRadius: 2 }} />)}
          </Box>
        ) : data && (
          <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
            <Paper variant="outlined" sx={{ p: 2, minWidth: 120, textAlign: "center" }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#2E7D32" }}>{stats.fixed_count ?? 0}</Typography>
              <Typography variant="caption" color="text.secondary">Fixed</Typography>
            </Paper>
            <Paper variant="outlined" sx={{ p: 2, minWidth: 120, textAlign: "center" }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#C62828" }}>{stats.new_count ?? 0}</Typography>
              <Typography variant="caption" color="text.secondary">New</Typography>
            </Paper>
            <Paper variant="outlined" sx={{ p: 2, minWidth: 120, textAlign: "center" }}>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#E65100" }}>{stats.persisting_count ?? 0}</Typography>
              <Typography variant="caption" color="text.secondary">Persisting</Typography>
            </Paper>
            <Paper variant="outlined" sx={{ p: 2, minWidth: 180, textAlign: "center" }}>
              <ScoreDelta a={stats.score_a ?? 0} b={stats.score_b ?? 0} />
              <Typography variant="caption" color="text.secondary">Security Score</Typography>
            </Paper>
          </Box>
        )}

        {/* Tabs */}
        {isLoading ? (
          <Skeleton variant="rectangular" height={400} sx={{ borderRadius: 2 }} />
        ) : data && (
          <Paper variant="outlined" sx={{ borderRadius: 2 }}>
            <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ borderBottom: "1px solid", borderColor: "divider", px: 2 }}>
              <Tab label={`Fixed (${stats.fixed_count ?? 0})`} />
              <Tab label={`New (${stats.new_count ?? 0})`} />
              <Tab label={`Persisting (${stats.persisting_count ?? 0})`} />
            </Tabs>

            {/* Fixed */}
            {tab === 0 && (
              <Box sx={{ p: 2 }}>
                {fixed.length === 0 ? (
                  <Typography color="text.secondary" sx={{ py: 3, textAlign: "center" }}>
                    No findings were fixed between these two reports.
                  </Typography>
                ) : (
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ "& th": { fontWeight: 700, color: "text.secondary", fontSize: "0.75rem" } }}>
                          <TableCell>#</TableCell>
                          <TableCell>Finding</TableCell>
                          <TableCell>Severity</TableCell>
                          <TableCell>Affected Asset</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {fixed.map((f, i) => (
                          <TableRow key={f.id ?? i} sx={{ borderLeft: "4px solid #2E7D32" }}>
                            <TableCell sx={{ color: "text.secondary", width: 40 }}>{i + 1}</TableCell>
                            <TableCell sx={{ fontWeight: 500 }}>{f.title}</TableCell>
                            <TableCell><SevChip severity={f.severity} /></TableCell>
                            <TableCell sx={{ color: "text.secondary", fontSize: "0.8rem" }}>{f.affected_asset ?? "—"}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </Box>
            )}

            {/* New */}
            {tab === 1 && (
              <Box sx={{ p: 2 }}>
                {newFindings.length === 0 ? (
                  <Typography color="text.secondary" sx={{ py: 3, textAlign: "center" }}>
                    No new findings introduced in Report B.
                  </Typography>
                ) : (
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ "& th": { fontWeight: 700, color: "text.secondary", fontSize: "0.75rem" } }}>
                          <TableCell>#</TableCell>
                          <TableCell>Finding</TableCell>
                          <TableCell>Severity</TableCell>
                          <TableCell>Affected Asset</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {newFindings.map((f, i) => (
                          <TableRow key={f.id ?? i} sx={{ borderLeft: "4px solid #C62828" }}>
                            <TableCell sx={{ color: "text.secondary", width: 40 }}>{i + 1}</TableCell>
                            <TableCell sx={{ fontWeight: 500 }}>{f.title}</TableCell>
                            <TableCell><SevChip severity={f.severity} /></TableCell>
                            <TableCell sx={{ color: "text.secondary", fontSize: "0.8rem" }}>{f.affected_asset ?? "—"}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </Box>
            )}

            {/* Persisting */}
            {tab === 2 && (
              <Box sx={{ p: 2 }}>
                {persisting.length === 0 ? (
                  <Typography color="text.secondary" sx={{ py: 3, textAlign: "center" }}>
                    No persisting findings between these two reports.
                  </Typography>
                ) : (
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ "& th": { fontWeight: 700, color: "text.secondary", fontSize: "0.75rem" } }}>
                          <TableCell>#</TableCell>
                          <TableCell>Finding</TableCell>
                          <TableCell>Severity (A)</TableCell>
                          <TableCell>Severity (B)</TableCell>
                          <TableCell>Change</TableCell>
                          <TableCell>Affected Asset</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {persisting.map((item: any, i: number) => {
                          const fa = item.a ?? {};
                          const fb = item.b ?? {};
                          const rankA = sevRank(fa.severity);
                          const rankB = sevRank(fb.severity);
                          const changed = fa.severity?.toLowerCase() !== fb.severity?.toLowerCase();
                          const worse = rankB < rankA;
                          const better = rankB > rankA;
                          return (
                            <TableRow key={fa.id ?? i} sx={{ borderLeft: "4px solid #E65100" }}>
                              <TableCell sx={{ color: "text.secondary", width: 40 }}>{i + 1}</TableCell>
                              <TableCell sx={{ fontWeight: 500 }}>{fa.title}</TableCell>
                              <TableCell><SevChip severity={fa.severity} /></TableCell>
                              <TableCell><SevChip severity={fb.severity} /></TableCell>
                              <TableCell>
                                {!changed ? (
                                  <Typography variant="caption" color="text.secondary">Unchanged</Typography>
                                ) : worse ? (
                                  <Typography variant="caption" sx={{ color: "#C62828", fontWeight: 700 }}>↑ Worse</Typography>
                                ) : better ? (
                                  <Typography variant="caption" sx={{ color: "#2E7D32", fontWeight: 700 }}>↓ Better</Typography>
                                ) : null}
                              </TableCell>
                              <TableCell sx={{ color: "text.secondary", fontSize: "0.8rem" }}>{fa.affected_asset ?? "—"}</TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </Box>
            )}
          </Paper>
        )}
      </Box>
    </Box>
  );
}
