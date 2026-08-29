import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Alert, CircularProgress, Chip,
  Table, TableBody, TableCell, TableHead, TableRow, Select, MenuItem,
  FormControl, InputLabel, Grid,
} from "@mui/material";
import { GpsFixed, CheckCircle, Warning, Error as ErrorIcon } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useActiveClient } from "../contexts/ClientContext";
import { assetsApi, scansApi } from "../services/api";
function differenceInDays(a: Date, b: Date) { return Math.floor((a.getTime() - b.getTime()) / 86400000); }
function fmtDate(d: Date) { return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }); }

const POLICY_DAYS: Record<string, number> = {
  "7": 7, "14": 14, "30": 30, "60": 60, "90": 90,
};

function CoverageStatus({ daysSince, policy }: { daysSince: number | null; policy: number }) {
  if (daysSince === null) {
    return <Chip icon={<ErrorIcon sx={{ fontSize: 14 }} />} label="Never scanned" size="small"
      sx={{ bgcolor: "rgba(234,67,53,0.15)", color: "#EA4335", fontWeight: 700 }} />;
  }
  if (daysSince <= policy) {
    return <Chip icon={<CheckCircle sx={{ fontSize: 14 }} />} label={`${daysSince}d ago`} size="small"
      sx={{ bgcolor: "rgba(52,168,83,0.15)", color: "#34A853", fontWeight: 700 }} />;
  }
  if (daysSince <= policy * 1.5) {
    return <Chip icon={<Warning sx={{ fontSize: 14 }} />} label={`${daysSince}d ago`} size="small"
      sx={{ bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04", fontWeight: 700 }} />;
  }
  return <Chip icon={<ErrorIcon sx={{ fontSize: 14 }} />} label={`${daysSince}d ago`} size="small"
    sx={{ bgcolor: "rgba(234,67,53,0.15)", color: "#EA4335", fontWeight: 700 }} />;
}

export default function ScanCoverage() {
  const { clientId } = useActiveClient();
  const [policy, setPolicy] = useState("30");

  const { data: assets, isLoading: loadA } = useQuery({
    queryKey: ["coverage-assets", clientId],
    queryFn: () => assetsApi.list(clientId, {}),
    enabled: !!clientId,
  });

  const { data: scans, isLoading: loadS } = useQuery({
    queryKey: ["coverage-scans", clientId],
    queryFn: () => scansApi.list(clientId),
    enabled: !!clientId,
  });

  if (!clientId) return <Alert severity="info" sx={{ mt: 2 }}>Select a client to view scan coverage.</Alert>;

  const assetList: any[] = Array.isArray(assets) ? assets : (assets as any)?.items ?? [];
  const scanList: any[] = Array.isArray(scans) ? scans : (scans as any)?.items ?? [];
  const policyDays = POLICY_DAYS[policy] ?? 30;
  const now = new Date();

  // Map asset → last scan date
  const assetLastScan: Record<string, Date | null> = {};
  assetList.forEach(a => { assetLastScan[a.external_id ?? a.id] = null; });
  scanList.forEach((s: any) => {
    if (s.status !== "completed" || !s.completed_at) return;
    const scanDate = new Date(s.completed_at);
    const assetRef = s.asset_id ?? s.resource_id;
    if (assetRef && (assetLastScan[assetRef] === null || scanDate > (assetLastScan[assetRef] as Date))) {
      assetLastScan[assetRef] = scanDate;
    }
  });

  const tableRows = assetList.map(a => {
    const key = a.external_id ?? a.id;
    const lastScan = assetLastScan[key] ?? null;
    const daysSince = lastScan ? differenceInDays(now, lastScan as Date) : null;
    return { ...a, lastScan, daysSince };
  });

  const covered   = tableRows.filter(r => r.daysSince !== null && r.daysSince <= policyDays).length;
  const stale     = tableRows.filter(r => r.daysSince !== null && r.daysSince > policyDays).length;
  const neverScan = tableRows.filter(r => r.daysSince === null).length;
  const total     = tableRows.length;
  const pct       = total > 0 ? Math.round((covered / total) * 100) : 0;

  const isLoading = loadA || loadS;

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>Scan Coverage</Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
          Assets not scanned within the policy window — identify coverage gaps.
        </Typography>
      </Box>

      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
        <FormControl size="small" sx={{ minWidth: 160 }}>
          <InputLabel>Policy Window</InputLabel>
          <Select value={policy} label="Policy Window" onChange={e => setPolicy(e.target.value as string)}>
            {Object.keys(POLICY_DAYS).map(d => (
              <MenuItem key={d} value={d}>Every {d} days</MenuItem>
            ))}
          </Select>
        </FormControl>
        {!isLoading && (
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            {covered}/{total} assets within policy ({pct}%)
          </Typography>
        )}
      </Box>

      {isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", pt: 6 }}><CircularProgress /></Box>
      ) : (
        <>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { label: "Total Assets",    value: total,     color: "#4285F4" },
              { label: "Covered",         value: covered,   color: "#34A853" },
              { label: "Stale",           value: stale,     color: "#FBBC04" },
              { label: "Never Scanned",   value: neverScan, color: "#EA4335" },
            ].map(({ label, value, color }) => (
              <Grid key={label} size={{ xs: 6, md: 3 }}>
                <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
                  <CardContent sx={{ textAlign: "center" }}>
                    <Typography variant="h4" sx={{ fontWeight: 800, color }}>{value}</Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>{label}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
            <CardContent sx={{ p: 0 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { fontWeight: 700, fontSize: 12, bgcolor: "rgba(255,255,255,0.03)", color: "text.secondary", borderBottom: "1px solid rgba(255,255,255,0.1)" } }}>
                    <TableCell>Asset Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Platform</TableCell>
                    <TableCell>Last Scan</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {tableRows.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} sx={{ textAlign: "center", py: 4, color: "text.secondary" }}>
                        No assets found. Run a scanner to populate this view.
                      </TableCell>
                    </TableRow>
                  ) : (
                    tableRows.map((row: any) => (
                      <TableRow key={row.id} sx={{ "&:hover": { bgcolor: "rgba(255,255,255,0.03)" } }}>
                        <TableCell sx={{ fontSize: 13, fontWeight: 600 }}>{row.name || row.external_id || row.id}</TableCell>
                        <TableCell sx={{ fontSize: 12, color: "text.secondary", textTransform: "capitalize" }}>{row.asset_type || "—"}</TableCell>
                        <TableCell sx={{ fontSize: 12, color: "text.secondary" }}>{row.platform || "—"}</TableCell>
                        <TableCell sx={{ fontSize: 12, color: "text.secondary" }}>
                          {row.lastScan ? fmtDate(row.lastScan as Date) : "—"}
                        </TableCell>
                        <TableCell><CoverageStatus daysSince={row.daysSince} policy={policyDays} /></TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </>
      )}
    </Box>
  );
}
