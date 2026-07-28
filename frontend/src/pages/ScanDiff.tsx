import React, { useState } from "react";
import { useParams, useSearchParams, useNavigate, useLocation } from "react-router-dom";
import { useActiveClient } from "../contexts/ClientContext";
import {
  Box,
  Typography,
  Button,
  Chip,
  CircularProgress,
  Tabs,
  Tab,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  Stack,
  Alert,
} from "@mui/material";
import { ArrowBack } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../services/api";

// ── Severity chip color map ───────────────────────────────────────────────────
const SEV_COLOR: Record<string, "error" | "warning" | "info" | "default"> = {
  critical: "error",
  high: "warning",
  medium: "info",
  low: "default",
  info: "default",
};

// ── Types ─────────────────────────────────────────────────────────────────────
interface DiffFinding {
  id: string;
  title: string;
  severity: string;
  resource_id?: string;
  resource_type?: string;
  control_id?: string;
  description?: string;
}

interface ScanDiffResponse {
  scan_id: string;
  base_scan_id: string;
  scan_completed_at?: string;
  base_scan_completed_at?: string;
  summary: {
    new: number;
    resolved: number;
    persisting: number;
    total_current: number;
    total_base: number;
  };
  new_findings: DiffFinding[];
  resolved_findings: DiffFinding[];
  persisting_findings: DiffFinding[];
}

// ── Finding table ─────────────────────────────────────────────────────────────
function FindingsTable({ findings }: { findings: DiffFinding[] }) {
  if (findings.length === 0) {
    return (
      <Box sx={{ p: 4, textAlign: "center", color: "text.secondary" }}>
        No findings in this category.
      </Box>
    );
  }
  return (
    <Table size="small">
      <TableHead>
        <TableRow
          sx={{
            "& th": {
              borderColor: "divider",
              color: "text.secondary",
              fontSize: 11,
              fontWeight: 600,
            },
          }}
        >
          <TableCell sx={{ width: 100 }}>Severity</TableCell>
          <TableCell>Title</TableCell>
          <TableCell>Resource</TableCell>
          <TableCell>Control ID</TableCell>
        </TableRow>
      </TableHead>
      <TableBody>
        {findings.map((f) => (
          <TableRow
            key={f.id}
            hover
            sx={{ "& td": { borderColor: "divider", color: "text.primary", fontSize: 12 } }}
          >
            <TableCell>
              <Chip
                label={f.severity}
                size="small"
                color={SEV_COLOR[f.severity] ?? "default"}
                sx={{ fontSize: 10, height: 20, fontWeight: 700, textTransform: "uppercase" }}
              />
            </TableCell>
            <TableCell sx={{ maxWidth: 360 }}>
              <Typography variant="caption" sx={{ display: "block", fontWeight: 600 }}>
                {f.title}
              </Typography>
              {f.description && (
                <Typography
                  variant="caption"
                  sx={{ color: "text.secondary", display: "block", mt: 0.25 }}
                >
                  {f.description.slice(0, 120)}
                  {f.description.length > 120 ? "…" : ""}
                </Typography>
              )}
            </TableCell>
            <TableCell>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {f.resource_id || "—"}
              </Typography>
            </TableCell>
            <TableCell>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {f.control_id || "—"}
              </Typography>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function ScanDiff() {
  const { scanId } = useParams<{ scanId: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();
  const scansBase = location.pathname.startsWith("/vulnerability") ? "/vulnerability/scans" : "/scans";
  const { clientId } = useActiveClient();
  const [tab, setTab] = useState(0);

  const baseParam = searchParams.get("base") || undefined;

  const { data, isLoading, error } = useQuery<ScanDiffResponse>({
    queryKey: ["scan-diff", clientId, scanId, baseParam],
    queryFn: () =>
      apiClient
        .get(`/clients/${clientId}/scans/${scanId}/diff`, {
          params: baseParam ? { compare_with: baseParam } : {},
        })
        .then((r) => r.data),
    enabled: !!clientId && !!scanId,
    retry: false,
  });

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 3 }}>
        <Button
          variant="text"
          startIcon={<ArrowBack />}
          onClick={() => navigate(scansBase)}
          sx={{ color: "text.secondary", textTransform: "none" }}
        >
          Back to Scans
        </Button>
        <Box sx={{ flex: 1 }}>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>
            Scan Delta Comparison
          </Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            New, resolved, and persisting findings between two scan runs
          </Typography>
        </Box>
      </Box>

      {/* Loading */}
      {isLoading && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
          <CircularProgress sx={{ color: "#4285F4" }} />
        </Box>
      )}

      {/* Error */}
      {!isLoading && error && (
        <Alert
          severity="error"
          sx={{ mt: 2, bgcolor: "rgba(234,67,53,0.08)", color: "text.primary", border: "1px solid rgba(234,67,53,0.3)" }}
        >
          {(error as any)?.response?.data?.detail ||
            "Failed to load diff. Make sure this scan has a parent scan to compare against, or provide a ?base= query param."}
        </Alert>
      )}

      {/* Main content */}
      {!isLoading && data && (
        <>
          {/* Summary chips */}
          <Stack direction="row" spacing={1.5} sx={{ mb: 3, flexWrap: "wrap" }}>
            <Chip
              label={`▲ ${data.summary.new} new finding${data.summary.new !== 1 ? "s" : ""}`}
              sx={{
                bgcolor: "rgba(234,67,53,0.15)",
                color: "#EA4335",
                fontWeight: 700,
                fontSize: 13,
                height: 30,
              }}
            />
            <Chip
              label={`✓ ${data.summary.resolved} resolved`}
              sx={{
                bgcolor: "rgba(52,168,83,0.15)",
                color: "#34A853",
                fontWeight: 700,
                fontSize: 13,
                height: 30,
              }}
            />
            <Chip
              label={`→ ${data.summary.persisting} persisting`}
              sx={{
                bgcolor: "rgba(255,255,255,0.06)",
                color: "text.secondary",
                fontWeight: 700,
                fontSize: 13,
                height: 30,
              }}
            />
            <Box sx={{ flex: 1 }} />
            <Typography variant="caption" sx={{ color: "text.secondary", alignSelf: "center" }}>
              Current scan: {data.summary.total_current} findings &nbsp;·&nbsp; Base scan:{" "}
              {data.summary.total_base} findings
            </Typography>
          </Stack>

          {/* Scan date metadata */}
          {(data.scan_completed_at || data.base_scan_completed_at) && (
            <Box sx={{ mb: 2, display: "flex", gap: 3 }}>
              {data.scan_completed_at && (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  <b>Current scan</b>:{" "}
                  {new Date(data.scan_completed_at).toLocaleString()}
                </Typography>
              )}
              {data.base_scan_completed_at && (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                  <b>Base scan</b>:{" "}
                  {new Date(data.base_scan_completed_at).toLocaleString()}
                </Typography>
              )}
            </Box>
          )}

          {/* Tabs */}
          <Tabs
            value={tab}
            onChange={(_, v) => setTab(v)}
            sx={{
              borderBottom: "1px solid rgba(255,255,255,0.08)",
              mb: 0,
              "& .MuiTab-root": {
                color: "text.secondary",
                textTransform: "none",
                fontWeight: 600,
                minHeight: 44,
              },
              "& .Mui-selected": { color: "text.primary" },
              "& .MuiTabs-indicator": { backgroundColor: "#4285F4" },
            }}
          >
            <Tab label={`New (${data.summary.new})`} />
            <Tab label={`Resolved (${data.summary.resolved})`} />
            <Tab label={`Persisting (${data.summary.persisting})`} />
          </Tabs>

          <Box
            sx={{
              border: "1px solid rgba(255,255,255,0.08)",
              borderTop: "none",
              borderRadius: "0 0 8px 8px",
              overflow: "hidden",
            }}
          >
            {tab === 0 && <FindingsTable findings={data.new_findings} />}
            {tab === 1 && <FindingsTable findings={data.resolved_findings} />}
            {tab === 2 && <FindingsTable findings={data.persisting_findings} />}
          </Box>
        </>
      )}
    </Box>
  );
}
