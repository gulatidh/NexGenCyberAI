import React, { useEffect, useMemo, useState } from "react";
import { Box, Typography, Grid, Alert, Button, CircularProgress } from "@mui/material";
import { Refresh } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import dayjs from "dayjs";

import { clientsApi, riskOverviewApi } from "../services/api";
import { Client, RiskOverview, Severity } from "../types";
import GlobalFilters, { GlobalFilterState } from "../components/risk-overview/GlobalFilters";
import ComplianceOverview from "../components/risk-overview/ComplianceOverview";
import OpenIssuesSummary from "../components/risk-overview/OpenIssuesSummary";
import IssuesTrendChart from "../components/risk-overview/IssuesTrendChart";
import AverageIssueAge from "../components/risk-overview/AverageIssueAge";
import SecurityScoreWidget from "../components/risk-overview/SecurityScoreWidget";
import TopIssuesTable from "../components/risk-overview/TopIssuesTable";
import OpenedVsResolvedChart from "../components/risk-overview/OpenedVsResolvedChart";
import ProjectsTable from "../components/risk-overview/ProjectsTable";
import ServicesTable from "../components/risk-overview/ServicesTable";

// Mock fallback — used when backend is unreachable or the client has no data
// yet. Lets the dashboard render fully so layout/styling is reviewable from
// day one, before scans have populated real signal.
const MOCK: RiskOverview = {
  compliance: [
    { framework: "cis_azure", score: 76.4, total: 134, compliant: 78, non_compliant: 12, partial: 4, not_applicable: 40 },
    { framework: "nist_csf", score: 88.2, total: 185, compliant: 142, non_compliant: 8, partial: 3, not_applicable: 32 },
    { framework: "cis_v8", score: 64.1, total: 153, compliant: 67, non_compliant: 22, partial: 6, not_applicable: 58 },
    { framework: "nist_800_53", score: 72.0, total: 322, compliant: 180, non_compliant: 24, partial: 8, not_applicable: 110 },
    { framework: "iso_27001", score: 81.5, total: 114, compliant: 78, non_compliant: 6, partial: 2, not_applicable: 28 },
  ],
  open_issues: { critical: 4, high: 18, medium: 47, low: 22, info: 0, deltas: { critical: 33.3, high: -5.6, medium: 12.0, low: 0.0 } },
  severity_trend: Array.from({ length: 30 }, (_, i) => ({
    date: dayjs().subtract(29 - i, "day").format("YYYY-MM-DD"),
    critical: Math.max(0, Math.round(Math.sin(i / 4) * 2 + 2)),
    high: Math.max(0, Math.round(Math.cos(i / 5) * 4 + 6)),
    medium: Math.max(0, Math.round(Math.sin(i / 3) * 5 + 10)),
    low: Math.max(0, Math.round(Math.cos(i / 6) * 3 + 5)),
    info: 0,
  })),
  avg_age: { critical: 12, high: 22, medium: 41, low: 78, sla: { critical: 7, high: 30, medium: 60, low: 90 } },
  security_score: {
    current: 78.4, prev_7d: 76.1, delta: 2.3,
    history: Array.from({ length: 30 }, (_, i) => ({
      date: dayjs().subtract(29 - i, "day").format("YYYY-MM-DD"),
      score: Math.round((75 + Math.sin(i / 4) * 4 + i * 0.1) * 10) / 10,
    })),
  },
  top_issues: [
    { title: "Storage account allows unencrypted HTTP traffic", severity: "high" as Severity, framework: "cis_azure", count: 8, affected_resources: 3 },
    { title: "NSG allows unrestricted inbound RDP (port 3389)", severity: "critical" as Severity, framework: "cis_azure", count: 4, affected_resources: 2 },
    { title: "Key Vault has soft delete disabled", severity: "medium" as Severity, framework: "cis_azure", count: 6, affected_resources: 6 },
    { title: "Subscription has 12 Owner role assignments", severity: "high" as Severity, framework: "cis_azure", count: 1, affected_resources: 1 },
    { title: "VM OS disk is not encrypted with ADE", severity: "high" as Severity, framework: "cis_azure", count: 9, affected_resources: 9 },
  ],
  issues_flow: Array.from({ length: 30 }, (_, i) => ({
    date: dayjs().subtract(29 - i, "day").format("YYYY-MM-DD"),
    opened: Math.max(0, Math.round(Math.sin(i / 4) * 6 + 10)),
    resolved: Math.max(0, Math.round(Math.cos(i / 4) * 5 + 8)),
  })),
  projects: [
    { name: "prod-payments-sub", asset_count: 42, issues: 28, critical: 2, high: 8, medium: 12, low: 6, environment: "production" },
    { name: "staging-platform-sub", asset_count: 31, issues: 14, critical: 0, high: 3, medium: 7, low: 4, environment: "non-production" },
    { name: "dev-data-sub", asset_count: 18, issues: 9, critical: 1, high: 2, medium: 4, low: 2, environment: "non-production" },
  ],
  services: [
    { name: "vm", owner: "platform-team", asset_count: 24, issues: 18, critical: 1, high: 6, risk_level: "critical" },
    { name: "storage", owner: "data-team", asset_count: 12, issues: 14, critical: 1, high: 4, risk_level: "critical" },
    { name: "network", owner: "platform-team", asset_count: 8, issues: 9, critical: 1, high: 3, risk_level: "critical" },
    { name: "keyvault", owner: "security-team", asset_count: 5, issues: 6, critical: 0, high: 1, risk_level: "medium" },
    { name: "identity", owner: "iam-team", asset_count: 47, issues: 4, critical: 0, high: 1, risk_level: "low" },
  ],
  filter_options: {
    projects: ["prod-payments-sub", "staging-platform-sub", "dev-data-sub"],
    environments: ["production", "staging", "development", "non-production"],
    cloud_providers: ["azure"],
    frameworks: ["cis_azure", "cis_v8", "nist_csf", "nist_800_53", "iso_27001"],
    statuses: ["open", "remediated", "accepted", "false_positive"],
  },
  as_of: dayjs().toISOString(),
};


function applyClientSideFilters(data: RiskOverview, state: GlobalFilterState): RiskOverview {
  // Most filters are sent to the backend; for the ones we can apply locally
  // (severity, environment), narrow the visible cards/tables here so the UI is
  // responsive without re-fetching.
  let next = { ...data };

  if (state.severity) {
    next = {
      ...next,
      top_issues: data.top_issues.filter((i) => i.severity === state.severity),
    };
  }
  if (state.environment) {
    next = {
      ...next,
      projects: data.projects.filter((p) => p.environment === state.environment),
    };
  }
  if (state.framework) {
    next = {
      ...next,
      compliance: data.compliance.filter((c) => c.framework === state.framework),
      top_issues: next.top_issues.filter((i) => !i.framework || i.framework === state.framework),
    };
  }

  return next;
}


export default function RiskOverviewPage() {
  const navigate = useNavigate();
  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });

  const [state, setState] = useState<GlobalFilterState>({
    clientId: "",
    days: 30,
    severity: "",
    framework: "",
    project: "",
    environment: "",
    cloud: "",
    status: "",
  });

  // Auto-pick first client on initial load
  useEffect(() => {
    if (!state.clientId && clients.length > 0) {
      setState((s) => ({ ...s, clientId: clients[0].id }));
    }
  }, [clients, state.clientId]);

  const { data: raw, isLoading, isError, refetch, isFetching } = useQuery<RiskOverview>({
    queryKey: ["risk-overview", state.clientId, state.days],
    queryFn: () => riskOverviewApi.get(state.clientId, state.days),
    enabled: !!state.clientId,
  });

  const usingMock = !raw && !isLoading;
  const sourceData = raw || (state.clientId ? MOCK : null);
  const filtered = useMemo(
    () => (sourceData ? applyClientSideFilters(sourceData, state) : null),
    [sourceData, state],
  );

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2.5, flexWrap: "wrap", gap: 1 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Risk Overview</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            Posture, compliance, and remediation across your environment
          </Typography>
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          {filtered?.as_of && (
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>
              as of {dayjs(filtered.as_of).format("MMM D, HH:mm")}
            </Typography>
          )}
          <Button size="small" startIcon={isFetching ? <CircularProgress size={14} sx={{ color: "white" }} /> : <Refresh />}
            onClick={() => refetch()} disabled={isFetching}
            sx={{ color: "rgba(255,255,255,0.7)", borderColor: "rgba(255,255,255,0.2)" }}
            variant="outlined">
            Refresh
          </Button>
        </Box>
      </Box>

      <GlobalFilters clients={clients} options={sourceData?.filter_options || null} state={state} onChange={setState} />

      {isError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Failed to load risk overview. Showing mock data so the layout remains visible.
        </Alert>
      )}
      {usingMock && state.clientId && (
        <Alert severity="info" sx={{ mb: 2, bgcolor: "rgba(0,229,255,0.06)", color: "white", borderColor: "rgba(0,229,255,0.2)" }}>
          Showing sample data. Run a scan to populate live values.
        </Alert>
      )}
      {!state.clientId && clients.length === 0 && !isLoading && (
        <Alert severity="info" sx={{ mb: 2 }}>
          No clients yet. Create one in the Clients page to get started.
        </Alert>
      )}

      {/* Top row: compliance scroller + security score */}
      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <ComplianceOverview data={filtered?.compliance || []} loading={isLoading}
            onClick={(fw) => navigate(`/frameworks?framework=${fw}`)} />
        </Grid>
        <Grid size={{ xs: 12, lg: 4 }}>
          <SecurityScoreWidget data={filtered?.security_score} loading={isLoading} />
        </Grid>
      </Grid>

      {/* Severity summary */}
      <Box sx={{ mb: 2 }}>
        <OpenIssuesSummary data={filtered?.open_issues} loading={isLoading} />
      </Box>

      {/* Trend charts */}
      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <IssuesTrendChart data={filtered?.severity_trend || []} loading={isLoading} />
        </Grid>
        <Grid size={{ xs: 12, lg: 4 }}>
          <AverageIssueAge data={filtered?.avg_age} loading={isLoading} />
        </Grid>
      </Grid>

      {/* Top issues + flow */}
      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 12, lg: 7 }}>
          <TopIssuesTable data={filtered?.top_issues || []} loading={isLoading} />
        </Grid>
        <Grid size={{ xs: 12, lg: 5 }}>
          <OpenedVsResolvedChart data={filtered?.issues_flow || []} loading={isLoading} />
        </Grid>
      </Grid>

      {/* Projects + services */}
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, lg: 6 }}>
          <ProjectsTable data={filtered?.projects || []} loading={isLoading} />
        </Grid>
        <Grid size={{ xs: 12, lg: 6 }}>
          <ServicesTable data={filtered?.services || []} loading={isLoading} />
        </Grid>
      </Grid>
    </Box>
  );
}
