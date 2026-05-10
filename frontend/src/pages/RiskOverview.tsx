import React, { useEffect, useMemo, useState } from "react";
import { Box, Typography, Grid, Alert, Button, CircularProgress } from "@mui/material";
import { Refresh } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import dayjs from "dayjs";

import { clientsApi, riskOverviewApi } from "../services/api";
import { Client, RiskOverview } from "../types";
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

  const filtered = useMemo(
    () => (raw ? applyClientSideFilters(raw, state) : null),
    [raw, state],
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

      <GlobalFilters clients={clients} options={raw?.filter_options || null} state={state} onChange={setState} />

      {isError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Failed to load risk overview. Try refreshing.
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
