import React, { useEffect, useMemo, useState } from "react";
import { Box, Typography, Grid, FormControl, InputLabel, Select, MenuItem, Alert, Button, CircularProgress } from "@mui/material";
import { Refresh } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { fmt } from "../utils/datetime";

import { clientsApi, projectsApi, technologiesApi } from "../services/api";
import { Client, Project, TechnologyInventory, TechnologyRow } from "../types";

import SearchAndFilters, { FilterState } from "../components/technologies/SearchAndFilters";
import BreakdownByCategory from "../components/technologies/BreakdownByCategory";
import BreakdownBySubcategory from "../components/technologies/BreakdownBySubcategory";
import BreakdownByType from "../components/technologies/BreakdownByType";
import TechnologyTable from "../components/technologies/TechnologyTable";
import TechnologyDetailDrawer from "../components/technologies/TechnologyDetailDrawer";

const EMPTY_FILTERS: FilterState = {
  search: "", status: "", category: "", type: "",
  cloud: "", account: "", region: "", owner: "", environment: "",
};

export default function Technologies() {
  const [clientId, setClientId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [filters, setFilters] = useState<FilterState>(EMPTY_FILTERS);
  const [selected, setSelected] = useState<TechnologyRow | null>(null);

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", clientId],
    queryFn: () => projectsApi.list(clientId),
    enabled: !!clientId,
  });

  // Auto-pick first client
  useEffect(() => {
    if (!clientId && clients.length > 0) setClientId(clients[0].id);
  }, [clients, clientId]);

  const { data: inventory, isLoading, isFetching, refetch, isError, error } = useQuery<TechnologyInventory>({
    queryKey: ["technology-inventory", clientId, projectId, filters.category, filters.type, filters.status, filters.search],
    queryFn: () => technologiesApi.inventory(clientId, {
      project_id: projectId || undefined,
      category: filters.category || undefined,
      type: filters.type || undefined,
      status: filters.status || undefined,
      search: filters.search || undefined,
    }),
    enabled: !!clientId,
  });

  // Apply remaining client-side filters that the backend doesn't support yet
  const filteredTechnologies = useMemo(() => {
    if (!inventory) return [];
    return inventory.technologies.filter((t) => {
      if (filters.environment && !t.environments.includes(filters.environment)) return false;
      if (filters.region && !t.regions.includes(filters.region)) return false;
      if (filters.account && !t.subscriptions.includes(filters.account)) return false;
      if (filters.owner && t.owner !== filters.owner) return false;
      return true;
    });
  }, [inventory, filters]);

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 2.5, flexWrap: "wrap", gap: 1 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Technology Inventory</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            Discover, classify, and assess technologies running across your environment
          </Typography>
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
            <Select value={clientId} onChange={(e) => { setClientId(e.target.value); setProjectId(""); }} label="Client"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 160 }} disabled={!clientId}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Project</InputLabel>
            <Select value={projectId} onChange={(e) => setProjectId(e.target.value)} label="Project"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All projects</MenuItem>
              {projects.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
            </Select>
          </FormControl>
          {inventory?.as_of && (
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>
              as of {fmt(inventory.as_of, "MMM D, HH:mm")}
            </Typography>
          )}
          <Button size="small" startIcon={isFetching ? <CircularProgress size={14} sx={{ color: "white" }} /> : <Refresh />}
            onClick={() => refetch()} disabled={isFetching}
            sx={{ color: "rgba(255,255,255,0.7)", borderColor: "rgba(255,255,255,0.2)" }} variant="outlined">
            Refresh
          </Button>
        </Box>
      </Box>

      <SearchAndFilters state={filters} options={inventory?.filter_options || null} onChange={setFilters} />

      {/* Total + status counts */}
      <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2, alignItems: "center", gap: 2 }}>
        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
          {filteredTechnologies.length} of {inventory?.summary.total ?? 0} technologies
        </Typography>
      </Box>

      {isError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {(error as any)?.response?.data?.detail || "Failed to load technology inventory."}
        </Alert>
      )}

      {!clientId && clients.length === 0 && !isLoading && (
        <Alert severity="info" sx={{ mb: 2 }}>
          No clients yet. Create one in the Clients page first.
        </Alert>
      )}

      {/* Breakdown widgets */}
      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 12, md: 4 }}>
          <BreakdownByCategory data={inventory?.categories || []} loading={isLoading}
            selected={filters.category}
            onSelect={(name) => setFilters({ ...filters, category: name })} />
        </Grid>
        <Grid size={{ xs: 12, md: 4 }}>
          <BreakdownBySubcategory data={inventory?.subcategories || []} loading={isLoading} />
        </Grid>
        <Grid size={{ xs: 12, md: 4 }}>
          <BreakdownByType data={inventory?.types || []} loading={isLoading}
            selected={filters.type}
            onSelect={(name) => setFilters({ ...filters, type: name })} />
        </Grid>
      </Grid>

      <TechnologyTable
        data={filteredTechnologies}
        loading={isLoading}
        onRowClick={(row) => setSelected(row)}
      />

      <TechnologyDetailDrawer
        clientId={clientId}
        technologyName={selected?.name || null}
        onClose={() => setSelected(null)}
      />
    </Box>
  );
}
