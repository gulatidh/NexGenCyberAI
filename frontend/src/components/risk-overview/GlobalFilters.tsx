import React from "react";
import {
  Box, FormControl, InputLabel, Select, MenuItem, Chip, Stack,
} from "@mui/material";
import { Client, RiskOverviewFilters } from "../../types";
import { FRAMEWORK_LABEL } from "./tokens";

export interface GlobalFilterState {
  clientId: string;
  days: number;
  severity: string;
  framework: string;
  project: string;
  environment: string;
  cloud: string;
  status: string;
}

interface Props {
  clients: Client[];
  options: RiskOverviewFilters | null;
  state: GlobalFilterState;
  onChange: (s: GlobalFilterState) => void;
}

const RANGE_OPTIONS = [
  { label: "7 days", value: 7 },
  { label: "30 days", value: 30 },
  { label: "60 days", value: 60 },
  { label: "90 days", value: 90 },
];

const SEV_OPTIONS = ["", "critical", "high", "medium", "low", "info"];

export default function GlobalFilters({ clients, options, state, onChange }: Props) {
  const update = (patch: Partial<GlobalFilterState>) => onChange({ ...state, ...patch });

  const filterSx = {
    minWidth: 130,
    "& .MuiOutlinedInput-root": { color: "white", fontSize: 13, "& fieldset": { borderColor: "rgba(255,255,255,0.15)" } },
    "& .MuiInputLabel-root": { color: "rgba(255,255,255,0.5)" },
  };

  return (
    <Box sx={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 1.5, mb: 2.5 }}>
      <FormControl size="small" sx={{ ...filterSx, minWidth: 200 }}>
        <InputLabel>Client</InputLabel>
        <Select label="Client" value={state.clientId} onChange={(e) => update({ clientId: e.target.value })}>
          {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
        </Select>
      </FormControl>
      <FormControl size="small" sx={filterSx}>
        <InputLabel>Date range</InputLabel>
        <Select label="Date range" value={state.days} onChange={(e) => update({ days: Number(e.target.value) })}>
          {RANGE_OPTIONS.map((r) => <MenuItem key={r.value} value={r.value}>{r.label}</MenuItem>)}
        </Select>
      </FormControl>
      <FormControl size="small" sx={filterSx}>
        <InputLabel>Severity</InputLabel>
        <Select label="Severity" value={state.severity} onChange={(e) => update({ severity: e.target.value })}>
          {SEV_OPTIONS.map((s) => <MenuItem key={s || "all"} value={s}>{s ? s[0].toUpperCase() + s.slice(1) : "All"}</MenuItem>)}
        </Select>
      </FormControl>
      <FormControl size="small" sx={filterSx} disabled={!options?.frameworks?.length}>
        <InputLabel>Framework</InputLabel>
        <Select label="Framework" value={state.framework} onChange={(e) => update({ framework: e.target.value })}>
          <MenuItem value="">All</MenuItem>
          {(options?.frameworks || []).map((f) => (
            <MenuItem key={f} value={f}>{FRAMEWORK_LABEL[f] || f}</MenuItem>
          ))}
        </Select>
      </FormControl>
      <FormControl size="small" sx={filterSx} disabled={!options?.projects?.length}>
        <InputLabel>Project</InputLabel>
        <Select label="Project" value={state.project} onChange={(e) => update({ project: e.target.value })}>
          <MenuItem value="">All</MenuItem>
          {(options?.projects || []).map((p) => <MenuItem key={p} value={p}>{p}</MenuItem>)}
        </Select>
      </FormControl>
      <FormControl size="small" sx={filterSx}>
        <InputLabel>Environment</InputLabel>
        <Select label="Environment" value={state.environment} onChange={(e) => update({ environment: e.target.value })}>
          <MenuItem value="">All</MenuItem>
          {(options?.environments || []).map((e) => <MenuItem key={e} value={e}>{e}</MenuItem>)}
        </Select>
      </FormControl>
      <FormControl size="small" sx={filterSx}>
        <InputLabel>Cloud</InputLabel>
        <Select label="Cloud" value={state.cloud} onChange={(e) => update({ cloud: e.target.value })}>
          <MenuItem value="">All</MenuItem>
          {(options?.cloud_providers || []).map((c) => <MenuItem key={c} value={c}>{c.toUpperCase()}</MenuItem>)}
        </Select>
      </FormControl>
      <FormControl size="small" sx={filterSx}>
        <InputLabel>Status</InputLabel>
        <Select label="Status" value={state.status} onChange={(e) => update({ status: e.target.value })}>
          <MenuItem value="">All</MenuItem>
          {(options?.statuses || []).map((s) => <MenuItem key={s} value={s}>{s.replace("_", " ")}</MenuItem>)}
        </Select>
      </FormControl>
      <Box sx={{ flex: 1 }} />
      {Object.entries({ severity: state.severity, framework: state.framework, project: state.project, environment: state.environment, cloud: state.cloud, status: state.status })
        .filter(([_, v]) => v).length > 0 && (
        <Stack direction="row" spacing={0.5}>
          <Chip size="small" label="Clear filters" onClick={() => onChange({ ...state, severity: "", framework: "", project: "", environment: "", cloud: "", status: "" })}
            sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", cursor: "pointer" }} />
        </Stack>
      )}
    </Box>
  );
}
