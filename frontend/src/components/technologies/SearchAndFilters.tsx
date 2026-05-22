import React, { useState } from "react";
import {
  Box, TextField, InputAdornment, Chip, IconButton, Tooltip, FormControl, InputLabel,
  Select, MenuItem, Collapse, Button,
} from "@mui/material";
import {
  Search, FilterList, Warning, Error, BlockOutlined, CheckCircleOutlined, AllInclusive,
} from "@mui/icons-material";
import type { TechStatus, TechnologyFilters } from "../../types";
import { STATUS_COLOR } from "./tokens";

export interface FilterState {
  search: string;
  status: TechStatus | "";
  category: string;
  type: string;
  cloud: string;
  account: string;
  region: string;
  owner: string;
  environment: string;
}

interface Props {
  state: FilterState;
  options: TechnologyFilters | null;
  onChange: (s: FilterState) => void;
}

const STATUS_PILLS: Array<{ key: TechStatus | ""; label: string; icon: React.ReactNode }> = [
  { key: "",         label: "All",      icon: <AllInclusive sx={{ fontSize: 14 }} /> },
  { key: "healthy",  label: "Healthy",  icon: <CheckCircleOutlined sx={{ fontSize: 14 }} /> },
  { key: "warning",  label: "Warning",  icon: <Warning sx={{ fontSize: 14 }} /> },
  { key: "critical", label: "Critical", icon: <Error sx={{ fontSize: 14 }} /> },
  { key: "ignored",  label: "Ignored",  icon: <BlockOutlined sx={{ fontSize: 14 }} /> },
];

export default function SearchAndFilters({ state, options, onChange }: Props) {
  const [advanced, setAdvanced] = useState(false);
  const update = (patch: Partial<FilterState>) => onChange({ ...state, ...patch });

  const inputSx = {
    "& .MuiOutlinedInput-root": { color: "white", "& fieldset": { borderColor: "rgba(255,255,255,0.15)" } },
    "& input::placeholder": { color: "rgba(255,255,255,0.4)" },
    "& .MuiInputLabel-root": { color: "rgba(255,255,255,0.5)" },
  };
  const filterSx = {
    minWidth: 140,
    "& .MuiOutlinedInput-root": { color: "white", fontSize: 13, "& fieldset": { borderColor: "rgba(255,255,255,0.15)" } },
    "& .MuiInputLabel-root": { color: "rgba(255,255,255,0.5)" },
  };

  return (
    <Box sx={{ mb: 2 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5, flexWrap: "wrap" }}>
        <TextField
          size="small"
          placeholder="Search technologies"
          value={state.search}
          onChange={(e) => update({ search: e.target.value })}
          sx={{ flex: 1, minWidth: 240, ...inputSx }}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <Search sx={{ color: "rgba(255,255,255,0.4)", fontSize: 18 }} />
                </InputAdornment>
              ),
            },
          }}
        />
        {STATUS_PILLS.map((p) => (
          <Tooltip key={p.key || "all"} title={p.label}>
            <Chip
              icon={p.icon as any}
              label={p.label}
              size="small"
              clickable
              onClick={() => update({ status: state.status === p.key ? "" : p.key as any })}
              sx={{
                bgcolor: state.status === p.key
                  ? `${p.key ? STATUS_COLOR[p.key] : "#A100FF"}30`
                  : "rgba(255,255,255,0.04)",
                color: p.key ? STATUS_COLOR[p.key] : "#A100FF",
                border: state.status === p.key
                  ? `1px solid ${p.key ? STATUS_COLOR[p.key] : "#A100FF"}`
                  : "1px solid transparent",
                fontWeight: 600, fontSize: 11,
              }}
            />
          </Tooltip>
        ))}
        <IconButton onClick={() => setAdvanced((v) => !v)} sx={{ color: advanced ? "#A100FF" : "rgba(255,255,255,0.5)" }}>
          <FilterList />
        </IconButton>
      </Box>

      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
        <FormControl size="small" sx={filterSx}>
          <InputLabel>Category</InputLabel>
          <Select label="Category" value={state.category} onChange={(e) => update({ category: e.target.value })}>
            <MenuItem value="">All</MenuItem>
            {(options?.categories || []).map((v) => <MenuItem key={v} value={v}>{v}</MenuItem>)}
          </Select>
        </FormControl>
        <FormControl size="small" sx={filterSx}>
          <InputLabel>Type</InputLabel>
          <Select label="Type" value={state.type} onChange={(e) => update({ type: e.target.value })}>
            <MenuItem value="">All</MenuItem>
            {(options?.types || []).map((v) => <MenuItem key={v} value={v}>{v}</MenuItem>)}
          </Select>
        </FormControl>
        <FormControl size="small" sx={filterSx}>
          <InputLabel>Environment</InputLabel>
          <Select label="Environment" value={state.environment} onChange={(e) => update({ environment: e.target.value })}>
            <MenuItem value="">All</MenuItem>
            {(options?.environments || []).map((v) => <MenuItem key={v} value={v}>{v}</MenuItem>)}
          </Select>
        </FormControl>
        <FormControl size="small" sx={filterSx}>
          <InputLabel>Cloud</InputLabel>
          <Select label="Cloud" value={state.cloud} onChange={(e) => update({ cloud: e.target.value })}>
            <MenuItem value="">All</MenuItem>
            {(options?.cloud_providers || []).map((v) => <MenuItem key={v} value={v}>{v.toUpperCase()}</MenuItem>)}
          </Select>
        </FormControl>
        <Button size="small" onClick={() => setAdvanced((v) => !v)}
          sx={{ color: "rgba(255,255,255,0.6)", fontSize: 12 }}>
          {advanced ? "Hide" : "More filters"}
        </Button>
      </Box>

      <Collapse in={advanced} timeout="auto" unmountOnExit>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 1.5 }}>
          <FormControl size="small" sx={filterSx}>
            <InputLabel>Account / Subscription</InputLabel>
            <Select label="Account / Subscription" value={state.account}
              onChange={(e) => update({ account: e.target.value })}>
              <MenuItem value="">All</MenuItem>
              {(options?.subscriptions || []).map((v) => <MenuItem key={v} value={v}>{v}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={filterSx}>
            <InputLabel>Region</InputLabel>
            <Select label="Region" value={state.region} onChange={(e) => update({ region: e.target.value })}>
              <MenuItem value="">All</MenuItem>
              {(options?.regions || []).map((v) => <MenuItem key={v} value={v}>{v}</MenuItem>)}
            </Select>
          </FormControl>
          <FormControl size="small" sx={filterSx}>
            <InputLabel>Owner Team</InputLabel>
            <Select label="Owner Team" value={state.owner} onChange={(e) => update({ owner: e.target.value })}>
              <MenuItem value="">All</MenuItem>
              {(options?.owners || []).map((v) => <MenuItem key={v} value={v}>{v}</MenuItem>)}
            </Select>
          </FormControl>
        </Box>
      </Collapse>
    </Box>
  );
}
