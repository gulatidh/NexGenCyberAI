import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Chip, CircularProgress, Grid,
  Table, TableHead, TableRow, TableCell, TableBody, TableContainer, TableSortLabel,
  FormControl, InputLabel, Select, MenuItem, Button, Tabs, Tab, Skeleton,
  Dialog, DialogTitle, DialogContent, DialogActions, Alert, Tooltip, IconButton,
  Snackbar,
} from "@mui/material";
import { BugReport, DeleteOutlined, CleaningServices } from "@mui/icons-material";
import * as Icons from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { clientsApi, findingsApi, projectsApi } from "../services/api";
import { Client, Finding, Project, FindingCategoriesResponse } from "../types";
import { fromNow } from "../utils/datetime";

const SEV_COLOR: Record<string, string> = {
  critical: "#f44336", high: "#ff9800", medium: "#ffeb3b", low: "#4caf50", info: "#4285F4",
};
const STATUS_COLOR: Record<string, string> = {
  open: "#ff9800", remediated: "#00e676", accepted: "#34A853", false_positive: "rgba(255,255,255,0.4)",
};

function CatIcon({ name, sx }: { name: string; sx?: any }) {
  const C = (Icons as any)[name] || Icons.Apps;
  return <C sx={sx || { fontSize: 14 }} />;
}

// Per-category accent colors — keeps each tile distinct in the grid.
const CAT_COLOR: Record<string, string> = {
  vulnerability:       "#f44336",
  cloud_configuration: "#4285F4",
  host_configuration:  "#34A853",
  attack_surface:      "#ff6d00",
  data:                "#ff9800",
  secret:              "#ffd54f",
  end_of_life:         "#9e9e9e",
  sast:                "#00e676",
  web:                 "#FBBC04",
  network_exposure:    "#03a9f4",
  excessive_access:    "#ff5252",
  identity_access:     "#f06292",
  ai_security:         "#ba68c8",
  detections:          "#ff4081",
  code_build_scans:    "#26c6da",
  kubernetes_admission:"#9ccc65",
};

function CategoryTile({ cat, active, onClick }: {
  cat: { key: string; label: string; icon: string; count: number };
  active: boolean;
  onClick: () => void;
}) {
  const color = CAT_COLOR[cat.key] || "#4285F4";
  const empty = cat.count === 0;
  return (
    <Card onClick={onClick}
      sx={{
        bgcolor: active ? `${color}15` : "#1E1E1E",
        border: active ? `1px solid ${color}` : "1px solid rgba(255,255,255,0.08)",
        borderRadius: 2, cursor: "pointer", height: "100%",
        transition: "transform .12s, border-color .12s, background-color .12s",
        opacity: empty && !active ? 0.6 : 1,
        "&:hover": {
          borderColor: color,
          bgcolor: active ? `${color}20` : `${color}08`,
          transform: "translateY(-1px)",
        },
      }}>
      <CardContent sx={{ p: 1.75, "&:last-child": { pb: 1.75 } }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.75 }}>
          <Box sx={{ width: 32, height: 32, borderRadius: 1, bgcolor: `${color}20`,
            display: "flex", alignItems: "center", justifyContent: "center" }}>
            <CatIcon name={cat.icon} sx={{ fontSize: 18, color }} />
          </Box>
          <Typography sx={{ color: empty ? "rgba(255,255,255,0.5)" : "white",
            fontSize: 26, fontWeight: 700, lineHeight: 1, ml: "auto" }}>
            {cat.count}
          </Typography>
        </Box>
        <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.85)",
          fontSize: 12, fontWeight: 500, lineHeight: 1.25 }}>
          {cat.label}
        </Typography>
      </CardContent>
    </Card>
  );
}

export default function Findings() {
  const qc = useQueryClient();
  const [clientId, setClientId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [section, setSection] = useState("security_posture");
  const [category, setCategory] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["projects", clientId],
    queryFn: () => projectsApi.list(clientId),
    enabled: !!clientId,
  });
  const { data: catData } = useQuery<FindingCategoriesResponse>({
    queryKey: ["findings-categories", clientId, projectId, statusFilter],
    queryFn: () => findingsApi.categories(clientId, projectId || undefined, statusFilter || "open"),
    enabled: !!clientId,
  });
  const { data: findings = [], isLoading } = useQuery<Finding[]>({
    queryKey: ["findings-all", clientId, projectId, sevFilter, statusFilter, section, category],
    queryFn: () => findingsApi.listAll(clientId, sevFilter || undefined, statusFilter || undefined, projectId || undefined, section, category || undefined),
    enabled: !!clientId,
  });

  const sectionData = (catData?.sections || []).find((s) => s.key === section);

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: any) => findingsApi.update(clientId, id, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings-all"] }); setSelected(null); },
  });

  const [pendingDelete, setPendingDelete] = React.useState<Finding | null>(null);
  const [snack, setSnack] = React.useState<string>("");

  const deleteMutation = useMutation({
    mutationFn: (findingId: string) => findingsApi.delete(clientId, findingId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings-all"] });
      qc.invalidateQueries({ queryKey: ["findings-categories"] });
      setPendingDelete(null);
      setSelected(null);
      setSnack("Finding deleted");
    },
  });

  const cleanupBlankMutation = useMutation({
    mutationFn: () => findingsApi.cleanupBlank(clientId),
    onSuccess: (resp: any) => {
      qc.invalidateQueries({ queryKey: ["findings-all"] });
      qc.invalidateQueries({ queryKey: ["findings-categories"] });
      setSnack(`Deleted ${resp?.deleted ?? 0} blank finding(s)`);
    },
  });

  const [sortKey, setSortKey] = React.useState<string>("first_seen_at");
  const [sortDir, setSortDir] = React.useState<"asc" | "desc">("desc");
  const sortedFindings = React.useMemo(() => {
    const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const dir = sortDir === "asc" ? 1 : -1;
    return [...findings].sort((a, b) => {
      let av: any = (a as any)[sortKey];
      let bv: any = (b as any)[sortKey];
      if (sortKey === "severity") {
        av = SEV_RANK[(typeof a.severity === "object" ? (a.severity as any).value : a.severity) || "info"] ?? 99;
        bv = SEV_RANK[(typeof b.severity === "object" ? (b.severity as any).value : b.severity) || "info"] ?? 99;
      }
      if (sortKey === "first_seen_at") {
        av = a.first_seen_at || a.created_at;
        bv = b.first_seen_at || b.created_at;
      }
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av || "").localeCompare(String(bv || "")) * dir;
    });
  }, [findings, sortKey, sortDir]);
  const setSort = (k: string) => {
    if (sortKey === k) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else { setSortKey(k); setSortDir("desc"); }
  };

  const sevCounts = findings.reduce((acc: Record<string, number>, f) => {
    const s = typeof f.severity === "object" ? (f.severity as any).value ?? f.severity : f.severity;
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Findings</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            All security findings across scans
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
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
          <FormControl size="small" sx={{ minWidth: 130 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Severity</InputLabel>
            <Select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} label="Severity"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All</MenuItem>
              {["critical","high","medium","low","info"].map((s) => (
                <MenuItem key={s} value={s} sx={{ color: SEV_COLOR[s] }}>{s.charAt(0).toUpperCase() + s.slice(1)}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 130 }}>
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Status</InputLabel>
            <Select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} label="Status"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">All</MenuItem>
              <MenuItem value="open">Open</MenuItem>
              <MenuItem value="remediated">Remediated</MenuItem>
              <MenuItem value="accepted">Accepted</MenuItem>
              <MenuItem value="false_positive">False Positive</MenuItem>
            </Select>
          </FormControl>
        </Box>
      </Box>

      {clientId && (
        <>
          {/* Section tabs */}
          <Tabs value={section} onChange={(_, v) => { setSection(v); setCategory(""); }}
            sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)", mb: 1.5,
              "& .MuiTab-root": { color: "rgba(255,255,255,0.5)", textTransform: "none", fontWeight: 500 },
              "& .Mui-selected": { color: "#4285F4" }, "& .MuiTabs-indicator": { backgroundColor: "#4285F4" } }}>
            {(catData?.sections || []).map((s) => (
              <Tab key={s.key} value={s.key} label={`${s.label} (${s.total})`} />
            ))}
          </Tabs>

          {/* Category tile grid */}
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, letterSpacing: 0.5 }}>
              CATEGORIES — CLICK TO FILTER
            </Typography>
            {category && (
              <Button size="small" onClick={() => setCategory("")}
                sx={{ color: "#4285F4", fontSize: 11 }}>
                Clear category
              </Button>
            )}
          </Box>
          <Grid container spacing={1.5} sx={{ mb: 2 }}>
            {!catData ? (
              [0, 1, 2, 3, 4, 5].map((i) => (
                <Grid key={i} size={{ xs: 6, sm: 4, md: 3, lg: 2 }}>
                  <Skeleton variant="rectangular" height={88}
                    sx={{ borderRadius: 2, bgcolor: "rgba(255,255,255,0.04)" }} />
                </Grid>
              ))
            ) : (
              (sectionData?.categories || []).map((c) => (
                <Grid key={c.key} size={{ xs: 6, sm: 4, md: 3, lg: 2 }}>
                  <CategoryTile cat={c}
                    active={category === c.key}
                    onClick={() => setCategory(category === c.key ? "" : c.key)} />
                </Grid>
              ))
            )}
          </Grid>

          {findings.length > 0 && (
            <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap", alignItems: "center" }}>
              {["critical","high","medium","low","info"].filter((s) => sevCounts[s]).map((s) => (
                <Chip key={s} label={`${s.charAt(0).toUpperCase() + s.slice(1)}: ${sevCounts[s]}`} size="small"
                  onClick={() => setSevFilter(sevFilter === s ? "" : s)}
                  sx={{ bgcolor: `${SEV_COLOR[s]}${sevFilter === s ? "40" : "20"}`, color: SEV_COLOR[s],
                    border: sevFilter === s ? `1px solid ${SEV_COLOR[s]}` : "none", cursor: "pointer" }} />
              ))}
              <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", alignSelf: "center", ml: 1 }}>
                {findings.length} matching
              </Typography>
              <Box sx={{ flex: 1 }} />
              <Button
                size="small"
                variant="outlined"
                startIcon={<CleaningServices sx={{ fontSize: 16 }} />}
                disabled={cleanupBlankMutation.isPending}
                onClick={() => {
                  if (window.confirm("Delete all findings that have no title, description, or resource? This is used to tidy up empty rows after a scanner returned partial data.")) {
                    cleanupBlankMutation.mutate();
                  }
                }}
                sx={{
                  color: "rgba(255,255,255,0.7)",
                  borderColor: "rgba(255,255,255,0.15)",
                  textTransform: "none",
                  "&:hover": { borderColor: "#EA4335", color: "#EA4335", bgcolor: "rgba(234,67,53,0.05)" },
                }}
              >
                Delete blank findings
              </Button>
            </Box>
          )}
        </>
      )}

      {!clientId ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "white" }}>Select a client to view findings.</Alert>
      ) : isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>
      ) : findings.length === 0 ? (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px dashed rgba(255,255,255,0.2)", borderRadius: 2, p: 6, textAlign: "center" }}>
          <BugReport sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
          <Typography sx={{ color: "rgba(255,255,255,0.5)" }}>
            No findings found. Run a scan to discover security issues.
          </Typography>
        </Card>
      ) : (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
                  <TableCell><TableSortLabel active={sortKey === "severity"} direction={sortDir} onClick={() => setSort("severity")}
                    sx={{ color: "rgba(255,255,255,0.5) !important", "& .MuiTableSortLabel-icon": { color: "rgba(255,255,255,0.5) !important" } }}>SEVERITY</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "title"} direction={sortDir} onClick={() => setSort("title")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>TITLE</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "cve_id"} direction={sortDir} onClick={() => setSort("cve_id")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>CVE</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "cvss_score"} direction={sortDir} onClick={() => setSort("cvss_score")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>CVSS</TableSortLabel></TableCell>
                  <TableCell>RESOURCE</TableCell>
                  <TableCell><TableSortLabel active={sortKey === "status"} direction={sortDir} onClick={() => setSort("status")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>STATUS</TableSortLabel></TableCell>
                  <TableCell><TableSortLabel active={sortKey === "first_seen_at"} direction={sortDir} onClick={() => setSort("first_seen_at")}
                    sx={{ color: "rgba(255,255,255,0.5) !important" }}>FOUND</TableSortLabel></TableCell>
                  <TableCell align="right" sx={{ width: 44 }} />
                </TableRow>
              </TableHead>
              <TableBody>
                {sortedFindings.map((f) => {
                  const sev = typeof f.severity === "object" ? (f.severity as any).value ?? f.severity : f.severity;
                  return (
                    <TableRow key={f.id}
                      sx={{ cursor: "pointer", "&:hover": { bgcolor: "rgba(255,255,255,0.03)" },
                        "& td": { borderColor: "rgba(255,255,255,0.05)", py: 1 } }}
                      onClick={() => setSelected(f)}>
                      <TableCell>
                        <Chip label={sev} size="small"
                          sx={{ bgcolor: `${SEV_COLOR[sev] || "#888"}20`, color: SEV_COLOR[sev] || "#888", fontSize: 10, height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ color: "white", maxWidth: 300 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
                          <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {f.title}
                          </Typography>
                          {(f.seen_count ?? 1) > 1 && (
                            <Tooltip title={`Detected in ${f.seen_count} scans`}>
                              <Chip label={`×${f.seen_count}`} size="small"
                                sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 10, height: 16, flexShrink: 0 }} />
                            </Tooltip>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: f.cve_id ? "#4285F4" : "rgba(255,255,255,0.3)", fontSize: 12 }}>
                        {f.cve_id || "—"}
                      </TableCell>
                      <TableCell sx={{ color: f.cvss_score != null ? (f.cvss_score >= 9 ? "#f44336" : f.cvss_score >= 7 ? "#ff9800" : "white") : "rgba(255,255,255,0.3)", fontSize: 12 }}>
                        {f.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.6)", fontSize: 12, maxWidth: 160 }}>
                        <Typography variant="caption" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>
                          {f.resource_id || f.resource_type || "—"}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={f.status || "open"} size="small"
                          sx={{ bgcolor: `${STATUS_COLOR[f.status || "open"] || "#888"}20`,
                            color: STATUS_COLOR[f.status || "open"] || "#888", fontSize: 10, height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.4)", fontSize: 11 }}>
                        {(() => {
                          const ts = f.first_seen_at || f.created_at;
                          return fromNow(ts);
                        })()}
                      </TableCell>
                      <TableCell align="right" sx={{ width: 44 }}>
                        <Tooltip title="Delete finding">
                          <IconButton
                            size="small"
                            onClick={(e) => { e.stopPropagation(); setPendingDelete(f); }}
                            sx={{
                              color: "rgba(255,255,255,0.4)",
                              "&:hover": { color: "#EA4335", bgcolor: "rgba(234,67,53,0.08)" },
                            }}
                          >
                            <DeleteOutlined sx={{ fontSize: 18 }} />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </Card>
      )}

      {/* Detail / status update dialog */}
      <Dialog open={!!selected} onClose={() => setSelected(null)} maxWidth="md" fullWidth
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
        {selected && (() => {
          const sev = typeof selected.severity === "object" ? (selected.severity as any).value ?? selected.severity : selected.severity;
          return (
            <>
              <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)", pb: 1.5 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Chip label={sev} size="small" sx={{ bgcolor: `${SEV_COLOR[sev]}20`, color: SEV_COLOR[sev], fontSize: 11 }} />
                  <Typography sx={{ fontWeight: 600 }}>{selected.title}</Typography>
                </Box>
              </DialogTitle>
              <DialogContent sx={{ mt: 1 }}>
                {selected.description && (
                  <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.7)", mb: 2 }}>{selected.description}</Typography>
                )}
                <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2 }}>
                  {selected.cve_id && <Chip label={selected.cve_id} size="small" sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4" }} />}
                  {selected.cvss_score != null && <Chip label={`CVSS ${selected.cvss_score.toFixed(1)}`} size="small" sx={{ bgcolor: "rgba(255,255,255,0.08)", color: "white" }} />}
                  {selected.control_id && <Chip label={selected.control_id} size="small" sx={{ bgcolor: "rgba(124,77,255,0.2)", color: "#34A853" }} />}
                </Box>
                {selected.resource_id && (
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 2 }}>
                    Resource: {selected.resource_id} {selected.resource_type ? `(${selected.resource_type})` : ""}
                  </Typography>
                )}
                {selected.remediation && (
                  <Box sx={{ bgcolor: "rgba(0,230,118,0.08)", border: "1px solid rgba(0,230,118,0.2)", borderRadius: 1, p: 1.5, mb: 2 }}>
                    <Typography variant="caption" sx={{ color: "#00e676", fontWeight: 600, display: "block", mb: 0.5 }}>Remediation</Typography>
                    <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)" }}>{selected.remediation}</Typography>
                  </Box>
                )}
                <Box>
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", mb: 1, display: "block" }}>Update Status</Typography>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    {["open","remediated","accepted","false_positive"].map((s) => (
                      <Chip key={s} label={s.replace("_", " ")} size="small" clickable
                        onClick={() => updateMutation.mutate({ id: selected.id, data: { status: s } })}
                        sx={{ bgcolor: selected.status === s ? `${STATUS_COLOR[s]}40` : `${STATUS_COLOR[s]}15`,
                          color: STATUS_COLOR[s], border: selected.status === s ? `1px solid ${STATUS_COLOR[s]}` : "none",
                          cursor: "pointer" }} />
                    ))}
                  </Box>
                </Box>
              </DialogContent>
              <DialogActions sx={{ p: 2 }}>
                <Button
                  startIcon={<DeleteOutlined />}
                  onClick={() => setPendingDelete(selected)}
                  sx={{
                    color: "#EA4335", textTransform: "none",
                    "&:hover": { bgcolor: "rgba(234,67,53,0.08)" },
                  }}
                >
                  Delete
                </Button>
                <Box sx={{ flex: 1 }} />
                <Button onClick={() => setSelected(null)} sx={{ color: "rgba(255,255,255,0.5)" }}>Close</Button>
              </DialogActions>
            </>
          );
        })()}
      </Dialog>

      {/* Confirm delete */}
      <Dialog open={!!pendingDelete} onClose={() => setPendingDelete(null)}
        slotProps={{ paper: { sx: { bgcolor: "#1E1E1E", color: "white" } } }}>
        <DialogTitle sx={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>Delete finding?</DialogTitle>
        <DialogContent sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.75)" }}>
            This permanently removes the finding from the database. If the same issue is detected again on the next scan it will be re-created.
          </Typography>
          {pendingDelete && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Typography variant="body2" sx={{ color: "white", fontWeight: 600 }}>{pendingDelete.title || "(no title)"}</Typography>
              {pendingDelete.resource_id && (
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>{pendingDelete.resource_id}</Typography>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setPendingDelete(null)} sx={{ color: "rgba(255,255,255,0.5)" }}>Cancel</Button>
          <Button
            variant="contained"
            color="error"
            disabled={deleteMutation.isPending}
            onClick={() => pendingDelete && deleteMutation.mutate(pendingDelete.id)}
            sx={{ bgcolor: "#EA4335", "&:hover": { bgcolor: "#c5362b" } }}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={!!snack}
        autoHideDuration={3000}
        onClose={() => setSnack("")}
        message={snack}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
      />
    </Box>
  );
}
