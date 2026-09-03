import React, { useMemo, useState } from "react";
import {
  Box, Typography, Card, Chip, TextField, Collapse, IconButton,
  CircularProgress, InputAdornment, Alert, Tabs, Tab,
  ToggleButton, ToggleButtonGroup, FormControl, InputLabel, Select, MenuItem,
  FormControlLabel, Switch, Table, TableHead, TableRow, TableCell, TableBody,
  TableContainer, TablePagination, Tooltip,
} from "@mui/material";
import {
  Search, ExpandMore, ExpandLess, Storage, AutoStories, OpenInNew, Hub,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { knowledgeApi, adminApi } from "../services/api";

// ── Threat Intelligence browser (synced feeds) ───────────────────────────────

const TI_SOURCES = [
  { id: "attack", label: "MITRE ATT&CK" },
  { id: "capec", label: "MITRE CAPEC" },
  { id: "kev", label: "CISA KEV" },
  { id: "nvd_recent", label: "NVD CVEs" },
  { id: "epss", label: "EPSS" },
];

function ThreatIntelBrowser() {
  const [source, setSource] = useState<string>("attack");
  const [q, setQ] = useState("");
  const [category, setCategory] = useState("");
  const [cwe, setCwe] = useState("");
  const [minCvss, setMinCvss] = useState<string>("");
  const [minScore, setMinScore] = useState<string>("");
  const [ransomware, setRansomware] = useState(false);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  const isLib = source === "attack" || source === "capec";
  const isNvd = source === "nvd_recent";
  const isEpss = source === "epss";
  const isKev = source === "kev";

  const { data, isFetching } = useQuery<{ id: string; total: number; rows: any[]; facets?: { categories?: string[] }; note?: string }>({
    queryKey: ["ti-entries", source, q, category, cwe, minCvss, minScore, ransomware],
    queryFn: () => adminApi.syncFeedEntries(source, {
      limit: 300,
      q: q || undefined,
      category: isLib && category ? category : undefined,
      cwe: (isLib || isNvd) && cwe ? cwe : undefined,
      min_cvss: isNvd && minCvss ? Number(minCvss) : undefined,
      min_score: isEpss && minScore ? Number(minScore) : undefined,
      ransomware: isKev ? ransomware : undefined,
    }),
  });

  const rows = data?.rows || [];
  const cols = rows.length ? Object.keys(rows[0]).filter((k) => k !== "ref") : [];
  const cats = data?.facets?.categories || [];
  const pagedRows = rows.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);

  const resetFilters = () => { setQ(""); setCategory(""); setCwe(""); setMinCvss(""); setMinScore(""); setRansomware(false); setPage(0); };

  // Reset to page 0 whenever source or filters change
  React.useEffect(() => { setPage(0); }, [source, q, category, cwe, minCvss, minScore, ransomware]);

  return (
    <Box>
      {/* Source selector */}
      <ToggleButtonGroup
        size="small" exclusive value={source}
        onChange={(_, v) => { if (v) { setSource(v); resetFilters(); } }}
        sx={{ mb: 2, flexWrap: "wrap",
          "& .MuiToggleButton-root": { textTransform: "none", color: "text.secondary", borderColor: "divider", px: 1.5 },
          "& .Mui-selected": { color: "#4285F4 !important", bgcolor: "rgba(66,133,244,0.12) !important" } }}
      >
        {TI_SOURCES.map((s) => <ToggleButton key={s.id} value={s.id}>{s.label}</ToggleButton>)}
      </ToggleButtonGroup>

      {/* Filters */}
      <Box sx={{ display: "flex", gap: 1.5, mb: 2, flexWrap: "wrap", alignItems: "center" }}>
        <TextField size="small" placeholder={isLib ? "Search id / name / description…" : "Search CVE…"}
          value={q} onChange={(e) => setQ(e.target.value)} sx={{ minWidth: 240 }}
          slotProps={{ input: { startAdornment: <InputAdornment position="start"><Search sx={{ color: "text.secondary", fontSize: 18 }} /></InputAdornment> } }} />

        {isLib && (
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Category</InputLabel>
            <Select label="Category" value={category} onChange={(e) => setCategory(e.target.value)}
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              <MenuItem value="">All categories</MenuItem>
              {cats.map((c) => <MenuItem key={c} value={c} sx={{ textTransform: "capitalize" }}>{c.replace(/_/g, " ")}</MenuItem>)}
            </Select>
          </FormControl>
        )}
        {(isLib || isNvd) && (
          <TextField size="small" label="CWE" placeholder="CWE-79" value={cwe}
            onChange={(e) => setCwe(e.target.value)} sx={{ width: 130 }} />
        )}
        {isNvd && (
          <FormControl size="small" sx={{ minWidth: 140 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Min CVSS</InputLabel>
            <Select label="Min CVSS" value={minCvss} onChange={(e) => setMinCvss(e.target.value)}
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              {["", "4", "7", "9"].map((v) => <MenuItem key={v} value={v}>{v ? `≥ ${v}` : "Any"}</MenuItem>)}
            </Select>
          </FormControl>
        )}
        {isEpss && (
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel sx={{ color: "text.secondary" }}>Min EPSS</InputLabel>
            <Select label="Min EPSS" value={minScore} onChange={(e) => setMinScore(e.target.value)}
              sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
              {["", "0.1", "0.5", "0.9"].map((v) => <MenuItem key={v} value={v}>{v ? `≥ ${v}` : "Any"}</MenuItem>)}
            </Select>
          </FormControl>
        )}
        {isKev && (
          <FormControlLabel sx={{ color: "text.secondary" }}
            control={<Switch size="small" checked={ransomware} onChange={(e) => setRansomware(e.target.checked)} />}
            label="Ransomware-linked only" />
        )}
      </Box>

      <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>
        Showing {rows.length} of {(data?.total ?? 0).toLocaleString()} · click a row to open the authoritative source ↗
      </Typography>

      {data?.note ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.08)" }}>{data.note}</Alert>
      ) : isFetching ? (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}><CircularProgress sx={{ color: "#4285F4" }} /></Box>
      ) : rows.length === 0 ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.08)" }}>
          No entries — adjust filters, or run a Sync for this feed first.
        </Alert>
      ) : (
        <>
          <TableContainer component={Card} sx={{ bgcolor: "background.paper", maxHeight: "58vh", overflow: "auto" }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  {cols.map((c) => (
                    <TableCell key={c} sx={{ fontWeight: 700, textTransform: "uppercase", fontSize: 10, color: "text.secondary", bgcolor: "background.paper" }}>
                      {c.replace(/_/g, " ")}
                    </TableCell>
                  ))}
                  <TableCell sx={{ bgcolor: "background.paper", width: 36 }} />
                </TableRow>
              </TableHead>
              <TableBody>
                {pagedRows.map((r, i) => (
                  <TableRow key={i} hover
                    onClick={() => { if (r.ref) window.open(r.ref, "_blank", "noopener"); }}
                    sx={{ cursor: r.ref ? "pointer" : "default", "&:hover": r.ref ? { bgcolor: "rgba(66,133,244,0.06)" } : {} }}>
                    {cols.map((c) => (
                      <TableCell key={c} sx={{ fontSize: 12, color: "text.primary", maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: c === "description" ? "normal" : "nowrap" }}>
                        {typeof r[c] === "boolean" ? (r[c] ? "yes" : "—") : (r[c] ?? "—")}
                      </TableCell>
                    ))}
                    <TableCell sx={{ width: 36 }}>
                      {r.ref && (
                        <Tooltip title="Open authoritative source">
                          <OpenInNew sx={{ fontSize: 15, color: "text.secondary" }} />
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          <TablePagination
            component="div"
            count={rows.length}
            page={page}
            onPageChange={(_, p) => setPage(p)}
            rowsPerPage={rowsPerPage}
            onRowsPerPageChange={(e) => { setRowsPerPage(parseInt(e.target.value, 10)); setPage(0); }}
            rowsPerPageOptions={[10, 25, 50, 100]}
            sx={{ borderTop: "1px solid", borderColor: "divider", color: "text.secondary", "& .MuiTablePagination-selectLabel, & .MuiTablePagination-displayedRows": { fontSize: 12 } }}
          />
        </>
      )}
    </Box>
  );
}

interface Section {
  id: string; position: number; name: string; section_type: string;
  body: Record<string, any>;
}
interface KFile {
  id: string; name: string; category: string; category_label: string;
  description?: string; version?: string; size_kb: number;
  used_by: string[]; section_count: number; sections: Section[];
}
interface KCategory { key: string; label: string; count: number; files: KFile[]; }
interface Stats { file_count: number; agent_count: number; total_size_kb: number; }

// ── Section renderers ────────────────────────────────────────────────────────

function SectionBlock({ section }: { section: Section }) {
  const { body, section_type, name } = section;
  return (
    <Box sx={{ py: 1, borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
      <Box sx={{ display: "flex", alignItems: "baseline", gap: 1, mb: 0.5 }}>
        <Typography sx={{ color: "text.secondary", fontWeight: 600, fontSize: 13 }}>{name}</Typography>
        {section_type === "disclaimer" && (
          <Typography variant="caption" sx={{ color: "text.secondary" }}>{body.chars || 0} chars</Typography>
        )}
        {(section_type === "items" || section_type === "applicability") && Array.isArray(body.items || body.keys) && (
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            {(body.items || body.keys).length} items
          </Typography>
        )}
        {section_type === "matrix" && body.keys && (
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            {Object.keys(body.keys).length} capabilities
          </Typography>
        )}
      </Box>
      {section_type === "disclaimer" && body.text && (
        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", fontStyle: "italic" }}>
          {body.text}
        </Typography>
      )}
      {(section_type === "items" || section_type === "applicability") && (
        <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
          {(body.items || body.keys || []).slice(0, 30).map((item: string, i: number) => (
            <Chip key={i} label={item} size="small"
              sx={{ bgcolor: "rgba(255,255,255,0.05)", color: "text.secondary", fontSize: 11, height: 22 }} />
          ))}
          {(body.items || body.keys || []).length > 30 && (
            <Chip label={`+${(body.items || body.keys).length - 30} more`} size="small"
              sx={{ bgcolor: "transparent", color: "text.secondary", fontSize: 11, height: 22 }} />
          )}
        </Box>
      )}
      {section_type === "matrix" && body.keys && (
        <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
          {Object.entries(body.keys as Record<string, number>).slice(0, 40).map(([k, v]) => (
            <Chip key={k} label={`${k}: ${v}`} size="small"
              sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "#4285F4", fontSize: 11, height: 22 }} />
          ))}
        </Box>
      )}
    </Box>
  );
}

function KnowledgeCard({ file }: { file: KFile }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 1.5 }}>
      <Box sx={{ display: "flex", alignItems: "center", p: 1.5, cursor: "pointer" }}
        onClick={() => setExpanded((v) => !v)}>
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", mr: 1.5 }}>
          <Storage sx={{ color: "#4285F4", fontSize: 24 }} />
        </Box>
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography sx={{ color: "text.primary", fontWeight: 600, fontSize: 14 }}>{file.name}</Typography>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            {file.description}
          </Typography>
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mr: 1 }}>
          <Chip label={`${file.section_count} sections`} size="small"
            sx={{ bgcolor: "rgba(255,255,255,0.05)", color: "text.secondary", fontSize: 11, height: 20 }} />
          <Chip label={`${file.size_kb} KB`} size="small"
            sx={{ bgcolor: "rgba(255,255,255,0.05)", color: "text.secondary", fontSize: 11, height: 20 }} />
          {file.version && (
            <Chip label={file.version} size="small"
              sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontSize: 11, height: 20, fontWeight: 700 }} />
          )}
        </Box>
        <IconButton size="small" sx={{ color: "text.secondary" }}>
          {expanded ? <ExpandLess /> : <ExpandMore />}
        </IconButton>
      </Box>
      <Collapse in={expanded}>
        <Box sx={{ px: 2, pb: 1.5, borderTop: "1px solid rgba(255,255,255,0.06)" }}>
          {file.used_by.length > 0 && (
            <Typography variant="caption" sx={{ color: "text.secondary", display: "block", py: 1 }}>
              Powers agents: {file.used_by.join(", ")}
            </Typography>
          )}
          {file.sections.map((s) => <SectionBlock key={s.id} section={s} />)}
        </Box>
      </Collapse>
    </Card>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function KnowledgeBase() {
  const [search, setSearch] = useState("");
  const [tab, setTab] = useState(0);

  const { data, isLoading } = useQuery<{ categories: KCategory[] }>({
    queryKey: ["knowledge-list"], queryFn: knowledgeApi.list,
  });
  const { data: stats } = useQuery<Stats>({ queryKey: ["knowledge-stats"], queryFn: knowledgeApi.stats });
  const { data: searchData } = useQuery<{ results: { file_id: string }[] }>({
    queryKey: ["knowledge-search", search],
    queryFn: () => knowledgeApi.search(search),
    enabled: search.trim().length >= 2,
  });

  // When searching, filter files by IDs that matched
  const matchedIds = useMemo(() => new Set((searchData?.results || []).map((r) => r.file_id)), [searchData]);

  const visibleCategories = useMemo(() => {
    if (!data) return [];
    if (search.trim().length < 2) return data.categories;
    return data.categories
      .map((c) => ({ ...c, files: c.files.filter((f) => matchedIds.has(f.id)) }))
      .filter((c) => c.files.length > 0);
  }, [data, search, matchedIds]);

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Knowledge Base</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            {stats
              ? `${stats.file_count} knowledge file${stats.file_count === 1 ? "" : "s"} powering ${stats.agent_count} specialist agent${stats.agent_count === 1 ? "" : "s"}`
              : "Loading…"}
          </Typography>
        </Box>
        {stats && (
          <Chip
            icon={<AutoStories sx={{ fontSize: 16 }} />}
            label={`${stats.total_size_kb.toLocaleString()} KB total`}
            sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", fontWeight: 600, "& .MuiChip-icon": { color: "#4285F4" } }}
          />
        )}
      </Box>

      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2,
        "& .MuiTab-root": { color: "text.secondary", textTransform: "none", fontWeight: 600, minHeight: 42 },
        "& .Mui-selected": { color: "#4285F4 !important" }, "& .MuiTabs-indicator": { backgroundColor: "#4285F4" } }}>
        <Tab icon={<AutoStories sx={{ fontSize: 16 }} />} iconPosition="start" label="Knowledge Files" />
        <Tab icon={<Hub sx={{ fontSize: 16 }} />} iconPosition="start" label="Threat Intelligence" />
      </Tabs>

      {tab === 1 ? <ThreatIntelBrowser /> : (<>
      <TextField
        fullWidth size="small" placeholder="Search files, sections, frameworks, capabilities…"
        value={search} onChange={(e) => setSearch(e.target.value)}
        slotProps={{
          input: {
            startAdornment: <InputAdornment position="start"><Search sx={{ color: "text.secondary" }} /></InputAdornment>,
          },
          htmlInput: { style: { color: "text.primary" } },
        }}
        sx={{ mb: 3, "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
      />

      {isLoading ? (
        <CircularProgress sx={{ color: "#4285F4" }} />
      ) : visibleCategories.length === 0 ? (
        <Alert severity="info" sx={{ bgcolor: "rgba(66,133,244,0.08)", color: "text.primary" }}>
          {search.trim().length >= 2 ? `No matches for "${search}"` : "No knowledge files loaded yet."}
        </Alert>
      ) : (
        visibleCategories.map((cat) => (
          <Box key={cat.key} sx={{ mb: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
              <Typography sx={{ color: "text.secondary", fontWeight: 700, fontSize: 12, textTransform: "uppercase", letterSpacing: 1.5 }}>
                {cat.label}
              </Typography>
              <Chip label={cat.count} size="small"
                sx={{ height: 20, bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontWeight: 700, fontSize: 11 }} />
              <Box sx={{ flex: 1, height: 1, bgcolor: "rgba(255,255,255,0.08)" }} />
            </Box>
            {cat.files.map((f) => <KnowledgeCard key={f.id} file={f} />)}
          </Box>
        ))
      )}
      </>)}
    </Box>
  );
}
