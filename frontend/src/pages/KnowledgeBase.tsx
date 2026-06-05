import React, { useMemo, useState } from "react";
import {
  Box, Typography, Card, Chip, TextField, Collapse, IconButton,
  CircularProgress, InputAdornment, Alert,
} from "@mui/material";
import {
  Search, ExpandMore, ExpandLess, Storage, AutoStories,
} from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { knowledgeApi } from "../services/api";

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
        <Box sx={{ width: 36, height: 36, borderRadius: 1, bgcolor: "rgba(66,133,244,0.1)",
          display: "flex", alignItems: "center", justifyContent: "center", mr: 1.5 }}>
          <Storage sx={{ color: "#4285F4", fontSize: 20 }} />
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
    </Box>
  );
}
