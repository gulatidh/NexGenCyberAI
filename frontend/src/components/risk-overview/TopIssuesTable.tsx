import React, { useMemo, useState } from "react";
import {
  Card, CardContent, Typography, Table, TableHead, TableRow, TableCell, TableBody,
  TableContainer, Chip, Box, TextField, TableSortLabel, Skeleton, TablePagination,
} from "@mui/material";
import { RiskTopIssue } from "../../types";
import { cardSx, SEV_COLOR, FRAMEWORK_LABEL } from "./tokens";

interface Props {
  data: RiskTopIssue[];
  loading?: boolean;
}

type SortKey = "title" | "severity" | "count" | "affected_resources";
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function TopIssuesTable({ data, loading }: Props) {
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("count");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(0);
  const [perPage, setPerPage] = useState(10);

  const sorted = useMemo(() => {
    const filtered = data.filter((d) =>
      !search || d.title.toLowerCase().includes(search.toLowerCase()) ||
      (d.framework || "").toLowerCase().includes(search.toLowerCase())
    );
    const dir = sortDir === "asc" ? 1 : -1;
    return [...filtered].sort((a, b) => {
      if (sortKey === "title") return a.title.localeCompare(b.title) * dir;
      if (sortKey === "severity") return (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) * dir;
      const av = (a as any)[sortKey] || 0;
      const bv = (b as any)[sortKey] || 0;
      return (av - bv) * dir;
    });
  }, [data, search, sortKey, sortDir]);

  const pageRows = sorted.slice(page * perPage, page * perPage + perPage);

  const setSort = (key: SortKey) => {
    if (sortKey === key) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("desc"); }
  };

  return (
    <Card sx={cardSx}>
      <CardContent sx={{ "&:last-child": { pb: 1 } }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1.5, flexWrap: "wrap", gap: 1 }}>
          <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>
            Top Issues
          </Typography>
          <TextField size="small" placeholder="Search issue or framework…"
            value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            sx={{ minWidth: 240,
              "& .MuiOutlinedInput-root": { color: "white", "& fieldset": { borderColor: "rgba(255,255,255,0.15)" } },
              "& input::placeholder": { color: "rgba(255,255,255,0.4)" } }} />
        </Box>
        {loading ? (
          <Skeleton variant="rectangular" height={300} sx={{ bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1 }} />
        ) : (
          <>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
                    <TableCell>
                      <TableSortLabel active={sortKey === "severity"} direction={sortDir} onClick={() => setSort("severity")}
                        sx={{ color: "rgba(255,255,255,0.5) !important", "& .MuiTableSortLabel-icon": { color: "rgba(255,255,255,0.5) !important" } }}>
                        SEV
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel active={sortKey === "title"} direction={sortDir} onClick={() => setSort("title")}
                        sx={{ color: "rgba(255,255,255,0.5) !important", "& .MuiTableSortLabel-icon": { color: "rgba(255,255,255,0.5) !important" } }}>
                        ISSUE
                      </TableSortLabel>
                    </TableCell>
                    <TableCell>FRAMEWORK</TableCell>
                    <TableCell align="right">
                      <TableSortLabel active={sortKey === "affected_resources"} direction={sortDir} onClick={() => setSort("affected_resources")}
                        sx={{ color: "rgba(255,255,255,0.5) !important", "& .MuiTableSortLabel-icon": { color: "rgba(255,255,255,0.5) !important" } }}>
                        RESOURCES
                      </TableSortLabel>
                    </TableCell>
                    <TableCell align="right">
                      <TableSortLabel active={sortKey === "count"} direction={sortDir} onClick={() => setSort("count")}
                        sx={{ color: "rgba(255,255,255,0.5) !important", "& .MuiTableSortLabel-icon": { color: "rgba(255,255,255,0.5) !important" } }}>
                        COUNT
                      </TableSortLabel>
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pageRows.length === 0 && (
                    <TableRow><TableCell colSpan={5} align="center" sx={{ color: "rgba(255,255,255,0.4)", py: 3 }}>
                      No matching issues
                    </TableCell></TableRow>
                  )}
                  {pageRows.map((r, i) => (
                    <TableRow key={`${r.title}-${i}`} sx={{ "& td": { color: "white", fontSize: 12, borderColor: "rgba(255,255,255,0.05)", py: 1 } }}>
                      <TableCell>
                        <Chip label={r.severity} size="small"
                          sx={{ bgcolor: `${SEV_COLOR[r.severity]}20`, color: SEV_COLOR[r.severity], fontSize: 10, height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ maxWidth: 420 }}>
                        <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {r.title}
                        </Typography>
                      </TableCell>
                      <TableCell sx={{ color: "rgba(255,255,255,0.6) !important", fontSize: 11 }}>
                        {r.framework ? (FRAMEWORK_LABEL[r.framework] || r.framework) : "—"}
                      </TableCell>
                      <TableCell align="right" sx={{ color: "rgba(255,255,255,0.7) !important" }}>{r.affected_resources}</TableCell>
                      <TableCell align="right" sx={{ fontWeight: 600 }}>{r.count}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            <TablePagination
              component="div"
              count={sorted.length}
              page={page}
              onPageChange={(_, p) => setPage(p)}
              rowsPerPage={perPage}
              onRowsPerPageChange={(e) => { setPerPage(parseInt(e.target.value, 10)); setPage(0); }}
              rowsPerPageOptions={[5, 10, 25]}
              sx={{ color: "rgba(255,255,255,0.6)", "& .MuiTablePagination-actions svg": { color: "rgba(255,255,255,0.6)" } }}
            />
          </>
        )}
      </CardContent>
    </Card>
  );
}
