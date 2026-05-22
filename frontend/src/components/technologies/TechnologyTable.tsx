import React, { useMemo, useState } from "react";
import {
  Card, CardContent, Box, Typography, Table, TableHead, TableRow, TableCell,
  TableBody, TableContainer, TableSortLabel, Chip, Tooltip, IconButton, LinearProgress,
  TablePagination, Button, Menu, MenuItem, Checkbox, FormControlLabel, Skeleton,
} from "@mui/material";
import { CheckCircle, Warning, Error, BlockOutlined, ViewColumn, Download } from "@mui/icons-material";
import dayjs from "dayjs";
import { fromNow } from "../../utils/datetime";
import type { TechnologyRow, TechStatus } from "../../types";
import { cardSx, STATUS_COLOR, RISK_COLOR } from "./tokens";

interface Props {
  data: TechnologyRow[];
  loading?: boolean;
  onRowClick?: (row: TechnologyRow) => void;
}

const ALL_COLUMNS = [
  { key: "name", label: "Technology", default: true },
  { key: "resources_count", label: "Resources", default: true, numeric: true },
  { key: "type", label: "Type", default: true },
  { key: "category", label: "Category", default: true },
  { key: "subcategory", label: "Subcategory", default: false },
  { key: "organization_usage_pct", label: "Org Usage", default: true },
  { key: "status", label: "Status", default: true },
  { key: "risk_level", label: "Risk", default: true },
  { key: "open_findings", label: "Open Findings", default: false, numeric: true },
  { key: "cve_count", label: "CVEs", default: false, numeric: true },
  { key: "last_seen", label: "Last Seen", default: true },
  { key: "environments", label: "Environment", default: false },
  { key: "owner", label: "Owner", default: false },
];

const STATUS_ICONS: Record<TechStatus, React.ReactNode> = {
  healthy:  <CheckCircle sx={{ fontSize: 14, color: STATUS_COLOR.healthy }} />,
  warning:  <Warning sx={{ fontSize: 14, color: STATUS_COLOR.warning }} />,
  critical: <Error sx={{ fontSize: 14, color: STATUS_COLOR.critical }} />,
  ignored:  <BlockOutlined sx={{ fontSize: 14, color: STATUS_COLOR.ignored }} />,
};


export default function TechnologyTable({ data, loading, onRowClick }: Props) {
  const [sortKey, setSortKey] = useState<string>("resources_count");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(0);
  const [perPage, setPerPage] = useState(25);
  const [colMenuAnchor, setColMenuAnchor] = useState<null | HTMLElement>(null);
  const [visibleCols, setVisibleCols] = useState<string[]>(ALL_COLUMNS.filter((c) => c.default).map((c) => c.key));

  const sorted = useMemo(() => {
    const dir = sortDir === "asc" ? 1 : -1;
    return [...data].sort((a, b) => {
      const av = (a as any)[sortKey];
      const bv = (b as any)[sortKey];
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av || "").localeCompare(String(bv || "")) * dir;
    });
  }, [data, sortKey, sortDir]);

  const setSort = (k: string) => {
    if (sortKey === k) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else { setSortKey(k); setSortDir("desc"); }
  };

  const pageRows = sorted.slice(page * perPage, page * perPage + perPage);

  const exportCsv = () => {
    const cols = ALL_COLUMNS.filter((c) => visibleCols.includes(c.key));
    const header = cols.map((c) => c.label).join(",");
    const rows = sorted.map((r) =>
      cols.map((c) => {
        let v = (r as any)[c.key];
        if (Array.isArray(v)) v = v.join(";");
        if (typeof v === "string" && (v.includes(",") || v.includes('"'))) v = `"${v.replace(/"/g, '""')}"`;
        return v ?? "";
      }).join(",")
    );
    const blob = new Blob([header + "\n" + rows.join("\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `technologies-${dayjs().format("YYYYMMDD-HHmm")}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const renderCell = (row: TechnologyRow, key: string) => {
    switch (key) {
      case "name":
        return <Typography variant="body2" sx={{ color: "white", fontSize: 12.5, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 280 }}>{row.name}</Typography>;
      case "resources_count":
        return <Typography variant="body2" sx={{ color: "white", fontWeight: 600 }}>{row.resources_count}</Typography>;
      case "type":
      case "category":
      case "subcategory":
      case "owner":
        return <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.7)", fontSize: 11 }}>{(row as any)[key]}</Typography>;
      case "organization_usage_pct":
        return (
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, minWidth: 110 }}>
            <LinearProgress variant="determinate" value={row.organization_usage_pct}
              sx={{ flex: 1, height: 5, borderRadius: 2, bgcolor: "rgba(255,255,255,0.06)",
                "& .MuiLinearProgress-bar": { bgcolor: "#A100FF", borderRadius: 2 } }} />
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.6)", fontSize: 10, minWidth: 28 }}>
              {row.organization_usage_pct}%
            </Typography>
          </Box>
        );
      case "status":
        return (
          <Chip icon={STATUS_ICONS[row.status] as any} label={row.status} size="small"
            sx={{ bgcolor: `${STATUS_COLOR[row.status]}20`, color: STATUS_COLOR[row.status], fontSize: 10, height: 20, textTransform: "capitalize" }} />
        );
      case "risk_level":
        return <Chip label={row.risk_level} size="small"
          sx={{ bgcolor: `${RISK_COLOR[row.risk_level]}20`, color: RISK_COLOR[row.risk_level], fontSize: 10, height: 18, textTransform: "capitalize" }} />;
      case "open_findings":
        return <Typography variant="caption" sx={{ color: row.open_findings > 0 ? STATUS_COLOR.warning : "rgba(255,255,255,0.4)", fontWeight: 600 }}>{row.open_findings}</Typography>;
      case "cve_count":
        return <Typography variant="caption" sx={{ color: row.cve_count > 0 ? STATUS_COLOR.critical : "rgba(255,255,255,0.4)", fontWeight: 600 }}>{row.cve_count}</Typography>;
      case "last_seen":
        return <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontSize: 11 }}>{fromNow(row.last_seen)}</Typography>;
      case "environments":
        return (
          <Box sx={{ display: "flex", gap: 0.25, flexWrap: "wrap" }}>
            {(row.environments || []).slice(0, 3).map((e) => (
              <Chip key={e} label={e} size="small" sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.7)", fontSize: 9, height: 16 }} />
            ))}
          </Box>
        );
      default:
        return null;
    }
  };

  const visibleColumnDefs = ALL_COLUMNS.filter((c) => visibleCols.includes(c.key));

  return (
    <Card sx={cardSx}>
      <CardContent sx={{ "&:last-child": { pb: 1 } }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1, flexWrap: "wrap", gap: 1 }}>
          <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>
            Technology Inventory
          </Typography>
          <Box sx={{ display: "flex", gap: 0.5 }}>
            <Tooltip title="Toggle columns">
              <IconButton size="small" onClick={(e) => setColMenuAnchor(e.currentTarget)}
                sx={{ color: "rgba(255,255,255,0.6)" }}>
                <ViewColumn fontSize="small" />
              </IconButton>
            </Tooltip>
            <Button size="small" startIcon={<Download />} onClick={exportCsv}
              sx={{ color: "rgba(255,255,255,0.7)", fontSize: 11 }}>
              Export CSV
            </Button>
          </Box>
        </Box>

        <Menu anchorEl={colMenuAnchor} open={!!colMenuAnchor} onClose={() => setColMenuAnchor(null)}>
          {ALL_COLUMNS.map((c) => (
            <MenuItem key={c.key} dense onClick={() => {
              setVisibleCols((prev) => prev.includes(c.key) ? prev.filter((k) => k !== c.key) : [...prev, c.key]);
            }}>
              <FormControlLabel
                control={<Checkbox size="small" checked={visibleCols.includes(c.key)} />}
                label={c.label}
                sx={{ pointerEvents: "none" }}
              />
            </MenuItem>
          ))}
        </Menu>

        {loading ? (
          <Skeleton variant="rectangular" height={420} sx={{ borderRadius: 1, bgcolor: "rgba(255,255,255,0.04)" }} />
        ) : (
          <>
            <TableContainer sx={{ maxHeight: 540 }}>
              <Table size="small" stickyHeader>
                <TableHead>
                  <TableRow sx={{ "& th": { bgcolor: "#1A1A1A", color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
                    {visibleColumnDefs.map((c) => (
                      <TableCell key={c.key} align={c.numeric ? "right" : "left"}>
                        <TableSortLabel active={sortKey === c.key} direction={sortDir} onClick={() => setSort(c.key)}
                          sx={{ color: "rgba(255,255,255,0.5) !important", "& .MuiTableSortLabel-icon": { color: "rgba(255,255,255,0.5) !important" } }}>
                          {c.label.toUpperCase()}
                        </TableSortLabel>
                      </TableCell>
                    ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pageRows.length === 0 ? (
                    <TableRow><TableCell colSpan={visibleColumnDefs.length} align="center" sx={{ color: "rgba(255,255,255,0.4)", py: 4 }}>
                      No technologies match the current filters.
                    </TableCell></TableRow>
                  ) : pageRows.map((row) => (
                    <TableRow key={row.id} hover
                      onClick={() => onRowClick?.(row)}
                      sx={{ cursor: onRowClick ? "pointer" : "default",
                        "& td": { color: "white", fontSize: 12, borderColor: "rgba(255,255,255,0.05)", py: 0.75 },
                        "&:hover": { bgcolor: "rgba(255,255,255,0.03)" } }}>
                      {visibleColumnDefs.map((c) => (
                        <TableCell key={c.key} align={c.numeric ? "right" : "left"}>{renderCell(row, c.key)}</TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            <TablePagination
              component="div" count={sorted.length} page={page}
              onPageChange={(_, p) => setPage(p)}
              rowsPerPage={perPage}
              onRowsPerPageChange={(e) => { setPerPage(parseInt(e.target.value, 10)); setPage(0); }}
              rowsPerPageOptions={[10, 25, 50, 100]}
              sx={{ color: "rgba(255,255,255,0.6)", "& .MuiTablePagination-actions svg": { color: "rgba(255,255,255,0.6)" } }}
            />
          </>
        )}
      </CardContent>
    </Card>
  );
}
