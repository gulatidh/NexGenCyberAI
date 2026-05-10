import React, { useMemo, useState } from "react";
import {
  Card, CardContent, Typography, Table, TableHead, TableRow, TableCell, TableBody,
  TableContainer, Chip, Skeleton, TableSortLabel,
} from "@mui/material";
import { RiskProjectRow } from "../../types";
import { cardSx, SEV_COLOR } from "./tokens";

interface Props {
  data: RiskProjectRow[];
  loading?: boolean;
}

type SortKey = "name" | "asset_count" | "issues" | "critical" | "high";

export default function ProjectsTable({ data, loading }: Props) {
  const [sortKey, setSortKey] = useState<SortKey>("issues");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const sorted = useMemo(() => {
    const dir = sortDir === "asc" ? 1 : -1;
    return [...data].sort((a, b) => {
      if (sortKey === "name") return a.name.localeCompare(b.name) * dir;
      return (((a as any)[sortKey] || 0) - ((b as any)[sortKey] || 0)) * dir;
    });
  }, [data, sortKey, sortDir]);

  const setSort = (k: SortKey) => {
    if (sortKey === k) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else { setSortKey(k); setSortDir("desc"); }
  };

  return (
    <Card sx={cardSx}>
      <CardContent sx={{ "&:last-child": { pb: 2 } }}>
        <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600, mb: 1.5 }}>
          Projects with Most Issues
        </Typography>
        {loading ? (
          <Skeleton variant="rectangular" height={220} sx={{ borderRadius: 1, bgcolor: "rgba(255,255,255,0.04)" }} />
        ) : data.length === 0 ? (
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.4)", textAlign: "center", py: 3 }}>
            No project data — assets without subscription/account/project IDs aren't grouped yet.
          </Typography>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
                  <TableCell>
                    <TableSortLabel active={sortKey === "name"} direction={sortDir} onClick={() => setSort("name")}
                      sx={{ color: "rgba(255,255,255,0.5) !important" }}>PROJECT</TableSortLabel>
                  </TableCell>
                  <TableCell>ENV</TableCell>
                  <TableCell align="right">
                    <TableSortLabel active={sortKey === "asset_count"} direction={sortDir} onClick={() => setSort("asset_count")}
                      sx={{ color: "rgba(255,255,255,0.5) !important" }}>ASSETS</TableSortLabel>
                  </TableCell>
                  <TableCell align="right">
                    <TableSortLabel active={sortKey === "critical"} direction={sortDir} onClick={() => setSort("critical")}
                      sx={{ color: "rgba(255,255,255,0.5) !important" }}>CRIT</TableSortLabel>
                  </TableCell>
                  <TableCell align="right">
                    <TableSortLabel active={sortKey === "high"} direction={sortDir} onClick={() => setSort("high")}
                      sx={{ color: "rgba(255,255,255,0.5) !important" }}>HIGH</TableSortLabel>
                  </TableCell>
                  <TableCell align="right">
                    <TableSortLabel active={sortKey === "issues"} direction={sortDir} onClick={() => setSort("issues")}
                      sx={{ color: "rgba(255,255,255,0.5) !important" }}>TOTAL</TableSortLabel>
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sorted.map((p) => (
                  <TableRow key={p.name} sx={{ "& td": { color: "white", fontSize: 12, borderColor: "rgba(255,255,255,0.05)", py: 1 } }}>
                    <TableCell sx={{ maxWidth: 260 }}>
                      <Typography variant="body2" sx={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "monospace", fontSize: 11 }}>
                        {p.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={p.environment} size="small"
                        sx={{ bgcolor: p.environment === "production" ? "rgba(244,67,54,0.15)" : "rgba(255,255,255,0.06)",
                          color: p.environment === "production" ? "#f44336" : "rgba(255,255,255,0.7)",
                          fontSize: 10, height: 18 }} />
                    </TableCell>
                    <TableCell align="right" sx={{ color: "rgba(255,255,255,0.7) !important" }}>{p.asset_count}</TableCell>
                    <TableCell align="right" sx={{ color: `${SEV_COLOR.critical} !important`, fontWeight: 600 }}>{p.critical}</TableCell>
                    <TableCell align="right" sx={{ color: `${SEV_COLOR.high} !important`, fontWeight: 600 }}>{p.high}</TableCell>
                    <TableCell align="right" sx={{ fontWeight: 700 }}>{p.issues}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </CardContent>
    </Card>
  );
}
