import React, { useMemo, useState } from "react";
import {
  Card, CardContent, Typography, Table, TableHead, TableRow, TableCell, TableBody,
  TableContainer, Chip, Skeleton, TableSortLabel,
} from "@mui/material";
import { RiskServiceRow } from "../../types";
import { cardSx, RISK_COLOR, SEV_COLOR } from "./tokens";

interface Props {
  data: RiskServiceRow[];
  loading?: boolean;
}

type SortKey = "name" | "asset_count" | "issues" | "critical" | "high";

export default function ServicesTable({ data, loading }: Props) {
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
          Services with Most Issues
        </Typography>
        {loading ? (
          <Skeleton variant="rectangular" height={220} sx={{ borderRadius: 1, bgcolor: "rgba(255,255,255,0.04)" }} />
        ) : data.length === 0 ? (
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.4)", textAlign: "center", py: 3 }}>
            No service data — sync assets to populate this table.
          </Typography>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ "& th": { color: "rgba(255,255,255,0.5)", fontSize: 11, fontWeight: 600, borderColor: "rgba(255,255,255,0.08)" } }}>
                  <TableCell>
                    <TableSortLabel active={sortKey === "name"} direction={sortDir} onClick={() => setSort("name")}
                      sx={{ color: "rgba(255,255,255,0.5) !important" }}>SERVICE</TableSortLabel>
                  </TableCell>
                  <TableCell>OWNER</TableCell>
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
                  <TableCell>RISK</TableCell>
                  <TableCell align="right">
                    <TableSortLabel active={sortKey === "issues"} direction={sortDir} onClick={() => setSort("issues")}
                      sx={{ color: "rgba(255,255,255,0.5) !important" }}>TOTAL</TableSortLabel>
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sorted.map((s) => (
                  <TableRow key={s.name} sx={{ "& td": { color: "white", fontSize: 12, borderColor: "rgba(255,255,255,0.05)", py: 1 } }}>
                    <TableCell sx={{ textTransform: "capitalize" }}>{s.name}</TableCell>
                    <TableCell sx={{ color: "rgba(255,255,255,0.5) !important", fontSize: 11 }}>{s.owner}</TableCell>
                    <TableCell align="right" sx={{ color: "rgba(255,255,255,0.7) !important" }}>{s.asset_count}</TableCell>
                    <TableCell align="right" sx={{ color: `${SEV_COLOR.critical} !important`, fontWeight: 600 }}>{s.critical}</TableCell>
                    <TableCell align="right" sx={{ color: `${SEV_COLOR.high} !important`, fontWeight: 600 }}>{s.high}</TableCell>
                    <TableCell>
                      <Chip label={s.risk_level} size="small"
                        sx={{ bgcolor: `${RISK_COLOR[s.risk_level]}20`, color: RISK_COLOR[s.risk_level],
                          fontSize: 10, height: 18, textTransform: "capitalize" }} />
                    </TableCell>
                    <TableCell align="right" sx={{ fontWeight: 700 }}>{s.issues}</TableCell>
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
