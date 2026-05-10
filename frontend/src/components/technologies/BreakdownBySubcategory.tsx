import React, { useMemo, useState } from "react";
import { Card, CardContent, Typography, Box, Skeleton, TextField, InputAdornment } from "@mui/material";
import { Search } from "@mui/icons-material";
import * as Icons from "@mui/icons-material";
import type { SubcategoryBreakdown } from "../../types";
import { cardSx } from "./tokens";

interface Props {
  data: SubcategoryBreakdown[];
  loading?: boolean;
}

function IconFor({ name }: { name: string }) {
  const Cmp = (Icons as any)[name] || Icons.Apps;
  return <Cmp sx={{ fontSize: 20, color: "rgba(255,255,255,0.6)" }} />;
}

export default function BreakdownBySubcategory({ data, loading }: Props) {
  const [search, setSearch] = useState("");
  const filtered = useMemo(() => {
    if (!search) return data;
    return data.filter((d) => d.name.toLowerCase().includes(search.toLowerCase()));
  }, [data, search]);

  return (
    <Card sx={{ ...cardSx, height: "100%" }}>
      <CardContent>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1.5 }}>
          <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>
            Breakdown by Subcategory
          </Typography>
        </Box>
        <TextField
          size="small" placeholder="Filter…" value={search} onChange={(e) => setSearch(e.target.value)}
          sx={{ mb: 1, width: "100%",
            "& .MuiOutlinedInput-root": { color: "white", fontSize: 12, "& fieldset": { borderColor: "rgba(255,255,255,0.15)" } },
            "& input::placeholder": { color: "rgba(255,255,255,0.4)" } }}
          slotProps={{ input: { startAdornment: <InputAdornment position="start"><Search sx={{ fontSize: 16, color: "rgba(255,255,255,0.4)" }} /></InputAdornment> } }}
        />
        {loading ? (
          [0, 1, 2, 3, 4].map((i) => (
            <Skeleton key={i} variant="rectangular" height={32} sx={{ mb: 0.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1 }} />
          ))
        ) : filtered.length === 0 ? (
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.4)", textAlign: "center", py: 3 }}>
            None.
          </Typography>
        ) : (
          <Box sx={{ maxHeight: 300, overflowY: "auto", pr: 0.5 }}>
            {filtered.map((s) => (
              <Box key={s.name}
                sx={{ display: "flex", alignItems: "center", gap: 1.5, py: 0.75, px: 1, borderRadius: 1,
                  "&:hover": { bgcolor: "rgba(255,255,255,0.04)" } }}>
                <IconFor name={s.icon} />
                <Typography variant="body2" sx={{ color: "white", flex: 1, fontSize: 12.5 }}>
                  {s.name}
                </Typography>
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.6)", fontWeight: 600 }}>
                  {s.count}
                </Typography>
              </Box>
            ))}
          </Box>
        )}
      </CardContent>
    </Card>
  );
}
