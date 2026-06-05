import React from "react";
import { Card, CardContent, Typography, Box, Skeleton } from "@mui/material";
import * as Icons from "@mui/icons-material";
import type { CategoryBreakdown } from "../../types";
import { cardSx } from "./tokens";

interface Props {
  data: CategoryBreakdown[];
  loading?: boolean;
  selected: string;
  onSelect: (name: string) => void;
}

function IconFor({ name, color }: { name: string; color?: string }) {
  const Cmp = (Icons as any)[name] || Icons.Apps;
  return <Cmp sx={{ fontSize: 20, color: color || "rgba(255,255,255,0.7)" }} />;
}

export default function BreakdownByCategory({ data, loading, selected, onSelect }: Props) {
  return (
    <Card sx={{ ...cardSx, height: "100%" }}>
      <CardContent>
        <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 600, mb: 1.5 }}>
          Breakdown by Category
        </Typography>
        {loading ? (
          [0, 1, 2, 3].map((i) => (
            <Skeleton key={i} variant="rectangular" height={36} sx={{ mb: 0.5, bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1 }} />
          ))
        ) : data.length === 0 ? (
          <Typography variant="body2" sx={{ color: "text.secondary", textAlign: "center", py: 3 }}>
            No categories yet — sync assets to populate.
          </Typography>
        ) : (
          <Box sx={{ maxHeight: 340, overflowY: "auto", pr: 0.5 }}>
            {data.map((c) => {
              const isActive = selected === c.name;
              return (
                <Box key={c.name}
                  onClick={() => onSelect(isActive ? "" : c.name)}
                  sx={{
                    display: "flex", alignItems: "center", gap: 1.5, py: 1, px: 1, borderRadius: 1,
                    cursor: "pointer",
                    bgcolor: isActive ? `${c.color}15` : "transparent",
                    border: isActive ? `1px solid ${c.color}40` : "1px solid transparent",
                    transition: "background-color .15s",
                    "&:hover": { bgcolor: `${c.color}10` },
                  }}>
                  <IconFor name={c.icon} color={c.color} />
                  <Typography variant="body2" sx={{ color: "text.primary", flex: 1, fontSize: 13 }}>
                    {c.name}
                  </Typography>
                  <Typography variant="body2" sx={{ color: c.color, fontWeight: 600 }}>
                    {c.count}
                  </Typography>
                </Box>
              );
            })}
          </Box>
        )}
      </CardContent>
    </Card>
  );
}
