import React from "react";
import { Card, CardContent, Typography, Box, Skeleton } from "@mui/material";
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts";
import type { TypeBreakdown } from "../../types";
import { cardSx, TYPE_COLORS } from "./tokens";

interface Props {
  data: TypeBreakdown[];
  loading?: boolean;
  selected: string;
  onSelect: (name: string) => void;
}

export default function BreakdownByType({ data, loading, selected, onSelect }: Props) {
  const total = data.reduce((acc, d) => acc + d.count, 0);

  return (
    <Card sx={{ ...cardSx, height: "100%" }}>
      <CardContent>
        <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600, mb: 1.5 }}>
          Breakdown by Type
        </Typography>
        {loading ? (
          <Skeleton variant="rectangular" height={260} sx={{ borderRadius: 1, bgcolor: "rgba(255,255,255,0.04)" }} />
        ) : data.length === 0 ? (
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.4)", textAlign: "center", py: 6 }}>
            No type data — sync assets to populate.
          </Typography>
        ) : (
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ position: "relative", width: 180, height: 180 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data}
                    dataKey="count"
                    nameKey="name"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={2}
                    onClick={(d) => onSelect(selected === (d as any).name ? "" : (d as any).name)}
                  >
                    {data.map((d, i) => (
                      <Cell key={d.name}
                        fill={TYPE_COLORS[i % TYPE_COLORS.length]}
                        stroke={selected === d.name ? "#fff" : undefined}
                        strokeWidth={selected === d.name ? 2 : 0}
                        style={{ cursor: "pointer" }} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: "#1e232c", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 6 }}
                    labelStyle={{ color: "white" }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <Box sx={{
                position: "absolute", inset: 0, display: "flex", alignItems: "center",
                justifyContent: "center", flexDirection: "column", pointerEvents: "none",
              }}>
                <Typography sx={{ color: "white", fontSize: 28, fontWeight: 700, lineHeight: 1 }}>
                  {total}
                </Typography>
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontSize: 10 }}>
                  TOTAL
                </Typography>
              </Box>
            </Box>
            <Box sx={{ flex: 1, maxHeight: 200, overflowY: "auto" }}>
              {data.map((d, i) => (
                <Box key={d.name}
                  onClick={() => onSelect(selected === d.name ? "" : d.name)}
                  sx={{
                    display: "flex", alignItems: "center", gap: 1, py: 0.5, px: 0.5, borderRadius: 1,
                    cursor: "pointer",
                    bgcolor: selected === d.name ? "rgba(255,255,255,0.05)" : "transparent",
                    "&:hover": { bgcolor: "rgba(255,255,255,0.04)" },
                  }}>
                  <Box sx={{ width: 10, height: 10, borderRadius: "50%", bgcolor: TYPE_COLORS[i % TYPE_COLORS.length], flexShrink: 0 }} />
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.8)", flex: 1, fontSize: 11 }}>
                    {d.name}
                  </Typography>
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontWeight: 600 }}>
                    {d.count}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}
