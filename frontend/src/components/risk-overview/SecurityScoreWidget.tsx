import React from "react";
import { Card, CardContent, Box, Typography, Skeleton } from "@mui/material";
import { TrendingUp, TrendingDown, TrendingFlat } from "@mui/icons-material";
import { ResponsiveContainer, LineChart, Line, YAxis } from "recharts";
import { RiskSecurityScore } from "../../types";
import { cardSx, SCORE_COLOR } from "./tokens";

interface Props {
  data?: RiskSecurityScore;
  loading?: boolean;
}

export default function SecurityScoreWidget({ data, loading }: Props) {
  if (loading || !data) {
    return (
      <Card sx={cardSx}>
        <CardContent>
          <Skeleton variant="text" width={140} height={20} sx={{ bgcolor: "rgba(255,255,255,0.06)" }} />
          <Skeleton variant="rectangular" height={120} sx={{ mt: 2, borderRadius: 1, bgcolor: "rgba(255,255,255,0.04)" }} />
        </CardContent>
      </Card>
    );
  }
  const color = SCORE_COLOR(data.current);
  const TrendIcon = data.delta > 0 ? TrendingUp : data.delta < 0 ? TrendingDown : TrendingFlat;
  const trendColor = data.delta > 0 ? "#00e676" : data.delta < 0 ? "#f44336" : "rgba(255,255,255,0.4)";
  return (
    <Card sx={cardSx}>
      <CardContent sx={{ p: 2.5 }}>
        <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, fontSize: 11, letterSpacing: 0.5 }}>
          OVERALL SECURITY SCORE
        </Typography>
        <Box sx={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", mt: 1, gap: 2 }}>
          <Box>
            <Box sx={{ display: "flex", alignItems: "baseline", gap: 1 }}>
              <Typography sx={{ color, fontSize: 56, fontWeight: 700, lineHeight: 1 }}>
                {data.current.toFixed(0)}
              </Typography>
              <Typography sx={{ color: "text.secondary", fontSize: 18 }}>/ 100</Typography>
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mt: 0.5 }}>
              <TrendIcon sx={{ fontSize: 16, color: trendColor }} />
              <Typography variant="body2" sx={{ color: trendColor, fontWeight: 600 }}>
                {data.delta > 0 ? "+" : ""}{data.delta.toFixed(1)}
              </Typography>
              <Typography variant="caption" sx={{ color: "text.secondary", ml: 0.5 }}>vs 7d ago</Typography>
            </Box>
          </Box>
          <Box sx={{ width: 180, height: 60 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data.history}>
                <YAxis hide domain={["dataMin - 5", "dataMax + 5"]} />
                <Line type="monotone" dataKey="score" stroke={color} strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
}
