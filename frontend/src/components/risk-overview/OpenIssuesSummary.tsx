import React from "react";
import { Box, Card, CardContent, Grid, Typography, Skeleton } from "@mui/material";
import { TrendingUp, TrendingDown, TrendingFlat } from "@mui/icons-material";
import { RiskOverviewOpenIssues } from "../../types";
import { cardSx, SEV_COLOR, SEV_BG } from "./tokens";

interface Props {
  data?: RiskOverviewOpenIssues;
  loading?: boolean;
}

const ORDER: Array<keyof Omit<RiskOverviewOpenIssues, "deltas" | "info">> = ["critical", "high", "medium", "low"];
const LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

export default function OpenIssuesSummary({ data, loading }: Props) {
  if (loading || !data) {
    return (
      <Grid container spacing={2}>
        {ORDER.map((s) => (
          <Grid key={s} size={{ xs: 6, md: 3 }}>
            <Skeleton variant="rectangular" height={104} sx={{ borderRadius: 2, bgcolor: "rgba(255,255,255,0.04)" }} />
          </Grid>
        ))}
      </Grid>
    );
  }

  return (
    <Grid container spacing={2}>
      {ORDER.map((sev) => {
        const count = data[sev];
        const delta = data.deltas[sev as "critical" | "high" | "medium" | "low"];
        const TrendIcon = delta > 0 ? TrendingUp : delta < 0 ? TrendingDown : TrendingFlat;
        const trendColor = delta > 0 ? "#f44336" : delta < 0 ? "#00e676" : "rgba(255,255,255,0.4)";
        return (
          <Grid key={sev} size={{ xs: 6, md: 3 }}>
            <Card sx={{ ...cardSx, bgcolor: SEV_BG[sev], borderColor: `${SEV_COLOR[sev]}40` }}>
              <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
                  <Typography variant="caption" sx={{ color: SEV_COLOR[sev], fontWeight: 700, fontSize: 11, letterSpacing: 0.5 }}>
                    {LABEL[sev].toUpperCase()}
                  </Typography>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 0.25 }}>
                    <TrendIcon sx={{ fontSize: 14, color: trendColor }} />
                    <Typography variant="caption" sx={{ color: trendColor, fontSize: 11, fontWeight: 600 }}>
                      {Math.abs(delta).toFixed(0)}%
                    </Typography>
                  </Box>
                </Box>
                <Typography sx={{ color: "white", fontSize: 32, fontWeight: 700, lineHeight: 1.1 }}>{count}</Typography>
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", fontSize: 11 }}>
                  open · vs prev 7d
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        );
      })}
    </Grid>
  );
}
