import React from "react";
import { Box, Card, CardContent, LinearProgress, Typography, Skeleton } from "@mui/material";
import { RiskOverviewCompliance } from "../../types";
import { cardSx, SCORE_COLOR, FRAMEWORK_LABEL } from "./tokens";

interface Props {
  data: RiskOverviewCompliance[];
  loading?: boolean;
  onClick?: (framework: string) => void;
}

export default function ComplianceOverview({ data, loading, onClick }: Props) {
  if (loading) {
    return (
      <Box sx={{ display: "flex", gap: 2, overflowX: "auto", pb: 1 }}>
        {[0, 1, 2, 3, 4].map((i) => (
          <Skeleton key={i} variant="rectangular" width={220} height={120} sx={{ borderRadius: 2, bgcolor: "rgba(255,255,255,0.04)", flexShrink: 0 }} />
        ))}
      </Box>
    );
  }

  if (!data.length) {
    return (
      <Card sx={{ ...cardSx, p: 3, textAlign: "center" }}>
        <Typography sx={{ color: "text.secondary" }}>
          No framework data yet. Run a scan with a framework selected to populate compliance.
        </Typography>
      </Card>
    );
  }

  return (
    <Box sx={{ display: "flex", gap: 2, overflowX: "auto", pb: 1, "&::-webkit-scrollbar": { height: 4 } }}>
      {data.map((c) => {
        const color = SCORE_COLOR(c.score);
        return (
          <Card key={c.framework}
            onClick={() => onClick?.(c.framework)}
            sx={{ ...cardSx, minWidth: 220, maxWidth: 260, flexShrink: 0,
              cursor: onClick ? "pointer" : "default",
              transition: "border-color .15s",
              "&:hover": { borderColor: onClick ? color : "rgba(255,255,255,0.08)" } }}>
            <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11, fontWeight: 600, letterSpacing: 0.5 }}>
                {(FRAMEWORK_LABEL[c.framework] || c.framework).toUpperCase()}
              </Typography>
              <Box sx={{ display: "flex", alignItems: "baseline", gap: 1, mt: 0.5, mb: 1 }}>
                <Typography sx={{ color, fontSize: 30, fontWeight: 700, lineHeight: 1 }}>
                  {c.score.toFixed(0)}
                </Typography>
                <Typography sx={{ color: "text.secondary", fontSize: 14 }}>/ 100</Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={c.score}
                sx={{
                  height: 6, borderRadius: 3, mb: 1,
                  bgcolor: "rgba(255,255,255,0.06)",
                  "& .MuiLinearProgress-bar": { bgcolor: color, borderRadius: 3 },
                }}
              />
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                {c.compliant} / {c.total - c.not_applicable} compliant · {c.non_compliant} failing
              </Typography>
            </CardContent>
          </Card>
        );
      })}
    </Box>
  );
}
