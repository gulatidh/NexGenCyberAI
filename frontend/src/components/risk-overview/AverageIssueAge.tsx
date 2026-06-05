import React from "react";
import { Card, CardContent, Box, Typography, Grid, LinearProgress, Skeleton, Tooltip } from "@mui/material";
import { Warning } from "@mui/icons-material";
import { RiskAvgAge } from "../../types";
import { cardSx, SEV_COLOR } from "./tokens";

interface Props {
  data?: RiskAvgAge;
  loading?: boolean;
}

const ORDER: Array<keyof Omit<RiskAvgAge, "sla">> = ["critical", "high", "medium", "low"];
const LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

export default function AverageIssueAge({ data, loading }: Props) {
  return (
    <Card sx={cardSx}>
      <CardContent>
        <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 600, mb: 1 }}>
          Average Issue Age
        </Typography>
        <Typography variant="caption" sx={{ color: "text.secondary", mb: 2, display: "block" }}>
          Days open vs SLA threshold
        </Typography>
        <Grid container spacing={2}>
          {ORDER.map((sev) => {
            if (loading || !data) {
              return (
                <Grid key={sev} size={{ xs: 6, md: 3 }}>
                  <Skeleton variant="rectangular" height={80} sx={{ borderRadius: 1, bgcolor: "rgba(255,255,255,0.04)" }} />
                </Grid>
              );
            }
            const age = data[sev];
            const sla = data.sla[sev];
            const breached = age > sla;
            const pct = Math.min(100, (age / sla) * 100);
            const color = breached ? "#f44336" : SEV_COLOR[sev];
            return (
              <Grid key={sev} size={{ xs: 6, md: 3 }}>
                <Box sx={{ p: 1 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mb: 0.5 }}>
                    <Typography variant="caption" sx={{ color: SEV_COLOR[sev], fontWeight: 700, fontSize: 11 }}>
                      {LABEL[sev].toUpperCase()}
                    </Typography>
                    {breached && (
                      <Tooltip title={`Past SLA (${sla}d)`}>
                        <Warning sx={{ color: "#f44336", fontSize: 14 }} />
                      </Tooltip>
                    )}
                  </Box>
                  <Box sx={{ display: "flex", alignItems: "baseline", gap: 0.5, mb: 0.5 }}>
                    <Typography sx={{ color: breached ? "#f44336" : "white", fontSize: 22, fontWeight: 700, lineHeight: 1 }}>
                      {age.toFixed(0)}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>days</Typography>
                  </Box>
                  <LinearProgress variant="determinate" value={pct}
                    sx={{ height: 4, borderRadius: 2, bgcolor: "rgba(255,255,255,0.06)",
                      "& .MuiLinearProgress-bar": { bgcolor: color } }} />
                  <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, mt: 0.5, display: "block" }}>
                    SLA: {sla}d
                  </Typography>
                </Box>
              </Grid>
            );
          })}
        </Grid>
      </CardContent>
    </Card>
  );
}
