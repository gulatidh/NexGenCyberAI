import React from "react";
import { Card, CardContent, Typography, Box, Skeleton, useTheme } from "@mui/material";
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from "recharts";
import dayjs from "dayjs";
import { RiskSeverityTrendPoint } from "../../types";
import { cardSx, SEV_COLOR } from "./tokens";

interface Props {
  data: RiskSeverityTrendPoint[];
  loading?: boolean;
}

export default function IssuesTrendChart({ data, loading }: Props) {
  const theme = useTheme();
  return (
    <Card sx={cardSx}>
      <CardContent>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1.5 }}>
          <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 600 }}>
            Issues by severity — last {data.length} days
          </Typography>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            new findings per day
          </Typography>
        </Box>
        {loading ? (
          <Skeleton variant="rectangular" height={260} sx={{ borderRadius: 1, bgcolor: "rgba(255,255,255,0.04)" }} />
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={data.map(d => ({ ...d, label: dayjs(d.date).format("MMM D") }))}>
              <defs>
                {(["critical", "high", "medium", "low"] as const).map(sev => (
                  <linearGradient key={sev} id={`grad-${sev}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={SEV_COLOR[sev]} stopOpacity={0.5} />
                    <stop offset="95%" stopColor={SEV_COLOR[sev]} stopOpacity={0.05} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
              <XAxis dataKey="label" tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} />
              <YAxis tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: "#1e232c", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 6 }}
                labelStyle={{ color: theme.palette.text.primary }}
              />
              <Legend wrapperStyle={{ color: theme.palette.text.secondary, fontSize: 11 }} iconSize={10} />
              {(["low", "medium", "high", "critical"] as const).map(sev => (
                <Area key={sev} type="monotone" dataKey={sev} stackId="1"
                  stroke={SEV_COLOR[sev]} strokeWidth={1.5}
                  fill={`url(#grad-${sev})`} fillOpacity={1} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
