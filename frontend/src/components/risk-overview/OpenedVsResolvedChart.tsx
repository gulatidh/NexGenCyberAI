import React from "react";
import { Card, CardContent, Typography, Box, Skeleton } from "@mui/material";
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from "recharts";
import dayjs from "dayjs";
import { RiskIssuesFlowPoint } from "../../types";
import { cardSx } from "./tokens";

interface Props {
  data: RiskIssuesFlowPoint[];
  loading?: boolean;
}

export default function OpenedVsResolvedChart({ data, loading }: Props) {
  return (
    <Card sx={cardSx}>
      <CardContent>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1.5 }}>
          <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 600 }}>
            Opened vs Resolved
          </Typography>
          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>
            issue flow over time
          </Typography>
        </Box>
        {loading ? (
          <Skeleton variant="rectangular" height={260} sx={{ borderRadius: 1, bgcolor: "rgba(255,255,255,0.04)" }} />
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={data.map(d => ({ ...d, label: dayjs(d.date).format("MMM D") }))}>
              <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
              <XAxis dataKey="label" tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} />
              <YAxis tick={{ fill: "rgba(255,255,255,0.5)", fontSize: 11 }} />
              <Tooltip contentStyle={{ backgroundColor: "#1e232c", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 6 }}
                labelStyle={{ color: "white" }} />
              <Legend wrapperStyle={{ color: "rgba(255,255,255,0.6)", fontSize: 11 }} iconSize={10} />
              <Line type="monotone" dataKey="opened" name="Opened" stroke="#f44336" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="resolved" name="Resolved" stroke="#00e676" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
