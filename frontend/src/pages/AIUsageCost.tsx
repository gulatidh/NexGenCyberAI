import React from "react";
import {
  Box, Typography, Card, CardContent, Grid, Alert, CircularProgress, Chip,
  Table, TableBody, TableCell, TableHead, TableRow, Divider,
} from "@mui/material";
import { BarChart, AttachMoney, Token, TrendingUp } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { useActiveClient } from "../contexts/ClientContext";
import { agentsApi } from "../services/api";

const COST_PER_1K = {
  azure_openai:   { input: 0.003, output: 0.004 },
  openai:         { input: 0.003, output: 0.006 },
  google_gemini:  { input: 0.001, output: 0.002 },
  aws_bedrock:    { input: 0.003, output: 0.004 },
  anthropic:      { input: 0.003, output: 0.015 },
};

function estimateCost(tokensIn: number, tokensOut: number, provider: string): number {
  const rates = (COST_PER_1K as any)[provider] ?? { input: 0.003, output: 0.006 };
  return (tokensIn / 1000) * rates.input + (tokensOut / 1000) * rates.output;
}

function KpiCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string; color: string }) {
  return (
    <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
          <Box sx={{ color }}>{icon}</Box>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>{label}</Typography>
        </Box>
        <Typography variant="h5" sx={{ fontWeight: 800, color }}>{value}</Typography>
      </CardContent>
    </Card>
  );
}

export default function AIUsageCost() {
  const { clientId } = useActiveClient();

  const { data: runs, isLoading } = useQuery({
    queryKey: ["ai-usage", clientId],
    queryFn: () => agentsApi.listRuns(clientId),
    enabled: !!clientId,
  });

  if (!clientId) return <Alert severity="info" sx={{ mt: 2 }}>Select a client to view AI usage.</Alert>;

  const runList: any[] = Array.isArray(runs) ? runs : (runs as any)?.items ?? [];

  // Aggregate by provider
  const providerMap: Record<string, { runs: number; tokensIn: number; tokensOut: number; cost: number }> = {};
  let totalRuns = 0, totalTokensIn = 0, totalTokensOut = 0, totalCost = 0;

  runList.forEach((r: any) => {
    const provider = r.provider ?? r.ai_provider ?? "unknown";
    const tIn  = r.tokens_input  ?? r.input_tokens  ?? 0;
    const tOut = r.tokens_output ?? r.output_tokens ?? 0;
    const cost = estimateCost(tIn, tOut, provider);
    if (!providerMap[provider]) providerMap[provider] = { runs: 0, tokensIn: 0, tokensOut: 0, cost: 0 };
    providerMap[provider].runs++;
    providerMap[provider].tokensIn  += tIn;
    providerMap[provider].tokensOut += tOut;
    providerMap[provider].cost      += cost;
    totalRuns++; totalTokensIn += tIn; totalTokensOut += tOut; totalCost += cost;
  });

  const providerRows = Object.entries(providerMap).sort((a, b) => b[1].cost - a[1].cost);

  // Aggregate by agent type
  const agentMap: Record<string, { runs: number; tokensIn: number; tokensOut: number }> = {};
  runList.forEach((r: any) => {
    const agent = r.agent_type ?? "unknown";
    if (!agentMap[agent]) agentMap[agent] = { runs: 0, tokensIn: 0, tokensOut: 0 };
    agentMap[agent].runs++;
    agentMap[agent].tokensIn  += r.tokens_input  ?? r.input_tokens  ?? 0;
    agentMap[agent].tokensOut += r.tokens_output ?? r.output_tokens ?? 0;
  });
  const agentRows = Object.entries(agentMap).sort((a, b) => b[1].runs - a[1].runs);

  const hasData = totalRuns > 0 && (totalTokensIn + totalTokensOut) > 0;

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>AI Usage & Cost</Typography>
        <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
          Token consumption and estimated spend per provider and agent.
        </Typography>
      </Box>

      {isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", pt: 6 }}><CircularProgress /></Box>
      ) : !hasData ? (
        <>
          <Alert severity="info" sx={{ mb: 3, borderRadius: 2 }}>
            Token usage data is not available — the backend does not currently emit token counts with agent runs.
            Costs below are estimated from agent run counts using average token assumptions.
          </Alert>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid size={{ xs: 6, md: 3 }}>
              <KpiCard icon={<BarChart />}    label="Total Agent Runs"    value={String(runList.length)} color="#4285F4" />
            </Grid>
            <Grid size={{ xs: 6, md: 3 }}>
              <KpiCard icon={<Token />}       label="Est. Input Tokens"   value={runList.length > 0 ? `~${(runList.length * 2500).toLocaleString()}` : "—"} color="#9C27B0" />
            </Grid>
            <Grid size={{ xs: 6, md: 3 }}>
              <KpiCard icon={<TrendingUp />}  label="Est. Output Tokens"  value={runList.length > 0 ? `~${(runList.length * 800).toLocaleString()}`  : "—"} color="#FBBC04" />
            </Grid>
            <Grid size={{ xs: 6, md: 3 }}>
              <KpiCard icon={<AttachMoney />} label="Est. Spend (USD)"    value={runList.length > 0 ? `~$${(runList.length * 0.012).toFixed(2)}` : "$0.00"} color="#34A853" />
            </Grid>
          </Grid>
        </>
      ) : (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid size={{ xs: 6, md: 3 }}>
            <KpiCard icon={<BarChart />}    label="Total Agent Runs"    value={String(totalRuns)} color="#4285F4" />
          </Grid>
          <Grid size={{ xs: 6, md: 3 }}>
            <KpiCard icon={<Token />}       label="Input Tokens"   value={totalTokensIn.toLocaleString()}  color="#9C27B0" />
          </Grid>
          <Grid size={{ xs: 6, md: 3 }}>
            <KpiCard icon={<TrendingUp />}  label="Output Tokens"  value={totalTokensOut.toLocaleString()} color="#FBBC04" />
          </Grid>
          <Grid size={{ xs: 6, md: 3 }}>
            <KpiCard icon={<AttachMoney />} label="Est. Spend (USD)" value={`$${totalCost.toFixed(4)}`}   color="#34A853" />
          </Grid>
        </Grid>
      )}

      {runList.length > 0 && (
        <Grid container spacing={2}>
          {/* By provider */}
          <Grid size={{ xs: 12, md: 6 }}>
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <CardContent>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>By Provider</Typography>
                {providerRows.length === 0 ? (
                  <Typography variant="body2" sx={{ color: "text.secondary" }}>No provider data available.</Typography>
                ) : (
                  <Table size="small">
                    <TableHead>
                      <TableRow sx={{ "& th": { fontWeight: 700, fontSize: 11, color: "text.secondary", borderBottom: "1px solid rgba(255,255,255,0.08)" } }}>
                        <TableCell>Provider</TableCell>
                        <TableCell align="right">Runs</TableCell>
                        <TableCell align="right">Est. Cost</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {providerRows.map(([provider, data]) => (
                        <TableRow key={provider} sx={{ "&:hover": { bgcolor: "rgba(255,255,255,0.02)" } }}>
                          <TableCell sx={{ fontSize: 12 }}>
                            <Chip label={provider.replace(/_/g, " ")} size="small"
                              sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontWeight: 700, fontSize: 10, textTransform: "capitalize" }} />
                          </TableCell>
                          <TableCell align="right" sx={{ fontSize: 12 }}>{data.runs}</TableCell>
                          <TableCell align="right" sx={{ fontSize: 12, color: "#34A853" }}>
                            {data.cost > 0 ? `$${data.cost.toFixed(4)}` : "~"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </Grid>

          {/* By agent */}
          <Grid size={{ xs: 12, md: 6 }}>
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <CardContent>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>By Agent Type</Typography>
                {agentRows.length === 0 ? (
                  <Typography variant="body2" sx={{ color: "text.secondary" }}>No agent data available.</Typography>
                ) : (
                  <Table size="small">
                    <TableHead>
                      <TableRow sx={{ "& th": { fontWeight: 700, fontSize: 11, color: "text.secondary", borderBottom: "1px solid rgba(255,255,255,0.08)" } }}>
                        <TableCell>Agent</TableCell>
                        <TableCell align="right">Runs</TableCell>
                        <TableCell align="right">In Tokens</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {agentRows.map(([agent, data]) => (
                        <TableRow key={agent} sx={{ "&:hover": { bgcolor: "rgba(255,255,255,0.02)" } }}>
                          <TableCell sx={{ fontSize: 12, textTransform: "capitalize" }}>{agent.replace(/_/g, " ")}</TableCell>
                          <TableCell align="right" sx={{ fontSize: 12 }}>{data.runs}</TableCell>
                          <TableCell align="right" sx={{ fontSize: 12, color: "text.secondary" }}>
                            {data.tokensIn > 0 ? data.tokensIn.toLocaleString() : "—"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}
    </Box>
  );
}
