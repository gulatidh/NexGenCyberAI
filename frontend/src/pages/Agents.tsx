import React, { useState } from "react";
import {
  Box, Typography, Button, Card, CardContent, Grid,
  Chip, Select, MenuItem, FormControl, InputLabel,
  CircularProgress, Alert, Accordion, AccordionSummary,
  AccordionDetails, LinearProgress,
} from "@mui/material";
import { ExpandMore, SmartToy, PlayArrow, CheckCircle } from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { agentsApi, clientsApi, scansApi } from "../services/api";
import { Client, Scan, AgentType } from "../types";
import { toast } from "react-toastify";

const AGENT_DEFINITIONS = [
  {
    type: "orchestrator" as AgentType,
    title: "Full Assessment Orchestrator",
    description: "Runs all agents in sequence: VA → Framework → Threat Intel → Risk → Remediation → Compliance",
    icon: "🤖",
    color: "#00e5ff",
  },
  {
    type: "va_scanner" as AgentType,
    title: "Vulnerability Assessment Agent",
    description: "Analyses vulnerabilities, enriches with NVD CVE data, and prioritises by CVSS score",
    icon: "🔍",
    color: "#ff9800",
  },
  {
    type: "framework_analyst" as AgentType,
    title: "Framework Compliance Agent",
    description: "Maps findings to NIST CSF, NIST 800-53, CIS v8, GDPR, ISO 27001 controls",
    icon: "📋",
    color: "#7c4dff",
  },
  {
    type: "threat_intel" as AgentType,
    title: "Threat Intelligence Agent",
    description: "Correlates findings with MITRE ATT&CK TTPs and threat actor campaigns",
    icon: "🎯",
    color: "#f44336",
  },
  {
    type: "risk_manager" as AgentType,
    title: "Risk Management Agent",
    description: "Calculates risk scores using NIST SP 800-30, builds risk register with mitigations",
    icon: "⚠️",
    color: "#ffeb3b",
  },
  {
    type: "remediation" as AgentType,
    title: "Remediation Agent",
    description: "Generates step-by-step playbooks and ServiceNow ticket payloads for all findings",
    icon: "🔧",
    color: "#00e676",
  },
  {
    type: "compliance_monitor" as AgentType,
    title: "Compliance Monitor Agent",
    description: "Continuous compliance drift detection, audit reports, and maturity assessment",
    icon: "✅",
    color: "#ff6d00",
  },
];

export default function Agents() {
  const qc = useQueryClient();
  const [selectedClientId, setSelectedClientId] = useState("");
  const [selectedScanId, setSelectedScanId] = useState("");
  const [runningAgent, setRunningAgent] = useState<AgentType | null>(null);

  const { data: clients = [] } = useQuery<Client[]>({ queryKey: ["clients"], queryFn: clientsApi.list });
  const { data: scans = [] } = useQuery<Scan[]>({
    queryKey: ["scans", selectedClientId],
    queryFn: () => scansApi.list(selectedClientId),
    enabled: !!selectedClientId,
  });
  const { data: runs = [] } = useQuery({
    queryKey: ["agent-runs", selectedClientId],
    queryFn: () => agentsApi.listRuns(selectedClientId),
    enabled: !!selectedClientId,
    refetchInterval: 10_000,
  });

  const runMutation = useMutation({
    mutationFn: (data: any) => agentsApi.run(selectedClientId, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["agent-runs"] }); setRunningAgent(null); toast.success("Agent run complete"); },
    onError: (e: any) => { setRunningAgent(null); toast.error(e.response?.data?.detail || "Agent error"); },
  });

  const handleRunAgent = (agentType: AgentType) => {
    if (!selectedClientId) { toast.error("Select a client first"); return; }
    setRunningAgent(agentType);
    runMutation.mutate({ agent_type: agentType, scan_id: selectedScanId || undefined });
  };

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
        <SmartToy sx={{ color: "#00e5ff", fontSize: 32 }} />
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>AI Security Agents</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            AI-powered analysis agents using your configured provider (Claude / OpenAI / Gemini / Bedrock)
          </Typography>
        </Box>
      </Box>

      {/* Context selectors */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 4 }}>
          <FormControl fullWidth size="small">
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Client</InputLabel>
            <Select value={selectedClientId} onChange={(e) => setSelectedClientId(e.target.value)} label="Client"
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              {clients.map((c) => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </Select>
          </FormControl>
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <FormControl fullWidth size="small">
            <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Scan (optional)</InputLabel>
            <Select value={selectedScanId} onChange={(e) => setSelectedScanId(e.target.value)} label="Scan" disabled={!selectedClientId}
              sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
              <MenuItem value="">No specific scan</MenuItem>
              {scans.filter((s) => s.status === "completed").map((s) => (
                <MenuItem key={s.id} value={s.id}>{s.scan_type} — {new Date(s.created_at!).toLocaleDateString()}</MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>
      </Grid>

      {/* Agent Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        {AGENT_DEFINITIONS.map((agent) => {
          const isRunning = runningAgent === agent.type;
          return (
            <Grid size={{ xs: 12, sm: 6, md: 4 }} key={agent.type}>
              <Card sx={{
                bgcolor: "#161b22",
                border: `1px solid ${isRunning ? agent.color : "rgba(255,255,255,0.08)"}`,
                borderRadius: 2,
                transition: "border-color 0.2s",
              }}>
                {isRunning && <LinearProgress sx={{ bgcolor: "rgba(255,255,255,0.1)", "& .MuiLinearProgress-bar": { bgcolor: agent.color } }} />}
                <CardContent>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                    <Typography sx={{ fontSize: 28 }}>{agent.icon}</Typography>
                    <Chip label={agent.type.replace("_", " ")} size="small"
                      sx={{ bgcolor: `${agent.color}20`, color: agent.color, fontSize: 10, fontWeight: 600 }} />
                  </Box>
                  <Typography sx={{ color: "white", fontWeight: 600, mb: 0.5, fontSize: 14 }}>{agent.title}</Typography>
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 2 }}>
                    {agent.description}
                  </Typography>
                  <Button fullWidth variant="contained" size="small" startIcon={isRunning ? <CircularProgress size={14} /> : <PlayArrow />}
                    onClick={() => handleRunAgent(agent.type)}
                    disabled={!selectedClientId || isRunning || !!runningAgent}
                    sx={{ bgcolor: agent.color, color: agent.color === "#ffeb3b" ? "#000" : "#000", fontSize: 12, fontWeight: 600 }}>
                    {isRunning ? "Running..." : "Run Agent"}
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>

      {/* Agent Run History */}
      {selectedClientId && (
        <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
          <CardContent>
            <Typography variant="h6" sx={{ color: "white", mb: 2 }}>Recent Agent Runs</Typography>
            {(runs as any[]).length === 0 ? (
              <Typography sx={{ color: "rgba(255,255,255,0.3)", textAlign: "center", py: 2 }}>No agent runs yet</Typography>
            ) : (
              (runs as any[]).slice(0, 5).map((run: any) => (
                <Accordion key={run.id} sx={{ bgcolor: "#1e232c", mb: 1, border: "1px solid rgba(255,255,255,0.06)", borderRadius: "8px !important" }}>
                  <AccordionSummary expandIcon={<ExpandMore sx={{ color: "rgba(255,255,255,0.5)" }} />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, width: "100%" }}>
                      <Chip label={run.agent_type} size="small" sx={{ bgcolor: "rgba(0,229,255,0.1)", color: "#00e5ff", fontSize: 11 }} />
                      <Chip label={run.status} size="small"
                        sx={{ bgcolor: run.status === "completed" ? "rgba(0,230,118,0.15)" : "rgba(244,67,54,0.15)",
                          color: run.status === "completed" ? "#00e676" : "#f44336" }} />
                      <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", ml: "auto" }}>
                        {run.started_at ? new Date(run.started_at).toLocaleString() : ""}
                      </Typography>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    {run.output_data?.local_summary && (
                      <Alert severity="info" sx={{ mb: 1, bgcolor: "rgba(0,229,255,0.05)", color: "rgba(255,255,255,0.8)", fontSize: 12 }}>
                        {run.output_data.local_summary}
                      </Alert>
                    )}
                    <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.7)", fontFamily: "monospace", whiteSpace: "pre-wrap", fontSize: 12 }}>
                      {run.output_data?.output || run.error_message || "No output"}
                    </Typography>
                  </AccordionDetails>
                </Accordion>
              ))
            )}
          </CardContent>
        </Card>
      )}
    </Box>
  );
}
