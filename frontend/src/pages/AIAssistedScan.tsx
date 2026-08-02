import React, { useEffect, useRef, useState } from "react";
import {
  Alert, Box, Button, Card, CardContent, Chip, CircularProgress,
  Divider, LinearProgress, List, ListItem, ListItemIcon, ListItemText,
  Paper, TextField, Tooltip, Typography, useTheme,
} from "@mui/material";
import {
  AutoFixHigh, CheckCircle, HourglassEmpty, Psychology,
  RadioButtonUnchecked, RocketLaunch, Send, SmartToy,
} from "@mui/icons-material";
import { useNavigate } from "react-router-dom";
import { useActiveClient } from "../contexts/ClientContext";
import { apiClient } from "../services/api";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface ScanState {
  phase: string;
  connector_type: string | null;
  connector_id: string | null;
  scan_name: string | null;
  target: string | null;
  framework: string | null;
  ready_to_launch: boolean;
}

interface AgentRec {
  agent_type: string;
  display_name: string;
  reason: string;
  priority: number;
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function chatApi(clientId: string, message: string, history: Message[]) {
  const r = await apiClient.post(`/clients/${clientId}/ai-assisted-scan/chat`, {
    message,
    history,
  });
  return r.data as { message: string; state: ScanState };
}

async function launchApi(clientId: string, state: ScanState) {
  const r = await apiClient.post(`/clients/${clientId}/ai-assisted-scan/launch`, {
    connector_id: state.connector_id,
    scan_name: state.scan_name || "AI Guided Scan",
    target: state.target,
    framework: state.framework,
  });
  return r.data as { scan_id: string; scan_name: string };
}

async function nextStepsApi(clientId: string, scanId: string) {
  const r = await apiClient.get(`/clients/${clientId}/ai-assisted-scan/${scanId}/next-steps`);
  return r.data as { recommendations: AgentRec[]; summary: string };
}

// ── Phase labels ──────────────────────────────────────────────────────────────

const PHASE_STEPS = [
  { id: "intent",    label: "Understand intent" },
  { id: "connector", label: "Choose scanner" },
  { id: "target",    label: "Set target" },
  { id: "framework", label: "Framework" },
  { id: "confirm",   label: "Confirm" },
  { id: "ready",     label: "Ready" },
];

function phaseIndex(phase: string) {
  const idx = PHASE_STEPS.findIndex(p => p.id === phase);
  return idx === -1 ? 0 : idx;
}

// ── Config panel ──────────────────────────────────────────────────────────────

interface ConfigPanelProps {
  state: ScanState;
  launching: boolean;
  launched: boolean;
  scanId: string | null;
  nextSteps: { recommendations: AgentRec[]; summary: string } | null;
  nextStepsLoading: boolean;
  onLaunch: () => void;
  onNavigate: (path: string) => void;
}

function ConfigPanel({ state, launching, launched, scanId, nextSteps, nextStepsLoading, onLaunch, onNavigate }: ConfigPanelProps) {
  const theme = useTheme();
  const currentPhase = phaseIndex(state.phase);

  const fields = [
    { label: "Scanner", value: state.connector_type, done: !!state.connector_type },
    { label: "Target",  value: state.target,         done: !!state.target },
    { label: "Framework", value: state.framework || "None", done: state.phase !== "intent" && state.phase !== "connector" && state.phase !== "target" },
    { label: "Scan name", value: state.scan_name,    done: !!state.scan_name },
  ];

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 2, height: "100%" }}>

      {/* Progress stepper */}
      <Card variant="outlined" sx={{ bgcolor: "background.paper" }}>
        <CardContent sx={{ pb: "12px !important" }}>
          <Typography variant="caption" sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "text.secondary" }}>
            Progress
          </Typography>
          <List dense disablePadding sx={{ mt: 1 }}>
            {PHASE_STEPS.map((step, i) => {
              const done = i < currentPhase;
              const active = i === currentPhase;
              return (
                <ListItem key={step.id} disablePadding sx={{ py: 0.25 }}>
                  <ListItemIcon sx={{ minWidth: 28 }}>
                    {done
                      ? <CheckCircle sx={{ fontSize: 16, color: "#34A853" }} />
                      : active
                        ? <HourglassEmpty sx={{ fontSize: 16, color: "#4285F4" }} />
                        : <RadioButtonUnchecked sx={{ fontSize: 16, color: "action.disabled" }} />
                    }
                  </ListItemIcon>
                  <ListItemText
                    primary={step.label}
                    slotProps={{ primary: { sx: { fontSize: 13, color: done ? "#34A853" : active ? "text.primary" : "text.disabled" } } }}
                  />
                </ListItem>
              );
            })}
          </List>
        </CardContent>
      </Card>

      {/* Collected config */}
      <Card variant="outlined" sx={{ bgcolor: "background.paper" }}>
        <CardContent sx={{ pb: "12px !important" }}>
          <Typography variant="caption" sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "text.secondary" }}>
            Scan Configuration
          </Typography>
          <Box sx={{ mt: 1.5, display: "flex", flexDirection: "column", gap: 1 }}>
            {fields.map(f => (
              <Box key={f.label} sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <Typography variant="caption" color="text.secondary">{f.label}</Typography>
                {f.done && f.value
                  ? <Chip label={f.value} size="small" sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontSize: 11, maxWidth: 160, overflow: "hidden" }} />
                  : <Typography variant="caption" sx={{ color: "action.disabled" }}>—</Typography>
                }
              </Box>
            ))}
          </Box>
        </CardContent>
      </Card>

      {/* Launch button */}
      {state.ready_to_launch && !launched && (
        <Button
          variant="contained"
          size="large"
          startIcon={launching ? <CircularProgress size={16} color="inherit" /> : <RocketLaunch />}
          disabled={launching}
          onClick={onLaunch}
          sx={{ bgcolor: "#34A853", "&:hover": { bgcolor: "#2D9248" }, fontWeight: 700, py: 1.5 }}
          fullWidth
        >
          {launching ? "Launching…" : "Launch Scan"}
        </Button>
      )}

      {/* Post-launch */}
      {launched && scanId && (
        <Card variant="outlined" sx={{ bgcolor: "rgba(52,168,83,0.06)", borderColor: "rgba(52,168,83,0.3)" }}>
          <CardContent sx={{ pb: "12px !important" }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
              <CheckCircle sx={{ color: "#34A853", fontSize: 18 }} />
              <Typography variant="body2" sx={{ fontWeight: 700, color: "#34A853" }}>Scan launched!</Typography>
            </Box>
            <Button size="small" variant="outlined" fullWidth
              sx={{ borderColor: "rgba(52,168,83,0.4)", color: "#34A853", mb: 1 }}
              onClick={() => onNavigate(`/scans/${scanId}`)}>
              View Scan Progress
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Next steps */}
      {nextStepsLoading && (
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, px: 1 }}>
          <CircularProgress size={14} />
          <Typography variant="caption" color="text.secondary">Getting AI recommendations…</Typography>
        </Box>
      )}
      {nextSteps && (
        <Card variant="outlined" sx={{ bgcolor: "background.paper" }}>
          <CardContent sx={{ pb: "12px !important" }}>
            <Typography variant="caption" sx={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, color: "text.secondary" }}>
              Recommended Next Steps
            </Typography>
            {nextSteps.summary && (
              <Typography variant="caption" sx={{ display: "block", color: "text.secondary", mt: 0.5, mb: 1 }}>
                {nextSteps.summary}
              </Typography>
            )}
            <List dense disablePadding>
              {nextSteps.recommendations.map((rec, i) => (
                <ListItem key={rec.agent_type} disablePadding sx={{ py: 0.5 }}>
                  <ListItemIcon sx={{ minWidth: 28 }}>
                    <Psychology sx={{ fontSize: 16, color: "#9C27B0" }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={`${i + 1}. ${rec.display_name}`}
                    secondary={rec.reason}
                    slotProps={{ primary: { sx: { fontSize: 13, fontWeight: 600 } }, secondary: { sx: { fontSize: 11 } } }}
                  />
                </ListItem>
              ))}
            </List>
            <Button size="small" variant="outlined" fullWidth sx={{ mt: 1 }}
              onClick={() => onNavigate("/agents")}>
              Open AI Agents →
            </Button>
          </CardContent>
        </Card>
      )}
    </Box>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AIAssistedScan() {
  const { clientId } = useActiveClient();
  const navigate = useNavigate();

  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [state, setState] = useState<ScanState>({
    phase: "intent", connector_type: null, connector_id: null,
    scan_name: null, target: null, framework: null, ready_to_launch: false,
  });
  const [launching, setLaunching] = useState(false);
  const [launched, setLaunched] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [nextSteps, setNextSteps] = useState<{ recommendations: AgentRec[]; summary: string } | null>(null);
  const [nextStepsLoading, setNextStepsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Kick off with a greeting on first load
  useEffect(() => {
    if (!clientId || messages.length > 0) return;
    setLoading(true);
    chatApi(clientId, "Hello, I want to run a security assessment.", [])
      .then(res => {
        setMessages([{ role: "assistant", content: res.message }]);
        setState(res.state);
      })
      .catch(() => {
        setMessages([{
          role: "assistant",
          content: "Hi! I'm your AI Scan Guide. Tell me what you'd like to assess — for example: 'I want to scan my Azure environment' or 'Check my web application for vulnerabilities'.",
        }]);
      })
      .finally(() => setLoading(false));
  }, [clientId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  const handleSend = async () => {
    const text = input.trim();
    if (!text || loading || !clientId) return;

    const newMessages: Message[] = [...messages, { role: "user", content: text }];
    setMessages(newMessages);
    setInput("");
    setLoading(true);
    setError(null);

    try {
      // Pass only prior messages (not the one we just added user side) as history
      const res = await chatApi(clientId, text, messages);
      setMessages([...newMessages, { role: "assistant", content: res.message }]);
      setState(res.state);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "AI unavailable — check AI provider settings.");
    } finally {
      setLoading(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  };

  const handleLaunch = async () => {
    if (!clientId) return;
    setLaunching(true);
    setError(null);
    try {
      const result = await launchApi(clientId, state);
      setScanId(result.scan_id);
      setLaunched(true);
      setMessages(prev => [...prev, {
        role: "assistant",
        content: `✅ Scan "${result.scan_name}" has been launched! I'm now analysing the best next steps for you once it completes.`,
      }]);
      // Fetch next steps after a brief delay
      setNextStepsLoading(true);
      setTimeout(async () => {
        try {
          const ns = await nextStepsApi(clientId, result.scan_id);
          setNextSteps(ns);
        } catch { /* non-fatal */ } finally {
          setNextStepsLoading(false);
        }
      }, 3000);
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to launch scan.");
    } finally {
      setLaunching(false);
    }
  };

  const suggestions = [
    "Scan my Azure environment",
    "Check a web application for vulnerabilities",
    "Scan my network for open ports",
    "Review my source code for security issues",
  ];

  return (
    <Box sx={{ height: "calc(100vh - 64px)", display: "flex", flexDirection: "column", overflow: "hidden" }}>

      {/* Header */}
      <Box sx={{ px: 3, py: 2, borderBottom: "1px solid", borderColor: "divider", flexShrink: 0 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
          <SmartToy sx={{ color: "#4285F4", fontSize: 28 }} />
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1.2 }}>AI Assisted Scan</Typography>
            <Typography variant="caption" color="text.secondary">
              Tell me what you want to assess — I'll guide you through the rest
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* Body: chat left, config right */}
      <Box sx={{ flex: 1, display: "flex", overflow: "hidden" }}>

        {/* Chat panel */}
        <Box sx={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", borderRight: "1px solid", borderColor: "divider" }}>

          {/* Messages */}
          <Box sx={{ flex: 1, overflowY: "auto", p: 2.5, display: "flex", flexDirection: "column", gap: 2 }}>

            {messages.length === 0 && !loading && (
              <Box sx={{ textAlign: "center", mt: 6 }}>
                <SmartToy sx={{ fontSize: 48, color: "action.disabled", mb: 2 }} />
                <Typography color="text.secondary" sx={{ mb: 3 }}>
                  Start by telling me what you want to scan
                </Typography>
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", justifyContent: "center" }}>
                  {suggestions.map(s => (
                    <Chip key={s} label={s} variant="outlined" clickable size="small"
                      onClick={() => { setInput(s); inputRef.current?.focus(); }}
                      sx={{ cursor: "pointer" }} />
                  ))}
                </Box>
              </Box>
            )}

            {messages.map((msg, i) => (
              <Box
                key={i}
                sx={{
                  display: "flex",
                  justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                  gap: 1.5,
                  alignItems: "flex-start",
                }}
              >
                {msg.role === "assistant" && (
                  <Box sx={{ bgcolor: "#4285F420", borderRadius: "50%", p: 0.5, display: "flex", flexShrink: 0, mt: 0.5 }}>
                    <SmartToy sx={{ fontSize: 18, color: "#4285F4" }} />
                  </Box>
                )}
                <Paper
                  elevation={0}
                  sx={{
                    px: 2, py: 1.5,
                    maxWidth: "78%",
                    bgcolor: msg.role === "user" ? "#4285F4" : "action.hover",
                    color: msg.role === "user" ? "#fff" : "text.primary",
                    borderRadius: msg.role === "user" ? "18px 18px 4px 18px" : "18px 18px 18px 4px",
                    whiteSpace: "pre-wrap",
                    fontSize: 14,
                    lineHeight: 1.6,
                  }}
                >
                  {msg.content}
                </Paper>
              </Box>
            ))}

            {loading && (
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                <Box sx={{ bgcolor: "#4285F420", borderRadius: "50%", p: 0.5, display: "flex" }}>
                  <SmartToy sx={{ fontSize: 18, color: "#4285F4" }} />
                </Box>
                <Paper elevation={0} sx={{ px: 2, py: 1.5, bgcolor: "action.hover", borderRadius: "18px 18px 18px 4px" }}>
                  <Box sx={{ display: "flex", gap: 0.5, alignItems: "center" }}>
                    {[0, 1, 2].map(d => (
                      <Box key={d} sx={{
                        width: 6, height: 6, borderRadius: "50%", bgcolor: "#4285F4",
                        animation: "bounce 1.2s ease-in-out infinite",
                        animationDelay: `${d * 0.2}s`,
                        "@keyframes bounce": {
                          "0%, 80%, 100%": { transform: "scale(0.6)", opacity: 0.4 },
                          "40%": { transform: "scale(1)", opacity: 1 },
                        },
                      }} />
                    ))}
                  </Box>
                </Paper>
              </Box>
            )}

            <div ref={bottomRef} />
          </Box>

          {error && (
            <Alert severity="error" onClose={() => setError(null)} sx={{ mx: 2, mb: 1 }}>
              {error}
            </Alert>
          )}

          {/* Input bar */}
          <Box sx={{ p: 2, borderTop: "1px solid", borderColor: "divider", flexShrink: 0 }}>
            <Box sx={{ display: "flex", gap: 1 }}>
              <TextField
                inputRef={inputRef}
                fullWidth
                size="small"
                placeholder={state.ready_to_launch ? "Scan ready — click Launch on the right" : "Type your answer…"}
                value={input}
                onChange={e => setInput(e.target.value)}
                disabled={loading || launched}
                onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
                multiline
                maxRows={3}
              />
              <Button
                variant="contained"
                onClick={handleSend}
                disabled={!input.trim() || loading || launched}
                sx={{ bgcolor: "#4285F4", "&:hover": { bgcolor: "#3367D6" }, minWidth: 44, px: 1.5 }}
              >
                <Send fontSize="small" />
              </Button>
            </Box>
            <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
              Press Enter to send · Shift+Enter for new line
            </Typography>
          </Box>
        </Box>

        {/* Config panel */}
        <Box sx={{ width: 300, flexShrink: 0, p: 2, overflowY: "auto" }}>
          {clientId ? (
            <ConfigPanel
              state={state}
              launching={launching}
              launched={launched}
              scanId={scanId}
              nextSteps={nextSteps}
              nextStepsLoading={nextStepsLoading}
              onLaunch={handleLaunch}
              onNavigate={navigate}
            />
          ) : (
            <Alert severity="warning">Select a client in the top toolbar to begin.</Alert>
          )}
        </Box>
      </Box>
    </Box>
  );
}
