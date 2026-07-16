import React, { useEffect, useRef, useState } from "react";
import {
  Box, Fab, IconButton, InputAdornment, Paper,
  TextField, Tooltip, Typography, CircularProgress,
} from "@mui/material";
import { AutoAwesome, Close, Send, SmartToy, Refresh } from "@mui/icons-material";
import { useLocation } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { assistantApi } from "../services/api";

interface Message {
  role: "user" | "assistant";
  content: string;
}

const SUGGESTIONS = [
  "Why is Risk Overview empty?",
  "How do I run the Orchestrator?",
  "What does the Threat Register show?",
  "How do I add a cloud connector?",
];

export default function AssistantWidget() {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const location = useLocation();
  const endRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 100);
  }, [open]);

  const mutation = useMutation({
    mutationFn: (message: string) =>
      assistantApi.chat({
        message,
        current_page: location.pathname,
        history: messages.slice(-12),
      }),
    onSuccess: (data) => {
      setMessages((prev) => [...prev, { role: "assistant", content: data.reply }]);
    },
    onError: () => {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "I couldn't reach the AI provider. Make sure an AI provider is configured and tested in AI Settings.",
        },
      ]);
    },
  });

  const send = (text?: string) => {
    const message = (text ?? input).trim();
    if (!message || mutation.isPending) return;
    setMessages((prev) => [...prev, { role: "user", content: message }]);
    setInput("");
    mutation.mutate(message);
  };

  return (
    <>
      <Tooltip title={open ? "" : "Ask Monitara Assistant"} placement="left">
        <Fab
          size="medium"
          onClick={() => setOpen((o) => !o)}
          sx={{
            position: "fixed",
            bottom: 24,
            right: 24,
            zIndex: 1400,
            bgcolor: open ? "#4285F4" : "rgba(15,15,15,0.9)",
            color: open ? "#fff" : "#4285F4",
            border: "1px solid",
            borderColor: open ? "#4285F4" : "rgba(66,133,244,0.5)",
            boxShadow: open
              ? "0 0 0 4px rgba(66,133,244,0.15)"
              : "0 4px 20px rgba(0,0,0,0.5)",
            "&:hover": { bgcolor: "#4285F4", color: "#fff", borderColor: "#4285F4" },
            transition: "all 0.2s ease",
          }}
        >
          {open ? <Close /> : <AutoAwesome />}
        </Fab>
      </Tooltip>

      {open && (
        <Paper
          elevation={12}
          sx={{
            position: "fixed",
            bottom: 88,
            right: 24,
            width: 400,
            height: 520,
            display: "flex",
            flexDirection: "column",
            bgcolor: "#111",
            border: "1px solid rgba(66,133,244,0.35)",
            borderRadius: 2,
            overflow: "hidden",
            zIndex: 1399,
            boxShadow: "0 8px 40px rgba(0,0,0,0.7)",
          }}
        >
          {/* Header */}
          <Box
            sx={{
              px: 2, py: 1.25,
              display: "flex", alignItems: "center", gap: 1,
              borderBottom: "1px solid rgba(255,255,255,0.07)",
              bgcolor: "rgba(66,133,244,0.07)",
              flexShrink: 0,
            }}
          >
            <SmartToy sx={{ color: "#4285F4", fontSize: 20 }} />
            <Box sx={{ flex: 1 }}>
              <Typography sx={{ fontWeight: 700, fontSize: 13.5, color: "text.primary", lineHeight: 1.2 }}>
                Monitara Assistant
              </Typography>
              <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                Ask anything about the platform
              </Typography>
            </Box>
            {messages.length > 0 && (
              <Tooltip title="Clear conversation">
                <IconButton size="small" onClick={() => setMessages([])} sx={{ color: "text.secondary" }}>
                  <Refresh sx={{ fontSize: 16 }} />
                </IconButton>
              </Tooltip>
            )}
            <IconButton size="small" onClick={() => setOpen(false)} sx={{ color: "text.secondary" }}>
              <Close sx={{ fontSize: 16 }} />
            </IconButton>
          </Box>

          {/* Messages */}
          <Box
            sx={{
              flex: 1,
              overflowY: "auto",
              p: 1.5,
              display: "flex",
              flexDirection: "column",
              gap: 1,
              "&::-webkit-scrollbar": { width: 4 },
              "&::-webkit-scrollbar-track": { bgcolor: "transparent" },
              "&::-webkit-scrollbar-thumb": { bgcolor: "rgba(255,255,255,0.1)", borderRadius: 2 },
            }}
          >
            {messages.length === 0 && (
              <Box sx={{ mt: 2, textAlign: "center" }}>
                <AutoAwesome sx={{ color: "#4285F4", fontSize: 28, mb: 1 }} />
                <Typography sx={{ color: "text.secondary", fontSize: 13, mb: 2 }}>
                  Ask me anything about Monitara AI
                </Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
                  {SUGGESTIONS.map((s) => (
                    <Box
                      key={s}
                      onClick={() => send(s)}
                      sx={{
                        px: 1.5, py: 0.75,
                        borderRadius: 1.5,
                        border: "1px solid rgba(66,133,244,0.25)",
                        bgcolor: "rgba(66,133,244,0.06)",
                        cursor: "pointer",
                        fontSize: 12.5,
                        color: "text.secondary",
                        textAlign: "left",
                        transition: "all 0.15s",
                        "&:hover": {
                          bgcolor: "rgba(66,133,244,0.14)",
                          borderColor: "rgba(66,133,244,0.5)",
                          color: "text.primary",
                        },
                      }}
                    >
                      {s}
                    </Box>
                  ))}
                </Box>
              </Box>
            )}

            {messages.map((msg, i) => (
              <Box
                key={i}
                sx={{
                  alignSelf: msg.role === "user" ? "flex-end" : "flex-start",
                  maxWidth: "88%",
                }}
              >
                {msg.role === "assistant" && (
                  <Typography variant="caption" sx={{ color: "#4285F4", fontSize: 10.5, fontWeight: 600, display: "block", mb: 0.25, pl: 0.5 }}>
                    MONITARA
                  </Typography>
                )}
                <Box
                  sx={{
                    px: 1.5, py: 1,
                    borderRadius: msg.role === "user" ? "12px 12px 2px 12px" : "2px 12px 12px 12px",
                    bgcolor: msg.role === "user" ? "rgba(66,133,244,0.18)" : "rgba(255,255,255,0.05)",
                    border: "1px solid",
                    borderColor: msg.role === "user" ? "rgba(66,133,244,0.35)" : "rgba(255,255,255,0.08)",
                  }}
                >
                  <Typography
                    sx={{ fontSize: 13, color: "text.primary", whiteSpace: "pre-wrap", lineHeight: 1.6 }}
                  >
                    {msg.content}
                  </Typography>
                </Box>
              </Box>
            ))}

            {mutation.isPending && (
              <Box sx={{ alignSelf: "flex-start", display: "flex", alignItems: "center", gap: 0.75, px: 1.5, py: 1 }}>
                {[0, 1, 2].map((i) => (
                  <Box
                    key={i}
                    sx={{
                      width: 6, height: 6, borderRadius: "50%", bgcolor: "#4285F4",
                      animation: "monitaraPulse 1.2s ease-in-out infinite",
                      animationDelay: `${i * 0.18}s`,
                      "@keyframes monitaraPulse": {
                        "0%, 80%, 100%": { opacity: 0.25, transform: "scale(0.75)" },
                        "40%": { opacity: 1, transform: "scale(1)" },
                      },
                    }}
                  />
                ))}
              </Box>
            )}
            <div ref={endRef} />
          </Box>

          {/* Input */}
          <Box
            sx={{ px: 1.5, py: 1.25, borderTop: "1px solid rgba(255,255,255,0.07)", flexShrink: 0 }}
          >
            <TextField
              inputRef={inputRef}
              fullWidth
              size="small"
              placeholder="Ask about the platform…"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  send();
                }
              }}
              multiline
              maxRows={3}
              slotProps={{
                input: {
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        size="small"
                        onClick={() => send()}
                        disabled={!input.trim() || mutation.isPending}
                        sx={{ color: input.trim() ? "#4285F4" : "text.disabled" }}
                      >
                        {mutation.isPending ? (
                          <CircularProgress size={14} sx={{ color: "#4285F4" }} />
                        ) : (
                          <Send sx={{ fontSize: 16 }} />
                        )}
                      </IconButton>
                    </InputAdornment>
                  ),
                },
              }}
              sx={{
                "& .MuiOutlinedInput-root": {
                  color: "text.primary",
                  fontSize: 13,
                  bgcolor: "rgba(255,255,255,0.04)",
                  "& fieldset": { borderColor: "rgba(255,255,255,0.1)" },
                  "&:hover fieldset": { borderColor: "rgba(66,133,244,0.4)" },
                  "&.Mui-focused fieldset": { borderColor: "#4285F4" },
                },
              }}
            />
          </Box>
        </Paper>
      )}
    </>
  );
}
