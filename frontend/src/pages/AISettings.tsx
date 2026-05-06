/**
 * AI Provider Settings Page
 * Allows users to view all AI providers, check availability,
 * test connectivity, and select the active provider per session.
 */
import React, { useState } from "react";
import {
  Box, Typography, Card, CardContent, Grid, Chip, Button,
  Select, MenuItem, FormControl, InputLabel, TextField,
  CircularProgress, Alert, Divider, List, ListItem, ListItemText,
} from "@mui/material";
import {
  CheckCircle, Cancel, PlayArrow, Psychology,
} from "@mui/icons-material";
import { useQuery, useMutation } from "@tanstack/react-query";
import { aiApi } from "../services/api";
import { AIProvider } from "../types";

const PROVIDER_LOGOS: Record<string, string> = {
  anthropic: "🟣 Anthropic Claude",
  openai: "🟢 OpenAI GPT",
  azure_openai: "🔵 Azure OpenAI",
  google_gemini: "🟡 Google Gemini",
  aws_bedrock: "🟠 AWS Bedrock",
};

export default function AISettings() {
  const [selectedProvider, setSelectedProvider] = useState("");
  const [selectedModel, setSelectedModel] = useState("");
  const [testPrompt, setTestPrompt] = useState("Summarise the top 3 cyber threats for a financial institution in 2025.");
  const [testResult, setTestResult] = useState<any>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["ai-providers"],
    queryFn: aiApi.listProviders,
  });

  const providers: AIProvider[] = data?.providers || [];
  const activeProvider = providers.find((p) => p.provider === selectedProvider);

  const testMutation = useMutation({
    mutationFn: (payload: any) => aiApi.testProvider(payload),
    onSuccess: (result) => setTestResult(result),
  });

  const handleTest = () => {
    testMutation.mutate({
      provider: selectedProvider,
      model: selectedModel || undefined,
      prompt: testPrompt,
    });
  };

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
        <Psychology sx={{ color: "#00e5ff", fontSize: 32 }} />
        <Box>
          <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>AI Provider Settings</Typography>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            Configure and test AI providers — Claude, OpenAI, Gemini, AWS Bedrock, Azure OpenAI
          </Typography>
        </Box>
      </Box>

      {isLoading ? (
        <CircularProgress sx={{ color: "#00e5ff" }} />
      ) : (
        <Grid container spacing={2}>
          {/* Provider Cards */}
          {providers.map((provider) => (
            <Grid size={{ xs: 12, sm: 6, md: 4 }} key={provider.provider}>
              <Card
                sx={{
                  bgcolor: provider.available ? "rgba(0,229,255,0.05)" : "#161b22",
                  border: `1px solid ${provider.available ? "rgba(0,229,255,0.3)" : "rgba(255,255,255,0.08)"}`,
                  borderRadius: 2,
                  cursor: "pointer",
                  transition: "all 0.2s",
                  "&:hover": { borderColor: "#00e5ff" },
                }}
                onClick={() => { setSelectedProvider(provider.provider); setSelectedModel(""); }}
              >
                <CardContent>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="h6" sx={{ color: "white", fontSize: 15 }}>
                      {PROVIDER_LOGOS[provider.provider] || provider.provider}
                    </Typography>
                    {provider.available ? (
                      <CheckCircle sx={{ color: "#00e676", fontSize: 20 }} />
                    ) : (
                      <Cancel sx={{ color: "#f44336", fontSize: 20 }} />
                    )}
                  </Box>
                  <Chip
                    label={provider.available ? "Configured" : "Not Configured"}
                    size="small"
                    sx={{
                      bgcolor: provider.available ? "rgba(0,230,118,0.15)" : "rgba(244,67,54,0.15)",
                      color: provider.available ? "#00e676" : "#f44336",
                      mb: 1.5,
                    }}
                  />
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block" }}>
                    Models:
                  </Typography>
                  {provider.models.slice(0, 3).map((m) => (
                    <Chip key={m} label={m} size="small" sx={{ mr: 0.5, mb: 0.5, bgcolor: "rgba(255,255,255,0.05)", color: "rgba(255,255,255,0.6)", fontSize: 10 }} />
                  ))}
                </CardContent>
              </Card>
            </Grid>
          ))}

          {/* Test Console */}
          <Grid size={{ xs: 12 }}>
            <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <CardContent>
                <Typography variant="h6" sx={{ color: "white", mb: 2 }}>Provider Test Console</Typography>
                <Grid container spacing={2} sx={{ alignItems: "flex-end" }}>
                  <Grid size={{ xs: 12, sm: 3 }}>
                    <FormControl fullWidth size="small">
                      <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Provider</InputLabel>
                      <Select
                        value={selectedProvider}
                        onChange={(e) => { setSelectedProvider(e.target.value); setSelectedModel(""); }}
                        label="Provider"
                        sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}
                      >
                        {providers.map((p) => (
                          <MenuItem key={p.provider} value={p.provider} disabled={!p.available}>
                            {PROVIDER_LOGOS[p.provider] || p.provider}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid size={{ xs: 12, sm: 3 }}>
                    <FormControl fullWidth size="small">
                      <InputLabel sx={{ color: "rgba(255,255,255,0.5)" }}>Model</InputLabel>
                      <Select
                        value={selectedModel}
                        onChange={(e) => setSelectedModel(e.target.value)}
                        label="Model"
                        disabled={!activeProvider}
                        sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}
                      >
                        {activeProvider?.models.map((m) => (
                          <MenuItem key={m} value={m}>{m}</MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid size={{ xs: 12, sm: 5 }}>
                    <TextField
                      fullWidth
                      size="small"
                      label="Test Prompt"
                      value={testPrompt}
                      onChange={(e) => setTestPrompt(e.target.value)}
                      slotProps={{ inputLabel: { sx: { color: 'rgba(255,255,255,0.5)' } }, htmlInput: { style: { color: 'white' } } }}
                      sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}
                    />
                  </Grid>
                  <Grid size={{ xs: 12, sm: 1 }}>
                    <Button
                      fullWidth
                      variant="contained"
                      onClick={handleTest}
                      disabled={!selectedProvider || testMutation.isPending}
                      startIcon={testMutation.isPending ? <CircularProgress size={16} /> : <PlayArrow />}
                      sx={{ bgcolor: "#00e5ff", color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}
                    >
                      Test
                    </Button>
                  </Grid>
                </Grid>

                {testResult && (
                  <Box sx={{ mt: 2 }}>
                    <Alert
                      severity={testResult.success ? "success" : "error"}
                      sx={{ bgcolor: testResult.success ? "rgba(0,230,118,0.1)" : "rgba(244,67,54,0.1)", color: "white" }}
                    >
                      <Typography variant="body2" sx={{ fontWeight: 700 }}>
                        {testResult.success ? `${testResult.provider} responded successfully` : `Error: ${testResult.error}`}
                      </Typography>
                      {testResult.response && (
                        <Typography variant="body2" sx={{ mt: 1, fontFamily: "monospace", whiteSpace: "pre-wrap" }}>
                          {testResult.response}
                        </Typography>
                      )}
                    </Alert>
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}
    </Box>
  );
}
