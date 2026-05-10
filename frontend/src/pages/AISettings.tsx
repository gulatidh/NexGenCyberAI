/**
 * AI Provider Settings Page
 * Allows users to view all AI providers, check availability,
 * test connectivity, and select the active provider per session.
 */
import React, { useState, useEffect } from "react";
import {
  Box, Typography, Card, CardContent, Grid, Chip, Button,
  Select, MenuItem, FormControl, InputLabel, TextField,
  CircularProgress, Alert, Divider, IconButton, Tooltip,
} from "@mui/material";
import {
  CheckCircle, Cancel, PlayArrow, Psychology, Save, Visibility, VisibilityOff,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";
import { aiApi, adminApi } from "../services/api";
import { AIProvider, MyAccess } from "../types";

const PROVIDER_LOGOS: Record<string, string> = {
  anthropic: "🟣 Anthropic Claude",
  openai: "🟢 OpenAI GPT",
  azure_openai: "🔵 Azure OpenAI",
  google_gemini: "🟡 Google Gemini",
  aws_bedrock: "🟠 AWS Bedrock",
};

type SecretField =
  | "openai_api_key" | "azure_openai_api_key" | "anthropic_api_key"
  | "google_api_key" | "aws_bedrock_access_key" | "aws_bedrock_secret_key";

const SECRET_FIELDS: SecretField[] = [
  "openai_api_key", "azure_openai_api_key", "anthropic_api_key",
  "google_api_key", "aws_bedrock_access_key", "aws_bedrock_secret_key",
];

export default function AISettings() {
  const qc = useQueryClient();
  const [selectedProvider, setSelectedProvider] = useState("");
  const [selectedModel, setSelectedModel] = useState("");
  const [testPrompt, setTestPrompt] = useState("Summarise the top 3 cyber threats for a financial institution in 2025.");
  const [testResult, setTestResult] = useState<any>(null);

  // Config form state — separate from query data so admins can stage edits
  // before saving. `null` means "no change", `""` means "clear value".
  const [form, setForm] = useState<Record<string, string | null>>({});
  const [showSecret, setShowSecret] = useState<Record<string, boolean>>({});

  const { data, isLoading } = useQuery({
    queryKey: ["ai-providers"],
    queryFn: aiApi.listProviders,
  });

  const { data: me } = useQuery<MyAccess>({
    queryKey: ["my-access"],
    queryFn: adminApi.me,
    retry: 0,
    staleTime: 60_000,
  });
  const isAdmin = !!me?.is_admin;

  const { data: config, refetch: refetchConfig } = useQuery({
    queryKey: ["ai-config"],
    queryFn: aiApi.getConfig,
    retry: 0,
  });

  useEffect(() => {
    // Reset staged edits whenever the canonical config changes.
    setForm({});
  }, [config]);

  const providers: AIProvider[] = data?.providers || [];
  const activeProvider = providers.find((p) => p.provider === selectedProvider);

  const testMutation = useMutation({
    mutationFn: (payload: any) => aiApi.testProvider(payload),
    onSuccess: (result) => setTestResult(result),
  });

  const saveMutation = useMutation({
    mutationFn: (payload: Record<string, any>) => aiApi.updateConfig(payload),
    onSuccess: () => {
      toast.success("AI settings saved");
      qc.invalidateQueries({ queryKey: ["ai-config"] });
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
      setForm({});
      refetchConfig();
    },
    onError: (e: any) => toast.error(`Save failed: ${e?.response?.data?.detail || e.message}`),
  });

  const fieldVal = (name: string): string => {
    if (name in form) return form[name] ?? "";
    if (SECRET_FIELDS.includes(name as SecretField)) return ""; // never echo secrets
    return (config?.[name] as string | null) ?? "";
  };
  const setField = (name: string, v: string) => setForm((f) => ({ ...f, [name]: v }));

  const handleTest = () => {
    testMutation.mutate({
      provider: selectedProvider,
      model: selectedModel || undefined,
      prompt: testPrompt,
    });
  };

  const handleSave = () => {
    // Only send changed fields. Empty-string entries get sent (signals clear).
    const payload = Object.fromEntries(
      Object.entries(form).filter(([, v]) => v !== null)
    );
    if (Object.keys(payload).length === 0) {
      toast.info("No changes to save");
      return;
    }
    saveMutation.mutate(payload);
  };

  const inputSx = {
    "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" },
    "& .MuiInputBase-input": { color: "white" },
    "& .MuiInputLabel-root": { color: "rgba(255,255,255,0.5)" },
  };

  const secretField = (name: SecretField, label: string) => {
    const sourceKey = `${name}_source`;
    const configuredKey = `${name}_configured`;
    const source = (config?.[sourceKey] as string) || "none";
    const configured = !!config?.[configuredKey];
    const staged = name in form;
    const placeholder = configured
      ? `Configured (${source}) — leave blank to keep, type new value to replace`
      : "Not set";
    return (
      <TextField
        fullWidth size="small" label={label}
        type={showSecret[name] ? "text" : "password"}
        value={fieldVal(name)}
        onChange={(e) => setField(name, e.target.value)}
        placeholder={placeholder}
        helperText={staged ? (form[name] === "" ? "Will clear on save" : "Will replace on save") : undefined}
        sx={inputSx}
        slotProps={{
          input: {
            endAdornment: (
              <IconButton size="small" onClick={() => setShowSecret((s) => ({ ...s, [name]: !s[name] }))}
                sx={{ color: "rgba(255,255,255,0.4)" }}>
                {showSecret[name] ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
              </IconButton>
            ),
          },
        }}
      />
    );
  };

  const plainField = (name: string, label: string) => (
    <TextField
      fullWidth size="small" label={label}
      value={fieldVal(name)}
      onChange={(e) => setField(name, e.target.value)}
      sx={inputSx}
    />
  );

  const dirty = Object.values(form).some((v) => v !== null);

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

          {/* Configuration */}
          <Grid size={{ xs: 12 }}>
            <Card sx={{ bgcolor: "#161b22", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <CardContent>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                  <Typography variant="h6" sx={{ color: "white" }}>Provider Configuration</Typography>
                  <Tooltip title={!isAdmin ? "Admin role required to edit" : ""}>
                    <span>
                      <Button
                        variant="contained" startIcon={<Save />}
                        disabled={!isAdmin || !dirty || saveMutation.isPending}
                        onClick={handleSave}
                        sx={{ bgcolor: "#00e5ff", color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}>
                        {saveMutation.isPending ? "Saving..." : "Save Changes"}
                      </Button>
                    </span>
                  </Tooltip>
                </Box>
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mb: 2 }}>
                  Stored values override the deployment env vars. API keys are encrypted at rest. Secrets are never echoed back — leave blank to keep the current value.
                </Typography>

                <Typography variant="caption" sx={{ color: "#00e5ff", fontWeight: 700, letterSpacing: 0.5, fontSize: 11 }}>
                  DEFAULTS
                </Typography>
                <Grid container spacing={2} sx={{ mt: 0.5, mb: 2 }}>
                  <Grid size={{ xs: 12, sm: 4 }}>
                    <FormControl fullWidth size="small" sx={inputSx}>
                      <InputLabel>Default Provider</InputLabel>
                      <Select
                        value={fieldVal("default_provider")}
                        onChange={(e) => setField("default_provider", e.target.value)}
                        label="Default Provider"
                        disabled={!isAdmin}
                        sx={{ color: "white", "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" } }}>
                        <MenuItem value="">— None —</MenuItem>
                        {providers.map((p) => (
                          <MenuItem key={p.provider} value={p.provider}>
                            {PROVIDER_LOGOS[p.provider] || p.provider}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid size={{ xs: 12, sm: 4 }}>{plainField("default_model", "Default Model")}</Grid>
                  <Grid size={{ xs: 12, sm: 4 }}>
                    <TextField fullWidth size="small" type="number" label="Default Temperature"
                      value={fieldVal("default_temperature")}
                      onChange={(e) => setField("default_temperature", e.target.value)}
                      slotProps={{ htmlInput: { step: 0.1, min: 0, max: 2 } }}
                      sx={inputSx} />
                  </Grid>
                </Grid>
                <Divider sx={{ borderColor: "rgba(255,255,255,0.08)", my: 2 }} />

                <Typography variant="caption" sx={{ color: "#00e5ff", fontWeight: 700, letterSpacing: 0.5, fontSize: 11 }}>
                  AZURE OPENAI
                </Typography>
                <Grid container spacing={2} sx={{ mt: 0.5, mb: 2 }}>
                  <Grid size={{ xs: 12, sm: 6 }}>{plainField("azure_openai_endpoint", "Endpoint URL")}</Grid>
                  <Grid size={{ xs: 12, sm: 3 }}>{plainField("azure_openai_deployment", "Deployment")}</Grid>
                  <Grid size={{ xs: 12, sm: 3 }}>{plainField("azure_openai_api_version", "API Version")}</Grid>
                  <Grid size={{ xs: 12, sm: 12 }}>{secretField("azure_openai_api_key", "Azure OpenAI API Key")}</Grid>
                </Grid>
                <Divider sx={{ borderColor: "rgba(255,255,255,0.08)", my: 2 }} />

                <Typography variant="caption" sx={{ color: "#00e5ff", fontWeight: 700, letterSpacing: 0.5, fontSize: 11 }}>
                  OPENAI
                </Typography>
                <Box sx={{ mt: 0.5, mb: 2 }}>{secretField("openai_api_key", "OpenAI API Key")}</Box>
                <Divider sx={{ borderColor: "rgba(255,255,255,0.08)", my: 2 }} />

                <Typography variant="caption" sx={{ color: "#00e5ff", fontWeight: 700, letterSpacing: 0.5, fontSize: 11 }}>
                  ANTHROPIC CLAUDE
                </Typography>
                <Box sx={{ mt: 0.5, mb: 2 }}>{secretField("anthropic_api_key", "Anthropic API Key")}</Box>
                <Divider sx={{ borderColor: "rgba(255,255,255,0.08)", my: 2 }} />

                <Typography variant="caption" sx={{ color: "#00e5ff", fontWeight: 700, letterSpacing: 0.5, fontSize: 11 }}>
                  GOOGLE GEMINI
                </Typography>
                <Box sx={{ mt: 0.5, mb: 2 }}>{secretField("google_api_key", "Google API Key")}</Box>
                <Divider sx={{ borderColor: "rgba(255,255,255,0.08)", my: 2 }} />

                <Typography variant="caption" sx={{ color: "#00e5ff", fontWeight: 700, letterSpacing: 0.5, fontSize: 11 }}>
                  AWS BEDROCK
                </Typography>
                <Grid container spacing={2} sx={{ mt: 0.5 }}>
                  <Grid size={{ xs: 12, sm: 4 }}>{plainField("aws_bedrock_region", "Region")}</Grid>
                  <Grid size={{ xs: 12, sm: 4 }}>{secretField("aws_bedrock_access_key", "Access Key ID")}</Grid>
                  <Grid size={{ xs: 12, sm: 4 }}>{secretField("aws_bedrock_secret_key", "Secret Access Key")}</Grid>
                </Grid>

                {!isAdmin && (
                  <Alert severity="info" sx={{ mt: 2, bgcolor: "rgba(0,229,255,0.08)", color: "white" }}>
                    Read-only — admin role required to edit AI provider configuration.
                  </Alert>
                )}
              </CardContent>
            </Card>
          </Grid>

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
