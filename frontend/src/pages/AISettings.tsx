/**
 * AI Provider Settings Page
 * Allows users to view all AI providers, check availability,
 * test connectivity, and select the active provider per session.
 */
import React, { useState, useEffect } from "react";
import {
  Box, Typography, Card, CardContent, Grid, Chip, Button,
  Select, MenuItem, FormControl, InputLabel, TextField,
  CircularProgress, Alert, Divider, IconButton, Tooltip, Switch, FormControlLabel,
} from "@mui/material";
import {
  CheckCircle, Cancel, PlayArrow, Psychology, Save, Visibility, VisibilityOff,
  AutoAwesome, ManageSearch, Forum, Edit, ExpandLess, NetworkCheck,
} from "@mui/icons-material";
import { Collapse } from "@mui/material";
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
  custom_openai: "⚫ Custom / Ollama",
};

type SecretField =
  | "openai_api_key" | "azure_openai_api_key" | "anthropic_api_key"
  | "google_api_key" | "aws_bedrock_access_key" | "aws_bedrock_secret_key"
  | "custom_openai_api_key";

const SECRET_FIELDS: SecretField[] = [
  "openai_api_key", "azure_openai_api_key", "anthropic_api_key",
  "google_api_key", "aws_bedrock_access_key", "aws_bedrock_secret_key",
  "custom_openai_api_key",
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
  // Which provider tile is currently expanded for inline editing. Only one
  // tile open at a time keeps the page compact and stops the eye from
  // bouncing between several long forms.
  const [expandedTile, setExpandedTile] = useState<string | null>(null);
  // Per-tile test result so each provider tile can show its own status.
  const [tileTest, setTileTest] = useState<Record<string, any>>({});
  const [tileTesting, setTileTesting] = useState<string | null>(null);

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

  const { data: learningStats } = useQuery({
    queryKey: ["ai-learning-stats"],
    queryFn: aiApi.learningStats,
    retry: 0,
    staleTime: 30_000,
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

  const handleTileTest = async (providerKey: string) => {
    setTileTesting(providerKey);
    try {
      const result = await aiApi.testProvider({
        provider: providerKey,
        prompt: "Reply with the single word 'ok' to confirm the connection.",
      });
      setTileTest((m) => ({ ...m, [providerKey]: result }));
    } catch (e: any) {
      setTileTest((m) => ({ ...m, [providerKey]: { success: false, error: e?.message || "Test failed" } }));
    } finally {
      setTileTesting(null);
    }
  };

  const handleSave = () => {
    // Only send changed fields. Empty-string entries get sent (signals clear).
    const BOOL_KEYS = new Set(["self_critique_enabled", "semantic_learning_enabled", "blackboard_enabled"]);
    const payload: Record<string, any> = {};
    for (const [k, v] of Object.entries(form)) {
      if (v === null) continue;
      payload[k] = BOOL_KEYS.has(k) ? v === "true" : v;
    }
    if (Object.keys(payload).length === 0) {
      toast.info("No changes to save");
      return;
    }
    saveMutation.mutate(payload);
  };

  const inputSx = {
    "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" },
    "& .MuiInputBase-input": { color: "text.primary" },
    "& .MuiInputLabel-root": { color: "text.secondary" },
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
                sx={{ color: "text.secondary" }}>
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

  // Phase 5 toggles — auto-saved immediately on toggle so navigation doesn't
  // lose the change. form state still updated for instant visual feedback.
  const boolVal = (name: string): boolean => {
    if (name in form) return form[name] === "true";
    return !!config?.[name];
  };
  const setBool = (name: string, v: boolean) => {
    setForm((f) => ({ ...f, [name]: v ? "true" : "false" }));
    if (isAdmin) {
      aiApi.updateConfig({ [name]: v })
        .then(() => qc.invalidateQueries({ queryKey: ["ai-config"] }))
        .catch((e: any) => toast.error(`Could not save: ${e?.response?.data?.detail || e.message}`));
    }
  };

  const dirty = Object.values(form).some((v) => v !== null);

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
        <Psychology sx={{ color: "#4285F4", fontSize: 32 }} />
        <Box>
          <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>AI Provider Settings</Typography>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
            Configure and test AI providers — Claude, OpenAI, Gemini, AWS Bedrock, Azure OpenAI, Ollama / Custom
          </Typography>
        </Box>
      </Box>

      {isLoading ? (
        <CircularProgress sx={{ color: "#4285F4" }} />
      ) : (
        <Grid container spacing={2}>
          {/* Defaults & Save strip — slim row above the provider tiles */}
          <Grid size={{ xs: 12 }}>
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <CardContent sx={{ "&:last-child": { pb: 2 } }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
                  <Box sx={{ flex: "1 1 auto", minWidth: 220 }}>
                    <Typography variant="caption" sx={{ color: "#4285F4", fontWeight: 700, letterSpacing: 0.5, fontSize: 11, display: "block", mb: 0.5 }}>
                      DEFAULT AI PROVIDER — USED WHEN AN AGENT DOESN'T SPECIFY ONE
                    </Typography>
                    <Grid container spacing={1.5}>
                      <Grid size={{ xs: 12, sm: 6 }}>
                        <FormControl fullWidth size="small" sx={inputSx} disabled={!isAdmin}>
                          <InputLabel>Default Provider</InputLabel>
                          <Select
                            value={fieldVal("default_provider")}
                            onChange={(e) => setField("default_provider", e.target.value)}
                            label="Default Provider"
                            sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}>
                            <MenuItem value="">— None —</MenuItem>
                            {providers.map((p) => (
                              <MenuItem key={p.provider} value={p.provider}>
                                {PROVIDER_LOGOS[p.provider] || p.provider}
                              </MenuItem>
                            ))}
                          </Select>
                        </FormControl>
                      </Grid>
                    </Grid>
                  </Box>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    {dirty && (
                      <Chip label={`${Object.values(form).filter((v) => v !== null).length} unsaved`}
                        size="small" sx={{ bgcolor: "rgba(251,188,4,0.15)", color: "#FBBC04", fontWeight: 700, fontSize: 11 }} />
                    )}
                    <Tooltip title={!isAdmin ? "Admin role required to edit" : ""}>
                      <span>
                        <Button
                          variant="contained" startIcon={<Save />}
                          disabled={!isAdmin || !dirty || saveMutation.isPending}
                          onClick={handleSave}
                          sx={{ bgcolor: "#4285F4", color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}>
                          {saveMutation.isPending ? "Saving..." : "Save Changes"}
                        </Button>
                      </span>
                    </Tooltip>
                  </Box>
                </Box>
                {!isAdmin && (
                  <Alert severity="info" sx={{ mt: 1.5, bgcolor: "rgba(66,133,244,0.08)", color: "text.primary", py: 0.5 }}>
                    Read-only — admin role required to edit provider configuration.
                  </Alert>
                )}
              </CardContent>
            </Card>
          </Grid>

          {/* Provider tiles — click Edit to expand inline */}
          {providers.map((provider) => {
            const expanded = expandedTile === provider.provider;
            const tres = tileTest[provider.provider];
            return (
              <Grid size={{ xs: 12, sm: 6, md: expanded ? 12 : 4 }} key={provider.provider}>
                <Card
                  sx={{
                    bgcolor: provider.available ? "rgba(52,168,83,0.04)" : "#1E1E1E",
                    border: `1px solid ${expanded ? "#4285F4" : (provider.available ? "rgba(52,168,83,0.3)" : "rgba(255,255,255,0.08)")}`,
                    borderRadius: 2,
                    transition: "border-color .15s ease",
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 1 }}>
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.75 }}>
                          <Typography variant="h6" sx={{ color: "text.primary", fontSize: 15, fontWeight: 700 }}>
                            {PROVIDER_LOGOS[provider.provider] || provider.provider}
                          </Typography>
                          {provider.available
                            ? <CheckCircle sx={{ color: "#00e676", fontSize: 18 }} />
                            : <Cancel sx={{ color: "rgba(244,67,54,0.7)", fontSize: 18 }} />}
                        </Box>
                        <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mb: 1 }}>
                          <Chip
                            label={provider.available ? "Configured" : "Not Configured"}
                            size="small"
                            sx={{
                              height: 20, fontSize: 10, fontWeight: 700,
                              bgcolor: provider.available ? "rgba(0,230,118,0.12)" : "rgba(244,67,54,0.12)",
                              color: provider.available ? "#00e676" : "#f44336",
                            }}
                          />
                          {tres && (
                            <Chip
                              label={tres.success ? "Test ok" : "Test failed"}
                              size="small"
                              sx={{
                                height: 20, fontSize: 10, fontWeight: 700,
                                bgcolor: tres.success ? "rgba(66,133,244,0.15)" : "rgba(244,67,54,0.15)",
                                color: tres.success ? "#4285F4" : "#f44336",
                              }}
                            />
                          )}
                        </Box>
                        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 1 }}>
                          MODELS
                        </Typography>
                        <Box sx={{ mt: 0.5, mb: 0.5 }}>
                          {provider.models.slice(0, expanded ? 6 : 3).map((m) => (
                            <Chip key={m} label={m} size="small"
                              sx={{ mr: 0.5, mb: 0.5, bgcolor: "rgba(255,255,255,0.05)", color: "text.secondary", fontSize: 10, height: 20 }} />
                          ))}
                        </Box>
                      </Box>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                        <Tooltip title={!isAdmin ? "Admin role required" : (expanded ? "Collapse" : "Edit configuration")}>
                          <span>
                            <IconButton
                              size="small"
                              disabled={!isAdmin}
                              onClick={() => setExpandedTile(expanded ? null : provider.provider)}
                              sx={{
                                color: expanded ? "#4285F4" : "text.secondary",
                                bgcolor: expanded ? "rgba(66,133,244,0.1)" : "transparent",
                                "&:hover": { bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4" },
                              }}
                            >
                              {expanded ? <ExpandLess fontSize="small" /> : <Edit fontSize="small" />}
                            </IconButton>
                          </span>
                        </Tooltip>
                        <Tooltip title="Test connection">
                          <span>
                            <IconButton
                              size="small"
                              disabled={!provider.available || tileTesting === provider.provider}
                              onClick={() => handleTileTest(provider.provider)}
                              sx={{
                                color: "text.secondary",
                                "&:hover": { bgcolor: "rgba(52,168,83,0.12)", color: "#34A853" },
                              }}
                            >
                              {tileTesting === provider.provider
                                ? <CircularProgress size={14} sx={{ color: "#34A853" }} />
                                : <NetworkCheck fontSize="small" />}
                            </IconButton>
                          </span>
                        </Tooltip>
                      </Box>
                    </Box>

                    <Collapse in={expanded} unmountOnExit>
                      <Divider sx={{ borderColor: "divider", my: 1.5 }} />
                      <Grid container spacing={1.5}>
                        {provider.provider === "azure_openai" && (
                          <>
                            <Grid size={{ xs: 12, sm: 6 }}>{plainField("azure_openai_endpoint", "Endpoint URL")}</Grid>
                            <Grid size={{ xs: 12, sm: 3 }}>{plainField("azure_openai_deployment", "Deployment")}</Grid>
                            <Grid size={{ xs: 12, sm: 3 }}>{plainField("azure_openai_api_version", "API Version")}</Grid>
                            <Grid size={{ xs: 12 }}>{secretField("azure_openai_api_key", "Azure OpenAI API Key")}</Grid>
                          </>
                        )}
                        {provider.provider === "openai" && (
                          <Grid size={{ xs: 12 }}>{secretField("openai_api_key", "OpenAI API Key")}</Grid>
                        )}
                        {provider.provider === "anthropic" && (
                          <Grid size={{ xs: 12 }}>{secretField("anthropic_api_key", "Anthropic API Key")}</Grid>
                        )}
                        {provider.provider === "google_gemini" && (
                          <Grid size={{ xs: 12 }}>{secretField("google_api_key", "Google API Key")}</Grid>
                        )}
                        {provider.provider === "aws_bedrock" && (
                          <>
                            <Grid size={{ xs: 12, sm: 4 }}>{plainField("aws_bedrock_region", "Region")}</Grid>
                            <Grid size={{ xs: 12, sm: 4 }}>{secretField("aws_bedrock_access_key", "Access Key ID")}</Grid>
                            <Grid size={{ xs: 12, sm: 4 }}>{secretField("aws_bedrock_secret_key", "Secret Access Key")}</Grid>
                          </>
                        )}
                        {provider.provider === "custom_openai" && (
                          <>
                            <Grid size={{ xs: 12, sm: 6 }}>
                              {plainField("custom_openai_base_url", "Base URL")}
                              <Typography variant="caption" sx={{ color: "text.secondary", mt: 0.5, display: "block" }}>
                                Ollama on VM: <code>http://10.0.0.5:11434/v1</code> · Azure AI Foundry: <code>https://&lt;name&gt;.inference.ai.azure.com/v1</code> · Together AI: <code>https://api.together.xyz/v1</code>
                              </Typography>
                            </Grid>
                            <Grid size={{ xs: 12, sm: 3 }}>{plainField("custom_openai_model", "Model Name")}</Grid>
                            <Grid size={{ xs: 12, sm: 3 }}>
                              {secretField("custom_openai_api_key", "API Key")}
                              <Typography variant="caption" sx={{ color: "text.secondary", mt: 0.5, display: "block" }}>
                                Leave blank for Ollama (uses "ollama" default). Required for Azure AI Foundry / Together AI.
                              </Typography>
                            </Grid>
                          </>
                        )}
                      </Grid>
                      <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1.5 }}>
                        Stored values override deployment env vars. API keys are encrypted at rest and never echoed back — leave blank to keep the current value.
                      </Typography>
                      {tres && (
                        <Alert
                          severity={tres.success ? "success" : "error"}
                          sx={{ mt: 1.5, bgcolor: tres.success ? "rgba(52,168,83,0.08)" : "rgba(244,67,54,0.08)", color: "text.primary" }}
                        >
                          <Typography variant="body2" sx={{ fontWeight: 700, fontSize: 12 }}>
                            {tres.success ? `${provider.provider} responded` : `Error: ${tres.error}`}
                          </Typography>
                          {tres.response && (
                            <Typography variant="caption" sx={{ display: "block", mt: 0.5, fontFamily: "monospace", whiteSpace: "pre-wrap", opacity: 0.85 }}>
                              {String(tres.response).slice(0, 240)}
                            </Typography>
                          )}
                        </Alert>
                      )}
                    </Collapse>
                  </CardContent>
                </Card>
              </Grid>
            );
          })}

          {/* Learning & Critique (Phase 5) */}
          <Grid size={{ xs: 12 }}>
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(156,39,176,0.25)", borderRadius: 2 }}>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                  <AutoAwesome sx={{ color: "#CE93D8", fontSize: 22 }} />
                  <Typography variant="h6" sx={{ color: "text.primary" }}>Learning &amp; Critique</Typography>
                  <Chip label="Phase 5" size="small" sx={{ bgcolor: "rgba(156,39,176,0.18)", color: "#CE93D8", fontWeight: 700, fontSize: 10, height: 18, ml: 1 }} />
                </Box>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 2 }}>
                  Make agents better over time. Self-critique catches weak answers before they're saved; semantic learning extracts durable lessons from completed engagements and feeds them to future agent runs via cosine-similarity retrieval; the blackboard lets peer agents on the same scan see each other's conclusions.
                </Typography>

                {/* Stats strip */}
                <Grid container spacing={1.5} sx={{ mb: 2 }}>
                  <Grid size={{ xs: 6, sm: 3 }}>
                    <Box sx={{ p: 1.5, bgcolor: "rgba(156,39,176,0.06)", borderRadius: 1.5, border: "1px solid rgba(156,39,176,0.15)" }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>
                        Learnings stored
                      </Typography>
                      <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 24, lineHeight: 1.1, mt: 0.5 }}>
                        {learningStats?.learnings?.total ?? "—"}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                        +{learningStats?.learnings?.last_30d ?? 0} in 30d
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid size={{ xs: 6, sm: 3 }}>
                    <Box sx={{ p: 1.5, bgcolor: "rgba(66,133,244,0.06)", borderRadius: 1.5, border: "1px solid rgba(66,133,244,0.15)" }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>
                        Embedded
                      </Typography>
                      <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 24, lineHeight: 1.1, mt: 0.5 }}>
                        {learningStats?.learnings?.with_embeddings ?? "—"}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                        retrievable by cosine
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid size={{ xs: 6, sm: 3 }}>
                    <Box sx={{ p: 1.5, bgcolor: "rgba(52,168,83,0.06)", borderRadius: 1.5, border: "1px solid rgba(52,168,83,0.15)" }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>
                        Blackboard
                      </Typography>
                      <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 24, lineHeight: 1.1, mt: 0.5 }}>
                        {learningStats?.blackboard?.total ?? "—"}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                        +{learningStats?.blackboard?.last_30d ?? 0} in 30d
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid size={{ xs: 6, sm: 3 }}>
                    <Box sx={{ p: 1.5, bgcolor: "rgba(251,188,4,0.06)", borderRadius: 1.5, border: "1px solid rgba(251,188,4,0.15)" }}>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>
                        Self-critiqued
                      </Typography>
                      <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 24, lineHeight: 1.1, mt: 0.5 }}>
                        {learningStats?.self_critique?.runs_30d ?? "—"}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                        agent runs in 30d
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>

                {/* Toggles */}
                <Grid container spacing={1}>
                  <Grid size={{ xs: 12 }}>
                    <FormControlLabel
                      disabled={!isAdmin}
                      control={
                        <Switch
                          checked={boolVal("self_critique_enabled")}
                          onChange={(e) => setBool("self_critique_enabled", e.target.checked)}
                          sx={{ "& .MuiSwitch-thumb": { backgroundColor: boolVal("self_critique_enabled") ? "#FBBC04" : undefined } }}
                        />
                      }
                      label={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <ManageSearch sx={{ fontSize: 18, color: "#FBBC04" }} />
                          <Box>
                            <Typography sx={{ color: "text.primary", fontWeight: 600, fontSize: 13 }}>Self-critique pass</Typography>
                            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                              Each agent reviews its own output before saving. ~2× LLM cost per agent run.
                            </Typography>
                          </Box>
                        </Box>
                      }
                      sx={{ alignItems: "flex-start", mr: 0 }}
                    />
                  </Grid>
                  <Grid size={{ xs: 12 }}>
                    <FormControlLabel
                      disabled={!isAdmin}
                      control={
                        <Switch
                          checked={boolVal("semantic_learning_enabled")}
                          onChange={(e) => setBool("semantic_learning_enabled", e.target.checked)}
                        />
                      }
                      label={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <AutoAwesome sx={{ fontSize: 18, color: "#CE93D8" }} />
                          <Box>
                            <Typography sx={{ color: "text.primary", fontWeight: 600, fontSize: 13 }}>Semantic learning &amp; retrieval</Typography>
                            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                              Extract durable lessons from every completed agent run / workflow report and inject the top-5 cosine-similar lessons into future agent prompts. Adds an embeddings call per atom (cheap with text-embedding-3-small).
                            </Typography>
                          </Box>
                        </Box>
                      }
                      sx={{ alignItems: "flex-start", mr: 0 }}
                    />
                  </Grid>
                  <Grid size={{ xs: 12 }}>
                    <FormControlLabel
                      disabled={!isAdmin}
                      control={
                        <Switch
                          checked={boolVal("blackboard_enabled")}
                          onChange={(e) => setBool("blackboard_enabled", e.target.checked)}
                        />
                      }
                      label={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <Forum sx={{ fontSize: 18, color: "#34A853" }} />
                          <Box>
                            <Typography sx={{ color: "text.primary", fontWeight: 600, fontSize: 13 }}>Shared scan blackboard</Typography>
                            <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 11 }}>
                              When multiple agents run on the same scan, each reads peer agents' one-paragraph synopses as context. Default on — cost is negligible.
                            </Typography>
                          </Box>
                        </Box>
                      }
                      sx={{ alignItems: "flex-start", mr: 0 }}
                    />
                  </Grid>
                </Grid>

                <Divider sx={{ borderColor: "divider", my: 2 }} />
                <Typography variant="caption" sx={{ color: "#4285F4", fontWeight: 700, letterSpacing: 0.5, fontSize: 11 }}>
                  EMBEDDING MODEL
                </Typography>
                <Grid container spacing={2} sx={{ mt: 0.5 }}>
                  <Grid size={{ xs: 12, sm: 4 }}>
                    <FormControl fullWidth size="small" sx={inputSx} disabled={!isAdmin}>
                      <InputLabel>Embedding Provider</InputLabel>
                      <Select
                        value={fieldVal("embedding_provider") || "openai"}
                        onChange={(e) => setField("embedding_provider", e.target.value)}
                        label="Embedding Provider"
                        sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                      >
                        <MenuItem value="openai">OpenAI</MenuItem>
                        <MenuItem value="azure_openai">Azure OpenAI</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid size={{ xs: 12, sm: 8 }}>
                    <TextField
                      fullWidth size="small" label="Embedding Model"
                      value={fieldVal("embedding_model") || "text-embedding-3-small"}
                      onChange={(e) => setField("embedding_model", e.target.value)}
                      disabled={!isAdmin}
                      helperText="Default: text-embedding-3-small (1536-d, cheap). For Azure use the deployment name."
                      sx={inputSx}
                    />
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>

          {/* Test Console */}
          <Grid size={{ xs: 12 }}>
            <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <CardContent>
                <Typography variant="h6" sx={{ color: "text.primary", mb: 2 }}>Provider Test Console</Typography>
                <Grid container spacing={2} sx={{ alignItems: "flex-end" }}>
                  <Grid size={{ xs: 12, sm: 3 }}>
                    <FormControl fullWidth size="small">
                      <InputLabel sx={{ color: "text.secondary" }}>Provider</InputLabel>
                      <Select
                        value={selectedProvider}
                        onChange={(e) => { setSelectedProvider(e.target.value); setSelectedModel(""); }}
                        label="Provider"
                        sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
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
                      <InputLabel sx={{ color: "text.secondary" }}>Model</InputLabel>
                      <Select
                        value={selectedModel}
                        onChange={(e) => setSelectedModel(e.target.value)}
                        label="Model"
                        disabled={!activeProvider}
                        sx={{ color: "text.primary", "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
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
                      sx={{ "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }}
                    />
                  </Grid>
                  <Grid size={{ xs: 12, sm: 1 }}>
                    <Button
                      fullWidth
                      variant="contained"
                      onClick={handleTest}
                      disabled={!selectedProvider || testMutation.isPending}
                      startIcon={testMutation.isPending ? <CircularProgress size={16} /> : <PlayArrow />}
                      sx={{ bgcolor: "#4285F4", color: "#000", "&:hover": { bgcolor: "#00b8d4" } }}
                    >
                      Test
                    </Button>
                  </Grid>
                </Grid>

                {testResult && (
                  <Box sx={{ mt: 2 }}>
                    <Alert
                      severity={testResult.success ? "success" : "error"}
                      sx={{ bgcolor: testResult.success ? "rgba(0,230,118,0.1)" : "rgba(244,67,54,0.1)", color: "text.primary" }}
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
