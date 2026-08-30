import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, Button, Chip, CircularProgress, Alert,
  Dialog, DialogTitle, DialogContent, DialogActions, TextField,
  Switch, Tooltip, Avatar, RadioGroup, FormControlLabel, Radio, FormLabel,
  FormControl, InputLabel, Select, MenuItem,
} from "@mui/material";
import { SmartToy, PlayArrow, CloudUpload, OpenInNew } from "@mui/icons-material";
import { useQuery } from "@tanstack/react-query";
import { agentCatalogApi, assetsApi, connectorsApi } from "../services/api";
import { toast } from "react-toastify";

export interface SelectOption {
  value: string;
  label: string;
  description?: string;
}

export interface InputField {
  type: "scan" | "framework" | "custom_prompt" | "text_context" | "select" | "file_upload" | "asset_select" | "platform_data";
  label: string;
  required: boolean;
  description?: string;
  options?: SelectOption[];
}

export const DEFAULT_SCHEMA: InputField[] = [
  { type: "custom_prompt", label: "Instructions (optional)", required: false,
    description: "Any specific instructions or context for this agent" },
];

export const GROUP_COLOR: Record<string, string> = {
  core_advisory: "#4285F4",
  architecture_engineering: "#34A853",
  threat_incident_response: "#EA4335",
  risk_compliance_governance: "#FBBC04",
  vulnerability_management: "#FF7043",
  agentic_ai_security: "#9C27B0",
  business_reporting: "#00ACC1",
  specialized_readiness: "#7CB342",
  operational: "#4285F4",
};

export interface AgentRunWizardAgent {
  id: string;
  key: string;
  name: string;
  group_key: string;
  group_label: string;
  description?: string;
  domain?: string;
  legacy_orchestrator: boolean;
  avatar_url?: string;
  input_schema?: InputField[];
  accent_color?: string;
}

export interface WizardScan {
  id: string;
  name?: string;
  connector_type?: string;
  created_at?: string;
  findings_count?: number;
  summary?: any;
  scan_type?: string;
}

export function AgentRunWizard({
  agent, scans, frameworks, clientId, color, onClose, onRunLegacy, onRunCatalog,
}: {
  agent: AgentRunWizardAgent;
  scans: WizardScan[];
  frameworks: any[];
  clientId: string;
  color: string;
  onClose: () => void;
  onRunLegacy: (scanId: string, framework: string) => void;
  onRunCatalog: (agentId: string, prompt: string, scanId: string, assetIds?: string[]) => void;
}) {
  const navigate = useNavigate();
  const schema = agent.input_schema?.length ? agent.input_schema : DEFAULT_SCHEMA;

  const [scanId, setScanId] = useState("");
  const [framework, setFramework] = useState("nist_csf");
  const [customPrompt, setCustomPrompt] = useState("");
  const [textContext, setTextContext] = useState("");
  const [selectValues, setSelectValues] = useState<Record<number, string>>({});

  const [fileData, setFileData] = useState<Record<number, { text: string; name: string; chars: number; truncated: boolean }>>({});
  const [fileLoading, setFileLoading] = useState<Record<number, boolean>>({});

  const [selectedAssets, setSelectedAssets] = useState<Record<number, string[]>>({});
  const [assetSearch, setAssetSearch] = useState("");

  const [platformPick, setPlatformPick] = useState<Record<number, string>>({});

  const needsAssets = schema.some((f) => f.type === "asset_select");
  const needsPlatform = schema.some((f) => f.type === "platform_data");

  const { data: assets = [] } = useQuery<any[]>({
    queryKey: ["wizard-assets", clientId],
    queryFn: () => assetsApi.list(clientId),
    enabled: !!clientId && needsAssets,
  });

  const { data: connectors = [] } = useQuery<any[]>({
    queryKey: ["wizard-connectors", clientId],
    queryFn: () => connectorsApi.list(clientId),
    enabled: !!clientId && needsPlatform,
  });

  const handleFileUpload = async (fieldIdx: number, file: File) => {
    setFileLoading((v) => ({ ...v, [fieldIdx]: true }));
    try {
      const result = await agentCatalogApi.extractFile(file);
      setFileData((v) => ({
        ...v,
        [fieldIdx]: { text: result.text, name: result.filename, chars: result.char_count, truncated: result.truncated },
      }));
    } catch {
      toast.error("Could not extract text from file");
    } finally {
      setFileLoading((v) => ({ ...v, [fieldIdx]: false }));
    }
  };

  const toggleAsset = (fieldIdx: number, assetId: string) => {
    setSelectedAssets((v) => {
      const cur = v[fieldIdx] || [];
      return { ...v, [fieldIdx]: cur.includes(assetId) ? cur.filter((id) => id !== assetId) : [...cur, assetId] };
    });
  };

  const needsScan = schema.some((f) => f.type === "scan" && f.required);
  const hasScanData = scans.length > 0;
  const missingRequiredScan = needsScan && !hasScanData && !textContext.trim();

  const allSelectedAssetIds = Object.values(selectedAssets).flat();

  const resolvedPlatformScanId = (() => {
    const platformField = schema.findIndex((f) => f.type === "platform_data");
    if (platformField < 0) return "";
    const connType = platformPick[platformField];
    if (!connType) return "";
    const match = scans
      .filter((s) => s.connector_type === connType || s.scan_type === connType)
      .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime())[0];
    return match?.id || "";
  })();

  const effectiveScanId = resolvedPlatformScanId || scanId;

  const canRun = !missingRequiredScan && schema.every((f, i) => {
    if (!f.required) return true;
    if (f.type === "scan") return !!scanId || !!textContext.trim();
    if (f.type === "framework") return !!framework;
    if (f.type === "custom_prompt") return !!customPrompt.trim();
    if (f.type === "text_context") return !!textContext.trim();
    if (f.type === "select") return !!selectValues[i];
    if (f.type === "file_upload") return !!fileData[i]?.text;
    if (f.type === "asset_select") return (selectedAssets[i]?.length || 0) > 0;
    if (f.type === "platform_data") return !!platformPick[i];
    return true;
  });

  const handleRun = () => {
    if (agent.legacy_orchestrator) {
      onRunLegacy(effectiveScanId, framework);
    } else {
      const parts: string[] = [];
      schema.forEach((f, i) => {
        if (f.type === "select" && selectValues[i]) {
          const opt = f.options?.find((o) => o.value === selectValues[i]);
          parts.push(`${f.label}: ${opt?.label || selectValues[i]}${opt?.description ? ` — ${opt.description}` : ""}`);
        }
        if (f.type === "file_upload" && fileData[i]?.text) {
          parts.push(`## Uploaded File: ${fileData[i].name}\n${fileData[i].text}`);
        }
        if (f.type === "platform_data" && platformPick[i]) {
          const conn = connectors.find((c: any) => c.connector_type === platformPick[i]);
          parts.push(`Platform data source: ${conn?.name || platformPick[i]} (${platformPick[i]})`);
        }
      });
      if (textContext.trim()) parts.push(`Data / Context:\n${textContext.trim()}`);
      if (customPrompt.trim()) parts.push(customPrompt.trim());
      onRunCatalog(agent.id, parts.join("\n\n"), effectiveScanId, allSelectedAssetIds.length ? allSelectedAssetIds : undefined);
    }
    onClose();
  };

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth
      slotProps={{ paper: { sx: { bgcolor: "background.paper" } } }}>
      <DialogTitle sx={{ pb: 1 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
          {agent.avatar_url ? (
            <Avatar src={agent.avatar_url} sx={{ width: 36, height: 36 }} />
          ) : (
            <Box sx={{ width: 36, height: 36, borderRadius: 1, bgcolor: `${color}1F`,
              display: "flex", alignItems: "center", justifyContent: "center" }}>
              <SmartToy sx={{ color, fontSize: 20 }} />
            </Box>
          )}
          <Box>
            <Typography sx={{ fontWeight: 700, fontSize: 16 }}>{agent.name}</Typography>
            <Typography variant="caption" sx={{ color: "text.secondary" }}>
              {agent.domain || agent.group_label}
            </Typography>
          </Box>
        </Box>
      </DialogTitle>

      <DialogContent dividers sx={{ borderColor: "divider", display: "flex", flexDirection: "column", gap: 2.5, pt: 2 }}>
        {agent.description && (
          <Typography variant="body2" sx={{ color: "text.secondary" }}>{agent.description}</Typography>
        )}

        {needsScan && !hasScanData && (
          <Alert severity="warning" sx={{ fontSize: 13 }}
            action={
              <Button size="small" endIcon={<OpenInNew sx={{ fontSize: 14 }} />}
                onClick={() => { onClose(); navigate("/platform/scans"); }}>
                Import data
              </Button>
            }>
            <strong>No completed scans found.</strong> You can paste your data in the text field below,
            or import scan data first.
          </Alert>
        )}

        {schema.map((field, i) => {
          if (field.type === "select") return (
            <Box key={i}>
              <FormLabel sx={{ fontSize: 13, color: "text.secondary", mb: 0.5, display: "block" }}>
                {field.label}{field.required ? " *" : ""}
              </FormLabel>
              {field.description && (
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>
                  {field.description}
                </Typography>
              )}
              <RadioGroup value={selectValues[i] || ""}
                onChange={(e) => setSelectValues((v) => ({ ...v, [i]: e.target.value }))}>
                {(field.options || []).map((opt) => (
                  <Box key={opt.value} onClick={() => setSelectValues((v) => ({ ...v, [i]: opt.value }))}
                    sx={{
                      border: 1,
                      borderColor: selectValues[i] === opt.value ? color : "divider",
                      borderRadius: 1, p: 1.5, mb: 1, cursor: "pointer",
                      bgcolor: selectValues[i] === opt.value ? `${color}12` : "transparent",
                      transition: "all 0.15s",
                      "&:hover": { borderColor: color, bgcolor: `${color}08` },
                    }}>
                    <FormControlLabel
                      value={opt.value}
                      control={<Radio size="small" sx={{ color, "&.Mui-checked": { color } }} />}
                      label={
                        <Box>
                          <Typography sx={{ fontWeight: 600, fontSize: 14 }}>{opt.label}</Typography>
                          {opt.description && (
                            <Typography variant="caption" sx={{ color: "text.secondary" }}>
                              {opt.description}
                            </Typography>
                          )}
                        </Box>
                      }
                      sx={{ m: 0, width: "100%" }}
                    />
                  </Box>
                ))}
              </RadioGroup>
            </Box>
          );

          if (field.type === "scan") {
            if (!hasScanData) return (
              <Alert key={i} severity="info" icon={<CloudUpload />} sx={{ fontSize: 12 }}>
                Paste your scan/VM data in the field below, or use the "Import data" button above
                to load findings from a scanner export (SARIF, Nessus, Burp, CSV…).
              </Alert>
            );
            return (
              <FormControl key={i} fullWidth size="small">
                <InputLabel>{field.label}{field.required ? " *" : ""}</InputLabel>
                <Select value={scanId} label={field.label + (field.required ? " *" : "")}
                  onChange={(e) => setScanId(e.target.value)}>
                  {!field.required && <MenuItem value="">— none —</MenuItem>}
                  {scans.map((s) => (
                    <MenuItem key={s.id} value={s.id}>
                      {s.name || s.id.slice(0, 8)}
                      {s.connector_type && (
                        <Chip label={s.connector_type} size="small"
                          sx={{ ml: 1, height: 16, fontSize: 10 }} />
                      )}
                    </MenuItem>
                  ))}
                </Select>
                {field.description && (
                  <Typography variant="caption" sx={{ color: "text.secondary", mt: 0.5 }}>{field.description}</Typography>
                )}
              </FormControl>
            );
          }

          if (field.type === "framework") {
            // Build a lookup map so renderValue can show the name instead of the raw key
            const fwMap: Record<string, { name: string; is_custom: boolean }> = {};
            frameworks.forEach((f: any) => {
              const v = f.value ?? f.framework;
              if (v) fwMap[v] = { name: f.label ?? f.name ?? v, is_custom: !!f.is_custom };
            });
            return (
              <FormControl key={i} fullWidth size="small">
                <InputLabel>{field.label}{field.required ? " *" : ""}</InputLabel>
                <Select
                  value={framework}
                  label={field.label + (field.required ? " *" : "")}
                  onChange={(e) => setFramework(e.target.value)}
                  renderValue={(v) => {
                    const entry = fwMap[v as string];
                    return (
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Typography variant="body2" sx={{ color: "text.primary" }}>
                          {entry?.name ?? v}
                        </Typography>
                        {entry?.is_custom && (
                          <Chip label="Custom" size="small"
                            sx={{ height: 16, fontSize: 9, fontWeight: 700, bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4" }} />
                        )}
                      </Box>
                    );
                  }}
                  MenuProps={{ slotProps: { paper: { sx: { bgcolor: "background.paper", maxHeight: 320 } } } }}
                >
                  {frameworks.map((f: any) => {
                    const val = f.value ?? f.framework;
                    const lbl = f.label ?? f.name ?? val;
                    return (
                      <MenuItem key={val} value={val} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Typography variant="body2" sx={{ color: "text.primary", flex: 1 }}>{lbl}</Typography>
                        {f.is_custom && (
                          <Chip label="Custom" size="small"
                            sx={{ height: 16, fontSize: 9, fontWeight: 700, bgcolor: "rgba(66,133,244,0.15)", color: "#4285F4" }} />
                        )}
                      </MenuItem>
                    );
                  })}
                </Select>
                {field.description && (
                  <Typography variant="caption" sx={{ color: "text.secondary", mt: 0.5 }}>{field.description}</Typography>
                )}
              </FormControl>
            );
          }

          if (field.type === "text_context") return (
            <TextField key={i} fullWidth size="small" multiline minRows={4}
              label={field.label + (field.required ? " *" : "")}
              placeholder={field.description}
              value={textContext} onChange={(e) => setTextContext(e.target.value)} />
          );

          if (field.type === "custom_prompt") return (
            <TextField key={i} fullWidth size="small" multiline minRows={3}
              label={field.label + (field.required ? " *" : "")}
              placeholder={field.description || "Any specific instructions or focus area…"}
              value={customPrompt} onChange={(e) => setCustomPrompt(e.target.value)} />
          );

          if (field.type === "file_upload") {
            const fd = fileData[i];
            const loading = fileLoading[i];
            return (
              <Box key={i}>
                <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mb: 0.5, display: "block" }}>
                  {field.label}{field.required ? " *" : ""}
                </Typography>
                {field.description && (
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>{field.description}</Typography>
                )}
                <Box
                  component="label"
                  sx={{
                    display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
                    border: "2px dashed", borderColor: fd ? "#34A853" : "divider",
                    borderRadius: 1.5, p: 2, cursor: "pointer", minHeight: 80,
                    bgcolor: fd ? "rgba(52,168,83,0.06)" : "transparent",
                    transition: "all 0.15s",
                    "&:hover": { borderColor: color, bgcolor: `${color}08` },
                  }}>
                  <input type="file" hidden accept=".pdf,.docx,.txt,.csv,.json,.xlsx,.log"
                    onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFileUpload(i, f); }} />
                  {loading ? (
                    <CircularProgress size={24} sx={{ color }} />
                  ) : fd ? (
                    <Box sx={{ textAlign: "center" }}>
                      <Typography sx={{ fontSize: 13, fontWeight: 700, color: "#34A853" }}>✓ {fd.name}</Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        {fd.chars.toLocaleString()} characters extracted{fd.truncated ? " (truncated to 12k)" : ""}
                      </Typography>
                      <Box sx={{ mt: 1, p: 1, bgcolor: "action.hover", borderRadius: 1, maxHeight: 60, overflow: "hidden" }}>
                        <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace", fontSize: 10 }}>
                          {fd.text.slice(0, 200)}…
                        </Typography>
                      </Box>
                    </Box>
                  ) : (
                    <Box sx={{ textAlign: "center" }}>
                      <CloudUpload sx={{ color: "text.disabled", fontSize: 32, mb: 0.5 }} />
                      <Typography variant="body2" sx={{ color: "text.secondary" }}>Click or drag to upload</Typography>
                      <Typography variant="caption" sx={{ color: "text.disabled" }}>PDF, DOCX, TXT, CSV, JSON, XLSX — max 20 MB</Typography>
                    </Box>
                  )}
                </Box>
              </Box>
            );
          }

          if (field.type === "asset_select") {
            const picked = selectedAssets[i] || [];
            const filtered = assets.filter((a: any) =>
              !assetSearch || [a.name, a.hostname, a.ip_address, a.resource_id]
                .some((v) => v?.toLowerCase().includes(assetSearch.toLowerCase()))
            );
            return (
              <Box key={i}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600 }}>
                    {field.label}{field.required ? " *" : ""}{" "}
                    {picked.length > 0 && (
                      <Chip label={`${picked.length} selected`} size="small"
                        sx={{ ml: 1, height: 16, fontSize: 10, bgcolor: `${color}20`, color }} />
                    )}
                  </Typography>
                </Box>
                {field.description && (
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>{field.description}</Typography>
                )}
                <TextField fullWidth size="small" placeholder="Search assets…"
                  value={assetSearch} onChange={(e) => setAssetSearch(e.target.value)}
                  sx={{ mb: 1, "& .MuiOutlinedInput-notchedOutline": { borderColor: "divider" } }} />
                <Box sx={{ maxHeight: 200, overflowY: "auto", border: 1, borderColor: "divider", borderRadius: 1 }}>
                  {assets.length === 0 ? (
                    <Typography variant="caption" sx={{ p: 2, display: "block", color: "text.disabled", textAlign: "center" }}>
                      No assets found for this client
                    </Typography>
                  ) : filtered.map((a: any) => {
                    const checked = picked.includes(a.id);
                    return (
                      <Box key={a.id} onClick={() => toggleAsset(i, a.id)}
                        sx={{
                          display: "flex", alignItems: "center", gap: 1.5, px: 1.5, py: 1,
                          cursor: "pointer", borderBottom: 1, borderColor: "divider",
                          bgcolor: checked ? `${color}12` : "transparent",
                          "&:hover": { bgcolor: checked ? `${color}18` : "action.hover" },
                        }}>
                        <Switch size="small" checked={checked} readOnly
                          sx={{ "& .MuiSwitch-switchBase.Mui-checked": { color }, pointerEvents: "none" }} />
                        <Box sx={{ flex: 1, minWidth: 0 }}>
                          <Typography sx={{ fontSize: 13, fontWeight: 600 }} noWrap>{a.name || a.resource_id}</Typography>
                          <Typography variant="caption" sx={{ color: "text.secondary" }} noWrap>
                            {[a.asset_class, a.ip_address || a.hostname, a.region].filter(Boolean).join(" · ")}
                          </Typography>
                        </Box>
                        {a.criticality && (
                          <Chip label={a.criticality} size="small"
                            sx={{ height: 16, fontSize: 9, bgcolor: a.criticality === "critical" ? "#EA433520" : "action.hover", color: a.criticality === "critical" ? "#EA4335" : "text.secondary" }} />
                        )}
                      </Box>
                    );
                  })}
                </Box>
              </Box>
            );
          }

          if (field.type === "platform_data") {
            const picked = platformPick[i];
            const platforms = connectors.reduce((acc: any[], c: any) => {
              if (!acc.find((x) => x.connector_type === c.connector_type)) acc.push(c);
              return acc;
            }, []);
            const latestScan = picked
              ? scans
                  .filter((s) => s.connector_type === picked || s.scan_type === picked)
                  .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime())[0]
              : null;
            return (
              <Box key={i}>
                <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, mb: 0.5, display: "block" }}>
                  {field.label}{field.required ? " *" : ""}
                </Typography>
                {field.description && (
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 1 }}>{field.description}</Typography>
                )}
                {platforms.length === 0 ? (
                  <Alert severity="info" sx={{ fontSize: 12 }}>
                    No platform connectors configured for this client.{" "}
                    <Button size="small" onClick={() => { onClose(); navigate("/platform/connections"); }} sx={{ p: 0, minWidth: 0, fontSize: 12 }}>
                      Add a connector
                    </Button>
                  </Alert>
                ) : (
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {platforms.map((c: any) => {
                      const ctype = c.connector_type;
                      const isSelected = picked === ctype;
                      const lastScan = scans
                        .filter((s) => s.connector_type === ctype || s.scan_type === ctype)
                        .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime())[0];
                      return (
                        <Box key={ctype} onClick={() => setPlatformPick((v) => ({ ...v, [i]: isSelected ? "" : ctype }))}
                          sx={{
                            border: 1.5, borderColor: isSelected ? color : "divider",
                            borderRadius: 1.5, px: 2, py: 1.5, cursor: "pointer", minWidth: 120,
                            bgcolor: isSelected ? `${color}12` : "transparent",
                            "&:hover": { borderColor: color, bgcolor: `${color}08` },
                          }}>
                          <Typography sx={{ fontSize: 13, fontWeight: 700, textTransform: "capitalize" }}>{ctype}</Typography>
                          <Typography variant="caption" sx={{ color: "text.secondary" }} noWrap>
                            {c.name}
                          </Typography>
                          <Typography variant="caption" sx={{ display: "block", color: lastScan ? "#34A853" : "text.disabled", fontSize: 10 }}>
                            {lastScan ? `Last scan: ${new Date(lastScan.created_at || "").toLocaleDateString()}` : "No scans yet"}
                          </Typography>
                        </Box>
                      );
                    })}
                  </Box>
                )}
                {latestScan && (
                  <Alert severity="success" sx={{ mt: 1, fontSize: 12, py: 0.5 }}>
                    Will use scan: <strong>{latestScan.name || latestScan.id.slice(0, 8)}</strong> — {latestScan.findings_count ?? "?"} findings
                  </Alert>
                )}
                {picked && !latestScan && (
                  <Alert severity="warning" sx={{ mt: 1, fontSize: 12, py: 0.5 }}>
                    No completed scans for {picked}. Run a scan first or switch to a different platform.
                  </Alert>
                )}
              </Box>
            );
          }

          return null;
        })}
      </DialogContent>

      <DialogActions sx={{ p: 2, gap: 1 }}>
        <Button onClick={onClose} sx={{ color: "text.secondary" }}>Cancel</Button>
        <Tooltip title={missingRequiredScan ? "Paste data above or import a scan first" : ""}>
          <span>
            <Button variant="contained" disabled={!canRun} startIcon={<PlayArrow />}
              onClick={handleRun}
              sx={{ bgcolor: color, "&:hover": { bgcolor: color, filter: "brightness(0.9)" } }}>
              Run Agent
            </Button>
          </span>
        </Tooltip>
      </DialogActions>
    </Dialog>
  );
}
