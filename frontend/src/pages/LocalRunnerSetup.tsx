import { useState, useRef, useEffect } from "react";
import {
  Alert, Box, Button, Chip, CircularProgress, Collapse, Divider,
  Paper, Stack, Step, StepLabel, Stepper, Switch, TextField,
  Tooltip, Typography, LinearProgress,
} from "@mui/material";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";
import DownloadingIcon from "@mui/icons-material/Downloading";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import RefreshIcon from "@mui/icons-material/Refresh";
import ComputerIcon from "@mui/icons-material/Computer";
import CloudIcon from "@mui/icons-material/Cloud";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useMsal } from "@azure/msal-react";
import { loginRequest } from "../auth/msalConfig";
import { apiClient } from "../services/api";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ToolStatus {
  tool: string;
  label: string;
  desc: string;
  installed: boolean;
  version: string | null;
  binary_path: string | null;
  mode: string;
  has_local_exec: boolean;
}

interface StatusResponse {
  tools: ToolStatus[];
  owlet_bin: string;
  is_kali: boolean;
}

// ── API helpers ───────────────────────────────────────────────────────────────

const BASE = (apiClient.defaults.baseURL || "").replace(/\/$/, "");

const localRunnerApi = {
  status: (): Promise<StatusResponse> =>
    apiClient.get("/local-runner/status").then((r) => r.data),
  setMode: (tool: string, mode: string) =>
    apiClient.patch(`/local-runner/config/${tool}`, { mode }).then((r) => r.data),
  test: (tool: string): Promise<{ ok: boolean; output: string }> =>
    apiClient.post(`/local-runner/test/${tool}`).then((r) => r.data),
  cloudStatus: () =>
    apiClient.get("/local-runner/cloud/status").then((r) => r.data),
  cloudLink: (cloud_url: string, token: string) =>
    apiClient.post("/local-runner/cloud/link", { cloud_url, token }).then((r) => r.data),
  heartbeat: () =>
    apiClient.post("/local-runner/cloud/heartbeat").then((r) => r.data),
  githubConfig: () =>
    apiClient.get("/local-runner/github-config").then((r) => r.data),
  saveGithubConfig: (data: Record<string, string>) =>
    apiClient.post("/local-runner/github-config", data).then((r) => r.data),
};

// ── Wizard steps ──────────────────────────────────────────────────────────────

const STEPS = [
  "Check environment",
  "Install tools",
  "Configure dispatch",
  "Test & finish",
];

// ── Cloud pairing sub-component ───────────────────────────────────────────────

function CloudPairingCard() {
  const [open, setOpen] = useState(false);
  const [cloudUrl, setCloudUrl] = useState("https://owlet-api.azurewebsites.net");
  const [token, setToken] = useState("");
  const [linking, setLinking] = useState(false);
  const [linkResult, setLinkResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [pinging, setPinging] = useState(false);
  const [pingResult, setPingResult] = useState<string | null>(null);
  const qc = useQueryClient();

  const { data: cloudStatus } = useQuery({
    queryKey: ["local-runner-cloud-status"],
    queryFn: localRunnerApi.cloudStatus,
    retry: false,
    staleTime: 60_000,
  });

  const linked: boolean = cloudStatus?.linked ?? false;

  const handleLink = async () => {
    if (!cloudUrl || !token) return;
    setLinking(true);
    setLinkResult(null);
    try {
      const result = await localRunnerApi.cloudLink(cloudUrl.trim(), token.trim());
      setLinkResult({ ok: true, message: result.message || "Linked successfully" });
      qc.invalidateQueries({ queryKey: ["local-runner-cloud-status"] });
    } catch (e: any) {
      setLinkResult({ ok: false, message: e?.response?.data?.detail || String(e) });
    } finally {
      setLinking(false);
    }
  };

  const handleHeartbeat = async () => {
    setPinging(true);
    setPingResult(null);
    try {
      const result = await localRunnerApi.heartbeat();
      setPingResult(`Last seen: ${result.last_seen_at}`);
    } catch (e: any) {
      setPingResult(`Failed: ${e?.response?.data?.detail || String(e)}`);
    } finally {
      setPinging(false);
    }
  };

  return (
    <Paper variant="outlined" sx={{ p: 2, mt: 1 }}>
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between" }}>
        <Box>
          <Stack direction="row" sx={{ alignItems: "center", gap: 1 }}>
            <CloudIcon sx={{ color: linked ? "success.main" : "text.disabled", fontSize: 18 }} />
            <Typography sx={{ fontWeight: 600, fontSize: 13 }}>
              Cloud portal pairing
            </Typography>
            <Chip
              label={linked ? "Linked" : "Not linked"}
              size="small"
              color={linked ? "success" : "default"}
              variant="outlined"
            />
          </Stack>
          <Typography sx={{ fontSize: 12, color: "text.secondary", mt: 0.5 }}>
            {linked
              ? `Connected to ${cloudStatus?.cloud_url}`
              : "Pair this local runner with the Owlet cloud portal so the AI assistant can see your runner status."}
          </Typography>
        </Box>
        <Stack direction="row" sx={{ gap: 1 }}>
          {linked && (
            <Button size="small" variant="outlined" onClick={handleHeartbeat} disabled={pinging}>
              {pinging ? <CircularProgress size={12} /> : "Ping"}
            </Button>
          )}
          <Button size="small" onClick={() => setOpen((p) => !p)}>
            {open ? "Hide" : linked ? "Reconfigure" : "Set up"}
          </Button>
        </Stack>
      </Stack>

      {pingResult && (
        <Typography sx={{ fontSize: 11, color: "text.secondary", mt: 1 }}>{pingResult}</Typography>
      )}

      <Collapse in={open}>
        <Divider sx={{ my: 1.5 }} />
        <Typography sx={{ fontSize: 12, color: "text.secondary", mb: 1.5 }}>
          1. In the cloud portal, go to <strong>Settings → Local Runner → Generate Token</strong> and copy the token.
          2. Paste it here with the cloud API URL and click Link.
        </Typography>
        <Stack spacing={1.5}>
          <TextField
            label="Cloud API URL"
            size="small"
            fullWidth
            value={cloudUrl}
            onChange={(e) => setCloudUrl(e.target.value)}
            placeholder="https://owlet-api.azurewebsites.net"
          />
          <TextField
            label="Pairing token"
            size="small"
            fullWidth
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="owlet_runner_..."
            type="password"
          />
          <Button
            variant="contained"
            size="small"
            onClick={handleLink}
            disabled={!cloudUrl || !token || linking}
            startIcon={linking ? <CircularProgress size={12} /> : undefined}
          >
            {linking ? "Linking…" : "Link to cloud portal"}
          </Button>
          {linkResult && (
            <Alert severity={linkResult.ok ? "success" : "error"} sx={{ py: 0.5, fontSize: 12 }}>
              {linkResult.message}
            </Alert>
          )}
        </Stack>
      </Collapse>
    </Paper>
  );
}

// ── GitHub Actions config sub-component ──────────────────────────────────────

function GitHubActionsConfigCard() {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ token: "", repo_owner: "", repo_name: "", public_api_base: "" });
  const [saving, setSaving] = useState(false);
  const [saveResult, setSaveResult] = useState<{ ok: boolean; message: string } | null>(null);
  const qc = useQueryClient();

  const { data } = useQuery({
    queryKey: ["local-runner-github-config"],
    queryFn: localRunnerApi.githubConfig,
    retry: false,
    staleTime: 30_000,
  });

  const handleSave = async () => {
    setSaving(true);
    setSaveResult(null);
    const payload: Record<string, string> = {};
    if (form.token)           payload.token = form.token;
    if (form.repo_owner)      payload.repo_owner = form.repo_owner;
    if (form.repo_name)       payload.repo_name = form.repo_name;
    if (form.public_api_base) payload.public_api_base = form.public_api_base;
    try {
      const res = await localRunnerApi.saveGithubConfig(payload);
      setSaveResult({ ok: true, message: `Saved: ${(res.updated || []).join(", ") || "no changes"}` });
      qc.invalidateQueries({ queryKey: ["local-runner-github-config"] });
      setForm({ token: "", repo_owner: "", repo_name: "", public_api_base: "" });
    } catch (e: any) {
      setSaveResult({ ok: false, message: e?.response?.data?.detail || String(e) });
    } finally {
      setSaving(false);
    }
  };

  const rows = [
    { label: "GitHub Token", set: data?.token_set, value: data?.token_prefix ? `${data.token_prefix}…` : null },
    { label: "Repo Owner",   set: !!data?.repo_owner,  value: data?.repo_owner  || null },
    { label: "Repo Name",    set: !!data?.repo_name,   value: data?.repo_name   || null },
    { label: "Public API Base", set: !!data?.public_api_base, value: data?.public_api_base || null },
  ];

  const allSet = rows.every((r) => r.set);
  const missingApiBase = data && !data.public_api_base;

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between" }}>
        <Box>
          <Stack direction="row" sx={{ alignItems: "center", gap: 1 }}>
            <Typography sx={{ fontWeight: 600, fontSize: 13 }}>GitHub Actions configuration</Typography>
            <Chip
              label={allSet ? "Configured" : "Incomplete"}
              size="small"
              color={allSet ? "success" : "warning"}
              variant="outlined"
            />
          </Stack>
          <Typography sx={{ fontSize: 12, color: "text.secondary", mt: 0.5 }}>
            Required for: CodeQL, ZAP, Semgrep (GH Actions mode), Nmap (GH Actions mode). Not needed for local-mode scanners.
          </Typography>
        </Box>
        <Button size="small" onClick={() => setOpen((p) => !p)}>
          {open ? "Hide" : allSet ? "Edit" : "Configure"}
        </Button>
      </Stack>

      {/* Status grid */}
      <Stack spacing={0.5} sx={{ mt: 1.5 }}>
        {rows.map((r) => (
          <Stack key={r.label} direction="row" sx={{ alignItems: "center", gap: 1.5 }}>
            <Typography sx={{ fontSize: 12, color: "text.secondary", width: 130, flexShrink: 0 }}>{r.label}</Typography>
            <Chip
              label={r.set ? "Set" : "Missing"}
              size="small"
              color={r.set ? "success" : "error"}
              variant="outlined"
              sx={{ fontSize: 10, height: 18 }}
            />
            <Typography sx={{ fontSize: 11, color: "text.disabled", fontFamily: "monospace" }}>
              {r.value || "—"}
            </Typography>
          </Stack>
        ))}
      </Stack>

      {missingApiBase && (
        <Alert severity="warning" sx={{ mt: 1.5, fontSize: 12, py: 0.5 }}>
          Without a public API base URL, GitHub Actions runners can't post results back.
          Use the cloud portal URL: <strong>https://owlet-api.azurewebsites.net</strong>
        </Alert>
      )}

      <Collapse in={open}>
        <Divider sx={{ my: 1.5 }} />
        <Stack spacing={1.5}>
          <TextField label="GitHub PAT (leave blank to keep existing)" size="small" fullWidth
            value={form.token} onChange={(e) => setForm((p) => ({ ...p, token: e.target.value }))}
            placeholder="github_pat_..." type="password" />
          <Stack direction="row" sx={{ gap: 1.5 }}>
            <TextField label="Repo Owner" size="small" sx={{ flex: 1 }}
              value={form.repo_owner} onChange={(e) => setForm((p) => ({ ...p, repo_owner: e.target.value }))}
              placeholder={data?.repo_owner || "gulatidh"} />
            <TextField label="Repo Name" size="small" sx={{ flex: 1 }}
              value={form.repo_name} onChange={(e) => setForm((p) => ({ ...p, repo_name: e.target.value }))}
              placeholder={data?.repo_name || "NexGenCyberAI"} />
          </Stack>
          <TextField label="Public API Base URL" size="small" fullWidth
            value={form.public_api_base} onChange={(e) => setForm((p) => ({ ...p, public_api_base: e.target.value }))}
            placeholder={data?.public_api_base || "https://owlet-api.azurewebsites.net"} />
          <Button variant="contained" size="small" onClick={handleSave}
            disabled={saving || (!form.token && !form.repo_owner && !form.repo_name && !form.public_api_base)}
            startIcon={saving ? <CircularProgress size={12} /> : undefined}>
            {saving ? "Saving…" : "Save"}
          </Button>
          {saveResult && (
            <Alert severity={saveResult.ok ? "success" : "error"} sx={{ py: 0.5, fontSize: 12 }}>
              {saveResult.message}
            </Alert>
          )}
        </Stack>
      </Collapse>
    </Paper>
  );
}

// ── Airgap mode card ──────────────────────────────────────────────────────────

function AirgapCard() {
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  const { data, refetch } = useQuery({
    queryKey: ["local-runner-airgap"],
    queryFn: () => apiClient.get("/local-runner/airgap-config").then((r) => r.data),
    retry: false,
    staleTime: 30_000,
  });

  const enabled: boolean = data?.airgap_mode === true;

  const toggle = async () => {
    setSaving(true);
    setResult(null);
    try {
      await apiClient.post("/local-runner/airgap-config", { airgap_mode: !enabled });
      setResult({ ok: true, message: !enabled ? "Airgap mode enabled — all scanners now run locally." : "Airgap mode disabled — scanners will use GitHub Actions when configured." });
      refetch();
    } catch (e: any) {
      setResult({ ok: false, message: e?.response?.data?.detail || String(e) });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2, borderColor: enabled ? "success.main" : "divider" }}>
      <Stack direction="row" sx={{ alignItems: "flex-start", justifyContent: "space-between", gap: 2 }}>
        <Box sx={{ flex: 1 }}>
          <Stack direction="row" sx={{ alignItems: "center", gap: 1, mb: 0.5 }}>
            <Typography sx={{ fontWeight: 600, fontSize: 13 }}>Airgap Mode</Typography>
            <Chip
              label={enabled ? "ENABLED" : "Disabled"}
              size="small"
              color={enabled ? "success" : "default"}
              variant={enabled ? "filled" : "outlined"}
              sx={{ fontSize: 10, height: 18 }}
            />
          </Stack>
          <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
            When enabled, ALL scanners run locally via subprocess — no GitHub Actions, no public URL required.
            Ideal for air-gapped environments with Azure Private Endpoint AI. Each tool must be installed locally first.
          </Typography>
          {result && (
            <Alert severity={result.ok ? "success" : "error"} sx={{ mt: 1, py: 0.5, fontSize: 12 }}>
              {result.message}
            </Alert>
          )}
        </Box>
        <Tooltip title={enabled ? "Disable airgap mode" : "Enable airgap mode"}>
          <span>
            <Switch
              checked={enabled}
              onChange={toggle}
              disabled={saving}
              color="success"
            />
          </span>
        </Tooltip>
      </Stack>
    </Paper>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function LocalRunnerSetup() {
  const [step, setStep] = useState(0);
  const [installLog, setInstallLog] = useState<Record<string, string[]>>({});
  const [installing, setInstalling] = useState<Record<string, boolean>>({});
  const [installDone, setInstallDone] = useState<Record<string, boolean>>({});
  const [installError, setInstallError] = useState<Record<string, string>>({});
  const [testResults, setTestResults] = useState<
    Record<string, { ok: boolean; output: string } | null>
  >({});
  const [testing, setTesting] = useState<Record<string, boolean>>({});
  const abortRefs = useRef<Record<string, AbortController>>({});
  const qc = useQueryClient();
  const { instance, accounts } = useMsal();

  const { data, isLoading, refetch } = useQuery<StatusResponse>({
    queryKey: ["local-runner-status"],
    queryFn: localRunnerApi.status,
    staleTime: 0,
  });

  const tools = data?.tools ?? [];
  const isKali = data?.is_kali ?? false;
  const installedCount = tools.filter((t) => t.installed || installDone[t.tool]).length;
  const localCount = tools.filter((t) => t.mode === "local").length;

  // ── Token helper ────────────────────────────────────────────────────────────

  const getToken = async (): Promise<string> => {
    if (!accounts.length) return "";
    try {
      const resp = await instance.acquireTokenSilent({
        ...loginRequest,
        account: accounts[0],
      });
      return resp.idToken || resp.accessToken;
    } catch {
      return "";
    }
  };

  // ── SSE install stream ──────────────────────────────────────────────────────

  const startInstall = async (tool: string) => {
    if (installing[tool]) return;
    setInstalling((p) => ({ ...p, [tool]: true }));
    setInstallLog((p) => ({ ...p, [tool]: [] }));
    setInstallDone((p) => ({ ...p, [tool]: false }));
    setInstallError((p) => ({ ...p, [tool]: "" }));

    const ctrl = new AbortController();
    abortRefs.current[tool] = ctrl;
    const token = await getToken();

    try {
      const res = await fetch(`${BASE}/local-runner/install/${tool}/stream`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        signal: ctrl.signal,
      });
      if (!res.ok || !res.body) {
        setInstallError((p) => ({ ...p, [tool]: `HTTP ${res.status}` }));
        setInstalling((p) => ({ ...p, [tool]: false }));
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const evt = JSON.parse(line.slice(6));
            const msg = evt.msg || evt.line || null;
            if (msg) setInstallLog((p) => ({ ...p, [tool]: [...(p[tool] ?? []), msg] }));
            if (evt.error) {
              setInstallError((p) => ({ ...p, [tool]: evt.error }));
              setInstalling((p) => ({ ...p, [tool]: false }));
            }
            if (evt.done) {
              setInstallDone((p) => ({ ...p, [tool]: true }));
              setInstalling((p) => ({ ...p, [tool]: false }));
              refetch();
            }
          } catch { /* skip malformed */ }
        }
      }
    } catch (e: any) {
      if (e?.name !== "AbortError") {
        setInstallError((p) => ({ ...p, [tool]: String(e?.message || e) }));
      }
    } finally {
      setInstalling((p) => ({ ...p, [tool]: false }));
    }
  };

  const stopInstall = (tool: string) => {
    abortRefs.current[tool]?.abort();
    setInstalling((p) => ({ ...p, [tool]: false }));
  };

  const installAll = () =>
    tools
      .filter((t) => !t.installed && !installDone[t.tool] && !installing[t.tool])
      .forEach((t) => startInstall(t.tool));

  // ── Mode toggle ─────────────────────────────────────────────────────────────

  const toggleMode = async (tool: ToolStatus) => {
    if (!tool.installed && !installDone[tool.tool]) return;
    const newMode = tool.mode === "local" ? "github_actions" : "local";
    try {
      await localRunnerApi.setMode(tool.tool, newMode);
      qc.invalidateQueries({ queryKey: ["local-runner-status"] });
    } catch (e: any) {
      alert(e?.response?.data?.detail || "Failed to update mode");
    }
  };

  // ── Smoke test ──────────────────────────────────────────────────────────────

  const runTest = async (tool: string) => {
    setTesting((p) => ({ ...p, [tool]: true }));
    try {
      const result = await localRunnerApi.test(tool);
      setTestResults((p) => ({ ...p, [tool]: result }));
    } catch {
      setTestResults((p) => ({ ...p, [tool]: { ok: false, output: "Request failed" } }));
    } finally {
      setTesting((p) => ({ ...p, [tool]: false }));
    }
  };

  const testAll = () =>
    tools.filter((t) => t.installed).forEach((t) => runTest(t.tool));

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <Box sx={{ maxWidth: 820, mx: "auto", p: 3 }}>
        {/* Header */}
        <Stack direction="row" sx={{ alignItems: "center", gap: 1.5, mb: 0.5 }}>
          <ComputerIcon sx={{ color: "#4285F4", fontSize: 28 }} />
          <Typography variant="h5" sx={{ fontFamily: "Space Grotesk", fontWeight: 700 }}>
            Local Runner Setup
          </Typography>
        </Stack>
        <Typography variant="body2" sx={{ color: "text.secondary", mb: 1 }}>
          Install and configure scanners to run directly on this machine
          instead of dispatching to GitHub Actions. Works best on Kali Linux
          (WSL or native) — most tools are pre-installed.
        </Typography>
        {isKali && (
          <Alert severity="success" sx={{ mb: 2, py: 0.5 }}>
            Kali Linux detected — apt packages available for most tools.
          </Alert>
        )}

        <Stepper activeStep={step} sx={{ mb: 4 }}>
          {STEPS.map((s) => (
            <Step key={s}>
              <StepLabel>{s}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {/* ── STEP 0 — Environment check ─────────────────────────────────── */}
        {step === 0 && (
          <Box>
            <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", mb: 2 }}>
              <Typography sx={{ fontWeight: 600 }}>Environment check</Typography>
              <Button size="small" startIcon={<RefreshIcon />} onClick={() => refetch()}>
                Refresh
              </Button>
            </Stack>

            {isLoading ? (
              <LinearProgress sx={{ mb: 2 }} />
            ) : (
              <Stack spacing={1.5} sx={{ mb: 3 }}>
                {tools.map((t) => {
                  const ok = t.installed || installDone[t.tool];
                  return (
                    <Paper
                      key={t.tool}
                      variant="outlined"
                      sx={{ p: 2, display: "flex", alignItems: "center", gap: 2 }}
                    >
                      {ok ? (
                        <CheckCircleIcon color="success" />
                      ) : (
                        <ErrorIcon sx={{ color: "warning.main" }} />
                      )}
                      <Box sx={{ flex: 1 }}>
                        <Typography sx={{ fontWeight: 600, fontSize: 14 }}>
                          {t.label}
                        </Typography>
                        <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
                          {t.desc}
                        </Typography>
                      </Box>
                      {ok ? (
                        <Chip
                          label={`v${t.version || "?"}`}
                          size="small"
                          color="success"
                          variant="outlined"
                        />
                      ) : (
                        <Chip label="Not installed" size="small" color="warning" variant="outlined" />
                      )}
                    </Paper>
                  );
                })}
              </Stack>
            )}

            <Alert
              severity={installedCount === tools.length ? "success" : "info"}
              sx={{ mb: 2 }}
            >
              {installedCount === tools.length
                ? "All tools installed. Proceed to configure dispatch mode."
                : `${tools.length - installedCount} tool(s) need installation.`}
            </Alert>

            {/* Cloud pairing */}
            <CloudPairingCard />

            <Stack direction="row" sx={{ justifyContent: "flex-end", mt: 2 }}>
              <Button variant="contained" onClick={() => setStep(1)}>
                {installedCount === tools.length ? "Next →" : "Install missing tools →"}
              </Button>
            </Stack>
          </Box>
        )}

        {/* ── STEP 1 — Install ───────────────────────────────────────────── */}
        {step === 1 && (
          <Box>
            <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", mb: 2 }}>
              <Typography sx={{ fontWeight: 600 }}>Install tools</Typography>
              <Button
                size="small"
                variant="outlined"
                onClick={installAll}
                disabled={tools.every(
                  (t) => t.installed || installDone[t.tool] || installing[t.tool]
                )}
              >
                Install all missing
              </Button>
            </Stack>

            <Stack spacing={2} sx={{ mb: 3 }}>
              {tools.map((t) => {
                const ready = t.installed || installDone[t.tool];
                const running = !!installing[t.tool];
                const errMsg = installError[t.tool];
                const logLines = installLog[t.tool] ?? [];

                return (
                  <Paper key={t.tool} variant="outlined" sx={{ p: 2 }}>
                    <Stack direction="row" sx={{ alignItems: "center", gap: 2 }}>
                      {ready ? (
                        <CheckCircleIcon color="success" fontSize="small" />
                      ) : running ? (
                        <DownloadingIcon color="primary" fontSize="small" />
                      ) : (
                        <ErrorIcon sx={{ color: "text.disabled" }} fontSize="small" />
                      )}
                      <Box sx={{ flex: 1 }}>
                        <Typography sx={{ fontWeight: 600, fontSize: 13 }}>
                          {t.label}
                        </Typography>
                        {t.version && (
                          <Typography sx={{ fontSize: 11, color: "text.secondary" }}>
                            v{t.version}
                          </Typography>
                        )}
                      </Box>
                      {!ready && !running && (
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => startInstall(t.tool)}
                          startIcon={<DownloadingIcon />}
                        >
                          Install
                        </Button>
                      )}
                      {running && (
                        <Button
                          size="small"
                          variant="outlined"
                          color="error"
                          onClick={() => stopInstall(t.tool)}
                          startIcon={<CircularProgress size={12} />}
                        >
                          Cancel
                        </Button>
                      )}
                      {ready && <Chip label="Ready" size="small" color="success" />}
                    </Stack>

                    {/* Install log */}
                    {logLines.length > 0 && (
                      <Box
                        sx={{
                          background: "#0d1219",
                          borderRadius: 1,
                          p: 1.5,
                          mt: 1.5,
                          fontFamily: "IBM Plex Mono, monospace",
                          fontSize: 11,
                          color: "#7dd3c0",
                          maxHeight: 160,
                          overflowY: "auto",
                        }}
                      >
                        {logLines.map((l, i) => (
                          <div key={i}>{l}</div>
                        ))}
                        {running && <div style={{ color: "#94a3b8" }}>▋</div>}
                      </Box>
                    )}

                    {/* Error */}
                    {errMsg && (
                      <Alert severity="error" sx={{ mt: 1, py: 0.5, fontSize: 12 }}>
                        {errMsg}
                      </Alert>
                    )}

                    {/* OpenVAS special notice */}
                    {t.tool === "openvas" && !ready && (
                      <Alert severity="info" sx={{ mt: 1, py: 0.5, fontSize: 12 }}>
                        OpenVAS setup downloads the NVT feed (~20 min first time). You can
                        move on to the next step and come back once it finishes.
                      </Alert>
                    )}
                  </Paper>
                );
              })}
            </Stack>

            <Stack direction="row" sx={{ justifyContent: "space-between" }}>
              <Button onClick={() => setStep(0)}>← Back</Button>
              <Button
                variant="contained"
                onClick={() => {
                  refetch();
                  setStep(2);
                }}
              >
                Configure dispatch →
              </Button>
            </Stack>
          </Box>
        )}

        {/* ── STEP 2 — Configure dispatch ────────────────────────────────── */}
        {step === 2 && (
          <Box>
            <Typography sx={{ fontWeight: 600, mb: 0.5 }}>
              Configure dispatch mode
            </Typography>
            <Typography sx={{ fontSize: 13, color: "text.secondary", mb: 2 }}>
              Toggle each scanner between running locally on this machine or via
              GitHub Actions. Only installed tools can be set to Local.
            </Typography>

            <AirgapCard />

            <GitHubActionsConfigCard />

            <Stack spacing={1.5} sx={{ mb: 3 }}>
              {tools.map((t) => {
                const ready = t.installed || installDone[t.tool];
                const isLocal = t.mode === "local";
                return (
                  <Paper
                    key={t.tool}
                    variant="outlined"
                    sx={{ p: 2, display: "flex", alignItems: "center", gap: 2 }}
                  >
                    <Box sx={{ flex: 1 }}>
                      <Typography sx={{ fontWeight: 600, fontSize: 14 }}>
                        {t.label}
                      </Typography>
                      <Typography sx={{ fontSize: 12, color: "text.secondary" }}>
                        {t.desc}
                      </Typography>
                    </Box>

                    <Stack direction="row" sx={{ alignItems: "center", gap: 1 }}>
                      <CloudIcon
                        fontSize="small"
                        sx={{ color: isLocal ? "text.disabled" : "primary.main" }}
                      />
                      <Tooltip
                        title={!ready ? "Install first" : isLocal ? "Switch to GitHub Actions" : "Switch to local"}
                      >
                        <span>
                          <Switch
                            checked={isLocal}
                            disabled={!ready}
                            onChange={() => toggleMode(t)}
                            size="small"
                            color="success"
                          />
                        </span>
                      </Tooltip>
                      <ComputerIcon
                        fontSize="small"
                        sx={{ color: isLocal ? "success.main" : "text.disabled" }}
                      />
                    </Stack>

                    <Chip
                      label={isLocal ? "Local" : "GitHub Actions"}
                      size="small"
                      color={isLocal ? "success" : "default"}
                      variant={isLocal ? "filled" : "outlined"}
                      sx={{ minWidth: 110 }}
                    />
                  </Paper>
                );
              })}
            </Stack>

            {localCount > 0 ? (
              <Alert severity="success" sx={{ mb: 2 }}>
                {localCount} scanner{localCount > 1 ? "s" : ""} will run locally on this
                machine. No GitHub token or Actions quota needed.
              </Alert>
            ) : (
              <Alert severity="info" sx={{ mb: 2 }}>
                All scanners will continue using GitHub Actions.
              </Alert>
            )}

            <Stack direction="row" sx={{ justifyContent: "space-between" }}>
              <Button onClick={() => setStep(1)}>← Back</Button>
              <Button variant="contained" onClick={() => setStep(3)}>
                Test &amp; finish →
              </Button>
            </Stack>
          </Box>
        )}

        {/* ── STEP 3 — Test & finish ─────────────────────────────────────── */}
        {step === 3 && (
          <Box>
            <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", mb: 2 }}>
              <Box>
                <Typography sx={{ fontWeight: 600 }}>Smoke test</Typography>
                <Typography sx={{ fontSize: 13, color: "text.secondary" }}>
                  Confirm each installed tool responds correctly.
                </Typography>
              </Box>
              <Button
                size="small"
                variant="outlined"
                onClick={testAll}
                disabled={tools.filter((t) => t.installed).every((t) => testing[t.tool])}
              >
                Test all
              </Button>
            </Stack>

            <Stack spacing={1.5} sx={{ mb: 3 }}>
              {tools
                .filter((t) => t.installed || installDone[t.tool])
                .map((t) => {
                  const result = testResults[t.tool];
                  return (
                    <Paper key={t.tool} variant="outlined" sx={{ p: 2 }}>
                      <Stack direction="row" sx={{ alignItems: "center", gap: 2 }}>
                        {result?.ok === true ? (
                          <CheckCircleIcon color="success" />
                        ) : result?.ok === false ? (
                          <ErrorIcon color="error" />
                        ) : (
                          <Box sx={{ width: 24 }} />
                        )}
                        <Box sx={{ flex: 1 }}>
                          <Typography sx={{ fontWeight: 600, fontSize: 13 }}>
                            {t.label}
                          </Typography>
                          <Chip
                            label={t.mode === "local" ? "Local" : "GitHub Actions"}
                            size="small"
                            color={t.mode === "local" ? "success" : "default"}
                            sx={{ mt: 0.5 }}
                          />
                        </Box>
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => runTest(t.tool)}
                          disabled={!!testing[t.tool]}
                          startIcon={
                            testing[t.tool] ? (
                              <CircularProgress size={12} />
                            ) : (
                              <PlayArrowIcon />
                            )
                          }
                        >
                          {testing[t.tool] ? "Running…" : "Test"}
                        </Button>
                      </Stack>

                      {result && (
                        <Box
                          sx={{
                            background: "#0d1219",
                            borderRadius: 1,
                            p: 1.5,
                            mt: 1.5,
                            fontFamily: "IBM Plex Mono, monospace",
                            fontSize: 11,
                            color: result.ok ? "#7dd3c0" : "#f87171",
                            whiteSpace: "pre-wrap",
                          }}
                        >
                          {result.output}
                        </Box>
                      )}
                    </Paper>
                  );
                })}
            </Stack>

            <Alert severity="success" sx={{ mb: 2 }}>
              Setup complete. When you launch a scan for a locally-configured
              scanner from the Assessments page, it runs on this machine — no
              GitHub Actions needed.
            </Alert>

            <Stack direction="row" sx={{ justifyContent: "space-between" }}>
              <Button onClick={() => setStep(2)}>← Back</Button>
              <Button variant="contained" href="/discover/scans">
                Go to Assessments →
              </Button>
            </Stack>
          </Box>
        )}
    </Box>
  );
}
