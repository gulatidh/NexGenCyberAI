/**
 * NexGenCyberAI – Axios API client.
 * Automatically attaches the Entra ID bearer token to every request.
 */
import axios, { InternalAxiosRequestConfig } from "axios";
import { InteractionRequiredAuthError } from "@azure/msal-browser";
import { msalInstance } from "../auth/AuthProvider";
import { loginRequest as loginReq } from "../auth/msalConfig";
import { addNotification } from "./notifications";

const BASE_URL = import.meta.env.REACT_APP_API_URL || "http://localhost:8000/api/v1";

export const apiClient = axios.create({ baseURL: BASE_URL });

// Attach Entra ID token on every request
// Throttle interactive redirects — if multiple API calls race to "needs
// login", we still trigger only one acquireTokenRedirect per page load.
// Otherwise concurrent requests cause MSAL 'interaction_in_progress'
// loops where every retry kicks another redirect.
let _redirectInFlight = false;

apiClient.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
  // Ensure MSAL has finished loading the cache (no-op if already initialized)
  await msalInstance.initialize();
  const account = msalInstance.getActiveAccount() ?? msalInstance.getAllAccounts()[0];
  if (account) {
    try {
      const tokenResponse = await msalInstance.acquireTokenSilent({
        ...loginReq,
        account,
      });
      config.headers.Authorization = `Bearer ${tokenResponse.accessToken}`;
    } catch (err) {
      // Only redirect for errors that actually need interactive login
      // (consent required, MFA, expired refresh token, account changed).
      // Transient AAD glitches, network blips, or non-auth errors should
      // NOT trigger a redirect — that's how the 'login loop' happens.
      if (err instanceof InteractionRequiredAuthError && !_redirectInFlight) {
        _redirectInFlight = true;
        try {
          await msalInstance.acquireTokenRedirect(loginReq);
        } catch {
          _redirectInFlight = false;
        }
      } else {
        // Let the request go through without a token; the backend will
        // 401 and the user sees a real error instead of a silent reload.
        // eslint-disable-next-line no-console
        console.warn("Token acquisition failed:", err);
      }
    }
  }
  return config;
});

// Record write operations and errors in the notification log
const OPERATION_LABELS: Record<string, string> = {
  post: "Created", patch: "Updated", put: "Updated", delete: "Deleted",
};
apiClient.interceptors.response.use(
  (response) => {
    const method = (response.config.method || "").toLowerCase();
    if (["post", "patch", "put", "delete"].includes(method)) {
      const url = response.config.url || "";
      const label = OPERATION_LABELS[method] || method.toUpperCase();
      addNotification({ type: "success", message: `${label}: ${url}` });
    }
    return response;
  },
  (error) => {
    // Suppress aborted/cancelled requests — no HTTP response means the request
    // was cancelled by React Query's AbortController or by an MSAL redirect.
    // These are client-side noise, not real server errors.
    if (axios.isCancel(error) || error.code === "ERR_CANCELED" || !error.response) {
      return Promise.reject(error);
    }
    const method = (error.config?.method || "").toUpperCase();
    const url = error.config?.url || "";
    const status = error.response.status;
    const detail = error.response?.data?.detail || error.message || "Unknown error";
    addNotification({ type: "error", message: `${method} ${url} — ${status}`, detail });
    return Promise.reject(error);
  },
);

// ── Typed API functions ───────────────────────────────────────────────────────

export const clientsApi = {
  list: () => apiClient.get("/clients/").then((r) => r.data),
  get: (id: string) => apiClient.get(`/clients/${id}`).then((r) => r.data),
  create: (data: any) => apiClient.post("/clients/", data).then((r) => r.data),
  update: (id: string, data: any) => apiClient.patch(`/clients/${id}`, data).then((r) => r.data),
  delete: (id: string) => apiClient.delete(`/clients/${id}`),
};

export const connectorsApi = {
  list: (clientId: string, projectId?: string) =>
    apiClient.get(`/clients/${clientId}/connectors/`, { params: projectId ? { project_id: projectId } : {} }).then((r) => r.data),
  create: (clientId: string, data: any) => apiClient.post(`/clients/${clientId}/connectors/`, data).then((r) => r.data),
  test: (clientId: string, connectorId: string) =>
    apiClient.post(`/clients/${clientId}/connectors/${connectorId}/test`).then((r) => r.data),
  update: (clientId: string, connectorId: string, data: any) =>
    apiClient.patch(`/clients/${clientId}/connectors/${connectorId}`, data).then((r) => r.data),
  delete: (clientId: string, connectorId: string) =>
    apiClient.delete(`/clients/${clientId}/connectors/${connectorId}`),
  health: (clientId: string) =>
    apiClient.get(`/clients/${clientId}/connectors/health`).then((r) => r.data),
  moveConnector: (clientId: string, connectorId: string, targetProjectId: string | null) =>
    apiClient.patch(`/clients/${clientId}/connectors/${connectorId}/move`, { target_project_id: targetProjectId }).then((r) => r.data),
  copyConnector: (clientId: string, connectorId: string, targetProjectId: string | null, name?: string) =>
    apiClient.post(`/clients/${clientId}/connectors/${connectorId}/copy`, { target_project_id: targetProjectId, name }).then((r) => r.data),
};

export const projectsApi = {
  list: (clientId: string) => apiClient.get(`/clients/${clientId}/projects/`).then((r) => r.data),
  get: (clientId: string, projectId: string) =>
    apiClient.get(`/clients/${clientId}/projects/${projectId}`).then((r) => r.data),
  create: (clientId: string, data: any) =>
    apiClient.post(`/clients/${clientId}/projects/`, data).then((r) => r.data),
  update: (clientId: string, projectId: string, data: any) =>
    apiClient.patch(`/clients/${clientId}/projects/${projectId}`, data).then((r) => r.data),
  delete: (clientId: string, projectId: string) =>
    apiClient.delete(`/clients/${clientId}/projects/${projectId}`),
  summary: (clientId: string, projectId: string) =>
    apiClient.get(`/clients/${clientId}/projects/${projectId}/summary`).then((r) => r.data),
};

export const scansApi = {
  list: (clientId: string, projectId?: string) =>
    apiClient.get(`/clients/${clientId}/scans/`, { params: projectId ? { project_id: projectId } : {} }).then((r) => r.data),
  get: (clientId: string, scanId: string) => apiClient.get(`/clients/${clientId}/scans/${scanId}`).then((r) => r.data),
  start: (clientId: string, data: any) => apiClient.post(`/clients/${clientId}/scans/`, data).then((r) => r.data),
  findings: (clientId: string, scanId: string, severity?: string) =>
    apiClient.get(`/clients/${clientId}/scans/${scanId}/findings/`, { params: { severity } }).then((r) => r.data),
  startFrameworkScan: (clientId: string, body: {
    connector_id?: string; framework: string; scan_type?: string; control_ids?: string[]; name?: string;
  }) =>
    apiClient.post(`/clients/${clientId}/scans/`, {
      scan_type: body.scan_type || "full",
      framework: body.framework,
      connector_id: body.connector_id,
      control_ids: body.control_ids,
      name: body.name,
    }).then((r) => r.data),
  delete: (clientId: string, scanId: string) =>
    apiClient.delete(`/clients/${clientId}/scans/${scanId}`),
  rescan: (clientId: string, scanId: string) =>
    apiClient.post(`/clients/${clientId}/scans/${scanId}/rescan`).then((r) => r.data),
  versions: (clientId: string, scanId: string) =>
    apiClient.get(`/clients/${clientId}/scans/${scanId}/versions`).then((r) => r.data),
  parseScanImport: (clientId: string, file: File, toolHint: string) => {
    const form = new FormData();
    form.append("file", file);
    form.append("tool_hint", toolHint);
    return apiClient.post(`/clients/${clientId}/scans/import/parse`, form, {
      headers: { "Content-Type": "multipart/form-data" },
    }).then((r) => r.data);
  },
  commitScanImport: (clientId: string, file: File, toolHint: string, scanName: string) => {
    const form = new FormData();
    form.append("file", file);
    form.append("tool_hint", toolHint);
    form.append("scan_name", scanName);
    return apiClient.post(`/clients/${clientId}/scans/import/commit`, form, {
      headers: { "Content-Type": "multipart/form-data" },
    }).then((r) => r.data);
  },
  importHistory: (clientId: string) =>
    apiClient.get(`/clients/${clientId}/scans/import/history`).then((r) => r.data),
  setLive: (clientId: string, scanId: string) =>
    apiClient.patch(`/clients/${clientId}/scans/${scanId}/set-live`).then((r) => r.data),
  triggerEnrich: (clientId: string, scanId: string) =>
    apiClient.post(`/clients/${clientId}/scans/${scanId}/enrich`).then((r) => r.data),
  move: (clientId: string, scanId: string, targetProjectId: string | null) =>
    apiClient.patch(`/clients/${clientId}/scans/${scanId}/move`, { target_project_id: targetProjectId }).then((r) => r.data),
};

export const findingsApi = {
  listAll: (clientId: string, severity?: string, status?: string, projectId?: string, section?: string, category?: string, scanId?: string) =>
    apiClient.get(`/clients/${clientId}/findings/`, {
      params: { severity, status, project_id: projectId || undefined, section: section || undefined, category: category || undefined, scan_id: scanId || undefined },
    }).then((r) => r.data),
  categories: (clientId: string, projectId?: string, status?: string) =>
    apiClient.get(`/clients/${clientId}/findings/categories`, {
      params: { project_id: projectId || undefined, status: status || undefined },
    }).then((r) => r.data),
  update: (clientId: string, findingId: string, data: any) =>
    apiClient.patch(`/clients/${clientId}/findings/${findingId}`, data).then((r) => r.data),
  delete: (clientId: string, findingId: string) =>
    apiClient.delete(`/clients/${clientId}/findings/${findingId}`).then((r) => r.data),
  cleanupBlank: (clientId: string) =>
    apiClient.post(`/clients/${clientId}/findings/cleanup-blank`).then((r) => r.data),
};

export const risksApi = {
  list: (clientId: string, projectId?: string) =>
    apiClient.get(`/clients/${clientId}/risks/`, { params: projectId ? { project_id: projectId } : {} }).then((r) => r.data),
  create: (clientId: string, data: any) => apiClient.post(`/clients/${clientId}/risks/`, data).then((r) => r.data),
  update: (clientId: string, riskId: string, data: any) =>
    apiClient.patch(`/clients/${clientId}/risks/${riskId}`, data).then((r) => r.data),
  delete: (clientId: string, riskId: string) => apiClient.delete(`/clients/${clientId}/risks/${riskId}`),
};

export const agentsApi = {
  run: (clientId: string, data: any) => apiClient.post(`/clients/${clientId}/agents/run/`, data).then((r) => r.data),
  listRuns: (clientId: string) => apiClient.get(`/clients/${clientId}/agents/runs/`).then((r) => r.data),
  listHiddenRuns: (clientId: string) => apiClient.get(`/clients/${clientId}/agents/runs/hidden/`).then((r) => r.data),
  getRun: (clientId: string, runId: string) =>
    apiClient.get(`/clients/${clientId}/agents/runs/${runId}`).then((r) => r.data),
  deleteRun: (clientId: string, runId: string) =>
    apiClient.delete(`/clients/${clientId}/agents/runs/${runId}`).then((r) => r.data),
  restoreRun: (clientId: string, runId: string) =>
    apiClient.post(`/clients/${clientId}/agents/runs/${runId}/restore`).then((r) => r.data),
  permanentDeleteRun: (clientId: string, runId: string) =>
    apiClient.delete(`/clients/${clientId}/agents/runs/${runId}/permanent`).then((r) => r.data),
};

export const aiApi = {
  listProviders: () => apiClient.get("/ai/providers/").then((r) => r.data),
  testProvider: (data: any) => apiClient.post("/ai/test/", data).then((r) => r.data),
  getDefault: () => apiClient.get("/ai/default-provider/").then((r) => r.data),
  getConfig: () => apiClient.get("/ai/config/").then((r) => r.data),
  updateConfig: (data: Record<string, any>) =>
    apiClient.patch("/ai/config/", data).then((r) => r.data),
  learningStats: () => apiClient.get("/ai/learning-stats/").then((r) => r.data),
};

export const emailApi = {
  getConfig: () => apiClient.get("/email/config/").then((r) => r.data),
  updateConfig: (data: Record<string, any>) =>
    apiClient.patch("/email/config/", data).then((r) => r.data),
  test: (to: string) => apiClient.post("/email/test/", { to }).then((r) => r.data),
  send: (data: {
    to: string | string[];
    cc?: string | string[];
    subject: string;
    body_html?: string;
    body_text?: string;
    attachments?: { filename: string; content_base64: string; mime?: string }[];
  }) => apiClient.post("/email/send/", data).then((r) => r.data),
};

export const ssoApi = {
  getConfig: () => apiClient.get("/sso/config/").then((r) => r.data),
  updateConfig: (data: Record<string, any>) =>
    apiClient.patch("/sso/config/", data).then((r) => r.data),
  test: () => apiClient.post("/sso/test/").then((r) => r.data),
};

export const dashboardApi = {
  summary: () => apiClient.get("/dashboard/").then((r) => r.data),
  activity: (days: number = 3) =>
    apiClient.get(`/dashboard/activity`, { params: { days } }).then((r) => r.data),
};

export const trendsApi = {
  findings: (clientId: string) =>
    apiClient.get(`/dashboard/clients/${clientId}/trends/findings/`).then((r) => r.data),
  riskScore: (clientId: string) =>
    apiClient.get(`/dashboard/clients/${clientId}/trends/risk-score/`).then((r) => r.data),
  compliance: (clientId: string) =>
    apiClient.get(`/dashboard/clients/${clientId}/trends/compliance/`).then((r) => r.data),
};

export const riskOverviewApi = {
  get: (clientId: string, days: number = 30) =>
    apiClient.get(`/clients/${clientId}/risk-overview/`, { params: { days } }).then((r) => r.data),
};

export const threatModelsApi = {
  methodologies: () => apiClient.get(`/threat-models/methodologies`).then((r) => r.data),
  libraryEntry: (source: string, sourceId: string) =>
    apiClient.get(`/threat-models/library/${source}/${encodeURIComponent(sourceId)}`).then((r) => r.data),
  list: (clientId: string) =>
    apiClient.get(`/clients/${clientId}/threat-models/`).then((r) => r.data),
  get: (clientId: string, modelId: string) =>
    apiClient.get(`/clients/${clientId}/threat-models/${modelId}`).then((r) => r.data),
  create: (clientId: string, data: any) =>
    apiClient.post(`/clients/${clientId}/threat-models/`, data).then((r) => r.data),
  rescan: (clientId: string, modelId: string) =>
    apiClient.post(`/clients/${clientId}/threat-models/${modelId}/rescan`).then((r) => r.data),
  remodel: (clientId: string, modelId: string, body: { components?: any[]; data_flows?: any[]; analyst_notes?: string }) =>
    apiClient.post(`/clients/${clientId}/threat-models/${modelId}/remodel`, body).then((r) => r.data),
  versions: (clientId: string, modelId: string) =>
    apiClient.get(`/clients/${clientId}/threat-models/${modelId}/versions`).then((r) => r.data),
  delete: (clientId: string, modelId: string) =>
    apiClient.delete(`/clients/${clientId}/threat-models/${modelId}`),
  convertThreat: (clientId: string, modelId: string, threatId: string) =>
    apiClient.post(`/clients/${clientId}/threat-models/${modelId}/threats/${encodeURIComponent(threatId)}/convert-to-risk`).then((r) => r.data),
  convertAll: (clientId: string, modelId: string) =>
    apiClient.post(`/clients/${clientId}/threat-models/${modelId}/convert-all-to-risks`).then((r) => r.data),
  drawioXml: (clientId: string, modelId: string) =>
    apiClient.get(`/clients/${clientId}/threat-models/${modelId}/drawio`).then((r) => r.data),
  drawioDownloadUrl: (clientId: string, modelId: string) =>
    `${apiClient.defaults.baseURL || ""}/clients/${clientId}/threat-models/${modelId}/drawio?download=1`,
  // Phase 8 endpoints
  styledDfd: (clientId: string, modelId: string, view: string) =>
    apiClient.get(`/clients/${clientId}/threat-models/${modelId}/dfd`, { params: { view } }).then((r) => r.data),
  coverage: (clientId: string, modelId: string) =>
    apiClient.get(`/clients/${clientId}/threat-models/${modelId}/coverage`).then((r) => r.data),
  fillGaps: (clientId: string, modelId: string, cells?: { component_id: string; category: string }[]) =>
    apiClient.post(`/clients/${clientId}/threat-models/${modelId}/coverage/fill-gaps`,
      cells && cells.length ? { cells } : {}).then((r) => r.data),
  maturity: (clientId: string, modelId: string) =>
    apiClient.get(`/clients/${clientId}/threat-models/${modelId}/maturity`).then((r) => r.data),
  diff: (clientId: string, modelId: string, prevId: string) =>
    apiClient.get(`/clients/${clientId}/threat-models/${modelId}/diff/${prevId}`).then((r) => r.data),
  pdfUrl: (clientId: string, modelId: string) =>
    `${apiClient.defaults.baseURL || ""}/clients/${clientId}/threat-models/${modelId}/pdf`,
  patchThreat: (clientId: string, modelId: string, threatId: string, body: any) =>
    apiClient.patch(`/clients/${clientId}/threat-models/${modelId}/threats/${encodeURIComponent(threatId)}`, body).then((r) => r.data),
  patchMitigation: (clientId: string, modelId: string, mitId: string, body: any) =>
    apiClient.patch(`/clients/${clientId}/threat-models/${modelId}/mitigations/${encodeURIComponent(mitId)}`, body).then((r) => r.data),
  createFromDiagram: (clientId: string, file: File, opts: { name?: string; methodology?: string; framework?: string }) => {
    const fd = new FormData();
    fd.append("file", file);
    if (opts.name) fd.append("name", opts.name);
    if (opts.methodology) fd.append("methodology", opts.methodology);
    if (opts.framework) fd.append("framework", opts.framework);
    return apiClient.post(`/clients/${clientId}/threat-models/from-diagram`, fd, {
      headers: { "Content-Type": "multipart/form-data" },
    }).then((r) => r.data);
  },
  startModeling: (clientId: string, modelId: string, body: any = {}) =>
    apiClient.post(`/clients/${clientId}/threat-models/${modelId}/start-modeling`, body).then((r) => r.data),
  // Phase 9 — Sigma rule endpoints
  suggestDetections: (clientId: string, modelId: string) =>
    apiClient.post(`/clients/${clientId}/threat-models/${modelId}/suggest-detections`).then((r) => r.data),
  validateSigmaRule: (clientId: string, modelId: string, index: number) =>
    apiClient.patch(`/clients/${clientId}/threat-models/${modelId}/sigma-rules/${index}/validate`).then((r) => r.data),
  downloadSigmaRules: async (clientId: string, modelId: string) => {
    const url = `${apiClient.defaults.baseURL || ""}/clients/${clientId}/threat-models/${modelId}/sigma-rules?format=yaml`;
    // Acquire auth token the same way the interceptor does
    const { msalInstance } = await import("../auth/AuthProvider");
    const { loginRequest } = await import("../auth/msalConfig");
    await msalInstance.initialize();
    const account = msalInstance.getActiveAccount() ?? msalInstance.getAllAccounts()[0];
    let token = "";
    if (account) {
      try {
        const resp = await msalInstance.acquireTokenSilent({ ...loginRequest, account });
        token = resp.accessToken;
      } catch {
        // proceed without token; backend will 401
      }
    }
    const res = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    if (!res.ok) return;
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `sigma-rules-${modelId}.yaml`;
    a.click();
    URL.revokeObjectURL(a.href);
  },
};

export const adminApi = {
  me: () => apiClient.get("/admin/me").then((r) => r.data),
  bootstrapAdmin: () => apiClient.post("/admin/bootstrap-admin").then((r) => r.data),
  listUsers: () => apiClient.get("/admin/users").then((r) => r.data),
  createGrant: (data: any) => apiClient.post("/admin/grants", data).then((r) => r.data),
  deleteGrant: (grantId: string) => apiClient.delete(`/admin/grants/${grantId}`),
  listSyncFeeds: () => apiClient.get("/admin/sync/feeds").then((r) => r.data),
  refreshSyncFeed: (feedId: string) =>
    apiClient.post(`/admin/sync/feeds/${feedId}/refresh`).then((r) => r.data),
  refreshAllSyncFeeds: () =>
    apiClient.post("/admin/sync/feeds/refresh-all").then((r) => r.data),
  syncFeedEntries: (feedId: string, params?: {
    limit?: number; q?: string; category?: string; cwe?: string;
    min_cvss?: number; min_score?: number; ransomware?: boolean;
  }) =>
    apiClient.get(`/admin/sync/feeds/${feedId}/entries`, { params }).then((r) => r.data),
  accessLogs: (params?: {
    user_email?: string; method?: string; path?: string;
    since_hours?: number; limit?: number; offset?: number;
  }) =>
    apiClient.get("/admin/access-logs/", { params }).then((r) => r.data),
  promptLogs: (params?: {
    user_id?: string; endpoint?: string; status?: string;
    since_hours?: number; limit?: number; offset?: number;
  }) =>
    apiClient.get("/admin/prompt-logs", { params }).then((r) => r.data),
  listDeletedClients: () => apiClient.get("/admin/clients/deleted").then((r) => r.data),
  restoreClient: (clientId: string) =>
    apiClient.post(`/admin/clients/${clientId}/restore`).then((r) => r.data),
  permanentlyDeleteClient: (clientId: string) =>
    apiClient.delete(`/admin/clients/${clientId}/permanent`),
  purgeExpiredClients: () =>
    apiClient.post("/admin/clients/purge-expired").then((r) => r.data),
};

export const technologiesApi = {
  inventory: (clientId: string, params?: Record<string, any>) =>
    apiClient.get(`/clients/${clientId}/technologies/`, { params }).then((r) => r.data),
  detail: (clientId: string, name: string) =>
    apiClient.get(`/clients/${clientId}/technologies/${encodeURIComponent(name)}/detail`).then((r) => r.data),
};

export const frameworksApi = {
  catalog: () => apiClient.get("/frameworks/").then((r) => r.data),
  catalogAll: () => apiClient.get("/frameworks/all/").then((r) => r.data),
  controls: (framework: string) => apiClient.get(`/frameworks/${framework}/controls/`).then((r) => r.data),
  summary: (clientId: string) => apiClient.get(`/clients/${clientId}/frameworks/`).then((r) => r.data),
  forClient: (clientId: string, framework: string, scanId?: string) =>
    apiClient.get(`/clients/${clientId}/frameworks/${framework}/`, { params: scanId ? { scan_id: scanId } : {} }).then((r) => r.data),
  controlDetail: (clientId: string, framework: string, controlId: string) =>
    apiClient.get(`/clients/${clientId}/frameworks/${framework}/controls/${encodeURIComponent(controlId)}`).then((r) => r.data),
  override: (clientId: string, framework: string, controlId: string, body: any) =>
    apiClient
      .patch(`/clients/${clientId}/frameworks/${framework}/controls/${encodeURIComponent(controlId)}`, body)
      .then((r) => r.data),
  resetOverride: (clientId: string, framework: string, controlId: string) =>
    apiClient.delete(`/clients/${clientId}/frameworks/${framework}/controls/${encodeURIComponent(controlId)}/override`),
  recompute: (clientId: string, framework: string) =>
    apiClient.post(`/clients/${clientId}/frameworks/${framework}/recompute/`).then((r) => r.data),
  importControls: (framework: string, file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return apiClient
      .post(`/frameworks/${framework}/import/`, fd, { headers: { "Content-Type": "multipart/form-data" } })
      .then((r) => r.data);
  },
};

export const assetsApi = {
  list: (clientId: string, params?: Record<string, any>) =>
    apiClient.get(`/clients/${clientId}/assets/`, { params }).then((r) => r.data),
  facets: (clientId: string) =>
    apiClient.get(`/clients/${clientId}/assets/facets`).then((r) => r.data),
  get: (clientId: string, assetId: string) =>
    apiClient.get(`/clients/${clientId}/assets/${assetId}`).then((r) => r.data),
  sync: (clientId: string, connectorId?: string) =>
    apiClient
      .post(`/clients/${clientId}/assets/sync/`, null, { params: connectorId ? { connector_id: connectorId } : {} })
      .then((r) => r.data),
  scan: (clientId: string, assetId: string) =>
    apiClient.post(`/clients/${clientId}/assets/${assetId}/scan/`).then((r) => r.data),
  approve: (clientId: string, assetIds: string[]) =>
    apiClient.post(`/clients/${clientId}/assets/approve/`, { asset_ids: assetIds }).then((r) => r.data),
  heatmap: (clientId: string, limit = 20) =>
    apiClient.get(`/clients/${clientId}/assets/heatmap?limit=${limit}`).then((r) => r.data),
  timeline: (clientId: string, assetId: string) =>
    apiClient.get(`/clients/${clientId}/assets/${assetId}/timeline`).then((r) => r.data),
  deduplicate: (clientId: string, assetId: string) =>
    apiClient.get(`/clients/${clientId}/assets/${assetId}/deduplicate`).then((r) => r.data),
  compliance: (clientId: string, assetId: string, framework?: string) =>
    apiClient.get(`/clients/${clientId}/assets/${assetId}/compliance`, { params: framework ? { framework } : {} }).then((r) => r.data),
};

export const missionsApi = {
  list: (clientId?: string) =>
    apiClient.get(`/missions/`, { params: clientId ? { client_id: clientId } : {} }).then((r) => r.data),
  create: (data: any) => apiClient.post(`/missions/`, data).then((r) => r.data),
  update: (missionId: string, data: any) =>
    apiClient.patch(`/missions/${missionId}`, data).then((r) => r.data),
  delete: (missionId: string) =>
    apiClient.delete(`/missions/${missionId}`).then((r) => r.data),
  runNow: (missionId: string) =>
    apiClient.post(`/missions/${missionId}/run`).then((r) => r.data),
  runs: (missionId: string) =>
    apiClient.get(`/missions/${missionId}/runs`).then((r) => r.data),
  recentRuns: (limit = 50) =>
    apiClient.get(`/missions/runs/recent`, { params: { limit } }).then((r) => r.data),
};

export const knowledgeApi = {
  list: () => apiClient.get(`/knowledge/`).then((r) => r.data),
  search: (q: string) => apiClient.get(`/knowledge/search`, { params: { q } }).then((r) => r.data),
  stats: () => apiClient.get(`/knowledge/stats`).then((r) => r.data),
  get: (fileId: string) => apiClient.get(`/knowledge/${fileId}`).then((r) => r.data),
};

export const riskPortfolioApi = {
  get: (clientId: string) =>
    apiClient.get(`/clients/${clientId}/risk-portfolio/`).then((r) => r.data),
};

export const assessmentsApi = {
  listAll: () => apiClient.get(`/scans/all`).then((r) => r.data),
  detail: (scanId: string) => apiClient.get(`/scans/${scanId}/detail`).then((r) => r.data),
  generateVerdict: (scanId: string) =>
    apiClient.post(`/scans/${scanId}/generate-verdict`).then((r) => r.data),
};

export const agentCatalogApi = {
  list: (includeHidden = false) =>
    apiClient.get(`/agents/catalog/`, { params: includeHidden ? { include_hidden: true } : {} }).then((r) => r.data),
  get: (agentId: string) => apiClient.get(`/agents/catalog/${agentId}`).then((r) => r.data),
  create: (data: any) => apiClient.post(`/agents/catalog/`, data).then((r) => r.data),
  update: (agentId: string, data: any) =>
    apiClient.patch(`/agents/catalog/${agentId}`, data).then((r) => r.data),
  delete: (agentId: string) => apiClient.delete(`/agents/catalog/${agentId}`).then((r) => r.data),
  restore: (agentId: string) => apiClient.post(`/agents/catalog/${agentId}/restore`).then((r) => r.data),
  run: (agentId: string, prompt?: string, clientId?: string, scanId?: string, assetIds?: string[]) =>
    apiClient.post(`/agents/catalog/${agentId}/run`, {
      prompt,
      client_id: clientId,
      scan_id: scanId,
      asset_ids: assetIds?.length ? assetIds : undefined,
    }).then((r) => r.data),
  extractFile: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return apiClient.post(`/agents/catalog/extract-file`, fd, {
      headers: { "Content-Type": "multipart/form-data" },
    }).then((r) => r.data as { filename: string; char_count: number; text: string; truncated: boolean });
  },
  // Phase 7A — one-click apply for a buddy-produced artifact
  applyArtifact: (runId: string, idx: number) =>
    apiClient.post(`/agents/catalog/runs/${runId}/artifacts/${idx}/apply`).then((r) => r.data),
  // Phase 7C — per-buddy usage stats
  stats: (agentId: string) =>
    apiClient.get(`/agents/catalog/${agentId}/stats`).then((r) => r.data),
};

export const threatRegisterApi = {
  list: (clientId: string, params?: { status?: string; severity?: string; scan_id?: string }) =>
    apiClient.get(`/clients/${clientId}/threat-register/`, { params }).then((r) => r.data),
  update: (clientId: string, entryId: string, data: { status: string }) =>
    apiClient.patch(`/clients/${clientId}/threat-register/${entryId}`, data).then((r) => r.data),
  delete: (clientId: string, entryId: string) =>
    apiClient.delete(`/clients/${clientId}/threat-register/${entryId}`),
};

export const controlDeficienciesApi = {
  list: (clientId: string, params?: { status?: string; severity?: string; framework?: string; scan_id?: string }) =>
    apiClient.get(`/clients/${clientId}/control-deficiencies/`, { params }).then((r) => r.data),
  update: (clientId: string, deficiencyId: string, data: { status: string }) =>
    apiClient.patch(`/clients/${clientId}/control-deficiencies/${deficiencyId}`, data).then((r) => r.data),
  delete: (clientId: string, deficiencyId: string) =>
    apiClient.delete(`/clients/${clientId}/control-deficiencies/${deficiencyId}`),
};

export const remediationTrackerApi = {
  list: (clientId: string, params?: { status?: string; band?: string; scan_id?: string }) =>
    apiClient.get(`/clients/${clientId}/remediation-actions/`, { params }).then((r) => r.data),
  update: (clientId: string, actionId: string, data: { status?: string; assigned_to?: string; due_date?: string; notes?: string }) =>
    apiClient.patch(`/clients/${clientId}/remediation-actions/${actionId}`, data).then((r) => r.data),
  delete: (clientId: string, actionId: string) =>
    apiClient.delete(`/clients/${clientId}/remediation-actions/${actionId}`),
};

export const assistantApi = {
  chat: (data: { message: string; current_page?: string; history?: Array<{ role: string; content: string }> }) =>
    apiClient.post("/assistant/chat", data).then((r) => r.data),
};

export const vaptApi = {
  list: (clientId: string) =>
    apiClient.get(`/clients/${clientId}/vapt-reports/`).then((r) => r.data),
  create: (clientId: string, data: any) =>
    apiClient.post(`/clients/${clientId}/vapt-reports/`, data).then((r) => r.data),
  get: (clientId: string, reportId: string) =>
    apiClient.get(`/clients/${clientId}/vapt-reports/${reportId}/`).then((r) => r.data),
  update: (clientId: string, reportId: string, data: any) =>
    apiClient.patch(`/clients/${clientId}/vapt-reports/${reportId}/`, data).then((r) => r.data),
  delete: (clientId: string, reportId: string) =>
    apiClient.delete(`/clients/${clientId}/vapt-reports/${reportId}/`),
  createRetest: (clientId: string, reportId: string) =>
    apiClient.post(`/clients/${clientId}/vapt-reports/${reportId}/retest/`).then((r) => r.data),
  addFinding: (clientId: string, reportId: string, data: any) =>
    apiClient.post(`/clients/${clientId}/vapt-reports/${reportId}/findings/`, data).then((r) => r.data),
  updateFinding: (clientId: string, reportId: string, findingId: string, data: any) =>
    apiClient.patch(`/clients/${clientId}/vapt-reports/${reportId}/findings/${findingId}/`, data).then((r) => r.data),
  deleteFinding: (clientId: string, reportId: string, findingId: string) =>
    apiClient.delete(`/clients/${clientId}/vapt-reports/${reportId}/findings/${findingId}/`),
  exportUrl: (clientId: string, reportId: string, format: string) =>
    `/clients/${clientId}/vapt-reports/${reportId}/export/${format}`,
  createFromScan: (clientId: string, data: { scan_id: string; title?: string; classification?: string; prepared_by?: string }) =>
    apiClient.post(`/clients/${clientId}/vapt-reports/from-scan/`, data).then((r) => r.data),
};

export const changelogApi = {
  list: () => apiClient.get("/changelog/").then((r) => r.data),
};

export const ticketsApi = {
  list: (clientId: string) =>
    apiClient.get(`/clients/${clientId}/tickets/`).then((r) => r.data),
  createFromFinding: (clientId: string, data: any) =>
    apiClient.post(`/clients/${clientId}/tickets/create-from-finding/`, data).then((r) => r.data),
  createFromRemediation: (clientId: string, data: any) =>
    apiClient.post(`/clients/${clientId}/tickets/create-from-remediation/`, data).then((r) => r.data),
  sync: (clientId: string, ticketSyncId: string) =>
    apiClient.post(`/clients/${clientId}/tickets/${ticketSyncId}/sync/`).then((r) => r.data),
  getConnectors: (clientId: string) =>
    apiClient.get(`/clients/${clientId}/tickets/connectors/`).then((r) => r.data),
};

export const customFrameworksApi = {
  listAll: () => apiClient.get("/frameworks/all/").then((r) => r.data),
  list: () => apiClient.get("/frameworks/custom/").then((r) => r.data),
  create: (data: { name: string; description?: string }) =>
    apiClient.post("/frameworks/custom/", data).then((r) => r.data),
  get: (id: string) => apiClient.get(`/frameworks/custom/${id}/`).then((r) => r.data),
  delete: (id: string) => apiClient.delete(`/frameworks/custom/${id}/`),
  addControls: (id: string, controlIds: string[]) =>
    apiClient.post(`/frameworks/custom/${id}/controls/`, { control_ids: controlIds }).then((r) => r.data),
  removeControl: (id: string, fkCtrlId: string) =>
    apiClient.delete(`/frameworks/custom/${id}/controls/${fkCtrlId}/`),
  pickerControls: (params: { framework?: string; domain?: string; search?: string; page?: number }) =>
    apiClient.get("/frameworks/controls/", { params }).then((r) => r.data),
  // Domains
  listDomains: (cfId: string) => apiClient.get(`/frameworks/custom/${cfId}/domains/`).then((r) => r.data),
  createDomain: (cfId: string, data: { name: string; description?: string; sort_order?: number }) =>
    apiClient.post(`/frameworks/custom/${cfId}/domains/`, data).then((r) => r.data),
  deleteDomain: (cfId: string, domainId: string) =>
    apiClient.delete(`/frameworks/custom/${cfId}/domains/${domainId}/`),
  // Native custom controls
  createNativeControl: (cfId: string, data: {
    control_id: string; title: string; description?: string;
    weight?: number; domain_id?: string; sort_order?: number;
  }) => apiClient.post(`/frameworks/custom/${cfId}/native-controls/`, data).then((r) => r.data),
  deleteNativeControl: (cfId: string, ncId: string) =>
    apiClient.delete(`/frameworks/custom/${cfId}/native-controls/${ncId}/`),
};

export const usersApi = {
  me: () => apiClient.get("/users/me/").then((r) => r.data),
};

export const postureApi = {
  getHistory: (clientId: string, days = 90) =>
    apiClient.get(`/clients/${clientId}/posture-history/?days=${days}`).then((r) => r.data),
  getScanSummary: (clientId: string, scanId: string) =>
    apiClient.get(`/clients/${clientId}/posture-history/scan-summary?scan_id=${scanId}`).then((r) => r.data),
  triggerSnapshot: (clientId: string) =>
    apiClient.post(`/clients/${clientId}/posture-history/snapshot`).then((r) => r.data),
};

export const attackPathApi = {
  get: (clientId: string, scanId?: string, projectId?: string) => {
    const params = new URLSearchParams();
    if (scanId) params.set("scan_id", scanId);
    if (projectId) params.set("project_id", projectId);
    const qs = params.toString();
    return apiClient.get(`/clients/${clientId}/attack-paths/${qs ? `?${qs}` : ""}`).then((r) => r.data);
  },
  getForAsset: (clientId: string, assetId: string) =>
    apiClient.get(`/clients/${clientId}/attack-paths/?asset_id=${assetId}`).then((r) => r.data),
};

export const nlQueryApi = {
  query: (clientId: string, question: string) =>
    apiClient.post(`/clients/${clientId}/query/nl`, { question }).then((r) => r.data),
};

export const cveApi = {
  list: (clientId: string, q?: string) =>
    apiClient.get(`/clients/${clientId}/cve/${q ? `?q=${encodeURIComponent(q)}` : ""}`).then((r) => r.data),
  get: (clientId: string, cveId: string) =>
    apiClient.get(`/clients/${clientId}/cve/${encodeURIComponent(cveId)}`).then((r) => r.data),
  impact: (clientId: string, cveId: string) =>
    apiClient.get(`/clients/${clientId}/cve/${encodeURIComponent(cveId)}/impact`).then((r) => r.data),
};

export const mttrApi = {
  // MTTR is computed client-side from posture history snapshots; no dedicated endpoint needed
};

// ── New API clients ────────────────────────────────────────────────────────────

// Alias for convenience in new APIs
const api = apiClient;
const API_BASE = apiClient.defaults.baseURL || "";

export const commentsApi = {
  list: (clientId: string, entityType: string, entityId: string) =>
    api.get(`/clients/${clientId}/comments/?entity_type=${entityType}&entity_id=${entityId}`).then(r => r.data),
  create: (clientId: string, data: { entity_type: string; entity_id: string; body: string }) =>
    api.post(`/clients/${clientId}/comments/`, data).then(r => r.data),
  update: (clientId: string, commentId: string, body: string) =>
    api.patch(`/clients/${clientId}/comments/${commentId}?body=${encodeURIComponent(body)}`).then(r => r.data),
  delete: (clientId: string, commentId: string) =>
    api.delete(`/clients/${clientId}/comments/${commentId}`).then(r => r.data),
  assign: (clientId: string, entityType: string, entityId: string, assigneeEmail: string, dueDate?: string) => {
    let url = `/clients/${clientId}/comments/assign?entity_type=${entityType}&entity_id=${entityId}&assignee_email=${encodeURIComponent(assigneeEmail)}`;
    if (dueDate) url += `&due_date=${dueDate}`;
    return api.put(url).then(r => r.data);
  },
};

export const webhooksApi = {
  list: (clientId?: string) =>
    api.get(`/webhooks/${clientId ? `?client_id=${clientId}` : ''}`).then(r => r.data),
  create: (data: { name: string; url: string; secret?: string; events: string[]; client_id?: string }) =>
    api.post('/webhooks/', data).then(r => r.data),
  toggle: (id: string, isActive: boolean) =>
    api.patch(`/webhooks/${id}?is_active=${isActive}`).then(r => r.data),
  delete: (id: string) => api.delete(`/webhooks/${id}`).then(r => r.data),
  test: (id: string) => api.post(`/webhooks/${id}/test`).then(r => r.data),
  deliveries: (id: string) => api.get(`/webhooks/${id}/deliveries`).then(r => r.data),
};

export const ctemApi = {
  list: (clientId: string) => api.get(`/clients/${clientId}/ctem/`).then(r => r.data),
  create: (clientId: string, data: { name: string; description?: string; connector_ids?: string[] }) =>
    api.post(`/clients/${clientId}/ctem/`, data).then(r => r.data),
  get: (clientId: string, programId: string) =>
    api.get(`/clients/${clientId}/ctem/${programId}`).then(r => r.data),
  updatePhase: (clientId: string, programId: string, phase: string, notes?: string, completed?: boolean) => {
    const params = new URLSearchParams();
    if (notes !== undefined) params.set('notes', notes);
    if (completed !== undefined) params.set('completed', String(completed));
    return api.patch(`/clients/${clientId}/ctem/${programId}/phases/${phase}?${params}`).then(r => r.data);
  },
  delete: (clientId: string, programId: string) =>
    api.delete(`/clients/${clientId}/ctem/${programId}`).then(r => r.data),
  // Phase structured data
  getPhaseData: (clientId: string, programId: string, phase: string) =>
    api.get(`/clients/${clientId}/ctem/${programId}/phase-data/${phase}`).then(r => r.data),
  savePhaseData: (clientId: string, programId: string, phase: string, data: Record<string, unknown>) =>
    api.put(`/clients/${clientId}/ctem/${programId}/phase-data/${phase}`, data).then(r => r.data),
  // AI brief
  generateAIBrief: (clientId: string, programId: string, phase: string) =>
    api.post(`/clients/${clientId}/ctem/${programId}/ai-brief/${phase}`).then(r => r.data),
  saveAIBrief: (clientId: string, programId: string, phase: string, brief: string) =>
    api.put(`/clients/${clientId}/ctem/${programId}/ai-brief/${phase}`, { brief }).then(r => r.data),
  // Scope assets
  getScopeAssets: (clientId: string, programId: string) =>
    api.get(`/clients/${clientId}/ctem/${programId}/scope/assets`).then(r => r.data),
  // Discover findings
  getDiscoverFindings: (clientId: string, programId: string) =>
    api.get(`/clients/${clientId}/ctem/${programId}/discover/findings`).then(r => r.data),
  // Prioritise: AI generate
  generatePriorities: (clientId: string, programId: string) =>
    api.post(`/clients/${clientId}/ctem/${programId}/prioritise/generate`).then(r => r.data),
  // Export
  exportUrl: (clientId: string, programId: string, format: 'pdf' | 'docx') =>
    `${api.defaults.baseURL}/clients/${clientId}/ctem/${programId}/export?format=${format}`,
};

export const scorecardApi = {
  listTokens: (clientId: string) =>
    api.get(`/clients/${clientId}/scorecard/tokens`).then(r => r.data),
  createToken: (clientId: string, label: string) =>
    api.post(`/clients/${clientId}/scorecard/tokens?label=${encodeURIComponent(label)}`).then(r => r.data),
  revokeToken: (clientId: string, tokenId: string) =>
    api.delete(`/clients/${clientId}/scorecard/tokens/${tokenId}`).then(r => r.data),
};

export const documentsApi = {
  list: (clientId: string) => api.get(`/clients/${clientId}/documents/`).then(r => r.data),
  upload: (clientId: string, file: File) => {
    const fd = new FormData(); fd.append('file', file);
    return api.post(`/clients/${clientId}/documents/`, fd).then(r => r.data);
  },
  delete: (clientId: string, docId: string) =>
    api.delete(`/clients/${clientId}/documents/${docId}`).then(r => r.data),
  query: (clientId: string, question: string) =>
    api.post(`/clients/${clientId}/documents/query`, { question }).then(r => r.data),
};

export const apiKeysApi = {
  list: () => api.get('/api-keys/').then(r => r.data),
  create: (data: { name: string; client_id?: string; scopes: string[]; expires_days?: number }) =>
    api.post('/api-keys/', data).then(r => r.data),
  revoke: (id: string) => api.delete(`/api-keys/${id}`).then(r => r.data),
};

export const evidenceApi = {
  downloadUrl: (clientId: string, framework?: string) =>
    `${API_BASE}/clients/${clientId}/evidence/package${framework ? `?framework=${framework}` : ''}`,
};

export const dataModelApi = {
  stats: (clientId: string) =>
    api.get(`/clients/${clientId}/data-model/stats`).then(r => r.data),
  connections: (clientId: string, entityType: string, entityId: string) =>
    api.get(`/clients/${clientId}/data-model/connections`, {
      params: { entity_type: entityType, entity_id: entityId },
    }).then(r => r.data),
  list: (clientId: string, entityType: string, search?: string, limit?: number) =>
    api.get(`/clients/${clientId}/data-model/list`, {
      params: { entity_type: entityType, ...(search ? { search } : {}), ...(limit ? { limit } : {}) },
    }).then(r => r.data),
};

export const remediationJobsApi = {
  list: (clientId: string) =>
    api.get(`/clients/${clientId}/remediation-jobs/`).then(r => r.data),
  get: (clientId: string, jobId: string) =>
    api.get(`/clients/${clientId}/remediation-jobs/${jobId}`).then(r => r.data),
  create: (clientId: string, findingIds: string[], scanId?: string) =>
    api.post(`/clients/${clientId}/remediation-jobs/`, {
      finding_ids: findingIds,
      ...(scanId ? { scan_id: scanId } : {}),
    }).then(r => r.data),
  verify: (clientId: string, jobId: string) =>
    api.post(`/clients/${clientId}/remediation-jobs/${jobId}/verify`).then(r => r.data),
  delete: (clientId: string, jobId: string) =>
    api.delete(`/clients/${clientId}/remediation-jobs/${jobId}`).then(r => r.data),
};
