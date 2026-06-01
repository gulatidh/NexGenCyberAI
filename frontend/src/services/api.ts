/**
 * NexGenCyberAI – Axios API client.
 * Automatically attaches the Entra ID bearer token to every request.
 */
import axios, { InternalAxiosRequestConfig } from "axios";
import { InteractionRequiredAuthError } from "@azure/msal-browser";
import { msalInstance } from "../auth/AuthProvider";
import { loginRequest as loginReq } from "../auth/msalConfig";
import { addNotification } from "./notifications";

const BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000/api/v1";

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
    const method = (error.config?.method || "").toUpperCase();
    const url = error.config?.url || "";
    const status = error.response?.status ?? "?";
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
};

export const findingsApi = {
  listAll: (clientId: string, severity?: string, status?: string, projectId?: string, section?: string, category?: string) =>
    apiClient.get(`/clients/${clientId}/findings/`, {
      params: { severity, status, project_id: projectId || undefined, section: section || undefined, category: category || undefined },
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
  getRun: (clientId: string, runId: string) =>
    apiClient.get(`/clients/${clientId}/agents/runs/${runId}`).then((r) => r.data),
  deleteRun: (clientId: string, runId: string) =>
    apiClient.delete(`/clients/${clientId}/agents/runs/${runId}`).then((r) => r.data),
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

export const dashboardApi = {
  summary: () => apiClient.get("/dashboard/").then((r) => r.data),
  activity: (days: number = 3) =>
    apiClient.get(`/dashboard/activity`, { params: { days } }).then((r) => r.data),
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
  coverage: (clientId: string, modelId: string) =>
    apiClient.get(`/clients/${clientId}/threat-models/${modelId}/coverage`).then((r) => r.data),
  fillGaps: (clientId: string, modelId: string) =>
    apiClient.post(`/clients/${clientId}/threat-models/${modelId}/coverage/fill-gaps`).then((r) => r.data),
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
};

export const adminApi = {
  me: () => apiClient.get("/admin/me").then((r) => r.data),
  listUsers: () => apiClient.get("/admin/users").then((r) => r.data),
  createGrant: (data: any) => apiClient.post("/admin/grants", data).then((r) => r.data),
  deleteGrant: (grantId: string) => apiClient.delete(`/admin/grants/${grantId}`),
  listSyncFeeds: () => apiClient.get("/admin/sync/feeds").then((r) => r.data),
  refreshSyncFeed: (feedId: string) =>
    apiClient.post(`/admin/sync/feeds/${feedId}/refresh`).then((r) => r.data),
  refreshAllSyncFeeds: () =>
    apiClient.post("/admin/sync/feeds/refresh-all").then((r) => r.data),
};

export const technologiesApi = {
  inventory: (clientId: string, params?: Record<string, any>) =>
    apiClient.get(`/clients/${clientId}/technologies/`, { params }).then((r) => r.data),
  detail: (clientId: string, name: string) =>
    apiClient.get(`/clients/${clientId}/technologies/${encodeURIComponent(name)}/detail`).then((r) => r.data),
};

export const frameworksApi = {
  catalog: () => apiClient.get("/frameworks/").then((r) => r.data),
  controls: (framework: string) => apiClient.get(`/frameworks/${framework}/controls/`).then((r) => r.data),
  summary: (clientId: string) => apiClient.get(`/clients/${clientId}/frameworks/`).then((r) => r.data),
  forClient: (clientId: string, framework: string) =>
    apiClient.get(`/clients/${clientId}/frameworks/${framework}/`).then((r) => r.data),
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
  list: () => apiClient.get(`/agents/catalog/`).then((r) => r.data),
  get: (agentId: string) => apiClient.get(`/agents/catalog/${agentId}`).then((r) => r.data),
  create: (data: any) => apiClient.post(`/agents/catalog/`, data).then((r) => r.data),
  update: (agentId: string, data: any) =>
    apiClient.patch(`/agents/catalog/${agentId}`, data).then((r) => r.data),
  delete: (agentId: string) => apiClient.delete(`/agents/catalog/${agentId}`).then((r) => r.data),
  run: (agentId: string, prompt?: string, clientId?: string, scanId?: string) =>
    apiClient.post(`/agents/catalog/${agentId}/run`, {
      prompt,
      client_id: clientId,
      scan_id: scanId,
    }).then((r) => r.data),
  // Phase 7A — one-click apply for a buddy-produced artifact
  applyArtifact: (runId: string, idx: number) =>
    apiClient.post(`/agents/catalog/runs/${runId}/artifacts/${idx}/apply`).then((r) => r.data),
  // Phase 7C — per-buddy usage stats
  stats: (agentId: string) =>
    apiClient.get(`/agents/catalog/${agentId}/stats`).then((r) => r.data),
};
