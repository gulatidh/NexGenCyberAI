/**
 * NexGenCyberAI – Axios API client.
 * Automatically attaches the Entra ID bearer token to every request.
 */
import axios, { InternalAxiosRequestConfig } from "axios";
import { msalInstance } from "../auth/AuthProvider";
import { loginRequest as loginReq } from "../auth/msalConfig";
import { addNotification } from "./notifications";

const BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000/api/v1";

export const apiClient = axios.create({ baseURL: BASE_URL });

// Attach Entra ID token on every request
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
    } catch {
      // Silent token acquisition failed — redirect to login
      await msalInstance.acquireTokenRedirect(loginReq);
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
};

export const aiApi = {
  listProviders: () => apiClient.get("/ai/providers/").then((r) => r.data),
  testProvider: (data: any) => apiClient.post("/ai/test/", data).then((r) => r.data),
  getDefault: () => apiClient.get("/ai/default-provider/").then((r) => r.data),
};

export const dashboardApi = {
  summary: () => apiClient.get("/dashboard/").then((r) => r.data),
};

export const riskOverviewApi = {
  get: (clientId: string, days: number = 30) =>
    apiClient.get(`/clients/${clientId}/risk-overview/`, { params: { days } }).then((r) => r.data),
};

export const adminApi = {
  me: () => apiClient.get("/admin/me").then((r) => r.data),
  listUsers: () => apiClient.get("/admin/users").then((r) => r.data),
  createGrant: (data: any) => apiClient.post("/admin/grants", data).then((r) => r.data),
  deleteGrant: (grantId: string) => apiClient.delete(`/admin/grants/${grantId}`),
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
