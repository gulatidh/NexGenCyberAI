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
  list: (clientId: string) => apiClient.get(`/clients/${clientId}/connectors/`).then((r) => r.data),
  create: (clientId: string, data: any) => apiClient.post(`/clients/${clientId}/connectors/`, data).then((r) => r.data),
  test: (clientId: string, connectorId: string) =>
    apiClient.post(`/clients/${clientId}/connectors/${connectorId}/test`).then((r) => r.data),
  update: (clientId: string, connectorId: string, data: any) =>
    apiClient.patch(`/clients/${clientId}/connectors/${connectorId}`, data).then((r) => r.data),
  delete: (clientId: string, connectorId: string) =>
    apiClient.delete(`/clients/${clientId}/connectors/${connectorId}`),
};

export const scansApi = {
  list: (clientId: string) => apiClient.get(`/clients/${clientId}/scans/`).then((r) => r.data),
  get: (clientId: string, scanId: string) => apiClient.get(`/clients/${clientId}/scans/${scanId}`).then((r) => r.data),
  start: (clientId: string, data: any) => apiClient.post(`/clients/${clientId}/scans/`, data).then((r) => r.data),
  findings: (clientId: string, scanId: string, severity?: string) =>
    apiClient.get(`/clients/${clientId}/scans/${scanId}/findings/`, { params: { severity } }).then((r) => r.data),
};

export const findingsApi = {
  listAll: (clientId: string, severity?: string, status?: string) =>
    apiClient.get(`/clients/${clientId}/findings/`, { params: { severity, status } }).then((r) => r.data),
  update: (clientId: string, findingId: string, data: any) =>
    apiClient.patch(`/clients/${clientId}/findings/${findingId}`, data).then((r) => r.data),
};

export const risksApi = {
  list: (clientId: string) => apiClient.get(`/clients/${clientId}/risks/`).then((r) => r.data),
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
