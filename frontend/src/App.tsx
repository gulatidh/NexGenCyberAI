import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeModeProvider } from "./theme/ThemeModeContext";
import { ViewModeProvider } from "./theme/ViewModeContext";
import { ClientProvider } from "./contexts/ClientContext";
import { MsalAuthenticationTemplate } from "@azure/msal-react";
import { InteractionType } from "@azure/msal-browser";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { AuthProvider } from "./auth/AuthProvider";
import { loginRequest } from "./auth/msalConfig";
import AppLayout from "./components/layout/AppLayout";
import ProductLayout from "./components/layout/ProductLayout";
import Hub from "./pages/Hub";
import {
  THREAT_INTEL, RISK_MANAGER, VULN_MGMT, PEN_TEST,
  COMPLIANCE_MONITOR, GOVERNANCE, AI_ADVISOR, INTELLIGENCE, PLATFORM,
} from "./products";
import Dashboard from "./pages/Dashboard";
import Clients from "./pages/Clients";
import ClientDetail from "./pages/ClientDetail";
import Connectors from "./pages/Connectors";
import Connections from "./pages/Connections";
import Scans from "./pages/Scans";
import Agents from "./pages/Agents";
import EmailSettings from "./pages/EmailSettings";
import AccessLogs from "./pages/AccessLogs";
import Findings from "./pages/Findings";
import Risks from "./pages/Risks";
import Assets from "./pages/Assets";
import StaleAssets from "./pages/StaleAssets";
import AssetDetail from "./pages/AssetDetail";
import Frameworks from "./pages/Frameworks";
import RiskOverviewPage from "./pages/RiskOverview";
import Projects from "./pages/Projects";
import Technologies from "./pages/Technologies";
import Admin from "./pages/Admin";
import SyncPage from "./pages/Sync";
import Help from "./pages/Help";
import ThreatModels from "./pages/ThreatModels";
import ThreatModelDetail from "./pages/ThreatModelDetail";
import Reports from "./pages/Reports";
import Account from "./pages/Account";
import Missions from "./pages/Missions";
import KnowledgeBase from "./pages/KnowledgeBase";
import ScanDetail from "./pages/ScanDetail";
import Settings from "./pages/Settings";
import LandingV2 from "./pages/LandingV2";
import ThreatRegister from "./pages/ThreatRegister";
import ControlDeficiencies from "./pages/ControlDeficiencies";
import RemediationTracker from "./pages/RemediationTracker";
import CustomFrameworks from "./pages/CustomFrameworks";
import VAPTReports from "./pages/VAPTReports";
import VAPTReportDetail from "./pages/VAPTReportDetail";
import ScanDiff from "./pages/ScanDiff";
import TicketSyncPage from "./pages/TicketSync";
import CTEMPage from "./pages/CTEMPage";
import SecurityDocs from "./pages/SecurityDocs";
import AttackPaths from "./pages/AttackPaths";
import NLQuery from "./pages/NLQuery";
import PostureTrends from "./pages/PostureTrends";
import ComplianceHeatmap from "./pages/ComplianceHeatmap";
import ClientComparison from "./pages/ClientComparison";
import EvidencePackage from "./pages/EvidencePackage";
import RemediationJobs from "./pages/RemediationJobs";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30_000 } },
});

function LoginPage() {
  return (
    <div style={{
      height: "100vh", display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center", background: "#0F0F0F",
    }}>
      <img src={`${process.env.PUBLIC_URL}/monitara-logo.jpg`} alt="Monitara AI"
        style={{ width: 90, height: 90, marginBottom: 16 }} />
      <h1 style={{ fontFamily: "Inter, sans-serif", fontSize: 36, margin: 0, letterSpacing: "-0.02em", fontWeight: 800 }}>
        <span style={{ color: "#4285F4" }}>A</span>
        <span style={{ color: "#EA4335" }}>e</span>
        <span style={{ color: "#FBBC04" }}>g</span>
        <span style={{ color: "#4285F4" }}>i</span>
        <span style={{ color: "#34A853" }}>s</span>
        <span style={{ color: "#FFFFFF" }}>{" AI"}</span>
      </h1>
      <p style={{ color: "rgba(255,255,255,0.5)", fontFamily: "Inter, sans-serif", marginBottom: 8 }}>
        AI-Powered Security Posture &amp; Threat Modeling
      </p>
      <p style={{ color: "#4285F4", fontFamily: "Inter, sans-serif", fontSize: 13, letterSpacing: 0.5, fontWeight: 600, marginTop: 0, marginBottom: 32 }}>
        See your risk. Model your threats. Fix what matters.
      </p>
      <p style={{ color: "rgba(255,255,255,0.3)", fontSize: 14 }}>Redirecting to Microsoft Entra ID login...</p>
    </div>
  );
}

function AuthError({ error }: { error: any }) {
  const code = error?.errorCode || error?.name || "unknown";
  const msg = error?.errorMessage || error?.message || String(error || "");
  const isInteractionInProgress = code === "interaction_in_progress" || /interaction.in.progress/i.test(msg);
  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 40, fontFamily: "Inter, sans-serif", color: "white", background: "#0d1117" }}>
      <div style={{ maxWidth: 640, width: "100%", background: "#1E1E1E", border: "1px solid rgba(234,67,53,0.4)", borderRadius: 12, padding: 32 }}>
        <h2 style={{ color: "#EA4335", marginTop: 0 }}>Sign-in failed</h2>
        <p style={{ color: "rgba(255,255,255,0.85)", marginBottom: 24 }}>Microsoft Entra ID returned an error during the sign-in flow.</p>
        <div style={{ background: "rgba(234,67,53,0.08)", border: "1px solid rgba(234,67,53,0.3)", borderRadius: 8, padding: 16, marginBottom: 24, fontFamily: "monospace", fontSize: 12, color: "rgba(255,255,255,0.85)", wordBreak: "break-word" }}>
          <div style={{ color: "#FBBC04", marginBottom: 6, fontWeight: 700 }}>Error code: {code}</div>
          <div>{msg || "(no error message)"}</div>
        </div>
        {isInteractionInProgress && (
          <p style={{ color: "rgba(255,255,255,0.75)", fontSize: 13, lineHeight: 1.5 }}>
            A previous sign-in attempt is still in progress. Clearing browser session storage usually resolves this.
          </p>
        )}
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <button onClick={() => { try { sessionStorage.clear(); localStorage.clear(); } catch {} window.location.href = "/"; }} style={{ background: "#4285F4", color: "white", border: "none", padding: "10px 18px", borderRadius: 6, cursor: "pointer", fontWeight: 600, fontSize: 14 }}>
            Clear session and retry
          </button>
          <button onClick={() => window.location.reload()} style={{ background: "transparent", color: "rgba(255,255,255,0.8)", border: "1px solid rgba(255,255,255,0.2)", padding: "10px 18px", borderRadius: 6, cursor: "pointer", fontSize: 14 }}>
            Just retry
          </button>
        </div>
      </div>
    </div>
  );
}

function ProtectedApp() {
  return (
    <MsalAuthenticationTemplate
      interactionType={InteractionType.Redirect}
      authenticationRequest={loginRequest}
      loadingComponent={LoginPage}
      errorComponent={AuthError}
    >
      <Routes>
        {/* ── v2 Hub ─────────────────────────────────────────────────────── */}
        <Route path="/hub" element={<Hub />} />

        {/* ── v2 Products ────────────────────────────────────────────────── */}
        <Route path="/threat-intel" element={<ProductLayout product={THREAT_INTEL} />}>
          <Route index element={<Navigate to="register" replace />} />
          <Route path="register" element={<ThreatRegister />} />
          <Route path="threat-models" element={<ThreatModels />} />
          <Route path="threat-models/:modelId" element={<ThreatModelDetail />} />
          <Route path="attack-paths" element={<AttackPaths />} />
        </Route>

        <Route path="/risk" element={<ProductLayout product={RISK_MANAGER} />}>
          <Route index element={<Navigate to="overview" replace />} />
          <Route path="overview" element={<RiskOverviewPage />} />
          <Route path="register" element={<Risks />} />
        </Route>

        <Route path="/vulnerability" element={<ProductLayout product={VULN_MGMT} />}>
          <Route index element={<Navigate to="scans" replace />} />
          <Route path="scans" element={<Scans />} />
          <Route path="scans/:scanId" element={<ScanDetail />} />
          <Route path="scans/:scanId/diff" element={<ScanDiff />} />
          <Route path="findings" element={<Findings />} />
          <Route path="posture" element={<PostureTrends />} />
        </Route>

        <Route path="/vapt" element={<ProductLayout product={PEN_TEST} />}>
          <Route index element={<Navigate to="reports" replace />} />
          <Route path="reports" element={<VAPTReports />} />
          <Route path="reports/:reportId" element={<VAPTReportDetail />} />
        </Route>

        <Route path="/compliance" element={<ProductLayout product={COMPLIANCE_MONITOR} />}>
          <Route index element={<Navigate to="deficiencies" replace />} />
          <Route path="deficiencies" element={<ControlDeficiencies />} />
          <Route path="frameworks" element={<Frameworks />} />
          <Route path="custom-frameworks" element={<CustomFrameworks />} />
          <Route path="evidence" element={<EvidencePackage />} />
        </Route>

        <Route path="/governance" element={<ProductLayout product={GOVERNANCE} />}>
          <Route index element={<Navigate to="ctem" replace />} />
          <Route path="ctem" element={<CTEMPage />} />
          <Route path="remediation" element={<RemediationTracker />} />
        </Route>

        <Route path="/ai-advisor" element={<ProductLayout product={AI_ADVISOR} />}>
          <Route index element={<Navigate to="agents" replace />} />
          <Route path="agents" element={<Agents />} />
          <Route path="workflows" element={<Missions />} />
        </Route>

        <Route path="/intelligence" element={<ProductLayout product={INTELLIGENCE} />}>
          <Route index element={<Navigate to="nl-query" replace />} />
          <Route path="nl-query" element={<NLQuery />} />
          <Route path="security-docs" element={<SecurityDocs />} />
          <Route path="reports" element={<Reports />} />
          <Route path="knowledge" element={<KnowledgeBase />} />
        </Route>

        {/* ── Platform product (Clients / Assets / Connections / Ticket Sync) ── */}
        <Route path="/platform" element={<ProductLayout product={PLATFORM} />}>
          <Route index element={<Navigate to="clients" replace />} />
          <Route path="clients" element={<Clients />} />
          <Route path="clients/:clientId" element={<ClientDetail />} />
          <Route path="assets" element={<Assets />} />
          <Route path="assets/technologies" element={<Technologies />} />
          <Route path="assets/:assetId" element={<AssetDetail />} />
          <Route path="connections" element={<Connections />} />
          <Route path="ticket-sync" element={<TicketSyncPage />} />
          <Route path="settings" element={<Settings />} />
        </Route>

        {/* ── v1 AppLayout routes (classic view — still accessible) ─────── */}
        <Route element={<AppLayout />}>
          <Route index element={<Navigate to="/hub" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/risk-overview" element={<RiskOverviewPage />} />
          <Route path="/threat-register" element={<ThreatRegister />} />
          <Route path="/control-deficiencies" element={<ControlDeficiencies />} />
          <Route path="/remediation-tracker" element={<RemediationTracker />} />
          <Route path="/custom-frameworks" element={<CustomFrameworks />} />
          <Route path="/clients" element={<Clients />} />
          <Route path="/clients/:clientId" element={<ClientDetail />} />
          <Route path="/projects" element={<Projects />} />
          <Route path="/connections" element={<Connections />} />
          <Route path="/connectors" element={<Connectors />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/scans/:scanId" element={<ScanDetail />} />
          <Route path="/scans/:scanId/diff" element={<ScanDiff />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/risks" element={<Risks />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/stale-assets" element={<StaleAssets />} />
          <Route path="/assets/technologies" element={<Technologies />} />
          <Route path="/assets/:assetId" element={<AssetDetail />} />
          <Route path="/frameworks" element={<Frameworks />} />
          <Route path="/agents" element={<Agents />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/ai-settings" element={<Navigate to="/settings" replace />} />
          <Route path="/email-settings" element={<EmailSettings />} />
          <Route path="/access-logs" element={<AccessLogs />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="/sync" element={<SyncPage />} />
          <Route path="/help" element={<Help />} />
          <Route path="/threat-models" element={<ThreatModels />} />
          <Route path="/threat-models/:modelId" element={<ThreatModelDetail />} />
          <Route path="/account" element={<Account />} />
          <Route path="/missions" element={<Missions />} />
          <Route path="/knowledge" element={<KnowledgeBase />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/vapt-reports" element={<VAPTReports />} />
          <Route path="/vapt-reports/:reportId" element={<VAPTReportDetail />} />
          <Route path="/ticket-sync" element={<TicketSyncPage />} />
          <Route path="/ctem" element={<CTEMPage />} />
          <Route path="/security-docs" element={<SecurityDocs />} />
          <Route path="/webhooks" element={<Navigate to="/settings" replace />} />
          <Route path="/api-keys" element={<Navigate to="/settings" replace />} />
          <Route path="/attack-paths" element={<AttackPaths />} />
          <Route path="/nl-query" element={<NLQuery />} />
          <Route path="/posture-trends" element={<PostureTrends />} />
          <Route path="/compliance-heatmap" element={<ComplianceHeatmap />} />
          <Route path="/client-comparison" element={<ClientComparison />} />
          <Route path="/remediation-jobs" element={<RemediationJobs />} />
        </Route>
      </Routes>
    </MsalAuthenticationTemplate>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <QueryClientProvider client={queryClient}>
        <ThemeModeProvider>
          <ViewModeProvider>
            <ClientProvider>
            <ToastContainer theme="dark" position="bottom-right" autoClose={3000} />
            <BrowserRouter>
              <Routes>
                {/* Public landing page — v2 light theme */}
                <Route path="/" element={<LandingV2 />} />
                {/* All other routes require Microsoft Entra ID sign-in */}
                <Route path="/*" element={<ProtectedApp />} />
              </Routes>
            </BrowserRouter>
            </ClientProvider>
          </ViewModeProvider>
        </ThemeModeProvider>
      </QueryClientProvider>
    </AuthProvider>
  );
}
