import React, { Suspense, Component, ErrorInfo, ReactNode } from "react";
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
import { Box, CircularProgress, Typography, Button } from "@mui/material";

// ── Global error boundary — prevents a single component crash from blanking the app
class AppErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(_error: Error, info: ErrorInfo) { console.error("AppErrorBoundary caught:", _error, info); }
  render() {
    if (this.state.error) {
      return (
        <Box sx={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", bgcolor: "#0d1117", color: "white", p: 4 }}>
          <Typography variant="h5" sx={{ mb: 2, color: "#EA4335" }}>Something went wrong</Typography>
          <Typography sx={{ mb: 3, color: "rgba(255,255,255,0.6)", fontSize: 13, maxWidth: 500, textAlign: "center" }}>
            {(this.state.error as Error).message}
          </Typography>
          <Button variant="outlined" onClick={() => { this.setState({ error: null }); window.location.reload(); }}>
            Reload page
          </Button>
        </Box>
      );
    }
    return this.props.children;
  }
}

// ── Static imports (always-needed layout + landing) ───────────────────────────
import AppLayout from "./components/layout/AppLayout";
import ProductLayout from "./components/layout/ProductLayout";
import Hub from "./pages/Hub";
import LandingV2 from "./pages/LandingV2";
import {
  THREAT_INTEL, RISK_MANAGER, VULN_MGMT, PEN_TEST,
  COMPLIANCE_MONITOR, GOVERNANCE, AI_ADVISOR, INTELLIGENCE, PLATFORM,
} from "./products";

// ── Lazy page imports (code-split per route, reduces webpack peak memory) ──────
const Dashboard         = React.lazy(() => import("./pages/Dashboard"));
const Clients           = React.lazy(() => import("./pages/Clients"));
const ClientDetail      = React.lazy(() => import("./pages/ClientDetail"));
const Connectors        = React.lazy(() => import("./pages/Connectors"));
const Connections       = React.lazy(() => import("./pages/Connections"));
const Scans             = React.lazy(() => import("./pages/Scans"));
const ScanDetail        = React.lazy(() => import("./pages/ScanDetail"));
const ScanDiff          = React.lazy(() => import("./pages/ScanDiff"));
const Agents            = React.lazy(() => import("./pages/Agents"));
const EmailSettings     = React.lazy(() => import("./pages/EmailSettings"));
const AccessLogs        = React.lazy(() => import("./pages/AccessLogs"));
const Findings          = React.lazy(() => import("./pages/Findings"));
const Risks             = React.lazy(() => import("./pages/Risks"));
const RiskAIAnalysis    = React.lazy(() => import("./pages/RiskAIAnalysis"));
const Assets            = React.lazy(() => import("./pages/Assets"));
const StaleAssets       = React.lazy(() => import("./pages/StaleAssets"));
const AssetDetail       = React.lazy(() => import("./pages/AssetDetail"));
const Frameworks        = React.lazy(() => import("./pages/Frameworks"));
const RiskOverviewPage  = React.lazy(() => import("./pages/RiskOverview"));
const Projects          = React.lazy(() => import("./pages/Projects"));
const Technologies      = React.lazy(() => import("./pages/Technologies"));
const Admin             = React.lazy(() => import("./pages/Admin"));
const SyncPage          = React.lazy(() => import("./pages/Sync"));
const Help              = React.lazy(() => import("./pages/Help"));
const ThreatModels      = React.lazy(() => import("./pages/ThreatModels"));
const ThreatModelDetail = React.lazy(() => import("./pages/ThreatModelDetail"));
const Reports           = React.lazy(() => import("./pages/Reports"));
const Account           = React.lazy(() => import("./pages/Account"));
const Missions          = React.lazy(() => import("./pages/Missions"));
const KnowledgeBase     = React.lazy(() => import("./pages/KnowledgeBase"));
const Settings          = React.lazy(() => import("./pages/Settings"));
const ThreatRegister    = React.lazy(() => import("./pages/ThreatRegister"));
const ControlDeficiencies = React.lazy(() => import("./pages/ControlDeficiencies"));
const RemediationTracker  = React.lazy(() => import("./pages/RemediationTracker"));
const CustomFrameworks    = React.lazy(() => import("./pages/CustomFrameworks"));
const VAPTReports         = React.lazy(() => import("./pages/VAPTReports"));
const VAPTReportDetail    = React.lazy(() => import("./pages/VAPTReportDetail"));
const TicketSyncPage      = React.lazy(() => import("./pages/TicketSync"));
const CTEMPage            = React.lazy(() => import("./pages/CTEMPage"));
const SecurityDocs        = React.lazy(() => import("./pages/SecurityDocs"));
const AttackPaths         = React.lazy(() => import("./pages/AttackPaths"));
const CVEPivot            = React.lazy(() => import("./pages/CVEPivot"));
const OntologyPage        = React.lazy(() => import("./pages/OntologyPage"));
const NLQuery             = React.lazy(() => import("./pages/NLQuery"));
const AIAssistedScan      = React.lazy(() => import("./pages/AIAssistedScan"));
const PostureTrends       = React.lazy(() => import("./pages/PostureTrends"));
const ComplianceHeatmap   = React.lazy(() => import("./pages/ComplianceHeatmap"));
const ClientComparison    = React.lazy(() => import("./pages/ClientComparison"));
const EvidencePackage     = React.lazy(() => import("./pages/EvidencePackage"));
const AIGuardrails        = React.lazy(() => import("./pages/AIGuardrails"));
const RemediationJobs     = React.lazy(() => import("./pages/RemediationJobs"));
const AgentRunTrash       = React.lazy(() => import("./pages/AgentRunTrash"));
const DiscoverPage        = React.lazy(() => import("./pages/DiscoverPage"));
const AnalysePage         = React.lazy(() => import("./pages/AnalysePage"));
const RespondPage         = React.lazy(() => import("./pages/RespondPage"));
const AutomatePage        = React.lazy(() => import("./pages/AutomatePage"));
const SampleHub           = React.lazy(() => import("./pages/SampleHub"));
const SampleHubCmd        = React.lazy(() => import("./pages/SampleHubCmd"));
const SampleAzure         = React.lazy(() => import("./pages/SampleAzure"));
const SampleHub4          = React.lazy(() => import("./pages/SampleHub4"));

// ── Loading fallback ──────────────────────────────────────────────────────────
const Shell = AppLayout;

function PageLoader() {
  return (
    <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", bgcolor: "background.default" }}>
      <CircularProgress size={36} />
    </Box>
  );
}

function LoginPage() {
  return (
    <div style={{
      height: "100vh", display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center", background: "#0F0F0F",
    }}>
      <img src="/monitara-logo.jpg" alt="Owlet AI"
        style={{ width: 90, height: 90, marginBottom: 16 }} />
      <h1 style={{ fontFamily: "Inter, sans-serif", fontSize: 36, margin: 0, letterSpacing: "-0.02em", fontWeight: 800 }}>
        <span style={{ color: "#4285F4" }}>O</span>
        <span style={{ color: "#EA4335" }}>w</span>
        <span style={{ color: "#FBBC04" }}>l</span>
        <span style={{ color: "#4285F4" }}>e</span>
        <span style={{ color: "#34A853" }}>t</span>
        <span style={{ color: "#FFFFFF" }}>{" AI"}</span>
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
      <Suspense fallback={<PageLoader />}>
        <Routes>
          {/* ── v2 Hub ─────────────────────────────────────────────────────── */}
          <Route path="/hub" element={<Hub />} />

          {/* ── Section landing pages (v3 theme) ──────────────────────────── */}
          <Route element={<Shell />}>
            <Route path="/discover"  element={<DiscoverPage />} />
            <Route path="/analyse"   element={<AnalysePage />} />
            <Route path="/respond"   element={<RespondPage />} />
            <Route path="/automate"  element={<AutomatePage />} />
          </Route>

          {/* ── Samples (full-page, no AppLayout) ──────────────────────────── */}
          <Route path="/sample3" element={<SampleAzure />} />
          <Route path="/sample4" element={<SampleHub4 />} />

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
            <Route path="ai-analysis" element={<RiskAIAnalysis />} />
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
            <Route index element={<Navigate to="scans" replace />} />
            <Route path="scans" element={<Scans />} />
            <Route path="scans/:scanId" element={<ScanDetail />} />
            <Route path="scans/:scanId/diff" element={<ScanDiff />} />
            <Route path="reports" element={<VAPTReports />} />
            <Route path="reports/:reportId" element={<VAPTReportDetail />} />
            <Route path="attack-paths" element={<AttackPaths />} />
            <Route path="evidence" element={<EvidencePackage />} />
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
            <Route path="remediation-jobs" element={<RemediationJobs />} />
          </Route>

          <Route path="/ai-advisor" element={<ProductLayout product={AI_ADVISOR} />}>
            <Route index element={<Navigate to="agents" replace />} />
            <Route path="agents" element={<Agents />} />
            <Route path="workflows" element={<Missions />} />
            <Route path="run-trash" element={<AgentRunTrash />} />
          </Route>

          <Route path="/intelligence" element={<ProductLayout product={INTELLIGENCE} />}>
            <Route index element={<Navigate to="ai-assisted-scan" replace />} />
            <Route path="ai-assisted-scan" element={<AIAssistedScan />} />
            <Route path="nl-query" element={<NLQuery />} />
            <Route path="security-docs" element={<SecurityDocs />} />
            <Route path="reports" element={<Reports />} />
            <Route path="knowledge" element={<KnowledgeBase />} />
          </Route>

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
            <Route path="help" element={<Help />} />
          </Route>

          {/* ── v1 AppLayout routes (classic view) ───────────────────────── */}
          <Route element={<Shell />}>
            <Route index element={<Navigate to="/hub" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/risk-overview" element={<RiskOverviewPage />} />
            <Route path="/threat-register" element={<ThreatRegister />} />
            <Route path="/control-deficiencies" element={<ControlDeficiencies />} />
            <Route path="/remediation-tracker" element={<Navigate to="/governance/remediation" replace />} />
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
            <Route path="/vapt-reports" element={<Navigate to="/vapt/reports" replace />} />
            <Route path="/vapt-reports/:reportId" element={<Navigate to="/vapt/reports" replace />} />
            <Route path="/ticket-sync" element={<TicketSyncPage />} />
            <Route path="/ctem" element={<CTEMPage />} />
            <Route path="/security-docs" element={<SecurityDocs />} />
            <Route path="/webhooks" element={<Navigate to="/settings" replace />} />
            <Route path="/api-keys" element={<Navigate to="/settings" replace />} />
            <Route path="/attack-paths" element={<AttackPaths />} />
            <Route path="/cve-pivot" element={<CVEPivot />} />
            <Route path="/data-model" element={<OntologyPage />} />
            <Route path="/nl-query" element={<NLQuery />} />
            <Route path="/ai-assisted-scan" element={<AIAssistedScan />} />
            <Route path="/posture-trends" element={<PostureTrends />} />
            <Route path="/compliance-heatmap" element={<ComplianceHeatmap />} />
            <Route path="/client-comparison" element={<ClientComparison />} />
            <Route path="/ai-guardrails" element={<AIGuardrails />} />
            <Route path="/remediation-jobs" element={<Navigate to="/governance/remediation-jobs" replace />} />
            <Route path="/sample1" element={<SampleHub />} />
            <Route path="/sample2" element={<SampleHubCmd />} />
            <Route path="/1+2" element={<SampleHubCmd />} />
          </Route>
        </Routes>
      </Suspense>
    </MsalAuthenticationTemplate>
  );
}

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30_000 } },
});

export default function App() {
  return (
    <AppErrorBoundary>
    <AuthProvider>
      <QueryClientProvider client={queryClient}>
        <ThemeModeProvider>
          <ViewModeProvider>
            <ClientProvider>
              <ToastContainer theme="dark" position="bottom-right" autoClose={3000} />
              <BrowserRouter>
                <Routes>
                  <Route path="/" element={<LandingV2 />} />
                  <Route path="/*" element={<ProtectedApp />} />
                </Routes>
              </BrowserRouter>
            </ClientProvider>
          </ViewModeProvider>
        </ThemeModeProvider>
      </QueryClientProvider>
    </AuthProvider>
    </AppErrorBoundary>
  );
}
