import React, { Suspense, Component, ErrorInfo, ReactNode } from "react";
import { BrowserRouter, Routes, Route, Navigate, useParams } from "react-router-dom";
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

// Redirect that preserves the :id param for old deep-links
function RedirectWithId({ to }: { to: string }) {
  const { id } = useParams();
  return <Navigate to={id ? `${to}/${id}` : to} replace />;
}

// ── Static imports ────────────────────────────────────────────────────────────
import AppLayout from "./components/layout/AppLayout";
import ProductLayout from "./components/layout/ProductLayout";
import DetailLayout from "./components/layout/DetailLayout";
import Hub from "./pages/Hub";
import LandingV2 from "./pages/LandingV2";
import {
  DISCOVER_PRODUCT, ANALYSE_PRODUCT, RESPOND_PRODUCT, AUTOMATE_PRODUCT, REPORT_PRODUCT, PLATFORM,
} from "./products";

// ── Lazy page imports ─────────────────────────────────────────────────────────
const Dashboard         = React.lazy(() => import("./pages/Dashboard"));
const Clients           = React.lazy(() => import("./pages/Clients"));
const ClientDetail      = React.lazy(() => import("./pages/ClientDetail"));
const Connections       = React.lazy(() => import("./pages/Connections"));
const Scans             = React.lazy(() => import("./pages/Scans"));
const ScanDetail        = React.lazy(() => import("./pages/ScanDetail"));
const ScanDiff          = React.lazy(() => import("./pages/ScanDiff"));
const Agents            = React.lazy(() => import("./pages/Agents"));
const EmailSettings     = React.lazy(() => import("./pages/EmailSettings"));
const AccessLogs        = React.lazy(() => import("./pages/AccessLogs"));
const Findings          = React.lazy(() => import("./pages/Findings"));
const Risks             = React.lazy(() => import("./pages/Risks"));
const RiskStaging       = React.lazy(() => import("./pages/RiskStaging"));
const RiskAIAnalysis    = React.lazy(() => import("./pages/RiskAIAnalysis"));
const Assets            = React.lazy(() => import("./pages/Assets"));
const AssetDetail       = React.lazy(() => import("./pages/AssetDetail"));
const Frameworks           = React.lazy(() => import("./pages/Frameworks"));
const FrameworkLibrary     = React.lazy(() => import("./pages/FrameworkLibrary"));
const AuditIntelligence    = React.lazy(() => import("./pages/AuditIntelligence"));
const ComplianceEvaluation = React.lazy(() => import("./pages/ComplianceEvaluation"));
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
const AIAssistedReview    = React.lazy(() => import("./pages/AIAssistedReview"));
const PostureTrends       = React.lazy(() => import("./pages/PostureTrends"));
const ComplianceHeatmap   = React.lazy(() => import("./pages/ComplianceHeatmap"));
const ClientComparison    = React.lazy(() => import("./pages/ClientComparison"));
const EvidencePackage     = React.lazy(() => import("./pages/EvidencePackage"));
const AIGuardrails        = React.lazy(() => import("./pages/AIGuardrails"));
const AuditLogs           = React.lazy(() => import("./pages/AuditLogs"));
const RemediationJobs     = React.lazy(() => import("./pages/RemediationJobs"));
const AgentRunTrash       = React.lazy(() => import("./pages/AgentRunTrash"));
const ReportPage          = React.lazy(() => import("./pages/ReportPage"));
const SetupPage           = React.lazy(() => import("./pages/SetupPage"));
const AISettings          = React.lazy(() => import("./pages/AISettings"));
const Webhooks            = React.lazy(() => import("./pages/Webhooks"));
const APIKeysPage         = React.lazy(() => import("./pages/APIKeysPage"));
const DiscoverPage        = React.lazy(() => import("./pages/DiscoverPage"));
const AnalysePage         = React.lazy(() => import("./pages/AnalysePage"));
const RespondPage         = React.lazy(() => import("./pages/RespondPage"));
const AutomatePage        = React.lazy(() => import("./pages/AutomatePage"));
const SampleHub           = React.lazy(() => import("./pages/SampleHub"));
const SampleHubCmd        = React.lazy(() => import("./pages/SampleHubCmd"));
const SampleAzure         = React.lazy(() => import("./pages/SampleAzure"));
const SampleHub4          = React.lazy(() => import("./pages/SampleHub4"));
const IntegrationsHub     = React.lazy(() => import("./pages/IntegrationsHub"));
const MyProfile           = React.lazy(() => import("./pages/MyProfile"));
const NotificationsCenter = React.lazy(() => import("./pages/NotificationsCenter"));
const Incidents           = React.lazy(() => import("./pages/Incidents"));
const RiskAppetite        = React.lazy(() => import("./pages/RiskAppetite"));
const ScanCoverage        = React.lazy(() => import("./pages/ScanCoverage"));
const ExecutiveSummary    = React.lazy(() => import("./pages/ExecutiveSummary"));
const ReportScheduler     = React.lazy(() => import("./pages/ReportScheduler"));
const AIUsageCost         = React.lazy(() => import("./pages/AIUsageCost"));
const GuestLanding        = React.lazy(() => import("./pages/GuestLanding"));
const GuestPortal         = React.lazy(() => import("./pages/GuestPortal"));

// Redirect helpers that preserve route params
function RedirectScanDetail() { const { id } = useParams(); return <Navigate to={`/discover/scans/${id}`} replace />; }
function RedirectScanDiff()   { const { id } = useParams(); return <Navigate to={`/discover/scans/${id}/diff`} replace />; }

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
          {/* ── Hub ──────────────────────────────────────────────────────── */}
          <Route path="/hub" element={<Hub />} />

          {/* ── DISCOVER ─────────────────────────────────────────────────── */}
          <Route path="/discover" element={<ProductLayout product={DISCOVER_PRODUCT} />}>
            <Route index element={<DiscoverPage />} />
            <Route path="scans"        element={<Scans />} />
            <Route path="findings"     element={<Findings />} />
            <Route path="assets"       element={<Assets />} />
            <Route path="technologies" element={<Technologies />} />
            <Route path="posture"      element={<PostureTrends />} />
            <Route path="ai-scan"      element={<AIAssistedScan />} />
            <Route path="cve-pivot"    element={<CVEPivot />} />
            <Route path="coverage"     element={<ScanCoverage />} />
          </Route>

          {/* ── ANALYSE ──────────────────────────────────────────────────── */}
          <Route path="/analyse" element={<ProductLayout product={ANALYSE_PRODUCT} />}>
            <Route index element={<AnalysePage />} />
            <Route path="risks/staging"      element={<RiskStaging />} />
            <Route path="risks"              element={<Risks />} />
            <Route path="risk-overview"      element={<RiskOverviewPage />} />
            <Route path="ai-analysis"        element={<RiskAIAnalysis />} />
            <Route path="attack-paths"       element={<AttackPaths />} />
            <Route path="threat-models"          element={<ThreatModels />} />
            <Route path="threat-models/:modelId" element={<ThreatModelDetail />} />
            <Route path="nl-query"               element={<NLQuery />} />
            <Route path="compliance-heatmap" element={<ComplianceHeatmap />} />
            <Route path="comparison"         element={<ClientComparison />} />
            <Route path="risk-appetite"      element={<RiskAppetite />} />
          </Route>

          {/* ── RESPOND ──────────────────────────────────────────────────── */}
          <Route path="/respond" element={<ProductLayout product={RESPOND_PRODUCT} />}>
            <Route index element={<RespondPage />} />
            <Route path="threats"          element={<ThreatRegister />} />
            <Route path="gaps"             element={<ControlDeficiencies />} />
            <Route path="remediation"      element={<RemediationTracker />} />
            <Route path="remediation-jobs" element={<RemediationJobs />} />
            <Route path="ctem"             element={<CTEMPage />} />
            <Route path="vapt-reports"     element={<VAPTReports />} />
            <Route path="security-docs"    element={<SecurityDocs />} />
            <Route path="incidents"        element={<Incidents />} />
          </Route>

          {/* ── REPORT ───────────────────────────────────────────────────── */}
          <Route path="/report" element={<ProductLayout product={REPORT_PRODUCT} />}>
            <Route index                    element={<ReportPage />} />
            <Route path="vapt-reports"      element={<VAPTReports />} />
            <Route path="gaps"              element={<ControlDeficiencies />} />
            <Route path="frameworks"        element={<FrameworkLibrary />} />
            <Route path="compliance"        element={<ComplianceEvaluation />} />
            <Route path="custom-frameworks" element={<Navigate to="/report/frameworks" replace />} />
            <Route path="evidence"          element={<EvidencePackage />} />
            <Route path="reports"           element={<Reports />} />
            <Route path="audit"              element={<AuditIntelligence />} />
            <Route path="executive-summary" element={<ExecutiveSummary />} />
            <Route path="scheduler"         element={<ReportScheduler />} />
          </Route>

          {/* ── DETAIL PAGES (full chrome, no product sidebar) ───────────── */}
          <Route element={<DetailLayout />}>
            <Route path="/discover/scans/:scanId"          element={<ScanDetail />} />
            <Route path="/discover/scans/:scanId/diff"     element={<ScanDiff />} />
            <Route path="/discover/assets/:assetId"        element={<AssetDetail />} />
            <Route path="/respond/vapt-reports/:reportId"  element={<VAPTReportDetail />} />
            <Route path="/report/vapt-reports/:reportId"   element={<VAPTReportDetail />} />
          </Route>

          {/* ── AUTOMATE ─────────────────────────────────────────────────── */}
          <Route path="/automate" element={<ProductLayout product={AUTOMATE_PRODUCT} />}>
            <Route index element={<AutomatePage />} />
            <Route path="agents"       element={<Agents />} />
            <Route path="workflows"    element={<Missions />} />
            <Route path="knowledge"    element={<KnowledgeBase />} />
            <Route path="reports"      element={<Reports />} />
            <Route path="ai-scan"      element={<AIAssistedScan />} />
            <Route path="ai-review"    element={<AIAssistedReview />} />
            <Route path="nl-query"     element={<NLQuery />} />
            <Route path="ai-guardrails" element={<AIGuardrails />} />
            <Route path="webhooks"     element={<Navigate to="/platform/integrations?tab=webhooks" replace />} />
            <Route path="api-keys"     element={<Navigate to="/platform/integrations?tab=api-keys" replace />} />
            <Route path="run-trash"    element={<AgentRunTrash />} />
            <Route path="usage"        element={<AIUsageCost />} />
          </Route>

          {/* ── SETUP / PLATFORM ─────────────────────────────────────────── */}
          <Route path="/platform" element={<ProductLayout product={PLATFORM} />}>
            <Route index element={<SetupPage />} />
            <Route path="clients"             element={<Clients />} />
            <Route path="clients/:clientId"   element={<ClientDetail />} />
            <Route path="assets"              element={<Assets />} />
            <Route path="assets/technologies" element={<Technologies />} />
            <Route path="assets/:assetId"     element={<AssetDetail />} />
            <Route path="integrations"        element={<IntegrationsHub />} />
            <Route path="connections"         element={<Navigate to="/platform/integrations" replace />} />
            <Route path="ticket-sync"         element={<TicketSyncPage />} />
            <Route path="ai-settings"         element={<Navigate to="/platform/integrations" replace />} />
            <Route path="audit-logs"          element={<AuditLogs />} />
            <Route path="settings"            element={<Settings />} />
            <Route path="help"                element={<Help />} />
          </Route>

          {/* ── Samples ──────────────────────────────────────────────────── */}
          <Route path="/sample3" element={<SampleAzure />} />
          <Route path="/sample4" element={<SampleHub4 />} />

          {/* ── Redirects from old v2 product routes ─────────────────────── */}
          <Route path="/setup"           element={<Navigate to="/platform" replace />} />
          <Route path="/setup/*"         element={<Navigate to="/platform" replace />} />
          <Route path="/vulnerability"   element={<Navigate to="/discover/scans" replace />} />
          <Route path="/vulnerability/*" element={<Navigate to="/discover/scans" replace />} />
          <Route path="/risk"            element={<Navigate to="/analyse/risks" replace />} />
          <Route path="/risk/*"          element={<Navigate to="/analyse/risks" replace />} />
          <Route path="/threat-intel"    element={<Navigate to="/respond/threats" replace />} />
          <Route path="/threat-intel/*"  element={<Navigate to="/respond/threats" replace />} />
          <Route path="/compliance"      element={<Navigate to="/respond/gaps" replace />} />
          <Route path="/compliance/*"    element={<Navigate to="/respond/gaps" replace />} />
          <Route path="/governance"      element={<Navigate to="/respond/remediation" replace />} />
          <Route path="/governance/*"    element={<Navigate to="/respond/remediation" replace />} />
          <Route path="/ai-advisor"      element={<Navigate to="/automate/agents" replace />} />
          <Route path="/ai-advisor/*"    element={<Navigate to="/automate/agents" replace />} />
          <Route path="/intelligence"    element={<Navigate to="/automate/agents" replace />} />
          <Route path="/intelligence/*"  element={<Navigate to="/automate/agents" replace />} />
          <Route path="/vapt"            element={<Navigate to="/respond/vapt-reports" replace />} />
          <Route path="/vapt/*"          element={<Navigate to="/respond/vapt-reports" replace />} />

          {/* ── Redirects from old v1 shell routes ───────────────────────── */}
          <Route path="/scans"                  element={<Navigate to="/discover/scans" replace />} />
          <Route path="/scans/:id"              element={<RedirectScanDetail />} />
          <Route path="/scans/:id/diff"         element={<RedirectScanDiff />} />
          <Route path="/findings"               element={<Navigate to="/discover/findings" replace />} />
          <Route path="/assets"                 element={<Navigate to="/discover/assets" replace />} />
          <Route path="/assets/technologies"    element={<Navigate to="/discover/technologies" replace />} />
          <Route path="/assets/:id"             element={<Navigate to="/discover/assets" replace />} />
          <Route path="/risks"                  element={<Navigate to="/analyse/risks" replace />} />
          <Route path="/risk-overview"          element={<Navigate to="/analyse/risk-overview" replace />} />
          <Route path="/attack-paths"           element={<Navigate to="/analyse/attack-paths" replace />} />
          <Route path="/threat-models"          element={<Navigate to="/analyse/threat-models" replace />} />
          <Route path="/threat-models/:id"      element={<RedirectWithId to="/analyse/threat-models" />} />
          <Route path="/nl-query"               element={<Navigate to="/analyse/nl-query" replace />} />
          <Route path="/compliance-heatmap"     element={<Navigate to="/analyse/compliance-heatmap" replace />} />
          <Route path="/client-comparison"      element={<Navigate to="/analyse/comparison" replace />} />
          <Route path="/threat-register"        element={<Navigate to="/respond/threats" replace />} />
          <Route path="/control-deficiencies"   element={<Navigate to="/respond/gaps" replace />} />
          <Route path="/remediation-tracker"    element={<Navigate to="/respond/remediation" replace />} />
          <Route path="/remediation-jobs"       element={<Navigate to="/respond/remediation-jobs" replace />} />
          <Route path="/ctem"                   element={<Navigate to="/respond/ctem" replace />} />
          <Route path="/vapt-reports"           element={<Navigate to="/respond/vapt-reports" replace />} />
          <Route path="/vapt-reports/:id"       element={<Navigate to="/respond/vapt-reports" replace />} />
          <Route path="/security-docs"          element={<Navigate to="/respond/security-docs" replace />} />
          <Route path="/ai-assisted-scan"       element={<Navigate to="/discover/ai-scan" replace />} />
          <Route path="/cve-pivot"              element={<Navigate to="/discover/cve-pivot" replace />} />
          <Route path="/posture-trends"         element={<Navigate to="/discover/posture" replace />} />
          <Route path="/ai-guardrails"          element={<Navigate to="/automate/ai-guardrails" replace />} />
          <Route path="/agents"                 element={<Navigate to="/automate/agents" replace />} />
          <Route path="/missions"               element={<Navigate to="/automate/workflows" replace />} />
          <Route path="/knowledge"              element={<Navigate to="/automate/knowledge" replace />} />
          <Route path="/reports"               element={<Navigate to="/automate/reports" replace />} />
          <Route path="/frameworks"             element={<Navigate to="/analyse/compliance-heatmap" replace />} />
          <Route path="/custom-frameworks"      element={<Navigate to="/platform/settings" replace />} />
          <Route path="/webhooks"               element={<Navigate to="/platform/integrations?tab=webhooks" replace />} />
          <Route path="/api-keys"               element={<Navigate to="/platform/integrations?tab=api-keys" replace />} />
          <Route path="/data-model"             element={<OntologyPage />} />
          <Route path="/connections"            element={<Navigate to="/platform/connections" replace />} />
          <Route path="/clients"                element={<Navigate to="/platform/clients" replace />} />
          <Route path="/clients/:id"            element={<Navigate to="/platform/clients" replace />} />
          <Route path="/ticket-sync"            element={<Navigate to="/platform/ticket-sync" replace />} />
          <Route path="/settings"               element={<Navigate to="/platform/settings" replace />} />
          <Route path="/help"                   element={<Navigate to="/platform/help" replace />} />
          <Route path="/ai-settings"            element={<Navigate to="/platform/integrations" replace />} />

          {/* ── Admin-only Shell pages (kept in AppLayout) ───────────────── */}
          <Route element={<Shell />}>
            <Route index element={<Navigate to="/hub" replace />} />
            <Route path="/dashboard"          element={<Dashboard />} />
            <Route path="/account"            element={<Account />} />
            <Route path="/account/profile"    element={<MyProfile />} />
            <Route path="/account/notifications" element={<NotificationsCenter />} />
            <Route path="/admin"           element={<Admin />} />
            <Route path="/sync"            element={<SyncPage />} />
            <Route path="/email-settings"  element={<EmailSettings />} />
            <Route path="/access-logs"     element={<AccessLogs />} />
            <Route path="/projects"        element={<Projects />} />
            <Route path="/stale-assets"    element={<Navigate to="/discover/assets" replace />} />
            <Route path="/sample1"         element={<SampleHub />} />
            <Route path="/sample2"         element={<SampleHubCmd />} />
            <Route path="/1+2"             element={<SampleHubCmd />} />
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
                  {/* Guest routes — no MSAL auth, token is the credential */}
                  <Route path="/guest/:token" element={
                    <Suspense fallback={<PageLoader />}><GuestLanding /></Suspense>
                  } />
                  <Route path="/guest/portal/*" element={
                    <Suspense fallback={<PageLoader />}><GuestPortal /></Suspense>
                  } />
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
