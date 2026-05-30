import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { ThemeProvider, createTheme, CssBaseline } from "@mui/material";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MsalAuthenticationTemplate } from "@azure/msal-react";
import { InteractionType } from "@azure/msal-browser";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { AuthProvider } from "./auth/AuthProvider";
import { loginRequest } from "./auth/msalConfig";
import AppLayout from "./components/layout/AppLayout";
import Dashboard from "./pages/Dashboard";
import Clients from "./pages/Clients";
import ClientDetail from "./pages/ClientDetail";
import Connectors from "./pages/Connectors";
import Scans from "./pages/Scans";
import Agents from "./pages/Agents";
import AISettings from "./pages/AISettings";
import Findings from "./pages/Findings";
import Risks from "./pages/Risks";
import Assets from "./pages/Assets";
import AssetDetail from "./pages/AssetDetail";
import Frameworks from "./pages/Frameworks";
import RiskOverviewPage from "./pages/RiskOverview";
import Projects from "./pages/Projects";
import Technologies from "./pages/Technologies";
import Admin from "./pages/Admin";
import SyncPage from "./pages/Sync";
import Help from "./pages/Help";
import Reports from "./pages/Reports";
import Account from "./pages/Account";
import Missions from "./pages/Missions";
import KnowledgeBase from "./pages/KnowledgeBase";
import ScanDetail from "./pages/ScanDetail";

const darkTheme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: "#4285F4" },
    secondary: { main: "#34A853" },
    warning: { main: "#FBBC04" },
    error: { main: "#EA4335" },
    background: { default: "#0F0F0F", paper: "#1E1E1E" },
    divider: "rgba(255,255,255,0.08)",
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Google Sans", sans-serif',
    button: { textTransform: "none", fontWeight: 600 },
    h1: { fontWeight: 700, letterSpacing: "-0.02em" },
    h2: { fontWeight: 700, letterSpacing: "-0.02em" },
    h3: { fontWeight: 700, letterSpacing: "-0.01em" },
    h4: { fontWeight: 700, letterSpacing: "-0.01em" },
    h5: { fontWeight: 600 },
    h6: { fontWeight: 600 },
  },
  shape: { borderRadius: 12 },
  components: {
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          border: "1px solid rgba(255,255,255,0.06)",
        },
      },
    },
    MuiPaper: {
      styleOverrides: { root: { backgroundImage: "none" } },
    },
    MuiButton: {
      styleOverrides: {
        root: { textTransform: "none", fontWeight: 600, borderRadius: 24 },
      },
      variants: [
        {
          props: { variant: "contained", color: "primary" },
          style: {
            background: "linear-gradient(135deg, #4285F4 0%, #1A73E8 100%)",
            boxShadow: "0 4px 14px rgba(66,133,244,0.35)",
            "&:hover": {
              background: "linear-gradient(135deg, #5B9CFF 0%, #2B85F5 100%)",
              boxShadow: "0 6px 20px rgba(66,133,244,0.5)",
            },
          },
        },
      ],
    },
  },
});

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30_000 } },
});

function LoginPage() {
  return (
    <div style={{
      height: "100vh", display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center", background: "#0F0F0F",
    }}>
      <div style={{ fontSize: 64, marginBottom: 16 }}>🛡️</div>
      <h1 style={{ fontFamily: "Inter, sans-serif", fontSize: 32, margin: 0, letterSpacing: "-0.02em" }}>
        <span style={{ color: "#4285F4" }}>N</span>
        <span style={{ color: "#EA4335" }}>e</span>
        <span style={{ color: "#FBBC04" }}>x</span>
        <span style={{ color: "#4285F4" }}>G</span>
        <span style={{ color: "#34A853" }}>e</span>
        <span style={{ color: "#EA4335" }}>n</span>
        <span style={{ color: "#FFFFFF" }}>CyberAI</span>
      </h1>
      <p style={{ color: "rgba(255,255,255,0.5)", fontFamily: "Inter, sans-serif", marginBottom: 8 }}>
        AI-Powered Cybersecurity Posture Management
      </p>
      <p style={{ color: "#4285F4", fontFamily: "Inter, sans-serif", fontSize: 12, letterSpacing: 2, textTransform: "uppercase", fontWeight: 700, marginTop: 0, marginBottom: 32 }}>
        A DRJ Product
      </p>
      <p style={{ color: "rgba(255,255,255,0.3)", fontSize: 14 }}>Redirecting to Microsoft Entra ID login...</p>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider theme={darkTheme}>
          <CssBaseline />
          <ToastContainer theme="dark" position="bottom-right" autoClose={3000} />
          <MsalAuthenticationTemplate
            interactionType={InteractionType.Redirect}
            authenticationRequest={loginRequest}
            loadingComponent={LoginPage}
            errorComponent={() => (
              <div style={{ color: "red", padding: 40, fontFamily: "Inter, sans-serif" }}>
                Authentication Error — check Entra ID app registration
              </div>
            )}
          >
            <BrowserRouter>
              <Routes>
                <Route element={<AppLayout />}>
                  <Route index element={<Navigate to="/dashboard" replace />} />
                  <Route path="/dashboard" element={<Dashboard />} />
                  <Route path="/risk-overview" element={<RiskOverviewPage />} />
                  <Route path="/clients" element={<Clients />} />
                  <Route path="/clients/:clientId" element={<ClientDetail />} />
                  <Route path="/projects" element={<Projects />} />
                  <Route path="/connectors" element={<Connectors />} />
                  <Route path="/scans" element={<Scans />} />
                  <Route path="/scans/:scanId" element={<ScanDetail />} />
                  <Route path="/findings" element={<Findings />} />
                  <Route path="/risks" element={<Risks />} />
                  <Route path="/assets" element={<Assets />} />
                  <Route path="/assets/technologies" element={<Technologies />} />
                  <Route path="/assets/:assetId" element={<AssetDetail />} />
                  <Route path="/frameworks" element={<Frameworks />} />
                  <Route path="/agents" element={<Agents />} />
                  <Route path="/reports" element={<Reports />} />
                  <Route path="/ai-settings" element={<AISettings />} />
                  <Route path="/admin" element={<Admin />} />
                  <Route path="/sync" element={<SyncPage />} />
                  <Route path="/help" element={<Help />} />
                  <Route path="/account" element={<Account />} />
                  <Route path="/missions" element={<Missions />} />
                  <Route path="/knowledge" element={<KnowledgeBase />} />
                </Route>
              </Routes>
            </BrowserRouter>
          </MsalAuthenticationTemplate>
        </ThemeProvider>
      </QueryClientProvider>
    </AuthProvider>
  );
}
