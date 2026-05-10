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

const darkTheme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: "#00e5ff" },
    secondary: { main: "#7c4dff" },
    background: { default: "#0f1117", paper: "#161b22" },
  },
  typography: { fontFamily: '"Inter", "Roboto", sans-serif' },
  components: {
    MuiCard: { styleOverrides: { root: { backgroundImage: "none" } } },
  },
});

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30_000 } },
});

function LoginPage() {
  return (
    <div style={{
      height: "100vh", display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center", background: "#0f1117",
    }}>
      <div style={{ fontSize: 64, marginBottom: 16 }}>🛡️</div>
      <h1 style={{ color: "#00e5ff", fontFamily: "Inter, sans-serif", fontSize: 32, margin: 0 }}>NexGenCyberAI</h1>
      <p style={{ color: "rgba(255,255,255,0.5)", fontFamily: "Inter, sans-serif", marginBottom: 32 }}>
        AI-Powered Cybersecurity Posture Management
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
                  <Route path="/findings" element={<Findings />} />
                  <Route path="/risks" element={<Risks />} />
                  <Route path="/assets" element={<Assets />} />
                  <Route path="/assets/technologies" element={<Technologies />} />
                  <Route path="/assets/:assetId" element={<AssetDetail />} />
                  <Route path="/frameworks" element={<Frameworks />} />
                  <Route path="/agents" element={<Agents />} />
                  <Route path="/reports" element={<div style={{ color: "white", padding: 24 }}>Reports</div>} />
                  <Route path="/ai-settings" element={<AISettings />} />
                  <Route path="/admin" element={<Admin />} />
                </Route>
              </Routes>
            </BrowserRouter>
          </MsalAuthenticationTemplate>
        </ThemeProvider>
      </QueryClientProvider>
    </AuthProvider>
  );
}
