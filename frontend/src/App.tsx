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
import Reports from "./pages/Reports";
import Account from "./pages/Account";

const darkTheme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: "#A100FF" },
    secondary: { main: "#7500C0" },
    background: { default: "#0A0A0A", paper: "#1A1A1A" },
    divider: "rgba(255,255,255,0.08)",
  },
  typography: {
    fontFamily: '"Inter", "Roboto", sans-serif',
    button: { textTransform: "none", fontWeight: 600 },
    h1: { fontWeight: 700, letterSpacing: "-0.02em" },
    h2: { fontWeight: 700, letterSpacing: "-0.02em" },
    h3: { fontWeight: 700, letterSpacing: "-0.01em" },
    h4: { fontWeight: 700, letterSpacing: "-0.01em" },
    h5: { fontWeight: 600 },
    h6: { fontWeight: 600 },
  },
  shape: { borderRadius: 10 },
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
        root: { textTransform: "none", fontWeight: 600 },
      },
      variants: [
        {
          props: { variant: "contained", color: "primary" },
          style: {
            background: "linear-gradient(135deg, #A100FF 0%, #7500C0 100%)",
            boxShadow: "0 4px 14px rgba(161,0,255,0.35)",
            "&:hover": {
              background: "linear-gradient(135deg, #B533FF 0%, #8810D0 100%)",
              boxShadow: "0 6px 20px rgba(161,0,255,0.5)",
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
      alignItems: "center", justifyContent: "center", background: "#0A0A0A",
    }}>
      <div style={{ fontSize: 64, marginBottom: 16 }}>🛡️</div>
      <h1 style={{ color: "#A100FF", fontFamily: "Inter, sans-serif", fontSize: 32, margin: 0, letterSpacing: "-0.02em" }}>
        NexGenCyberAI
      </h1>
      <p style={{ color: "rgba(255,255,255,0.5)", fontFamily: "Inter, sans-serif", marginBottom: 8 }}>
        AI-Powered Cybersecurity Posture Management
      </p>
      <p style={{ color: "#A100FF", fontFamily: "Inter, sans-serif", fontSize: 12, letterSpacing: 2, textTransform: "uppercase", fontWeight: 700, marginTop: 0, marginBottom: 32 }}>
        An Accenture Product
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
                  <Route path="/reports" element={<Reports />} />
                  <Route path="/ai-settings" element={<AISettings />} />
                  <Route path="/admin" element={<Admin />} />
                  <Route path="/account" element={<Account />} />
                </Route>
              </Routes>
            </BrowserRouter>
          </MsalAuthenticationTemplate>
        </ThemeProvider>
      </QueryClientProvider>
    </AuthProvider>
  );
}
