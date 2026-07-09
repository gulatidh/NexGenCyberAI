/**
 * TrialActivate — landing page after "Start Free Trial" login redirect.
 * Calls POST /users/trial/start/ then navigates to /dashboard.
 * Requires auth (wrapped in MsalAuthenticationTemplate like ProtectedApp).
 */
import React, { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useMsal, MsalAuthenticationTemplate } from "@azure/msal-react";
import { InteractionType } from "@azure/msal-browser";
import { Box, CircularProgress, Typography } from "@mui/material";
import { loginRequest } from "../auth/msalConfig";
import { usersApi } from "../services/api";

function ActivateInner() {
  const navigate = useNavigate();
  const { accounts } = useMsal();
  const called = useRef(false);

  useEffect(() => {
    if (called.current || accounts.length === 0) return;
    called.current = true;
    usersApi.startTrial()
      .catch(() => {})
      .finally(() => navigate("/dashboard", { replace: true }));
  }, [accounts, navigate]);

  return (
    <Box sx={{
      height: "100vh", display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center", bgcolor: "#060810", color: "#fff",
    }}>
      <CircularProgress sx={{ color: "#4285F4", mb: 3 }} size={48} />
      <Typography variant="h6" sx={{ fontWeight: 600 }}>Activating your free trial…</Typography>
      <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)", mt: 1 }}>
        You'll be redirected to the dashboard in a moment.
      </Typography>
    </Box>
  );
}

export default function TrialActivate() {
  return (
    <MsalAuthenticationTemplate interactionType={InteractionType.Redirect} authenticationRequest={loginRequest}>
      <ActivateInner />
    </MsalAuthenticationTemplate>
  );
}
