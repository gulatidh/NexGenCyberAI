/**
 * Guest landing page — /guest/:token
 * Validates the raw token, stores the guest JWT in sessionStorage, then
 * redirects into the read-only guest shell.
 */
import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Box, Typography, Button, CircularProgress, Alert, Paper, Chip,
} from "@mui/material";
import { Shield, CalendarMonth, AccountCircle, FolderOpen } from "@mui/icons-material";
import { guestTokensApi } from "../services/api";

export const GUEST_JWT_KEY = "aegis-guest-jwt";
export const GUEST_META_KEY = "aegis-guest-meta";

export default function GuestLanding() {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();
  const [info, setInfo] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [entering, setEntering] = useState(false);

  useEffect(() => {
    if (!token) { setError("Invalid link — no token found."); setLoading(false); return; }
    guestTokensApi.info(token)
      .then((d) => { setInfo(d); setLoading(false); })
      .catch((e) => {
        setError(e?.response?.data?.detail || "This link is invalid or has expired.");
        setLoading(false);
      });
  }, [token]);

  const enter = async () => {
    if (!token) return;
    setEntering(true);
    try {
      const resp = await guestTokensApi.redeem(token);
      sessionStorage.setItem(GUEST_JWT_KEY, resp.access_token);
      sessionStorage.setItem(GUEST_META_KEY, JSON.stringify({
        label: resp.label,
        client_id: resp.client_id,
        project_id: resp.project_id,
        expires_at: resp.expires_at,
      }));
      // Pre-select the scoped client so the global selector is correct on entry
      if (resp.client_id) {
        localStorage.setItem("aegis-active-client", String(resp.client_id));
      }
      navigate("/hub");
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Could not redeem link.");
      setEntering(false);
    }
  };

  const expiry = info?.expires_at ? new Date(info.expires_at) : null;
  const daysLeft = expiry ? Math.ceil((expiry.getTime() - Date.now()) / 86400000) : null;

  return (
    <Box sx={{
      minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center",
      bgcolor: "#0a0a0f", p: 3,
    }}>
      <Paper elevation={8} sx={{
        maxWidth: 480, width: "100%", p: 4, borderRadius: 3,
        bgcolor: "#141420", border: "1px solid rgba(66,133,244,0.2)",
      }}>
        {/* Header */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 3 }}>
          <Shield sx={{ color: "#4285F4", fontSize: 32 }} />
          <Box>
            <Typography sx={{ fontWeight: 800, fontSize: 20, color: "#fff" }}>
              Owlet AI Portal
            </Typography>
            <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.4)" }}>
              Guest access link
            </Typography>
          </Box>
        </Box>

        {loading && (
          <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
            <CircularProgress size={36} sx={{ color: "#4285F4" }} />
          </Box>
        )}

        {error && (
          <Alert severity="error" sx={{ mt: 1 }}>{error}</Alert>
        )}

        {info && !error && (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <Typography sx={{ fontSize: 18, fontWeight: 700, color: "#fff", lineHeight: 1.3 }}>
              {info.label}
            </Typography>

            {info.note && (
              <Typography sx={{ fontSize: 13, color: "rgba(255,255,255,0.55)", lineHeight: 1.5 }}>
                {info.note}
              </Typography>
            )}

            <Box sx={{ display: "flex", flexDirection: "column", gap: 1, p: 2,
              bgcolor: "rgba(255,255,255,0.04)", borderRadius: 1.5, border: "1px solid rgba(255,255,255,0.08)" }}>
              <Row icon={<AccountCircle sx={{ fontSize: 15, color: "#4285F4" }} />}
                label="Account" value={info.client_name} />
              {info.project_name && (
                <Row icon={<FolderOpen sx={{ fontSize: 15, color: "#FBBC04" }} />}
                  label="Project" value={info.project_name} />
              )}
              <Row icon={<CalendarMonth sx={{ fontSize: 15, color: "#34A853" }} />}
                label="Expires"
                value={expiry ? expiry.toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" }) : "—"} />
            </Box>

            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              <Chip label="Full access" size="small"
                sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontSize: 11 }} />
              <Chip label={`${daysLeft} day${daysLeft === 1 ? "" : "s"} remaining`} size="small"
                sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 11 }} />
              {info.scope === "project" && (
                <Chip label="Project-scoped" size="small"
                  sx={{ bgcolor: "rgba(156,39,176,0.12)", color: "#ce93d8", fontSize: 11 }} />
              )}
            </Box>

            <Alert severity="success" sx={{ fontSize: 12, bgcolor: "rgba(52,168,83,0.08)",
              border: "1px solid rgba(52,168,83,0.2)", color: "rgba(255,255,255,0.7)" }}>
              You have full read-write access to this portal. This link expires automatically on the date shown above.
            </Alert>

            <Button variant="contained" size="large" onClick={enter} disabled={entering}
              startIcon={entering ? <CircularProgress size={16} color="inherit" /> : undefined}
              sx={{ mt: 0.5, fontWeight: 700, fontSize: 15 }}>
              {entering ? "Opening portal…" : "Enter Portal"}
            </Button>
          </Box>
        )}
      </Paper>
    </Box>
  );
}

function Row({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
      {icon}
      <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.4)", minWidth: 60 }}>{label}</Typography>
      <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.8)", fontWeight: 600 }}>{value}</Typography>
    </Box>
  );
}
