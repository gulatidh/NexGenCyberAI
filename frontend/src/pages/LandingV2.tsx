/**
 * Owlet v2 — public landing page (no auth required).
 * Light theme: white hero, blue gradient accents, product tiles, CTA.
 */
import { Box, Typography, Button, Card, CardContent, Chip } from "@mui/material";
import {
  Shield, Radar, BugReport, GppBad, SmartToy,
  PlaylistAddCheck, Assessment, ArrowForward, Security,
  CheckCircleOutlined,
} from "@mui/icons-material";
import { useMsal, useIsAuthenticated } from "@azure/msal-react";
import { useNavigate } from "react-router-dom";
import { useEffect } from "react";
import { loginRequest } from "../auth/msalConfig";

// ── Feature tiles ──────────────────────────────────────────────────────────

const FEATURES = [
  {
    icon: <BugReport />, color: "#00695C", bg: "#E0F2F1",
    title: "Vulnerability Management",
    desc: "Scans, findings, posture trends, and multi-scanner orchestration in one place.",
  },
  {
    icon: <Radar />, color: "#1565C0", bg: "#E3F2FD",
    title: "Threat Intelligence",
    desc: "MITRE ATT&CK mapped threats, attack path graphs, and risk exposure tracking.",
  },
  {
    icon: <GppBad />, color: "#6A1B9A", bg: "#F3E5F5",
    title: "Compliance Monitor",
    desc: "Framework control gaps across NIST, ISO 27001, PCI DSS, GDPR, and CIS v8.",
  },
  {
    icon: <SmartToy />, color: "#E65100", bg: "#FBE9E7",
    title: "AI Security Advisor",
    desc: "60+ specialist AI agents — risk scoring, threat intel, IR playbooks, and more.",
  },
  {
    icon: <Assessment />, color: "#1565C0", bg: "#E3F2FD",
    title: "Risk Manager",
    desc: "FAIR-lite ALE scoring, financial exposure dashboard, and board-ready reports.",
  },
  {
    icon: <PlaylistAddCheck />, color: "#6A1B9A", bg: "#F3E5F5",
    title: "Governance & CTEM",
    desc: "5-phase CTEM workflow, remediation tracker, and embeddable security scorecard.",
  },
];

const TRUST_POINTS = [
  "Microsoft Entra ID — no separate passwords",
  "Azure-hosted — data stays in your tenant",
  "Role-based access — Reader, Editor, Admin",
  "End-to-end encrypted credentials at rest",
];

// ── Nav bar ────────────────────────────────────────────────────────────────

function NavBar({ onSignIn }: { onSignIn: () => void }) {
  return (
    <Box sx={{
      position: "sticky", top: 0, zIndex: 100,
      bgcolor: "rgba(255,255,255,0.92)",
      backdropFilter: "blur(10px)",
      borderBottom: "1px solid rgba(0,0,0,0.08)",
      px: { xs: 2, md: 6 }, py: 1.5,
      display: "flex", alignItems: "center", justifyContent: "space-between",
    }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
        <Box sx={{
          width: 34, height: 34, borderRadius: 1.5,
          background: "linear-gradient(135deg, #1565C0, #0288D1)",
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <Shield sx={{ color: "#fff", fontSize: 18 }} />
        </Box>
        <Typography sx={{ fontWeight: 800, fontSize: 18, color: "#1A2027" }}>
          Owlet
        </Typography>
      </Box>
      <Button
        variant="contained"
        onClick={onSignIn}
        endIcon={<ArrowForward />}
        sx={{
          background: "linear-gradient(135deg, #1565C0, #0288D1)",
          textTransform: "none", fontWeight: 700, fontSize: 13,
          borderRadius: 2, px: 2.5, py: 0.75,
          boxShadow: "0 4px 14px rgba(21,101,192,0.3)",
          "&:hover": { boxShadow: "0 6px 20px rgba(21,101,192,0.45)" },
        }}
      >
        Sign in with Microsoft
      </Button>
    </Box>
  );
}

// ── Hero ───────────────────────────────────────────────────────────────────

function Hero({ onSignIn }: { onSignIn: () => void }) {
  return (
    <Box sx={{
      minHeight: "85vh",
      background: "linear-gradient(160deg, #EEF2F7 0%, #E3F2FD 40%, #F3E5F5 100%)",
      display: "flex", flexDirection: "column", alignItems: "center",
      justifyContent: "center", textAlign: "center",
      px: { xs: 3, md: 8 }, py: 8,
    }}>
      <Chip
        label="AI-Powered Security Platform"
        size="small"
        icon={<Security sx={{ fontSize: "14px !important" }} />}
        sx={{
          mb: 3, bgcolor: "#E3F2FD", color: "#1565C0",
          border: "1px solid rgba(21,101,192,0.2)",
          fontWeight: 600, fontSize: 12,
        }}
      />

      <Typography
        variant="h2"
        sx={{
          fontWeight: 900, lineHeight: 1.1,
          color: "#0F172A",
          fontSize: { xs: 36, md: 56 },
          maxWidth: 800, mb: 2.5,
        }}
      >
        See your risk.{" "}
        <Box component="span" sx={{
          background: "linear-gradient(90deg, #1565C0, #0288D1)",
          WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
        }}>
          Fix what matters.
        </Box>
      </Typography>

      <Typography sx={{
        fontSize: { xs: 15, md: 18 }, color: "#546E7A",
        maxWidth: 600, lineHeight: 1.7, mb: 4,
      }}>
        Owlet unifies vulnerability management, threat intelligence, compliance monitoring,
        and AI-powered analysis into a single security operations platform.
      </Typography>

      <Box sx={{ display: "flex", gap: 1.5, flexWrap: "wrap", justifyContent: "center" }}>
        <Button
          variant="contained"
          size="large"
          onClick={onSignIn}
          endIcon={<ArrowForward />}
          sx={{
            background: "linear-gradient(135deg, #1565C0, #0288D1)",
            textTransform: "none", fontWeight: 700, fontSize: 15,
            borderRadius: 2.5, px: 3.5, py: 1.25,
            boxShadow: "0 6px 24px rgba(21,101,192,0.35)",
            "&:hover": { boxShadow: "0 8px 30px rgba(21,101,192,0.5)" },
          }}
        >
          Sign in with Microsoft
        </Button>
        <Button
          variant="outlined"
          size="large"
          onClick={onSignIn}
          sx={{
            textTransform: "none", fontWeight: 600, fontSize: 15,
            borderRadius: 2.5, px: 3, py: 1.25,
            borderColor: "rgba(21,101,192,0.4)",
            color: "#1565C0",
            "&:hover": { bgcolor: "rgba(21,101,192,0.06)", borderColor: "#1565C0" },
          }}
        >
          Start Free Trial
        </Button>
      </Box>

      {/* Trust points */}
      <Box sx={{ mt: 4, display: "flex", gap: 2, flexWrap: "wrap", justifyContent: "center" }}>
        {TRUST_POINTS.map((point) => (
          <Box key={point} sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <CheckCircleOutlined sx={{ fontSize: 14, color: "#00695C" }} />
            <Typography sx={{ fontSize: 12.5, color: "#546E7A" }}>{point}</Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

// ── Features grid ──────────────────────────────────────────────────────────

function FeaturesSection() {
  return (
    <Box sx={{ bgcolor: "#FFFFFF", px: { xs: 3, md: 8 }, py: 8 }}>
      <Box sx={{ textAlign: "center", mb: 6 }}>
        <Typography variant="h4" sx={{ fontWeight: 800, color: "#0F172A", mb: 1.5 }}>
          One platform, every security function
        </Typography>
        <Typography sx={{ color: "#546E7A", fontSize: 16, maxWidth: 540, mx: "auto" }}>
          Eight purpose-built products across four categories — choose what you need or use them all together.
        </Typography>
      </Box>

      <Box sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr", lg: "1fr 1fr 1fr" },
        gap: 2.5, maxWidth: 1100, mx: "auto",
      }}>
        {FEATURES.map((f) => (
          <Card key={f.title} elevation={0} sx={{
            border: "1px solid rgba(0,0,0,0.08)", borderRadius: 2,
            transition: "box-shadow .2s, transform .2s",
            "&:hover": { boxShadow: "0 8px 28px rgba(0,0,0,0.1)", transform: "translateY(-3px)" },
          }}>
            <CardContent sx={{ p: 2.5 }}>
              <Box sx={{
                width: 44, height: 44, borderRadius: 1.5,
                bgcolor: f.bg, display: "flex", alignItems: "center",
                justifyContent: "center", mb: 1.5, color: f.color,
                "& svg": { fontSize: 22 },
              }}>
                {f.icon}
              </Box>
              <Typography sx={{ fontWeight: 700, fontSize: 15, color: "#0F172A", mb: 0.75 }}>
                {f.title}
              </Typography>
              <Typography sx={{ fontSize: 13.5, color: "#546E7A", lineHeight: 1.6 }}>
                {f.desc}
              </Typography>
            </CardContent>
          </Card>
        ))}
      </Box>
    </Box>
  );
}

// ── CTA section ────────────────────────────────────────────────────────────

function CTASection({ onSignIn }: { onSignIn: () => void }) {
  return (
    <Box sx={{
      background: "linear-gradient(135deg, #1565C0 0%, #0288D1 100%)",
      px: { xs: 3, md: 8 }, py: 8,
      textAlign: "center",
    }}>
      <Typography variant="h4" sx={{ fontWeight: 800, color: "#fff", mb: 2 }}>
        Ready to get started?
      </Typography>
      <Typography sx={{ color: "rgba(255,255,255,0.8)", fontSize: 16, mb: 4, maxWidth: 480, mx: "auto" }}>
        Sign in with your Microsoft work account — no separate account or password needed.
      </Typography>
      <Button
        variant="contained"
        size="large"
        onClick={onSignIn}
        endIcon={<ArrowForward />}
        sx={{
          bgcolor: "#fff", color: "#1565C0",
          textTransform: "none", fontWeight: 700, fontSize: 15,
          borderRadius: 2.5, px: 4, py: 1.25,
          boxShadow: "0 6px 24px rgba(0,0,0,0.15)",
          "&:hover": { bgcolor: "#f5f9ff", boxShadow: "0 8px 30px rgba(0,0,0,0.2)" },
        }}
      >
        Sign in with Microsoft
      </Button>
    </Box>
  );
}

// ── Footer ─────────────────────────────────────────────────────────────────

function Footer() {
  return (
    <Box sx={{
      bgcolor: "#0F172A", px: { xs: 3, md: 8 }, py: 4,
      display: "flex", alignItems: "center", justifyContent: "space-between",
      flexWrap: "wrap", gap: 2,
    }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
        <Box sx={{
          width: 28, height: 28, borderRadius: 1,
          background: "linear-gradient(135deg, #1565C0, #0288D1)",
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <Shield sx={{ color: "#fff", fontSize: 16 }} />
        </Box>
        <Typography sx={{ fontWeight: 700, fontSize: 14, color: "#fff" }}>Owlet</Typography>
      </Box>
      <Typography sx={{ fontSize: 12, color: "rgba(255,255,255,0.4)" }}>
        © {new Date().getFullYear()} Owlet Security Platform. Powered by Anthropic Claude.
      </Typography>
    </Box>
  );
}

// ── Main export ────────────────────────────────────────────────────────────

export default function LandingV2() {
  const { instance } = useMsal();
  const isAuthenticated = useIsAuthenticated();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) navigate("/hub", { replace: true });
  }, [isAuthenticated, navigate]);

  const handleSignIn = () => {
    instance.loginRedirect({
      ...loginRequest,
      redirectStartPage: `${window.location.origin}/hub`,
    }).catch(console.error);
  };

  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "#FFFFFF" }}>
      <NavBar onSignIn={handleSignIn} />
      <Hero onSignIn={handleSignIn} />
      <FeaturesSection />
      <CTASection onSignIn={handleSignIn} />
      <Footer />
    </Box>
  );
}
