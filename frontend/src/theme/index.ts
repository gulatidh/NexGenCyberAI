/**
 * Theme module — builds the MUI theme for one of four modes:
 *
 *   "dark"   — refreshed deep-navy palette (default). Replaces the
 *              earlier harsh pure-black look.
 *   "light"  — light surface with the same Google-vibrant accents.
 *   "glass"  — Apple Liquid Glass: animated mesh gradient background,
 *              frosted-glass surfaces with backdrop-filter blur.
 *   "custom" — user picks primary + background; everything else is
 *              derived. Stored as a CustomPalette in localStorage.
 *
 * Theme tokens to use in components instead of hard-coded hex:
 *
 *   bgcolor: "background.default"  — page background
 *   bgcolor: "background.paper"    — card / tile background
 *   color:   "text.primary"        — high-contrast text
 *   color:   "text.secondary"      — labels, captions
 *   border:  "1px solid"           — combined with borderColor: "divider"
 *
 * Pages that still use hard-coded values (#1E1E1E, #0F0F0F, etc.) will
 * stay dark across modes; migrate them incrementally.
 */
import { createTheme, Theme } from "@mui/material/styles";
import { ThemeOptions } from "@mui/material/styles";

export type ThemeMode = "dark" | "light" | "glass" | "custom";

export interface CustomPalette {
  primary?: string;
  background?: string;
  paper?: string;
}

const SG = "'Space Grotesk', 'Inter', sans-serif";

const COMMON: ThemeOptions = {
  typography: {
    fontFamily: '"Inter", "Roboto", "Google Sans", sans-serif',
    button: { textTransform: "none", fontWeight: 600 },
    h1: { fontFamily: SG, fontWeight: 700, letterSpacing: "-0.03em" },
    h2: { fontFamily: SG, fontWeight: 700, letterSpacing: "-0.02em" },
    h3: { fontFamily: SG, fontWeight: 700, letterSpacing: "-0.02em" },
    h4: { fontFamily: SG, fontWeight: 700, letterSpacing: "-0.02em" },
    h5: { fontFamily: SG, fontWeight: 700, letterSpacing: "-0.01em" },
    h6: { fontFamily: SG, fontWeight: 600, letterSpacing: "-0.01em" },
  },
  shape: { borderRadius: 12 },
};

function buildComponents(mode: "dark" | "light"): ThemeOptions["components"] {
  const isDark = mode === "dark";
  return {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundImage: isDark
            ? "linear-gradient(180deg, #0B1220 0%, #0E1626 100%)"
            : "linear-gradient(180deg, #F6F8FB 0%, #EEF2F7 100%)",
          backgroundAttachment: "fixed",
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          border: isDark ? "1px solid rgba(148,163,184,0.13)" : "1px solid rgba(15,23,42,0.09)",
          borderRadius: 10,
          boxShadow: "none",
          transition: "border-color .15s ease, box-shadow .15s ease",
          "&:hover": {
            borderColor: isDark ? "rgba(66,133,244,0.45)" : "rgba(26,115,232,0.35)",
            boxShadow: isDark
              ? "0 2px 12px rgba(66,133,244,0.12)"
              : "0 2px 12px rgba(26,115,232,0.08)",
          },
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
  };
}

function buildGlassComponents(): ThemeOptions["components"] {
  const BLUR = "blur(24px) saturate(180%)";
  const BLUR_HEAVY = "blur(32px) saturate(200%)";
  const GLASS_BG = "rgba(18, 8, 55, 0.35)";
  const GLASS_BORDER = "1px solid rgba(255,255,255,0.13)";
  const GLASS_SHADOW = "inset 0 1px 0 rgba(255,255,255,0.10), 0 8px 32px rgba(0,0,0,0.45)";

  return {
    MuiCssBaseline: {
      styleOverrides: {
        "@keyframes liquidGlass": {
          "0%, 100%": { backgroundPosition: "0% 50%" },
          "25%": { backgroundPosition: "100% 0%" },
          "50%": { backgroundPosition: "100% 50%" },
          "75%": { backgroundPosition: "0% 100%" },
        },
        "@keyframes orbFloat": {
          "0%, 100%": { transform: "translate(0, 0) scale(1)" },
          "33%": { transform: "translate(40px, -40px) scale(1.08)" },
          "66%": { transform: "translate(-30px, 30px) scale(0.93)" },
        },
        "@keyframes orbFloat2": {
          "0%, 100%": { transform: "translate(0, 0) scale(1)" },
          "33%": { transform: "translate(-50px, 30px) scale(1.05)" },
          "66%": { transform: "translate(35px, -25px) scale(0.96)" },
        },
        body: {
          background: "linear-gradient(-45deg, #0a0025, #00082e, #080030, #001133, #0d0040, #001a44, #060028)",
          backgroundSize: "400% 400%",
          animation: "liquidGlass 22s ease infinite",
          backgroundAttachment: "fixed",
          "&::before": {
            content: '""',
            position: "fixed",
            width: 700,
            height: 700,
            background: "radial-gradient(circle, rgba(120, 60, 255, 0.28) 0%, transparent 65%)",
            top: -200,
            left: -150,
            animation: "orbFloat 14s ease-in-out infinite",
            pointerEvents: "none",
            zIndex: 0,
          },
          "&::after": {
            content: '""',
            position: "fixed",
            width: 600,
            height: 600,
            background: "radial-gradient(circle, rgba(0, 160, 255, 0.22) 0%, transparent 65%)",
            bottom: -180,
            right: -120,
            animation: "orbFloat2 18s ease-in-out infinite",
            pointerEvents: "none",
            zIndex: 0,
          },
        },
        "#root": {
          position: "relative",
          zIndex: 1,
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          background: GLASS_BG,
          backdropFilter: BLUR,
          WebkitBackdropFilter: BLUR,
          border: GLASS_BORDER,
          boxShadow: GLASS_SHADOW,
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          background: "rgba(18, 8, 55, 0.30)",
          backdropFilter: BLUR,
          WebkitBackdropFilter: BLUR,
          border: GLASS_BORDER,
          borderRadius: 16,
          boxShadow: GLASS_SHADOW,
          transition: "border-color .2s ease, box-shadow .2s ease, transform .2s ease",
          "&:hover": {
            borderColor: "rgba(130, 100, 255, 0.5)",
            boxShadow: "inset 0 1px 0 rgba(255,255,255,0.14), 0 12px 40px rgba(100,60,255,0.25)",
            transform: "translateY(-1px)",
          },
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          background: "rgba(10, 3, 40, 0.45) !important",
          backdropFilter: BLUR_HEAVY,
          WebkitBackdropFilter: BLUR_HEAVY,
          borderBottom: "1px solid rgba(255,255,255,0.10)",
          boxShadow: "0 1px 0 rgba(255,255,255,0.06)",
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          background: "rgba(8, 2, 35, 0.55) !important",
          backdropFilter: BLUR_HEAVY,
          WebkitBackdropFilter: BLUR_HEAVY,
          border: "none",
          borderRight: "1px solid rgba(255,255,255,0.08)",
          boxShadow: "4px 0 24px rgba(0,0,0,0.4)",
        },
      },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          background: "rgba(14, 5, 50, 0.65) !important",
          backdropFilter: BLUR_HEAVY,
          WebkitBackdropFilter: BLUR_HEAVY,
          border: "1px solid rgba(255,255,255,0.15)",
          boxShadow: "0 30px 80px rgba(0,0,0,0.7), inset 0 1px 0 rgba(255,255,255,0.12)",
        },
      },
    },
    MuiPopover: {
      styleOverrides: {
        paper: {
          background: "rgba(14, 5, 50, 0.70) !important",
          backdropFilter: BLUR_HEAVY,
          WebkitBackdropFilter: BLUR_HEAVY,
          border: "1px solid rgba(255,255,255,0.13)",
          boxShadow: "0 20px 60px rgba(0,0,0,0.6)",
        },
      },
    },
    MuiMenu: {
      styleOverrides: {
        paper: {
          background: "rgba(14, 5, 50, 0.72) !important",
          backdropFilter: BLUR_HEAVY,
          WebkitBackdropFilter: BLUR_HEAVY,
          border: "1px solid rgba(255,255,255,0.12)",
          boxShadow: "0 16px 48px rgba(0,0,0,0.55)",
        },
      },
    },
    MuiTableContainer: {
      styleOverrides: {
        root: {
          background: "rgba(14, 5, 50, 0.25)",
          backdropFilter: "blur(12px)",
          WebkitBackdropFilter: "blur(12px)",
          border: GLASS_BORDER,
          borderRadius: 12,
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          background: "rgba(255,255,255,0.08)",
          backdropFilter: "blur(10px)",
          WebkitBackdropFilter: "blur(10px)",
          border: "1px solid rgba(255,255,255,0.12)",
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: { textTransform: "none", fontWeight: 600, borderRadius: 24 },
        outlined: {
          borderColor: "rgba(255,255,255,0.20)",
          background: "rgba(255,255,255,0.06)",
          backdropFilter: "blur(10px)",
          WebkitBackdropFilter: "blur(10px)",
          "&:hover": {
            borderColor: "rgba(255,255,255,0.35)",
            background: "rgba(255,255,255,0.10)",
          },
        },
      },
      variants: [
        {
          props: { variant: "contained", color: "primary" },
          style: {
            background: "linear-gradient(135deg, rgba(100, 80, 255, 0.85) 0%, rgba(66,133,244,0.85) 100%)",
            backdropFilter: "blur(10px)",
            WebkitBackdropFilter: "blur(10px)",
            border: "1px solid rgba(255,255,255,0.25)",
            boxShadow: "0 4px 20px rgba(100,80,255,0.45), inset 0 1px 0 rgba(255,255,255,0.25)",
            "&:hover": {
              background: "linear-gradient(135deg, rgba(120, 100, 255, 0.9) 0%, rgba(80,150,255,0.9) 100%)",
              boxShadow: "0 6px 28px rgba(100,80,255,0.6), inset 0 1px 0 rgba(255,255,255,0.30)",
            },
          },
        },
      ],
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          "& .MuiOutlinedInput-root": {
            background: "rgba(255,255,255,0.05)",
            backdropFilter: "blur(10px)",
            WebkitBackdropFilter: "blur(10px)",
            "& fieldset": { borderColor: "rgba(255,255,255,0.15)" },
            "&:hover fieldset": { borderColor: "rgba(255,255,255,0.28)" },
            "&.Mui-focused fieldset": { borderColor: "rgba(130,100,255,0.7)" },
          },
        },
      },
    },
    MuiTabs: {
      styleOverrides: {
        root: {
          background: "rgba(255,255,255,0.04)",
          backdropFilter: "blur(12px)",
          WebkitBackdropFilter: "blur(12px)",
          borderBottom: "1px solid rgba(255,255,255,0.10)",
        },
      },
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          background: "rgba(18, 8, 55, 0.50)",
          backdropFilter: BLUR,
          WebkitBackdropFilter: BLUR,
          border: GLASS_BORDER,
        },
      },
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          "&:hover": {
            background: "rgba(255,255,255,0.07)",
            backdropFilter: "blur(8px)",
          },
          "&.Mui-selected": {
            background: "rgba(130,100,255,0.18)",
            backdropFilter: "blur(8px)",
            borderLeft: "3px solid rgba(130,100,255,0.8)",
          },
        },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          background: "rgba(14, 5, 50, 0.80)",
          backdropFilter: "blur(16px)",
          WebkitBackdropFilter: "blur(16px)",
          border: "1px solid rgba(255,255,255,0.12)",
          fontSize: 12,
        },
      },
    },
  };
}

const DARK: ThemeOptions = {
  ...COMMON,
  palette: {
    mode: "dark",
    primary: { main: "#4285F4" },
    secondary: { main: "#34A853" },
    warning: { main: "#FBBC04" },
    error: { main: "#EA4335" },
    background: { default: "#0B1220", paper: "#141B2B" },
    divider: "rgba(148,163,184,0.16)",
    text: {
      primary: "#E6EBF3",
      secondary: "rgba(230,235,243,0.62)",
    },
  },
  components: buildComponents("dark"),
};

const LIGHT: ThemeOptions = {
  ...COMMON,
  palette: {
    mode: "light",
    primary: { main: "#1A73E8" },
    secondary: { main: "#34A853" },
    warning: { main: "#F9AB00" },
    error: { main: "#D93025" },
    background: { default: "#F6F8FB", paper: "#FFFFFF" },
    divider: "rgba(15,23,42,0.12)",
    text: {
      primary: "#0F172A",
      secondary: "rgba(15,23,42,0.62)",
    },
  },
  components: buildComponents("light"),
};

const GLASS: ThemeOptions = {
  ...COMMON,
  palette: {
    mode: "dark",
    primary: { main: "#8A6FFF" },
    secondary: { main: "#00D4AA" },
    warning: { main: "#FBBC04" },
    error: { main: "#FF6B6B" },
    // transparent defaults — the animated body gradient shows through
    background: { default: "transparent", paper: "rgba(18, 8, 55, 0.35)" },
    divider: "rgba(255,255,255,0.12)",
    text: {
      primary: "#F0EDFF",
      secondary: "rgba(220,210,255,0.65)",
    },
  },
  components: buildGlassComponents(),
};

export function buildTheme(mode: ThemeMode, custom?: CustomPalette): Theme {
  if (mode === "light") return createTheme(LIGHT);
  if (mode === "glass") return createTheme(GLASS);
  if (mode === "custom" && custom) {
    const primary = custom.primary || "#4285F4";
    const bg = custom.background || "#0B1220";
    const paper = custom.paper || "#141B2B";
    return createTheme({
      ...COMMON,
      palette: {
        mode: "dark",
        primary: { main: primary },
        secondary: { main: "#34A853" },
        warning: { main: "#FBBC04" },
        error: { main: "#EA4335" },
        background: { default: bg, paper },
        divider: "rgba(148,163,184,0.18)",
        text: {
          primary: "#E6EBF3",
          secondary: "rgba(230,235,243,0.62)",
        },
      },
      components: buildComponents("dark"),
    });
  }
  return createTheme(DARK);
}
