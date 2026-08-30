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
const FR = "'Fraunces', Georgia, serif";
const MONO = "'IBM Plex Mono', 'Fira Code', monospace";

// ── Monitara design tokens (from prototype v4) ───────────────────────────────
export const M = {
  // Palette
  paper:       "#EFF1EA",  // page background — warm sage
  paper2:      "#F7F8F3",  // secondary surface
  card:        "#FFFFFF",  // card / tile surface
  ink:         "#20261F",  // primary text
  inkDim:      "#5B6459",  // secondary text
  inkFaint:    "#93998D",  // muted / captions / disabled
  line:        "#DDE1D5",  // borders
  lineSoft:    "#E8EBE1",  // soft dividers
  // Stage accents
  hub:         "#1F6F78",  // teal — primary brand
  setup:       "#3D5A80",  // navy
  discover:    "#C68A2E",  // amber
  analyse:     "#7A4B6D",  // purple
  respond:     "#B0492E",  // terracotta
  report:      "#4C7A52",  // forest green
  automate:    "#4A4E9E",  // indigo
  // Shadows
  shadow:      "0 1px 2px rgba(32,38,31,0.04), 0 6px 18px rgba(32,38,31,0.06)",
  shadowLift:  "0 4px 10px rgba(32,38,31,0.06), 0 14px 32px rgba(32,38,31,0.10)",
} as const;

const COMMON: ThemeOptions = {
  typography: {
    fontFamily: '"Inter", "Roboto", sans-serif',
    button: { textTransform: "none", fontWeight: 600 },
    h1: { fontFamily: FR, fontWeight: 600, letterSpacing: "-0.01em" },
    h2: { fontFamily: FR, fontWeight: 600, letterSpacing: "-0.01em" },
    h3: { fontFamily: FR, fontWeight: 600, letterSpacing: "0em" },
    h4: { fontFamily: FR, fontWeight: 600, letterSpacing: "0em" },
    h5: { fontFamily: FR, fontWeight: 600, letterSpacing: "0em" },
    h6: { fontFamily: SG, fontWeight: 600, letterSpacing: "-0.01em" },
  },
  shape: { borderRadius: 12 },
};

function buildLightComponents(): ThemeOptions["components"] {
  return {
    MuiCssBaseline: {
      styleOverrides: {
        "*, *::before, *::after": { boxSizing: "border-box" },
        body: {
          background: M.paper,
          backgroundImage: "none",
          WebkitFontSmoothing: "antialiased",
          MozOsxFontSmoothing: "grayscale",
        },
        "::selection": { background: "#CFE0DD", color: M.hub },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          background: `${M.paper} !important`,
          backgroundImage: "none !important",
          borderBottom: `1px solid ${M.line}`,
          boxShadow: "none",
          color: M.ink,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          background: `${M.paper2} !important`,
          backgroundImage: "none !important",
          borderRight: `1px solid ${M.line}`,
          boxShadow: "none",
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          background: M.card,
          border: `1px solid ${M.line}`,
          borderRadius: 14,
          boxShadow: M.shadow,
          transition: "transform .12s ease, box-shadow .12s ease",
          "&:hover": {
            transform: "translateY(-1px)",
            boxShadow: M.shadowLift,
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          background: M.card,
          border: `1px solid ${M.line}`,
          boxShadow: M.shadow,
        },
        elevation0: { boxShadow: "none", border: `1px solid ${M.line}` },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: "none",
          fontWeight: 600,
          borderRadius: 9,
          fontSize: "0.8375rem",
          boxShadow: M.shadow,
          "&:active": { transform: "scale(0.98)" },
        },
        outlined: {
          borderWidth: "1.5px",
          borderColor: M.line,
          background: M.card,
          color: M.inkDim,
          "&:hover": { borderColor: M.inkFaint, color: M.ink, background: M.card, borderWidth: "1.5px" },
        },
        contained: {
          background: M.ink,
          color: "#fff",
          "&:hover": { background: "#333d31" },
        },
      },
      variants: [
        {
          props: { variant: "contained", color: "primary" },
          style: {
            background: M.hub,
            boxShadow: `0 2px 8px rgba(31,111,120,0.25)`,
            "&:hover": { background: "#1a5f66", boxShadow: `0 4px 14px rgba(31,111,120,0.35)` },
          },
        },
      ],
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          background: M.paper2,
          borderRadius: 9,
          "& fieldset": { borderColor: M.line, borderWidth: "1.5px" },
          "&:hover fieldset": { borderColor: M.inkFaint },
          "&.Mui-focused fieldset": { borderColor: M.hub, borderWidth: "1.5px" },
        },
        input: { color: M.ink, "&::placeholder": { color: M.inkFaint, opacity: 1 } },
      },
    },
    MuiInputLabel: {
      styleOverrides: {
        root: { color: M.inkFaint, "&.Mui-focused": { color: M.hub } },
      },
    },
    MuiSelect: {
      styleOverrides: {
        select: { background: M.paper2 },
      },
    },
    MuiMenuItem: {
      styleOverrides: {
        root: {
          color: M.ink,
          fontSize: "0.875rem",
          "&:hover": { background: M.paper2 },
          "&.Mui-selected": { background: `rgba(31,111,120,0.08)`, "&:hover": { background: `rgba(31,111,120,0.12)` } },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: 20,
          fontWeight: 600,
          fontSize: "0.72rem",
          background: M.paper2,
          border: `1px solid ${M.line}`,
          color: M.inkDim,
        },
      },
    },
    MuiTableContainer: {
      styleOverrides: {
        root: { background: M.card, border: `1px solid ${M.line}`, borderRadius: 14 },
      },
    },
    MuiTableHead: {
      styleOverrides: {
        root: { background: M.paper2, "& .MuiTableCell-head": { color: M.inkFaint, fontWeight: 700, fontSize: "0.72rem", textTransform: "uppercase", letterSpacing: "0.06em" } },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: { borderColor: M.lineSoft, color: M.ink, fontSize: "0.875rem" },
      },
    },
    MuiTabs: {
      styleOverrides: {
        root: { borderBottom: `1px solid ${M.line}`, background: "transparent", minHeight: 44 },
        indicator: { background: M.hub, height: 2.5 },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          textTransform: "none",
          fontWeight: 500,
          color: M.inkFaint,
          minHeight: 44,
          fontSize: "0.875rem",
          "&.Mui-selected": { color: M.hub, fontWeight: 600 },
        },
      },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          backgroundImage: "none",
          background: M.card,
          border: `1px solid ${M.line}`,
          borderRadius: 16,
          boxShadow: M.shadowLift,
        },
      },
    },
    MuiPopover: {
      styleOverrides: {
        paper: {
          backgroundImage: "none",
          background: M.card,
          border: `1px solid ${M.line}`,
          borderRadius: 12,
          boxShadow: M.shadowLift,
        },
      },
    },
    MuiMenu: {
      styleOverrides: {
        paper: {
          backgroundImage: "none",
          background: M.card,
          border: `1px solid ${M.line}`,
          borderRadius: 12,
          boxShadow: M.shadowLift,
        },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          background: M.ink,
          color: "#fff",
          fontSize: "0.72rem",
          borderRadius: 8,
          fontWeight: 500,
        },
        arrow: { color: M.ink },
      },
    },
    MuiAlert: {
      styleOverrides: {
        root: { borderRadius: 10, border: `1px solid ${M.line}`, fontSize: "0.875rem" },
      },
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          borderRadius: 10,
          color: M.inkDim,
          "&:hover": { background: M.card, color: M.ink },
          "&.Mui-selected": { background: M.card, color: M.ink, borderColor: M.line, boxShadow: M.shadow },
        },
      },
    },
    MuiDivider: {
      styleOverrides: { root: { borderColor: M.line } },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: { borderRadius: 20, background: M.lineSoft },
      },
    },
    MuiCircularProgress: {
      styleOverrides: { root: { color: M.hub } },
    },
    MuiSkeleton: {
      styleOverrides: { root: { background: M.lineSoft } },
    },
    MuiAccordion: {
      styleOverrides: {
        root: {
          background: M.card,
          border: `1px solid ${M.line}`,
          borderRadius: "10px !important",
          boxShadow: "none",
          "&:before": { display: "none" },
          "&.Mui-expanded": { boxShadow: M.shadow },
        },
      },
    },
    MuiSwitch: {
      styleOverrides: {
        track: { background: M.line },
        switchBase: { "&.Mui-checked + .MuiSwitch-track": { background: M.hub } },
        thumb: { boxShadow: M.shadow },
      },
    },
  };
}

function buildDarkComponents(): ThemeOptions["components"] {
  return {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundImage: "linear-gradient(180deg, #0B1220 0%, #0E1626 100%)",
          backgroundAttachment: "fixed",
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          border: "1px solid rgba(148,163,184,0.13)",
          borderRadius: 14,
          boxShadow: "none",
          transition: "border-color .15s ease, box-shadow .15s ease",
          "&:hover": {
            borderColor: "rgba(31,111,120,0.5)",
            boxShadow: "0 2px 12px rgba(31,111,120,0.12)",
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: { root: { backgroundImage: "none" } },
    },
    MuiButton: {
      styleOverrides: {
        root: { textTransform: "none", fontWeight: 600, borderRadius: 9 },
      },
      variants: [
        {
          props: { variant: "contained", color: "primary" },
          style: {
            background: M.hub,
            boxShadow: "0 4px 14px rgba(31,111,120,0.35)",
            "&:hover": { background: "#1a5f66", boxShadow: "0 6px 20px rgba(31,111,120,0.5)" },
          },
        },
      ],
    },
    MuiMenuItem: {
      styleOverrides: {
        root: { color: "#E6EBF3", "&:hover": { background: "rgba(255,255,255,0.06)" } },
      },
    },
    MuiTabs: {
      styleOverrides: {
        indicator: { background: M.hub },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: { textTransform: "none", fontWeight: 500, "&.Mui-selected": { color: M.hub, fontWeight: 600 } },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: { background: "#1E2D3D", border: "1px solid rgba(148,163,184,0.2)", fontSize: 12 },
      },
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
    primary: { main: M.hub },
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
  components: buildDarkComponents(),
};

const LIGHT: ThemeOptions = {
  ...COMMON,
  palette: {
    mode: "light",
    primary: { main: M.hub, light: "#2A8F9A", dark: "#165860" },
    secondary: { main: M.report },
    warning: { main: M.discover },
    error: { main: M.respond },
    background: { default: M.paper, paper: M.card },
    divider: M.line,
    text: {
      primary: M.ink,
      secondary: M.inkDim,
      disabled: M.inkFaint,
    },
  },
  components: buildLightComponents(),
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
      components: buildDarkComponents(),
    });
  }
  return createTheme(DARK);
}
