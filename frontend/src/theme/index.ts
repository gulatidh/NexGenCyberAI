/**
 * Theme module — builds the MUI theme for one of three modes:
 *
 *   "dark"   — refreshed deep-navy palette (default). Replaces the
 *              earlier harsh pure-black look.
 *   "light"  — light surface with the same Google-vibrant accents.
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

export type ThemeMode = "dark" | "light" | "custom";

export interface CustomPalette {
  primary?: string;
  background?: string;
  paper?: string;
}

const COMMON: ThemeOptions = {
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
};

function buildComponents(mode: "dark" | "light"): ThemeOptions["components"] {
  const isDark = mode === "dark";
  return {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          // Subtle gradient backdrop so the page doesn't read as a flat slab.
          // In light mode this is a near-white linear gradient; in dark it's
          // navy → slightly cooler navy.
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
          // Rich tile treatment: a layered elevation shadow + crisp hairline
          // border gives depth in both modes instead of a flat slab. (No
          // background gradient here — it would fight MuiPaper's reset below,
          // since a Card is also a Paper.)
          backgroundImage: "none",
          border: isDark ? "1px solid rgba(255,255,255,0.07)" : "1px solid rgba(15,23,42,0.08)",
          borderRadius: 14,
          boxShadow: isDark
            ? "0 1px 2px rgba(0,0,0,0.45), 0 8px 24px rgba(0,0,0,0.30)"
            : "0 1px 2px rgba(15,23,42,0.06), 0 10px 28px rgba(15,23,42,0.10)",
          transition: "box-shadow .2s ease, border-color .2s ease, transform .2s ease",
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

const DARK: ThemeOptions = {
  ...COMMON,
  palette: {
    mode: "dark",
    primary: { main: "#4285F4" },
    secondary: { main: "#34A853" },
    warning: { main: "#FBBC04" },
    error: { main: "#EA4335" },
    // Refreshed: deep navy instead of harsh pure black; warmer paper.
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

export function buildTheme(mode: ThemeMode, custom?: CustomPalette): Theme {
  if (mode === "light") return createTheme(LIGHT);
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
