/**
 * Theme mode + custom-palette context, persisted in localStorage.
 *
 * Wraps the app with an MUI ThemeProvider whose theme is rebuilt
 * whenever the mode or custom palette changes. Components that need
 * to switch the theme call `useThemeMode()` and invoke `setMode` /
 * `setCustomPalette`.
 */
import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { ThemeProvider, CssBaseline } from "@mui/material";
import { buildTheme, ThemeMode, CustomPalette } from "./index";

const MODE_KEY = "ui-theme-mode";
const CUSTOM_KEY = "ui-theme-custom";

interface ThemeModeCtx {
  mode: ThemeMode;
  setMode: (m: ThemeMode) => void;
  customPalette: CustomPalette;
  setCustomPalette: (p: CustomPalette) => void;
}

const Ctx = createContext<ThemeModeCtx>({
  mode: "dark",
  setMode: () => {},
  customPalette: {},
  setCustomPalette: () => {},
});

export function useThemeMode(): ThemeModeCtx {
  return useContext(Ctx);
}

function loadInitialMode(): ThemeMode {
  try {
    const v = window.localStorage.getItem(MODE_KEY);
    if (v === "dark" || v === "light" || v === "glass" || v === "custom") return v;
  } catch { /* SSR / private mode */ }
  return "light"; // v2 default — light theme
}

function loadInitialCustom(): CustomPalette {
  try {
    const v = window.localStorage.getItem(CUSTOM_KEY);
    if (v) return JSON.parse(v) as CustomPalette;
  } catch { /* ignore */ }
  return {};
}

export function ThemeModeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(loadInitialMode);
  const [customPalette, setCustomState] = useState<CustomPalette>(loadInitialCustom);

  useEffect(() => {
    try { window.localStorage.setItem(MODE_KEY, mode); } catch {}
  }, [mode]);

  useEffect(() => {
    try { window.localStorage.setItem(CUSTOM_KEY, JSON.stringify(customPalette)); } catch {}
  }, [customPalette]);

  const theme = useMemo(() => buildTheme(mode, customPalette), [mode, customPalette]);

  const value: ThemeModeCtx = {
    mode,
    setMode: setModeState,
    customPalette,
    setCustomPalette: setCustomState,
  };

  return (
    <Ctx.Provider value={value}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        {children}
      </ThemeProvider>
    </Ctx.Provider>
  );
}
