/**
 * View mode — "executive" (read-only: dashboards, reports, drill-downs) vs
 * "analyst" (full: can initiate scans, agents, threat models, syncs, …).
 *
 * Persisted in localStorage. Default is "analyst" so existing behaviour is
 * unchanged; Executive is an opt-in read-only lens. Components gate
 * job-initiating actions with `isExecutive` / `canAct`.
 */
import React, { createContext, useContext, useEffect, useState } from "react";

export type ViewMode = "executive" | "analyst";

interface ViewModeCtx {
  mode: ViewMode;
  setMode: (m: ViewMode) => void;
  isExecutive: boolean;
  canAct: boolean; // true in analyst mode — gate write/initiate actions on this
}

const MODE_KEY = "ui-view-mode";

const Ctx = createContext<ViewModeCtx>({
  mode: "analyst",
  setMode: () => {},
  isExecutive: false,
  canAct: true,
});

export function useViewMode(): ViewModeCtx {
  return useContext(Ctx);
}

function loadInitial(): ViewMode {
  try {
    const v = window.localStorage.getItem(MODE_KEY);
    if (v === "executive" || v === "analyst") return v;
  } catch { /* SSR / private mode */ }
  return "analyst";
}

export function ViewModeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<ViewMode>(loadInitial);

  useEffect(() => {
    try { window.localStorage.setItem(MODE_KEY, mode); } catch { /* ignore */ }
  }, [mode]);

  const value: ViewModeCtx = {
    mode,
    setMode: setModeState,
    isExecutive: mode === "executive",
    canAct: mode === "analyst",
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
