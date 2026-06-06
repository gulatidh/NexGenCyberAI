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
  canAct: boolean; // true in analyst mode AND not RBAC-read-only
  // RBAC binding: users with no editor/admin grant anywhere are forced
  // read-only (locked to Executive). Set by AppLayout from /admin/me.
  readOnly: boolean;
  setReadOnly: (v: boolean) => void;
}

const MODE_KEY = "ui-view-mode";

const Ctx = createContext<ViewModeCtx>({
  mode: "analyst",
  setMode: () => {},
  isExecutive: false,
  canAct: true,
  readOnly: false,
  setReadOnly: () => {},
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
  const [readOnly, setReadOnly] = useState(false);

  useEffect(() => {
    try { window.localStorage.setItem(MODE_KEY, mode); } catch { /* ignore */ }
  }, [mode]);

  // Read-only (reader) users are always Executive and can never act, no
  // matter what the persisted preference says; the backend enforces this too.
  const effectiveExecutive = mode === "executive" || readOnly;
  const value: ViewModeCtx = {
    mode,
    setMode: setModeState,
    isExecutive: effectiveExecutive,
    canAct: !effectiveExecutive,
    readOnly,
    setReadOnly,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
