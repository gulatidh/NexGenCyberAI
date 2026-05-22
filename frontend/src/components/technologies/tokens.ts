// Shared tokens for the Technology Inventory page.

import type { TechStatus, RiskLevelLow } from "../../types";

export const STATUS_COLOR: Record<TechStatus, string> = {
  healthy: "#00e676",
  warning: "#ff9800",
  critical: "#f44336",
  ignored: "rgba(255,255,255,0.4)",
};

export const STATUS_BG: Record<TechStatus, string> = {
  healthy: "rgba(0,230,118,0.10)",
  warning: "rgba(255,152,0,0.10)",
  critical: "rgba(244,67,54,0.10)",
  ignored: "rgba(255,255,255,0.05)",
};

export const RISK_COLOR: Record<RiskLevelLow, string> = {
  critical: "#f44336",
  high: "#ff9800",
  medium: "#ffeb3b",
  low: "#4caf50",
};

export const TYPE_COLORS = [
  "#A100FF", "#7500C0", "#ff6d00", "#00e676", "#ff4081",
  "#ffd54f", "#ba68c8", "#26c6da", "#9ccc65", "#ff8a65",
];

export const cardSx = {
  bgcolor: "#1A1A1A",
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: 2,
};
