/**
 * Central datetime utilities. Backend timestamps are UTC (with or without
 * an explicit "Z" suffix); these helpers parse them as UTC and convert to
 * the user-selected timezone before formatting.
 *
 * Timezone preference is persisted in localStorage under "user_tz".
 */
import dayjs from "dayjs";
import utc from "dayjs/plugin/utc";
import timezone from "dayjs/plugin/timezone";
import relativeTime from "dayjs/plugin/relativeTime";
import advancedFormat from "dayjs/plugin/advancedFormat";

dayjs.extend(utc);
dayjs.extend(timezone);
dayjs.extend(relativeTime);
dayjs.extend(advancedFormat);

const TZ_KEY = "user_tz";

export function getUserTz(): string {
  return localStorage.getItem(TZ_KEY) || dayjs.tz.guess() || "UTC";
}

export function setUserTz(tz: string): void {
  if (tz) localStorage.setItem(TZ_KEY, tz);
  else localStorage.removeItem(TZ_KEY);
}

export function clearUserTz(): void {
  localStorage.removeItem(TZ_KEY);
}

/** Parse a backend UTC string and return a dayjs in the user's tz. Null → null. */
export function dt(input?: string | null): dayjs.Dayjs | null {
  if (!input) return null;
  return dayjs.utc(input).tz(getUserTz());
}

/** Format helper: returns "—" for missing input. Default format: "YYYY-MM-DD HH:mm". */
export function fmt(input?: string | null, format: string = "YYYY-MM-DD HH:mm"): string {
  const d = dt(input);
  return d ? d.format(format) : "—";
}

/** Date-only format: "YYYY-MM-DD". */
export function fmtDate(input?: string | null): string {
  return fmt(input, "YYYY-MM-DD");
}

/** Format with timezone abbreviation, e.g. "2026-05-10 23:45 SGT". */
export function fmtTz(input?: string | null, format: string = "YYYY-MM-DD HH:mm z"): string {
  return fmt(input, format);
}

/** Relative-time helper: "5 minutes ago". UTC-safe. */
export function fromNow(input?: string | null): string {
  if (!input) return "—";
  return dayjs.utc(input).fromNow();
}

/**
 * Common timezone choices grouped by region. Browsers expose far more via
 * Intl.supportedValuesOf("timeZone") but a curated list is friendlier in
 * a select. The "Auto" option uses the browser's detected zone.
 */
export const TZ_OPTIONS: { label: string; value: string }[] = [
  { label: "Auto-detect (browser)", value: "" },
  { label: "UTC", value: "UTC" },
  // Asia-Pacific
  { label: "Asia/Singapore (SGT, UTC+8)", value: "Asia/Singapore" },
  { label: "Asia/Hong_Kong (HKT, UTC+8)", value: "Asia/Hong_Kong" },
  { label: "Asia/Tokyo (JST, UTC+9)", value: "Asia/Tokyo" },
  { label: "Asia/Shanghai (CST, UTC+8)", value: "Asia/Shanghai" },
  { label: "Asia/Seoul (KST, UTC+9)", value: "Asia/Seoul" },
  { label: "Asia/Kolkata (IST, UTC+5:30)", value: "Asia/Kolkata" },
  { label: "Asia/Dubai (GST, UTC+4)", value: "Asia/Dubai" },
  { label: "Australia/Sydney (AEDT/AEST)", value: "Australia/Sydney" },
  { label: "Australia/Perth (AWST, UTC+8)", value: "Australia/Perth" },
  // Europe
  { label: "Europe/London (GMT/BST)", value: "Europe/London" },
  { label: "Europe/Paris (CET/CEST)", value: "Europe/Paris" },
  { label: "Europe/Berlin (CET/CEST)", value: "Europe/Berlin" },
  { label: "Europe/Madrid (CET/CEST)", value: "Europe/Madrid" },
  { label: "Europe/Amsterdam (CET/CEST)", value: "Europe/Amsterdam" },
  { label: "Europe/Stockholm (CET/CEST)", value: "Europe/Stockholm" },
  // Americas
  { label: "America/New_York (EST/EDT)", value: "America/New_York" },
  { label: "America/Chicago (CST/CDT)", value: "America/Chicago" },
  { label: "America/Denver (MST/MDT)", value: "America/Denver" },
  { label: "America/Los_Angeles (PST/PDT)", value: "America/Los_Angeles" },
  { label: "America/Sao_Paulo (BRT/BRST)", value: "America/Sao_Paulo" },
  { label: "America/Mexico_City (CST/CDT)", value: "America/Mexico_City" },
  { label: "America/Toronto (EST/EDT)", value: "America/Toronto" },
  // Africa
  { label: "Africa/Johannesburg (SAST, UTC+2)", value: "Africa/Johannesburg" },
];
