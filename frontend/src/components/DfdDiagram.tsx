/**
 * Mermaid DFD renderer — theme-aware, emoji-safe.
 *
 * Uses Mermaid %%{init}%% frontmatter for per-render theme config so we
 * don't depend on the cached singleton's initialization (Mermaid stores a
 * single global config; overriding it via initialize() between renders races
 * with concurrent renders).  The frontmatter approach is clean and per-call.
 *
 * Old stored diagrams may contain emoji (🗄️ ⚙️ 🔒 etc.) that Mermaid renders
 * as "??".  We strip them client-side before parsing.
 */
import React, { useEffect, useRef, useState } from "react";
import { Box, CircularProgress, Typography, useTheme } from "@mui/material";
import { ImageNotSupported } from "@mui/icons-material";

let _mermaid: any = null;
let _loadPromise: Promise<any> | null = null;

async function getMermaid(): Promise<any> {
  if (_mermaid) return _mermaid;
  if (!_loadPromise) {
    _loadPromise = (async () => {
      const m = (await import("mermaid")).default;
      // Minimal base init — actual theme goes in each diagram's %%{init}%%
      m.initialize({ startOnLoad: false, securityLevel: "loose" });
      _mermaid = m;
      return m;
    })();
  }
  return _loadPromise;
}

// ── Zone colour rules ──────────────────────────────────────────────────────
// Applied via Mermaid `style` statements appended to the source so they work
// with any theme. Fills use 8-digit hex (no rgba — Mermaid splits on commas).
const ZONE_RULES: { test: RegExp; fill: string; stroke: string; textColor: string }[] = [
  { test: /(public|internet|external|untrust|wan)/,                   fill: "#EA433520", stroke: "#EA4335", textColor: "#EA4335" },
  { test: /(dmz|perimeter|edge|public.facing)/,                       fill: "#F9AB0018", stroke: "#F9AB00", textColor: "#E37400" },
  { test: /(corporate|private|internal|trusted|corp|lan|intranet)/,   fill: "#1A73E818", stroke: "#1A73E8", textColor: "#1A73E8" },
  { test: /(vendor|saas|third.party)/,                                fill: "#FF704318", stroke: "#FF7043", textColor: "#FF7043" },
  { test: /(data|database|storage|tier|backend)/,                     fill: "#9C27B018", stroke: "#9C27B0", textColor: "#9C27B0" },
  { test: /(manage|mgmt|admin|control|management|sentinel|siem)/,     fill: "#00897B18", stroke: "#00897B", textColor: "#00897B" },
];

function colorizeZones(src: string, isDark: boolean): string {
  if (!src) return src;
  const re = /subgraph\s+([A-Za-z0-9_-]+)\s*(?:\[\s*"?([^"\]]*)"?\s*\])?/g;
  const styles: string[] = [];
  const seen = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    const id = m[1];
    if (seen.has(id)) continue;
    seen.add(id);
    const hay = `${id} ${m[2] || ""}`.toLowerCase();
    const rule = ZONE_RULES.find((r) => r.test.test(hay));
    if (rule) {
      const textCol = isDark ? "#ffffff" : rule.textColor;
      styles.push(`style ${id} fill:${rule.fill},stroke:${rule.stroke},stroke-width:2px,color:${textCol}`);
    }
  }
  return styles.length ? `${src}\n${styles.join("\n")}` : src;
}

// ── Emoji stripper ─────────────────────────────────────────────────────────
// Removes any emoji / pictograph / dingbat codepoints that Mermaid's SVG
// renderer cannot handle and shows as "??".
const EMOJI_RE = /[\u{1F000}-\u{1FFFF}\u{2600}-\u{27BF}\u{1F300}-\u{1FAFF}]️?/gu;

function stripEmoji(src: string): string {
  return src.replace(EMOJI_RE, "").replace(/\s{2,}/g, " ");
}

// ── Per-render %%{init}%% frontmatter ──────────────────────────────────────
function buildFrontmatter(isDark: boolean): string {
  const theme = isDark ? "dark" : "default";
  const vars = isDark
    ? {
        primaryColor: "#1E2433",
        primaryTextColor: "#E0E0E0",
        primaryBorderColor: "#4285F4",
        lineColor: "#9E9E9E",
        secondaryColor: "#263145",
        tertiaryColor: "#161b22",
        mainBkg: "#1E2433",
        clusterBkg: "transparent",
        clusterBorder: "#444",
        edgeLabelBackground: "#1E2433",
        fontFamily: "Inter, system-ui, sans-serif",
      }
    : {
        primaryColor: "#F5F7FA",
        primaryTextColor: "#212121",
        primaryBorderColor: "#4285F4",
        lineColor: "#555555",
        secondaryColor: "#EEF2F8",
        tertiaryColor: "#F0F4FB",
        mainBkg: "#F5F7FA",
        clusterBkg: "transparent",
        clusterBorder: "#BDBDBD",
        edgeLabelBackground: "#FFFFFF",
        fontFamily: "Inter, system-ui, sans-serif",
      };
  return `%%{init:{'theme':'${theme}','themeVariables':${JSON.stringify(vars)},'flowchart':{'curve':'basis','htmlLabels':true,'padding':14}}}%%\n`;
}

// ── Component ──────────────────────────────────────────────────────────────

interface Props {
  source: string;
  className?: string;
}

export default function DfdDiagram({ source, className }: Props) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const ref = useRef<HTMLDivElement | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function render() {
      if (!source?.trim()) {
        if (!cancelled) { setError("No diagram available."); setLoading(false); }
        return;
      }
      try {
        setLoading(true);
        setError(null);
        const mermaid = await getMermaid();
        const clean = stripEmoji(source);
        const fm = buildFrontmatter(isDark);
        const full = fm + colorizeZones(clean, isDark);
        const id = `dfd-${Math.random().toString(36).slice(2)}`;
        const { svg } = await mermaid.render(id, full);
        if (!cancelled && ref.current) {
          ref.current.innerHTML = svg;
          setLoading(false);
        }
      } catch (exc: any) {
        if (!cancelled) {
          setError(exc?.message || "Failed to render diagram.");
          setLoading(false);
        }
      }
    }
    render();
    return () => { cancelled = true; };
  }, [source, isDark]);

  if (error) {
    return (
      <Box className={className} sx={{
        display: "flex", alignItems: "center", justifyContent: "center", gap: 1,
        p: 4, border: "1px dashed", borderColor: "divider", borderRadius: 2,
        color: "text.secondary",
      }}>
        <ImageNotSupported sx={{ fontSize: 24 }} />
        <Typography variant="body2">{error}</Typography>
      </Box>
    );
  }

  return (
    <Box
      className={className}
      sx={{
        position: "relative", overflow: "auto",
        bgcolor: "background.paper",
        borderRadius: 2,
        border: "1px solid",
        borderColor: "divider",
        p: 2, minHeight: 200,
        "& svg": { maxWidth: "100%", height: "auto", display: "block", mx: "auto" },
        "& .cluster rect": { rx: 8, ry: 8 },
        "& .edgeLabel": { fontSize: "11px !important" },
      }}
    >
      {loading && (
        <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
          <CircularProgress size={20} sx={{ color: "#4285F4" }} />
        </Box>
      )}
      <Box ref={ref} sx={{ display: loading ? "none" : "block" }} />
    </Box>
  );
}
