/**
 * Renders agent / LLM output as styled markdown for the dark theme.
 *
 * Used in:
 *   - Scan Detail per-agent run tabs
 *   - Agents page briefing drawer
 *   - Risks page AI Agent Insights panel (when present)
 *
 * Accepts a `value` that may be:
 *   - a markdown string                              → rendered as markdown
 *   - an object containing { summary | text | output | result | analysis |
 *     report | verdict } → that field is rendered as markdown; remaining
 *     fields render below as a key/value list for transparency
 *   - any other object/array                         → rendered as a JSON
 *     code block (still inside the markdown styling)
 */
import React from "react";
import { Box, Typography, Divider, Link as MuiLink, Chip } from "@mui/material";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const NARRATIVE_KEYS = ["summary", "text", "output", "result", "analysis", "report", "verdict"];

// Keys that are noisy plumbing and should never appear in the rendered output.
// (Provider info, success flags, raw payload shells etc.)
const HIDE_KEYS = new Set([
  "provider", "success", "model", "tokens_used", "token_usage",
  "raw", "raw_response", "raw_output", "request_id", "trace_id",
  "duration_ms", "elapsed", "cached", "tools_used", "tool_calls",
]);

// Conversational closers we strip from agent text. The LLM keeps offering
// follow-up actions ("would you like me to also generate ServiceNow tickets")
// even when system-prompted not to — easier to scrub on render than to
// re-train the prompt.
const CONVERSATIONAL_PATTERNS: RegExp[] = [
  /\n*if you (would |'d )?like[\s\S]*?\?\s*$/i,
  /\n*shall i[\s\S]*?\?\s*$/i,
  /\n*do you want me to[\s\S]*?\?\s*$/i,
  /\n*would you like me to[\s\S]*?\?\s*$/i,
  /\n*let me know if[\s\S]*$/i,
  /\n*happy to[\s\S]*?\.\s*$/i,
];

function stripConversational(s: string): string {
  let out = s.trim();
  for (const re of CONVERSATIONAL_PATTERNS) out = out.replace(re, "").trim();
  return out;
}

function pickNarrative(obj: any): { text: string; rest: Record<string, any> } {
  if (typeof obj === "string") return { text: stripConversational(obj), rest: {} };
  if (!obj || typeof obj !== "object") return { text: String(obj ?? ""), rest: {} };
  for (const k of NARRATIVE_KEYS) {
    const v = obj[k];
    if (typeof v === "string" && v.trim().length > 0) {
      const rest = { ...obj };
      delete rest[k];
      return { text: stripConversational(v), rest };
    }
  }
  return { text: "", rest: obj };
}

function isPlainObject(v: any): boolean {
  return v && typeof v === "object" && !Array.isArray(v);
}

const mdComponents = {
  h1: ({ children }: any) => (
    <Typography variant="h6" sx={{ color: "text.primary", fontWeight: 700, mt: 2, mb: 1 }}>{children}</Typography>
  ),
  h2: ({ children }: any) => (
    <Typography variant="subtitle1" sx={{ color: "text.primary", fontWeight: 700, mt: 1.5, mb: 0.75 }}>{children}</Typography>
  ),
  h3: ({ children }: any) => (
    <Typography variant="subtitle2" sx={{ color: "#4285F4", fontWeight: 700, mt: 1.25, mb: 0.5, textTransform: "uppercase", fontSize: 12, letterSpacing: 1 }}>
      {children}
    </Typography>
  ),
  h4: ({ children }: any) => (
    <Typography variant="subtitle2" sx={{ color: "text.secondary", fontWeight: 700, mt: 1, mb: 0.5 }}>{children}</Typography>
  ),
  p: ({ children }: any) => (
    <Typography sx={{ color: "text.secondary", fontSize: 13.5, lineHeight: 1.6, mb: 1 }}>{children}</Typography>
  ),
  ul: ({ children }: any) => (
    <Box component="ul" sx={{ pl: 3, my: 0.5, color: "text.secondary", "& li::marker": { color: "#4285F4" } }}>{children}</Box>
  ),
  ol: ({ children }: any) => (
    <Box component="ol" sx={{ pl: 3, my: 0.5, color: "text.secondary", "& li::marker": { color: "#4285F4", fontWeight: 700 } }}>{children}</Box>
  ),
  li: ({ children }: any) => (
    <Box component="li" sx={{ fontSize: 13.5, lineHeight: 1.6, mb: 0.5 }}>{children}</Box>
  ),
  strong: ({ children }: any) => (
    <Box component="strong" sx={{ color: "text.primary", fontWeight: 700 }}>{children}</Box>
  ),
  em: ({ children }: any) => (
    <Box component="em" sx={{ color: "text.secondary", fontStyle: "italic" }}>{children}</Box>
  ),
  blockquote: ({ children }: any) => (
    <Box sx={{
      borderLeft: "3px solid #4285F4", pl: 1.5, ml: 0, my: 1, py: 0.5,
      bgcolor: "rgba(66,133,244,0.06)", borderRadius: "0 4px 4px 0",
      color: "text.secondary", fontStyle: "italic",
    }}>{children}</Box>
  ),
  code: ({ inline, children }: any) =>
    inline ? (
      <Box component="code" sx={{
        bgcolor: "rgba(255,255,255,0.08)", color: "#FBBC04",
        px: 0.6, py: 0.15, borderRadius: 0.5,
        fontFamily: "monospace", fontSize: 12,
      }}>{children}</Box>
    ) : (
      <Box component="pre" sx={{
        bgcolor: "rgba(0,0,0,0.35)", border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 1.5, p: 1.25, my: 1, overflow: "auto",
        fontFamily: "monospace", fontSize: 12, color: "text.secondary", lineHeight: 1.5,
      }}>
        <code>{children}</code>
      </Box>
    ),
  a: ({ href, children }: any) => (
    <MuiLink href={href} target="_blank" rel="noreferrer"
      sx={{ color: "#4285F4", textDecorationColor: "rgba(66,133,244,0.4)" }}>{children}</MuiLink>
  ),
  hr: () => <Divider sx={{ my: 1.5, borderColor: "divider" }} />,
  table: ({ children }: any) => (
    <Box component="table" sx={{
      width: "100%", borderCollapse: "collapse", my: 1,
      "& th, & td": { borderBottom: "1px solid rgba(255,255,255,0.08)", px: 1, py: 0.75, fontSize: 12.5, textAlign: "left" },
      "& th": { color: "text.secondary", fontWeight: 700, textTransform: "uppercase", fontSize: 11, letterSpacing: 0.5 },
      "& td": { color: "text.secondary" },
    }}>{children}</Box>
  ),
} as const;

// ── Risk Register helpers ────────────────────────────────────────────────────

type RiskRow = {
  id?: string;
  title?: string;
  level?: string;
  score?: number | string;
  control?: string;
};

const LEVEL_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853",
};

// Parse a "R001: Title | Level=high | Score=6.4 | Control=NIST AC-17" string
// (with multiple entries pipe-joined) into structured rows.
function parseRiskRegisterText(s: string): RiskRow[] {
  if (!s || typeof s !== "string") return [];
  // Split on `Rnnn: ` boundaries while preserving the id token.
  const parts = s.split(/\s*(?=R\d{2,4}:\s)/).map((p) => p.trim()).filter(Boolean);
  const rows: RiskRow[] = [];
  for (const p of parts) {
    const idMatch = p.match(/^(R\d+):\s*([\s\S]*)/);
    if (!idMatch) continue;
    const [, id, rest] = idMatch;
    const segments = rest.split("|").map((x) => x.trim());
    const title = segments[0] || "";
    const meta: Record<string, string> = {};
    for (const seg of segments.slice(1)) {
      const m = seg.match(/^([A-Za-z]+)\s*=\s*(.*)$/);
      if (m) meta[m[1].toLowerCase()] = m[2].trim();
    }
    rows.push({
      id,
      title,
      level: (meta.level || "").toLowerCase() || undefined,
      score: meta.score ? Number(meta.score) || meta.score : undefined,
      control: meta.control || undefined,
    });
  }
  return rows;
}

function normaliseRiskRegister(v: any): RiskRow[] | null {
  if (!v) return null;
  if (typeof v === "string") {
    const rows = parseRiskRegisterText(v);
    return rows.length ? rows : null;
  }
  if (Array.isArray(v)) {
    const rows = v.map((it: any) => {
      if (typeof it === "string") return parseRiskRegisterText(it)[0];
      if (it && typeof it === "object") {
        return {
          id: it.id || it.risk_id,
          title: it.title || it.name || it.description,
          level: (it.level || it.severity || it.risk_level || "").toString().toLowerCase() || undefined,
          score: it.score ?? it.risk_score,
          control: it.control || it.control_id,
        } as RiskRow;
      }
      return null;
    }).filter(Boolean) as RiskRow[];
    return rows.length ? rows : null;
  }
  return null;
}

function RiskRegisterTable({ rows }: { rows: RiskRow[] }) {
  return (
    <Box sx={{ my: 1 }}>
      <Typography variant="caption" sx={{
        color: "#4285F4", textTransform: "uppercase", letterSpacing: 1, fontSize: 11, fontWeight: 700, display: "block", mb: 0.75,
      }}>
        Risk Register ({rows.length})
      </Typography>
      <Box component="table" sx={{
        width: "100%", borderCollapse: "collapse",
        "& th, & td": { borderBottom: "1px solid rgba(255,255,255,0.08)", px: 1, py: 0.6, fontSize: 12, textAlign: "left", verticalAlign: "top" },
        "& th": { color: "text.secondary", fontWeight: 700, textTransform: "uppercase", fontSize: 10.5, letterSpacing: 0.5 },
        "& td": { color: "text.secondary" },
      }}>
        <thead>
          <tr>
            <th style={{ width: 50 }}>ID</th>
            <th style={{ width: 70 }}>LEVEL</th>
            <th style={{ width: 50 }}>SCORE</th>
            <th>RISK</th>
            <th style={{ width: 120 }}>CONTROL</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => {
            const lv = (r.level || "").toLowerCase();
            const color = LEVEL_COLOR[lv] || "rgba(255,255,255,0.5)";
            return (
              <tr key={r.id || i}>
                <td style={{ color: "rgba(255,255,255,0.6)", fontFamily: "monospace" }}>{r.id || `R${i + 1}`}</td>
                <td>
                  {r.level && (
                    <Chip label={r.level} size="small" sx={{
                      bgcolor: `${color}25`, color, fontSize: 10, height: 18, textTransform: "uppercase", fontWeight: 700,
                    }} />
                  )}
                </td>
                <td>
                  {r.score != null && (
                    <Typography component="span" sx={{ color, fontWeight: 700, fontSize: 12 }}>
                      {typeof r.score === "number" ? r.score.toFixed(1) : r.score}
                    </Typography>
                  )}
                </td>
                <td>
                  <Typography variant="body2" sx={{ color: "text.primary", fontSize: 12.5, fontWeight: 500 }}>
                    {r.title || "—"}
                  </Typography>
                </td>
                <td style={{ color: "rgba(255,255,255,0.6)", fontSize: 11.5 }}>{r.control || "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </Box>
    </Box>
  );
}

// ── Metadata list (cleaned) ──────────────────────────────────────────────────

function MetadataList({ data }: { data: Record<string, any> }) {
  const entries = Object.entries(data).filter(([k, v]) => {
    if (HIDE_KEYS.has(k)) return false;
    if (v === null || v === undefined || v === "") return false;
    return true;
  });
  if (entries.length === 0) return null;
  return (
    <Box sx={{ mt: 1, pt: 1, borderTop: "1px solid rgba(255,255,255,0.06)" }}>
      <Box sx={{ display: "grid", gridTemplateColumns: "auto 1fr", columnGap: 1.5, rowGap: 0.5, mt: 0.5 }}>
        {entries.map(([k, v]) => (
          <React.Fragment key={k}>
            <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 600, textTransform: "capitalize" }}>
              {k.replace(/_/g, " ")}
            </Typography>
            <Typography variant="caption" sx={{ color: "text.secondary", wordBreak: "break-word" }}>
              {Array.isArray(v) ? v.join(", ")
                : isPlainObject(v) ? JSON.stringify(v)
                : String(v)}
            </Typography>
          </React.Fragment>
        ))}
      </Box>
    </Box>
  );
}

export default function RichOutput({ value, maxHeight }: { value: any; maxHeight?: number | string }) {
  if (value === null || value === undefined) {
    return <Typography variant="caption" sx={{ color: "text.secondary" }}>No output yet.</Typography>;
  }
  const { text, rest } = pickNarrative(value);

  // Pull risk_register out of rest and render as a structured table.
  let riskRegisterRows: RiskRow[] | null = null;
  let trimmedRest = rest;
  if (isPlainObject(rest) && "risk_register" in rest) {
    riskRegisterRows = normaliseRiskRegister(rest.risk_register);
    if (riskRegisterRows) {
      const r = { ...rest };
      delete r.risk_register;
      trimmedRest = r;
    }
  }

  const fallback = (!text || !text.trim()) && Object.keys(trimmedRest).length > 0 && !riskRegisterRows
    ? "```json\n" + JSON.stringify(trimmedRest, null, 2) + "\n```"
    : "";
  const renderText = text || fallback || (riskRegisterRows ? "" : "_(empty output)_");

  return (
    <Box sx={{
      maxHeight: maxHeight ?? "none",
      overflow: maxHeight ? "auto" : "visible",
      "& > :first-of-type": { mt: "0 !important" },
    }}>
      {renderText && (
        <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents as any}>
          {renderText}
        </ReactMarkdown>
      )}
      {riskRegisterRows && <RiskRegisterTable rows={riskRegisterRows} />}
      {text && Object.keys(trimmedRest).length > 0 && <MetadataList data={trimmedRest} />}
    </Box>
  );
}
