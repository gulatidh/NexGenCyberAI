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
import { Box, Typography, Divider, Link as MuiLink } from "@mui/material";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const NARRATIVE_KEYS = ["summary", "text", "output", "result", "analysis", "report", "verdict"];

function pickNarrative(obj: any): { text: string; rest: Record<string, any> } {
  if (typeof obj === "string") return { text: obj, rest: {} };
  if (!obj || typeof obj !== "object") return { text: String(obj ?? ""), rest: {} };
  for (const k of NARRATIVE_KEYS) {
    const v = obj[k];
    if (typeof v === "string" && v.trim().length > 0) {
      const rest = { ...obj };
      delete rest[k];
      return { text: v, rest };
    }
  }
  return { text: "", rest: obj };
}

function isPlainObject(v: any): boolean {
  return v && typeof v === "object" && !Array.isArray(v);
}

const mdComponents = {
  h1: ({ children }: any) => (
    <Typography variant="h6" sx={{ color: "white", fontWeight: 700, mt: 2, mb: 1 }}>{children}</Typography>
  ),
  h2: ({ children }: any) => (
    <Typography variant="subtitle1" sx={{ color: "white", fontWeight: 700, mt: 1.5, mb: 0.75 }}>{children}</Typography>
  ),
  h3: ({ children }: any) => (
    <Typography variant="subtitle2" sx={{ color: "#4285F4", fontWeight: 700, mt: 1.25, mb: 0.5, textTransform: "uppercase", fontSize: 12, letterSpacing: 1 }}>
      {children}
    </Typography>
  ),
  h4: ({ children }: any) => (
    <Typography variant="subtitle2" sx={{ color: "rgba(255,255,255,0.85)", fontWeight: 700, mt: 1, mb: 0.5 }}>{children}</Typography>
  ),
  p: ({ children }: any) => (
    <Typography sx={{ color: "rgba(255,255,255,0.88)", fontSize: 13.5, lineHeight: 1.6, mb: 1 }}>{children}</Typography>
  ),
  ul: ({ children }: any) => (
    <Box component="ul" sx={{ pl: 3, my: 0.5, color: "rgba(255,255,255,0.88)", "& li::marker": { color: "#4285F4" } }}>{children}</Box>
  ),
  ol: ({ children }: any) => (
    <Box component="ol" sx={{ pl: 3, my: 0.5, color: "rgba(255,255,255,0.88)", "& li::marker": { color: "#4285F4", fontWeight: 700 } }}>{children}</Box>
  ),
  li: ({ children }: any) => (
    <Box component="li" sx={{ fontSize: 13.5, lineHeight: 1.6, mb: 0.5 }}>{children}</Box>
  ),
  strong: ({ children }: any) => (
    <Box component="strong" sx={{ color: "white", fontWeight: 700 }}>{children}</Box>
  ),
  em: ({ children }: any) => (
    <Box component="em" sx={{ color: "rgba(255,255,255,0.9)", fontStyle: "italic" }}>{children}</Box>
  ),
  blockquote: ({ children }: any) => (
    <Box sx={{
      borderLeft: "3px solid #4285F4", pl: 1.5, ml: 0, my: 1, py: 0.5,
      bgcolor: "rgba(66,133,244,0.06)", borderRadius: "0 4px 4px 0",
      color: "rgba(255,255,255,0.8)", fontStyle: "italic",
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
        fontFamily: "monospace", fontSize: 12, color: "rgba(255,255,255,0.85)", lineHeight: 1.5,
      }}>
        <code>{children}</code>
      </Box>
    ),
  a: ({ href, children }: any) => (
    <MuiLink href={href} target="_blank" rel="noreferrer"
      sx={{ color: "#4285F4", textDecorationColor: "rgba(66,133,244,0.4)" }}>{children}</MuiLink>
  ),
  hr: () => <Divider sx={{ my: 1.5, borderColor: "rgba(255,255,255,0.08)" }} />,
  table: ({ children }: any) => (
    <Box component="table" sx={{
      width: "100%", borderCollapse: "collapse", my: 1,
      "& th, & td": { borderBottom: "1px solid rgba(255,255,255,0.08)", px: 1, py: 0.75, fontSize: 12.5, textAlign: "left" },
      "& th": { color: "rgba(255,255,255,0.55)", fontWeight: 700, textTransform: "uppercase", fontSize: 11, letterSpacing: 0.5 },
      "& td": { color: "rgba(255,255,255,0.88)" },
    }}>{children}</Box>
  ),
} as const;

function MetadataList({ data }: { data: Record<string, any> }) {
  const entries = Object.entries(data).filter(([_, v]) => v !== null && v !== undefined && v !== "");
  if (entries.length === 0) return null;
  return (
    <Box sx={{ mt: 1, pt: 1, borderTop: "1px solid rgba(255,255,255,0.06)" }}>
      <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", textTransform: "uppercase", letterSpacing: 1, fontSize: 10, fontWeight: 700 }}>
        Additional Detail
      </Typography>
      <Box sx={{ display: "grid", gridTemplateColumns: "auto 1fr", columnGap: 1.5, rowGap: 0.5, mt: 0.5 }}>
        {entries.map(([k, v]) => (
          <React.Fragment key={k}>
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.6)", fontWeight: 600, textTransform: "capitalize" }}>
              {k.replace(/_/g, " ")}
            </Typography>
            <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.85)", wordBreak: "break-word" }}>
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
    return <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)" }}>No output yet.</Typography>;
  }
  const { text, rest } = pickNarrative(value);
  const fallback = (!text || !text.trim()) && Object.keys(rest).length > 0
    ? "```json\n" + JSON.stringify(rest, null, 2) + "\n```"
    : "";
  const renderText = text || fallback || "_(empty output)_";
  return (
    <Box sx={{
      maxHeight: maxHeight ?? "none",
      overflow: maxHeight ? "auto" : "visible",
      "& > :first-of-type": { mt: "0 !important" },
    }}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents as any}>
        {renderText}
      </ReactMarkdown>
      {text && Object.keys(rest).length > 0 && <MetadataList data={rest} />}
    </Box>
  );
}
