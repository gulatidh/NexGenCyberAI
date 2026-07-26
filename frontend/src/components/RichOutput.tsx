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
import { Box, Typography, Divider, Link as MuiLink, Chip, Tab, Tabs } from "@mui/material";
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

// ── Structured agent output sections ────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "#EA4335", high: "#FF7043", medium: "#FBBC04", low: "#34A853", info: "#4285F4",
};

function SectionLabel({ label }: { label: string }) {
  return (
    <Typography variant="caption" sx={{
      display: "block", color: "#4285F4", textTransform: "uppercase",
      letterSpacing: 1, fontWeight: 700, fontSize: 11, mb: 1, mt: 2,
    }}>
      {label}
    </Typography>
  );
}

function StructuredExecSummary({ data }: { data: any }) {
  if (!data || typeof data !== "object") return null;
  const { posture_verdict, critical_findings_count, top_3_risks, quick_wins_90d } = data;
  return (
    <Box sx={{ mt: 1.5, p: 1.5, bgcolor: "rgba(66,133,244,0.06)", borderRadius: 1.5, border: "1px solid rgba(66,133,244,0.15)" }}>
      <SectionLabel label="Executive Summary" />
      {posture_verdict && (
        <Typography sx={{ color: "text.primary", fontSize: 13.5, fontWeight: 500, mb: 1, lineHeight: 1.5 }}>
          {posture_verdict}
        </Typography>
      )}
      {critical_findings_count != null && (
        <Box sx={{ display: "flex", gap: 1, mb: 1, flexWrap: "wrap" }}>
          <Chip label={`${critical_findings_count} critical`} size="small"
            sx={{ bgcolor: critical_findings_count > 0 ? "#EA433522" : "rgba(255,255,255,0.06)", color: critical_findings_count > 0 ? "#EA4335" : "text.secondary", fontSize: 11 }} />
        </Box>
      )}
      {Array.isArray(top_3_risks) && top_3_risks.length > 0 && (
        <Box sx={{ mb: 1 }}>
          <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700 }}>Top Risks</Typography>
          <Box component="ul" sx={{ m: 0, pl: 2.5, mt: 0.25 }}>
            {top_3_risks.map((r: string, i: number) => (
              <Box component="li" key={i} sx={{ fontSize: 13, color: "text.secondary", lineHeight: 1.5, mb: 0.25 }}>{r}</Box>
            ))}
          </Box>
        </Box>
      )}
      {Array.isArray(quick_wins_90d) && quick_wins_90d.length > 0 && (
        <Box>
          <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 700 }}>Quick Wins (90d)</Typography>
          <Box component="ul" sx={{ m: 0, pl: 2.5, mt: 0.25 }}>
            {quick_wins_90d.map((q: string, i: number) => (
              <Box component="li" key={i} sx={{ fontSize: 13, color: "text.secondary", lineHeight: 1.5, mb: 0.25 }}>{q}</Box>
            ))}
          </Box>
        </Box>
      )}
    </Box>
  );
}

function StructuredFindings({ rows }: { rows: any[] }) {
  if (!rows?.length) return null;
  return (
    <Box sx={{ mt: 1.5 }}>
      <SectionLabel label={`Findings (${rows.length})`} />
      <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
        {rows.map((f: any, i: number) => {
          const sev = (f.severity || "info").toLowerCase();
          const color = SEV_COLOR[sev] || "rgba(255,255,255,0.5)";
          return (
            <Box key={f.finding_id || i} sx={{
              p: 1.25, borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)",
              bgcolor: "rgba(255,255,255,0.02)",
            }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5, flexWrap: "wrap" }}>
                <Chip label={(f.severity || "INFO").toUpperCase()} size="small"
                  sx={{ bgcolor: `${color}22`, color, fontSize: 10, height: 18, fontWeight: 700 }} />
                {f.finding_id && (
                  <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace" }}>
                    {f.finding_id}
                  </Typography>
                )}
                <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 600, fontSize: 13 }}>
                  {f.title}
                </Typography>
              </Box>
              {f.description && (
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mb: 0.5 }}>
                  {f.description}
                </Typography>
              )}
              {f.remediation && (
                <Typography variant="caption" sx={{ color: "#34A853", display: "block" }}>
                  ↳ {f.remediation}
                </Typography>
              )}
              {Array.isArray(f.framework_references) && f.framework_references.length > 0 && (
                <Box sx={{ mt: 0.5, display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                  {f.framework_references.map((ref: string, j: number) => (
                    <Chip key={j} label={ref} size="small"
                      sx={{ bgcolor: "rgba(66,133,244,0.1)", color: "#4285F4", fontSize: 10, height: 16 }} />
                  ))}
                </Box>
              )}
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}

const BAND_COLOR: Record<string, string> = {
  "Quick Win (0-30d)": "#34A853",
  "Near Term (30-90d)": "#4285F4",
  "Medium Term (90-180d)": "#FBBC04",
  "Strategic (180d+)": "#9C27B0",
};

function StructuredRecommendations({ rows }: { rows: any[] }) {
  if (!rows?.length) return null;
  return (
    <Box sx={{ mt: 1.5 }}>
      <SectionLabel label={`Recommendations (${rows.length})`} />
      <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
        {rows.map((r: any, i: number) => {
          const color = BAND_COLOR[r.band] || "#4285F4";
          return (
            <Box key={i} sx={{
              p: 1.25, borderRadius: 1, border: "1px solid rgba(255,255,255,0.08)",
              bgcolor: "rgba(255,255,255,0.02)", display: "flex", gap: 1.5, alignItems: "flex-start",
            }}>
              <Box sx={{ minWidth: 28, height: 28, borderRadius: "50%", bgcolor: `${color}22`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <Typography sx={{ fontSize: 11, fontWeight: 700, color }}>{r.priority ?? i + 1}</Typography>
              </Box>
              <Box sx={{ flex: 1 }}>
                <Box sx={{ display: "flex", gap: 0.75, mb: 0.5, flexWrap: "wrap" }}>
                  {r.band && (
                    <Chip label={r.band} size="small"
                      sx={{ bgcolor: `${color}22`, color, fontSize: 10, height: 18 }} />
                  )}
                  {r.effort && (
                    <Chip label={`Effort: ${r.effort}`} size="small"
                      sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", fontSize: 10, height: 18 }} />
                  )}
                  {r.impact && (
                    <Chip label={`Impact: ${r.impact}`} size="small"
                      sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", fontSize: 10, height: 18 }} />
                  )}
                </Box>
                <Typography variant="body2" sx={{ color: "text.primary", fontSize: 13, lineHeight: 1.4 }}>
                  {r.action}
                </Typography>
              </Box>
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}

const TIER_LABEL: Record<number, string> = { 0: "Inactive", 1: "Partial", 2: "Risk Informed", 3: "Repeatable", 4: "Adaptive" };
const TIER_COLOR = ["#9e9e9e", "#FF7043", "#FBBC04", "#4285F4", "#34A853"];

function StructuredMaturity({ data }: { data: any }) {
  if (!data || typeof data !== "object") return null;
  const { overall_tier, sub_domains } = data;
  const tier = typeof overall_tier === "number" ? overall_tier : parseInt(overall_tier, 10);
  const color = TIER_COLOR[Math.min(tier, 4)] || "#9e9e9e";
  return (
    <Box sx={{ mt: 1.5 }}>
      <SectionLabel label="Maturity Indicators" />
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1.5 }}>
        <Box sx={{ width: 48, height: 48, borderRadius: "50%", bgcolor: `${color}22`, border: `2px solid ${color}`, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Typography sx={{ fontSize: 18, fontWeight: 700, color }}>{isNaN(tier) ? "?" : tier}</Typography>
        </Box>
        <Box>
          <Typography variant="body2" sx={{ color: "text.primary", fontWeight: 700 }}>
            Tier {isNaN(tier) ? "?" : tier} — {TIER_LABEL[tier] ?? "Unknown"}
          </Typography>
          <Box sx={{ display: "flex", gap: 0.5, mt: 0.5 }}>
            {[0, 1, 2, 3, 4].map((t) => (
              <Box key={t} sx={{ width: 20, height: 6, borderRadius: 1, bgcolor: t <= tier ? color : "rgba(255,255,255,0.1)" }} />
            ))}
          </Box>
        </Box>
      </Box>
      {isPlainObject(sub_domains) && Object.keys(sub_domains).length > 0 && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.75 }}>
          {Object.entries(sub_domains).map(([domain, info]: [string, any]) => {
            const t = typeof info?.tier === "number" ? info.tier : parseInt(info?.tier, 10) || 0;
            const c = TIER_COLOR[Math.min(t, 4)] || "#9e9e9e";
            return (
              <Box key={domain} sx={{ display: "flex", gap: 1.5, alignItems: "flex-start", p: 0.75, borderRadius: 1, bgcolor: "rgba(255,255,255,0.02)" }}>
                <Chip label={`T${t}`} size="small"
                  sx={{ bgcolor: `${c}22`, color: c, fontSize: 10, height: 20, fontWeight: 700, minWidth: 32 }} />
                <Box>
                  <Typography variant="caption" sx={{ color: "text.primary", fontWeight: 600, textTransform: "capitalize" }}>
                    {domain.replace(/_/g, " ")}
                  </Typography>
                  {info?.evidence && (
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.25 }}>
                      {info.evidence}
                    </Typography>
                  )}
                </Box>
              </Box>
            );
          })}
        </Box>
      )}
    </Box>
  );
}

// ── Metadata list (cleaned) — for unknown leftover keys ──────────────────────

// Keys handled by dedicated section renderers — suppress in MetadataList
const STRUCTURED_KEYS = new Set(["executive_summary_structured", "findings", "recommendations", "maturity_indicators"]);

function MetadataList({ data }: { data: Record<string, any> }) {
  const entries = Object.entries(data).filter(([k, v]) => {
    if (HIDE_KEYS.has(k)) return false;
    if (STRUCTURED_KEYS.has(k)) return false;
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
              {Array.isArray(v)
                ? v.every((el) => typeof el !== "object" || el === null)
                  ? v.join(", ")
                  : JSON.stringify(v)
                : isPlainObject(v) ? JSON.stringify(v)
                : String(v)}
            </Typography>
          </React.Fragment>
        ))}
      </Box>
    </Box>
  );
}

// ── Orchestrator multi-section renderer ─────────────────────────────────────

const ORCH_SECTIONS: Array<{ key: string; label: string; color: string }> = [
  { key: "va_analysis",       label: "Vulnerability Analysis", color: "#EA4335" },
  { key: "framework_analysis",label: "Framework Mapping",      color: "#4285F4" },
  { key: "threat_intel",      label: "Threat Intelligence",    color: "#FF7043" },
  { key: "risk_analysis",     label: "Risk Assessment",        color: "#FBBC04" },
  { key: "remediation",       label: "Remediation Playbook",   color: "#34A853" },
  { key: "audit_report",      label: "Compliance Audit",       color: "#9C27B0" },
];

function isOrchestratorOutput(v: any): boolean {
  return v && typeof v === "object" &&
    ("va_analysis" in v || "framework_analysis" in v) &&
    ("risk_analysis" in v || "remediation" in v);
}

function OrchestratorSection({ data }: { data: any }) {
  if (!data || typeof data !== "object") return null;
  const narrative = typeof data.output === "string" ? stripConversational(data.output) : "";
  const execSummary = data.executive_summary_structured;
  const findings: any[] = Array.isArray(data.findings) ? data.findings : [];
  const recs: any[] = Array.isArray(data.recommendations) ? data.recommendations : [];
  const maturity = data.maturity_indicators;

  return (
    <Box>
      {narrative && (
        <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents as any}>
          {narrative}
        </ReactMarkdown>
      )}
      {execSummary && <StructuredExecSummary data={execSummary} />}
      {findings.length > 0 && <StructuredFindings rows={findings} />}
      {recs.length > 0 && <StructuredRecommendations rows={recs} />}
      {maturity && <StructuredMaturity data={maturity} />}
      {!narrative && !execSummary && !findings.length && !recs.length && !maturity && (
        <Typography variant="caption" sx={{ color: "text.secondary", fontStyle: "italic" }}>
          No output for this section.
        </Typography>
      )}
    </Box>
  );
}

function OrchestratorOutput({ value }: { value: any }) {
  const [tab, setTab] = React.useState(0);

  const visibleSections = ORCH_SECTIONS.filter(s => value[s.key]);

  const risksCreated: number = value.risks_created ?? 0;
  const threatsCreated: number = value.threats_created ?? 0;
  const defCreated: number = value.deficiencies_created ?? 0;
  const actionsCreated: number = value.actions_created ?? 0;

  return (
    <Box>
      {/* Summary stat chips */}
      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 1.5 }}>
        {risksCreated > 0 && (
          <Chip label={`${risksCreated} risks`} size="small"
            sx={{ bgcolor: "rgba(251,188,4,0.12)", color: "#FBBC04", fontSize: 11, fontWeight: 700 }} />
        )}
        {threatsCreated > 0 && (
          <Chip label={`${threatsCreated} threats`} size="small"
            sx={{ bgcolor: "rgba(255,112,67,0.12)", color: "#FF7043", fontSize: 11, fontWeight: 700 }} />
        )}
        {defCreated > 0 && (
          <Chip label={`${defCreated} control gaps`} size="small"
            sx={{ bgcolor: "rgba(66,133,244,0.12)", color: "#4285F4", fontSize: 11, fontWeight: 700 }} />
        )}
        {actionsCreated > 0 && (
          <Chip label={`${actionsCreated} actions`} size="small"
            sx={{ bgcolor: "rgba(52,168,83,0.12)", color: "#34A853", fontSize: 11, fontWeight: 700 }} />
        )}
        {value.findings_count != null && (
          <Chip label={`${value.findings_count} findings analysed`} size="small"
            sx={{ bgcolor: "rgba(255,255,255,0.06)", color: "text.secondary", fontSize: 11 }} />
        )}
      </Box>

      {/* Section tabs */}
      <Tabs
        value={Math.min(tab, visibleSections.length - 1)}
        onChange={(_e, v) => setTab(v)}
        variant="scrollable"
        scrollButtons="auto"
        sx={{
          minHeight: 32, mb: 1.5,
          "& .MuiTab-root": { minHeight: 32, fontSize: 11, fontWeight: 700, textTransform: "none", px: 1.5, py: 0.5 },
          "& .MuiTabs-indicator": { bgcolor: visibleSections[tab]?.color ?? "#4285F4" },
        }}
      >
        {visibleSections.map((s, i) => (
          <Tab key={s.key} label={s.label}
            sx={{ color: tab === i ? s.color : "text.secondary" }} />
        ))}
      </Tabs>

      {visibleSections.map((s, i) => (
        <Box key={s.key} hidden={tab !== i}>
          {tab === i && <OrchestratorSection data={value[s.key]} />}
        </Box>
      ))}
    </Box>
  );
}

export default function RichOutput({ value, maxHeight }: { value: any; maxHeight?: number | string }) {
  if (value === null || value === undefined) {
    return <Typography variant="caption" sx={{ color: "text.secondary" }}>No output yet.</Typography>;
  }

  if (isOrchestratorOutput(value)) {
    return (
      <Box sx={{ maxHeight: maxHeight ?? "none", overflow: maxHeight ? "auto" : "visible" }}>
        <OrchestratorOutput value={value} />
      </Box>
    );
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

  // Extract well-known structured sections from rest
  const execSummary = isPlainObject(trimmedRest) ? trimmedRest.executive_summary_structured : undefined;
  const agentFindings = isPlainObject(trimmedRest) && Array.isArray(trimmedRest.findings) ? trimmedRest.findings : undefined;
  const agentRecs = isPlainObject(trimmedRest) && Array.isArray(trimmedRest.recommendations) ? trimmedRest.recommendations : undefined;
  const maturityData = isPlainObject(trimmedRest) ? trimmedRest.maturity_indicators : undefined;

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
      {execSummary && <StructuredExecSummary data={execSummary} />}
      {agentFindings && agentFindings.length > 0 && <StructuredFindings rows={agentFindings} />}
      {agentRecs && agentRecs.length > 0 && <StructuredRecommendations rows={agentRecs} />}
      {maturityData && <StructuredMaturity data={maturityData} />}
      {Object.keys(trimmedRest).length > 0 && <MetadataList data={trimmedRest} />}
    </Box>
  );
}
