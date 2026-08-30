/**
 * SectionPage — reusable v3-theme landing page for pipeline sections.
 * Matches Hub.tsx visual language exactly: circle node, Space Grotesk heading,
 * info callout, HubCard grid.  Used by Discover, Analyse, Respond, Automate pages.
 */
import React from "react";
import { alpha, Box, Divider, Typography } from "@mui/material";
import { InfoOutlined, ArrowBack, HelpOutlined } from "@mui/icons-material";
import { Outlet, useMatch, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { dashboardApi } from "../services/api";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface CardDef { name: string; desc: string; route: string; group?: string; icon?: React.ReactNode; }

export interface SectionDef {
  num: string;
  label: string;
  color: string;
  title: string;
  sub: string;
  info: string;
  cards: CardDef[];
  stats: Array<{ label: string; field: string; color: string }>;
}

// ── HubCard ───────────────────────────────────────────────────────────────────

function SectionCard({ card, color }: { card: CardDef; color: string }) {
  const navigate = useNavigate();
  return (
    <Box
      onClick={() => navigate(card.route)}
      sx={{
        bgcolor: "background.paper",
        border: "1px solid", borderColor: "divider",
        borderTop: `3px solid ${color}`,
        borderRadius: 2, p: 1.75, cursor: "pointer",
        display: "flex", flexDirection: "column", gap: 0.75, minHeight: 94,
        transition: "box-shadow .15s, transform .12s",
        "&:hover": {
          transform: "translateY(-1px)",
          boxShadow: `0 4px 14px rgba(0,0,0,0.08)`,
        },
      }}
    >
      <Typography sx={{ fontWeight: 700, fontSize: 13, lineHeight: 1.3, color: "text.primary" }}>
        {card.name}
      </Typography>
      <Typography sx={{ fontSize: 11.5, color: "text.secondary", lineHeight: 1.5, flex: 1 }}>
        {card.desc}
      </Typography>
      <Typography sx={{ fontSize: 11, color: "text.secondary", fontWeight: 600, textAlign: "right" }}>
        Open →
      </Typography>
    </Box>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function SectionPage({ section }: { section: SectionDef }) {
  const navigate = useNavigate();
  const { data: summary } = useQuery<Record<string, number>>({
    queryKey: ["dashboard-summary"],
    queryFn: () => dashboardApi.summary(),
    staleTime: 60_000,
  });

  return (
    <Box sx={{ maxWidth: 1100 }}>
      {/* ── Breadcrumb ───────────────────────────────────────────────── */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
        <Box
          onClick={() => navigate("/hub")}
          sx={{
            display: "flex", alignItems: "center", gap: 0.75, cursor: "pointer",
            color: "text.secondary", fontSize: 12.5,
            "&:hover": { color: "text.primary" }, transition: "color .12s",
          }}
        >
          <ArrowBack sx={{ fontSize: 14 }} />
          Hub
        </Box>
        <Typography sx={{ color: "text.secondary", fontSize: 12 }}>·</Typography>
        <Typography sx={{ fontSize: 12, color: section.color, fontWeight: 600 }}>
          Stage {section.num} · {section.label}
        </Typography>
      </Box>

      {/* ── Stage hero ───────────────────────────────────────────────── */}
      <Box sx={{ position: "relative", pl: "64px", mb: 4 }}>
        {/* Circle node */}
        <Box sx={{
          position: "absolute", left: 0, top: 0, width: 48, height: 48,
          borderRadius: "50%", bgcolor: "background.default",
          border: `2px solid ${section.color}`,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontFamily: "monospace", fontWeight: 700, fontSize: "1rem", color: section.color,
          boxShadow: `0 0 18px -4px ${section.color}60`,
        }}>
          {section.num}
        </Box>

        <Box sx={{ pt: "4px" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.75 }}>
            <Box sx={{ width: 4, height: 16, borderRadius: 2, bgcolor: section.color }} />
            <Typography sx={{
              fontSize: "0.71rem", fontWeight: 700, color: section.color,
              textTransform: "uppercase", letterSpacing: "0.1em",
            }}>
              Stage {section.num} · {section.label}
            </Typography>
          </Box>
          <Typography sx={{
            fontFamily: "'Space Grotesk', sans-serif",
            fontSize: { xs: 20, md: 26 }, fontWeight: 700, letterSpacing: "-0.02em", mb: 0.75,
          }}>
            {section.title}
          </Typography>
          <Typography sx={{ color: "text.secondary", fontSize: "0.88rem", maxWidth: 560, lineHeight: 1.6, mb: 2 }}>
            {section.sub}
          </Typography>
          <Box sx={{
            display: "flex", alignItems: "flex-start", gap: 1.5,
            bgcolor: alpha(section.color, 0.06),
            border: "1px solid", borderColor: alpha(section.color, 0.2),
            borderRadius: 1.5, px: 2, py: 1.25,
          }}>
            <InfoOutlined sx={{ color: section.color, fontSize: 15, mt: "2px", flexShrink: 0 }} />
            <Typography sx={{ fontSize: 12.5, color: "text.secondary", lineHeight: 1.55 }}>
              {section.info}
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* ── Overview stats ───────────────────────────────────────────── */}
      {summary && (
        <Box sx={{ display: "flex", gap: 1.5, mb: 4, flexWrap: "wrap" }}>
          {section.stats.map(stat => (
            <Box key={stat.label} sx={{
              bgcolor: "background.paper",
              border: "1px solid", borderColor: "divider",
              borderRadius: 2, px: 2.5, py: 1.5,
              display: "flex", flexDirection: "column", gap: 0.25, minWidth: 110,
            }}>
              <Typography sx={{ fontSize: 24, fontWeight: 800, color: stat.color, lineHeight: 1 }}>
                {summary[stat.field] ?? 0}
              </Typography>
              <Typography sx={{ fontSize: 11, color: "text.secondary", fontWeight: 500 }}>
                {stat.label}
              </Typography>
            </Box>
          ))}
        </Box>
      )}

      {/* ── Feature cards (grouped) ───────────────────────────────────── */}
      <Box sx={{ mb: 5 }}>
        {(() => {
          const groups: Array<{ name: string; cards: CardDef[] }> = [];
          for (const card of section.cards) {
            const g = card.group ?? "";
            if (groups.length === 0 || groups[groups.length - 1].name !== g) {
              groups.push({ name: g, cards: [] });
            }
            groups[groups.length - 1].cards.push(card);
          }
          return groups.map((g, gi) => (
            <Box key={g.name || gi} sx={{ mb: gi < groups.length - 1 ? 3 : 0 }}>
              {g.name && (
                <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1.25, mt: gi > 0 ? 0.5 : 0 }}>
                  <Typography sx={{
                    fontSize: 9.5, fontWeight: 700, letterSpacing: "0.12em",
                    textTransform: "uppercase", color: "text.disabled", whiteSpace: "nowrap",
                  }}>
                    {g.name}
                  </Typography>
                  <Box sx={{ flex: 1, height: "1px", bgcolor: "divider" }} />
                </Box>
              )}
              <Box sx={{
                display: "grid",
                gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr", md: "repeat(4, 1fr)" },
                gap: 1.5,
              }}>
                {g.cards.map(card => (
                  <SectionCard key={card.name} card={card} color={section.color} />
                ))}
              </Box>
            </Box>
          ));
        })()}
      </Box>

      {/* ── Help ─────────────────────────────────────────────────────── */}
      <Divider sx={{ mb: 3 }} />
      <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, mb: 1.5 }}>
        <HelpOutlined sx={{ fontSize: 15, color: "#00BCD4" }} />
        <Typography sx={{
          fontSize: 10, fontWeight: 700, color: "#00BCD4",
          textTransform: "uppercase", letterSpacing: 1.2,
        }}>
          Help
        </Typography>
      </Box>
      <Box
        onClick={() => navigate("/platform/help")}
        sx={{
          bgcolor: "background.paper", border: "1px solid", borderColor: "divider",
          borderRadius: 2, p: 1.75, cursor: "pointer",
          display: "flex", alignItems: "center", gap: 1.5, maxWidth: 340,
          "&:hover": { borderColor: "#00BCD4" }, transition: "border-color .15s",
        }}
      >
        <HelpOutlined sx={{ fontSize: 20, color: "#00BCD4", flexShrink: 0 }} />
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography sx={{ fontWeight: 700, fontSize: 13 }}>Help & Docs</Typography>
          <Typography sx={{ fontSize: 11.5, color: "text.secondary" }}>
            Guides and platform documentation.
          </Typography>
        </Box>
        <Typography sx={{ fontSize: 11, color: "#00BCD4", fontWeight: 600 }}>Open →</Typography>
      </Box>
    </Box>
  );
}

// ── SectionLayout ──────────────────────────────────────────────────────────────
// Layout wrapper used as the route element for nested section routes.
// At /discover: renders the full SectionPage overview.
// At /discover/findings etc: renders a context bar + Outlet (the sub-page).

export function SectionLayout({ section, basePath }: { section: SectionDef; basePath: string }) {
  const navigate = useNavigate();
  const isRoot = useMatch(basePath);

  if (isRoot) {
    return <SectionPage section={section} />;
  }

  return (
    <Box>
      {/* Section context breadcrumb */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
        <Box
          onClick={() => navigate(basePath)}
          sx={{
            display: "flex", alignItems: "center", gap: 0.75, cursor: "pointer",
            color: "text.secondary", fontSize: 12.5,
            "&:hover": { color: "text.primary" }, transition: "color .12s",
          }}
        >
          <ArrowBack sx={{ fontSize: 14 }} />
          {section.label}
        </Box>
        <Typography sx={{ color: "text.disabled", fontSize: 12 }}>·</Typography>
        <Box sx={{
          px: 1, py: 0.25, borderRadius: 1,
          bgcolor: alpha(section.color, 0.1), color: section.color,
          fontSize: 10.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.09em",
        }}>
          Stage {section.num}
        </Box>
      </Box>
      <Outlet />
    </Box>
  );
}
