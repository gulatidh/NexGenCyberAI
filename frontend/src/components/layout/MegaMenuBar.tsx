/**
 * MegaMenuBar — Palo Alto–style mega menu for the Hub topbar.
 *
 * Desktop: hover a nav item → full-width panel slides in below the bar.
 *          250 ms leave-delay prevents flicker when moving diagonally into panel.
 * Mobile:  horizontal nav items become accordion toggles (tap to expand).
 * A11y:    aria-expanded / aria-haspopup / keyboard Enter+Space+Escape+Arrow.
 */
import { useState, useRef, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box, Typography, useTheme, alpha, Collapse,
  IconButton, useMediaQuery,
} from "@mui/material";
import {
  ExpandMore, Shield, BugReport, Psychology, Radar,
  Assessment, GppBad, PlaylistAddCheck, SmartToy,
  AutoStories, Tune, Policy, Hub as HubIcon, Close,
} from "@mui/icons-material";

// ── Data ──────────────────────────────────────────────────────────────────────

interface MegaItem {
  name: string;
  desc: string;
  route: string;
  Icon: React.ElementType;
}

interface MegaColumn {
  heading: string;
  color: string;
  items: MegaItem[];
}

interface MenuItem {
  id: string;
  label: string;
  color: string;
  columns: MegaColumn[];
}

const MENU: MenuItem[] = [
  {
    id: "setup", label: "Setup", color: "#2563eb",
    columns: [
      {
        heading: "Environment",
        color: "#2563eb",
        items: [
          { name: "Platform Setup",    desc: "Clients, assets, connectors, AI providers, and settings.",         route: "/platform",         Icon: Tune       },
          { name: "Connections",       desc: "Scanner connectors, enterprise tools, and SIEM integrations.",     route: "/connections",      Icon: Shield     },
          { name: "AI Settings",       desc: "Configure AI providers with automatic failover.",                  route: "/ai-settings",      Icon: SmartToy   },
        ],
      },
      {
        heading: "Design",
        color: "#7c3aed",
        items: [
          { name: "Threat Models",     desc: "DFD diagrams, STRIDE threats, and Sigma detection rules.",        route: "/threat-intel/threat-models",    Icon: HubIcon    },
          { name: "Frameworks",        desc: "NIST, CIS, ISO 27001, PCI DSS, GDPR, and custom standards.",     route: "/compliance/frameworks",          Icon: Policy     },
          { name: "Custom Standards",  desc: "Build your own control framework from existing controls.",        route: "/compliance/custom-frameworks",   Icon: Policy     },
        ],
      },
    ],
  },
  {
    id: "discover", label: "Discover", color: "#0f766e",
    columns: [
      {
        heading: "Scanning",
        color: "#0f766e",
        items: [
          { name: "Vulnerability Management", desc: "Scans, findings, posture trends, CVE enrichment.",              route: "/vulnerability",                Icon: BugReport  },
          { name: "AI Assisted Scan",         desc: "Conversational guided assessment — one question at a time.",    route: "/intelligence/ai-assisted-scan", Icon: SmartToy   },
          { name: "Import External Data",     desc: "Import SARIF, Nessus, Burp, Qualys, and more.",               route: "/vulnerability/scans",          Icon: BugReport  },
        ],
      },
      {
        heading: "Assets",
        color: "#0f766e",
        items: [
          { name: "Asset Inventory",   desc: "All discovered assets with compliance and CVE posture.",             route: "/platform/assets",              Icon: Shield     },
          { name: "Ask Your Data",     desc: "Natural language queries over your entire security dataset.",        route: "/intelligence/nl-query",         Icon: Psychology },
        ],
      },
    ],
  },
  {
    id: "analyse", label: "Analyse", color: "#b45309",
    columns: [
      {
        heading: "Risk",
        color: "#b45309",
        items: [
          { name: "Risk Manager",      desc: "FAIR-scored risk register, ALE exposure, and domain heatmap.",      route: "/risk",                         Icon: Assessment },
          { name: "Attack Paths",      desc: "MITRE-phased attack chain graph from live findings.",               route: "/threat-intel/attack-paths",     Icon: Radar      },
          { name: "Posture Trends",    desc: "Time-series charts of open findings and audit readiness.",          route: "/intelligence/posture-trends",   Icon: Assessment },
        ],
      },
      {
        heading: "Intelligence",
        color: "#4338ca",
        items: [
          { name: "Smart Intelligence", desc: "Compliance heatmap, asset intel, and multi-source correlation.",   route: "/intelligence",                  Icon: Psychology },
          { name: "Security Docs",     desc: "Upload policy documents and ask questions via RAG.",               route: "/intelligence/security-docs",    Icon: AutoStories },
        ],
      },
    ],
  },
  {
    id: "respond", label: "Respond", color: "#b91c1c",
    columns: [
      {
        heading: "Threat Intelligence",
        color: "#b91c1c",
        items: [
          { name: "Threat Register",    desc: "MITRE ATT&CK–mapped threat entries from AI threat intel agent.",  route: "/threat-intel",                 Icon: Radar          },
          { name: "Control Deficiencies", desc: "Framework control gaps identified by the compliance monitor.",  route: "/compliance/deficiencies",      Icon: GppBad         },
        ],
      },
      {
        heading: "Governance",
        color: "#15803d",
        items: [
          { name: "CTEM Programs",      desc: "5-phase exposure management: scope → discover → mobilise.",       route: "/governance/ctem",              Icon: PlaylistAddCheck },
          { name: "Remediation Tracker", desc: "Priority-banded remediation actions from the AI agent.",        route: "/governance/remediation",       Icon: PlaylistAddCheck },
          { name: "Scorecard",          desc: "Public-embeddable security scorecard token per client.",         route: "/governance/scorecard",         Icon: Shield          },
        ],
      },
    ],
  },
  {
    id: "report", label: "Report", color: "#15803d",
    columns: [
      {
        heading: "Pen Testing",
        color: "#15803d",
        items: [
          { name: "VAPT Reports",       desc: "Full engagement lifecycle with retest versioning and PDF/DOCX export.", route: "/vapt",             Icon: Shield  },
          { name: "Evidence Package",   desc: "ZIP of findings, control deficiencies, and agent logs for auditors.",   route: "/compliance/evidence", Icon: Shield },
        ],
      },
      {
        heading: "Compliance",
        color: "#7c3aed",
        items: [
          { name: "Compliance Monitor", desc: "Framework assessments and audit-ready evidence.",                 route: "/compliance",                   Icon: GppBad    },
          { name: "Frameworks",         desc: "Compliance posture scored per control across all frameworks.",   route: "/compliance/frameworks",         Icon: Policy    },
        ],
      },
    ],
  },
  {
    id: "automate", label: "Automate", color: "#4338ca",
    columns: [
      {
        heading: "AI Agents",
        color: "#4338ca",
        items: [
          { name: "AI Buddies",         desc: "60+ AI agents — orchestrator, risk, threat intel, remediation.",  route: "/ai-advisor",                   Icon: SmartToy   },
          { name: "Webhooks",           desc: "HMAC-signed webhooks for finding.critical and scan.completed.",  route: "/governance/webhooks",          Icon: Shield     },
          { name: "API Keys",           desc: "M2M API keys for CI/CD and SIEM integrations.",                  route: "/governance/api-keys",          Icon: Shield     },
        ],
      },
      {
        heading: "Knowledge",
        color: "#4338ca",
        items: [
          { name: "Knowledge & Docs",   desc: "Upload security policies and run RAG question answering.",        route: "/intelligence/security-docs",   Icon: AutoStories },
          { name: "Ask Your Data",      desc: "SQL-backed natural language queries over all findings and risks.", route: "/intelligence/nl-query",        Icon: Psychology  },
        ],
      },
    ],
  },
];

// ── Panel ─────────────────────────────────────────────────────────────────────

function MegaPanel({
  item, barRef, onClose,
}: {
  item: MenuItem;
  barRef: React.RefObject<HTMLDivElement>;
  onClose: () => void;
}) {
  const theme = useTheme();
  const navigate = useNavigate();
  const isDark = theme.palette.mode === "dark";

  const go = (route: string) => { onClose(); navigate(route); };

  return (
    <Box
      role="region"
      aria-label={`${item.label} menu`}
      sx={{
        position: "fixed",
        top: barRef.current ? barRef.current.getBoundingClientRect().bottom : 52,
        left: 0,
        right: 0,
        zIndex: 1300,
        bgcolor: "background.paper",
        borderBottom: "1px solid",
        borderColor: "divider",
        boxShadow: isDark
          ? "0 8px 32px rgba(0,0,0,0.5)"
          : "0 8px 32px rgba(0,0,0,0.12)",
        px: { xs: 2, md: 6 },
        py: 3,
        animation: "megaIn 0.18s ease",
        "@keyframes megaIn": {
          from: { opacity: 0, transform: "translateY(-8px)" },
          to:   { opacity: 1, transform: "translateY(0)" },
        },
      }}
    >
      {/* Close on mobile */}
      <IconButton
        size="small"
        onClick={onClose}
        sx={{ position: "absolute", top: 8, right: 8, display: { md: "none" } }}
      >
        <Close fontSize="small" />
      </IconButton>

      {/* Columns */}
      <Box sx={{ display: "flex", gap: { xs: 3, md: 6 }, flexWrap: "wrap", maxWidth: 1100, mx: "auto" }}>
        {item.columns.map((col) => (
          <Box key={col.heading} sx={{ flex: "1 1 220px", minWidth: 200 }}>
            <Typography sx={{
              fontSize: 11, fontWeight: 700, color: col.color,
              textTransform: "uppercase", letterSpacing: "0.08em",
              mb: 1.5, pb: 0.75,
              borderBottom: `2px solid ${col.color}`,
              display: "inline-block",
            }}>
              {col.heading}
            </Typography>
            <Box sx={{ display: "flex", flexDirection: "column", gap: 0.25 }}>
              {col.items.map((mi) => (
                <Box
                  key={mi.name}
                  component="button"
                  onClick={() => go(mi.route)}
                  sx={{
                    display: "flex", alignItems: "flex-start", gap: 1.5,
                    p: 1, borderRadius: 1.5, border: "none", bgcolor: "transparent",
                    cursor: "pointer", textAlign: "left", width: "100%",
                    transition: "background-color 0.14s",
                    "&:hover, &:focus-visible": {
                      bgcolor: alpha(col.color, 0.07),
                      outline: "none",
                    },
                  }}
                >
                  <Box sx={{
                    width: 34, height: 34, flexShrink: 0, borderRadius: 1.5,
                    bgcolor: alpha(col.color, isDark ? 0.15 : 0.1),
                    display: "flex", alignItems: "center", justifyContent: "center",
                    color: col.color, mt: 0.1,
                  }}>
                    <mi.Icon sx={{ fontSize: 18 }} />
                  </Box>
                  <Box>
                    <Typography sx={{ fontSize: 13.5, fontWeight: 600, color: "text.primary", lineHeight: 1.3, mb: 0.2 }}>
                      {mi.name}
                    </Typography>
                    <Typography sx={{ fontSize: 12, color: "text.secondary", lineHeight: 1.4 }}>
                      {mi.desc}
                    </Typography>
                  </Box>
                </Box>
              ))}
            </Box>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface Props {
  /** If provided, a logo/brand area is rendered on the left */
  brand?: React.ReactNode;
  /** Rendered on the right side of the bar (client picker, user, etc.) */
  trailing?: React.ReactNode;
}

export default function MegaMenuBar({ brand, trailing }: Props) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [open, setOpen] = useState<string | null>(null);
  const [mobileOpen, setMobileOpen] = useState<string | null>(null);
  const barRef = useRef<HTMLDivElement>(null!);
  const leaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearLeave = () => { if (leaveTimer.current) clearTimeout(leaveTimer.current); };

  const enter = useCallback((id: string) => {
    clearLeave();
    setOpen(id);
  }, []);

  const leave = useCallback(() => {
    leaveTimer.current = setTimeout(() => setOpen(null), 250);
  }, []);

  const closeAll = useCallback(() => {
    clearLeave();
    setOpen(null);
  }, []);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") closeAll(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [closeAll]);

  const activeItem = MENU.find((m) => m.id === open) ?? null;

  return (
    <>
      {/* Backdrop — click outside closes panel */}
      {activeItem && (
        <Box
          onClick={closeAll}
          sx={{ position: "fixed", inset: 0, zIndex: 1299, bgcolor: "transparent" }}
        />
      )}

      {/* Nav bar */}
      <Box
        ref={barRef}
        sx={{
          display: "flex", alignItems: "center", gap: 0.5,
          px: { xs: 1.5, md: 3 }, height: "100%",
        }}
      >
        {brand && <Box sx={{ mr: 2, flexShrink: 0 }}>{brand}</Box>}

        {isMobile ? (
          /* ── Mobile: accordion ──────────────────────────────────────── */
          <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
            {MENU.map((item) => {
              const expanded = mobileOpen === item.id;
              return (
                <Box key={item.id}>
                  <Box
                    component="button"
                    role="button"
                    aria-expanded={expanded}
                    aria-haspopup="true"
                    onClick={() => setMobileOpen(expanded ? null : item.id)}
                    onKeyDown={(e: React.KeyboardEvent) => {
                      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setMobileOpen(expanded ? null : item.id); }
                    }}
                    sx={{
                      display: "flex", alignItems: "center", gap: 0.5,
                      px: 1.25, py: 0.5, border: "none",
                      bgcolor: expanded ? alpha(item.color, 0.1) : "transparent",
                      color: expanded ? item.color : "text.primary",
                      borderRadius: 1, cursor: "pointer", fontSize: 13, fontWeight: 600,
                      "&:focus-visible": { outline: `2px solid ${item.color}` },
                    }}
                  >
                    {item.label}
                    <ExpandMore sx={{ fontSize: 16, transform: expanded ? "rotate(180deg)" : "none", transition: "transform 0.2s" }} />
                  </Box>

                  <Collapse in={expanded} timeout={180}>
                    <Box sx={{ pl: 1, py: 1 }}>
                      {item.columns.flatMap((col) => col.items).map((mi) => (
                        <Box
                          key={mi.name}
                          component="button"
                          onClick={() => { setMobileOpen(null); }}
                          sx={{
                            display: "block", width: "100%", textAlign: "left",
                            px: 1.5, py: 0.75, border: "none", bgcolor: "transparent",
                            color: "text.primary", cursor: "pointer", fontSize: 13, borderRadius: 1,
                            "&:hover": { bgcolor: "action.hover" },
                          }}
                        >
                          {mi.name}
                        </Box>
                      ))}
                    </Box>
                  </Collapse>
                </Box>
              );
            })}
          </Box>
        ) : (
          /* ── Desktop: hover mega menu ───────────────────────────────── */
          <Box
            onMouseLeave={leave}
            sx={{ display: "flex", alignItems: "center", gap: 0.25, height: "100%" }}
          >
            {MENU.map((item) => {
              const isOpen = open === item.id;
              return (
                <Box
                  key={item.id}
                  component="button"
                  role="button"
                  aria-haspopup="true"
                  aria-expanded={isOpen}
                  aria-controls={`mega-panel-${item.id}`}
                  onMouseEnter={() => enter(item.id)}
                  onFocus={() => enter(item.id)}
                  onKeyDown={(e: React.KeyboardEvent) => {
                    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setOpen(isOpen ? null : item.id); }
                    if (e.key === "Escape") closeAll();
                    if (e.key === "ArrowRight") {
                      const idx = MENU.findIndex((m) => m.id === item.id);
                      if (idx < MENU.length - 1) enter(MENU[idx + 1].id);
                    }
                    if (e.key === "ArrowLeft") {
                      const idx = MENU.findIndex((m) => m.id === item.id);
                      if (idx > 0) enter(MENU[idx - 1].id);
                    }
                  }}
                  sx={{
                    px: 1.75, height: "100%", border: "none",
                    bgcolor: "transparent", cursor: "pointer",
                    display: "flex", alignItems: "center", gap: 0.5,
                    fontSize: 13.5, fontWeight: isOpen ? 700 : 500,
                    color: isOpen ? item.color : "text.primary",
                    borderBottom: isOpen ? `2px solid ${item.color}` : "2px solid transparent",
                    transition: "color 0.15s, border-color 0.15s",
                    "&:hover": { color: item.color },
                    "&:focus-visible": { outline: `2px solid ${item.color}`, outlineOffset: -2 },
                  }}
                >
                  {item.label}
                  <ExpandMore sx={{ fontSize: 14, transform: isOpen ? "rotate(180deg)" : "none", transition: "transform 0.2s", color: "inherit" }} />
                </Box>
              );
            })}
          </Box>
        )}

        {trailing && <Box sx={{ ml: "auto", display: "flex", alignItems: "center", gap: 1 }}>{trailing}</Box>}
      </Box>

      {/* Desktop panel — rendered via portal-like fixed positioning */}
      {!isMobile && activeItem && (
        <Box
          id={`mega-panel-${activeItem.id}`}
          onMouseEnter={clearLeave}
          onMouseLeave={leave}
        >
          <MegaPanel item={activeItem} barRef={barRef} onClose={closeAll} />
        </Box>
      )}
    </>
  );
}
