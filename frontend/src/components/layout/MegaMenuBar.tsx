/**
 * MegaMenuBar — Palo Alto–style mega menu nav bar.
 *
 * Desktop: hover a phase label → full-width panel slides in below bar.
 *          250 ms leave-delay prevents flicker when moving diagonally.
 * Mobile:  tap to expand accordion. No hover on touch devices.
 * A11y:    aria-expanded / aria-haspopup / Enter·Space·Escape·Arrow keys.
 */
import { useState, useRef, useCallback, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import {
  Box, Typography, Collapse, useMediaQuery, useTheme, alpha,
} from "@mui/material";
import {
  ExpandMore, BugReport, Psychology, Radar, Assessment,
  GppBad, PlaylistAddCheck, SmartToy, Tune, Policy,
  LibraryAdd, Storage, TrendingUp, Security, FindInPage,
  Description, AltRoute, FolderZip, AccountTree,
  DeviceHub, People, Cable, MenuBook, Search, AutoFixHigh,
  Hub as HubIcon, Devices, VpnKey, Webhook, ManageSearch,
} from "@mui/icons-material";

// ── Phase → route mapping for active highlight ────────────────────────────────

function getActivePhase(pathname: string): string | null {
  if (pathname.startsWith("/platform"))  return "setup";
  if (pathname.startsWith("/data-model")) return "setup";
  if (pathname.startsWith("/discover"))  return "discover";
  if (pathname.startsWith("/analyse"))   return "analyse";
  if (pathname.startsWith("/respond"))   return "respond";
  if (pathname.startsWith("/report"))    return "report";
  if (pathname.startsWith("/automate"))  return "automate";
  return null;
}

// ── Data ──────────────────────────────────────────────────────────────────────

interface MegaItem {
  name: string;
  desc: string;
  route: string;
  Icon: React.ElementType;
}

interface MegaColumn {
  heading: string;
  items: MegaItem[];
}

interface MenuItem {
  id: string;
  label: string;
  color: string;
  overviewPath: string;
  columns: MegaColumn[];
}

const MENU: MenuItem[] = [
  {
    id: "setup", label: "Setup", color: "#2563eb", overviewPath: "/platform",
    columns: [
      {
        heading: "Environment",
        items: [
          { name: "Accounts",            desc: "Client profiles, contact details, and security posture scoping.",         route: "/platform/clients",            Icon: People      },
          { name: "Asset Inventory",     desc: "Discovered assets — servers, apps, containers, and cloud resources.",     route: "/platform/assets",             Icon: Storage     },
          { name: "Connectors",          desc: "Scanner integrations, enterprise tools, and SIEM connectors.",            route: "/platform/connections",        Icon: Cable       },
          { name: "AI Settings",         desc: "AI provider credentials, model selection, and automatic failover config.",route: "/platform/ai-settings",        Icon: Tune        },
        ],
      },
      {
        heading: "Design",
        items: [
          { name: "AI Guardrails",       desc: "AI safety controls, prompt audit logs, and guardrail coverage.",          route: "/automate/ai-guardrails",      Icon: Security      },
          { name: "Audit Logs",          desc: "LLM prompt audit trail — per-user, per-endpoint, with CSV export.",       route: "/platform/audit-logs",         Icon: ManageSearch  },
          { name: "Threat Models",       desc: "DFD diagrams, STRIDE analysis, and Sigma detection rule generation.",     route: "/analyse/threat-models",       Icon: DeviceHub     },
          { name: "Frameworks",          desc: "NIST CSF, CIS v8, ISO 27001, PCI DSS, GDPR compliance mapping.",         route: "/report/frameworks",           Icon: Policy        },
          { name: "Custom Standards",    desc: "Build your own control framework from existing platform controls.",        route: "/report/custom-frameworks",    Icon: LibraryAdd    },
          { name: "Data Model",          desc: "Platform ontology — eleven entities, one interactive graph.",             route: "/data-model",                  Icon: AccountTree   },
        ],
      },
    ],
  },
  {
    id: "discover", label: "Discover", color: "#0f766e", overviewPath: "/discover",
    columns: [
      {
        heading: "Scanning",
        items: [
          { name: "Assessments",         desc: "Launch scans, manage versions, and import external scan results.",        route: "/discover/scans",              Icon: BugReport   },
          { name: "Findings",            desc: "All findings with severity, CVE enrichment, and remediation status.",     route: "/discover/findings",           Icon: FindInPage  },
          { name: "AI Assisted Scan",    desc: "Conversational guided assessment — describe the environment, AI configures.", route: "/discover/ai-scan",       Icon: SmartToy    },
          { name: "Posture Trends",      desc: "Time-series charts of open findings and audit readiness score.",          route: "/discover/posture",            Icon: TrendingUp  },
        ],
      },
      {
        heading: "Assets & CVE",
        items: [
          { name: "Asset Inventory",     desc: "All discovered assets with compliance and CVE posture.",                  route: "/discover/assets",             Icon: Storage     },
          { name: "Technology Inventory",desc: "Software and technology stack across all assets.",                        route: "/discover/technologies",       Icon: Devices     },
          { name: "CVE Blast Radius",    desc: "Map CVE exposure across assets — which assets are actually affected.",    route: "/discover/cve-pivot",          Icon: Radar       },
        ],
      },
    ],
  },
  {
    id: "analyse", label: "Analyse", color: "#b45309", overviewPath: "/analyse",
    columns: [
      {
        heading: "Risk",
        items: [
          { name: "Risk Register",         desc: "FAIR-scored risk register with domain heatmap and financial ALE.",     route: "/analyse/risks",               Icon: Security    },
          { name: "Risk Overview",         desc: "Executive summary of ALE exposure, risk domains, and top risks.",      route: "/analyse/risk-overview",       Icon: Assessment  },
          { name: "AI Risk Analysis",      desc: "AI-generated risk narrative with actionable recommendations.",         route: "/analyse/ai-analysis",         Icon: SmartToy    },
          { name: "Attack Paths",          desc: "MITRE-phased attack chain graph derived from live findings.",          route: "/analyse/attack-paths",        Icon: AltRoute    },
        ],
      },
      {
        heading: "Intelligence",
        items: [
          { name: "AI Threat Intelligence",desc: "DFD diagrams, STRIDE threats, and Sigma detection rule generation.",   route: "/analyse/threat-models",       Icon: DeviceHub   },
          { name: "Compliance Heatmap",    desc: "Control coverage heatmap across all frameworks.",                      route: "/analyse/compliance-heatmap",  Icon: GppBad      },
          { name: "Ask Your Data",         desc: "Natural language SQL queries over findings, risks, and assets.",       route: "/analyse/nl-query",            Icon: Search      },
          { name: "Project Comparison",    desc: "Compare security posture across multiple accounts.",                   route: "/analyse/comparison",          Icon: Assessment  },
        ],
      },
    ],
  },
  {
    id: "respond", label: "Respond", color: "#b91c1c", overviewPath: "/respond",
    columns: [
      {
        heading: "Threat Intelligence",
        items: [
          { name: "Threat Register",     desc: "MITRE ATT&CK–mapped threat entries and IOCs from AI analysis.",          route: "/respond/threats",             Icon: Radar           },
          { name: "Control Deficiencies",desc: "Framework control gaps identified by the compliance monitor agent.",      route: "/respond/gaps",                Icon: GppBad          },
          { name: "CTEM Programs",       desc: "5-phase exposure management: scope → discover → validate → mobilise.",   route: "/respond/ctem",                Icon: AccountTree     },
        ],
      },
      {
        heading: "Remediation",
        items: [
          { name: "Remediation",         desc: "Priority-banded remediation actions from the AI agent.",                 route: "/respond/remediation",         Icon: PlaylistAddCheck },
          { name: "AI Remediations",     desc: "AI-generated remediation plans with automated workflows.",               route: "/respond/remediation-jobs",    Icon: AutoFixHigh     },
          { name: "VAPT Reports",        desc: "Full engagement lifecycle with retest versioning and PDF/DOCX export.",  route: "/respond/vapt-reports",        Icon: Description     },
          { name: "Security Docs",       desc: "Upload security policies and ask questions via RAG.",                    route: "/respond/security-docs",       Icon: MenuBook        },
        ],
      },
    ],
  },
  {
    id: "report", label: "Report", color: "#15803d", overviewPath: "/report",
    columns: [
      {
        heading: "Pen Testing",
        items: [
          { name: "VAPT Reports",        desc: "Full engagement lifecycle with retest versioning and PDF/DOCX export.",  route: "/report/vapt-reports",         Icon: Description },
          { name: "Evidence Package",    desc: "ZIP of findings, deficiencies, and agent logs for auditors.",            route: "/report/evidence",             Icon: FolderZip   },
          { name: "Reports",             desc: "AI-generated security posture and trend reports.",                       route: "/report/reports",              Icon: Assessment  },
        ],
      },
      {
        heading: "Compliance",
        items: [
          { name: "Frameworks",          desc: "NIST CSF, CIS v8, ISO 27001, PCI DSS, GDPR compliance posture.",        route: "/report/frameworks",           Icon: Policy      },
          { name: "Custom Standards",    desc: "Build and evaluate custom control frameworks.",                          route: "/report/custom-frameworks",    Icon: LibraryAdd  },
          { name: "Control Gaps",        desc: "Framework control deficiencies identified by the compliance monitor.",   route: "/report/gaps",                 Icon: GppBad      },
        ],
      },
    ],
  },
  {
    id: "automate", label: "Automate", color: "#4338ca", overviewPath: "/automate",
    columns: [
      {
        heading: "AI Agents",
        items: [
          { name: "AI Buddies",          desc: "60+ AI agents — orchestrator, risk, threat intel, and remediation planner.", route: "/automate/agents",        Icon: SmartToy    },
          { name: "AI Workflows",        desc: "Multi-agent workflow missions and automated analysis pipelines.",         route: "/automate/workflows",          Icon: HubIcon     },
          { name: "AI Assisted Scan",    desc: "Conversational guided assessment — describe the environment, AI configures.", route: "/automate/ai-scan",      Icon: Psychology  },
        ],
      },
      {
        heading: "Knowledge",
        items: [
          { name: "Knowledge Base",      desc: "Platform knowledge base and Aegis reference documentation.",             route: "/automate/knowledge",          Icon: MenuBook    },
          { name: "Reports",             desc: "AI-generated security posture and trend reports.",                       route: "/automate/reports",            Icon: Assessment  },
          { name: "Ask Your Data",       desc: "SQL-backed natural language queries over all your data.",                route: "/automate/nl-query",           Icon: Search      },
          { name: "AI Guardrails",       desc: "AI safety controls, prompt audit logs, and guardrail coverage.",         route: "/automate/ai-guardrails",      Icon: Security    },
          { name: "Webhooks",            desc: "Event-driven alerts on critical findings and completed scans.",          route: "/automate/webhooks",           Icon: Webhook     },
          { name: "API Keys",            desc: "M2M API keys for CI/CD pipelines and programmatic access.",             route: "/automate/api-keys",           Icon: VpnKey      },
        ],
      },
    ],
  },
];

// ── Panel ─────────────────────────────────────────────────────────────────────

function MegaPanel({
  item, topPx, panelLeft, onClose, onMouseEnter, onMouseLeave,
}: {
  item: MenuItem;
  topPx: number;
  panelLeft: number;
  onClose: () => void;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
}) {
  const theme = useTheme();
  const navigate = useNavigate();
  const isDark = theme.palette.mode === "dark";

  const go = (route: string) => { onClose(); navigate(route); };

  return (
    <Box
      role="region"
      aria-label={`${item.label} menu`}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      sx={{
        position: "fixed",
        top: topPx - 1,           // -1 to close the 1px gap at bar border
        left: panelLeft,
        width: "58%",
        minWidth: 560,
        maxWidth: 920,
        zIndex: 1300,
        bgcolor: "background.paper",
        border: "1px solid", borderColor: "divider",
        borderTop: "none",
        borderRadius: "0 0 12px 12px",
        boxShadow: isDark ? "0 12px 40px rgba(0,0,0,0.55)" : "0 8px 32px rgba(0,0,0,0.13)",
        px: 3, py: 2.5,
        animation: "mmIn 0.15s ease",
        "@keyframes mmIn": {
          from: { opacity: 0, transform: "translateY(-6px)" },
          to:   { opacity: 1, transform: "translateY(0)" },
        },
      }}
    >
      <Box sx={{ display: "flex", gap: { xs: 2, md: 4 }, flexWrap: "wrap" }}>
        {item.columns.map((col) => (
          <Box key={col.heading} sx={{ flex: "1 1 240px", minWidth: 210 }}>
            {/* Column header */}
            <Typography sx={{
              fontSize: 10.5, fontWeight: 700, color: item.color,
              textTransform: "uppercase", letterSpacing: "0.1em",
              mb: 1.25, pb: 0.5,
              borderBottom: `2px solid ${item.color}`,
              display: "inline-block",
            }}>
              {col.heading}
            </Typography>
            <Box sx={{ display: "flex", flexDirection: "column", gap: 0.15 }}>
              {col.items.map((mi) => (
                <Box
                  key={mi.name}
                  component="button"
                  onClick={() => go(mi.route)}
                  tabIndex={0}
                  sx={{
                    display: "flex", alignItems: "flex-start", gap: 1.5,
                    p: 0.875, borderRadius: 1.5, border: "none", bgcolor: "transparent",
                    cursor: "pointer", textAlign: "left", width: "100%",
                    transition: "background 0.12s",
                    "&:hover, &:focus-visible": {
                      bgcolor: alpha(item.color, isDark ? 0.12 : 0.07),
                      outline: "none",
                    },
                  }}
                >
                  <Box sx={{
                    width: 32, height: 32, flexShrink: 0, borderRadius: 1.25,
                    bgcolor: alpha(item.color, isDark ? 0.16 : 0.09),
                    display: "flex", alignItems: "center", justifyContent: "center",
                    color: item.color, mt: 0.1,
                  }}>
                    <mi.Icon sx={{ fontSize: 17 }} />
                  </Box>
                  <Box>
                    <Typography sx={{ fontSize: 13, fontWeight: 600, color: "text.primary", lineHeight: 1.3, mb: 0.15 }}>
                      {mi.name}
                    </Typography>
                    <Typography sx={{ fontSize: 11.5, color: "text.secondary", lineHeight: 1.4 }}>
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
  brand?: React.ReactNode;
  trailing?: React.ReactNode;
}

export default function MegaMenuBar({ brand, trailing }: Props) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const location = useLocation();
  const navigate = useNavigate();
  const [open, setOpen] = useState<string | null>(null);
  const [mobileOpen, setMobileOpen] = useState<string | null>(null);
  const [panelLeft, setPanelLeft] = useState(0);
  const barRef = useRef<HTMLDivElement>(null!);
  const leaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const activePhase = getActivePhase(location.pathname);

  const clearLeave = () => { if (leaveTimer.current) clearTimeout(leaveTimer.current); };

  const enter = useCallback((id: string, el?: HTMLElement) => {
    clearLeave();
    setOpen(id);
    if (el) {
      const rect = el.getBoundingClientRect();
      const vw = window.innerWidth;
      const panelW = Math.min(920, Math.max(560, vw * 0.58));
      // Align to the button's left edge, clamped so panel stays within viewport
      setPanelLeft(Math.max(8, Math.min(rect.left, vw - panelW - 8)));
    }
  }, []);
  const leave = useCallback(() => { leaveTimer.current = setTimeout(() => setOpen(null), 350); }, []);
  const closeAll = useCallback(() => { clearLeave(); setOpen(null); }, []);

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") closeAll(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [closeAll]);

  // close panel on navigation
  useEffect(() => { closeAll(); }, [location.pathname, closeAll]);

  const activeItem = MENU.find((m) => m.id === open) ?? null;
  const barBottom = barRef.current ? barRef.current.getBoundingClientRect().bottom : 52;

  return (
    <>
      {/* Click-outside backdrop — starts BELOW the bar so it never covers nav buttons */}
      {activeItem && (
        <Box onClick={closeAll} sx={{ position: "fixed", top: barBottom, left: 0, right: 0, bottom: 0, zIndex: 1299 }} />
      )}

      {/* Bar row */}
      <Box
        ref={barRef}
        sx={{ display: "flex", alignItems: "center", height: "100%", px: { xs: 1.5, md: 2 }, gap: 0 }}
      >
        {/* Brand */}
        {brand && (
          <Box
            onClick={() => navigate("/hub")}
            sx={{ mr: { xs: 1, md: 2 }, flexShrink: 0, cursor: "pointer", display: "flex", alignItems: "center" }}
          >
            {brand}
          </Box>
        )}

        {isMobile ? (
          /* ── Mobile: tap accordion ──────────────────────────────────────── */
          <Box sx={{ display: "flex", gap: 0.25, flexWrap: "wrap", alignItems: "center", flexGrow: 1 }}>
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
                      display: "flex", alignItems: "center", gap: 0.25, px: 1, py: 0.5,
                      border: "none", borderRadius: 1, cursor: "pointer",
                      bgcolor: expanded ? alpha(item.color, 0.1) : "transparent",
                      color: expanded ? item.color : "text.primary",
                      fontSize: 12.5, fontWeight: 600,
                      "&:focus-visible": { outline: `2px solid ${item.color}` },
                    }}
                  >
                    {item.label}
                    <ExpandMore sx={{ fontSize: 14, transform: expanded ? "rotate(180deg)" : "none", transition: "transform 0.2s" }} />
                  </Box>
                  <Collapse in={expanded} timeout={160}>
                    <Box sx={{ pl: 1, py: 0.5 }}>
                      {item.columns.flatMap((c) => c.items).map((mi) => (
                        <Box
                          key={mi.name}
                          component="button"
                          onClick={() => { setMobileOpen(null); navigate(mi.route); }}
                          sx={{
                            display: "block", width: "100%", textAlign: "left",
                            px: 1.5, py: 0.6, border: "none", bgcolor: "transparent",
                            color: "text.primary", cursor: "pointer", fontSize: 12.5, borderRadius: 1,
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
          /* ── Desktop: hover mega menu ───────────────────────────────────── */
          <Box
            onMouseEnter={clearLeave}
            onMouseLeave={leave}
            sx={{ display: "flex", alignItems: "center", height: "100%", flexGrow: 1 }}
          >
            {MENU.map((item, idx) => {
              const isOpen = open === item.id;
              const isActive = activePhase === item.id;
              return (
                <Box
                  key={item.id}
                  component="button"
                  role="button"
                  aria-haspopup="true"
                  aria-expanded={isOpen}
                  aria-controls={`mega-panel-${item.id}`}
                  onMouseEnter={(e) => enter(item.id, e.currentTarget)}
                  onFocus={(e) => enter(item.id, e.currentTarget)}
                  onClick={() => { closeAll(); navigate(item.overviewPath); }}
                  onKeyDown={(e: React.KeyboardEvent) => {
                    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); closeAll(); navigate(item.overviewPath); }
                    if (e.key === "Escape") closeAll();
                    if (e.key === "ArrowRight" && idx < MENU.length - 1) enter(MENU[idx + 1].id);
                    if (e.key === "ArrowLeft"  && idx > 0)               enter(MENU[idx - 1].id);
                  }}
                  sx={{
                    px: 1.5, height: "100%", border: "none", bgcolor: "transparent",
                    cursor: "pointer", display: "flex", alignItems: "center", gap: 0.25,
                    fontSize: 13, fontWeight: isOpen || isActive ? 700 : 500,
                    color: isOpen ? item.color : isActive ? item.color : "text.primary",
                    borderBottom: isOpen ? `2px solid ${item.color}` : isActive ? `2px solid ${alpha(item.color, 0.45)}` : "2px solid transparent",
                    transition: "color 0.14s, border-color 0.14s",
                    "&:hover": { color: item.color },
                    "&:focus-visible": { outline: `2px solid ${item.color}`, outlineOffset: -2 },
                  }}
                >
                  {item.label}
                  <ExpandMore sx={{
                    fontSize: 13, color: "inherit",
                    transform: isOpen ? "rotate(180deg)" : "none",
                    transition: "transform 0.18s",
                  }} />
                </Box>
              );
            })}
          </Box>
        )}

        {/* Trailing */}
        {trailing && (
          <Box sx={{ ml: { xs: "auto", md: 1 }, flexShrink: 0 }}>{trailing}</Box>
        )}
      </Box>

      {/* Desktop panel — handlers go directly on the fixed Box inside MegaPanel */}
      {!isMobile && activeItem && (
        <MegaPanel
          item={activeItem}
          topPx={barBottom}
          panelLeft={panelLeft}
          onClose={closeAll}
          onMouseEnter={clearLeave}
          onMouseLeave={leave}
        />
      )}
    </>
  );
}
