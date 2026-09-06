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
  Drawer, IconButton, List, ListItemButton,
} from "@mui/material";
import {
  ExpandMore, ExpandLess, Psychology, Radar, Assessment,
  GppBad, PlaylistAddCheck, SmartToy,
  LibraryAdd, TrendingUp, Security, FindInPage,
  Description, AltRoute, FolderZip, AccountTree, BarChart,
  DeviceHub, People, Cable, MenuBook, Search, AutoFixHigh,
  Hub as HubIcon, VpnKey, Webhook, ManageSearch, ReportProblem,
  Menu as MenuIcon, Close as CloseIcon,
  SyncAlt, Settings, HelpOutlined, Memory, BusinessCenter, UploadFile,
  Tune, GpsFixed, RateReview, Schedule, PendingActions,
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
          { name: "Accounts",     desc: "Client profiles, contact details, and security posture scoping.",                       route: "/platform/clients",      Icon: People      },
          { name: "Integrations", desc: "Platform connectors, scanners, AI providers, webhooks, and API keys — all in one hub.", route: "/platform/integrations", Icon: Cable       },
          { name: "Ticket Sync",  desc: "Bi-directional sync of findings and remediations with your ticket system.",             route: "/platform/ticket-sync",  Icon: SyncAlt     },
        ],
      },
      {
        heading: "Governance Config",
        items: [
          { name: "Risk Appetite", desc: "Configure organisation risk tolerance bands for the 5×5 GCC IM8 matrix.",  route: "/analyse/risk-appetite", Icon: Tune        },
          { name: "Data Model",    desc: "Platform ontology — eleven entities, one interactive graph.",              route: "/data-model",            Icon: AccountTree },
          { name: "Settings",      desc: "User preferences, deleted accounts, and platform configuration.",          route: "/platform/settings",     Icon: Settings    },
          { name: "Help",          desc: "Documentation, setup guides, and platform support resources.",             route: "/platform/help",         Icon: HelpOutlined},
        ],
      },
    ],
  },
  {
    id: "discover", label: "Discover", color: "#0f766e", overviewPath: "/discover",
    columns: [
      {
        heading: "Security Scanners",
        items: [
          { name: "Inbuilt Scanners",       desc: "Platform-native scanners — DAST, SAST, network, container, and secret scanning.",        route: "/discover/inbuilt",       Icon: Memory         },
          { name: "Enterprise Integration", desc: "Connect enterprise scanners — Tenable, Burp, Snyk, Rapid7, Qualys, Invicti, Acunetix.", route: "/discover/enterprise",    Icon: BusinessCenter },
          { name: "Import Result",          desc: "Import external scan results from SARIF, Nessus, Burp, OpenVAS, Qualys, and more.",      route: "/discover/import-result", Icon: UploadFile     },
          { name: "AI Assisted Scan",       desc: "Conversational guided assessment — describe the environment, AI configures.",             route: "/discover/ai-scan",       Icon: SmartToy       },
        ],
      },
      {
        heading: "Findings & Coverage",
        items: [
          { name: "Findings",         desc: "All findings with severity, CVE enrichment, and remediation status.",          route: "/discover/findings",  Icon: FindInPage },
          { name: "CVE Blast Radius", desc: "Map CVE exposure across assets — which assets are actually affected.",         route: "/discover/cve-pivot", Icon: Radar      },
          { name: "Scan Coverage",    desc: "Assets not scanned within the policy window — identify coverage gaps.",        route: "/discover/coverage",  Icon: GpsFixed   },
          { name: "Posture Trends",   desc: "Time-series charts of open findings and audit readiness score.",               route: "/discover/posture",   Icon: TrendingUp },
        ],
      },
      {
        heading: "Assets & Tech",
        items: [
          { name: "Asset Inventory",      desc: "All discovered assets with compliance and CVE posture.", route: "/discover/assets",       Icon: AccountTree },
          { name: "Technology Inventory", desc: "Software and technology stack across all assets.",       route: "/discover/technologies", Icon: DeviceHub   },
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
          { name: "Risk Staging",     desc: "AI / finding / manual proposals — 8-step evaluation wizard before the register.", route: "/analyse/risks/staging", Icon: PendingActions },
          { name: "Risk Register",    desc: "FAIR-scored risk register with domain heatmap and financial ALE.",                route: "/analyse/risks",         Icon: Security       },
          { name: "Risk Overview",    desc: "Executive summary of ALE exposure, risk domains, and top risks.",                 route: "/analyse/risk-overview", Icon: Assessment     },
          { name: "AI Risk Analysis", desc: "AI-generated risk narrative with actionable recommendations.",                    route: "/analyse/ai-analysis",   Icon: SmartToy       },
        ],
      },
      {
        heading: "Exposure & Threat Modelling",
        items: [
          { name: "Attack Paths",       desc: "MITRE-phased attack chain graph derived from live findings.",      route: "/analyse/attack-paths",       Icon: AltRoute  },
          { name: "Threat Models",      desc: "DFD diagrams, STRIDE threats, and Sigma detection rule generation.", route: "/analyse/threat-models",    Icon: DeviceHub },
          { name: "Compliance Heatmap", desc: "Control coverage heatmap across all active frameworks.",            route: "/analyse/compliance-heatmap", Icon: GppBad    },
        ],
      },
      {
        heading: "Query & Compare",
        items: [
          { name: "Ask Your Data", desc: "Natural language SQL queries over findings, risks, and assets.",  route: "/analyse/nl-query",  Icon: Search     },
          { name: "Comparison",    desc: "Compare security posture side-by-side across multiple accounts.", route: "/analyse/comparison", Icon: Assessment },
        ],
      },
    ],
  },
  {
    id: "respond", label: "Respond", color: "#b91c1c", overviewPath: "/respond",
    columns: [
      {
        heading: "Incidents",
        items: [
          { name: "Incidents", desc: "Security incident cases with timelines, owners, SLA tracking, and linked findings.", route: "/respond/incidents", Icon: ReportProblem },
        ],
      },
      {
        heading: "Threat Intelligence",
        items: [
          { name: "Threat Register", desc: "MITRE ATT&CK–mapped threat entries and IOCs from AI analysis.",        route: "/respond/threats", Icon: Radar       },
          { name: "CTEM Programs",   desc: "5-phase exposure management: scope → discover → validate → mobilise.", route: "/respond/ctem",    Icon: AccountTree },
        ],
      },
      {
        heading: "Remediation",
        items: [
          { name: "Remediation",     desc: "Priority-banded remediation actions from the AI agent.",          route: "/respond/remediation",      Icon: PlaylistAddCheck },
          { name: "AI Remediations", desc: "AI-generated remediation plans with automated workflows.",        route: "/respond/remediation-jobs", Icon: AutoFixHigh      },
          { name: "Security Docs",   desc: "Upload security policies and ask questions via RAG.",             route: "/respond/security-docs",    Icon: MenuBook         },
        ],
      },
    ],
  },
  {
    id: "report", label: "Audit", color: "#15803d", overviewPath: "/report",
    columns: [
      {
        heading: "Reporting",
        items: [
          { name: "VAPT Reports",      desc: "Full engagement lifecycle with retest versioning and PDF/DOCX export.",               route: "/report/vapt-reports",      Icon: Description },
          { name: "Evidence Package",  desc: "ZIP of findings, deficiencies, and agent logs for auditors.",                       route: "/report/evidence",          Icon: FolderZip   },
          { name: "Reports",           desc: "AI-generated security posture and trend reports.",                                  route: "/report/reports",           Icon: Assessment  },
          { name: "Executive Summary", desc: "Non-technical leadership report — posture score, key risks, remediation progress.", route: "/report/executive-summary", Icon: Assessment  },
          { name: "Report Scheduler",  desc: "Schedule recurring report delivery to stakeholders via email.",                     route: "/report/scheduler",         Icon: Schedule    },
        ],
      },
      {
        heading: "Audit Operations",
        items: [
          { name: "Audit Intelligence", desc: "ICS Audit & Risk — how every audit activity maps to the platform.",                    route: "/report/audit",          Icon: ManageSearch },
          { name: "Audit Agents",       desc: "Wizard-driven AI agents for control testing, readiness reports, and evidence curation.", route: "/report/audit-agents",  Icon: Psychology   },
          { name: "Audit Logs",         desc: "LLM prompt audit trail — per-user, per-endpoint, with CSV export.",                    route: "/platform/audit-logs",   Icon: ManageSearch },
        ],
      },
      {
        heading: "Compliance Frameworks",
        items: [
          { name: "Framework Library",     desc: "Browse standard frameworks and manage custom compliance policies.",    route: "/report/frameworks",        Icon: LibraryAdd },
          { name: "Custom Standards",      desc: "Build your own control framework from existing platform controls.",    route: "/report/custom-frameworks", Icon: LibraryAdd },
          { name: "Compliance Evaluation", desc: "Evaluate posture and run targeted scans against any framework.",       route: "/report/compliance",        Icon: BarChart   },
          { name: "Control Gaps",          desc: "Framework control deficiencies identified by the compliance monitor.", route: "/report/gaps",              Icon: GppBad     },
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
          { name: "AI Buddies",         desc: "60+ AI agents — orchestrator, risk, threat intel, and remediation planner.",   route: "/automate/agents",    Icon: SmartToy   },
          { name: "AI Workflows",       desc: "Multi-agent workflow missions and automated analysis pipelines.",               route: "/automate/workflows", Icon: HubIcon    },
          { name: "AI Assisted Review", desc: "Select a completed assessment and let AI recommend which agents to run next.", route: "/automate/ai-review", Icon: RateReview },
        ],
      },
      {
        heading: "Knowledge",
        items: [
          { name: "Knowledge Base", desc: "Platform knowledge base and Aegis reference documentation.", route: "/automate/knowledge",     Icon: MenuBook },
          { name: "AI Guardrails",  desc: "AI safety controls, prompt audit logs, and guardrail coverage.", route: "/automate/ai-guardrails", Icon: Security },
        ],
      },
      {
        heading: "Governance",
        items: [
          { name: "Webhooks",        desc: "Event-driven alerts on critical findings and completed scans.", route: "/platform/integrations?tab=webhooks", Icon: Webhook  },
          { name: "API Keys",        desc: "M2M API keys for CI/CD pipelines and programmatic access.",    route: "/platform/integrations?tab=api-keys", Icon: VpnKey   },
          { name: "AI Usage & Cost", desc: "Token consumption and estimated spend per provider and agent.", route: "/automate/usage",                    Icon: BarChart },
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
                    flexShrink: 0,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    color: item.color, mt: 0.1,
                  }}>
                    <mi.Icon sx={{ fontSize: 20 }} />
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

// ── Mobile Drawer ─────────────────────────────────────────────────────────────

function MobileDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const theme = useTheme();
  const navigate = useNavigate();
  const [expanded, setExpanded] = useState<string | null>(null);

  const go = (route: string) => { onClose(); navigate(route); };

  return (
    <Drawer
      anchor="left"
      variant="temporary"
      open={open}
      onClose={onClose}
      ModalProps={{ keepMounted: true }}
      sx={{
        zIndex: 1400,
        "& .MuiDrawer-paper": {
          width: 280,
          bgcolor: "background.paper",
          border: "none",
        },
      }}
    >
      {/* Header */}
      <Box sx={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        px: 2, py: 1.5, borderBottom: "1px solid", borderColor: "divider",
      }}>
        <Typography sx={{ fontWeight: 700, fontSize: 15, color: "text.primary" }}>
          Navigation
        </Typography>
        <IconButton size="small" onClick={onClose} sx={{ color: "text.secondary" }}>
          <CloseIcon fontSize="small" />
        </IconButton>
      </Box>

      {/* Nav sections */}
      <Box sx={{ overflowY: "auto", flex: 1 }}>
        {MENU.map((item) => {
          const isExpanded = expanded === item.id;
          return (
            <Box key={item.id}>
              <ListItemButton
                onClick={() => setExpanded(isExpanded ? null : item.id)}
                sx={{
                  px: 2, py: 1,
                  bgcolor: isExpanded ? alpha(item.color, 0.07) : "transparent",
                  "&:hover": { bgcolor: alpha(item.color, 0.05) },
                }}
              >
                <Typography sx={{
                  flex: 1, fontSize: 13, fontWeight: 700, color: isExpanded ? item.color : "text.primary",
                  textTransform: "uppercase", letterSpacing: "0.06em",
                }}>
                  {item.label}
                </Typography>
                {isExpanded
                  ? <ExpandLess sx={{ fontSize: 18, color: item.color }} />
                  : <ExpandMore sx={{ fontSize: 18, color: "text.secondary" }} />}
              </ListItemButton>
              <Collapse in={isExpanded} timeout={160}>
                <Box sx={{ pb: 0.5 }}>
                  {item.columns.map((col) => (
                    <Box key={col.heading}>
                      <Typography sx={{
                        fontSize: 10, fontWeight: 700, letterSpacing: "0.1em",
                        color: item.color, textTransform: "uppercase",
                        pl: 2.5, pt: 1.25, pb: 0.25,
                      }}>
                        {col.heading}
                      </Typography>
                      {col.items.map((mi) => (
                        <ListItemButton
                          key={mi.name}
                          onClick={() => go(mi.route)}
                          sx={{ pl: 3, py: 0.6, "&:hover": { bgcolor: "action.hover" } }}
                        >
                          <Typography sx={{ fontSize: 13, color: "text.primary" }}>
                            {mi.name}
                          </Typography>
                        </ListItemButton>
                      ))}
                    </Box>
                  ))}
                </Box>
              </Collapse>
            </Box>
          );
        })}
      </Box>
    </Drawer>
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
  const [drawerOpen, setDrawerOpen] = useState(false);
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

  useEffect(() => { closeAll(); }, [location.pathname, closeAll]);

  const activeItem = MENU.find((m) => m.id === open) ?? null;
  const barBottom = barRef.current ? barRef.current.getBoundingClientRect().bottom : 52;

  return (
    <>
      {/* Click-outside backdrop */}
      {activeItem && (
        <Box onClick={closeAll} sx={{ position: "fixed", top: barBottom, left: 0, right: 0, bottom: 0, zIndex: 1299 }} />
      )}

      {/* Bar row */}
      <Box
        ref={barRef}
        sx={{ display: "flex", alignItems: "center", height: "100%", px: { xs: 1, md: 2 }, gap: 0 }}
      >
        {isMobile ? (
          /* ── Mobile: hamburger + drawer ─────────────────────────────────── */
          <>
            <IconButton
              size="small"
              onClick={() => setDrawerOpen(true)}
              sx={{ mr: 1, color: "text.primary" }}
              aria-label="Open navigation"
            >
              <MenuIcon />
            </IconButton>
            {brand && (
              <Box
                onClick={() => navigate("/hub")}
                sx={{ flexGrow: 1, cursor: "pointer", display: "flex", alignItems: "center" }}
              >
                {brand}
              </Box>
            )}
            <MobileDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} />
          </>
        ) : (
          /* ── Desktop: brand + hover mega menu ───────────────────────────── */
          <>
            {brand && (
              <Box
                onClick={() => navigate("/hub")}
                sx={{ mr: 2, flexShrink: 0, cursor: "pointer", display: "flex", alignItems: "center" }}
              >
                {brand}
              </Box>
            )}
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
          </>
        )}

        {/* Trailing */}
        {trailing && (
          <Box sx={{ ml: { xs: "auto", md: 1 }, flexShrink: 0 }}>{trailing}</Box>
        )}
      </Box>

      {/* Desktop panel */}
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
