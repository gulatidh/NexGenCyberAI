/**
 * Help — the Platform Guide.
 *
 * Single-page reference that walks a new user through every major
 * workflow on the platform. Organized as topic groups; each topic is
 * an accordion with numbered steps and contextual tips.
 *
 * Anyone authenticated can view this (no admin gate).
 */
import React, { useMemo, useState } from "react";
import {
  Accordion, AccordionDetails, AccordionSummary, Alert, Box, Card,
  CardContent, Chip, Grid, InputAdornment, TextField, Typography,
} from "@mui/material";
import {
  ExpandMore, MenuBook, RocketLaunch, Hub, BugReport, Insights,
  SmartToy, Schedule, AutoStories, BarChart, AdminPanelSettings,
  SettingsSuggest, Search, Lightbulb, Warning,
} from "@mui/icons-material";

interface Step {
  text: string;
  detail?: string;
}
interface Topic {
  id: string;
  title: string;
  summary: string;
  steps: Step[];
  tips?: string[];
  warnings?: string[];
}
interface Group {
  id: string;
  title: string;
  icon: React.ReactNode;
  color: string;
  topics: Topic[];
}

const GROUPS: Group[] = [
  {
    id: "getting-started",
    title: "Getting started",
    icon: <RocketLaunch />,
    color: "#4285F4",
    topics: [
      {
        id: "sign-in",
        title: "Sign in to NexGenCyberAI",
        summary: "Use your work Microsoft account — there's no separate password to manage.",
        steps: [
          { text: "Open the platform URL provided by your administrator." },
          { text: "Click 'Sign in' and authenticate with your Microsoft Entra ID account (Single Sign-On)." },
          { text: "If you see an 'access required' screen, ask any global or scoped admin to grant your account a role from Administration → Grant access." },
        ],
        tips: [
          "Your access is checked against Microsoft Entra ID on every API call — no local passwords are stored.",
        ],
      },
      {
        id: "first-client",
        title: "Create your first client",
        summary: "Clients are the top-level multi-tenant container — connectors, scans, risks all live under a client.",
        steps: [
          { text: "Open the Clients tab from the left navigation." },
          { text: "Click 'Add client'." },
          { text: "Fill in the name, slug, industry, and primary contact. Slug must be unique." },
          { text: "Click 'Create'. You'll land on the new Client Detail page where you can add Projects, Connectors, and view scans." },
        ],
      },
      {
        id: "nav-tour",
        title: "Where to find things in the nav",
        summary: "The left navigation is split into a main workflow group and a Settings group.",
        steps: [
          { text: "Main workflow group (top): Dashboard, Risk Overview, Clients, Assessments, Findings, Risk Register, Asset Inventory, Technologies, Frameworks, AI Agents, Workflows, Knowledge Base, Reports." },
          { text: "Settings group (bottom): AI Settings, Sync (admin), Administration (admin), Help." },
          { text: "Connectors and Projects don't have top-level nav — they're tabs inside the Client Detail page." },
        ],
      },
    ],
  },
  {
    id: "setup",
    title: "Connecting your environment",
    icon: <Hub />,
    color: "#34A853",
    topics: [
      {
        id: "cloud-connector",
        title: "Add a cloud connector (Azure / AWS / GCP / Entra ID)",
        summary: "Cloud connectors run security checks directly against your cloud provider's API.",
        steps: [
          { text: "Open the Client whose environment you want to scan." },
          { text: "Switch to the Connectors tab on the Client Detail page." },
          { text: "Click 'Add connector' and pick a type (Azure, AWS, GCP, Entra ID, Containers, On-Prem, etc.)." },
          { text: "Paste the required credentials (service principal / IAM role / etc.) and the target subscription / account / tenant ID." },
          { text: "Click 'Test connection' to verify reachability before saving." },
          { text: "Click 'Save'. The connector immediately syncs the asset inventory for that account." },
        ],
        warnings: [
          "Credentials are encrypted at rest with the platform's Fernet key — but the key is in App Service config. Treat connector creds like any other production secret.",
        ],
      },
      {
        id: "scanner-connector",
        title: "Add a workflow scanner (Nmap, Trivy, Gitleaks, Semgrep, ZAP, …)",
        summary: "Workflow scanners run in GitHub Actions and post findings back to the platform.",
        steps: [
          { text: "On the Client Detail → Connectors tab, click 'Add connector' and pick the scanner type." },
          { text: "Fill in the target field — repo URL for SAST / secret scanners, host or CIDR for Nmap / OpenVAS, image ref or repo URL for Trivy, URL for ZAP." },
          { text: "For private repos, paste a Git PAT — the workflow injects it into the clone URL at scan time." },
          { text: "Save the connector. Run a scan from Assessments tab when ready." },
        ],
        tips: [
          "The setup help text at the top of each connector dialog shows the exact command the workflow runs and which credentials are needed.",
          "Each scan dispatch is authenticated via a per-scan HMAC token; secrets are never logged in the GitHub Actions workflow inputs.",
        ],
      },
    ],
  },
  {
    id: "scanning",
    title: "Running scans (Assessments)",
    icon: <BugReport />,
    color: "#FBBC04",
    topics: [
      {
        id: "start-scan",
        title: "Start a scan",
        summary: "Every scan turns into an 'Assessment' tile with its own AI verdict.",
        steps: [
          { text: "Open Assessments from the left nav." },
          { text: "Click 'New scan'." },
          { text: "Pick the Client and the Connector you want to scan from." },
          { text: "Choose scan type (configuration, vulnerability, compliance, or full). For some scanners only one type is meaningful." },
          { text: "Optionally tag a Framework (NIST CSF / 800-53 / CIS / OWASP / GDPR / …) — findings will be control-mapped." },
          { text: "Click 'Start'. The tile flips to 'Running'; the AI verdict + findings auto-populate when the workflow completes." },
        ],
      },
      {
        id: "tile-view",
        title: "Understanding the tile view",
        summary: "Assessments is a tile grid — one tile per scan across all clients you have access to.",
        steps: [
          { text: "Header shows 'Category · Client' (DAST · Acme, Network · TechCorp, etc.)." },
          { text: "Top-right status chip: pending → running → completed (or failed)." },
          { text: "Top-right trash icon deletes the entire scan + its findings + agent runs + verdict (with a confirm dialog)." },
          { text: "Footer chips show severity counts and whether an AI verdict has been generated." },
          { text: "Click anywhere on the tile to drill into the Assessment detail." },
        ],
      },
      {
        id: "scan-detail",
        title: "Reading the Assessment detail (AI verdict + findings + agent runs)",
        summary: "The detail page is structured as a Verdict tab, a Findings tab, and one tab per AI agent that ran.",
        steps: [
          { text: "Verdict tab: The Verdict (one-line headline), What We Found, Why It Matters, Executive Summary, Capability Gaps, Signal Coverage, Attack Paths, Vendor Scorecard, RPS factor breakdown, Data Completeness, Automation Opportunities." },
          { text: "Findings tab: every individual finding with severity, CVE, CVSS, RPS, resource. Per-row trash icon deletes a finding." },
          { text: "Per-agent tabs: the raw output from each AI agent that ran against this scan." },
          { text: "Top-right 'Print / PDF' button expands every tab into a single document and opens the browser print dialog — pick 'Save as PDF'." },
        ],
        tips: [
          "If a scan completed but the AI verdict didn't auto-generate, click 'Generate verdict' on the Verdict tab.",
          "RPS factors are tagged evidenced / estimated / unknown. Unknown factors are dropped from the score — they don't penalise findings.",
        ],
      },
      {
        id: "delete-blank-findings",
        title: "Tidy up empty / failed findings",
        summary: "Some scanners return partial rows. The Findings page has a one-click cleanup.",
        steps: [
          { text: "Open Findings from the left nav and pick a Client." },
          { text: "Click 'Delete blank findings' (top-right of the chip row). This removes any finding with no title, no description, and no resource." },
          { text: "For one-off deletions, click the trash icon on any individual row or open the detail dialog and use the Delete button there." },
        ],
      },
    ],
  },
  {
    id: "risk",
    title: "Working with risks",
    icon: <Insights />,
    color: "#EA4335",
    topics: [
      {
        id: "risk-overview",
        title: "Risk Overview — the executive dashboard",
        summary: "FAIR-lite ALE estimates, 30-day breach probability, and risk-by-domain breakdown.",
        steps: [
          { text: "Open Risk Overview from the left nav and pick a Client." },
          { text: "Top row: Total Exposure (ALE high), Net Exposure (after controls), Open Critical/High count, 30-Day Breach Probability." },
          { text: "Risk-by-domain bar chart shows where the exposure concentrates." },
          { text: "Bottom table lists every risk with its ALE range, remediation status, and source link." },
        ],
      },
      {
        id: "risk-register",
        title: "Risk Register — prioritised risks + AI analysis",
        summary: "Multi-select slicer chips, top 5 risks, and an AI Agent Risk Analysis tile grid.",
        steps: [
          { text: "Open Risk Register, pick a Client." },
          { text: "Use the slicer chips to filter by severity / status / category." },
          { text: "Click any row in the risk table to update its status (open / mitigated / accepted / closed)." },
          { text: "Scroll to AI Agent Risk Analysis — one tile per agent type (Risk Manager / Threat Intel / Remediation)." },
          { text: "Click a tile to expand the full agent narrative inline; only one tile is open at a time." },
          { text: "Yellow History icon (with a badge count) on a tile means previous versions of that agent's analysis exist. Click it to see the version history." },
          { text: "Trash icon on a tile deletes the live analysis. Trash icons inside the version history dialog delete individual older versions." },
        ],
      },
    ],
  },
  {
    id: "ai-agents",
    title: "AI Agents",
    icon: <SmartToy />,
    color: "#9C27B0",
    topics: [
      {
        id: "run-agent",
        title: "Run an AI agent against a scan",
        summary: "Agents enrich a scan with risk scoring, framework mapping, remediation, threat intel.",
        steps: [
          { text: "Open the AI Agents tab from the left nav." },
          { text: "Pick a Client and the Scan to analyse." },
          { text: "Choose which agents to run (Risk Manager, Vulnerability Analysis, Framework Mapping, Threat Intel, Remediation, Compliance) and click 'Run agents'." },
          { text: "Agents run in parallel; outputs land both on the Scan Detail per-agent tab and on the Risk Register (for risk-related agents)." },
        ],
        warnings: [
          "If no AI provider is configured (AI Settings), agents fall back to rule-based output. Configure Azure OpenAI / OpenAI / Anthropic / Gemini / Bedrock in AI Settings for full narrative output.",
        ],
      },
      {
        id: "ai-settings",
        title: "Choose your AI provider",
        summary: "Configure which LLM the platform uses for agent narratives and scan verdicts.",
        steps: [
          { text: "Open Settings → AI Settings." },
          { text: "Pick a provider: Azure OpenAI, OpenAI, Anthropic, Gemini, or AWS Bedrock." },
          { text: "Paste the API key + endpoint (where applicable)." },
          { text: "Click 'Test'. A green success means the provider is reachable; this provider then powers every agent run + scan verdict + workflow report." },
        ],
      },
      {
        id: "agent-catalog",
        title: "Browse the AI Agent catalog",
        summary: "Beyond the operational agents, ~43 advisory agents covering SOC design, GRC, IR, zero trust, IGA, threat intel, and more.",
        steps: [
          { text: "AI Agents → Catalog tab." },
          { text: "Browse the 7 groups (Operational, Strategy, Compliance, Cloud, Identity, Detection, Response)." },
          { text: "Admins can add / edit / delete agents from this view; non-admins can read and run." },
        ],
      },
    ],
  },
  {
    id: "automation",
    title: "Automation (Workflows)",
    icon: <Schedule />,
    color: "#FF7043",
    topics: [
      {
        id: "create-workflow",
        title: "Schedule a recurring workflow",
        summary: "Workflows = scheduled missions. APScheduler-based cron, no external broker needed.",
        steps: [
          { text: "Open Workflows from the left nav." },
          { text: "Click 'New workflow'." },
          { text: "Pick a Client, give the workflow a name, choose a mission type (Cloud Security Assessment, SOC Design, GRC Advisory, …)." },
          { text: "Pick a schedule — use a preset (Daily 06:00, Weekly Monday, Monthly 1st) or paste a 5-field cron expression." },
          { text: "Toggle 'Send summary email' and 'Update risk quantification' if you want post-run hooks." },
          { text: "Save. The workflow fires on its schedule, or you can 'Run now' from the row to test it." },
        ],
      },
      {
        id: "workflow-reports",
        title: "Standardised workflow reports + PDF download",
        summary: "Every workflow run produces a 7-section AI report with the same shape every time.",
        steps: [
          { text: "Open Workflows and click the History icon on any workflow row." },
          { text: "Each run shows a status chip + 'View Report' button (when a report was generated)." },
          { text: "Click 'View Report' to open the standardised report viewer (Executive Summary, Scope & Inputs, Key Findings, Risk Picture, Recommendations, Next Steps, Data Completeness)." },
          { text: "Click 'Download PDF' inside the viewer — opens the browser print dialog scoped to the report content; pick 'Save as PDF'." },
        ],
        tips: [
          "Reports are persisted with the run, so the PDF stays reproducible. The 7-section schema is enforced server-side even if the LLM tries to skip or add sections.",
        ],
      },
    ],
  },
  {
    id: "knowledge",
    title: "Knowledge Base",
    icon: <AutoStories />,
    color: "#26C6DA",
    topics: [
      {
        id: "browse-kb",
        title: "Find a runbook or framework reference",
        summary: "Pre-seeded files covering common controls, runbooks, and playbooks.",
        steps: [
          { text: "Open Knowledge Base from the left nav." },
          { text: "Use the category filter or the search box to narrow the list." },
          { text: "Click any card to expand the contents inline. Each card shows the document sections in order." },
        ],
      },
    ],
  },
  {
    id: "reports",
    title: "Reports",
    icon: <BarChart />,
    color: "#03A9F4",
    topics: [
      {
        id: "browse-reports",
        title: "Browse cross-system reports",
        summary: "Workflow outputs + scan verdicts in one feed, cross-client.",
        steps: [
          { text: "Open Reports from the left nav." },
          { text: "The top section lists recent workflow run outputs (cross-mission)." },
          { text: "The next section lists scan verdicts you have access to." },
          { text: "Click any item to drill into its detail page (workflow report viewer / scan detail)." },
        ],
      },
    ],
  },
  {
    id: "admin",
    title: "Administration (admins only)",
    icon: <AdminPanelSettings />,
    color: "#F06292",
    topics: [
      {
        id: "grant-access",
        title: "Grant another user access",
        summary: "Three roles × three scopes — reader / editor / admin × global / client / project.",
        steps: [
          { text: "Open Settings → Administration." },
          { text: "Click 'Grant access'." },
          { text: "Enter the user's email (must be a valid Entra ID UPN). Pick the role and the scope (Global, specific Client, or specific Project)." },
          { text: "Click 'Save'. The user can now sign in and see whatever the role/scope allows." },
        ],
        warnings: [
          "Global admin is the highest level — it can grant any role at any scope. Use sparingly.",
        ],
      },
      {
        id: "sync-feeds",
        title: "Sync external feeds (EPSS / KEV / NVD / Frameworks)",
        summary: "Manual, on-demand sync of public CVE feeds + framework recompute. No automatic schedule.",
        steps: [
          { text: "Open Settings → Sync (admin only)." },
          { text: "Each tile shows the source URL, last-sync timestamp, and cached count for that feed." },
          { text: "Click 'Sync' on a single tile, or 'Sync all feeds' top-right to refresh everything sequentially." },
          { text: "RPS scoring picks up new data immediately — no need to re-scan." },
        ],
        tips: [
          "First-time visit shows 'no data synced yet' — click 'Run first sync' to populate. EPSS download is the largest (~10MB compressed); usually completes in under 30 seconds.",
          "Wiz / CrowdStrike Spotlight reachability is separate — it uses live API calls per finding (no batch sync needed) and only activates when WIZ_* or FALCON_* env vars are configured.",
        ],
      },
    ],
  },
];

function StepList({ steps }: { steps: Step[] }) {
  return (
    <Box component="ol" sx={{
      pl: 3, m: 0, mt: 1,
      "& li::marker": { color: "#4285F4", fontWeight: 700 },
    }}>
      {steps.map((s, i) => (
        <Box component="li" key={i} sx={{ color: "rgba(255,255,255,0.85)", fontSize: 13.5, lineHeight: 1.6, mb: 1 }}>
          <Box component="span">{s.text}</Box>
          {s.detail && (
            <Typography variant="caption" sx={{ display: "block", color: "rgba(255,255,255,0.55)", mt: 0.25 }}>
              {s.detail}
            </Typography>
          )}
        </Box>
      ))}
    </Box>
  );
}

function CalloutList({ items, kind }: { items?: string[]; kind: "tip" | "warning" }) {
  if (!items || items.length === 0) return null;
  const color = kind === "tip" ? "#34A853" : "#FBBC04";
  const Icon = kind === "tip" ? Lightbulb : Warning;
  const label = kind === "tip" ? "Tip" : "Heads up";
  return (
    <Box sx={{
      mt: 1.5, p: 1.5, borderRadius: 1,
      bgcolor: `${color}10`, border: `1px solid ${color}30`,
    }}>
      {items.map((s, i) => (
        <Box key={i} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: i === items.length - 1 ? 0 : 0.75 }}>
          <Icon sx={{ color, fontSize: 16, mt: 0.25, flexShrink: 0 }} />
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.85)", fontSize: 13, lineHeight: 1.5 }}>
            <Box component="span" sx={{ color, fontWeight: 700 }}>{label}: </Box>
            {s}
          </Typography>
        </Box>
      ))}
    </Box>
  );
}

function TopicBlock({ topic, color }: { topic: Topic; color: string }) {
  return (
    <Accordion
      disableGutters
      sx={{
        bgcolor: "rgba(255,255,255,0.02)",
        border: "1px solid rgba(255,255,255,0.06)",
        borderRadius: 1.5,
        "&:before": { display: "none" },
        "&.Mui-expanded": { borderColor: `${color}40` },
        mb: 0.75,
      }}
    >
      <AccordionSummary
        expandIcon={<ExpandMore sx={{ color: "rgba(255,255,255,0.5)" }} />}
        sx={{ "& .MuiAccordionSummary-content": { my: 1.25, gap: 0.5, flexDirection: "column" } }}
      >
        <Typography sx={{ color: "white", fontWeight: 600, fontSize: 14 }}>
          {topic.title}
        </Typography>
        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.55)", fontSize: 12 }}>
          {topic.summary}
        </Typography>
      </AccordionSummary>
      <AccordionDetails sx={{ borderTop: "1px solid rgba(255,255,255,0.05)", pt: 1.5 }}>
        <StepList steps={topic.steps} />
        <CalloutList items={topic.tips} kind="tip" />
        <CalloutList items={topic.warnings} kind="warning" />
      </AccordionDetails>
    </Accordion>
  );
}

export default function Help() {
  const [query, setQuery] = useState("");

  const groupsToShow = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return GROUPS;
    return GROUPS
      .map((g) => ({
        ...g,
        topics: g.topics.filter((t) =>
          t.title.toLowerCase().includes(q) ||
          t.summary.toLowerCase().includes(q) ||
          t.steps.some((s) => s.text.toLowerCase().includes(q))
        ),
      }))
      .filter((g) => g.topics.length > 0);
  }, [query]);

  const totalMatches = useMemo(
    () => groupsToShow.reduce((sum, g) => sum + g.topics.length, 0),
    [groupsToShow],
  );

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 3, flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
            <MenuBook sx={{ color: "#4285F4", fontSize: 28 }} />
            <Typography variant="h5" sx={{ color: "white", fontWeight: 700 }}>Platform Guide</Typography>
          </Box>
          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
            Step-by-step walkthroughs for every workflow on the platform
          </Typography>
        </Box>
        <TextField
          size="small"
          placeholder="Search the guide…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <Search sx={{ color: "rgba(255,255,255,0.4)", fontSize: 18 }} />
                </InputAdornment>
              ),
            },
          }}
          sx={{
            minWidth: 280,
            "& .MuiOutlinedInput-root": {
              color: "white",
              "& fieldset": { borderColor: "rgba(255,255,255,0.15)" },
              "&:hover fieldset": { borderColor: "rgba(255,255,255,0.3)" },
              "&.Mui-focused fieldset": { borderColor: "#4285F4" },
            },
          }}
        />
      </Box>

      {query && (
        <Alert
          severity={totalMatches > 0 ? "info" : "warning"}
          sx={{
            bgcolor: totalMatches > 0 ? "rgba(66,133,244,0.08)" : "rgba(251,188,4,0.08)",
            color: "white", mb: 2,
            border: totalMatches > 0 ? "1px solid rgba(66,133,244,0.3)" : "1px solid rgba(251,188,4,0.3)",
          }}
        >
          {totalMatches > 0
            ? `${totalMatches} topic${totalMatches === 1 ? "" : "s"} match "${query}"`
            : `No topics match "${query}". Try a different keyword.`}
        </Alert>
      )}

      {/* Topic-group quick links */}
      {!query && (
        <Card sx={{ bgcolor: "#1E1E1E", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
          <CardContent>
            <Typography variant="subtitle2" sx={{ color: "rgba(255,255,255,0.55)", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, mb: 1.5 }}>
              Jump to a topic
            </Typography>
            <Grid container spacing={1}>
              {GROUPS.map((g) => (
                <Grid key={g.id} size={{ xs: 12, sm: 6, md: 4, lg: 3 }}>
                  <Chip
                    icon={React.cloneElement(g.icon as any, { sx: { color: `${g.color} !important`, fontSize: 16 } })}
                    label={`${g.title} (${g.topics.length})`}
                    component="a"
                    href={`#group-${g.id}`}
                    clickable
                    sx={{
                      width: "100%", justifyContent: "flex-start",
                      bgcolor: `${g.color}10`, color: "white",
                      border: `1px solid ${g.color}30`,
                      fontWeight: 500, fontSize: 12.5, height: 32,
                      textDecoration: "none",
                      "&:hover": { bgcolor: `${g.color}20`, borderColor: `${g.color}60` },
                    }} />
                </Grid>
              ))}
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Topic groups */}
      {groupsToShow.map((g) => (
        <Card
          key={g.id}
          id={`group-${g.id}`}
          sx={{
            bgcolor: "#1E1E1E",
            border: `1px solid ${g.color}30`,
            borderRadius: 2, mb: 2,
            scrollMarginTop: 16,
          }}
        >
          <CardContent>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
              <Box sx={{
                width: 36, height: 36, borderRadius: 1.5, bgcolor: `${g.color}18`,
                display: "flex", alignItems: "center", justifyContent: "center", color: g.color,
              }}>
                {g.icon}
              </Box>
              <Box>
                <Typography sx={{ color: "white", fontWeight: 700, fontSize: 16 }}>{g.title}</Typography>
                <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                  {g.topics.length} topic{g.topics.length === 1 ? "" : "s"}
                </Typography>
              </Box>
            </Box>
            {g.topics.map((t) => (
              <TopicBlock key={t.id} topic={t} color={g.color} />
            ))}
          </CardContent>
        </Card>
      ))}

      {/* Footer pointers */}
      <Alert
        severity="info"
        icon={<SettingsSuggest />}
        sx={{
          bgcolor: "rgba(66,133,244,0.08)",
          color: "white",
          border: "1px solid rgba(66,133,244,0.3)",
          mt: 2,
        }}
      >
        <Typography sx={{ fontWeight: 600, mb: 0.25 }}>Need something deeper?</Typography>
        <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.75)" }}>
          Operational config (AI provider, threat-intel sync, RBAC grants) lives under <b>Settings</b>.
          API reference is at <code>/api/docs</code> on the backend host.
          File a feature request on the project's GitHub repository.
        </Typography>
      </Alert>
    </Box>
  );
}
