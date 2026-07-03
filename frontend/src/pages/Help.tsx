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
  SettingsSuggest, Search, Lightbulb, Warning, Radar,
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
        title: "Sign in to Aegis AI",
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
        summary: "The left navigation is split into a main workflow group and a Settings group. The active client is selected globally in the top toolbar.",
        steps: [
          { text: "Top toolbar (always visible): global client selector dropdown (left of the Analyst / Executive toggle). Changing it here updates every page simultaneously — no per-page client picker needed." },
          { text: "Main workflow group (top): Dashboard, Risk Overview, Clients, Assessments, Findings, Risk Register, Asset Inventory, Technologies, Frameworks, AI Buddies, Workflows, Knowledge Base, Reports." },
          { text: "Security section: Threat Register, Control Deficiencies, Remediation Tracker — each populated by running the matching AI agent." },
          { text: "Settings group (bottom): AI Settings, Sync (admin), Administration (admin), Help." },
          { text: "Connectors and Projects don't have top-level nav — they're tabs inside the Client Detail page." },
        ],
        tips: [
          "Select your client from the top toolbar before navigating to any page — all data views will automatically scope to that client.",
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
        title: "Add a workflow scanner (Nmap, Trivy, Gitleaks, Semgrep, CodeQL, ZAP, …)",
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
          "CodeQL supports two modes: 'Source repo' (clone + autodetect language + scan) and 'Upload binary' (multipart upload of a compiled artifact, then --build-mode=none scan). Pick the mode in the New Assessment dialog after choosing CodeQL.",
        ],
      },
      {
        id: "codeql-binary",
        title: "Scan a compiled binary with CodeQL (no source needed)",
        summary: "Upload a JAR / WAR / EAR / ZIP / tar.gz / DLL / EXE — CodeQL runs --build-mode=none against the bytecode.",
        steps: [
          { text: "Make sure you have a CodeQL connector for the client (the binary doesn't need a repo_url, but the connector is the access anchor)." },
          { text: "Open Assessments → New Assessment → SAST tab → click CodeQL." },
          { text: "Pick the connector. A 'SCAN MODE' chooser appears below — pick 'Upload binary'." },
          { text: "Click 'Choose binary archive' and pick a file. 500 MB hard cap." },
          { text: "Click 'Start Scan'. The platform creates the scan, uploads the file, and only then triggers the workflow — so the runner never starts before the binary lands." },
        ],
        tips: [
          "Java/Kotlin (.class/.jar) yields the best results. C# (.dll/.exe with IL) works but is less mature. Stripped native binaries (.so/.dylib without symbols) yield poor results — CodeQL was never designed for those.",
          "Uploads are stored on the App Service's /home/data/uploads mount, auto-deleted after 30 days. Admins can trigger an immediate purge via POST /admin/scan-binaries/cleanup.",
        ],
        warnings: [
          "Treat uploaded binaries as customer-sensitive — the App Service /home/ disk is in your Azure tenant but not encrypted at rest by default. For production tenants, consider moving the storage to Azure Blob with a customer-managed key.",
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
        summary: "Assessments is a tile grid — one tile per target across all clients you have access to.",
        steps: [
          { text: "Header shows 'Category · Client' (DAST · Acme, Network · TechCorp, etc.)." },
          { text: "Top-right status chip: pending → running → completed (or failed)." },
          { text: "Top-right corner has three icons (when applicable): trash (delete the entire scan + findings + verdict), replay (re-trigger the same scan as a new version), and a yellow history badge if previous versions exist." },
          { text: "Footer chips show severity counts and whether an AI verdict has been generated." },
          { text: "Click anywhere on the tile (not the icons) to drill into the Assessment detail." },
        ],
      },
      {
        id: "rescan",
        title: "Rescan / re-trigger a failed or completed scan",
        summary: "Replay icon on every tile. Keeps version history.",
        steps: [
          { text: "On the Assessments tile grid, hover over any tile — top-right shows trash + replay icons." },
          { text: "Click the replay icon to start a fresh run with the same connector + scan_type + framework as the original. Disabled while a previous run is still in progress." },
          { text: "The grid only shows the newest version per target. Older runs collapse into a History dialog." },
          { text: "If the same target has been scanned more than once, the newest tile shows a yellow history badge with the total run count. Click it to see every version with timestamp, findings count, duration, and status — click any row to open that version's detail." },
        ],
        tips: [
          "Rescan is the right move for a failed scan — easier than recreating the scan dialog. The original failure row stays as historical record.",
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
        summary: "FAIR-lite ALE estimates, 30-day breach probability, and risk-by-risk-domain breakdown.",
        steps: [
          { text: "Select a client from the top toolbar, then open Risk Overview from the left nav." },
          { text: "Top row: Total Exposure (ALE high), Net Exposure (after controls), Open Critical/High count, 30-Day Breach Probability." },
          { text: "Risk by Domain bar chart groups risks into stable categories (Identity, Cloud Security, AppSec, Network, …). AIDM and 'AWS Application Identity' alerts always map to the Identity domain." },
          { text: "Filter chips below the chart let you slice by SEVERITY, STATUS, and RISK DOMAIN." },
          { text: "Bottom table lists every risk with its ALE range, remediation status, and source link." },
        ],
        tips: [
          "Risk domains are derived automatically from the risk's category field — run the Risk Manager agent to populate them.",
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
    id: "registers",
    title: "Security Registers",
    icon: <Radar />,
    color: "#00ACC1",
    topics: [
      {
        id: "threat-register",
        title: "Threat Register — MITRE ATT&CK–mapped threats",
        summary: "Populated by the Threat Intel agent. Each entry maps to a MITRE technique, tactic, and confidence level.",
        steps: [
          { text: "Select your client in the top toolbar." },
          { text: "Open Threat Register from the left nav (Security section)." },
          { text: "Filter by Status (active / mitigated / false positive) or Severity." },
          { text: "Each row shows the severity chip, finding ID, title, MITRE technique ID + name, tactic, and confidence." },
          { text: "Use the ⋮ menu on any row to update its status (active → mitigated or false positive)." },
          { text: "To populate: run the Threat Intel agent from AI Buddies against a completed scan." },
        ],
        tips: [
          "Entries are generated per-finding — one scan can produce multiple threat entries if different techniques are detected.",
          "Confidence chips are color-coded: green = high, yellow = medium, red = low.",
        ],
      },
      {
        id: "control-deficiencies",
        title: "Control Deficiencies — compliance gap register",
        summary: "Populated by the Compliance Monitor agent. Auditor-ready register of framework control gaps.",
        steps: [
          { text: "Select your client in the top toolbar." },
          { text: "Open Control Deficiencies from the left nav (Security section)." },
          { text: "Filter by Status, Severity, or Framework (NIST CSF 2.0, ISO 27001, GDPR, PCI DSS, HIPAA, …)." },
          { text: "KPI strip shows total, open, in-remediation, closed counts plus an Avg Audit Readiness progress bar." },
          { text: "Each row shows the control ID (monospace), gap description, framework chip, regulatory reference, and status." },
          { text: "Use the status icon to move a deficiency from open → in_remediation → closed." },
          { text: "To populate: run the Compliance Monitor agent from AI Buddies against a completed scan." },
        ],
      },
      {
        id: "remediation-tracker",
        title: "Remediation Tracker — priority-banded action items",
        summary: "Populated by the Remediation agent. Actions grouped into Quick Win / Near Term / Medium Term / Strategic bands.",
        steps: [
          { text: "Select your client in the top toolbar." },
          { text: "Open Remediation (Tracker) from the left nav (Security section)." },
          { text: "Toggle between band-grouped view and flat table using the Assignment icon top-right." },
          { text: "Filter by Status (open / in progress / completed / cancelled) or Band." },
          { text: "Completion % progress bar in the KPI strip shows overall closure rate." },
          { text: "Use the ⋮ menu on any row to update status. Completed actions auto-stamp a completion date." },
          { text: "To populate: run the Remediation agent from AI Buddies against a completed scan." },
        ],
        tips: [
          "Bands are fixed: Quick Win (0-30d), Near Term (30-90d), Medium Term (90-180d), Strategic (180d+). The Remediation agent assigns the band based on effort and impact estimates.",
        ],
      },
    ],
  },
  {
    id: "ai-agents",
    title: "AI Buddies",
    icon: <SmartToy />,
    color: "#9C27B0",
    topics: [
      {
        id: "run-agent",
        title: "Run an AI agent against a scan",
        summary: "Agents enrich a scan with risk scoring, framework mapping, remediation, threat intel — each writing to its own register.",
        steps: [
          { text: "Select your client in the top toolbar." },
          { text: "Open the AI Buddies tab from the left nav." },
          { text: "Pick the Scan to analyse." },
          { text: "Choose which agents to run (Risk Manager, Vulnerability Analysis, Framework Mapping, Threat Intel, Remediation, Compliance) and click 'Run agents'." },
          { text: "Agents run in parallel. Each writes to its dedicated register:", detail: "Risk Manager / Orchestrator → Risk Register | Threat Intel → Threat Register | Compliance Monitor → Control Deficiencies | Remediation → Remediation Tracker" },
          { text: "Raw narrative output also appears on the Scan Detail per-agent tabs (structured: Executive Summary, Findings, Recommendations, Maturity Indicators)." },
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
        title: "Browse the AI Buddies catalog",
        summary: "Beyond the operational agents, ~43 advisory agents covering SOC design, GRC, IR, zero trust, IGA, threat intel, and more.",
        steps: [
          { text: "AI Buddies → Catalog tab." },
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
        id: "client-lifecycle",
        title: "Delete, restore, or permanently remove a client",
        summary: "Clients use a 30-day soft-delete — data is preserved and restorable until permanently deleted.",
        steps: [
          { text: "To soft-delete: open Clients, hover any client card, click the trash icon, then confirm in the dialog. The client moves to trash — its findings, scans, risks, and registers are hidden but not removed." },
          { text: "To restore: open Settings → Deleted Clients tab (admin only). Find the client and click the restore icon. All data comes back immediately." },
          { text: "To permanently delete: in the Deleted Clients tab, click the permanent delete icon. A warning dialog confirms the action — this is irreversible and removes ALL related data (scans, findings, risks, threat entries, control deficiencies, remediation actions, agent runs, assessments, etc.)." },
          { text: "Clients automatically purge after 30 days — the Days Remaining bar turns red when fewer than 3 days remain and yellow under 10 days." },
        ],
        tips: [
          "Soft-deleted clients are completely invisible: they don't appear in any selector, dashboard counts, or activity feeds until restored.",
          "The Deleted Clients tab also has a 'Purge expired' button to immediately hard-delete all clients past the 30-day window.",
        ],
        warnings: [
          "Permanent delete is truly irreversible — all child data is cascade-deleted from the database. There is no undo.",
        ],
      },
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
      {
        id: "binary-cleanup",
        title: "Manage uploaded scan binaries",
        summary: "CodeQL binary uploads live on the App Service disk. A daily job purges binaries older than 30 days, or you can trigger it manually.",
        steps: [
          { text: "Binaries land at /home/data/uploads/<scan_id>/<filename> on the App Service." },
          { text: "Background cleanup runs every 24h (kicked off ~60s after each boot)." },
          { text: "For an on-demand purge: POST /api/v1/admin/scan-binaries/cleanup?days=30 (or any retention you want). Returns {scanned, removed, freed_bytes}." },
        ],
        warnings: [
          "Deleting a scan from the Assessments tile does NOT delete its binary — the cleanup job handles that. If you need to wipe a binary immediately, delete its directory via Kudu console or call the cleanup endpoint with days=0.",
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
        <Box component="li" key={i} sx={{ color: "text.secondary", fontSize: 13.5, lineHeight: 1.6, mb: 1 }}>
          <Box component="span">{s.text}</Box>
          {s.detail && (
            <Typography variant="caption" sx={{ display: "block", color: "text.secondary", mt: 0.25 }}>
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
          <Typography variant="body2" sx={{ color: "text.secondary", fontSize: 13, lineHeight: 1.5 }}>
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
        expandIcon={<ExpandMore sx={{ color: "text.secondary" }} />}
        sx={{ "& .MuiAccordionSummary-content": { my: 1.25, gap: 0.5, flexDirection: "column" } }}
      >
        <Typography sx={{ color: "text.primary", fontWeight: 600, fontSize: 14 }}>
          {topic.title}
        </Typography>
        <Typography variant="caption" sx={{ color: "text.secondary", fontSize: 12 }}>
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
            <Typography variant="h5" sx={{ color: "text.primary", fontWeight: 700 }}>Platform Guide</Typography>
          </Box>
          <Typography variant="body2" sx={{ color: "text.secondary" }}>
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
                  <Search sx={{ color: "text.secondary", fontSize: 18 }} />
                </InputAdornment>
              ),
            },
          }}
          sx={{
            minWidth: 280,
            "& .MuiOutlinedInput-root": {
              color: "text.primary",
              "& fieldset": { borderColor: "divider" },
              "&:hover fieldset": { borderColor: "divider" },
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
            color: "text.primary", mb: 2,
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
        <Card sx={{ bgcolor: "background.paper", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 2, mb: 2 }}>
          <CardContent>
            <Typography variant="subtitle2" sx={{ color: "text.secondary", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, mb: 1.5 }}>
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
                      bgcolor: `${g.color}10`, color: "text.primary",
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
            bgcolor: "background.paper",
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
                <Typography sx={{ color: "text.primary", fontWeight: 700, fontSize: 16 }}>{g.title}</Typography>
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
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
          color: "text.primary",
          border: "1px solid rgba(66,133,244,0.3)",
          mt: 2,
        }}
      >
        <Typography sx={{ fontWeight: 600, mb: 0.25 }}>Need something deeper?</Typography>
        <Typography variant="caption" sx={{ color: "text.secondary" }}>
          Operational config (AI provider, threat-intel sync, RBAC grants) lives under <b>Settings</b>.
          API reference is at <code>/api/docs</code> on the backend host.
          File a feature request on the project's GitHub repository.
        </Typography>
      </Alert>
    </Box>
  );
}
