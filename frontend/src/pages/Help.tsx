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
        summary: "Aegis AI uses Microsoft Entra ID (Azure AD) for authentication — your work Microsoft account is your only credential. No separate passwords are created or stored anywhere on the platform.",
        steps: [
          { text: "Open the platform URL. The landing page is public. Click 'Sign in' or navigate to any protected route — you'll be redirected to Microsoft Entra ID automatically." },
          { text: "Authenticate with your work Microsoft account. Complete MFA if your organisation requires it." },
          { text: "On first sign-in you may see a consent screen asking to 'Sign in and read your profile'. Click Accept — the platform reads your name and email to create your session token." },
          { text: "If you see 'Access required': your account authenticated fine but hasn't been granted a platform role yet. Ask any global admin to open Administration → Grant access and assign you a role.", detail: "You can authenticate without a role, but every API call returns 403 until a role is assigned. The sign-in itself works regardless." },
          { text: "Once in, the top toolbar shows your name. Select a client from the global client selector before navigating to any data page." },
        ],
        tips: [
          "Why Entra ID? No password resets, no credential sprawl, and every sign-in is covered by your organisation's Conditional Access policies (MFA, device compliance, location). Your JWT is validated on every API call — losing your Entra account immediately revokes platform access with no stale sessions.",
          "If you see 'interaction_in_progress' on the login screen: a prior sign-in attempt didn't complete cleanly. Click 'Clear session and retry' — this resets MSAL's sessionStorage and restarts the auth flow.",
        ],
        warnings: [
          "If sign-in loops without landing on the dashboard: your browser may be blocking third-party cookies. MSAL uses them for silent token refresh. Safari ITP and Firefox strict mode can trigger this — use a different browser or relax the cookie setting.",
        ],
      },
      {
        id: "first-client",
        title: "Create your first client",
        summary: "Clients are the top-level multi-tenant containers in Aegis AI. Every piece of security data — connectors, scans, findings, risks, threat entries, remediation actions — lives under a client and is invisible across client boundaries.",
        steps: [
          { text: "Why create a client first? You cannot run a scan, add a connector, or view findings without one. Everything in the platform is scoped to a client." },
          { text: "Open the Clients tab from the left navigation." },
          { text: "Click 'Add client'. Fill in: Name (display label), Slug (URL-safe unique ID, auto-generated from name and editable), Industry, and Primary contact email." },
          { text: "Click 'Create'. You land on the new Client Detail page — the hub for that client, with tabs for Overview, Projects, Connectors, Scans, and more." },
          { text: "Add connectors under the Connectors tab next. Connectors define where scans run and what credentials to use." },
          { text: "Select the new client in the top toolbar's global selector. This scopes all pages — Dashboard, Risk Overview, Findings, all registers — to this client." },
        ],
        tips: [
          "Recommended pattern: one client per customer or business unit. MSPs typically create one client per managed customer; single-org teams often create one per environment (prod vs. staging).",
          "Soft-delete is available — deleting a client preserves all data for 30 days and is fully restorable by an admin. Permanent delete must be explicitly triggered separately.",
        ],
        warnings: [
          "Slug must be unique across all clients and cannot be changed after creation. Choose something stable — it becomes part of internal database references.",
        ],
      },
      {
        id: "nav-tour",
        title: "Where to find things in the nav",
        summary: "The left navigation is divided into workflow sections. The global client selector in the top toolbar controls which client's data every page shows — changing it there updates all pages simultaneously.",
        steps: [
          { text: "Top toolbar (always visible): global client selector dropdown. Change it to instantly re-scope every page. All pages use the ClientContext hook — if a page looks empty, check that the right client is selected here first.", detail: "Do NOT read localStorage directly or add per-page client selectors. The global selector in AppLayout is the single source of truth." },
          { text: "Dashboard — aggregate KPIs across all accessible clients: open findings by severity, recent scan activity, risk exposure, agent run counts." },
          { text: "Risk Overview — executive-level risk dashboard for the active client. FAIR-lite ALE estimates, heat map, and domain breakdown. Requires the Risk Manager agent to have run first." },
          { text: "Assessments — run and review scans. One tile per scan target. Connects to connectors, findings, and AI verdicts." },
          { text: "Findings — raw findings table across all scans for the active client. Filter/search, per-row status updates, and bulk cleanup." },
          { text: "Risk Register — FAIR-scored risks + AI agent analysis narratives. The direct output of the Risk Manager agent.", detail: "Risk Register (row-level list) ≠ Risk Overview (aggregate dashboard). They're fed by the same data but serve different audiences." },
          { text: "Security section: Threat Register (Threat Intel agent output), Control Deficiencies (Compliance Monitor output), Remediation Tracker (Remediation agent output). Each is populated by running its matching agent from AI Buddies." },
          { text: "Frameworks — view seeded framework controls (NIST CSF, CIS v8, GDPR, ISO 27001, PCI DSS) and build Custom Standards by picking controls from any existing framework." },
          { text: "AI Buddies — run agents against completed scans. Also browse the full catalog of 60+ advisory agents." },
          { text: "Settings group (bottom): AI Settings (LLM provider config), Sync (feed sync — admin), Administration (RBAC — admin), Help." },
        ],
        tips: [
          "Habit to build: select your client in the top toolbar before navigating anywhere. Every page reads the global selection — no data shows until a client is active.",
          "Connectors and Projects don't have standalone nav entries. They're tabs inside the Client Detail page: open Clients → click a client card.",
          "The Analyst / Executive toggle in the top toolbar switches the Dashboard between a detailed operational view and a summary executive view.",
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
        summary: "Cloud connectors query your cloud provider's read-only APIs to detect misconfigurations, exposed resources, and identity risks — no agent installation, no network probing, no changes to your infrastructure.",
        steps: [
          { text: "What cloud connectors do: they call cloud provider control-plane APIs (Azure Resource Graph, AWS Config, GCP Security Command Center, Entra ID Microsoft Graph) and translate the results into findings using Aegis's rule library.", detail: "This is fundamentally different from workflow scanners like Nmap or ZAP that actively probe targets. Cloud connectors read configuration state — they never touch your data plane." },
          { text: "Open the Client whose environment you want to connect. Switch to the Connectors tab on the Client Detail page." },
          { text: "Click 'Add connector'. Pick the cloud type: Azure Security, AWS Security, GCP Security, Entra ID, Container Security, On-Premises, etc." },
          { text: "Paste credentials. Azure: Tenant ID + Client ID + Client Secret + Subscription ID of a service principal. AWS: Access Key ID + Secret Access Key. GCP: service account JSON. Entra ID: same as Azure but scoped to Graph API.", detail: "Credentials are encrypted with the platform's Fernet key before being stored. They're decrypted at scan time only and never returned to the UI after saving." },
          { text: "Click 'Test connection'. The platform makes a low-privilege API call (e.g. list resource groups) to confirm reachability and credential validity before saving." },
          { text: "Click 'Save'. Run a scan from Assessments to pull findings from this cloud account. Asset inventory syncs automatically on the first successful scan." },
        ],
        tips: [
          "What you get: exposed storage blobs, overprivileged IAM roles, missing MFA, unpatched resources, open firewall rules, unencrypted disks, disabled audit logs — all mapped to framework controls automatically.",
          "Minimum permissions needed: Azure → Security Reader + Reader on the subscription. AWS → SecurityAudit managed policy. GCP → Security Reviewer role. All read-only — the connector never writes to your cloud.",
          "For Entra ID: the app registration needs 'AuditLog.Read.All', 'Directory.Read.All', and 'IdentityRiskEvent.Read.All' Microsoft Graph application permissions (not delegated).",
        ],
        warnings: [
          "If 'Test connection' fails with a permissions error: Azure — check the subscription-level role assignment, not just resource group. AWS — check for SCPs blocking the SecurityAudit policy. GCP — confirm the Security Command Center API is enabled in the project.",
          "If the Fernet key is rotated without re-encrypting existing connector records, decryption fails at scan time and scans error. Keep the key stable, or re-save connectors after key rotation.",
        ],
      },
      {
        id: "scanner-connector",
        title: "Add a workflow scanner (Nmap, Trivy, Gitleaks, Semgrep, CodeQL, ZAP…)",
        summary: "Workflow scanners run as GitHub Actions jobs. The platform dispatches the job, the workflow runs the tool in a cloud runner, and findings are posted back authenticated by a per-scan HMAC token. Nothing runs on your infrastructure.",
        steps: [
          { text: "What each scanner does:", detail: "ZAP (DAST): OWASP Top 10 web vulnerabilities against a live URL. Semgrep / CodeQL / SonarQube (SAST): static analysis of source code. Nmap / OpenVAS (Network): port scanning and service enumeration. Trivy / OWASP DC (SCA): CVEs in OS packages and language dependencies. Gitleaks / TruffleHog (Secrets): secrets committed to git history including rotated ones." },
          { text: "On the Client Detail → Connectors tab, click 'Add connector' and pick the scanner type." },
          { text: "Fill in the target field — format depends on scanner:", detail: "SAST/Secrets: Git repo URL. Network: host, IP, or CIDR. Container (Trivy): Docker image ref or repo URL. Web (ZAP): target HTTP/HTTPS URL." },
          { text: "For private repos, paste a Git PAT or deploy key. It's stored encrypted and injected into the clone URL at scan time — never logged in Actions inputs." },
          { text: "Save the connector. Start a scan from Assessments → New scan → pick this connector." },
          { text: "What happens: Aegis creates a PENDING scan, generates a per-scan HMAC token, and calls GitHub Actions workflow_dispatch. The runner clones the target, runs the tool, parses output, and POSTs findings to /api/v1/scans/ingest/ authenticated with the HMAC token. On success, the scan flips to COMPLETED and the AI verdict is queued." },
        ],
        tips: [
          "If GitHub Actions isn't triggering: (1) confirm AEGIS_API_URL is set as a GitHub Actions secret in the NexGenCyberAI repo, (2) the workflow .yml for the scanner exists in the repo, (3) the dispatch token has 'actions: write' permission.",
          "Findings are automatically control-mapped when you tag a framework at scan launch time. The control_id and control_mappings fields on each finding are populated by the workflow.",
        ],
        warnings: [
          "Nmap and OpenVAS scan network hosts. Only target hosts you own or have explicit written permission to scan — port scanning can trigger firewall alerts and may violate your cloud provider's Terms of Service if run against third-party infrastructure.",
          "If findings don't appear after a green Actions run: the HMAC token may have expired (they're single-use per scan), or the backend API URL is unreachable from the GitHub runner. Check the POST step in Actions logs.",
        ],
      },
      {
        id: "codeql-binary",
        title: "Scan a compiled binary with CodeQL (no source needed)",
        summary: "Upload a JAR / WAR / EAR / ZIP / tar.gz / DLL / EXE — CodeQL analyses the bytecode with --build-mode=none. Useful for vendor binaries or compiled artifacts where you have no source access.",
        steps: [
          { text: "Why binary mode: CodeQL decodes compiled Java (.class/.jar) and C# IL (.dll/.exe) into its intermediate representation and runs the same query suites as source mode. This catches SQL injection, XSS, path traversal, and other dataflow vulnerabilities in closed-source code." },
          { text: "Ensure you have a CodeQL connector for the client (the connector is the access anchor, even in binary mode)." },
          { text: "Open Assessments → New Assessment → SAST tab → click CodeQL. Pick the connector. A 'SCAN MODE' chooser appears — select 'Upload binary'." },
          { text: "Click 'Choose binary archive' and select your file. 500 MB hard cap.", detail: "If your artifact exceeds 500 MB, ZIP only the JARs containing application code — exclude third-party libraries to reduce size." },
          { text: "Click 'Start Scan'. The platform: (1) creates a PENDING scan record, (2) uploads the binary to App Service /home/data/uploads/<scan_id>/, (3) dispatches the CodeQL GitHub Actions workflow only after upload confirms success.", detail: "The two-step flow avoids the race condition where the runner starts before the binary lands — a common failure mode in naive dispatch implementations." },
          { text: "Monitor the tile: PENDING → RUNNING → COMPLETED. Findings appear in the Findings tab. AI verdict is auto-queued." },
        ],
        tips: [
          "Best results: Java/Kotlin bytecode (.jar with .class files). C# IL (.dll/.exe) works but has smaller query coverage. Stripped native binaries (.so/.dylib without symbols) yield almost nothing — CodeQL was designed for bytecode and source, not machine code.",
          "The CodeQL Standard Security suite runs ~150 queries covering OWASP Top 10, CWE Top 25, and common injection sinks. For Java, the highest-signal queries are sql-injection, xss, path-injection, and unsafe-deserialization.",
          "Uploaded binaries are auto-deleted after 30 days by a background cleanup job. Admins can trigger immediate cleanup via POST /api/v1/admin/scan-binaries/cleanup.",
        ],
        warnings: [
          "Treat uploaded binaries as sensitive — App Service /home/ disk is in your Azure tenant but not encrypted at rest by default. For regulated environments, consider moving uploads to Azure Blob with a customer-managed key.",
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
        summary: "Each scan is an Assessment — a discrete security check of one target by one scanner. Scans produce raw findings, an AI verdict, and optionally framework control mappings. They're the foundation everything else builds on.",
        steps: [
          { text: "What a scan does end-to-end: the platform creates a PENDING scan record, dispatches the job (GitHub Actions for most scanners; local BackgroundTask for AI Code Review), the tool runs, findings are ingested and scored with RPS (Risk Priority Score), and the AI verdict is auto-generated.", detail: "RPS scoring uses: CVSS base score (NVD), exploit probability (EPSS), active exploitation status (CISA KEV), and optionally live cloud context from Wiz / CrowdStrike Spotlight if those integrations are configured." },
          { text: "Open Assessments from the left nav. Click 'New scan'." },
          { text: "Select the Client and the Connector. The connector type determines which scan options appear." },
          { text: "Choose scan type: configuration (posture checks), vulnerability (CVE/weakness detection), compliance (framework-mapped), or full (all). For most workflow scanners, 'vulnerability' is the right choice." },
          { text: "Optionally tag a Framework — NIST CSF 2.0, NIST 800-53, CIS v8, OWASP, GDPR, ISO 27001, PCI DSS, etc. Findings will be control-mapped using control_id and control_mappings fields. The AI verdict also references the framework when discussing gaps." },
          { text: "Click 'Start'. The tile appears in PENDING state, transitions to RUNNING when the workflow picks it up, then COMPLETED (or FAILED) when done." },
        ],
        tips: [
          "What you get: raw findings (severity, CVE, CVSS, EPSS, resource, control mapping), an AI verdict (executive summary + capability gaps + attack paths + vendor scorecard), and per-agent analysis tabs. All of this feeds Risk Overview and the registers when agents are run.",
          "AI Code Review is the only scanner that runs locally (BackgroundTask, not GitHub Actions). It supports Git repo URL (cloned at scan time) or a ZIP archive upload. Results include function-level findings with exact file paths and line numbers.",
        ],
        warnings: [
          "If a scan stays in RUNNING for more than 30 minutes: the GitHub Actions job may have hit the 60-minute timeout. Check Actions → the workflow run for error output. Common causes: target unreachable (ZAP/Nmap), wrong PAT for private repo, or CodeQL out of memory on a very large codebase.",
        ],
      },
      {
        id: "tile-view",
        title: "Understanding the Assessment tile view",
        summary: "The Assessments page is a tile grid — one tile per scanner target per version. Each tile surfaces status, severity counts, and actions without needing to open the detail page.",
        steps: [
          { text: "Tile header: 'Category · Client' (e.g. DAST · Acme Corp, Network · TechCorp). Category comes from the connector type." },
          { text: "Status chip (top-right of tile): pending → running → completed → failed. 'Failed' means the GitHub Actions workflow errored or findings ingestion failed — check Actions logs." },
          { text: "Action icons (visible on hover, top-right): trash icon (deletes scan + all its findings + verdict — irreversible), replay icon (re-triggers as a new version), yellow history badge with count (opens version history dialog)." },
          { text: "Severity chips (tile footer): Critical / High / Medium / Low / Info counts. These populate as findings are ingested — they update in near-real-time during a running scan." },
          { text: "AI verdict chip: green 'Verdict' chip when the AI verdict has been generated; absent when pending. Click the tile to generate one manually from the Verdict tab if it didn't auto-trigger." },
          { text: "Click anywhere on the tile body (not the icons) to open the full Assessment detail page." },
        ],
        tips: [
          "The grid shows only the most recent version per target. If you've rescanned, the tile shows a yellow badge with the total run count. Click it to browse all historical runs with full timelines.",
          "Use the filter chips above the grid (Client, Connector type, Status) to narrow when managing many clients or many scan types simultaneously.",
        ],
      },
      {
        id: "rescan",
        title: "Rescan / re-trigger a failed or completed scan",
        summary: "The replay icon fires a new scan run with identical configuration — same connector, scan type, and framework. Prior runs are preserved as version history. Nothing is overwritten.",
        steps: [
          { text: "Why rescan: security posture changes constantly. Rescanning after a remediation confirms the fix. Rescanning a failed run retries without recreating the scan dialog." },
          { text: "Hover over any tile — the replay icon appears top-right alongside the trash icon. Click it. A confirmation dialog shows the config being reused. Confirm to dispatch." },
          { text: "The new run becomes the 'current' tile. The previous run archives to version history automatically." },
          { text: "The replay button is disabled while a run for the same connector is still in RUNNING state — two parallel scans against the same target are not queued." },
          { text: "To compare runs: click the yellow history badge. The history dialog lists all versions with timestamp, findings count, severity breakdown, duration, and status. Click any row to open that version's detail — fully readable, nothing deleted." },
        ],
        tips: [
          "Rescan is the right action for a failed scan — it retries without losing the failure record. Don't delete the failed tile; it's useful for diagnosing recurring infrastructure issues.",
          "For regularly scheduled rescans, use Workflows (Automations) instead — set a cron schedule rather than manually replaying.",
        ],
      },
      {
        id: "scan-detail",
        title: "Reading the Assessment detail (verdict + findings + agent tabs)",
        summary: "The Assessment detail page is the full picture of one scan run: AI verdict narrative, raw findings table, and per-agent analysis output. Everything needed for a security review or audit report is here.",
        steps: [
          { text: "Open the detail by clicking anywhere on the tile body (not the icons)." },
          { text: "Verdict tab: one-line Verdict headline → What We Found → Why It Matters → Executive Summary → Capability Gaps → Signal Coverage → Attack Paths → Vendor Scorecard → RPS factor breakdown → Data Completeness → Automation Opportunities.", detail: "Vendor Scorecard and RPS factor breakdown show which data sources (NVD, EPSS, KEV, Wiz, CrowdStrike) contributed to the risk score and which were missing. 'Unknown' factors are dropped from scoring — they don't penalise findings unfairly." },
          { text: "Findings tab: every individual finding with severity chip, title, CVE ID, CVSS score, RPS score, resource identifier, and control mapping. Per-row trash icon deletes a single finding.", detail: "Click any finding row to expand the detail panel: full description, remediation steps, evidence JSON, control_mappings breakdown, EPSS probability, and KEV status. Use this when briefing developers on exactly what to fix and why." },
          { text: "Per-agent tabs (one tab per agent that ran): structured AI narrative — Executive Summary, Findings, Recommendations, Maturity Indicators. If an agent tab shows 'No analysis yet', trigger it from AI Buddies → pick this scan." },
          { text: "Print / PDF button (top-right): expands every tab into a single continuous document and triggers the browser print dialog. Pick 'Save as PDF' for a full audit-ready report." },
        ],
        tips: [
          "RPS (Risk Priority Score) = CVSS base + EPSS exploit probability + KEV active exploitation + Wiz cloud context + CrowdStrike detections. Higher RPS = prioritise first. A low-CVSS finding in KEV often outranks a high-CVSS theoretical vulnerability.",
          "If the AI verdict didn't auto-generate: click the Verdict tab and hit 'Generate verdict'. This happens when the AI provider wasn't configured at scan time, or if the scan completed very quickly before the verdict queue fired.",
          "The finding detail panel's control_mappings JSON shows every framework control this finding affects. Use this to answer 'which controls does this vulnerability breach?' during a compliance audit.",
        ],
      },
      {
        id: "delete-blank-findings",
        title: "Tidy up empty or failed findings",
        summary: "Some scanners return partial rows when a rule fires but produces no matching output. These blank findings inflate counts without adding value. The Findings page has a one-click cleanup.",
        steps: [
          { text: "Why blank findings happen: scanner workflows can produce SARIF or JSON with empty entries if a rule triggers on a file with no match text, or if a scan partially failed mid-run and posted placeholder rows." },
          { text: "Open Findings from the left nav. Ensure the correct client is selected in the top toolbar." },
          { text: "Click 'Delete blank findings' (top-right chip row). This removes all findings where title, description, and resource are all null or empty for the active client.", detail: "Scoped to the active client only — cannot accidentally affect other clients." },
          { text: "For targeted cleanup: filter by scanner type or severity, then use per-row trash icons for individual deletions." },
          { text: "To delete everything from a scan: go to Assessments, hover the tile, click the trash icon. This deletes the scan record AND all its associated findings." },
        ],
        tips: [
          "Blank findings don't affect RPS scoring (no CVE/CVSS to score) but they inflate KPI counts on the Dashboard. Running cleanup before generating the AI verdict gives the LLM cleaner, denser input.",
          "After AI Code Review on large codebases, you may get many 'info' severity informational findings. Filter severity=info and review before bulk-deleting — some represent genuine low-risk issues worth tracking.",
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
        summary: "Risk Overview translates raw scan findings into financial risk estimates using FAIR-lite ALE (Annual Loss Expectancy). It's the board-level view of your client's security posture — not individual CVEs, but aggregated business risk by domain with dollar-range estimates.",
        steps: [
          { text: "What FAIR-lite ALE means: each risk is scored with a likelihood (probability of a loss event in a year) and impact (estimated financial loss range). ALE = likelihood × impact. Total Exposure = sum of all open risk ALEs.", detail: "Aegis derives likelihood from CVSS + EPSS + KEV data. Impact is mapped to a loss magnitude band based on the risk category and available threat intel. No full FAIR interviews needed." },
          { text: "Select a client from the top toolbar, then open Risk Overview from the left nav." },
          { text: "Top KPI strip: Total Exposure (ALE high estimate), Net Exposure (after applied controls), Open Critical/High count, 30-Day Breach Probability.", detail: "30-Day Breach Probability is derived from EPSS scores of open critical findings — the probability that at least one critical finding is actively exploited in the next 30 days. Keep EPSS synced weekly for accuracy." },
          { text: "Risk by Domain bar chart: groups risks into stable categories — Identity, Cloud Security, Application Security, Network, Data Protection, Compliance. Each bar shows ALE for that domain. Answers 'where is our biggest financial exposure?'", detail: "Domain mapping is deterministic: AIDM alerts and 'AWS Application Identity' findings always map to Identity; container findings to Cloud Security; web app findings to Application Security. Logic lives in _normalize_domain() in risk_portfolio.py." },
          { text: "Heat map: likelihood vs. impact quadrant. Risks in the top-right (high likelihood + high impact) are immediate priorities. Risks in the bottom-left are monitor-only." },
          { text: "Filter chips: SEVERITY, STATUS, RISK DOMAIN. Slice the bottom risk table to focus on a specific conversation — e.g. 'show only Identity risks still open'." },
          { text: "Bottom risk table: every risk with ALE range, domain, likelihood, impact, source scan link, and current status. Click a row to update status (open → mitigated → accepted → closed)." },
        ],
        tips: [
          "Net Exposure vs Total Exposure: Total is the raw ALE sum. Net subtracts ALE of risks marked 'mitigated' or 'closed'. As your team remediates, watch Net Exposure trend down — that's the measurable ROI of the security programme.",
          "Risk Overview is read-only — you don't enter data here. The data comes from scans → Risk Manager agent. If the page is empty, see 'How Risk Overview gets populated' in this guide.",
        ],
      },
      {
        id: "how-risk-overview-is-populated",
        title: "How Risk Overview gets populated",
        summary: "Risk Overview is built automatically — you don't manually construct it. Scans produce findings; the Risk Manager agent scores them into risks; Risk Overview aggregates those risks. Here's the exact workflow.",
        steps: [
          {
            text: "Step 1 — Run scans first.",
            detail: "Any scanner works: ZAP, Nmap, Semgrep, Trivy, AI Code Review, cloud connectors, etc. Findings from scans are the raw material. No findings = no risks = empty Risk Overview.",
          },
          {
            text: "Step 2 — Run the Risk Manager AI agent.",
            detail: "Go to AI Buddies → select the scan → choose Risk Manager → Run. It applies the FAIR-lite ALE model to each finding, producing structured risk entries with likelihood × impact scoring. These land in the Risk Register and immediately appear in Risk Overview.",
          },
          {
            text: "Step 3 (recommended) — Run the Orchestrator agent instead for full coverage.",
            detail: "The Orchestrator runs all agents together — Risk Manager + Threat Intel + Compliance Monitor + Remediation — in one go. It populates all 4 registers simultaneously: Risk Register (for Risk Overview), Threat Register, Control Deficiencies, and Remediation Tracker.",
          },
          {
            text: "Step 4 — Risk Overview updates automatically.",
            detail: "No manual refresh needed. Once the Risk Manager or Orchestrator writes risk entries, navigate to Risk Overview and the data is there — domain breakdown, ALE chart, heat map, and top risks table are all live.",
          },
        ],
        tips: [
          "Full workflow: Scan → Findings → Risk Agent → Risk Register → Risk Overview. If Risk Overview looks empty: (1) is the right client selected? (2) has at least one scan completed? (3) has the Risk Manager or Orchestrator agent been run against those findings?",
          "Risk Overview is only as good as your scans. Running multiple scanner types (network + SAST + cloud connector) gives the ALE model richer signal. A single Nmap scan shows Network risk but misses Application Security and Identity risks entirely.",
        ],
        warnings: [
          "If findings exist but no risks appear: the Risk Manager agent may have run without a configured AI provider, producing limited structured output. Configure an AI provider in AI Settings, then re-run the Risk Manager agent against the same scan.",
        ],
      },
      {
        id: "risk-register",
        title: "Risk Register — prioritised risks + AI analysis",
        summary: "The Risk Register is the row-level list of all FAIR-scored risks for the active client. Each entry has a likelihood/impact score, ALE estimate, status lifecycle, and a link to the source scan. AI agent narratives are attached as collapsible tiles below.",
        steps: [
          { text: "Risk Register vs Risk Overview: Register is the detailed row-level list (one row per risk). Overview is the aggregate dashboard (domains, heat map, total ALE). Same underlying data, different views for different audiences." },
          { text: "Open Risk Register from the left nav. Ensure the correct client is selected in the top toolbar." },
          { text: "Filter with slicer chips: SEVERITY (Critical / High / Medium / Low), STATUS (open / mitigated / accepted / closed), CATEGORY (domain label)." },
          { text: "Update a risk's status: click the status chip in the row directly, or expand the row and use the status dropdown. Changes are immediate — no save button needed.", detail: "Use 'Accepted' for risks you've formally decided to tolerate (e.g. legacy system, remediation cost exceeds impact). This keeps them visible without inflating the 'open' count." },
          { text: "Scroll below the risk table to AI Agent Risk Analysis: one collapsible tile per agent type that ran (Risk Manager, Threat Intel, Remediation). Click a tile to read the full narrative. Only one tile is open at a time." },
          { text: "Yellow history badge on a tile: previous analysis versions exist (agent was re-run after a rescan). Click the badge to browse versions with timestamps. Trash icons inside the history dialog delete individual older versions." },
        ],
        tips: [
          "The AI narrative tiles at the bottom are holistic interpretations of all findings combined. The risk table rows above are the structured, scored entries that feed Risk Overview. Both are useful — the table for prioritisation, the narratives for briefing stakeholders.",
          "'Accepted' status is the correct choice for known-and-tolerated risks. Document the business justification in a comment or ticket — if your audit process requires it, you'll thank yourself later.",
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
        summary: "The Threat Register maps scan findings to MITRE ATT&CK techniques and tactics. It bridges the gap between 'we have CVEs' and 'here are the specific attack techniques these vulnerabilities enable against us'.",
        steps: [
          { text: "What the Threat Register is for: it answers 'which threat actors and techniques are relevant to our current findings?' — turning vulnerability data into threat intelligence the blue team can act on directly." },
          { text: "How it gets populated: run the Threat Intel agent from AI Buddies → select a completed scan → choose Threat Intel → Run. The agent maps each finding to the most relevant MITRE ATT&CK technique (e.g. T1190 Exploit Public-Facing Application) and writes structured entries.", detail: "The Orchestrator agent also populates the Threat Register as part of its full-assessment run — no need to run Threat Intel separately if you run Orchestrator." },
          { text: "Select your client in the top toolbar. Open Threat Register from the left nav (Security section)." },
          { text: "KPI strip: total entries, active count, mitigated count, false positive count." },
          { text: "Filter by Status (active / mitigated / false positive) or Severity. Each row shows: severity chip, finding title, MITRE technique ID (e.g. T1190), technique name, tactic (Initial Access / Execution / Persistence / etc.), and confidence level." },
          { text: "Use the ⋮ menu on any row to update status. Move to 'Mitigated' when the underlying vulnerability is remediated. Move to 'False Positive' when the detection is incorrect." },
        ],
        tips: [
          "Confidence chips: green = high (strong CVE-to-technique mapping with clear evidence), yellow = medium (inferred from category or description), red = low (LLM best-guess with limited evidence). Prioritise high-confidence entries for immediate response; review low-confidence ones carefully before acting.",
          "MITRE technique IDs link to the MITRE ATT&CK website — open them to read the full technique description, detection recommendations, and known threat group associations. Use this when briefing a SOC team.",
          "One finding can produce multiple threat entries if it maps to multiple MITRE techniques — e.g. a misconfigured service may enable both Initial Access (T1190) and Persistence (T1505).",
        ],
        warnings: [
          "If the Threat Register is empty after running the agent: the Threat Intel agent requires a configured LLM to generate technique mappings. Without one, it falls back to rule-based output which may not produce register entries. Configure a provider in AI Settings and re-run.",
        ],
      },
      {
        id: "control-deficiencies",
        title: "Control Deficiencies — compliance gap register",
        summary: "The Control Deficiencies register maps scan findings to specific framework control failures — turning raw vulnerabilities into auditor-ready compliance gaps with control IDs, regulatory references, and an Audit Readiness score.",
        steps: [
          { text: "What the Control Deficiencies register is for: it answers 'which framework controls are we failing and why?' — exactly what an auditor needs, not just what a penetration tester needs." },
          { text: "How it gets populated: run the Compliance Monitor agent from AI Buddies → select a scan → choose Compliance Monitor → select a framework → Run. The agent maps each finding to specific control IDs and writes gap entries. The Orchestrator also populates this register.", detail: "Bug fixed in commit 350d541: the Compliance Monitor was previously passing an empty dict instead of scan findings to the LLM. It now correctly receives findings as input." },
          { text: "Select your client in the top toolbar. Open Control Deficiencies from the left nav (Security section)." },
          { text: "KPI strip: total deficiencies, open, in-remediation, closed, and Avg Audit Readiness percentage bar. Readiness rises as deficiencies move to 'closed'." },
          { text: "Filter by Status, Severity, or Framework. Each row shows the control ID in monospace (e.g. PR.DS-1 for NIST CSF, 8.7 for ISO 27001, REQ-6-3-1 for PCI DSS), the gap description, framework chip, and regulatory reference." },
          { text: "Use the status icon on a row to move a deficiency through: open → in_remediation (work started) → closed (control satisfied). Audit Readiness bar updates immediately." },
        ],
        tips: [
          "The regulatory reference field links each deficiency to the specific clause (e.g. 'GDPR Article 32 — Security of processing'). Use this when communicating with legal or compliance teams who speak regulation, not CVEs.",
          "Run the Compliance Monitor multiple times against the same scan with different framework selections — once for ISO 27001, once for GDPR, once for PCI DSS. The register shows all frameworks simultaneously with the framework filter chip.",
          "Audit Readiness % = (closed / total) × 100. Use this as a leading indicator in leadership briefings: 'Audit Readiness is at 67%, up from 42% last quarter' lands better than raw CVE counts.",
        ],
        warnings: [
          "Closing a deficiency in the register does NOT automatically verify the fix. It's a tracking action only. Always pair a 'closed' status change with evidence — a re-scan, a change ticket, or a pentest recheck — before presenting to an auditor.",
        ],
      },
      {
        id: "remediation-tracker",
        title: "Remediation Tracker — priority-banded action items",
        summary: "The Remediation Tracker converts findings into concrete, time-banded action items — Quick Win, Near Term, Medium Term, and Strategic — so engineering teams have a clear prioritised backlog without needing a security architect to triage manually.",
        steps: [
          { text: "What the Remediation Tracker is for: it bridges the gap between 'we have 847 findings' and 'here's what the team should do this week'. The Remediation agent assigns effort/impact bands so teams know what to tackle first." },
          { text: "How it gets populated: run the Remediation agent from AI Buddies → select a scan → choose Remediation → Run. The Orchestrator also populates this register as part of its full-assessment run." },
          { text: "Select your client in the top toolbar. Open Remediation Tracker from the left nav (Security section)." },
          { text: "Toggle between band-grouped view (default — Quick Win / Near Term / Medium Term / Strategic sections) and flat table (all actions sortable in one view). Toggle with the Assignment icon top-right." },
          { text: "KPI strip: total actions, completion %, actions by band. Completion bar shows overall closure rate." },
          { text: "Use the ⋮ menu on any row to update status: open → in progress → completed → cancelled. Completed actions auto-stamp a completion timestamp." },
          { text: "Band definitions:", detail: "Quick Win: 0–30 days, low effort / high impact. Near Term: 30–90 days. Medium Term: 90–180 days. Strategic: 180+ days, architectural or process changes. The Remediation agent assigns bands based on effort estimate and risk reduction potential." },
        ],
        tips: [
          "Start with Quick Wins — they reduce risk fastest with the least effort. Share the Quick Win band directly with the engineering team as a sprint backlog input.",
          "Strategic items represent architectural debt — missing SIEM, no network segmentation, no PAM solution. These need roadmap planning and budget, not just a ticket.",
          "Re-run the Remediation agent after each rescan to refresh action items. Completed items from previous runs are preserved with their timestamps. New items from new findings are added alongside.",
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
        summary: "AI Buddies agents take a completed scan's findings and produce two outputs: human-readable narrative analysis and structured register entries. Each agent specialises in a different register — risk scoring, threat intel, compliance gaps, or remediation planning.",
        steps: [
          { text: "What agents do under the hood: findings from the selected scan are packaged into a structured LLM prompt. The LLM returns structured JSON which is parsed into register entries (Risk, ThreatEntry, ControlDeficiency, RemediationAction) and a narrative. Both are persisted to the database.", detail: "Provider auto-failover: if your primary LLM is unavailable, the platform automatically tries the next in order — Azure OpenAI → OpenAI → Gemini → Bedrock → Anthropic. Each failover is logged at WARNING level in App Service logs." },
          { text: "Select your client in the top toolbar. Open AI Buddies from the left nav." },
          { text: "Pick the Scan to analyse. Only completed scans appear — running or pending scans have no findings yet." },
          { text: "Select a Framework from the Framework dropdown. This controls which compliance framework the Compliance Monitor and Framework Analyst evaluate your findings against. Standard options: NIST CSF, ISO 27001, PCI DSS, GDPR, CIS v8, SOC 2, and more. Your custom frameworks also appear here with a blue 'Custom' chip.", detail: "Selecting a custom framework tells the agent to evaluate findings against the specific controls you selected when building it — not a generic industry standard. If your organisation uses a bespoke standard (e.g. combining NIST + internal policy controls), build it in Custom Standards and select it here." },
          { text: "Choose which agents to run:", detail: "Risk Manager → Risk Register + Risk Overview. Threat Intel → Threat Register (MITRE ATT&CK mappings). Compliance Monitor → Control Deficiencies (framework control gaps — uses the Framework you selected). Remediation → Remediation Tracker (time-banded actions). Orchestrator → all 4 registers in one run. Vulnerability Analysis + Framework Mapping → scan verdict enrichment only." },
          { text: "Click 'Run agents'. Individual agents run in parallel. The Orchestrator sequences all sub-agents internally then persists all register outputs at once." },
          { text: "Results: register entries appear immediately in their respective register pages. Narrative output appears in the per-agent tabs on the Assessment detail page." },
        ],
        tips: [
          "Use the Orchestrator for complete coverage in one click — it runs all sub-agents and populates all 4 registers simultaneously. Use individual agents when you want to re-run just one (e.g. re-run Compliance Monitor with a different framework after an initial Orchestrator run).",
          "Agent output quality scales with finding quality. A single Nmap port scan produces thin agent output. Richer multi-scanner inputs (network + SAST + cloud) produce more specific, actionable narratives.",
          "Agent runs are versioned. Re-running an agent against the same scan creates a new version alongside the old one — both are accessible from the risk register tile history. You never lose prior analysis.",
        ],
        warnings: [
          "If no AI provider is configured, agents fall back to rule-based heuristics — limited register entries, no narrative. Configure a real LLM provider in AI Settings for full quality output.",
          "If the Orchestrator runs but only Risk entries appear (no Threat/Compliance/Remediation entries): this was a bug fixed in commit 350d541. Ensure that commit is deployed — it fixed orchestrator register routing where sub-agent results weren't being persisted to their dedicated tables.",
        ],
      },
      {
        id: "ai-settings",
        title: "Choose your AI provider",
        summary: "Aegis supports five AI providers with automatic failover. Configure your primary provider in AI Settings — all agents, scan verdicts, and workflow reports use it. If the primary fails at runtime, the platform automatically tries the next configured provider.",
        steps: [
          { text: "Why configure an AI provider: without one, agents produce rule-based output only — no narrative, limited register quality. The LLM turns raw CVE data into 'here's what this means for your business and what to fix first'." },
          { text: "Open Settings → AI Settings (or Connections → AI Settings from the left nav collapsible)." },
          { text: "Pick a provider: Azure OpenAI (recommended for enterprise — data stays in your Azure tenant), OpenAI, Anthropic, Google Gemini, or AWS Bedrock." },
          { text: "Paste the required credentials:", detail: "Azure OpenAI: endpoint URL + API key + deployment name. OpenAI: API key only. Anthropic: API key only. Gemini: API key only. Bedrock: AWS access key + secret + region + model ID." },
          { text: "Click 'Test'. Green success = provider is reachable and credentials are valid. This provider now powers all agent runs, scan verdicts, and workflow reports." },
          { text: "Failover order (automatic, no extra config): Azure OpenAI → OpenAI → Gemini → Bedrock → Anthropic. If the primary returns an error (rate limit, outage), the next configured provider takes over automatically.", detail: "Failover triggers on provider errors, not on credential errors. A 401 (wrong API key) does NOT trigger failover — it's treated as a misconfiguration. Fix the credentials." },
        ],
        tips: [
          "For regulated environments: use Azure OpenAI — your data is processed in your Azure region and doesn't leave your tenant boundary, unlike direct calls to OpenAI or Anthropic's public APIs.",
          "For best agent output quality: GPT-4o (OpenAI), claude-opus-4 (Anthropic), gemini-1.5-pro (Gemini). Cheaper/faster models produce lower-quality security narratives.",
          "Settings auto-save on toggle — no separate Save button needed. The config cache invalidates immediately.",
        ],
        warnings: [
          "If you change providers after agents have already run: re-run those agents to get output from the new provider. The new run is a new version alongside the old — nothing is overwritten.",
        ],
      },
      {
        id: "agent-catalog",
        title: "Browse the AI Buddies catalog",
        summary: "Beyond the seven operational agents, the catalog includes 50+ advisory agents across 7 speciality groups — SOC design, GRC, incident response, zero trust, identity governance, detection engineering, and red team planning.",
        steps: [
          { text: "What catalog agents are: pre-built domain-expert prompts you can invoke on demand. Unlike operational agents, they don't require scan findings — they take free-text context and return advisory output. Think of each as a specialist consultant available instantly." },
          { text: "Open AI Buddies → Catalog tab." },
          { text: "Browse 7 groups: Operational (risk scoring, findings analysis, remediation), Strategy (CISO advisory, roadmap, budget justification), Compliance (GRC, audit prep, framework gap), Cloud (posture review, architecture), Identity (IGA, PAM, zero trust), Detection (SIEM tuning, detection engineering), Response (IR playbooks, forensics, breach simulation)." },
          { text: "Click any agent card to see its full description, input parameters, and example output." },
          { text: "To run: click 'Run' on the card, fill in context fields (company name, industry, current tools, specific question), and submit. Output appears inline." },
          { text: "Admins can add, edit, and delete agents. Non-admins have read and run access." },
        ],
        tips: [
          "SOC Design and Zero Trust Readiness agents are useful for strategic planning — they produce board-level roadmap recommendations without needing any scan data.",
          "For active incidents: the IR Playbook agent generates step-by-step containment and recovery runbooks when given an incident type and affected systems. More useful during a live incident than post-hoc.",
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
        summary: "Workflows automate recurring security missions on a cron schedule — daily cloud posture checks, weekly vulnerability reviews, monthly compliance reports. APScheduler runs them in-process; no external broker or agent installation needed.",
        steps: [
          { text: "What workflows do: they run a pre-defined security mission (cloud security assessment, SOC design review, GRC advisory, threat model update, etc.) on a schedule. Each run produces a structured 7-section AI report and optionally sends an email summary and refreshes ALE scores." },
          { text: "Open Workflows from the left nav. Click 'New workflow'." },
          { text: "Fill in: Name (descriptive label), Client, Mission type, Schedule." },
          { text: "Choose a schedule — presets: Daily 06:00, Weekly Monday 08:00, Monthly 1st 09:00. Or paste a custom 5-field cron expression (minute hour day month weekday).", detail: "Cron runs in UTC on App Service. Add UTC offset for your timezone — e.g. for UTC+8, 'Daily 06:00 local' = '0 22 * * *' in cron." },
          { text: "Toggle 'Send summary email' to receive the report by email after each run (uses the email configuration from Settings → Email)." },
          { text: "Toggle 'Update risk quantification' to re-run the ALE model after the workflow completes — keeps Risk Overview current without manual agent runs." },
          { text: "Click Save. The workflow fires on its next scheduled time. Click 'Run now' from the workflow row to trigger an immediate test run without waiting for the schedule." },
        ],
        tips: [
          "'Run now' is the fastest way to test a new workflow configuration. If it produces a good report, the scheduled runs will too.",
          "Daily cloud posture workflows are highest-value for ongoing monitoring — cloud configurations drift quickly. Weekly or monthly cadences are appropriate for deeper compliance and threat model reviews.",
        ],
        warnings: [
          "If the App Service restarts, APScheduler reschedules all workflows from the database on startup. No runs are permanently lost — but a restart during an active run orphans that run (it won't complete). The next scheduled firing will run normally.",
        ],
      },
      {
        id: "workflow-reports",
        title: "Standardised workflow reports + PDF download",
        summary: "Every workflow run produces a 7-section AI report with identical structure every time. The schema is enforced server-side — the LLM cannot skip or add sections. Reports are persisted with each run and are permanently downloadable as PDF.",
        steps: [
          { text: "Why standardised structure: consistent format means leadership builds pattern recognition, not reading fatigue. It also makes automated comparison across runs practical — the same section is always in the same place." },
          { text: "Open Workflows. Click the History icon (clock) on any workflow row." },
          { text: "Each run row shows: timestamp, status chip (completed / failed / running), duration, and 'View Report' button." },
          { text: "Click 'View Report' to open the report viewer. The 7 sections load in order:", detail: "1. Executive Summary (2-3 paragraph narrative for leadership). 2. Scope & Inputs (what data was used and its completeness). 3. Key Findings (bulleted list with severity). 4. Risk Picture (quantified risk estimates, ALE). 5. Recommendations (prioritised action list). 6. Next Steps (immediate actions, 30-day horizon). 7. Data Completeness (what was missing and why it matters — read this first when assessing report confidence)." },
          { text: "Click 'Download PDF'. The browser print dialog opens scoped to the report content only (not the full page UI). Select 'Save as PDF'." },
          { text: "Reports persist with the run record — re-opening the viewer shows the same report every time. PDFs are fully reproducible." },
        ],
        tips: [
          "For monthly board packs: run a 'full' workflow mission on the last business day of the month, download the PDF. The Executive Summary section is written for non-technical audiences — it's suitable for direct attachment to board materials.",
          "Read the Data Completeness section first to understand the report's confidence level before presenting findings. It tells you exactly what was missing and what gaps that creates.",
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
        summary: "The Knowledge Base is a pre-seeded library of security runbooks, framework control references, and operational playbooks. Quick reference for analysts without leaving the platform — no context switching to external wikis.",
        steps: [
          { text: "What's in the Knowledge Base: framework control descriptions (NIST CSF, CIS v8, OWASP, ISO 27001, GDPR, PCI DSS), incident response runbooks (ransomware, data breach, DDoS, insider threat), SOC playbooks, hardening checklists, and vendor-agnostic architecture guides." },
          { text: "Open Knowledge Base from the left nav." },
          { text: "Use the category filter chips to narrow by type: Framework Reference, Runbook, Playbook, Checklist, Architecture Guide, etc." },
          { text: "Use the search box for keyword search across titles and document content — searches all documents, not just the visible page." },
          { text: "Click any document card to expand the content inline. Sections are collapsible — the card shows its section outline so you can jump directly to the relevant part without reading everything." },
          { text: "Documents are read-only for non-admins. Admins can add custom documents via the admin panel or directly via the API." },
        ],
        tips: [
          "During an active incident: search for the incident type (e.g. 'ransomware', 'credential stuffing', 'data exfiltration') and pull the matching runbook. It walks through detection → containment → eradication → recovery in sequence.",
          "Framework control references are useful when explaining a finding to a developer — find the control the finding maps to, share the Knowledge Base article, and they see the business context alongside the technical fix.",
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
        summary: "The Reports page aggregates workflow run outputs and scan verdicts into a single chronological feed, cross-client. One-stop view of everything the platform has generated — useful for audit trails, cross-client reporting, and surfacing missed verdicts.",
        steps: [
          { text: "What's in Reports: (1) Workflow run reports — the 7-section AI reports from every completed workflow run across all clients you have access to. (2) Scan verdicts — the AI verdict headline from every completed Assessment." },
          { text: "Open Reports from the left nav." },
          { text: "Top section: recent workflow reports, newest first. Each row shows client name, workflow name, mission type, run timestamp, and status chip." },
          { text: "Second section: scan verdicts. Each row shows client, scanner type, target, completion timestamp, and verdict headline." },
          { text: "Click any row to drill into its full detail — workflow report viewer (7 sections + PDF download) or full Assessment detail page (findings + per-agent tabs)." },
          { text: "Use the client filter at the top to narrow to a specific client. Global admins see all clients; scoped-role users see only their assigned clients." },
        ],
        tips: [
          "Reports is the fastest way to build an audit evidence trail — everything generated for a client, in reverse chronological order, in one view. For audit evidence packs, pull PDFs from relevant workflow report rows here.",
          "If a scan verdict is missing from the feed: it means the AI verdict wasn't generated at scan time. Open the Assessment detail → Verdict tab → click 'Generate verdict' to create it retroactively. It then appears in this feed.",
        ],
      },
    ],
  },
  {
    id: "frameworks",
    title: "Frameworks & Custom Standards",
    icon: <MenuBook />,
    color: "#00897B",
    topics: [
      {
        id: "framework-library",
        title: "What the framework library is",
        summary: "Aegis ships with a pre-seeded library of industry compliance frameworks — NIST CSF 2.0, ISO 27001:2022, PCI DSS 4.0, GDPR, CIS Controls v8, and more. Each framework is a structured list of controls with IDs, domains, and descriptions. Scan findings are automatically mapped to these controls when you tag a framework at scan time.",
        steps: [
          { text: "Open Frameworks from the left nav (under the Frameworks section)." },
          { text: "Browse controls by framework, domain, or search term. Each control shows its ID (e.g. PR.DS-1 for NIST CSF, A.8.24 for ISO 27001), title, domain, and description." },
          { text: "Controls are read-only — they reflect the official published standard. You cannot edit built-in controls." },
          { text: "To see which findings breach a specific control: open a finding's detail panel → look at the control_mappings field. Or filter Control Deficiencies by framework + control ID after running the Compliance Monitor agent." },
        ],
        tips: [
          "Framework controls are seeded on startup from JSON files in the backend. New frameworks can be added by dropping a correctly formatted JSON file into the frameworks data directory — no code change needed.",
          "The CIS Benchmarks (Azure, AWS, GCP, M365, Windows Server, Ubuntu) are also seeded — useful for cloud posture and OS hardening reviews.",
        ],
        warnings: [
          "If the Frameworks page shows no controls: the seed process may have failed on startup. Check the backend logs for '_seed_framework_controls' errors. Restarting the backend re-runs the seed automatically.",
        ],
      },
      {
        id: "custom-framework-build",
        title: "Build a custom compliance standard",
        summary: "Custom Standards let you define your own compliance framework by picking controls from any combination of built-in frameworks — mix NIST controls with ISO 27001 and your own internal policy requirements. Once built, the custom framework appears in the AI Agents framework selector and can be evaluated against any scan.",
        steps: [
          { text: "Open Frameworks → Custom Standards from the left nav." },
          { text: "Click 'New Framework'. Enter a name (e.g. 'Accenture Security Standard') and an optional description. Click Create.", detail: "A URL-safe slug is auto-generated from the name (e.g. 'accenture-security-standard'). If a slug already exists, a suffix (-2, -3, …) is added automatically." },
          { text: "The framework is created but has no controls yet. Click 'Add Controls' on the framework card to open the control picker." },
          { text: "In the control picker: choose a source framework (NIST CSF, ISO 27001, PCI DSS, etc.), optionally filter by domain (e.g. 'Access Control', 'Data Protection'), and search by keyword.", detail: "The picker loads 100 controls per page. Use the search box to narrow down — searching 'encryption' across ISO 27001 quickly surfaces A.8.24 (Cryptography)." },
          { text: "Select individual controls using their checkboxes, or use 'Select All' for the current page. Click 'Add Selected' to add them to your custom framework." },
          { text: "Repeat the picker process for each source framework you want to pull from — e.g. add NIST controls first, then ISO 27001, then CIS v8." },
          { text: "To remove a control: open the framework card → hover any control → click the Remove (×) icon. Removed controls are immediately detached from the framework but still exist in the control library." },
        ],
        tips: [
          "Good use case: you're a managed service provider who must comply with both ISO 27001 and a customer's internal security policy. Build one custom framework with the relevant ISO controls + the customer's policy controls. Run the Compliance Monitor against it — one evaluation covers both.",
          "Control count is shown on the framework card. Aim for 30–100 controls for meaningful compliance scoring. Very small frameworks (< 10 controls) produce narrow results; very large ones (> 200) slow down agent evaluations.",
          "You can have multiple custom frameworks — one per customer, one per regulation, one per internal audit area. They are independent of each other and of all standard frameworks.",
        ],
        warnings: [
          "Custom framework controls are references — they point at existing controls in the built-in library. If you want a control that doesn't exist in any built-in framework, it cannot be added to a custom framework. The control must exist in the seeded library first.",
          "Deleting a custom framework permanently removes it and all its control selections. This does not delete the underlying controls from the library — they are unaffected.",
        ],
      },
      {
        id: "custom-framework-evaluate",
        title: "Evaluate findings against a custom framework",
        summary: "After building your custom standard, use it in AI Agents exactly like any built-in framework. The Compliance Monitor and Framework Analyst agents will evaluate scan findings specifically against the controls you selected — producing control gap entries, an audit readiness score, and remediation guidance tailored to your framework.",
        steps: [
          { text: "Make sure your custom framework has controls added to it (Custom Standards page). An empty custom framework produces empty agent output." },
          { text: "Open AI Buddies from the left nav. Select your client in the top toolbar." },
          { text: "Choose a completed scan from the Scan selector." },
          { text: "Open the Framework dropdown (next to the Scan selector in the toolbar). Scroll to the bottom of the list — your custom frameworks appear there with a blue 'Custom' chip and their control count.", detail: "The framework dropdown shows all built-in frameworks (NIST CSF, ISO 27001, PCI DSS, etc.) followed by your custom frameworks. Custom frameworks are distinguished by the blue 'Custom' chip." },
          { text: "Select your custom framework from the dropdown." },
          { text: "Click 'Run' on the Compliance Monitor agent (or the Orchestrator to run all agents at once). The agent loads your custom framework's control list from the database, injects it as context into the LLM prompt, and evaluates each finding against those specific controls." },
          { text: "View results: open Control Deficiencies from the left nav. The gaps are now mapped to your custom framework's control IDs — not to a generic standard. Filter by framework if needed to isolate your custom standard's results." },
        ],
        tips: [
          "Run the Compliance Monitor separately for each framework you care about — NIST CSF one run, your custom standard the next. Control Deficiencies accumulates results from all runs, so you can see gaps across multiple frameworks simultaneously using the framework filter chip.",
          "The AI generates: a per-control gap assessment, an overall audit readiness score (0–100), regulatory obligation citations, and evidence inventory notes — all based on your custom control list. The more specific your controls, the more specific the output.",
          "If you update your custom framework (add or remove controls), re-run the Compliance Monitor — the agent always reads the current control list from the database at run time, so there's no caching issue.",
        ],
        warnings: [
          "If your custom framework doesn't appear in the Framework dropdown on the Agents page: the dropdown loads on page mount. Try refreshing the page. If still missing, check that the framework was actually saved (Custom Standards page should show it with a control count).",
          "Selecting a custom framework affects only the Compliance Monitor and Framework Analyst agents. Risk Manager, Threat Intel, and Remediation agents are framework-independent — they don't change behaviour based on the framework selector.",
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
        summary: "Client deletion in Aegis is a two-stage process: soft-delete (data hidden, 30-day grace period, fully restorable) then permanent delete (irreversible full database cascade). You can't accidentally permanently delete — it requires navigating to the Deleted Clients tab and explicitly confirming.",
        steps: [
          { text: "Soft-delete (stage 1): open Clients, hover any client card, click the trash icon, confirm in the dialog. The client and all its data are hidden from every view immediately — but nothing is removed from the database.", detail: "Soft-deleted clients don't appear in the global client selector, dashboard KPIs, activity feeds, or any list query. They're completely invisible to non-admin users." },
          { text: "To restore: open Settings → Deleted Clients tab (admin only). Find the client. Click the restore icon. All data reinstates immediately — the client reappears in selectors, dashboards, and list pages as if nothing happened." },
          { text: "30-day auto-purge: clients soft-deleted more than 30 days ago are automatically hard-deleted. The Days Remaining bar turns yellow under 10 days and red under 3 days as warnings." },
          { text: "Permanent delete (stage 2, irreversible): in the Deleted Clients tab, click the permanent delete icon. A confirmation dialog requires you to confirm the client name.", detail: "Permanent delete cascades through ALL related tables in order: assessments, findings, risks, threat entries, control deficiencies, remediation actions, agent runs, projects, connectors, assets — then the client record. Nothing survives. There is no undo." },
          { text: "'Purge expired' button: immediately hard-deletes all clients past their 30-day window without waiting for the automated scheduled job." },
        ],
        tips: [
          "Before soft-deleting a client for offboarding: export workflow report PDFs and scan verdict PDFs as audit evidence. Once hard-deleted, that data is gone forever.",
          "Soft-delete = 'engagement ended, preserve for 30 days'. Permanent delete = 'data must not exist' (GDPR right-to-erasure, contract requirement). Only use permanent delete when you have a legal or contractual obligation to do so.",
        ],
        warnings: [
          "Permanent delete is truly irreversible — the cascade runs directly at the database layer. There is no backup path within the platform. Double-check the client name in the confirmation dialog before clicking.",
        ],
      },
      {
        id: "grant-access",
        title: "Grant another user access",
        summary: "Aegis uses role-based access control with three roles (Reader, Editor, Admin) at three scopes (Global, Client, Project). A user's effective access is the union of all their grants. Revocation takes effect on the next API call — no re-login required.",
        steps: [
          { text: "How RBAC works: every API call checks the caller's role grants against the resource being accessed. Checks are live — no caching — so revocation is immediate." },
          { text: "Role breakdown:", detail: "Reader: view-only — no create, edit, or delete. Editor: full CRUD on security data (scans, findings, risks, agents, connectors, registers). Admin: all editor permissions plus RBAC management, client delete, sync controls, and admin API endpoints." },
          { text: "Scope breakdown:", detail: "Global: access to all clients and all admin functions. Client-scoped: access limited to one specific client and its data. Project-scoped: access limited to one project within a specific client." },
          { text: "Open Settings → Administration. Click 'Grant access'. Enter the user's email (must be a valid Microsoft Entra ID UPN in your tenant, or a guest account). Pick Role and Scope. Click Save." },
          { text: "The user can access immediately — their role is checked live on the next API call. No re-login needed if they're already signed in." },
          { text: "To revoke: find the user in the access list, click the revoke icon. Access is removed on the next API call from that user." },
        ],
        tips: [
          "For MSPs managing multiple clients: create Client-scoped Editor grants for client-side security teams. They see only their client's data, can run agents and update statuses, but can't see other clients or admin functions.",
          "For auditors needing read-only access: grant Global Reader — they can browse everything across all clients but can't change anything. Revoke after the audit engagement ends.",
        ],
        warnings: [
          "Global Admin is the highest privilege level — a global admin can grant any role at any scope, including escalating their own access. Restrict Global Admin to the security platform owner only.",
        ],
      },
      {
        id: "sync-feeds",
        title: "Sync external feeds (EPSS / KEV / NVD / Frameworks)",
        summary: "RPS scoring depends on current vulnerability feed data. EPSS (exploit probability), KEV (actively exploited CVEs), and NVD (CVE details) are synced on-demand from public sources. No automatic schedule — admins trigger syncs manually from the Sync page.",
        steps: [
          { text: "Why feeds matter for scoring: RPS per finding uses CVSS base score (NVD), daily exploit probability (EPSS), and active exploitation status (CISA KEV). Stale feeds = stale risk scores = wrong prioritisation." },
          { text: "Open Settings → Sync (admin only). Each feed tile shows: source URL, last-sync timestamp, cached record count, and a Sync button." },
          { text: "Click 'Sync' on a single tile to refresh that feed. Click 'Sync all feeds' top-right to refresh everything sequentially." },
          { text: "EPSS: downloads exploit probability scores for all CVEs (~10 MB compressed). Largest feed — usually completes in under 30 seconds on App Service. Updated daily by FIRST.org." },
          { text: "KEV: downloads CISA's Known Exploited Vulnerabilities catalog (~500 KB). Marks findings with active_exploitation = true. CISA updates KEV multiple times per week.", detail: "KEV status dramatically affects RPS. A CVE in KEV is treated as imminently exploitable regardless of its EPSS probability — active exploitation in the wild overrides theoretical scores." },
          { text: "NVD: syncs CVE details (CVSS scores, description, references) for CVEs referenced in your current findings. Targeted sync — only CVEs relevant to your data." },
          { text: "After syncing, RPS scores update immediately on the next page load — no need to re-scan or re-run agents." },
        ],
        tips: [
          "Recommended cadence: EPSS and KEV — weekly at minimum (KEV updates multiple times per week). NVD — sync after a large batch of new scans to pull descriptions for new CVEs.",
          "First-time setup: click 'Sync all feeds' before running your first scan. Without feed data, all findings score with partial RPS — only the CVSS component. EPSS and KEV components score as zero until synced.",
        ],
        warnings: [
          "Wiz and CrowdStrike Spotlight integrations are separate from feed sync — they use live per-finding API calls, not batch downloads. They activate only when WIZ_* or FALCON_* environment variables are configured in App Service settings.",
        ],
      },
      {
        id: "binary-cleanup",
        title: "Manage uploaded scan binaries",
        summary: "CodeQL binary uploads live on the App Service /home/data/uploads/ persistent disk. A background job auto-purges files older than 30 days. Admins can trigger immediate cleanup via API when needed.",
        steps: [
          { text: "Where binaries go: each upload lands at /home/data/uploads/<scan_id>/<original_filename> on the App Service. The /home/ mount is an Azure Files share — persistent across restarts and shared across all App Service instances if scaled out." },
          { text: "Automatic cleanup: a background task fires ~60 seconds after each App Service boot and runs every 24 hours. It deletes any directory in /home/data/uploads/ older than 30 days." },
          { text: "On-demand cleanup: POST /api/v1/admin/scan-binaries/cleanup?days=30 (or any retention window). Response: { scanned: N, removed: M, freed_bytes: X }. Requires admin role." },
          { text: "Deleting a scan from the Assessments tile does NOT delete its uploaded binary — the binary cleanup job handles that separately. If you need to wipe a binary immediately (e.g. accidental sensitive upload), call the cleanup endpoint with days=0 or delete via the Kudu console at /home/data/uploads/<scan_id>/." },
          { text: "Monitor disk usage: check App Service metrics → File System Usage in the Azure portal. CodeQL binaries can be up to 500 MB each. If the disk fills, uploads are rejected until space is freed — run on-demand cleanup first." },
        ],
        tips: [
          "For regulated environments with strict data handling requirements: if customer code or binaries must be deleted immediately after scanning, call the cleanup endpoint with days=0 after each scan completes rather than waiting for the 30-day automatic purge.",
        ],
        warnings: [
          "App Service /home/ is shared across all instances when scaled out. Slow Azure Files mount performance can make large binary uploads slower — scale up (larger SKU) rather than scale out for better upload throughput.",
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
          t.steps.some((s) => s.text.toLowerCase().includes(q) || (s.detail || "").toLowerCase().includes(q))
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
