import React, { useMemo, useState } from "react";
import {
  Accordion, AccordionDetails, AccordionSummary, Alert, Box,
  Tab, Tabs, TextField, Typography,
} from "@mui/material";
import {
  AdminPanelSettings, AutoStories, BarChart, BugReport, ExpandMore,
  Hub, Insights, Lightbulb, MenuBook, Psychology, Radar, RocketLaunch,
  Schedule, Search, Security, SettingsSuggest, SmartToy, Warning,
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
  navLabel: string;
  icon: React.ReactNode;
  color: string;
  topics: Topic[];
}

const GROUPS: Group[] = [
  {
    id: "getting-started",
    title: "Getting started",
    navLabel: "Getting Started",
    icon: <RocketLaunch fontSize="small" />,
    color: "#4285F4",
    topics: [
      {
        id: "sign-in",
        title: "Sign in to Monitara AI",
        summary: "Monitara AI uses Microsoft Entra ID (Azure AD) for authentication — your work Microsoft account is your only credential. No separate passwords are created or stored anywhere on the platform. Only Microsoft work or school accounts are accepted — personal Outlook.com, Hotmail.com, and Live.com accounts are blocked.",
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
        summary: "Clients are the top-level multi-tenant containers in Monitara AI. Every piece of security data — connectors, scans, findings, risks, threat entries, remediation actions — lives under a client and is invisible across client boundaries.",
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
          { text: "Intelligence section: Attack Paths (→ /attack-paths), Ask Your Data / NL Query (→ /nl-query), Security Docs / RAG (→ /security-docs)." },
          { text: "Governance section: Posture Trends (→ /posture-trends), CTEM Programs (→ /ctem)." },
          { text: "Settings section additions: Webhooks (→ /webhooks), API Keys (→ /api-keys)." },
        ],
        tips: [
          "Habit to build: select your client in the top toolbar before navigating anywhere. Every page reads the global selection — no data shows until a client is active.",
          "Connectors and Projects don't have standalone nav entries. They're tabs inside the Client Detail page: open Clients → click a client card.",
          "The Analyst / Executive toggle in the top toolbar switches the Dashboard between a detailed operational view and a summary executive view.",
        ],
      },
      {
        id: "platform-overview",
        title: "Advanced features overview",
        summary: "Monitara has 7 advanced features beyond the core scan → findings → agents flow: Attack Path Visualisation, Natural Language Query, Posture Trends, CTEM workflow, Security Document RAG, Webhooks, and API Keys.",
        steps: [
          { text: "Attack Path Visualisation (Intelligence → Attack Paths): SVG graph that maps your open findings onto MITRE ATT&CK phases — Initial Access through Exfiltration. See which findings chain together into a realistic attack path.", detail: "No configuration needed — the graph is generated automatically from your current findings. Select a client and navigate to /attack-paths." },
          { text: "Natural Language Query (Intelligence → Ask Your Data): type a plain-English question about your security data — 'How many critical findings are unresolved?', 'Which scanner found the most highs?' — and the platform generates SQL, runs it safely, and returns a result table plus a plain-English summary.", detail: "Only SELECT queries are allowed. The safety validator blocks DROP, DELETE, INSERT, UPDATE, and other write keywords before execution." },
          { text: "Posture Trends (Governance → Posture Trends): Recharts area and line charts showing how your open finding counts, risk scores, and audit readiness percentage have changed over time. Takes a ?days= parameter (default 90). Manual snapshots trigger via the button on the page.", detail: "Snapshots must exist for the charts to show data. Click 'Capture Snapshot' on the Posture Trends page to seed the first data point." },
          { text: "CTEM Programs (Governance → CTEM): structured 5-phase Continuous Threat Exposure Management workflow — Scope, Discover, Prioritise, Validate, Mobilise. Create a program per engagement or quarter. Advance phases with notes recording decisions made." },
          { text: "Security Document RAG (Intelligence → Security Docs): upload your security policies, procedures, or third-party assessment reports (PDF, DOCX, TXT). Then ask natural-language questions — 'Does our password policy cover MFA?' — and get answers grounded in your uploaded documents.", detail: "Documents are chunked at 800 chars with 100-char overlap. Retrieval uses keyword ranking followed by an LLM synthesis pass. Works entirely client-scoped — no cross-client document leakage." },
          { text: "Webhooks (Settings → Webhooks): configure Slack, Teams, or any HTTPS endpoint to receive real-time alerts. Supported events: 'finding.critical', 'scan.completed', 'agent.completed'. Payloads are HMAC-SHA256 signed." },
          { text: "API Keys (Settings → API Keys): generate machine-to-machine API keys (monitara_ prefix, 32-byte hex) for CI/CD pipelines, SIEM integrations, or scripts. The full key is shown only once at creation — store it immediately." },
        ],
        tips: [
          "Start with Posture Trends — capture a snapshot today and one per week going forward. After a month you'll have a concrete trending dataset to show stakeholders.",
          "NL Query is the fastest way to answer ad-hoc reporting questions during a meeting without building a custom dashboard.",
          "Set up a Webhook to Slack for 'finding.critical' events so the security team gets instant notification when a critical finding is ingested — no polling the portal required.",
        ],
        warnings: [
          "NL Query executes real database queries — results reflect live data at query time, not a snapshot. For audit evidence, use the Evidence Package download instead.",
          "API key full values are shown only at creation time. If you close the dialog without copying, the key cannot be recovered — you must revoke and create a new one.",
        ],
      },
    ],
  },
  {
    id: "setup",
    title: "Connecting your environment",
    navLabel: "Connections",
    icon: <Hub fontSize="small" />,
    color: "#34A853",
    topics: [
      {
        id: "cloud-connector",
        title: "Add a cloud connector (Azure / AWS / GCP / Entra ID)",
        summary: "Cloud connectors query your cloud provider's read-only APIs to detect misconfigurations, exposed resources, and identity risks — no agent installation, no network probing, no changes to your infrastructure.",
        steps: [
          { text: "What cloud connectors do: they call cloud provider control-plane APIs (Azure Resource Graph, AWS Config, GCP Security Command Center, Entra ID Microsoft Graph) and translate the results into findings using Monitara's rule library.", detail: "This is fundamentally different from workflow scanners like Nmap or ZAP that actively probe targets. Cloud connectors read configuration state — they never touch your data plane." },
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
          { text: "What happens: Monitara creates a PENDING scan, generates a per-scan HMAC token, and calls GitHub Actions workflow_dispatch. The runner clones the target, runs the tool, parses output, and POSTs findings to /api/v1/scans/ingest/ authenticated with the HMAC token." },
        ],
        tips: [
          "If GitHub Actions isn't triggering: (1) confirm MONITARA_API_URL is set as a GitHub Actions secret in the NexGenCyberAI repo, (2) the workflow .yml for the scanner exists in the repo, (3) the dispatch token has 'actions: write' permission.",
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
          { text: "Click 'Start Scan'. The platform: (1) creates a PENDING scan record, (2) uploads the binary to App Service /home/data/uploads/<scan_id>/, (3) dispatches the CodeQL GitHub Actions workflow only after upload confirms success." },
          { text: "Monitor the tile: PENDING → RUNNING → COMPLETED. Findings appear in the Findings tab. AI verdict is auto-queued." },
        ],
        tips: [
          "Best results: Java/Kotlin bytecode (.jar with .class files). C# IL (.dll/.exe) works but has smaller query coverage. Stripped native binaries (.so/.dylib without symbols) yield almost nothing.",
          "The CodeQL Standard Security suite runs ~150 queries covering OWASP Top 10, CWE Top 25, and common injection sinks.",
          "Uploaded binaries are auto-deleted after 30 days by a background cleanup job. Admins can trigger immediate cleanup via POST /api/v1/admin/scan-binaries/cleanup.",
        ],
        warnings: [
          "Treat uploaded binaries as sensitive — App Service /home/ disk is in your Azure tenant but not encrypted at rest by default. For regulated environments, consider moving uploads to Azure Blob with a customer-managed key.",
        ],
      },
      {
        id: "enterprise-scanners",
        title: "Add an enterprise scanner (Tenable, Burp Suite, Snyk, Rapid7, Qualys, Invicti, Acunetix)",
        summary: "Enterprise scanners connect to your existing commercial security tools via their REST APIs. Unlike workflow scanners, enterprise scanners run as direct API integrations — Monitara calls the tool's API, waits for results, and ingests findings automatically.",
        steps: [
          { text: "How enterprise scanners work: Monitara authenticates to the scanner's cloud or on-prem API, creates a scan job, polls for completion (up to 2 hours), fetches results, normalises severity, and persists findings to the database — identical to any other scan from the platform's perspective." },
          { text: "Supported enterprise tools:", detail: "Tenable.io — full vulnerability management via pytenable SDK. Burp Suite Enterprise — enterprise DAST via REST API. Snyk — SCA/SAST across all org projects. Rapid7 InsightVM — network vulnerability management via site scans. Qualys VMDR — cloud-based VM platform via XML API. Invicti (Netsparker) — proof-based DAST. Acunetix Enterprise — web application scanner." },
          { text: "Go to Connections → Scanners section → 'Add Scanner'. Pick your enterprise tool from the Enterprise Scanners category." },
          { text: "Fill in the credentials. Each tool requires different fields:", detail: "Tenable.io: access_key + secret_key. Burp Suite Enterprise: host URL + api_key. Snyk: api_token + org_id. Rapid7 InsightVM: host URL + username + password + site_id. Qualys VMDR: api_url + username + password + scan_title + ip_to_scan. Invicti: base_url + api_token. Acunetix: base_url + api_key + target_url." },
          { text: "Save the connector. Then go to Assessments → New Scan → Enterprise Scanners tab. Pick the tool and the connector you just saved. Click Start Scan." },
          { text: "The scan runs asynchronously. Status shows PENDING → RUNNING while the external scanner executes, then COMPLETED when findings are ingested. Large vulnerability scans can take 30–120 minutes." },
        ],
        tips: [
          "Enterprise scanners bypass the GitHub Actions workflow — they run as FastAPI BackgroundTasks. No GitHub repository or MONITARA_API_URL secret is needed for these.",
          "Tenable.io and Qualys VMDR are best for broad network/VM vulnerability coverage. Burp Suite Enterprise and Invicti are best for web application DAST. Snyk is best for developer-centric SCA and SAST.",
        ],
        warnings: [
          "Enterprise scanners launch real scans in your external tool — a Tenable.io scan will consume your scan credits/quota in that tool. Only configure connectors for targets you have explicit authorisation to scan.",
          "Credentials are encrypted at rest using the platform's Fernet key. Rotate your API keys in the external tool and re-save the connector if the key is compromised.",
        ],
      },
      {
        id: "jira-connector",
        title: "Add a Jira connector (ticket integration)",
        summary: "Connect to Jira Cloud to create tracked tickets directly from Findings and Remediation Tracker items. Jira is a ticket integration — not a security scanner — so you set it up once in Connections and then use it from the Findings or Remediation Tracker pages.",
        steps: [
          { text: "Navigate to Connections from the left nav. Scroll to the Platform Connectors section. Click 'Add Connector' → pick Jira." },
          { text: "Fill in four fields:", detail: "Jira URL: your full Atlassian subdomain, e.g. https://yourorg.atlassian.net — include https:// prefix. Email: the Atlassian account email associated with the API token. API Token: generate from id.atlassian.com → My account → Security → Create and manage API tokens. Default Project Key: optional pre-fill (e.g. KAN, SEC) — the ticket creation dialog uses this as the default but you can override it per ticket." },
          { text: "Click Save. The connector is now available for ticket creation from the Findings and Remediation Tracker pages." },
          { text: "Issue type: Monitara creates tickets with issue type 'Task' by default. This works with both classic and team-managed (next-gen) Jira projects. If your project doesn't support Task, ticket creation returns a 400 error — check your project's issue types in Jira Project Settings." },
        ],
        tips: [
          "Team-managed (next-gen) Jira projects typically support: Task, Incident, Epic, Service Request. Classic projects also have Bug, Story, and others. Monitara uses Task as the default because it exists in all project types.",
          "Your Default Project Key pre-fills the project key field in the ticket dialog. If you work across multiple Jira projects, you can override the key per ticket — it's an editable field.",
          "API tokens are scoped to your Atlassian account. The token needs 'Browse Projects' and 'Create Issues' permissions on the target project.",
        ],
        warnings: [
          "If ticket creation fails with a 400 error: the most common cause is a mismatch between issue type and project type. Team-managed projects reject Bug and Story types. Check your Jira project type (Project Settings → Project type) to confirm available issue types.",
          "Do not use your Atlassian password as the API token. Jira Cloud requires a dedicated API token — generate one at id.atlassian.com → Security.",
        ],
      },
    ],
  },
  {
    id: "scanning",
    title: "Running scans (Assessments)",
    navLabel: "Assessments",
    icon: <BugReport fontSize="small" />,
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
          { text: "Optionally tag a Framework — NIST CSF 2.0, NIST 800-53, CIS v8, OWASP, GDPR, ISO 27001, PCI DSS, etc. Findings will be control-mapped using control_id and control_mappings fields." },
          { text: "Click 'Start'. The tile appears in PENDING state, transitions to RUNNING when the workflow picks it up, then COMPLETED (or FAILED) when done." },
        ],
        tips: [
          "What you get: raw findings (severity, CVE, CVSS, EPSS, resource, control mapping), an AI verdict (executive summary + capability gaps + attack paths + vendor scorecard), and per-agent analysis tabs.",
          "AI Code Review is the only scanner that runs locally (BackgroundTask, not GitHub Actions). It supports Git repo URL or a ZIP archive upload. Results include function-level findings with exact file paths and line numbers.",
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
          { text: "AI verdict chip: green 'Verdict' chip when the AI verdict has been generated. Click the tile to generate one manually from the Verdict tab if it didn't auto-trigger." },
          { text: "Click anywhere on the tile body (not the icons) to open the full Assessment detail page." },
        ],
        tips: [
          "The grid shows only the most recent version per target. If you've rescanned, the tile shows a yellow badge with the total run count. Click it to browse all historical runs.",
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
          { text: "To compare runs: click the yellow history badge. The history dialog lists all versions with timestamp, findings count, severity breakdown, duration, and status." },
        ],
        tips: [
          "Rescan is the right action for a failed scan — it retries without losing the failure record. Don't delete the failed tile; it's useful for diagnosing recurring infrastructure issues.",
        ],
      },
      {
        id: "scan-detail",
        title: "Reading the Assessment detail (verdict + findings + agent tabs)",
        summary: "The Assessment detail page is the full picture of one scan run: AI verdict narrative, raw findings table, and per-agent analysis output. Everything needed for a security review or audit report is here.",
        steps: [
          { text: "Open the detail by clicking anywhere on the tile body (not the icons)." },
          { text: "Verdict tab: one-line Verdict headline → What We Found → Why It Matters → Executive Summary → Capability Gaps → Signal Coverage → Attack Paths → Vendor Scorecard → RPS factor breakdown → Data Completeness → Automation Opportunities.", detail: "Vendor Scorecard and RPS factor breakdown show which data sources (NVD, EPSS, KEV, Wiz, CrowdStrike) contributed to the risk score and which were missing." },
          { text: "Findings tab: every individual finding with severity chip, title, CVE ID, CVSS score, RPS score, resource identifier, and control mapping. Per-row trash icon deletes a single finding.", detail: "Click any finding row to expand the detail panel: full description, remediation steps, evidence JSON, control_mappings breakdown, EPSS probability, and KEV status." },
          { text: "Per-agent tabs (one tab per agent that ran): structured AI narrative — Executive Summary, Findings, Recommendations, Maturity Indicators. If an agent tab shows 'No analysis yet', trigger it from AI Buddies → pick this scan." },
          { text: "Print / PDF button (top-right): expands every tab into a single continuous document and triggers the browser print dialog. Pick 'Save as PDF' for a full audit-ready report." },
        ],
        tips: [
          "RPS (Risk Priority Score) = CVSS base + EPSS exploit probability + KEV active exploitation + Wiz cloud context + CrowdStrike detections. Higher RPS = prioritise first. A low-CVSS finding in KEV often outranks a high-CVSS theoretical vulnerability.",
          "If the AI verdict didn't auto-generate: click the Verdict tab and hit 'Generate verdict'. This happens when the AI provider wasn't configured at scan time, or if the scan completed very quickly before the verdict queue fired.",
        ],
      },
      {
        id: "scan-import",
        title: "Import external scan results",
        summary: "The Import External Data option accepts SARIF, Nessus XML, Burp XML, OpenVAS, Qualys CSV/XML, Checkmarx, generic CSV/JSON, and PDF (LLM fallback). Preview the import before committing — a delta diff shows new, fixed, and persisting findings vs. your existing open set.",
        steps: [
          { text: "Open Assessments → Import External Data accordion. Click 'Import'." },
          { text: "Upload the scan output file. Click 'Preview' — the platform detects the format, parses findings, and shows: detected_format, finding_count, severity_breakdown, avg_confidence (0–100), and delta diff (new / fixed / persisting counts vs. existing open findings)." },
          { text: "Review the preview. Confidence < 70 means the parser was unsure about some fields — review those rows before committing. avg_confidence is shown as an integer (0–100)." },
          { text: "Click 'Commit Import' to save findings to the database. The import is recorded in history (GET /import/history) with scan_name, detected_format, finding_count, and created_at." },
          { text: "Imported findings appear in the Findings table and are available for AI agent analysis immediately after commit." },
        ],
        tips: [
          "For PDF results (e.g. third-party pen test reports): the LLM fallback parser extracts findings from prose — confidence is typically 60–80%. Review each finding for accuracy before committing.",
          "The delta diff is valuable for tracking remediation progress: if a rescan shows 0 new + 12 fixed + 5 persisting, your team resolved 12 findings since the last scan.",
        ],
        warnings: [
          "Response field names in the preview must match exactly — if the preview shows a blank severity breakdown, the import format may not have been detected correctly. Try reformatting the file as SARIF or generic JSON.",
        ],
      },
    ],
  },
  {
    id: "risk",
    title: "Working with risks",
    navLabel: "Risk Register",
    icon: <Insights fontSize="small" />,
    color: "#EA4335",
    topics: [
      {
        id: "risk-overview",
        title: "Risk Overview — the executive dashboard",
        summary: "Risk Overview translates raw scan findings into financial risk estimates using FAIR-lite ALE (Annual Loss Expectancy). It's the board-level view of your client's security posture — not individual CVEs, but aggregated business risk by domain with dollar-range estimates.",
        steps: [
          { text: "What FAIR-lite ALE means: each risk is scored with a likelihood (probability of a loss event in a year) and impact (estimated financial loss range). ALE = likelihood × impact. Total Exposure = sum of all open risk ALEs.", detail: "Monitara derives likelihood from CVSS + EPSS + KEV data. Impact is mapped to a loss magnitude band based on the risk category and available threat intel." },
          { text: "Select a client from the top toolbar, then open Risk Overview from the left nav." },
          { text: "Top KPI strip: Total Exposure (ALE high estimate), Net Exposure (after applied controls), Open Critical/High count, 30-Day Breach Probability.", detail: "30-Day Breach Probability is derived from EPSS scores of open critical findings — the probability that at least one critical finding is actively exploited in the next 30 days." },
          { text: "Risk by Domain bar chart: groups risks into stable categories — Identity, Cloud Security, Application Security, Network, Data Protection, Compliance. Each bar shows ALE for that domain." },
          { text: "Heat map: likelihood vs. impact quadrant. Risks in the top-right (high likelihood + high impact) are immediate priorities." },
          { text: "Bottom risk table: every risk with ALE range, domain, likelihood, impact, source scan link, and current status. Click a row to update status (open → mitigated → accepted → closed)." },
        ],
        tips: [
          "Net Exposure vs Total Exposure: Total is the raw ALE sum. Net subtracts ALE of risks marked 'mitigated' or 'closed'. As your team remediates, watch Net Exposure trend down — that's the measurable ROI of the security programme.",
          "Risk Overview is read-only — you don't enter data here. The data comes from scans → Risk Manager agent. If the page is empty, see 'How Risk Overview gets populated' below.",
        ],
      },
      {
        id: "how-risk-overview-is-populated",
        title: "How Risk Overview gets populated",
        summary: "Risk Overview is built automatically — you don't manually construct it. Scans produce findings; the Risk Manager agent scores them into risks; Risk Overview aggregates those risks. Here's the exact workflow.",
        steps: [
          { text: "Step 1 — Run scans first.", detail: "Any scanner works: ZAP, Nmap, Semgrep, Trivy, AI Code Review, cloud connectors, etc. Findings from scans are the raw material. No findings = no risks = empty Risk Overview." },
          { text: "Step 2 — Run the Risk Manager AI agent.", detail: "Go to AI Buddies → select the scan → choose Risk Manager → Run. It applies the FAIR-lite ALE model to each finding, producing structured risk entries with likelihood × impact scoring. These land in the Risk Register and immediately appear in Risk Overview." },
          { text: "Step 3 (recommended) — Run the Orchestrator agent instead for full coverage.", detail: "The Orchestrator runs all agents together — Risk Manager + Threat Intel + Compliance Monitor + Remediation — in one go. It populates all 4 registers simultaneously." },
          { text: "Step 4 — Risk Overview updates automatically.", detail: "No manual refresh needed. Once the Risk Manager or Orchestrator writes risk entries, navigate to Risk Overview and the data is there." },
        ],
        tips: [
          "Full workflow: Scan → Findings → Risk Agent → Risk Register → Risk Overview. If Risk Overview looks empty: (1) is the right client selected? (2) has at least one scan completed? (3) has the Risk Manager or Orchestrator agent been run?",
          "Risk Overview is only as good as your scans. Running multiple scanner types (network + SAST + cloud connector) gives the ALE model richer signal.",
        ],
        warnings: [
          "If findings exist but no risks appear: the Risk Manager agent may have run without a configured AI provider, producing limited structured output. Configure a provider in AI Settings, then re-run the Risk Manager agent against the same scan.",
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
          { text: "Update a risk's status: click the status chip in the row directly, or expand the row and use the status dropdown. Changes are immediate — no save button needed.", detail: "Use 'Accepted' for risks you've formally decided to tolerate (e.g. legacy system, remediation cost exceeds impact)." },
          { text: "Scroll below the risk table to AI Agent Risk Analysis: one collapsible tile per agent type that ran (Risk Manager, Threat Intel, Remediation). Click a tile to read the full narrative." },
          { text: "Yellow history badge on a tile: previous analysis versions exist (agent was re-run after a rescan). Click the badge to browse versions with timestamps." },
        ],
        tips: [
          "The AI narrative tiles at the bottom are holistic interpretations of all findings combined. The risk table rows above are the structured, scored entries that feed Risk Overview. Both are useful — the table for prioritisation, the narratives for briefing stakeholders.",
          "'Accepted' status is the correct choice for known-and-tolerated risks. Document the business justification in a comment or ticket.",
        ],
      },
    ],
  },
  {
    id: "registers",
    title: "Security Registers",
    navLabel: "Sec. Registers",
    icon: <Radar fontSize="small" />,
    color: "#00ACC1",
    topics: [
      {
        id: "threat-register",
        title: "Threat Register — MITRE ATT&CK–mapped threats",
        summary: "The Threat Register maps scan findings to MITRE ATT&CK techniques and tactics. It bridges the gap between 'we have CVEs' and 'here are the specific attack techniques these vulnerabilities enable against us'.",
        steps: [
          { text: "What the Threat Register is for: it answers 'which threat actors and techniques are relevant to our current findings?' — turning vulnerability data into threat intelligence the blue team can act on directly." },
          { text: "How it gets populated: run the Threat Intel agent from AI Buddies → select a completed scan → choose Threat Intel → Run. The agent maps each finding to the most relevant MITRE ATT&CK technique (e.g. T1190 Exploit Public-Facing Application) and writes structured entries.", detail: "The Orchestrator agent also populates the Threat Register as part of its full-assessment run." },
          { text: "Select your client in the top toolbar. Open Threat Register from the left nav (Security section)." },
          { text: "KPI strip: total entries, active count, mitigated count, false positive count." },
          { text: "Filter by Status (active / mitigated / false positive) or Severity. Each row shows: severity chip, finding title, MITRE technique ID (e.g. T1190), technique name, tactic (Initial Access / Execution / Persistence / etc.), and confidence level." },
          { text: "Use the ⋮ menu on any row to update status. Move to 'Mitigated' when the underlying vulnerability is remediated. Move to 'False Positive' when the detection is incorrect." },
        ],
        tips: [
          "Confidence chips: green = high (strong CVE-to-technique mapping), yellow = medium (inferred from category), red = low (LLM best-guess). Prioritise high-confidence entries for immediate response.",
          "One finding can produce multiple threat entries if it maps to multiple MITRE techniques — e.g. a misconfigured service may enable both Initial Access (T1190) and Persistence (T1505).",
        ],
        warnings: [
          "If the Threat Register is empty after running the agent: the Threat Intel agent requires a configured LLM to generate technique mappings. Configure a provider in AI Settings and re-run.",
        ],
      },
      {
        id: "control-deficiencies",
        title: "Control Deficiencies — compliance gap register",
        summary: "The Control Deficiencies register maps scan findings to specific framework control failures — turning raw vulnerabilities into auditor-ready compliance gaps with control IDs, regulatory references, and an Audit Readiness score.",
        steps: [
          { text: "What the Control Deficiencies register is for: it answers 'which framework controls are we failing and why?' — exactly what an auditor needs." },
          { text: "How it gets populated: run the Compliance Monitor agent from AI Buddies → select a scan → choose Compliance Monitor → select a framework → Run. The Orchestrator also populates this register." },
          { text: "Select your client in the top toolbar. Open Control Deficiencies from the left nav (Security section)." },
          { text: "KPI strip: total deficiencies, open, in-remediation, closed, and Avg Audit Readiness percentage bar. Readiness rises as deficiencies move to 'closed'." },
          { text: "Filter by Status, Severity, or Framework. Each row shows the control ID in monospace (e.g. PR.DS-1 for NIST CSF, 8.7 for ISO 27001, REQ-6-3-1 for PCI DSS), the gap description, framework chip, and regulatory reference." },
          { text: "Use the status icon on a row to move a deficiency through: open → in_remediation (work started) → closed (control satisfied). Audit Readiness bar updates immediately." },
        ],
        tips: [
          "Run the Compliance Monitor multiple times against the same scan with different framework selections — once for ISO 27001, once for GDPR, once for PCI DSS. The register shows all frameworks simultaneously with the framework filter chip.",
          "Audit Readiness % = (closed / total) × 100. Use this as a leading indicator in leadership briefings: 'Audit Readiness is at 67%, up from 42% last quarter'.",
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
          { text: "What the Remediation Tracker is for: it bridges the gap between 'we have 847 findings' and 'here's what the team should do this week'." },
          { text: "How it gets populated: run the Remediation agent from AI Buddies → select a scan → choose Remediation → Run. The Orchestrator also populates this register." },
          { text: "Select your client in the top toolbar. Open Remediation Tracker from the left nav (Security section)." },
          { text: "Toggle between band-grouped view (default — Quick Win / Near Term / Medium Term / Strategic sections) and flat table. Toggle with the Assignment icon top-right." },
          { text: "KPI strip: total actions, completion %, actions by band." },
          { text: "Band definitions:", detail: "Quick Win: 0–30 days, low effort / high impact. Near Term: 30–90 days. Medium Term: 90–180 days. Strategic: 180+ days, architectural or process changes." },
          { text: "Use the ⋮ menu on any row to update status: open → in progress → completed → cancelled." },
        ],
        tips: [
          "Start with Quick Wins — they reduce risk fastest with the least effort. Share the Quick Win band directly with the engineering team as a sprint backlog input.",
          "Strategic items represent architectural debt — missing SIEM, no network segmentation, no PAM solution. These need roadmap planning and budget, not just a ticket.",
        ],
      },
    ],
  },
  {
    id: "ai-agents",
    title: "AI Buddies",
    navLabel: "AI Buddies",
    icon: <SmartToy fontSize="small" />,
    color: "#9C27B0",
    topics: [
      {
        id: "run-agent",
        title: "Run an AI agent against a scan",
        summary: "AI Buddies agents take a completed scan's findings and produce two outputs: human-readable narrative analysis and structured register entries. Each agent specialises in a different register — risk scoring, threat intel, compliance gaps, or remediation planning.",
        steps: [
          { text: "What agents do under the hood: findings from the selected scan are packaged into a structured LLM prompt. The LLM returns structured JSON which is parsed into register entries (Risk, ThreatEntry, ControlDeficiency, RemediationAction) and a narrative. Both are persisted to the database.", detail: "Provider auto-failover: if your primary LLM is unavailable, the platform automatically tries the next in order — Azure OpenAI → OpenAI → Gemini → Bedrock → Anthropic." },
          { text: "Select your client in the top toolbar. Open AI Buddies from the left nav." },
          { text: "Pick the Scan to analyse. Only completed scans appear — running or pending scans have no findings yet." },
          { text: "Select a Framework from the Framework dropdown. This controls which compliance framework the Compliance Monitor and Framework Analyst evaluate your findings against. Standard options: NIST CSF, ISO 27001, PCI DSS, GDPR, CIS v8, SOC 2, and more. Your custom frameworks appear with a blue 'Custom' chip." },
          { text: "Choose which agents to run:", detail: "Risk Manager → Risk Register + Risk Overview. Threat Intel → Threat Register (MITRE ATT&CK mappings). Compliance Monitor → Control Deficiencies (framework control gaps). Remediation → Remediation Tracker (time-banded actions). Orchestrator → all 4 registers in one run." },
          { text: "Click 'Run agents'. Individual agents run in parallel. The Orchestrator sequences all sub-agents internally then persists all register outputs at once." },
          { text: "Results: register entries appear immediately in their respective register pages. Narrative output appears in the per-agent tabs on the Assessment detail page." },
        ],
        tips: [
          "Use the Orchestrator for complete coverage in one click — it runs all sub-agents and populates all 4 registers simultaneously. Use individual agents when you want to re-run just one.",
          "Agent output quality scales with finding quality. A single Nmap port scan produces thin agent output. Richer multi-scanner inputs (network + SAST + cloud) produce more specific, actionable narratives.",
          "Agent runs are versioned. Re-running an agent against the same scan creates a new version alongside the old one — both are accessible from the risk register tile history.",
        ],
        warnings: [
          "If no AI provider is configured, agents fall back to rule-based heuristics — limited register entries, no narrative. Configure a real LLM provider in AI Settings for full quality output.",
          "If the Orchestrator runs but only Risk entries appear: ensure that the fix to orchestrator register routing is deployed (commit 350d541) — it fixed sub-agent results not being persisted to their dedicated tables.",
        ],
      },
      {
        id: "ai-settings",
        title: "Choose your AI provider",
        summary: "Monitara supports five AI providers with automatic failover. Configure your primary provider in AI Settings — all agents, scan verdicts, and workflow reports use it. If the primary fails at runtime, the platform automatically tries the next configured provider.",
        steps: [
          { text: "Why configure an AI provider: without one, agents produce rule-based output only — no narrative, limited register quality." },
          { text: "Open Settings → AI Settings (or Connections → AI Settings from the left nav collapsible)." },
          { text: "Pick a provider: Azure OpenAI (recommended for enterprise — data stays in your Azure tenant), OpenAI, Anthropic, Google Gemini, or AWS Bedrock." },
          { text: "Paste the required credentials:", detail: "Azure OpenAI: endpoint URL + API key + deployment name. OpenAI: API key only. Anthropic: API key only. Gemini: API key only. Bedrock: AWS access key + secret + region + model ID." },
          { text: "Click 'Test'. Green success = provider is reachable and credentials are valid." },
          { text: "Failover order (automatic, no extra config): Azure OpenAI → OpenAI → Gemini → Bedrock → Anthropic. If the primary returns an error, the next configured provider takes over automatically.", detail: "Failover triggers on provider errors, not on credential errors. A 401 (wrong API key) does NOT trigger failover — fix the credentials." },
        ],
        tips: [
          "For regulated environments: use Azure OpenAI — your data is processed in your Azure region and doesn't leave your tenant boundary.",
          "For best agent output quality: GPT-4o (OpenAI), claude-opus-4 (Anthropic), gemini-1.5-pro (Gemini). Cheaper/faster models produce lower-quality security narratives.",
        ],
      },
      {
        id: "agent-catalog",
        title: "Browse the AI Buddies catalog",
        summary: "Beyond the seven operational agents, the catalog includes 50+ advisory agents across 7 speciality groups — SOC design, GRC, incident response, zero trust, identity governance, detection engineering, and red team planning.",
        steps: [
          { text: "What catalog agents are: pre-built domain-expert prompts you can invoke on demand. Unlike operational agents, they don't require scan findings — they take free-text context and return advisory output." },
          { text: "Open AI Buddies → Catalog tab." },
          { text: "Browse 7 groups: Operational, Strategy (CISO advisory, roadmap, budget justification), Compliance (GRC, audit prep, framework gap), Cloud (posture review, architecture), Identity (IGA, PAM, zero trust), Detection (SIEM tuning, detection engineering), Response (IR playbooks, forensics, breach simulation)." },
          { text: "Click any agent card to see its full description, input parameters, and example output." },
          { text: "To run: click 'Run' on the card, fill in context fields, and submit. Output appears inline." },
        ],
        tips: [
          "SOC Design and Zero Trust Readiness agents are useful for strategic planning — they produce board-level roadmap recommendations without needing any scan data.",
          "For active incidents: the IR Playbook agent generates step-by-step containment and recovery runbooks when given an incident type and affected systems.",
        ],
      },
    ],
  },
  {
    id: "automation",
    title: "Automation (Workflows)",
    navLabel: "Workflows",
    icon: <Schedule fontSize="small" />,
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
          { text: "Choose a schedule — presets: Daily 06:00, Weekly Monday 08:00, Monthly 1st 09:00. Or paste a custom 5-field cron expression.", detail: "Cron runs in UTC on App Service. Add UTC offset for your timezone — e.g. for UTC+8, 'Daily 06:00 local' = '0 22 * * *' in cron." },
          { text: "Toggle 'Send summary email' to receive the report by email after each run." },
          { text: "Toggle 'Update risk quantification' to re-run the ALE model after the workflow completes." },
          { text: "Click Save. The workflow fires on its next scheduled time. Click 'Run now' from the workflow row to trigger an immediate test run." },
        ],
        tips: [
          "'Run now' is the fastest way to test a new workflow configuration. If it produces a good report, the scheduled runs will too.",
          "Daily cloud posture workflows are highest-value for ongoing monitoring — cloud configurations drift quickly.",
        ],
        warnings: [
          "If the App Service restarts, APScheduler reschedules all workflows from the database on startup. No runs are permanently lost — but a restart during an active run orphans that run.",
        ],
      },
      {
        id: "workflow-reports",
        title: "Standardised workflow reports + PDF download",
        summary: "Every workflow run produces a 7-section AI report with identical structure every time. The schema is enforced server-side — the LLM cannot skip or add sections. Reports are persisted with each run and are permanently downloadable as PDF.",
        steps: [
          { text: "Open Workflows. Click the History icon (clock) on any workflow row." },
          { text: "Each run row shows: timestamp, status chip (completed / failed / running), duration, and 'View Report' button." },
          { text: "Click 'View Report' to open the report viewer. The 7 sections load in order:", detail: "1. Executive Summary. 2. Scope & Inputs. 3. Key Findings. 4. Risk Picture. 5. Recommendations. 6. Next Steps. 7. Data Completeness (read this first when assessing report confidence)." },
          { text: "Click 'Download PDF'. The browser print dialog opens scoped to the report content only. Select 'Save as PDF'." },
        ],
        tips: [
          "For monthly board packs: run a 'full' workflow mission on the last business day of the month, download the PDF. The Executive Summary section is written for non-technical audiences.",
          "Read the Data Completeness section first to understand the report's confidence level before presenting findings.",
        ],
      },
    ],
  },
  {
    id: "vapt-reports",
    title: "VAPT Reports",
    navLabel: "VAPT Reports",
    icon: <AutoStories fontSize="small" />,
    color: "#7B61FF",
    topics: [
      {
        id: "vapt-what-is",
        title: "What is a VAPT Report",
        summary: "End-to-end penetration test report with findings, severity, and remediation. VAPT reports are structured engagement documents that capture all findings from a security test — including scope, methodology, executive summary, per-finding detail, and retest history.",
        steps: [
          { text: "What it does: VAPT (Vulnerability Assessment and Penetration Testing) reports in Monitara are structured engagement documents that capture all findings from a security test." },
          { text: "Why it matters: A VAPT report is the deliverable that goes to clients, boards, and auditors. It translates raw scanner output into an accountable, versioned document with clear remediation ownership." },
          { text: "Structure: Reports are versioned (1.0, 1.1…), linked to a scan, and contain: Document Control (title, classification, prepared by, reviewed by, dates), Scope & Methodology, Findings (severity-banded, with evidence and reproduction steps), and Export & History." },
          { text: "When to use: After completing a security scan — use 'Generate from Scan' to auto-populate findings. Or create a blank report for manual engagements." },
        ],
        tips: [
          "Always link a report to a completed scan so AI can auto-generate the executive summary.",
          "Use Classification: Confidential for client deliverables.",
        ],
        warnings: [
          "Retested reports bump to a minor version (1.0 → 1.1) — the original findings are preserved.",
        ],
      },
      {
        id: "vapt-generate-from-scan",
        title: "Generating a Report from a Scan",
        summary: "Use AI to auto-generate executive summary and per-finding remediation from scan results",
        steps: [
          { text: "What it does: The 'Generate from Scan' flow imports all findings from a completed scan, derives scope from discovered assets, selects the methodology template based on scan type, then calls an AI agent to write the executive summary, per-finding remediation guidance, and conclusion." },
          { text: "How to use: Security section → VAPT Reports → New Report → select 'Generate from Scan' (default) → pick a completed scan → click Generate. The AI takes 30–60 seconds." },
          { text: "What you get: A fully populated report with executive summary (professional prose), per-finding sections with CVSS context, tailored remediation steps, and a conclusion. You can edit anything after generation." },
          { text: "Scan picker shows: scan type, date, and finding count — choose a scan with findings.", detail: "Methodology is auto-selected from 10 templates based on connector type. Scope is derived from the scan's asset list." },
        ],
        tips: [
          "Re-generate is available — if AI output is poor, fix the scan findings and regenerate.",
          "Pick your highest-finding-count scan for the richest report.",
        ],
        warnings: [
          "Scan must be in COMPLETED status with at least one finding.",
          "AI generation requires a configured AI provider (Connections → AI Settings).",
        ],
      },
      {
        id: "vapt-findings-retest",
        title: "Managing Findings and Retest Lifecycle",
        summary: "Add, edit, and track findings through remediation and retest cycles",
        steps: [
          { text: "Each VAPT report contains its own findings table (separate from scanner findings). You can add findings manually, edit severity/evidence/reproduction steps, and track retest status through a lifecycle: pending → pass/fail." },
          { text: "Retest workflow: After remediation, create a retest (Report detail → Export & History → Initiate Retest). This creates a new report version (1.0 → 1.1) with all findings copied as 'pending retest'. Update each finding to 'pass' or 'fail' as you verify fixes." },
          { text: "Versioning: Minor version bumps on retest (1.0 → 1.1 → 1.2). The parent report is preserved. The version chain is visible in Export & History." },
          { text: "Finding fields: Title, severity, affected asset, description, impact, evidence (screenshots, logs), reproduction steps, recommendation, references, retest status, retest notes." },
        ],
        tips: [
          "Use retest notes to record what was fixed and when.",
          "Order findings by severity — the order_index field controls PDF export order.",
        ],
        warnings: [
          "Findings in a VAPT report are separate from scanner findings — changes here do not affect the Scan findings table.",
        ],
      },
      {
        id: "vapt-export",
        title: "Exporting Reports",
        summary: "Download full reports and remediation plans as PDF or Word documents",
        steps: [
          { text: "Four export formats are available from the Export & History tab: Full Report PDF, Full Report DOCX (Word), Remediation Plan PDF, Remediation Plan DOCX." },
          { text: "Full Report: Contains Document Control, Executive Summary, Scope & Methodology, all findings with full detail, and Conclusion. Suitable for client delivery." },
          { text: "Remediation Plan: Contains only actionable remediation items grouped by priority — a working document for the engineering team, not client-facing." },
          { text: "How to export: Report detail → Export & History tab → click the format button. The file downloads immediately.", detail: "If export fails: verify the report has findings. Empty reports generate empty documents." },
        ],
        tips: [
          "DOCX format is editable — use it when clients need to add their own branding.",
          "PDF is preferred for final client delivery — it cannot be accidentally modified.",
        ],
      },
    ],
  },
  {
    id: "frameworks",
    title: "Frameworks & Custom Standards",
    navLabel: "Frameworks",
    icon: <MenuBook fontSize="small" />,
    color: "#00897B",
    topics: [
      {
        id: "framework-library",
        title: "What the framework library is",
        summary: "Monitara ships with a pre-seeded library of industry compliance frameworks — NIST CSF 2.0, ISO 27001:2022, PCI DSS 4.0, GDPR, CIS Controls v8, and more. Each framework is a structured list of controls with IDs, domains, and descriptions. Scan findings are automatically mapped to these controls when you tag a framework at scan time.",
        steps: [
          { text: "Open Frameworks from the left nav (under the Frameworks section)." },
          { text: "Browse controls by framework, domain, or search term. Each control shows its ID (e.g. PR.DS-1 for NIST CSF, A.8.24 for ISO 27001), title, domain, and description." },
          { text: "Controls are read-only — they reflect the official published standard. You cannot edit built-in controls." },
          { text: "To see which findings breach a specific control: open a finding's detail panel → look at the control_mappings field. Or filter Control Deficiencies by framework + control ID after running the Compliance Monitor agent." },
        ],
        tips: [
          "Framework controls are seeded on startup from JSON files in the backend. New frameworks can be added by dropping a correctly formatted JSON file into the frameworks data directory — no code change needed.",
        ],
        warnings: [
          "If the Frameworks page shows no controls: the seed process may have failed on startup. Check the backend logs for '_seed_framework_controls' errors. Restarting the backend re-runs the seed automatically.",
        ],
      },
      {
        id: "custom-framework-build",
        title: "Build a custom compliance standard",
        summary: "Custom Standards let you define your own compliance framework by picking controls from any combination of built-in frameworks — mix NIST controls with ISO 27001 and your own internal policy requirements.",
        steps: [
          { text: "Open Frameworks → Custom Standards from the left nav." },
          { text: "Click 'New Framework'. Enter a name (e.g. 'Accenture Security Standard') and an optional description. Click Create.", detail: "A URL-safe slug is auto-generated from the name. If a slug already exists, a suffix (-2, -3, …) is added automatically." },
          { text: "Click 'Add Controls' on the framework card to open the control picker." },
          { text: "In the control picker: choose a source framework, optionally filter by domain, and search by keyword.", detail: "The picker loads 100 controls per page. Use the search box to narrow down — searching 'encryption' across ISO 27001 quickly surfaces A.8.24 (Cryptography)." },
          { text: "Select individual controls using their checkboxes, or use 'Select All' for the current page. Click 'Add Selected'." },
          { text: "Repeat the picker process for each source framework you want to pull from." },
          { text: "To remove a control: open the framework card → hover any control → click the Remove (×) icon." },
        ],
        tips: [
          "Good use case: you're a managed service provider who must comply with both ISO 27001 and a customer's internal security policy. Build one custom framework with the relevant ISO controls + the customer's policy controls.",
          "Control count is shown on the framework card. Aim for 30–100 controls for meaningful compliance scoring.",
        ],
        warnings: [
          "Custom framework controls are references — they point at existing controls in the built-in library. If you want a control that doesn't exist in any built-in framework, it cannot be added to a custom framework.",
          "Deleting a custom framework permanently removes it and all its control selections. This does not delete the underlying controls from the library.",
        ],
      },
      {
        id: "custom-framework-evaluate",
        title: "Evaluate findings against a custom framework",
        summary: "After building your custom standard, use it in AI Agents exactly like any built-in framework. The Compliance Monitor and Framework Analyst agents will evaluate scan findings specifically against the controls you selected.",
        steps: [
          { text: "Make sure your custom framework has controls added to it (Custom Standards page). An empty custom framework produces empty agent output." },
          { text: "Open AI Buddies from the left nav. Select your client in the top toolbar." },
          { text: "Choose a completed scan from the Scan selector." },
          { text: "Open the Framework dropdown. Scroll to the bottom of the list — your custom frameworks appear there with a blue 'Custom' chip and their control count." },
          { text: "Select your custom framework from the dropdown." },
          { text: "Click 'Run' on the Compliance Monitor agent (or the Orchestrator). The agent loads your custom framework's control list from the database, injects it as context into the LLM prompt, and evaluates each finding against those specific controls." },
          { text: "View results: open Control Deficiencies. The gaps are now mapped to your custom framework's control IDs. Filter by framework to isolate your custom standard's results." },
        ],
        tips: [
          "Run the Compliance Monitor separately for each framework you care about — NIST CSF one run, your custom standard the next. Control Deficiencies accumulates results from all runs.",
          "If you update your custom framework (add or remove controls), re-run the Compliance Monitor — the agent always reads the current control list from the database at run time.",
        ],
        warnings: [
          "If your custom framework doesn't appear in the Framework dropdown on the Agents page: the dropdown loads on page mount. Try refreshing the page.",
          "Selecting a custom framework affects only the Compliance Monitor and Framework Analyst agents. Risk Manager, Threat Intel, and Remediation agents are framework-independent.",
        ],
      },
      {
        id: "custom-policy-scan",
        title: "Scan against a custom policy (Custom tab)",
        summary: "The Frameworks page has a 'Custom' family tab alongside CIS, NIST, and Standards. Select any custom policy you have built and use the same Scan wizard to run a connector scan scoped to those controls.",
        steps: [
          { text: "Open Frameworks from the left nav. At the top of the page a row of family tabs appears: CIS, NIST, OWASP, Standards, Other, Custom. Click 'Custom'." },
          { text: "The Framework dropdown now shows only your custom policies, each with a purple 'Custom' chip and their control count." },
          { text: "Select your custom policy from the dropdown." },
          { text: "Click 'Scan' in the toolbar. The Scan wizard opens — pick a connector and scope (full policy / failing controls only / selected rows / custom IDs)." },
          { text: "Start the scan. The scan runs the connector and tags findings with your custom policy slug. The Frameworks page refreshes automatically when it completes.", detail: "Custom policy controls are drawn from standard frameworks, so the connector's output is mapped to those source controls. For a full gap analysis with AI reasoning, also run AI Buddies → Compliance Monitor with your custom policy selected." },
          { text: "The framework detail view (accordions, status chips, score donut) works identically for custom policies — it shows compliance status for each control in your policy based on all findings from this client." },
        ],
        tips: [
          "The purple info note in the Scan wizard is a reminder: for deep gap analysis with explanations, combine a connector scan with the Compliance Monitor agent.",
          "Use the Scan dropdown (see next topic) to scope the view to a specific scan after running it — this shows only the controls affected by that scan.",
        ],
        warnings: [
          "If the Custom tab is missing: you have no custom frameworks built yet. Go to Custom Standards and create one first.",
        ],
      },
      {
        id: "framework-scan-scope",
        title: "View compliance posture for a specific scan",
        summary: "The Frameworks page has a Scan dropdown (between Project and Framework) that scopes the entire compliance view — score, status chips, finding links — to a single completed scan. Use this to produce a per-engagement compliance report.",
        steps: [
          { text: "Open Frameworks. Select your client and a framework." },
          { text: "The Scan dropdown (labelled 'Scan') sits between the Project and Framework dropdowns. It lists all completed scans for the client, filtered by the selected project." },
          { text: "Choose a scan from the list. The framework detail reloads and now shows statuses derived live from that scan's findings only — not the aggregate across all scans.", detail: "Live derivation logic: for each framework control, the platform looks for findings from the selected scan that map to that control (via control_id match or control_mappings cross-reference). Non-compliant = open findings exist; Partial = some open, some remediated; Compliant = only historical findings (all remediated); N/A = no findings from this scan touch this control." },
          { text: "A blue 'Scoped: [scan name]' chip appears in the summary banner to confirm the view is filtered." },
          { text: "The score donut and control counts all reflect only the selected scan — this is the compliance posture at that point in time." },
          { text: "To return to the combined view: clear the Scan dropdown (select 'All scans (combined)')." },
        ],
        tips: [
          "Use scan-scoped views when generating compliance evidence for a specific audit cycle — select the scan that was run during the audit window.",
          "Pair with the Evidence Package export (Compliance Monitor → evidence/) to produce an auditor-ready ZIP with findings CSV and control deficiencies JSON scoped to that scan.",
        ],
        warnings: [
          "Scan-scoped status is derived in real time from that scan's findings and is NOT the same as the persisted ClientControlStatus (which is computed across all scans and updated by the Recompute button). The donut score may differ between the two views.",
        ],
      },
    ],
  },
  {
    id: "threat-models",
    title: "Threat Models",
    navLabel: "Threat Models",
    icon: <Hub fontSize="small" />,
    color: "#1565C0",
    topics: [
      {
        id: "threat-model-intro",
        title: "What a Threat Model is",
        summary: "A Threat Model is an AI-generated structured assessment of how an attacker could compromise your system. It produces a Data Flow Diagram (DFD), a threat list with STRIDE categories and CVSS-style scores, a MITRE ATT&CK control mapping, and — for each threat — a Sigma detection rule stub.",
        steps: [
          { text: "Navigate to Threat & Risk → Threat Models from the left nav." },
          { text: "Click 'New Threat Model'. Give it a name and an optional description." },
          { text: "Add components: in the Components tab, click '+ Component'. Each component represents a system element — web app, database, API gateway, identity provider, cloud service, etc.", detail: "Fields: Name, Type (web_app / database / api / identity / cloud_service / network / user / external_system), Platform (Azure / AWS / GCP / Corporate / Internet / Third-Party), Security Tier (DMZ / Web Tier / Application Tier / Data Tier / Management Zone / External), Criticality (critical/high/medium/low), Notes." },
          { text: "Click 'Generate Threats'. The AI analyses your component list, infers trust boundaries, and produces a prioritised threat list with STRIDE category, severity, CVSS score, affected component, and mitigations." },
          { text: "Review threats in the Threats tab. Each threat card shows the threat title, STRIDE category, severity chip, affected component, and a description. Click a card to see the full detail with mitigations and MITRE mapping." },
        ],
        tips: [
          "The more detail you put in component Notes (e.g. 'Stores PII, internet-facing, no WAF'), the more targeted the generated threats will be.",
          "Re-generate threats at any time — the AI keeps your pinned components and regenerates the threat list. Each regeneration creates a new version; the history is preserved.",
        ],
        warnings: [
          "AI-generated threats are a starting point. Review each threat for accuracy before presenting to stakeholders — the AI may flag risks that your architecture already mitigates.",
        ],
      },
      {
        id: "dfd-trust-zones",
        title: "DFD — Two-level trust zone hierarchy",
        summary: "The Data Flow Diagram renders components nested in two levels: Platform (outer solid-border box — where the component lives) and Security Tier (inner dashed-border box — the trust tier within that platform). This mirrors a real network segmentation model.",
        steps: [
          { text: "Open a Threat Model → DFD tab. Click 'React Flow' mode for the interactive graph (or 'Mermaid' for the text diagram)." },
          { text: "Platform values and their border colours:", detail: "Azure (#0078D4 blue), AWS (#FF9900 orange), GCP (#4285F4 blue), Corporate (#34A853 green), Internet (#EA4335 red), Third-Party (#9C27B0 purple)." },
          { text: "Security Tier values (inner dashed boxes):", detail: "DMZ — public-facing layer / Web Tier — presentation layer / Application Tier — business logic (default for most corporate components) / Data Tier — databases and storage / Management Zone — admin, SIEM, CA servers / External — untrusted or Internet-side actors." },
          { text: "When you add or edit a component, set both Platform and Security Tier using the dropdowns in the component table. Platform controls which outer box the component appears in; Security Tier controls the inner grouping." },
          { text: "Backward compatibility: old components with a flat 'trust_zone' field (e.g. 'Corporate Network', 'Vendor Cloud') are automatically migrated to the two-level model on load." },
        ],
        tips: [
          "A Key Vault or HSM should be: Platform=Azure, Tier=Management Zone. A public API endpoint: Platform=Azure (or Corporate), Tier=DMZ. An attacker persona: Platform=Internet, Tier=External.",
          "The DFD legend (bottom-left of the React Flow canvas) shows the colour coding for both platforms and security tiers.",
        ],
        warnings: [
          "The Mermaid diagram view uses subgraph blocks — very long tier names or special characters in component names may occasionally cause a parse error. Switch to React Flow view for interactive exploration.",
        ],
      },
      {
        id: "detection-rules",
        title: "AI Detection Rules — Sigma stubs",
        summary: "The Detection Rules tab on any Threat Model lets you generate Sigma rule stubs for every threat with one click. Each rule includes real log sources, detection conditions, MITRE ATT&CK tags, false-positive guidance, and severity.",
        steps: [
          { text: "Open a Threat Model that has threats generated. Click the 'Detection Rules' tab." },
          { text: "If no rules exist: a prompt appears with a 'Suggest Detection Rules with AI' button. Click it." },
          { text: "The AI generates one Sigma rule stub per threat. Each rule includes:", detail: "logsource (category + product matched to the platform — e.g. Azure activitylogs/signinlogs, Windows Security/Sysmon, AWS CloudTrail), detection selection with realistic field names (UriPath, HttpMethod, ClientIpAddress, EventID, etc.), condition, falsepositive list, level, and ATT&CK tags." },
          { text: "Rules display as collapsible cards: platform chip, severity, title, rule ID, ADVISORY/Validated status badge, description, and an expand arrow to see the full YAML." },
          { text: "Click 'Validate' on a rule card to mark it as reviewed. The badge changes from ADVISORY to Validated." },
          { text: "Click 'Download YAML' (top-right of the Detection Rules section) to export all rules as a single Sigma YAML file suitable for importing into your SIEM." },
          { text: "To regenerate rules (e.g. after adding more threats): click 'Re-generate with AI' button in the rules header. This replaces the current rule set." },
        ],
        tips: [
          "Sigma rules are stubs — the log source and field structure are correct for the platform, but the specific values (e.g. exact UriPath) should be tuned to your environment before deploying to a SIEM.",
          "Export the YAML and import into Microsoft Sentinel (via the Analytics rule template importer), Splunk (as a search or alert), or Elastic SIEM (as a detection rule) — all support Sigma format via converters.",
        ],
        warnings: [
          "Not all generated rules will have perfect detection conditions — review each rule in the context of your actual log schema before enabling in production.",
          "Detection rules require a working AI provider configured in AI Settings. If generation fails with '503', configure at least one provider (Azure OpenAI, Anthropic, OpenAI, etc.) first.",
        ],
      },
    ],
  },
  {
    id: "intelligence",
    title: "Intelligence & analysis",
    navLabel: "Intelligence",
    icon: <Psychology fontSize="small" />,
    color: "#9C27B0",
    topics: [
      {
        id: "attack-paths",
        title: "Attack Path Visualisation",
        summary: "The Attack Paths page renders your open findings as a layered SVG graph, grouping them by MITRE ATT&CK phase to show how individual vulnerabilities chain into realistic multi-stage attack paths from Initial Access to Exfiltration.",
        steps: [
          { text: "Select your client in the top toolbar. Navigate to Intelligence → Attack Paths." },
          { text: "How the graph is built: the backend reads all open findings for the client, applies rule-based phase classification (pattern matching on title, description, CVE ID, and severity), and returns nodes, edges, and path chains.", detail: "Phases: Initial Access (external-facing vulns, CVE exploits), Execution (code execution weaknesses), Persistence (config gaps, auth issues), Lateral Movement (network/IAM misconfigs), Exfiltration (data exposure, logging gaps). A finding can appear in multiple phases." },
          { text: "Reading the graph: nodes are colour-coded by phase. Edges connect phases that have correlated findings — a path with edges from Initial Access → Execution → Exfiltration means the platform detected findings enabling all three steps." },
          { text: "Use the Scan and Project dropdowns in the page header to scope the graph to a specific assessment or project. Leave both empty to see all open findings across the client." },
          { text: "Stats panel (right side): summary counts per phase, total nodes, total paths identified." },
          { text: "The graph regenerates live — run new scans and refresh the page to see updated paths." },
        ],
        tips: [
          "Focus remediation effort on findings that appear in the highest number of path chains — they are the nodes that enable the most complete attack scenarios.",
          "A long chain (Initial Access → Lateral Movement → Exfiltration) with no gaps is a red flag for a board briefing — it means an attacker has a complete playbook against your environment.",
        ],
        warnings: [
          "Attack path classification is rule-based — it does not run a real exploitation chain. It shows potential paths based on finding characteristics, not confirmed exploitability.",
        ],
      },
      {
        id: "nl-query",
        title: "Ask Your Data (Natural Language Query)",
        summary: "Type a plain-English security question and Monitara translates it into SQL, runs it safely against your live data, and returns a result table plus a plain-English summary — no SQL knowledge required.",
        steps: [
          { text: "Select your client in the top toolbar. Navigate to Intelligence → Ask Your Data." },
          { text: "Type your question in the text field. Examples:", detail: "'How many critical findings are still open?' / 'Which scanner found the most high-severity findings?' / 'What are the top 5 resources by finding count?' / 'Show me all findings with a CVSS score above 9.0'" },
          { text: "Click 'Ask'. The platform sends your question to the LLM which generates a SQLite SELECT statement targeting your client's findings, risks, and other tables." },
          { text: "Safety validation runs before execution: the generated SQL is checked for SELECT-only compliance. Any query containing DROP, DELETE, INSERT, UPDATE, ALTER, or EXEC is rejected — the database is never written to." },
          { text: "Results appear as a paginated table with column headers. A plain-English summary sentence appears above the table." },
          { text: "The generated SQL is shown below the results — review it to understand exactly what was queried." },
        ],
        tips: [
          "Be specific about severity and status in your questions: 'open critical findings' vs 'all critical findings' returns different counts.",
          "Copy the generated SQL and use it in your own reporting tools (Power BI, Grafana, etc.) by connecting directly to the backend database.",
        ],
        warnings: [
          "NL Query reads live data — counts change as findings are created or remediated. For point-in-time audit evidence, use the Evidence Package download instead.",
          "Complex multi-table JOIN queries may occasionally produce incorrect SQL from the LLM. If results look wrong, rephrase the question more simply and compare the generated SQL to the result.",
        ],
      },
      {
        id: "posture-trends",
        title: "Posture Trends & MTTR Tracking",
        summary: "Posture Trends shows time-series charts of your security metrics — open findings by severity, overall risk score, and audit readiness percentage — so you can demonstrate improvement over time and track MTTR (Mean Time to Remediate) against SLA targets.",
        steps: [
          { text: "Select your client in the top toolbar. Navigate to Governance → Posture Trends." },
          { text: "If the charts are empty: no snapshots have been captured yet. Click 'Capture Snapshot' to record today's metrics as the first data point.", detail: "Snapshots capture: open critical/high/medium/low/info counts, total risk ALE, and audit readiness %. Each snapshot is timestamped." },
          { text: "The ?days= selector (top-right) controls the time window: 30, 60, or 90 days (default). Adjust to zoom in on recent changes or view longer trends." },
          { text: "Use the Scan dropdown in the header to switch to Scan Summary mode — shows severity breakdown for a specific scan instead of the trend chart. Useful for post-scan reporting without navigating to the Assessment detail." },
          { text: "MTTR section (below the posture charts): shows average time-to-remediate per severity vs. SLA targets.", detail: "SLA targets: Critical 24h, High 168h (7 days), Medium 720h (30 days). MTTR is computed from Finding.remediated_at - Finding.created_at for all findings with status=remediated. Red bars = SLA breached; green = within target." },
          { text: "Capture snapshots regularly — weekly snapshots give meaningful trend lines. Monthly snapshots are the minimum for board-level reporting." },
        ],
        tips: [
          "Use the posture trend chart in monthly security reports: 'Open criticals dropped from 14 to 3 over 60 days' is more compelling than a static finding count.",
          "MTTR breaches on Critical findings are an immediate red flag — 24h SLA means a critical vuln should be remediated the same day it's found.",
        ],
        warnings: [
          "MTTR can only be computed for findings that have transitioned to 'remediated' status. Findings marked 'accepted' or 'closed' without being marked 'remediated' first are excluded from MTTR calculations.",
        ],
      },
      {
        id: "security-docs",
        title: "Security Document RAG (Policy Q&A)",
        summary: "Upload your organisation's security policies, procedures, compliance reports, or vendor assessments (PDF, DOCX, or TXT) and ask plain-English questions. The platform retrieves the most relevant sections and generates a grounded answer.",
        steps: [
          { text: "Select your client in the top toolbar. Navigate to Intelligence → Security Docs." },
          { text: "Click 'Upload Document'. Select a PDF, DOCX, or TXT file. The platform extracts text, chunks it (800 chars, 100-char overlap), and stores it in the SecurityDocument table for the active client.", detail: "Supported: PDF (via pdfminer/PyMuPDF), DOCX (via python-docx), TXT (plain text). Password-protected PDFs are not supported — export to unprotected PDF first." },
          { text: "Ask a question in the Q&A panel: type your question and click 'Ask'. The system retrieves the top-ranked chunks using keyword matching, then sends them to the LLM as context to generate an answer." },
          { text: "Example questions:", detail: "'Does our information security policy address remote access?' / 'What is our defined RTO for critical systems?' / 'Does this vendor SOC 2 report cover our data region?'" },
          { text: "Delete documents: click the trash icon on any document row. The document and all its chunks are removed from the RAG corpus immediately." },
        ],
        tips: [
          "Upload your most current versions of key documents: Information Security Policy, Business Continuity Plan, Incident Response Plan, and any relevant third-party audit reports.",
          "For compliance questionnaires (vendor DDQs): upload the questionnaire as TXT and ask 'Does our information security policy address [question]?' for quick first-pass responses.",
        ],
        warnings: [
          "Documents are stored client-scoped — documents uploaded for Client A are never accessible when Client B is the active client.",
          "RAG answers are only as accurate as your uploaded documents. If a policy is out of date, the answer reflects the outdated policy.",
        ],
      },
      {
        id: "asset-compliance",
        title: "Asset Compliance Posture (per-asset framework gap view)",
        summary: "The Compliance tab on any Asset Detail page shows which framework controls that specific asset is failing, with an overall compliance score. It gives you an asset-centric compliance view — answering 'is this server PCI DSS compliant?' — rather than navigating the global Control Deficiencies table.",
        steps: [
          { text: "Navigate to Asset Inventory from the left nav. Click any asset to open the Asset Detail page." },
          { text: "Click the Compliance tab (the last tab in the Asset Detail tab row)." },
          { text: "Select a framework from the dropdown: NIST CSF 2.0, ISO 27001, PCI DSS, CIS v8, or GDPR." },
          { text: "The compliance overview shows four metrics:", detail: "Compliance Score % — (total_controls − failing) / total × 100. Failing Controls — controls with at least one open finding mapped to them. Total Framework Controls — total control count in the selected framework. Open Findings — count of open findings associated with this asset." },
          { text: "The failing controls table lists each breached control: control ID chip (e.g. PR.DS-1 for NIST CSF, REQ-6 for PCI DSS), domain, control title, worst finding severity, and finding count mapped to that control." },
          { text: "Changing the framework dropdown immediately reloads the compliance data for the new framework — no page reload needed." },
        ],
        tips: [
          "Use Asset Compliance Posture for targeted questions: 'Is this database server PCI DSS compliant?' or 'Which ISO 27001 controls is this web app failing?'.",
          "Findings are mapped to controls via three fields: Finding.control_id + Finding.framework (direct mapping) and Finding.control_mappings JSON (secondary cross-framework mappings). The Compliance tab checks all three.",
          "Run the Compliance Monitor agent first (AI Buddies) to populate control_mappings on findings. Without agent enrichment, only findings with explicit control_id values are counted.",
        ],
        warnings: [
          "Compliance Score measures the absence of found failures, not positive proof of compliance. Unscanned assets may have findings that haven't been discovered yet.",
          "A control not appearing in the failing controls table doesn't mean it's satisfied — it may mean no scan has produced a finding mapped to that control. Treat a high compliance score as 'no known failures found', not as a compliance certification.",
        ],
      },
    ],
  },
  {
    id: "governance",
    title: "Governance & compliance",
    navLabel: "Governance",
    icon: <Radar fontSize="small" />,
    color: "#34A853",
    topics: [
      {
        id: "ctem",
        title: "CTEM Workflow (Continuous Threat Exposure Management)",
        summary: "Monitara CTEM is a 5-phase AI-assisted workflow — Scope → Discover → Prioritise → Validate → Mobilise. Each phase auto-populates from your existing platform data (findings, assets, scans) and is fully editable by analysts.",
        steps: [
          { text: "Select your client in the top toolbar. Navigate to Governance → CTEM Programs." },
          { text: "Click 'New Program'. Enter a name (e.g. 'Q3 2026 Exposure Cycle') and optional description. Optionally select one or more connectors from the multi-select dropdown to scope the asset inventory — only assets discovered by those connectors appear in Phase 1 and Phase 2. If no connectors are selected, all assets from all connectors are included.", detail: "Connector scoping prevents cross-environment contamination — e.g. scope a CTEM program to only your production Azure connector, excluding dev/test assets. Assets discovered by multiple connectors are deduplicated by external_id so each physical asset appears exactly once." },
          { text: "Phase 1 — Scope: the platform automatically discovers unique assets from your existing scan findings (resource_id + resource_type). For each asset you can set: In Scope, Out of Scope, or Crown Jewel.", detail: "If no assets appear: run at least one scan first. Assets are pulled from Finding.resource_id." },
          { text: "Phase 2 — Discover: shows all open findings filtered to the assets you tagged In Scope or Crown Jewel in Phase 1. Findings are grouped by exposure category — EASM (external attack surface), CSPM (cloud posture), Identity, SAST (code), Infrastructure, Third-Party." },
          { text: "Phase 3 — Prioritise: click 'Generate AI Top 5' to have the AI analyse scoped findings and crown-jewel assets and output the 5 highest-impact exposures with rationale. Crown Jewel assets receive automatic weighting — exposures affecting the most crown-jewel assets are ranked first regardless of raw CVSS score. Items affecting crown jewels show a red 👑 chip displaying the count of affected critical assets.", detail: "Weighting order: crown jewel asset count (highest first) → severity (highest first) → CVSS score (highest first). This ensures business-critical exposures always surface above theoretical-but-low-business-impact vulnerabilities. After AI generation you can add, remove, and reorder items using the up/down arrows." },
          { text: "Phase 4 — Validate: pre-seeded validation methods table — Automated BAS, Manual Attack-Path Validation, and Control-Efficacy Check. Fill in Tests Run and Confirmed Exploitable counts for each method." },
          { text: "Phase 5 — Mobilise: tracks remediation ownership by team. Add owner teams with their Open / Closed On-Time / SLA Breach counts. A red alert fires automatically if any team shows SLA Breach > 0." },
          { text: "AI Brief: every phase has a 'Generate AI Brief' button. The brief is fully editable." },
          { text: "Mark Phase Complete: click 'Mark Phase Complete'. This records who completed it and when, and unlocks the next phase." },
          { text: "Export: click PDF or DOCX on the program card to download the full CTEM report." },
        ],
        tips: [
          "Run CTEM Programs quarterly for broad coverage, or after significant infrastructure changes.",
          "Crown Jewel assets in Phase 1 give the AI Prioritise agent automatic extra weight — Phase 3 ranks exposures by crown jewel impact count first, then by severity, then by CVSS. A medium-severity exposure affecting 5 crown jewel assets ranks above a critical affecting none.",
          "AI Briefs are drafts. The analyst always has final editorial control — revise the tone, add business context, or remove jargon before including in a client report.",
        ],
        warnings: [
          "Phase gating means the next phase accordion is greyed-out until you click 'Mark Phase Complete' on the current one. This is intentional — it prevents analysts from jumping ahead.",
          "If the Scope phase shows no assets despite having completed scans: the findings for this client may have empty resource_id fields. Check the Findings page.",
        ],
      },
      {
        id: "evidence",
        title: "Compliance Evidence Collection (Evidence Package)",
        summary: "The Evidence Package endpoint bundles your compliance-relevant data — findings, control deficiencies, remediation actions, agent logs, and framework assessments — into a single downloadable ZIP file for audit submission.",
        steps: [
          { text: "Select your client in the top toolbar." },
          { text: "To download an evidence package: call GET /api/v1/clients/{cid}/evidence/package or use the 'Download Evidence' button on the Frameworks page. An optional ?framework= query param filters the control deficiencies to a specific framework.", detail: "The ZIP contains: findings.csv (all findings with severity, status, CVE, CVSS, assignee, due_date), control_deficiencies.json, remediation_actions.json, agent_run_log.json, framework_assessments.json." },
          { text: "Provide the ZIP directly to auditors as pre-packaged evidence. The package reflects data at the time of download — re-download at audit completion for a final evidence snapshot." },
          { text: "Filter by framework to produce a focused package: 'evidence for PCI DSS audit' only includes PCI DSS–mapped control deficiencies." },
        ],
        tips: [
          "Download evidence packages at the start and end of a remediation sprint to show before/after state — two timestamped ZIPs are more compelling audit evidence than a dashboard screenshot.",
          "The CSV format of findings.csv is importable into Excel, Google Sheets, or any GRC tool for further filtering or annotation by the auditor.",
        ],
        warnings: [
          "Evidence packages contain full finding details including descriptions, evidence JSON, and CVE information — treat them as confidential documents and share only via secure channels.",
        ],
      },
      {
        id: "scorecard",
        title: "Embeddable Security Scorecard",
        summary: "Generate a shareable public URL that displays a live security score for your client — no login required. Embed in customer portals, status pages, or executive dashboards. Score updates automatically as findings are resolved.",
        steps: [
          { text: "Select your client in the top toolbar. Navigate to the client's settings or the Scorecard section." },
          { text: "Click 'Generate Scorecard Link'. The platform creates a ScorecardToken (random hex) and returns the public URL: /public/scorecard/{token}." },
          { text: "Share the URL with anyone who needs visibility — customer, board member, partner. No Monitara account required to view it." },
          { text: "The scorecard shows: overall score (0–100), severity breakdown (critical/high/medium/low/info open counts), and a colour-coded risk band (green >80, yellow 60–80, red <60).", detail: "Score formula: max(0, 100 - critical*10 - high*3 - other_open). Each open critical deducts 10 points, each open high deducts 3 points, each other open finding deducts 1 point." },
          { text: "Multiple tokens can exist per client — create separate tokens for different audiences (e.g. one for the customer portal, one for the executive dashboard) and revoke each independently." },
        ],
        tips: [
          "Use scorecard URLs in SLA reporting to customers — they can self-serve their current security score without needing a portal login or a meeting.",
          "Revoke and reissue tokens when a client engagement ends or personnel change.",
        ],
        warnings: [
          "Scorecard URLs are public and require no authentication. Anyone with the URL can see the score and finding counts. Treat the token like a password.",
        ],
      },
    ],
  },
  {
    id: "integrations",
    title: "Integrations & API",
    navLabel: "Integrations & API",
    icon: <Hub fontSize="small" />,
    color: "#4285F4",
    topics: [
      {
        id: "webhooks",
        title: "Slack / Teams / Custom Webhook Notifications",
        summary: "Configure outbound webhooks to Slack, Microsoft Teams, or any HTTPS endpoint so your team receives real-time notifications when critical findings are created, scans complete, or AI agents finish analysis — without polling the portal.",
        steps: [
          { text: "Navigate to Settings → Webhooks." },
          { text: "Click 'Add Webhook'. Fill in:", detail: "Name: descriptive label. URL: the HTTPS endpoint. Events: select one or more — 'finding.critical', 'scan.completed', 'agent.completed'. Secret (optional but recommended): a string used to generate the HMAC-SHA256 signature." },
          { text: "Click 'Save'. Click 'Test Delivery' on the webhook row to send a test payload immediately." },
          { text: "How payload signing works: every delivery includes an X-Monitara-Signature header containing HMAC-SHA256(secret, payload_body_as_bytes). Verify this on your endpoint to confirm the payload is genuine.", detail: "In Python: hmac.compare_digest(computed_sig, received_sig). In Node.js: crypto.createHmac('sha256', secret).update(body).digest('hex')." },
          { text: "For Slack: create an Incoming Webhook App in your Slack workspace (api.slack.com/apps → Incoming Webhooks → Add New Webhook to Workspace). Paste the resulting URL into Monitara." },
          { text: "For Teams: create a workflow using 'Post to a channel when a webhook request is received' in Power Automate, or use the Teams Incoming Webhook connector. Paste the webhook URL into Monitara." },
        ],
        tips: [
          "Start with 'finding.critical' — an immediate Slack message when a critical finding is ingested is the highest-value notification.",
          "Use separate webhooks for separate audiences — one to the security team's Slack channel, one to the CISO's Teams channel, each subscribed to different event types.",
        ],
        warnings: [
          "Webhook deliveries are fire-and-forget with one retry on failure. If your endpoint is down during a critical finding event, the notification is not queued indefinitely.",
          "Do not use webhook URLs as substitutes for authentication. Validate the X-Monitara-Signature on every delivery.",
        ],
      },
      {
        id: "api-keys",
        title: "API Keys & Programmatic Access",
        summary: "Generate long-lived API keys for CI/CD pipelines, SIEM integrations, or scripts that need to call Monitara APIs without a user login. Keys use the 'monitara_' prefix and are scoped to specific capabilities. The full key is shown only once — store it securely immediately.",
        steps: [
          { text: "Navigate to Settings → API Keys." },
          { text: "Click 'Create API Key'. Enter a descriptive name. Select the scopes this key requires.", detail: "Scopes control access: 'findings:read', 'scans:write', 'reports:read', 'webhooks:write'. Assign minimum necessary scopes — principle of least privilege." },
          { text: "Click 'Generate'. The full key (format: monitara_[64 hex chars]) is displayed exactly once. Copy it immediately — this is the only time the platform shows the full key value." },
          { text: "Use the key in API calls via the Authorization header: Authorization: Bearer monitara_[your-key-here]. The platform verifies by hashing the received key and comparing to stored hashes." },
          { text: "To revoke: find the key in the API Keys list, click 'Revoke'. The key becomes invalid immediately." },
        ],
        tips: [
          "Create separate keys per integration — one for GitHub Actions, one for your SIEM, one for scripts. This makes it easy to revoke one without disrupting others.",
          "Use API keys in CI/CD to trigger scans automatically on code merge: POST /api/v1/clients/{cid}/scans/ with the appropriate connector and scan type.",
        ],
        warnings: [
          "Never commit API keys to source control, even in private repositories. Use CI/CD secret management (GitHub Actions Secrets, Azure Key Vault, HashiCorp Vault) to inject them as environment variables at runtime.",
          "If a key is compromised, revoke it immediately from Settings → API Keys. There is no 'suspend' — only revoke.",
        ],
      },
      {
        id: "ticket-creation",
        title: "Create tracked tickets from Findings or Remediation Tracker",
        summary: "Push any finding or remediation action to Jira or ServiceNow as a tracked ticket — directly from within Monitara. The ticket captures finding details (severity, CVE, description, remediation steps) and a deep link back to the source. No copy-paste required.",
        steps: [
          { text: "Prerequisite: save a Jira or ServiceNow connector in Connections. For Jira you need the URL, email, API token, and optionally a default project key." },
          { text: "From the Findings page: find the finding you want to track. Click the ticket icon or ⋮ menu → 'Create Ticket'. A dialog opens.", detail: "The dialog shows: connector selector, project key field (pre-filled from the connector's Default Project Key), priority selector, and a preview of the ticket title and description that will be sent." },
          { text: "From Remediation Tracker: find the remediation action row. Click 'Create Ticket'. Same dialog — same connector, project key, and priority fields." },
          { text: "For Jira: enter the Project Key — this is required. The key is typically 2–5 uppercase letters from your Jira project URL (e.g. KAN, SEC, OPS). The Create button stays disabled until a project key is provided.", detail: "Even if the connector has a Default Project Key set, confirm it is correct for the target project. Using the wrong project key returns a 400 error." },
          { text: "Click Create. Monitara calls the connector's API (Jira or ServiceNow). On success, the ticket key (e.g. KAN-42) is returned and displayed. The ticket is live in your issue tracker immediately." },
        ],
        tips: [
          "The ticket description includes: severity, CVE ID, CVSS score, resource identifier, full finding description, and AI-generated remediation steps. Engineering teams get everything they need without needing Monitara access.",
          "ServiceNow tickets land in the configured table (default: incident). The short_description is the finding title; work_notes contain the full finding context.",
          "Ticket creation is a one-way push. If you update the finding in Monitara, the Jira ticket is not automatically updated — use the ticket's assignee and comments for tracking follow-up.",
        ],
        warnings: [
          "If you see a 400 error: the project key is wrong, the issue type is not supported by your project, or the priority value is invalid. Open your Jira project settings → Issue Types to verify what types are available.",
          "Ticket creation does not automatically update the finding status in Monitara. After the finding is resolved, manually update the finding status to 'remediated' or 'accepted'.",
        ],
      },
    ],
  },
  {
    id: "reports",
    title: "Reports",
    navLabel: "Reports",
    icon: <BarChart fontSize="small" />,
    color: "#03A9F4",
    topics: [
      {
        id: "browse-reports",
        title: "Browse cross-system reports",
        summary: "The Reports page aggregates workflow run outputs and scan verdicts into a single chronological feed, cross-client. One-stop view of everything the platform has generated — useful for audit trails, cross-client reporting, and surfacing missed verdicts.",
        steps: [
          { text: "Open Reports from the left nav." },
          { text: "Top section: recent workflow reports, newest first. Each row shows client name, workflow name, mission type, run timestamp, and status chip." },
          { text: "Second section: scan verdicts. Each row shows client, scanner type, target, completion timestamp, and verdict headline." },
          { text: "Click any row to drill into its full detail — workflow report viewer (7 sections + PDF download) or full Assessment detail page (findings + per-agent tabs)." },
          { text: "Use the client filter at the top to narrow to a specific client. Global admins see all clients; scoped-role users see only their assigned clients." },
        ],
        tips: [
          "Reports is the fastest way to build an audit evidence trail — everything generated for a client, in reverse chronological order, in one view.",
          "If a scan verdict is missing from the feed: open the Assessment detail → Verdict tab → click 'Generate verdict' to create it retroactively.",
        ],
      },
      {
        id: "knowledge-base",
        title: "Knowledge Base",
        summary: "The Knowledge Base is a pre-seeded library of security runbooks, framework control references, and operational playbooks. Quick reference for analysts without leaving the platform.",
        steps: [
          { text: "What's in the Knowledge Base: framework control descriptions (NIST CSF, CIS v8, OWASP, ISO 27001, GDPR, PCI DSS), incident response runbooks (ransomware, data breach, DDoS, insider threat), SOC playbooks, hardening checklists, and vendor-agnostic architecture guides." },
          { text: "Open Knowledge Base from the left nav." },
          { text: "Use the category filter chips to narrow by type: Framework Reference, Runbook, Playbook, Checklist, Architecture Guide, etc." },
          { text: "Use the search box for keyword search across titles and document content — searches all documents, not just the visible page." },
          { text: "Click any document card to expand the content inline. Sections are collapsible." },
        ],
        tips: [
          "During an active incident: search for the incident type (e.g. 'ransomware', 'credential stuffing') and pull the matching runbook. It walks through detection → containment → eradication → recovery in sequence.",
          "Framework control references are useful when explaining a finding to a developer — find the control the finding maps to and share the Knowledge Base article.",
        ],
      },
    ],
  },
  {
    id: "admin",
    title: "Administration",
    navLabel: "Administration",
    icon: <AdminPanelSettings fontSize="small" />,
    color: "#F06292",
    topics: [
      {
        id: "client-lifecycle",
        title: "Delete, restore, or permanently remove a client",
        summary: "Client deletion in Monitara is a two-stage process: soft-delete (data hidden, 30-day grace period, fully restorable) then permanent delete (irreversible full database cascade). You can't accidentally permanently delete — it requires navigating to the Deleted Clients tab and explicitly confirming.",
        steps: [
          { text: "Soft-delete (stage 1): open Clients, hover any client card, click the trash icon, confirm in the dialog. The client and all its data are hidden from every view immediately — but nothing is removed from the database.", detail: "Soft-deleted clients don't appear in the global client selector, dashboard KPIs, activity feeds, or any list query. They're completely invisible to non-admin users." },
          { text: "To restore: open Settings → Deleted Clients tab (admin only). Find the client. Click the restore icon. All data reinstates immediately." },
          { text: "30-day auto-purge: clients soft-deleted more than 30 days ago are automatically hard-deleted. The Days Remaining bar turns yellow under 10 days and red under 3 days as warnings." },
          { text: "Permanent delete (stage 2, irreversible): in the Deleted Clients tab, click the permanent delete icon. A confirmation dialog requires you to confirm the client name.", detail: "Permanent delete cascades through ALL related tables: assessments, findings, risks, threat entries, control deficiencies, remediation actions, agent runs, projects, connectors, assets — then the client record. Nothing survives." },
          { text: "'Purge expired' button: immediately hard-deletes all clients past their 30-day window." },
        ],
        tips: [
          "Before soft-deleting a client for offboarding: export workflow report PDFs and scan verdict PDFs as audit evidence. Once hard-deleted, that data is gone forever.",
          "Soft-delete = 'engagement ended, preserve for 30 days'. Permanent delete = 'data must not exist' (GDPR right-to-erasure, contract requirement).",
        ],
        warnings: [
          "Permanent delete is truly irreversible — the cascade runs directly at the database layer. There is no backup path within the platform. Double-check the client name in the confirmation dialog before clicking.",
        ],
      },
      {
        id: "grant-access",
        title: "Grant another user access",
        summary: "Monitara uses role-based access control with three roles (Reader, Editor, Admin) at three scopes (Global, Client, Project). A user's effective access is the union of all their grants. Revocation takes effect on the next API call — no re-login required.",
        steps: [
          { text: "How RBAC works: every API call checks the caller's role grants against the resource being accessed. Checks are live — no caching — so revocation is immediate." },
          { text: "Role breakdown:", detail: "Reader: view-only — no create, edit, or delete. Editor: full CRUD on security data (scans, findings, risks, agents, connectors, registers). Admin: all editor permissions plus RBAC management, client delete, sync controls, and admin API endpoints." },
          { text: "Scope breakdown:", detail: "Global: access to all clients and all admin functions. Client-scoped: access limited to one specific client and its data. Project-scoped: access limited to one project within a specific client." },
          { text: "Open Settings → Administration. Click 'Grant access'. Enter the user's email (must be a valid Microsoft Entra ID UPN in your tenant). Pick Role and Scope. Click Save." },
          { text: "The user can access immediately — their role is checked live on the next API call. No re-login needed if they're already signed in." },
          { text: "To revoke: find the user in the access list, click the revoke icon. Access is removed on the next API call from that user." },
        ],
        tips: [
          "For MSPs managing multiple clients: create Client-scoped Editor grants for client-side security teams. They see only their client's data but can't see other clients or admin functions.",
          "For auditors needing read-only access: grant Global Reader — they can browse everything across all clients but can't change anything.",
        ],
        warnings: [
          "Global Admin is the highest privilege level — a global admin can grant any role at any scope, including escalating their own access. Restrict Global Admin to the security platform owner only.",
        ],
      },
      {
        id: "sync-feeds",
        title: "Sync external feeds (EPSS / KEV / NVD / Frameworks)",
        summary: "RPS scoring depends on current vulnerability feed data. EPSS (exploit probability), KEV (actively exploited CVEs), and NVD (CVE details) are synced on-demand from public sources. Admins trigger syncs manually from the Sync page.",
        steps: [
          { text: "Why feeds matter for scoring: RPS per finding uses CVSS base score (NVD), daily exploit probability (EPSS), and active exploitation status (CISA KEV). Stale feeds = stale risk scores = wrong prioritisation." },
          { text: "Open Settings → Sync (admin only). Each feed tile shows: source URL, last-sync timestamp, cached record count, and a Sync button." },
          { text: "Click 'Sync' on a single tile to refresh that feed. Click 'Sync all feeds' top-right to refresh everything sequentially." },
          { text: "EPSS: downloads exploit probability scores for all CVEs (~10 MB compressed). Updated daily by FIRST.org." },
          { text: "KEV: downloads CISA's Known Exploited Vulnerabilities catalog (~500 KB). Marks findings with active_exploitation = true. CISA updates KEV multiple times per week.", detail: "KEV status dramatically affects RPS. A CVE in KEV is treated as imminently exploitable regardless of its EPSS probability." },
          { text: "NVD: syncs CVE details (CVSS scores, description, references) for CVEs referenced in your current findings. Targeted sync — only CVEs relevant to your data." },
          { text: "After syncing, RPS scores update immediately on the next page load — no need to re-scan or re-run agents." },
        ],
        tips: [
          "Recommended cadence: EPSS and KEV — weekly at minimum. NVD — sync after a large batch of new scans.",
          "First-time setup: click 'Sync all feeds' before running your first scan. Without feed data, all findings score with partial RPS.",
        ],
      },
      {
        id: "binary-cleanup",
        title: "Manage uploaded scan binaries",
        summary: "CodeQL binary uploads live on the App Service /home/data/uploads/ persistent disk. A background job auto-purges files older than 30 days. Admins can trigger immediate cleanup via API when needed.",
        steps: [
          { text: "Where binaries go: each upload lands at /home/data/uploads/<scan_id>/<original_filename> on the App Service. The /home/ mount is an Azure Files share — persistent across restarts." },
          { text: "Automatic cleanup: a background task fires ~60 seconds after each App Service boot and runs every 24 hours. It deletes any directory in /home/data/uploads/ older than 30 days." },
          { text: "On-demand cleanup: POST /api/v1/admin/scan-binaries/cleanup?days=30. Response: { scanned: N, removed: M, freed_bytes: X }. Requires admin role." },
          { text: "Monitor disk usage: check App Service metrics → File System Usage in the Azure portal. CodeQL binaries can be up to 500 MB each." },
        ],
        tips: [
          "For regulated environments: if customer code or binaries must be deleted immediately after scanning, call the cleanup endpoint with days=0 after each scan completes.",
        ],
        warnings: [
          "App Service /home/ is shared across all instances when scaled out. Slow Azure Files mount performance can make large binary uploads slower — scale up (larger SKU) rather than scale out.",
        ],
      },
    ],
  },
  {
    id: "scanners",
    title: "Scanners & Tools",
    navLabel: "Scanners & Tools",
    icon: <Security fontSize="small" />,
    color: "#E91E63",
    topics: [
      {
        id: "tool-zap",
        title: "OWASP ZAP — Web Application Scanner (DAST)",
        summary: "ZAP (Zed Attack Proxy) is an open-source Dynamic Application Security Testing tool. It probes a live web application from the outside — exactly like an attacker would — and reports vulnerabilities it can observe or trigger through HTTP interactions.",
        steps: [
          { text: "Purpose: detect runtime web vulnerabilities that only appear when the application is running — SQL injection, XSS, CSRF, insecure headers, authentication bypasses, directory traversal, and OWASP Top 10 issues. Static analysis (Semgrep/CodeQL) cannot find these because they require a live HTTP response." },
          { text: "When to use:", detail: "Before any production release of a web app or API. After any change to authentication, session management, or input handling. As part of a scheduled security assessment cadence (quarterly minimum). When a new endpoint or feature is added that handles user input." },
          { text: "How to use: Connections → Add connector → Web (ZAP). Enter the target URL (must be publicly reachable or reachable from GitHub Actions runners). Assessments → New Scan → DAST tab → select your ZAP connector → choose profile: Baseline (passive, ~5 mins) or Active (~30–60 mins).", detail: "Baseline: ZAP spiders the site passively — no attack payloads sent. Safe for production. Active: ZAP sends attack payloads (SQLi, XSS, path traversal, etc.) against discovered endpoints. Use only on non-production unless you have explicit written authorisation." },
          { text: "What to expect from results: findings are grouped by alert type — XSS, SQL Injection, Missing Security Headers, Insecure Cookie Flags, etc. Each finding includes the vulnerable URL (resource_id), evidence (the HTTP request/response that triggered the alert), and CWE ID mapped to NIST/OWASP controls." },
          { text: "Severity mapping: ZAP uses risk codes 0–3. Risk 3 + CWE in {79 XSS, 89 SQLi, 78 OS Injection, 94 Code Injection} → Critical. Risk 3 → High. Risk 2 → Medium. Risk 1 → Low. Risk 0 → Info." },
        ],
        tips: [
          "Run Baseline first on production — it's passive and safe. Use the output to fix low-hanging fruit (missing headers, insecure cookies) before running Active on a staging environment.",
          "For authenticated scans: save session cookies or Bearer tokens as auth_headers in the connector config. ZAP injects them via the Replacer rule so all crawled pages are scanned in an authenticated context.",
          "ZAP produces many 'Informational' findings (e.g. server version disclosure). Filter to Medium+ in the Findings page for actionable results during triage.",
        ],
        warnings: [
          "Active scan sends real attack payloads — it WILL trigger WAF alerts, fill error logs, and may corrupt data in forms. Never run Active scan against production without written authorisation and a maintenance window.",
          "ZAP cannot scan SPAs (React/Vue/Angular) that require JavaScript execution. It crawls static HTML links. For SPA coverage, use ZAP's Ajax Spider (requires manual configuration outside this platform).",
        ],
      },
      {
        id: "tool-nmap",
        title: "Nmap — Network Port & Service Scanner",
        summary: "Nmap is the industry-standard network reconnaissance tool. It discovers which ports are open on a host or network range, identifies the services running on those ports, detects software versions, and runs NSE (Nmap Scripting Engine) scripts that can detect specific CVEs and misconfigurations.",
        steps: [
          { text: "Purpose: map your external and internal attack surface — find every service that is reachable from the network, identify services that should not be exposed, detect version-specific vulnerabilities (via NSE vuln scripts), and produce evidence of network exposure for compliance." },
          { text: "When to use:", detail: "Before and after firewall rule changes to verify intended exposure. For new cloud environments to confirm no services are accidentally public. During periodic external attack surface assessments. When a compliance framework (PCI DSS Req 11.2, CIS Control 4.4) requires network scanning." },
          { text: "How to use: Connections → Add connector → Network (Nmap). Enter target as IP, hostname, or CIDR (e.g. 10.0.0.0/24, api.example.com, 192.168.1.1). Assessments → New Scan → Network tab → select Nmap connector → Start.", detail: "The scan runs with: -Pn (skip host discovery — needed for cloud hosts that block ICMP), -sS SYN scan, -sV service detection, --top-ports 1000, --script='default,safe,vuln', host-timeout 5m." },
          { text: "What to expect: one finding per open port. High-risk ports (RDP 3389, SMB 445, databases 3306/5432/27017, Redis 6379, etc.) are automatically flagged High. Well-known service ports (SSH 22, SNMP 161) are Medium. Unknown open ports are Low. NSE vulnerability scripts (e.g. smb-vuln-ms17-010 EternalBlue) produce separate High findings with the CVE ID." },
          { text: "Severity logic by port:", detail: "Critical: none (port exposure alone is never critical — exploitation requires an additional step). High: RDP, SMB, Telnet, FTP, legacy r-services, databases exposed to the network. Medium: SSH, SNMP, LDAP, VNC. Low: any other open port. NSE vuln script hits override to High/Critical based on CVE severity." },
        ],
        tips: [
          "Scan your external IP(s) first — that's your real perimeter. Then scan internal subnets from within the VPN to find east-west exposure.",
          "For /16 or larger CIDRs, the scan may time out at 30 minutes. Break large ranges into /24 subnets and create one connector per subnet.",
          "Combine Nmap findings with cloud connector findings — Nmap tells you what's exposed on the wire; Azure/AWS connector tells you whether the NSG/Security Group rule was intentional.",
        ],
        warnings: [
          "Port scanning may be blocked or logged by cloud provider abuse detection systems. Azure, AWS, and GCP permit scanning your own resources but require you to notify them for aggressive scans against third-party infrastructure.",
          "The SYN scan (-sS) requires root privileges. GitHub Actions runners have sudo — this works correctly in the workflow. Do not attempt to run Nmap manually without root if you want accurate results.",
        ],
      },
      {
        id: "tool-semgrep",
        title: "Semgrep — Static Application Security Testing (SAST)",
        summary: "Semgrep is a fast, lightweight static analysis tool that finds security bugs in source code by pattern-matching against a library of rules. It supports 30+ languages and can detect injection flaws, insecure API usage, hardcoded secrets, and OWASP Top 10 patterns without executing the code.",
        steps: [
          { text: "Purpose: find security bugs in source code before they reach production. Semgrep excels at finding patterns like: SQL queries built from user input, use of dangerous functions (eval, exec, pickle.loads), hardcoded credentials, insecure random number generators, missing input validation, and framework-specific vulnerabilities (Flask debug mode, Django CSRF disabled, etc.)." },
          { text: "When to use:", detail: "On every code repository that contains application logic. Especially valuable for: new repositories before their first scan, after adding new libraries or frameworks, when fixing a security bug (verify the fix pattern is correct), and as a gating check in CI/CD." },
          { text: "How to use: Connections → Add connector → SAST (Semgrep). Enter the Git repository URL. For private repos, add a Git Personal Access Token. Assessments → New Scan → SAST tab → Semgrep → Start.", detail: "The workflow clones the repo and runs the Semgrep 'auto' ruleset which automatically selects the best rules for detected languages. Output is SARIF format, parsed into findings." },
          { text: "What to expect: findings are at the file:line level — each finding includes the exact file path, line number (in the description), the matched code pattern, and a remediation explanation. Severity ranges from Critical (RCE patterns) to Info (style suggestions)." },
          { text: "Languages supported best: Python, JavaScript/TypeScript, Go, Java, Ruby, PHP, C/C++, Rust, Kotlin, Scala. Limited support: Swift, Dart, Lua." },
        ],
        tips: [
          "Semgrep 'auto' mode picks the right rules automatically. For specific coverage (e.g. only OWASP Top 10, or only secrets), the rule set can be customised in the workflow YAML.",
          "False positive rate is low compared to older SAST tools because Semgrep matches on AST patterns not regex — it understands code structure. Still review each High/Critical finding before closing as false positive.",
          "Run Semgrep on your most critical repositories first: authentication services, payment processing, API gateways, anything that handles PII.",
        ],
        warnings: [
          "Semgrep does not execute code — it cannot detect runtime vulnerabilities like broken access control, IDOR, or business logic flaws. Use ZAP for those.",
          "Very large monorepos (millions of lines) may hit the 60-minute workflow timeout. Use path filters in the connector config to scope to specific directories.",
        ],
      },
      {
        id: "tool-codeql",
        title: "CodeQL — Deep Semantic Code Analysis (SAST)",
        summary: "CodeQL is GitHub's enterprise-grade static analysis engine. Unlike pattern-matching tools, CodeQL builds a full semantic model of your code — data flows, call graphs, type information — and then runs queries against that model to find vulnerabilities that span multiple files and function calls.",
        steps: [
          { text: "Purpose: find complex, multi-hop vulnerabilities that Semgrep misses: data flows from user input across function boundaries to a sink (SQL query, shell command, file write), second-order injection, deserialization vulnerabilities, and path traversal through indirect function calls. CodeQL is significantly more thorough than Semgrep but slower." },
          { text: "When to use:", detail: "For high-value repositories where deep coverage justifies longer scan time. Pre-release security gate for major versions. When a pentest or bug bounty finds an injection vulnerability — CodeQL can find similar patterns across the whole codebase. For Java, C#, C/C++, Go, Python, Ruby, Swift, Kotlin (best language coverage of any SAST tool)." },
          { text: "How to use — Source mode: Connections → Add connector → SAST (CodeQL). Enter Git repo URL. Assessments → New Scan → SAST tab → CodeQL → select Source mode → Start. The workflow clones and builds the code.", detail: "How to use — Binary mode (no source): Assessments → New Scan → SAST tab → CodeQL → select Upload Binary → attach JAR/WAR/EAR/DLL/EXE (max 500 MB). CodeQL analyses bytecode with --build-mode=none. Useful for vendor binaries or compiled artifacts." },
          { text: "What to expect: findings include the full data flow path — entry point → intermediate steps → sink. Each finding shows which variable carried tainted data and where it was used unsafely. This level of detail makes findings very actionable. A typical scan of 50k–200k LOC takes 10–25 minutes." },
          { text: "Query suite used: CodeQL Standard Security (150+ queries) covering OWASP Top 10, CWE Top 25, SQL injection, XSS, path traversal, SSRF, code injection, deserialization, and more." },
        ],
        tips: [
          "CodeQL is slower than Semgrep but produces fewer false positives and finds deeper bugs. Use Semgrep for fast feedback in PRs; use CodeQL for scheduled deep scans.",
          "Binary analysis works best on Java/Kotlin bytecode. C# IL works but with less query coverage. Stripped native binaries (.so/.dylib without debug symbols) yield almost nothing.",
          "CodeQL requires the code to compile for source mode. If your repo has build dependencies not available in the GitHub runner, the scan will fail. The binary upload path sidesteps this.",
        ],
        warnings: [
          "CodeQL source scan requires the repository to be compilable. Missing build tools, private package registries, or complex build systems can cause the workflow to fail before analysis begins.",
          "The 500 MB binary upload limit is hard. For large JARs, extract only the application JARs (excluding third-party dependencies) before uploading.",
        ],
      },
      {
        id: "tool-gitleaks",
        title: "Gitleaks — Git History Secret Scanning",
        summary: "Gitleaks scans your entire Git repository history — every commit, every branch — for secrets that were ever committed: API keys, passwords, connection strings, private keys, OAuth tokens, AWS/Azure/GCP credentials, and more. It finds secrets even if they were deleted in a later commit.",
        steps: [
          { text: "Purpose: detect secrets that were committed to source control. This is one of the most common causes of credential compromise — a developer commits a .env file or API key 'temporarily' and it becomes permanently embedded in git history even after deletion. Gitleaks finds these historical exposures." },
          { text: "When to use:", detail: "On every repository immediately — this should be one of the first scans you run. Before making a private repository public. After a developer incident where credentials may have been committed. As a continuous check: schedule it monthly to catch new secrets committed since the last scan." },
          { text: "How to use: Connections → Add connector → Secrets (Gitleaks). Enter the Git repository URL and a Personal Access Token for private repos. Assessments → New Scan → Secrets tab → Gitleaks → Start.", detail: "The workflow clones the full history (not --depth 1) so all commits are scanned. Gitleaks uses its built-in ruleset plus a generic high-entropy string detector." },
          { text: "What to expect: each finding is one secret match — the rule that matched (e.g. 'aws-access-token', 'generic-api-key'), the file path, the commit hash, the author, the date, and a redacted preview of the secret. Severity is High for all findings (any committed secret is a High finding — rotate immediately)." },
          { text: "What happens after a finding: the secret must be rotated (invalidated) in the originating system immediately. Then remove it from git history using `git filter-repo` or BFG Repo-Cleaner. Simply deleting it in a new commit is NOT sufficient — the secret remains in every prior commit." },
        ],
        tips: [
          "Treat every Gitleaks High finding as a confirmed breach of that credential until you verify the credential has been rotated. There is no 'it was only in git for a few minutes' — bots scrape GitHub commits in real time.",
          "After rotating a credential, update the finding status to 'remediated' and add a comment with the rotation date and ticket reference.",
          "Use Gitleaks + TruffleHog together — they use different rule sets and different detection algorithms. Running both catches more secrets.",
        ],
        warnings: [
          "Gitleaks findings are always High. Do not accept or suppress them without first verifying the credential has been rotated and is no longer valid.",
          "For very large repositories with deep history (10,000+ commits), the scan may take 20–30 minutes. The 60-minute workflow timeout should still be sufficient.",
        ],
      },
      {
        id: "tool-trufflehog",
        title: "TruffleHog — Deep Secret & Credential Scanning",
        summary: "TruffleHog goes further than Gitleaks by using a verification step — it attempts to validate discovered secrets against their originating services (AWS STS, GitHub API, Stripe, Slack, etc.) to confirm whether the secret is still active. It also uses entropy analysis and 700+ detectors to find secrets Gitleaks might miss.",
        steps: [
          { text: "Purpose: find and verify active secrets in git history. TruffleHog's verification feature distinguishes between rotated (dead) credentials and still-active ones — letting you prioritise which findings need immediate action vs. historical cleanup." },
          { text: "When to use:", detail: "Run TruffleHog alongside Gitleaks on every repository — they complement each other. TruffleHog is especially valuable when you have a large finding backlog and need to know which secrets are still live. Also use it on public repositories where secrets may have been exposed publicly." },
          { text: "How to use: Connections → Add connector → Secrets (TruffleHog). Enter the Git repository URL and PAT for private repos. Assessments → New Scan → Secrets tab → TruffleHog → Start. Output includes a Verified flag per finding." },
          { text: "What to expect: findings are similar to Gitleaks but with a Verified field. Verified=true means TruffleHog successfully authenticated with that credential — it is confirmed live and must be rotated immediately. Verified=false means it detected the pattern but couldn't confirm liveness (the credential may still be valid, or the service may not support verification)." },
          { text: "Detectors: 700+ built-in detectors covering AWS, GitHub, GitLab, Stripe, Twilio, SendGrid, Slack, Discord, Shopify, Jira, Azure, GCP, and hundreds more service-specific formats." },
        ],
        tips: [
          "Prioritise Verified=true findings above everything else — these are confirmed live credentials. Rotate them before closing the browser window.",
          "Verified=false findings still need investigation — TruffleHog may not have verification support for that service type, or the service may have rate-limited the check.",
          "Run both Gitleaks and TruffleHog. Gitleaks has faster rule matching and better generic patterns; TruffleHog has broader service-specific detectors and live verification.",
        ],
        warnings: [
          "TruffleHog's verification feature makes real API calls to third-party services. This is intentional — it's how it confirms liveness. These calls are read-only authentication attempts.",
          "Do not add TruffleHog findings to a public report without redacting the secret value. Even a partial key is sensitive.",
        ],
      },
      {
        id: "tool-trivy",
        title: "Trivy — Container & Dependency Vulnerability Scanner",
        summary: "Trivy scans container images, filesystems, and Git repositories for known CVEs in OS packages (Alpine, Debian, Ubuntu, RHEL) and language-specific dependencies (pip, npm, Maven, Go modules, Cargo, NuGet). It also detects IaC misconfigurations and exposed secrets.",
        steps: [
          { text: "Purpose: find CVEs in your container base images and application dependencies. A container image built from `ubuntu:20.04` may contain hundreds of vulnerable OS packages. A Node.js application may have transitive npm dependencies with known CVEs. Trivy finds both." },
          { text: "When to use:", detail: "On every container image before it is pushed to a registry or deployed. After updating a base image or major dependency. On a scheduled basis (weekly) because new CVEs are published daily against packages that were previously clean. As a gate in CI/CD: fail builds with Critical CVEs." },
          { text: "How to use: Connections → Add connector → Container (Trivy). Enter a container image reference (e.g. nginx:latest, myrepo/myapp:1.2.3, ghcr.io/org/app:sha-abc123) or a Git repo URL for filesystem scanning. Assessments → New Scan → select Trivy connector → Start." },
          { text: "What to expect: findings include the CVE ID, affected package, installed version, fixed version, CVSS score, and severity. Trivy outputs are NVD-sourced so CVSS scores are accurate. A typical production image has 5–50 findings; an old unpatched image may have 200+." },
          { text: "Severity: Trivy maps NVD CVSS v3 base score to Critical (9.0+), High (7.0–8.9), Medium (4.0–6.9), Low (<4.0), Unknown (no CVSS available). These map directly to Monitara severities." },
        ],
        tips: [
          "Always scan the exact image tag you deploy — `nginx:latest` changes over time. Pin to a specific SHA for reproducible results.",
          "Filter by 'fixed version available' — vulnerabilities without a fix cannot be patched and require compensating controls instead. Focus remediation effort on CVEs with a known fix first.",
          "For distroless images (minimal OS): Trivy still scans language package manifests inside the image (requirements.txt, package-lock.json, pom.xml). You won't see OS CVEs but will see dependency CVEs.",
        ],
        warnings: [
          "A 'clean' Trivy scan means no known CVEs in the NVD database at scan time — not that the image is vulnerability-free. Zero-day CVEs are not in any database by definition.",
          "Large images (>2 GB) can hit the GitHub Actions runner's disk limit. Use the filesystem scan mode on the repo instead of pulling the full image if this occurs.",
        ],
      },
      {
        id: "tool-owasp-dc",
        title: "OWASP Dependency-Check — Library CVE Scanner (SCA)",
        summary: "OWASP Dependency-Check is a Software Composition Analysis (SCA) tool that identifies project dependencies and checks whether any contain known CVEs. It supports Java (JAR/WAR/EAR), .NET, JavaScript (npm), Python (requirements.txt), Ruby, PHP, and more.",
        steps: [
          { text: "Purpose: detect vulnerable third-party libraries used by your application. Your code may be perfectly written but if you depend on log4j 2.14 (Log4Shell CVE-2021-44228) or OpenSSL 3.0.1 (CVE-2022-0778), you are vulnerable. OWASP DC finds these supply chain risks." },
          { text: "When to use:", detail: "On every application repository that has a dependency manifest (pom.xml, package.json, requirements.txt, Gemfile, composer.json, build.gradle). Run after every dependency update. Run weekly as a scheduled check because new CVEs are published against existing versions daily." },
          { text: "How to use: Connections → Add connector → Dependency (OWASP DC). Enter the Git repository URL. Assessments → New Scan → Dependency tab → OWASP DC → Start. The workflow clones the repo and runs dependency-check against all detected manifests.", detail: "OWASP DC downloads the NVD data feed on first run (cached in the workflow). Subsequent runs use the cached feed and run much faster." },
          { text: "What to expect: findings include the vulnerable library name, version, CVE ID, CVSS score, description, and evidence of how DC identified the dependency (filename + manifest location). One finding per CVE per library — a single old library may produce 5–10 findings." },
          { text: "Difference vs Trivy: OWASP DC is purpose-built for application dependencies and has deeper Java/Maven/Gradle support. Trivy excels at container OS packages. Use both for complete coverage." },
        ],
        tips: [
          "The most important field is 'fixed version' — upgrade to that version to remediate. If there is no fix, evaluate whether the vulnerable feature is used by your code (many CVEs are in components you may not call).",
          "OWASP DC can produce false positives — it sometimes matches a library by filename heuristic rather than confirmed content. Always verify the library version in your manifest before treating as confirmed.",
          "For Java: ensure the pom.xml or build.gradle is present in the repo root. DC resolves transitive dependencies by reading the manifest — it does not require a `mvn install` to work.",
        ],
        warnings: [
          "OWASP DC requires an NVD API key for reliable data feed downloads (rate limiting was introduced in 2024). Without it, the first run may fail or take very long. Configure the NVD_API_KEY as a GitHub Actions secret if feed download failures occur.",
          "Do not filter out Medium CVEs without review — many supply chain attacks exploit Medium-severity vulnerabilities that are widely ignored.",
        ],
      },
      {
        id: "tool-nuclei",
        title: "Nuclei — Template-Based Vulnerability Scanner",
        summary: "Nuclei is a fast, community-driven vulnerability scanner from ProjectDiscovery that runs thousands of templates covering CVEs, misconfigurations, exposed admin panels, default credentials, and more. Every Nuclei template is a PoC — a finding means the vulnerability was actually confirmed, not just hypothesised.",
        steps: [
          { text: "Purpose: scan web applications, APIs, and network hosts for specific, known vulnerabilities using proof-of-concept templates. Unlike ZAP which probes for vulnerability classes generically, Nuclei checks for specific CVEs (e.g. CVE-2021-44228 Log4Shell, CVE-2022-26134 Confluence RCE) and misconfigs by name. When Nuclei fires, the finding is confirmed." },
          { text: "When to use:", detail: "After new critical CVEs are published — Nuclei templates for major CVEs are typically available within 24–48 hours of disclosure. For exposed services where you want to confirm whether a specific vulnerability applies. For discovery of exposed admin panels, default credentials, and debug endpoints. As a complement to ZAP for web targets." },
          { text: "How to use: Connections → Add connector → Network (Nuclei). Enter the target URL or hostname. Assessments → New Scan → Network tab → Nuclei → Start.", detail: "Template sets run: network, http, ssl, default-login, misconfiguration, and cves. Templates are updated on every run (nuclei -update-templates). Timeout per request: 10 seconds. 25 concurrent threads." },
          { text: "What to expect: findings map directly to specific CVE IDs or misconfig types. Each finding includes the template name, what matched (the matched-at URL or host), severity from the template author, and extracted results. A low-finding-count result is often better than ZAP — Nuclei prioritises precision over coverage." },
          { text: "Template count at time of writing: 9,000+ templates. New templates added daily by the ProjectDiscovery community. Most impactful template sets: cves (confirmed CVE exploits), default-login (common default credentials), exposed-panels (admin interfaces), misconfiguration (CORS, SSRF, header issues)." },
        ],
        tips: [
          "Nuclei findings have very low false-positive rates — if a template fires, the vulnerability is confirmed. Treat every Nuclei High/Critical as requiring immediate action.",
          "The default-login template set checks for default credentials (admin/admin, admin/password) on common services — databases, Kubernetes dashboards, Jenkins, Grafana, etc. Always run this on new environments.",
          "Use Nuclei + ZAP together: ZAP finds broad vulnerability classes through active fuzzing; Nuclei confirms specific named CVEs. They complement each other perfectly.",
        ],
        warnings: [
          "Nuclei sends real attack payloads to confirm vulnerabilities. Do not run against production systems you don't own without written authorisation. The confirmed-exploit nature means some templates will trigger WAF alerts and IDS signatures.",
          "The CVE template set includes templates for critical vulnerabilities (Log4Shell, ProxyLogon, EternalBlue over web). These are genuine exploitation attempts — run only against your own targets in controlled environments.",
          "Template updates happen on every run. Occasionally a new community template may produce false positives. Pin to a specific Nuclei version in the workflow if scan-over-scan consistency is critical.",
        ],
      },
      {
        id: "tool-checkov",
        title: "Checkov — Infrastructure-as-Code Security Scanner",
        summary: "Checkov scans Infrastructure-as-Code files — Terraform, CloudFormation, Kubernetes manifests, Helm charts, Dockerfiles, Bicep, ARM templates, and more — for security misconfigurations before resources are provisioned. It catches cloud misconfigs at the PR stage, not after deployment.",
        steps: [
          { text: "Purpose: prevent cloud misconfigurations from ever being deployed. Checkov finds issues like: S3 buckets without encryption or public-access blocking, security groups with 0.0.0.0/0 ingress on sensitive ports, EC2 instances without IMDSv2 enforced, RDS without deletion protection, Kubernetes pods running as root, Dockerfiles using root user, missing network policies, unencrypted EBS volumes." },
          { text: "When to use:", detail: "On every IaC repository. Run Checkov before any Terraform apply or CloudFormation deploy. Especially important for: new environments being built from scratch, repositories where multiple developers push IaC changes, legacy IaC that has never been security-reviewed, and before cloud compliance audits (PCI DSS, ISO 27001, CIS Benchmarks)." },
          { text: "How to use: Connections → Add connector → SAST (Checkov). Enter the Git repository URL containing IaC files. For private repos, add a Personal Access Token. Assessments → New Scan → SAST tab → Checkov → Start.", detail: "Checkov auto-detects file types and runs the relevant checks. It scans the entire repo directory including subdirectories. Checks are mapped to CIS, NIST, SOC 2, PCI DSS, and ISO 27001 controls." },
          { text: "What to expect: findings are keyed by Check ID (e.g. CKV_AWS_18 — S3 access logging enabled, CKV_K8S_30 — containers not running as root). Each finding shows the resource name, file path, and a link to the Bridgecrew guideline explaining why it matters and how to fix it.", detail: "Typical finding volume: a mature Terraform codebase may have 20–100 Checkov findings. A greenfield IaC repo being security-reviewed for the first time may have 200–500." },
          { text: "IaC types supported: Terraform (HCL), AWS CloudFormation, Azure ARM/Bicep, Google Cloud Deployment Manager, Kubernetes YAML, Helm, Dockerfile, GitHub Actions workflows, Ansible, Serverless Framework, Kustomize." },
        ],
        tips: [
          "Start with the CRITICAL and HIGH findings — these represent misconfigs that directly enable data exposure or privilege escalation (public S3 buckets, world-open security groups, unencrypted databases).",
          "Many Checkov findings can be suppressed inline with a comment (# checkov:skip=CKV_AWS_18:reason) when the control genuinely doesn't apply. Document the business reason — auditors will ask.",
          "Checkov findings map to compliance controls — use the Control Deficiencies view after running the Compliance Monitor agent to see which Checkov findings are failing specific ISO 27001 or CIS Benchmark controls.",
        ],
        warnings: [
          "Checkov checks infrastructure configuration, not runtime behaviour. A Checkov-clean Terraform codebase may still be misconfigured at runtime if manual changes were made in the console after deployment.",
          "Checkov does not execute Terraform plan — it reads the HCL source. Dynamic values (variables, data sources, locals) that resolve at plan time may cause some checks to produce false positives or miss issues.",
        ],
      },
      {
        id: "tool-sslyze",
        title: "SSLyze — TLS/SSL Configuration Auditor",
        summary: "SSLyze is a Python-based TLS configuration analysis tool that connects to a live HTTPS/TLS endpoint and reports its full configuration: accepted protocol versions, cipher suites, certificate validity, and vulnerability to attacks like Heartbleed, ROBOT, and POODLE. It produces a compliance-ready TLS posture report.",
        steps: [
          { text: "Purpose: audit the TLS configuration of any HTTPS service — web servers, APIs, mail servers (STARTTLS), databases with TLS — and detect: deprecated protocol versions (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1), weak cipher suites (RC4, 3DES, EXPORT-grade, NULL ciphers), certificate issues (expired, self-signed, hostname mismatch, weak key size), and specific TLS vulnerabilities (Heartbleed CVE-2014-0160, ROBOT, CRIME/TLS compression, missing Fallback SCSV)." },
          { text: "When to use:", detail: "Before any compliance audit that checks TLS (PCI DSS Req 4.2, NIST SP 800-52 Rev 2, ISO 27001 A.10.1). After certificate renewal to confirm the new cert is correctly deployed. When users or security testers report TLS errors. After changing web server or load balancer TLS configuration. Quarterly as part of a certificate expiry monitoring programme." },
          { text: "How to use: Connections → Add connector → Network (SSLyze). Enter the target as hostname or hostname:port (default port is 443 if not specified, e.g. api.example.com or mail.example.com:465). Assessments → New Scan → Network tab → SSLyze → Start." },
          { text: "What to expect: findings cover up to 8 issue categories.", detail: "Critical: Heartbleed (server leaks memory), ROBOT (RSA decryption oracle). High: SSL 2.0/3.0 accepted (broken protocols), expired certificate, certificate hostname mismatch. Medium: TLS 1.0/1.1 accepted (deprecated), weak ciphers (RC4/3DES/EXPORT/NULL), TLS compression enabled (CRIME attack). Low: TLS 1.3 not offered (informational — TLS 1.2 only)." },
          { text: "A clean scan with no findings means: TLS 1.2 + 1.3 only, strong cipher suites, valid cert, no known TLS vulnerabilities. This is the target state for any public-facing service." },
        ],
        tips: [
          "Run SSLyze on all externally facing services: web apps, APIs, mail servers (ports 25/465/587), FTPS (990), LDAPS (636). TLS misconfigs are pervasive — most organisations find multiple issues on first scan.",
          "PCI DSS requires TLS 1.2 minimum — any finding of SSL/TLS 1.0/1.1 accepted is a direct PCI compliance failure. Fix by disabling the protocol in your web server config (nginx: ssl_protocols TLSv1.2 TLSv1.3).",
          "Certificate expiry findings include the exact number of days remaining. Use this to prioritise renewals — set up monitoring alerts at 30 and 7 days before expiry.",
        ],
        warnings: [
          "SSLyze performs a real TLS handshake with the target — it is not passive. Ensure the target is reachable from GitHub Actions runners (public internet or configured VPN). Internal-only services cannot be scanned.",
          "Some legacy systems (old Java keystores, ancient load balancers) reject SSLyze's TLS handshake and the scan fails. In those cases, use OpenSSL or nmap --script ssl-enum-ciphers for compatibility.",
          "Heartbleed and ROBOT checks involve sending specific malformed TLS records to the server. These are safe — they detect the vulnerability without exploiting it — but may appear in server logs as anomalous TLS connections.",
        ],
      },
      {
        id: "tool-ai-code-review",
        title: "AI Code Review — LLM-Powered Security Analysis",
        summary: "AI Code Review uses a 4-phase LLM pipeline to review source code for security vulnerabilities with the depth of a manual code review. Unlike rule-based SAST, it understands context — business logic flaws, missing authorisation checks, and subtle vulnerabilities that no pattern can detect.",
        steps: [
          { text: "Purpose: simulate a senior security engineer manually reviewing your code. It catches what Semgrep and CodeQL miss: missing ownership checks (IDOR), business logic bypasses, trust boundary violations, insecure design patterns, and context-dependent vulnerabilities that require understanding what the code is supposed to do." },
          { text: "When to use:", detail: "For the most security-sensitive repositories: authentication services, payment flows, authorisation middleware, admin APIs. For code that was never security-reviewed before. When a pentest finds a logical vulnerability and you want to find similar patterns. When you need to brief a client on code-level security findings." },
          { text: "How to use — Git repo: Connections → Add connector → SAST (AI Code Review). Enter Git repo URL. Assessments → New Scan → SAST tab → AI Code Review → Start. The platform clones, chunks, and analyses.", detail: "How to use — Archive upload: Assessments → New Scan → SAST tab → AI Code Review → Upload ZIP/tar.gz → select archive → Start. Maximum 500 MB. Useful for codebases without a public Git remote." },
          { text: "Pipeline phases:", detail: "Phase 1 — Triage: risk-scores every file by language, naming, imports, and structural heuristics. Only the top-risk files proceed to deep analysis. Phase 2 — Per-function review: analyses each function in isolation for vulnerabilities. Phase 3 — Self-critique: re-reads its own findings and removes false positives. Phase 4 — Cross-file taint tracing: traces data flows across file boundaries to find multi-hop vulnerabilities." },
          { text: "What to expect: findings are at the function level (resource_id = file path, description includes the function name and line context). Findings include: the vulnerability class, why it's a problem, a code-level explanation, and a concrete remediation suggestion. A medium-sized codebase (10k–50k LOC) typically produces 10–40 findings." },
        ],
        tips: [
          "AI Code Review is not a replacement for Semgrep/CodeQL — it complements them. Run all three: Semgrep for speed, CodeQL for depth, AI Code Review for context and business logic.",
          "Output quality scales with LLM quality. Use GPT-4o, claude-opus-4, or gemini-1.5-pro for best results. Smaller models produce more false positives and miss subtle issues.",
          "The triage phase skips test files, documentation, and generated code by default. If your test infrastructure handles secrets or sensitive operations, include it explicitly.",
        ],
        warnings: [
          "AI Code Review sends your source code to the configured LLM provider's API. Ensure your LLM provider agreement permits this for your codebase's sensitivity level. Use Azure OpenAI for regulated data — it stays within your Azure tenant.",
          "LLM-based analysis can produce false positives — treat Critical/High findings as 'requires human verification' rather than 'confirmed vulnerability'. The self-critique phase reduces but doesn't eliminate false positives.",
        ],
      },
      {
        id: "tool-enterprise",
        title: "Enterprise Scanners — Tenable, Burp Suite, Snyk, Rapid7, Qualys, Invicti, Acunetix",
        summary: "Enterprise scanners connect Monitara to your existing commercial security tools via their REST APIs. They run directly (not via GitHub Actions) and can access internal networks, authenticated targets, and full vulnerability management platforms. Results are normalised and appear in Monitara alongside findings from all other scanners.",
        steps: [
          { text: "Tenable.io — Vulnerability Management:", detail: "Purpose: enterprise-grade VM platform with 100,000+ plugins covering network, web, and cloud. When to use: you already have Tenable deployed and want findings in Monitara for correlation with SAST/DAST results. Credentials: access_key + secret_key. What to expect: Tenable pulls all active vulnerability findings from your configured assets. CVSS scores and KEV status are already enriched." },
          { text: "Burp Suite Enterprise — Authenticated DAST:", detail: "Purpose: the commercial version of Burp Suite's web scanner — deeper than ZAP for complex authenticated web apps. When to use: for critical web applications requiring authenticated scanning with complex session management. Credentials: host URL + API key. What to expect: web vulnerabilities with full request/response evidence, similar to ZAP but with greater depth on business-logic issues." },
          { text: "Snyk — Developer-First SCA + SAST:", detail: "Purpose: dependency vulnerability scanning across all org projects (npm, pip, Maven, Go, Nuget, Ruby). When to use: if developers use Snyk in their IDEs and you want central visibility in Monitara. Credentials: api_token + org_id. What to expect: one scan pulls all projects in the org (capped at 50). Findings include fix PRs and patch availability." },
          { text: "Rapid7 InsightVM — Network Vulnerability Management:", detail: "Purpose: network-based VM similar to Tenable. When to use: if InsightVM is your existing VM platform. Credentials: host URL + username + password + site_id. What to expect: findings from the specified scan site. CVSS v2 and v3 both ingested; v3 preferred." },
          { text: "Qualys VMDR — Cloud-Based Vulnerability Management:", detail: "Purpose: SaaS VM platform. When to use: if Qualys is your existing VM tool. Two modes: (1) Import existing detections (no target needed — pulls all active findings from your Qualys account), (2) Launch new scan (requires targets configured). Credentials: api_url + username + password. Also pulls Qualys TotalCloud CSPM findings if that module is enabled." },
          { text: "Invicti (Netsparker) / Acunetix — Proof-Based DAST:", detail: "Purpose: proof-based web app scanners that only report vulnerabilities with PoC evidence (no false positives by design). When to use: for web applications where ZAP/Burp produce too many unverified findings. Credentials: base_url + api_token (Invicti: Basic auth; Acunetix: API key header). Both require the scanner instance to be reachable from Monitara backend." },
          { text: "All enterprise scanners: Assessments → New Scan → Enterprise Scanners tab → pick tool → pick connector → Start. Scans run asynchronously — Monitara polls the external tool every 30 seconds (2-hour timeout). Severity is normalised to critical/high/medium/low/info regardless of source tool's native scale." },
        ],
        tips: [
          "Enterprise scanners don't require GitHub Actions or the MONITARA_API_URL secret — they run as FastAPI BackgroundTasks calling the external tool's API directly.",
          "Qualys import mode (no target) is the fastest way to get existing VM data into Monitara — it pulls all active detections in one API call with no scan scheduling needed.",
          "Use enterprise scanner findings as the 'ground truth' vulnerability baseline and run Monitara's AI agents (Risk Manager, Threat Intel, Remediation) on top of them for enriched analysis.",
        ],
        warnings: [
          "Enterprise scans launch real scans in external tools — Tenable, Qualys, and Rapid7 scans consume quota/credits in those platforms. Coordinate with your existing VM team before triggering scans.",
          "Acunetix uses self-signed TLS by default on on-prem installations — the connector disables certificate verification (verify=False) for the API connection. Ensure network access to the Acunetix server is restricted.",
        ],
      },
    ],
  },
];

// ── helpers ──────────────────────────────────────────────────────────────────

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
            <Typography variant="caption" sx={{ display: "block", color: "text.secondary", mt: 0.25, fontStyle: "italic" }}>
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
        borderRadius: "8px !important",
        "&:before": { display: "none" },
        "&.Mui-expanded": { borderColor: `${color}40` },
        mb: 1,
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

function TabPanel({ value, index, children }: { value: number; index: number; children: React.ReactNode }) {
  return value === index ? <Box sx={{ flexGrow: 1, overflow: "auto", p: 3 }}>{children}</Box> : null;
}

function GroupPanel({ group, query }: { group: Group; query: string }) {
  const q = query.trim().toLowerCase();
  const topics = q
    ? group.topics.filter((t) =>
        t.title.toLowerCase().includes(q) ||
        t.summary.toLowerCase().includes(q) ||
        t.steps.some((s) => s.text.toLowerCase().includes(q) || (s.detail || "").toLowerCase().includes(q))
      )
    : group.topics;

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2.5 }}>
        <Box sx={{
          width: 38, height: 38, borderRadius: 1.5, bgcolor: `${group.color}18`,
          display: "flex", alignItems: "center", justifyContent: "center", color: group.color,
        }}>
          {group.icon}
        </Box>
        <Box>
          <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1, color: "text.primary", fontSize: 17 }}>
            {group.title}
          </Typography>
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            {topics.length} topic{topics.length !== 1 ? "s" : ""}
            {q ? ` matching "${query}"` : ""}
          </Typography>
        </Box>
      </Box>

      {topics.length === 0 ? (
        <Alert severity="warning" sx={{ bgcolor: "rgba(251,188,4,0.08)", border: "1px solid rgba(251,188,4,0.3)", color: "text.primary" }}>
          No topics match "{query}" in this section. Try a different keyword or clear the search.
        </Alert>
      ) : (
        topics.map((t) => <TopicBlock key={t.id} topic={t} color={group.color} />)
      )}
    </Box>
  );
}

export default function Help() {
  const [tab, setTab] = useState(0);
  const [query, setQuery] = useState("");

  const matchCounts = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return GROUPS.map(() => null);
    return GROUPS.map((g) =>
      g.topics.filter((t) =>
        t.title.toLowerCase().includes(q) ||
        t.summary.toLowerCase().includes(q) ||
        t.steps.some((s) => s.text.toLowerCase().includes(q) || (s.detail || "").toLowerCase().includes(q))
      ).length
    );
  }, [query]);

  return (
    <Box sx={{ display: "flex", height: "100%", gap: 0 }}>
      {/* Left sidebar */}
      <Box sx={{
        width: 210, flexShrink: 0,
        borderRight: "1px solid", borderColor: "divider",
        display: "flex", flexDirection: "column",
      }}>
        <Typography variant="overline" sx={{
          display: "block", px: 2, pt: 2, pb: 1,
          color: "text.secondary", fontSize: 10, fontWeight: 700, letterSpacing: 1,
        }}>
          Platform Guide
        </Typography>

        <Box sx={{ px: 1.5, pb: 1 }}>
          <TextField
            size="small"
            placeholder="Search…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            slotProps={{
              input: {
                startAdornment: (
                  <Search sx={{ color: "text.secondary", fontSize: 16, mr: 0.5 }} />
                ),
              },
            }}
            sx={{
              width: "100%",
              "& .MuiOutlinedInput-root": {
                color: "text.primary", fontSize: 13,
                "& fieldset": { borderColor: "divider" },
                "&:hover fieldset": { borderColor: "divider" },
                "&.Mui-focused fieldset": { borderColor: "#4285F4" },
              },
              "& .MuiInputAdornment-root": { mr: 0 },
            }}
          />
        </Box>

        <Tabs
          orientation="vertical"
          value={tab}
          onChange={(_, v) => setTab(v)}
          sx={{
            flexGrow: 1, overflow: "auto",
            "& .MuiTabs-indicator": { left: 0, width: 3 },
            "& .MuiTab-root": {
              alignItems: "flex-start", textAlign: "left", textTransform: "none",
              fontSize: 12.5, minHeight: 38, px: 2, py: 0.75,
              justifyContent: "flex-start",
            },
          }}
        >
          {GROUPS.map((g, i) => (
            <Tab
              key={g.id}
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                  <Box sx={{ color: tab === i ? g.color : "text.secondary", display: "flex" }}>
                    {g.icon}
                  </Box>
                  <Box component="span" sx={{ flexGrow: 1 }}>{g.navLabel}</Box>
                  {matchCounts[i] !== null && (
                    <Box component="span" sx={{
                      fontSize: 10, fontWeight: 700,
                      bgcolor: matchCounts[i]! > 0 ? "#4285F420" : "rgba(255,255,255,0.05)",
                      color: matchCounts[i]! > 0 ? "#4285F4" : "text.disabled",
                      borderRadius: 1, px: 0.75, py: 0.25, lineHeight: 1.4,
                    }}>
                      {matchCounts[i]}
                    </Box>
                  )}
                </Box>
              }
            />
          ))}
        </Tabs>

        <Box sx={{ px: 2, py: 1.5, borderTop: "1px solid", borderColor: "divider" }}>
          <Alert
            severity="info"
            icon={<SettingsSuggest sx={{ fontSize: 14 }} />}
            sx={{
              p: 1, bgcolor: "rgba(66,133,244,0.06)",
              border: "1px solid rgba(66,133,244,0.2)",
              "& .MuiAlert-message": { fontSize: 11, lineHeight: 1.4 },
              "& .MuiAlert-icon": { mr: 0.5, py: 0 },
            }}
          >
            API reference at <code style={{ fontSize: 10 }}>/api/docs</code>
          </Alert>
        </Box>
      </Box>

      {/* Content panels */}
      {GROUPS.map((g, i) => (
        <TabPanel key={g.id} value={tab} index={i}>
          <GroupPanel group={g} query={query} />
        </TabPanel>
      ))}
    </Box>
  );
}
