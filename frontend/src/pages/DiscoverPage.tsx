import SectionPage, { SectionDef } from "../components/SectionPage";

const SECTION: SectionDef = {
  num: "02", label: "Discover", color: "#0f766e",
  title: "Find what's actually exposed",
  sub: "Scan the environment via inbuilt scanners, enterprise integrations, or an AI-guided conversation.",
  info: "CVE enrichment and severity scoring run automatically after each scan. Import results from external scanners via the Import tab in Assessments.",
  stats: [
    { label: "Total Findings",  field: "total_findings",  color: "#0f766e" },
    { label: "Critical",        field: "critical_findings", color: "#b91c1c" },
    { label: "High",            field: "high_findings",   color: "#ea580c" },
    { label: "Total Assets",    field: "total_assets",    color: "#0284c7" },
  ],
  cards: [
    { name: "Assessments",          desc: "Launch scans, manage versions, and import external scan results.",              route: "/vulnerability/scans" },
    { name: "Findings",             desc: "All findings with severity, CVE enrichment, and remediation status.",           route: "/vulnerability/findings" },
    { name: "AI Assisted Scan",     desc: "Conversational guided assessment — describe the environment, AI configures.",   route: "/intelligence/ai-assisted-scan" },
    { name: "CVE Blast Radius",     desc: "Which assets does a CVE affect? Map the full exposure path.",                   route: "/cve-pivot" },
    { name: "Technology Inventory", desc: "Software stack and technology across all discovered assets.",                   route: "/platform/assets/technologies" },
    { name: "Posture Trends",       desc: "Time-series charts of open findings and audit readiness score.",                route: "/vulnerability/posture" },
    { name: "Asset Inventory",      desc: "Discovered assets — servers, apps, containers, and cloud resources.",          route: "/platform/assets" },
    { name: "Pentest Scans",        desc: "Pentest scan sessions with structured findings and red-team evidence.",         route: "/vapt/scans" },
  ],
};

export default function DiscoverPage() {
  return <SectionPage section={SECTION} />;
}
