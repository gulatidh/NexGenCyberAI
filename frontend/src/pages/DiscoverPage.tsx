import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  BugReport, FindInPage, SmartToy, TrendingUp, Storage, Devices, Radar, GpsFixed,
} from "@mui/icons-material";
const ic = (color: string) => ({ color, fontSize: 16 } as const);

export const DISCOVER_SECTION: SectionDef = {
  num: "02", label: "Discover", color: "#0f766e",
  title: "Find what's actually exposed",
  sub: "Scan the environment via inbuilt scanners, enterprise integrations, or an AI-guided conversation.",
  info: "CVE enrichment and severity scoring run automatically after each scan. Import results from external scanners via the Import tab in Assessments.",
  stats: [
    { label: "Total Findings",  field: "total_findings",   color: "#0f766e" },
    { label: "Critical",        field: "critical_findings", color: "#b91c1c" },
    { label: "High",            field: "high_findings",    color: "#ea580c" },
    { label: "Total Assets",    field: "total_assets",     color: "#0284c7" },
  ],
  cards: [
    // Scanning
    { name: "Assessments",          icon: <BugReport sx={ic("#4285F4")} />,   desc: "Launch scans, manage versions, and import external scan results.",            route: "/discover/scans",        group: "Scanning" },
    { name: "Findings",             icon: <FindInPage sx={ic("#EA4335")} />,  desc: "All findings with severity, CVE enrichment, and remediation status.",         route: "/discover/findings",     group: "Scanning" },
    { name: "AI Assisted Scan",     icon: <SmartToy sx={ic("#9C27B0")} />,    desc: "Conversational guided assessment — describe the environment, AI configures.", route: "/discover/ai-scan",      group: "Scanning" },
    { name: "Posture Trends",       icon: <TrendingUp sx={ic("#34A853")} />,  desc: "Time-series charts of open findings and audit readiness score.",              route: "/discover/posture",      group: "Scanning" },
    // Assets & CVE
    { name: "Asset Inventory",      icon: <Storage sx={ic("#00BCD4")} />,     desc: "Discovered assets — servers, apps, containers, and cloud resources.",         route: "/discover/assets",       group: "Assets & CVE" },
    { name: "Technology Inventory", icon: <Devices sx={ic("#FF6D00")} />,     desc: "Software stack and technology across all discovered assets.",                 route: "/discover/technologies", group: "Assets & CVE" },
    { name: "CVE Blast Radius",     icon: <Radar sx={ic("#F44336")} />,       desc: "Which assets does a CVE affect? Map the full exposure path.",                 route: "/discover/cve-pivot",    group: "Assets & CVE" },
    { name: "Scan Coverage",       icon: <GpsFixed sx={ic("#FBBC04")} />,    desc: "Assets not scanned within the policy window — identify coverage gaps.",        route: "/discover/coverage",     group: "Assets & CVE" },
  ],
};

export default function DiscoverPage() {
  return <SectionPage section={DISCOVER_SECTION} />;
}
