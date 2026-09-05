import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  BugReport, FindInPage, SmartToy, Storage, Devices,
  Memory, BusinessCenter, UploadFile,
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
    // Assessment
    { name: "Inbuilt Scanners",         icon: <Memory sx={ic("#4285F4")} />,          desc: "Platform-native scanners — DAST, SAST, network, container, and secret scanning.", route: "/discover/inbuilt",       group: "Assessment" },
    { name: "Enterprise Integration",   icon: <BusinessCenter sx={ic("#9C27B0")} />,   desc: "Connect enterprise scanners — Tenable, Burp, Snyk, Rapid7, Qualys, Invicti, Acunetix.", route: "/discover/enterprise",    group: "Assessment" },
    { name: "Import Result",            icon: <UploadFile sx={ic("#34A853")} />,       desc: "Import external scan results from SARIF, Nessus, Burp, OpenVAS, Qualys, and more.", route: "/discover/import-result", group: "Assessment" },
    // Scanning
    { name: "Assessments",          icon: <BugReport sx={ic("#4285F4")} />,   desc: "Launch scans, manage versions, and import external scan results.",            route: "/discover/scans",        group: "Scanning" },
    { name: "Findings",             icon: <FindInPage sx={ic("#EA4335")} />,  desc: "All findings with severity, CVE enrichment, and remediation status.",         route: "/discover/findings",     group: "Scanning" },
    { name: "AI Assisted Scan",     icon: <SmartToy sx={ic("#9C27B0")} />,    desc: "Conversational guided assessment — describe the environment, AI configures.", route: "/discover/ai-scan",      group: "Scanning" },
    // Assets & CVE
    { name: "Asset Inventory",      icon: <Storage sx={ic("#00BCD4")} />,     desc: "Discovered assets — servers, apps, containers, and cloud resources.",         route: "/discover/assets",       group: "Assets & CVE" },
    { name: "Technology Inventory", icon: <Devices sx={ic("#FF6D00")} />,     desc: "Software stack and technology across all discovered assets.",                 route: "/discover/technologies", group: "Assets & CVE" },
  ],
};

export default function DiscoverPage() {
  return <SectionPage section={DISCOVER_SECTION} />;
}
