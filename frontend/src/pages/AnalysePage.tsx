import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  Security, Assessment, SmartToy, AltRoute, Policy, Search, Tune,
  Radar, GpsFixed, TrendingUp,
} from "@mui/icons-material";
const ic = (color: string) => ({ color, fontSize: 16 } as const);

export const ANALYSE_SECTION: SectionDef = {
  num: "03", label: "Analyse", color: "#b45309",
  title: "Turn findings into insight",
  sub: "Score findings, apply FAIR-lite ALE modelling, and query your entire posture in plain language.",
  info: "Risk domains are automatically normalised. Attack paths are derived from finding combinations — no manual correlation needed.",
  stats: [
    { label: "Open Risks",     field: "open_risks",         color: "#b45309" },
    { label: "Critical Risks", field: "critical_risks",     color: "#b91c1c" },
    { label: "Threat Entries", field: "total_threats",      color: "#ea580c" },
    { label: "Attack Paths",   field: "total_attack_paths", color: "#d97706" },
  ],
  cards: [
    // Risk
    { name: "Risk Register",          icon: <Security sx={ic("#EA4335")} />,    desc: "FAIR-scored risk register with domain heatmap and financial ALE.",        route: "/analyse/risks",              group: "Risk" },
    { name: "Risk Overview",          icon: <Assessment sx={ic("#FF6D00")} />,  desc: "Executive summary of ALE exposure, risk domains, and top risks.",         route: "/analyse/risk-overview",      group: "Risk" },
    { name: "AI Risk Analysis",       icon: <SmartToy sx={ic("#9C27B0")} />,    desc: "AI-generated risk narrative with actionable recommendations.",            route: "/analyse/ai-analysis",        group: "Risk" },
    { name: "Risk Appetite",          icon: <Tune sx={ic("#FBBC04")} />,        desc: "Configure organisation risk tolerance bands for the 5×5 GCC IM8 matrix.", route: "/analyse/risk-appetite",      group: "Risk" },
    // Vulnerability
    { name: "Attack Paths",           icon: <AltRoute sx={ic("#FF5722")} />,    desc: "MITRE-phased attack chain graph derived from live findings.",             route: "/analyse/attack-paths",       group: "Vulnerability" },
    { name: "Compliance Heatmap",     icon: <Policy sx={ic("#3F51B5")} />,      desc: "Control coverage heatmap across all active frameworks.",                  route: "/analyse/compliance-heatmap", group: "Vulnerability" },
    { name: "CVE Blast Radius",       icon: <Radar sx={ic("#F44336")} />,       desc: "Which assets does a CVE affect? Map the full exposure path.",             route: "/discover/cve-pivot",         group: "Vulnerability" },
    { name: "Scan Coverage",          icon: <GpsFixed sx={ic("#FBBC04")} />,    desc: "Assets not scanned within the policy window — identify coverage gaps.",   route: "/discover/coverage",          group: "Vulnerability" },
    // Intelligence
    { name: "Control Deficiencies",   icon: <Policy sx={ic("#FF6D00")} />,      desc: "Framework control gaps identified by the compliance monitor agent.",      route: "/respond/gaps",               group: "Intelligence" },
    { name: "Posture Trends",         icon: <TrendingUp sx={ic("#34A853")} />,  desc: "Time-series charts of open findings and audit readiness score.",          route: "/discover/posture",           group: "Intelligence" },
    { name: "Ask Your Data",          icon: <Search sx={ic("#4285F4")} />,      desc: "Natural language SQL queries over findings, risks, and assets.",          route: "/analyse/nl-query",           group: "Intelligence" },
    { name: "Comparison",             icon: <Assessment sx={ic("#34A853")} />,  desc: "Compare security posture side-by-side across multiple accounts.",         route: "/analyse/comparison",         group: "Intelligence" },
  ],
};

export default function AnalysePage() {
  return <SectionPage section={ANALYSE_SECTION} />;
}
