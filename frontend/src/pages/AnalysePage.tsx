import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  Security, Assessment, SmartToy, AltRoute, DeviceHub, Policy, Search,
} from "@mui/icons-material";

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
    { name: "Risk Register",          icon: <Security />,    desc: "FAIR-scored risk register with domain heatmap and financial ALE.",       route: "/analyse/risks",              group: "Risk" },
    { name: "Risk Overview",          icon: <Assessment />,  desc: "Executive summary of ALE exposure, risk domains, and top risks.",        route: "/analyse/risk-overview",      group: "Risk" },
    { name: "AI Risk Analysis",       icon: <SmartToy />,    desc: "AI-generated risk narrative with actionable recommendations.",           route: "/analyse/ai-analysis",        group: "Risk" },
    { name: "Attack Paths",           icon: <AltRoute />,    desc: "MITRE-phased attack chain graph derived from live findings.",            route: "/analyse/attack-paths",       group: "Risk" },
    // Intelligence
    { name: "AI Threat Intelligence", icon: <DeviceHub />,   desc: "DFD diagrams, STRIDE threats, and Sigma detection rule generation.",    route: "/analyse/threat-models",      group: "Intelligence" },
    { name: "Compliance Heatmap",     icon: <Policy />,      desc: "Control coverage heatmap across all active frameworks.",                route: "/analyse/compliance-heatmap", group: "Intelligence" },
    { name: "Ask Your Data",          icon: <Search />,      desc: "Natural language SQL queries over findings, risks, and assets.",         route: "/analyse/nl-query",           group: "Intelligence" },
    { name: "Comparison",             icon: <Assessment />,  desc: "Compare security posture side-by-side across multiple accounts.",        route: "/analyse/comparison",         group: "Intelligence" },
  ],
};

export default function AnalysePage() {
  return <SectionPage section={ANALYSE_SECTION} />;
}
