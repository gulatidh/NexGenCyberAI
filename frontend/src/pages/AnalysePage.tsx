import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  Security, Assessment, SmartToy, AltRoute, Policy, Search, DeviceHub, PendingActions,
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
    { name: "Risk Staging",    icon: <PendingActions sx={ic("#EA4335")} />, desc: "AI / finding / manual proposals → 8-step evaluation wizard before entering the register.", route: "/analyse/risks/staging", group: "Risk" },
    { name: "Risk Register",   icon: <Security sx={ic("#EA4335")} />,       desc: "FAIR-scored, formally evaluated risks with domain heatmap and financial ALE.",            route: "/analyse/risks",         group: "Risk" },
    { name: "Risk Overview",   icon: <Assessment sx={ic("#FF6D00")} />,     desc: "Executive summary of ALE exposure, risk domains, and top risks.",                        route: "/analyse/risk-overview", group: "Risk" },
    { name: "AI Risk Analysis", icon: <SmartToy sx={ic("#9C27B0")} />,      desc: "AI-generated risk narrative with actionable recommendations.",                           route: "/analyse/ai-analysis",   group: "Risk" },
    // Exposure & Threat Modelling
    { name: "Attack Paths",      icon: <AltRoute sx={ic("#FF5722")} />,    desc: "MITRE-phased attack chain graph derived from live findings.",             route: "/analyse/attack-paths",       group: "Exposure & Threat Modelling" },
    { name: "Threat Models",     icon: <DeviceHub sx={ic("#00BCD4")} />,   desc: "DFD diagrams, STRIDE threats, and Sigma detection rule generation.",     route: "/analyse/threat-models",      group: "Exposure & Threat Modelling" },
    { name: "Compliance Heatmap", icon: <Policy sx={ic("#3F51B5")} />,     desc: "Control coverage heatmap across all active frameworks.",                  route: "/analyse/compliance-heatmap", group: "Exposure & Threat Modelling" },
    // Query & Compare
    { name: "Ask Your Data", icon: <Search sx={ic("#4285F4")} />,      desc: "Natural language SQL queries over findings, risks, and assets.",         route: "/analyse/nl-query",  group: "Query & Compare" },
    { name: "Comparison",    icon: <Assessment sx={ic("#34A853")} />,  desc: "Compare security posture side-by-side across multiple accounts.",        route: "/analyse/comparison", group: "Query & Compare" },
  ],
};

export default function AnalysePage() {
  return <SectionPage section={ANALYSE_SECTION} />;
}
