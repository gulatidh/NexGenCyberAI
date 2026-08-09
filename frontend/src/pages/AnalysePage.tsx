import { SectionLayout } from "../components/SectionPage";
import { SectionDef } from "../components/SectionPage";

export const ANALYSE_SECTION: SectionDef = {
  num: "03", label: "Analyse", color: "#b45309",
  title: "Turn findings into insight",
  sub: "Score findings, apply FAIR-lite ALE modelling, and query your entire posture in plain language.",
  info: "Risk domains are automatically normalised. Attack paths are derived from finding combinations — no manual correlation needed.",
  stats: [
    { label: "Open Risks",     field: "open_risks",       color: "#b45309" },
    { label: "Critical Risks", field: "critical_risks",   color: "#b91c1c" },
    { label: "Threat Entries", field: "total_threats",    color: "#ea580c" },
    { label: "Attack Paths",   field: "total_attack_paths", color: "#d97706" },
  ],
  cards: [
    { name: "Risk Register",      desc: "FAIR-scored risk register with domain heatmap and financial ALE.",         route: "/analyse/risks" },
    { name: "Risk Overview",      desc: "Executive summary of ALE exposure, risk domains, and top risks.",          route: "/analyse/risk-overview" },
    { name: "AI Risk Analysis",   desc: "AI-generated risk narrative with actionable recommendations.",             route: "/analyse/ai-analysis" },
    { name: "Attack Paths",       desc: "MITRE-phased attack chain graph derived from live findings.",              route: "/analyse/attack-paths" },
    { name: "Threat Models",      desc: "DFD diagrams, STRIDE analysis, and Sigma detection rule generation.",      route: "/analyse/threat-models" },
    { name: "Compliance Heatmap", desc: "Control coverage heatmap across all active frameworks.",                   route: "/analyse/compliance-heatmap" },
    { name: "Ask Your Data",      desc: "Natural language SQL queries over findings, risks, and assets.",           route: "/analyse/nl-query" },
    { name: "Account Comparison", desc: "Compare security posture side-by-side across multiple accounts.",          route: "/analyse/comparison" },
  ],
};

export default function AnalysePage() {
  return <SectionLayout section={ANALYSE_SECTION} basePath="/analyse" />;
}
