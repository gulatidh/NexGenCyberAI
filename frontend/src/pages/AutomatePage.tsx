import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  SmartToy, Hub, BugReport, MenuBook, Assessment, Search, Shield, Webhook, VpnKey,
} from "@mui/icons-material";

export const AUTOMATE_SECTION: SectionDef = {
  num: "06", label: "Automate", color: "#4338ca",
  title: "Let AI carry the load",
  sub: "Agents run the full analysis loop — risk, intel, remediation, compliance — on demand or on repeat.",
  info: "AI Buddies output structured data directly into the Risk, Threat, Compliance, and Remediation registers. The Orchestrator runs all four in sequence from one trigger.",
  stats: [
    { label: "Agent Runs",     field: "total_agent_runs", color: "#4338ca" },
    { label: "AI Workflows",   field: "total_missions",   color: "#6366f1" },
    { label: "Knowledge Docs", field: "total_documents",  color: "#0284c7" },
    { label: "API Keys",       field: "total_api_keys",   color: "#7c3aed" },
  ],
  cards: [
    // AI Agents
    { name: "AI Buddies",       icon: <SmartToy />,    desc: "60+ AI agents — orchestrator, risk, threat intel, and remediation planner.", route: "/automate/agents",        group: "AI Agents" },
    { name: "AI Workflows",     icon: <Hub />,         desc: "Multi-agent workflow missions and automated analysis pipelines.",             route: "/automate/workflows",     group: "AI Agents" },
    { name: "AI Assisted Scan", icon: <BugReport />,   desc: "Conversational guided assessment — describe the environment, AI configures.",route: "/automate/ai-scan",       group: "AI Agents" },
    // Knowledge
    { name: "Knowledge Base",   icon: <MenuBook />,    desc: "Platform knowledge base and Aegis reference documentation.",                 route: "/automate/knowledge",     group: "Knowledge" },
    { name: "Reports",          icon: <Assessment />,  desc: "AI-generated security posture and trend reports.",                           route: "/automate/reports",       group: "Knowledge" },
    { name: "Ask Your Data",    icon: <Search />,      desc: "SQL-backed natural language queries over all your data.",                    route: "/automate/nl-query",      group: "Knowledge" },
    { name: "AI Guardrails",    icon: <Shield />,      desc: "AI safety controls, prompt audit logs, and guardrail coverage.",             route: "/automate/ai-guardrails", group: "Knowledge" },
    { name: "Webhooks",         icon: <Webhook />,     desc: "Event-driven alerts on critical findings and completed scans.",              route: "/automate/webhooks",      group: "Knowledge" },
    { name: "API Keys",         icon: <VpnKey />,      desc: "M2M API keys for CI/CD pipelines and programmatic access.",                 route: "/automate/api-keys",      group: "Knowledge" },
  ],
};

export default function AutomatePage() {
  return <SectionPage section={AUTOMATE_SECTION} />;
}
