import SectionPage, { SectionDef } from "../components/SectionPage";

const SECTION: SectionDef = {
  num: "06", label: "Automate", color: "#4338ca",
  title: "Let AI carry the load",
  sub: "Agents run the full analysis loop — risk, intel, remediation, compliance — on demand or on repeat.",
  info: "AI Buddies output structured data directly into the Risk, Threat, Compliance, and Remediation registers. The Orchestrator runs all four in sequence from one trigger.",
  stats: [
    { label: "Agent Runs",    field: "total_agent_runs",  color: "#4338ca" },
    { label: "AI Workflows",  field: "total_missions",    color: "#6366f1" },
    { label: "Knowledge Docs", field: "total_documents", color: "#0284c7" },
    { label: "API Keys",      field: "total_api_keys",    color: "#7c3aed" },
  ],
  cards: [
    { name: "AI Buddies",     desc: "60+ AI agents — orchestrator, risk, threat intel, and remediation planner.",    route: "/ai-advisor/agents" },
    { name: "AI Workflows",   desc: "Multi-agent workflow missions and automated analysis pipelines.",               route: "/ai-advisor/workflows" },
    { name: "Knowledge Base", desc: "Platform knowledge base and Aegis reference documentation.",                   route: "/intelligence/knowledge" },
    { name: "AI Assisted Scan", desc: "Conversational guided assessment — describe the environment, AI configures.", route: "/intelligence/ai-assisted-scan" },
    { name: "Ask Your Data",  desc: "Natural language SQL queries over findings, risks, and assets.",               route: "/intelligence/nl-query" },
    { name: "Reports",        desc: "AI-generated security posture and trend reports.",                              route: "/intelligence/reports" },
    { name: "API Keys",       desc: "M2M API keys for CI/CD pipelines and programmatic integrations.",              route: "/api-keys" },
    { name: "Help & Docs",    desc: "Documentation, setup guides, and platform support resources.",                  route: "/platform/help" },
  ],
};

export default function AutomatePage() {
  return <SectionPage section={SECTION} />;
}
