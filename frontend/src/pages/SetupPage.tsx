import SectionPage, { SectionDef } from "../components/SectionPage";

export const SETUP_SECTION: SectionDef = {
  num: "01", label: "Setup", color: "#2563eb",
  title: "Stand up the environment",
  sub: "Configure accounts, connectors, and AI providers before any scanning begins.",
  info: "Complete this stage first — every downstream scan depends on at least one connected account and a configured AI provider.",
  stats: [
    { label: "Accounts",    field: "total_clients",    color: "#2563eb" },
    { label: "Connectors",  field: "total_connectors", color: "#0284c7" },
    { label: "Assets",      field: "total_assets",     color: "#0f766e" },
    { label: "Frameworks",  field: "total_frameworks",  color: "#7c3aed" },
  ],
  cards: [
    { name: "Accounts",          desc: "Account profiles, contact details, and security posture scoping.",         route: "/platform/clients" },
    { name: "Asset Inventory",   desc: "Discovered assets — servers, apps, containers, and cloud resources.",      route: "/platform/assets" },
    { name: "Connectors",        desc: "Scanner integrations, enterprise tools, and SIEM connectors.",             route: "/connections" },
    { name: "AI Settings",       desc: "AI provider credentials, model selection, and automatic failover config.", route: "/ai-settings" },
    { name: "AI Guardrails",     desc: "AI safety controls, prompt audit logs, and guardrail coverage.",           route: "/automate/ai-guardrails" },
    { name: "Threat Models",     desc: "DFD diagrams, STRIDE analysis, and Sigma detection rule generation.",      route: "/platform/threat-models" },
    { name: "Frameworks",        desc: "NIST CSF, CIS v8, ISO 27001, PCI DSS, GDPR compliance mapping.",          route: "/compliance/frameworks" },
    { name: "Custom Standards",  desc: "Build your own control framework from existing platform controls.",         route: "/compliance/custom-frameworks" },
    { name: "Data Model",        desc: "Platform ontology — eleven entities, one interactive graph.",              route: "/data-model" },
    { name: "Settings",          desc: "User preferences, deleted accounts, and platform configuration.",          route: "/platform/settings" },
    { name: "Help",              desc: "Documentation, setup guides, and platform support resources.",             route: "/platform/help" },
  ],
};

export default function SetupPage() {
  return <SectionPage section={SETUP_SECTION} />;
}
