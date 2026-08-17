import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  People, Storage, Devices, Cable, SyncAlt,
  Tune, Shield, DeviceHub, Policy, LibraryAdd, AccountTree,
  Settings as SettingsIcon, HelpOutlined,
} from "@mui/icons-material";

export const SETUP_SECTION: SectionDef = {
  num: "01", label: "Setup", color: "#2563eb",
  title: "Stand up the environment",
  sub: "Configure accounts, connectors, and AI providers before any scanning begins.",
  info: "Complete this stage first — every downstream scan depends on at least one connected account and a configured AI provider.",
  stats: [
    { label: "Accounts",   field: "total_clients",    color: "#2563eb" },
    { label: "Connectors", field: "total_connectors", color: "#0284c7" },
    { label: "Assets",     field: "total_assets",     color: "#0f766e" },
    { label: "Frameworks", field: "total_frameworks",  color: "#7c3aed" },
  ],
  cards: [
    // Environment
    { name: "Accounts",              icon: <People />,       desc: "Account profiles, contact details, and security posture scoping.",         route: "/platform/clients",              group: "Environment" },
    { name: "Asset Inventory",       icon: <Storage />,      desc: "Discovered assets — servers, apps, containers, and cloud resources.",      route: "/platform/assets",               group: "Environment" },
    { name: "Technology Inventory",  icon: <Devices />,      desc: "Software stack and technology across all discovered assets.",              route: "/platform/assets/technologies",  group: "Environment" },
    { name: "Connectors",            icon: <Cable />,        desc: "Scanner integrations, enterprise tools, and SIEM connectors.",             route: "/platform/connections",          group: "Environment" },
    { name: "Ticket Sync",           icon: <SyncAlt />,      desc: "Bi-directional sync of findings and remediations with your ticket system.", route: "/platform/ticket-sync",          group: "Environment" },
    // Design
    { name: "AI Settings",           icon: <Tune />,         desc: "AI provider credentials, model selection, and automatic failover config.", route: "/platform/ai-settings",          group: "Design" },
    { name: "AI Guardrails",         icon: <Shield />,       desc: "AI safety controls, prompt audit logs, and guardrail coverage.",           route: "/automate/ai-guardrails",        group: "Design" },
    { name: "Threat Models",         icon: <DeviceHub />,    desc: "DFD diagrams, STRIDE analysis, and Sigma detection rule generation.",      route: "/analyse/threat-models",         group: "Design" },
    { name: "Frameworks",            icon: <Policy />,       desc: "NIST CSF, CIS v8, ISO 27001, PCI DSS, GDPR compliance mapping.",          route: "/report/frameworks",             group: "Design" },
    { name: "Custom Standards",      icon: <LibraryAdd />,   desc: "Build your own control framework from existing platform controls.",         route: "/report/custom-frameworks",      group: "Design" },
    { name: "Data Model",            icon: <AccountTree />,  desc: "Platform ontology — eleven entities, one interactive graph.",              route: "/data-model",                    group: "Design" },
    { name: "Settings",              icon: <SettingsIcon />, desc: "User preferences, deleted accounts, and platform configuration.",          route: "/platform/settings",             group: "Design" },
    { name: "Help",                  icon: <HelpOutlined />, desc: "Documentation, setup guides, and platform support resources.",             route: "/platform/help",                 group: "Design" },
  ],
};

export default function SetupPage() {
  return <SectionPage section={SETUP_SECTION} />;
}
