import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  People, Cable, SyncAlt, AccountTree,
  Settings as SettingsIcon, HelpOutlined, ManageSearch, DeviceHub,
} from "@mui/icons-material";
const ic = (color: string) => ({ color, fontSize: 16 } as const);

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
    { name: "Accounts",              icon: <People sx={ic("#4285F4")} />,       desc: "Account profiles, contact details, and security posture scoping.",         route: "/platform/clients",              group: "Environment" },
    { name: "Integrations",           icon: <Cable sx={ic("#FF6D00")} />,        desc: "Platform connectors, scanners, AI providers, webhooks, and API keys — all in one hub.", route: "/platform/integrations",         group: "Environment" },
    { name: "Ticket Sync",           icon: <SyncAlt sx={ic("#9C27B0")} />,      desc: "Bi-directional sync of findings and remediations with your ticket system.", route: "/platform/ticket-sync",          group: "Environment" },
    // Design
    { name: "Audit Logs",            icon: <ManageSearch sx={ic("#607D8B")} />, desc: "LLM prompt audit trail — per-user, per-endpoint, with CSV export.",          route: "/platform/audit-logs",           group: "Design" },
    { name: "Threat Models",         icon: <DeviceHub sx={ic("#00BCD4")} />,    desc: "DFD diagrams, STRIDE threats, and Sigma detection rule generation.",      route: "/analyse/threat-models",         group: "Design" },
    { name: "Data Model",            icon: <AccountTree sx={ic("#FF5722")} />,  desc: "Platform ontology — eleven entities, one interactive graph.",              route: "/data-model",                    group: "Design" },
    { name: "Settings",              icon: <SettingsIcon sx={ic("#78909C")} />, desc: "User preferences, deleted accounts, and platform configuration.",          route: "/platform/settings",             group: "Design" },
    { name: "Help",                  icon: <HelpOutlined sx={ic("#4285F4")} />, desc: "Documentation, setup guides, and platform support resources.",             route: "/platform/help",                 group: "Design" },
  ],
};

export default function SetupPage() {
  return <SectionPage section={SETUP_SECTION} />;
}
