import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  Radar, GppBad, AccountTree, PlaylistAddCheck, AutoFixHigh, Description, MenuBook,
} from "@mui/icons-material";

export const RESPOND_SECTION: SectionDef = {
  num: "04", label: "Respond", color: "#b91c1c",
  title: "Act on the picture",
  sub: "Map risk to real adversary behaviour, then track remediation through structured CTEM programs.",
  info: "Threat entries are mapped to MITRE ATT&CK automatically. CTEM programs progress through 5 phases: Scope → Discover → Prioritise → Validate → Mobilise.",
  stats: [
    { label: "Control Gaps",      field: "total_deficiencies",  color: "#b91c1c" },
    { label: "Open Remediations", field: "open_remediations",   color: "#ea580c" },
    { label: "CTEM Programs",     field: "total_ctem_programs", color: "#d97706" },
    { label: "Threat Entries",    field: "total_threats",       color: "#7c3aed" },
  ],
  cards: [
    // Threat Intelligence
    { name: "Threat Register",      icon: <Radar />,            desc: "MITRE ATT&CK–mapped threat entries and IOCs from AI analysis.",        route: "/respond/threats",          group: "Threat Intelligence" },
    { name: "Control Deficiencies", icon: <GppBad />,           desc: "Framework control gaps identified by the compliance monitor agent.",    route: "/respond/gaps",             group: "Threat Intelligence" },
    { name: "CTEM Programs",        icon: <AccountTree />,      desc: "5-phase continuous threat exposure management programs.",               route: "/respond/ctem",             group: "Threat Intelligence" },
    // Remediation
    { name: "Remediation",          icon: <PlaylistAddCheck />, desc: "Priority-banded remediation actions tracked to completion.",           route: "/respond/remediation",      group: "Remediation" },
    { name: "AI Remediations",      icon: <AutoFixHigh />,      desc: "AI-generated remediation plans dispatched as automated workflows.",    route: "/respond/remediation-jobs", group: "Remediation" },
    { name: "VAPT Reports",         icon: <Description />,      desc: "Engagement reports with retest versioning and PDF/DOCX export.",       route: "/respond/vapt-reports",     group: "Remediation" },
    { name: "Security Docs",        icon: <MenuBook />,         desc: "Upload security policies and query them with AI via RAG.",             route: "/respond/security-docs",    group: "Remediation" },
  ],
};

export default function RespondPage() {
  return <SectionPage section={RESPOND_SECTION} />;
}
