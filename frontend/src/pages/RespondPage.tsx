import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  Radar, GppBad, AccountTree, PlaylistAddCheck, AutoFixHigh, Description, MenuBook, ReportProblem,
} from "@mui/icons-material";
const ic = (color: string) => ({ color, fontSize: 16 } as const);

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
    // Incidents
    { name: "Incidents",            icon: <ReportProblem sx={ic("#F44336")} />,    desc: "Security incident cases with timelines, owners, SLA tracking, and linked findings.", route: "/respond/incidents", group: "Incidents" },
    // Threat Intelligence
    { name: "Threat Register",      icon: <Radar sx={ic("#EA4335")} />,            desc: "MITRE ATT&CK–mapped threat entries and IOCs from AI analysis.",        route: "/respond/threats",          group: "Threat Intelligence" },
    { name: "Control Deficiencies", icon: <GppBad sx={ic("#FF6D00")} />,           desc: "Framework control gaps identified by the compliance monitor agent.",    route: "/respond/gaps",             group: "Threat Intelligence" },
    { name: "CTEM Programs",        icon: <AccountTree sx={ic("#9C27B0")} />,      desc: "5-phase continuous threat exposure management programs.",               route: "/respond/ctem",             group: "Threat Intelligence" },
    // Remediation
    { name: "Remediation",          icon: <PlaylistAddCheck sx={ic("#34A853")} />, desc: "Priority-banded remediation actions tracked to completion.",           route: "/respond/remediation",      group: "Remediation" },
    { name: "AI Remediations",      icon: <AutoFixHigh sx={ic("#00BCD4")} />,      desc: "AI-generated remediation plans dispatched as automated workflows.",    route: "/respond/remediation-jobs", group: "Remediation" },
    { name: "VAPT Reports",         icon: <Description sx={ic("#FBBC04")} />,      desc: "Engagement reports with retest versioning and PDF/DOCX export.",       route: "/respond/vapt-reports",     group: "Remediation" },
    { name: "Security Docs",        icon: <MenuBook sx={ic("#4285F4")} />,         desc: "Upload security policies and query them with AI via RAG.",             route: "/respond/security-docs",    group: "Remediation" },
  ],
};

export default function RespondPage() {
  return <SectionPage section={RESPOND_SECTION} />;
}
