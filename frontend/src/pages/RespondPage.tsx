import SectionPage, { SectionDef } from "../components/SectionPage";

const SECTION: SectionDef = {
  num: "04", label: "Respond", color: "#b91c1c",
  title: "Act on the picture",
  sub: "Map risk to real adversary behaviour, then track remediation through structured CTEM programs.",
  info: "Threat entries are mapped to MITRE ATT&CK automatically. CTEM programs progress through 5 phases: Scope → Discover → Prioritise → Validate → Mobilise.",
  stats: [
    { label: "Control Gaps",       field: "total_deficiencies",     color: "#b91c1c" },
    { label: "Open Remediations",  field: "open_remediations",      color: "#ea580c" },
    { label: "CTEM Programs",      field: "total_ctem_programs",    color: "#d97706" },
    { label: "Threat Entries",     field: "total_threats",          color: "#7c3aed" },
  ],
  cards: [
    { name: "Threat Register",      desc: "MITRE ATT&CK–mapped threat entries and IOCs from AI analysis.",           route: "/threat-intel/register" },
    { name: "Control Deficiencies", desc: "Framework control gaps identified by the compliance monitor agent.",       route: "/compliance/deficiencies" },
    { name: "Remediation Tracker",  desc: "Priority-banded remediation actions tracked to completion.",              route: "/governance/remediation" },
    { name: "AI Remediations",      desc: "AI-generated remediation plans dispatched as automated workflows.",       route: "/governance/remediation-jobs" },
    { name: "CTEM Programs",        desc: "5-phase continuous threat exposure management programs.",                  route: "/governance/ctem" },
    { name: "VAPT Reports",         desc: "Engagement reports with retest versioning and PDF/DOCX export.",          route: "/vapt/reports" },
    { name: "Security Docs",        desc: "Upload security policies and query them with AI via RAG.",                route: "/intelligence/security-docs" },
    { name: "Ticket Sync",          desc: "Push findings and remediations to Jira, ServiceNow, or Linear.",          route: "/connections" },
  ],
};

export default function RespondPage() {
  return <SectionPage section={SECTION} />;
}
