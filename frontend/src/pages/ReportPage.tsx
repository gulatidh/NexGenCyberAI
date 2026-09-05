import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  Description, FolderZip, Assessment, LibraryAdd, GppBad, BarChart, ManageSearch,
  Summarize, Schedule, Psychology,
} from "@mui/icons-material";
const ic = (color: string) => ({ color, fontSize: 16 } as const);

export const REPORT_SECTION: SectionDef = {
  num: "05", label: "Audit", color: "#15803d",
  title: "Prove it happened",
  sub: "Close the loop with evidence the auditor — or the client — can actually use.",
  info: "VAPT reports are AI-generated from scan findings. Evidence packages are audit-ready ZIPs of findings, control deficiencies, remediation actions, and agent logs.",
  stats: [
    { label: "VAPT Reports", field: "total_vapt_reports", color: "#15803d" },
    { label: "Control Gaps", field: "total_deficiencies",  color: "#b91c1c" },
    { label: "Frameworks",   field: "total_frameworks",    color: "#0284c7" },
    { label: "Open Findings",field: "open_findings",       color: "#ea580c" },
  ],
  cards: [
    // Audit & Reporting
    { name: "VAPT Reports",          icon: <Description sx={ic("#FBBC04")} />,  desc: "Full engagement lifecycle with retest versioning and PDF/DOCX export.", route: "/report/vapt-reports", group: "Audit & Reporting" },
    { name: "Evidence Package",      icon: <FolderZip sx={ic("#34A853")} />,   desc: "ZIP of findings, deficiencies, and agent logs for auditors.",           route: "/report/evidence",     group: "Audit & Reporting" },
    { name: "Reports",               icon: <Assessment sx={ic("#4285F4")} />,  desc: "AI-generated security posture and trend reports.",                       route: "/report/reports",      group: "Audit & Reporting" },
    { name: "Audit Intelligence",    icon: <ManageSearch sx={ic("#00BCD4")} />, desc: "ICS Audit & Risk Intelligence — how every audit activity maps to the platform.", route: "/report/audit", group: "Audit & Reporting" },
    { name: "Audit Agents",         icon: <Psychology sx={ic("#9C27B0")} />,   desc: "Wizard-driven AI agents for control testing, readiness reports, evidence curation and interview prep.", route: "/report/audit-agents", group: "Audit & Reporting" },
    { name: "Executive Summary",    icon: <Summarize sx={ic("#FF6D00")} />,    desc: "Non-technical leadership report — posture score, key risks, and remediation progress.", route: "/report/executive-summary", group: "Audit & Reporting" },
    { name: "Report Scheduler",     icon: <Schedule sx={ic("#607D8B")} />,     desc: "Schedule recurring report delivery to stakeholders via email.",               route: "/report/scheduler",         group: "Audit & Reporting" },
    // Compliance
    { name: "Framework Library",     icon: <LibraryAdd sx={ic("#3F51B5")} />,  desc: "Browse standard frameworks and manage custom compliance policies.",                route: "/report/frameworks",        group: "Compliance" },
    { name: "Custom Standards",      icon: <LibraryAdd sx={ic("#009688")} />,  desc: "Build your own control framework from existing platform controls.",               route: "/report/custom-frameworks", group: "Compliance" },
    { name: "Compliance Evaluation", icon: <BarChart sx={ic("#009688")} />,    desc: "Evaluate posture and run targeted scans against any framework.",                   route: "/report/compliance",        group: "Compliance" },
    { name: "Control Gaps",          icon: <GppBad sx={ic("#EA4335")} />,      desc: "Framework control deficiencies identified by the compliance monitor.",             route: "/report/gaps",              group: "Compliance" },
  ],
};

export default function ReportPage() {
  return <SectionPage section={REPORT_SECTION} />;
}
