import SectionPage, { SectionDef } from "../components/SectionPage";
import {
  Description, FolderZip, Assessment, LibraryAdd, GppBad, BarChart,
} from "@mui/icons-material";

export const REPORT_SECTION: SectionDef = {
  num: "05", label: "Report", color: "#15803d",
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
    // Pen Testing
    { name: "VAPT Reports",          icon: <Description />, desc: "Full engagement lifecycle with retest versioning and PDF/DOCX export.", route: "/report/vapt-reports", group: "Pen Testing" },
    { name: "Evidence Package",      icon: <FolderZip />,   desc: "ZIP of findings, deficiencies, and agent logs for auditors.",          route: "/report/evidence",     group: "Pen Testing" },
    { name: "Reports",               icon: <Assessment />,  desc: "AI-generated security posture and trend reports.",                      route: "/report/reports",      group: "Pen Testing" },
    // Compliance
    { name: "Framework Library",     icon: <LibraryAdd />,  desc: "Browse standard frameworks and manage custom compliance policies.",     route: "/report/frameworks",   group: "Compliance" },
    { name: "Compliance Evaluation", icon: <BarChart />,    desc: "Evaluate posture and run targeted scans against any framework.",        route: "/report/compliance",   group: "Compliance" },
    { name: "Control Gaps",          icon: <GppBad />,      desc: "Framework control deficiencies identified by the compliance monitor.", route: "/report/gaps",          group: "Compliance" },
  ],
};

export default function ReportPage() {
  return <SectionPage section={REPORT_SECTION} />;
}
