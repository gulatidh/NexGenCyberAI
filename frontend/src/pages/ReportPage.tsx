import SectionPage, { SectionDef } from "../components/SectionPage";

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
    { name: "VAPT Reports",     desc: "Full engagement lifecycle with retest versioning and PDF/DOCX export.",  route: "/report/vapt-reports",      group: "Pen Testing" },
    { name: "Evidence Package", desc: "ZIP of findings, deficiencies, and agent logs for auditors.",           route: "/report/evidence",          group: "Pen Testing" },
    { name: "Reports",          desc: "AI-generated security posture and trend reports.",                       route: "/report/reports",           group: "Pen Testing" },
    // Compliance
    { name: "Frameworks",       desc: "NIST CSF, CIS v8, ISO 27001, PCI DSS, GDPR compliance posture.",       route: "/report/frameworks",        group: "Compliance" },
    { name: "Custom Standards", desc: "Build and evaluate custom control frameworks.",                          route: "/report/custom-frameworks", group: "Compliance" },
    { name: "Control Gaps",     desc: "Framework control deficiencies identified by the compliance monitor.",  route: "/report/gaps",              group: "Compliance" },
  ],
};

export default function ReportPage() {
  return <SectionPage section={REPORT_SECTION} />;
}
