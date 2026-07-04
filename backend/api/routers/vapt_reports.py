"""
VAPT Report endpoints — full lifecycle for VAPT engagements.

Routes (all under /clients/{cid}/vapt-reports/):
  GET    /                          list all reports for client
  POST   /                          create new report
  GET    /{rid}/                    get report with findings
  PATCH  /{rid}/                    update report
  DELETE /{rid}/                    delete report
  POST   /{rid}/retest/             create retest version (bumped version, copied findings)
  POST   /{rid}/findings/           add finding
  PATCH  /{rid}/findings/{fid}/     update finding
  DELETE /{rid}/findings/{fid}/     delete finding
  GET    /{rid}/export/pdf          full report PDF
  GET    /{rid}/export/docx         full report DOCX
  GET    /{rid}/export/remediation-pdf   remediation plan PDF
  GET    /{rid}/export/remediation-docx  remediation plan DOCX
"""
import io
import json
import logging
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.models.models import Client, Finding, Scan, VAPTFinding, VAPTReport
from core.security import get_current_user
from db.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["vapt_reports"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _bump_version(version: str) -> str:
    """Bump minor version: 1.0 → 1.1, 1.9 → 1.10."""
    try:
        parts = str(version).split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        return f"{major}.{minor + 1}"
    except Exception:
        return f"{version}.1"


def _get_report_or_404(rid: str, cid: str, db: Session) -> VAPTReport:
    report = db.query(VAPTReport).filter(
        VAPTReport.id == rid, VAPTReport.client_id == cid
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="VAPT report not found")
    return report


def _get_finding_or_404(fid: str, rid: str, db: Session) -> VAPTFinding:
    finding = db.query(VAPTFinding).filter(
        VAPTFinding.id == fid, VAPTFinding.report_id == rid
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


def _get_client_or_404(cid: str, db: Session) -> Client:
    client = db.query(Client).filter(Client.id == cid).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


def _sev_counts(findings: List[VAPTFinding]) -> Dict[str, int]:
    counts = {s: 0 for s in ["critical", "high", "medium", "low", "informational"]}
    for f in findings:
        s = (f.severity or "").lower()
        if s == "info":
            s = "informational"
        if s in counts:
            counts[s] += 1
    return counts


def _report_to_dict(report: VAPTReport) -> Dict:
    return {
        "id": report.id,
        "client_id": report.client_id,
        "parent_report_id": report.parent_report_id,
        "title": report.title,
        "version": report.version,
        "classification": report.classification,
        "prepared_by": report.prepared_by,
        "reviewed_by": report.reviewed_by,
        "report_date": report.report_date.isoformat() if report.report_date else None,
        "retest_date": report.retest_date.isoformat() if report.retest_date else None,
        "status": report.status,
        "executive_summary": report.executive_summary,
        "scope_json": report.scope_json,
        "methodology_json": report.methodology_json,
        "conclusion": report.conclusion,
        "appendices": report.appendices,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "updated_at": report.updated_at.isoformat() if report.updated_at else None,
    }


def _finding_to_dict(f: VAPTFinding) -> Dict:
    return {
        "id": f.id,
        "report_id": f.report_id,
        "finding_id": f.finding_id,
        "title": f.title,
        "severity": f.severity,
        "affected_asset": f.affected_asset,
        "description": f.description,
        "impact": f.impact,
        "evidence": f.evidence,
        "reproduction_steps": f.reproduction_steps,
        "recommendation": f.recommendation,
        "references": f.references,
        "retest_status": f.retest_status,
        "retest_notes": f.retest_notes,
        "order_index": f.order_index,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class VAPTReportCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    classification: str = "Confidential"
    version: str = "1.0"
    prepared_by: Optional[str] = None
    reviewed_by: Optional[str] = None
    report_date: Optional[str] = None   # ISO date string
    retest_date: Optional[str] = None


class VAPTReportFromScan(BaseModel):
    scan_id: str
    title: Optional[str] = None          # defaults to scan name
    classification: str = "Confidential"
    prepared_by: Optional[str] = None


class VAPTReportUpdate(BaseModel):
    title: Optional[str] = None
    classification: Optional[str] = None
    version: Optional[str] = None
    prepared_by: Optional[str] = None
    reviewed_by: Optional[str] = None
    report_date: Optional[str] = None
    retest_date: Optional[str] = None
    status: Optional[str] = None
    executive_summary: Optional[str] = None
    scope_json: Optional[str] = None
    methodology_json: Optional[str] = None
    conclusion: Optional[str] = None
    appendices: Optional[str] = None


class VAPTFindingCreate(BaseModel):
    finding_id: Optional[str] = None
    title: str = Field(..., min_length=1, max_length=500)
    severity: str = "medium"
    affected_asset: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    evidence: Optional[str] = None
    reproduction_steps: Optional[str] = None
    recommendation: Optional[str] = None
    references: Optional[str] = None
    retest_status: str = "pending"
    retest_notes: Optional[str] = None
    order_index: int = 0


class VAPTFindingUpdate(BaseModel):
    finding_id: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    affected_asset: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    evidence: Optional[str] = None
    reproduction_steps: Optional[str] = None
    recommendation: Optional[str] = None
    references: Optional[str] = None
    retest_status: Optional[str] = None
    retest_notes: Optional[str] = None
    order_index: Optional[int] = None


# ── List / Create ─────────────────────────────────────────────────────────────

@router.get("/clients/{cid}/vapt-reports/")
async def list_vapt_reports(
    cid: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    _get_client_or_404(cid, db)
    reports = db.query(VAPTReport).filter(VAPTReport.client_id == cid).order_by(
        VAPTReport.created_at.desc()
    ).all()

    result = []
    for r in reports:
        d = _report_to_dict(r)
        d["finding_counts"] = _sev_counts(r.findings)
        d["total_findings"] = len(r.findings)
        result.append(d)
    return result


@router.post("/clients/{cid}/vapt-reports/", status_code=status.HTTP_201_CREATED)
async def create_vapt_report(
    cid: str,
    payload: VAPTReportCreate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    _get_client_or_404(cid, db)
    report_date = None
    if payload.report_date:
        try:
            report_date = datetime.fromisoformat(payload.report_date.replace("Z", "+00:00"))
        except Exception:
            pass

    report = VAPTReport(
        client_id=cid,
        title=payload.title,
        classification=payload.classification,
        version=payload.version,
        prepared_by=payload.prepared_by,
        reviewed_by=payload.reviewed_by,
        report_date=report_date,
        status="draft",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    d = _report_to_dict(report)
    d["finding_counts"] = {}
    d["total_findings"] = 0
    return d


# ── Methodology templates by connector/scan type ──────────────────────────────

_METHODOLOGY: Dict[str, Dict] = {
    "web": {
        "phases": [
            {"name": "Reconnaissance", "description": "Passive and active information gathering — DNS enumeration, HTTP header analysis, technology fingerprinting."},
            {"name": "Automated Scanning", "description": "OWASP ZAP active scan covering OWASP Top 10 attack categories including injection, broken authentication, XSS, IDOR, and security misconfigurations."},
            {"name": "Manual Verification", "description": "Analyst review and proof-of-concept reproduction of flagged vulnerabilities to eliminate false positives."},
            {"name": "Reporting", "description": "Risk-rated findings with evidence, reproduction steps, and remediation guidance aligned to OWASP ASVS."},
        ],
        "tools": ["OWASP ZAP", "Burp Suite", "curl", "Nikto"],
        "standards": ["OWASP Top 10", "OWASP ASVS", "PTES"],
    },
    "semgrep": {
        "phases": [
            {"name": "Code Acquisition", "description": "Source code retrieved from repository or uploaded archive."},
            {"name": "Static Analysis", "description": "Semgrep pattern matching against community and custom rule sets covering injection, secrets, insecure deserialization, and cryptographic weaknesses."},
            {"name": "AI Triage", "description": "LLM-assisted triage to reduce false positives and enrich findings with context-aware remediation advice."},
            {"name": "Reporting", "description": "File- and line-level findings mapped to CWE identifiers with fix recommendations."},
        ],
        "tools": ["Semgrep", "Claude AI (triage)"],
        "standards": ["OWASP Top 10", "CWE/SANS Top 25", "NIST SSDF"],
    },
    "codeql": {
        "phases": [
            {"name": "Code Acquisition", "description": "Source code compiled or indexed into CodeQL database."},
            {"name": "Query Execution", "description": "CodeQL security queries executed across all supported languages, targeting data-flow vulnerabilities, injection sinks, and unsafe API usage."},
            {"name": "AI Enrichment", "description": "LLM-assisted severity assessment and step-by-step remediation generation."},
            {"name": "Reporting", "description": "Findings presented with taint-flow traces, CWE mappings, and actionable fixes."},
        ],
        "tools": ["CodeQL CLI", "GitHub Advanced Security", "Claude AI"],
        "standards": ["CWE Top 25", "OWASP Top 10", "NIST SSDF"],
    },
    "sonarqube": {
        "phases": [
            {"name": "Project Scan", "description": "SonarQube analysis run against the codebase covering bugs, vulnerabilities, code smells, and security hotspots."},
            {"name": "Security Hotspot Review", "description": "All security hotspots reviewed and triaged by severity."},
            {"name": "Reporting", "description": "Findings with quality-gate status, debt estimates, and remediation guidance."},
        ],
        "tools": ["SonarQube", "SonarScanner"],
        "standards": ["OWASP Top 10", "CWE", "CERT"],
    },
    "nmap": {
        "phases": [
            {"name": "Host Discovery", "description": "TCP/UDP port sweep to enumerate live hosts and open services."},
            {"name": "Service Fingerprinting", "description": "Version detection for identified services to flag outdated or vulnerable software."},
            {"name": "Vulnerability Correlation", "description": "Identified service versions cross-referenced against CVE database for known exploits."},
            {"name": "Reporting", "description": "Network attack surface mapped with risk ratings per open service."},
        ],
        "tools": ["Nmap", "NSE Scripts"],
        "standards": ["PTES", "NIST SP 800-115"],
    },
    "openvas": {
        "phases": [
            {"name": "Scan Configuration", "description": "OpenVAS scanner configured with full and fast scan policy against defined target range."},
            {"name": "Authenticated Scanning", "description": "Credentialed scan to identify privilege-escalation paths and internal misconfigurations."},
            {"name": "CVE Assessment", "description": "Identified CVEs prioritised by CVSS score and exploitability."},
            {"name": "Reporting", "description": "Risk-rated vulnerability report with remediation timelines."},
        ],
        "tools": ["OpenVAS / Greenbone", "CVE Database"],
        "standards": ["CVSSv3", "PTES", "NIST SP 800-115"],
    },
    "trivy": {
        "phases": [
            {"name": "Image/Filesystem Scan", "description": "Trivy scans container images and filesystems for OS package vulnerabilities and misconfigurations."},
            {"name": "Secret Detection", "description": "Embedded secrets and hardcoded credentials identified."},
            {"name": "CVE Triage", "description": "CVEs triaged by fixability and severity; unfixed CVEs flagged separately."},
            {"name": "Reporting", "description": "Container security posture report with patching recommendations."},
        ],
        "tools": ["Trivy", "OCI Registry"],
        "standards": ["CIS Docker Benchmark", "CVSSv3", "NIST SP 800-190"],
    },
    "gitleaks": {
        "phases": [
            {"name": "Repository Scan", "description": "Gitleaks scans entire git history for secrets, API keys, and credentials."},
            {"name": "Entropy Analysis", "description": "High-entropy strings analysed to surface non-pattern-matched secrets."},
            {"name": "Reporting", "description": "Exposed secrets listed with commit reference, file path, and remediation steps."},
        ],
        "tools": ["Gitleaks"],
        "standards": ["OWASP Top 10 (A02)", "NIST SSDF"],
    },
    "trufflehog": {
        "phases": [
            {"name": "Deep History Scan", "description": "TruffleHog scans all commits and branches for verified and unverified credentials."},
            {"name": "Verification", "description": "Discovered credentials verified against upstream APIs where supported."},
            {"name": "Reporting", "description": "Confirmed and suspected secret exposures with remediation guidance."},
        ],
        "tools": ["TruffleHog"],
        "standards": ["OWASP Top 10 (A02)", "NIST SSDF"],
    },
    "owasp_dc": {
        "phases": [
            {"name": "Dependency Extraction", "description": "All third-party libraries and transitive dependencies catalogued from project manifests."},
            {"name": "CVE Correlation", "description": "Dependencies cross-referenced against NVD and OSS Index for known vulnerabilities."},
            {"name": "Reporting", "description": "Vulnerable components reported with upgrade paths and severity."},
        ],
        "tools": ["OWASP Dependency-Check", "NVD", "OSS Index"],
        "standards": ["OWASP Top 10 (A06)", "CycloneDX SBOM"],
    },
    "ai_code_review": {
        "phases": [
            {"name": "Code Ingestion", "description": "Source code ingested, parsed, and chunked by file and function boundary."},
            {"name": "Risk Triage", "description": "AI triage phase scores each chunk for security relevance, prioritising high-risk files."},
            {"name": "Deep Review", "description": "LLM-assisted four-phase review: triage → per-chunk review → self-critique → cross-file taint tracing."},
            {"name": "Reporting", "description": "Structured findings with severity, CWE mapping, evidence, and AI-generated remediation."},
        ],
        "tools": ["Aegis AI Code Review", "Claude AI", "OpenAI GPT-4o"],
        "standards": ["OWASP Top 10", "CWE/SANS Top 25", "NIST SSDF"],
    },
}

_DEFAULT_METHODOLOGY = {
    "phases": [
        {"name": "Discovery", "description": "Target identification and information gathering."},
        {"name": "Assessment", "description": "Automated and manual vulnerability assessment."},
        {"name": "Reporting", "description": "Risk-rated findings with remediation guidance."},
    ],
    "tools": ["Aegis Security Platform"],
    "standards": ["PTES", "OWASP"],
}


async def _ai_generate_report_content(
    client_name: str,
    scan_type: str,
    findings: List[Dict],
    scope: Dict,
) -> Dict[str, str]:
    """Call LLM to generate executive summary, per-finding enhanced remediation, and conclusion."""
    try:
        from core.ai_providers import get_llm, ProviderUnavailableError
        from langchain_core.messages import HumanMessage, SystemMessage

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for f in findings:
            s = (f.get("severity") or "").lower()
            if s in sev_counts:
                sev_counts[s] += 1

        findings_summary = "\n".join(
            f"- [{f.get('severity','').upper()}] {f.get('title','')}: {(f.get('description') or '')[:200]}"
            for f in findings[:30]
        )

        system = (
            "You are a senior penetration tester writing a professional VAPT report. "
            "Be concise, precise, and business-appropriate. Do not use markdown headers or bullet symbols — "
            "write in clear prose paragraphs. Output JSON only."
        )

        prompt = f"""
Client: {client_name}
Scan type: {scan_type}
Scope: {json.dumps(scope)}
Findings ({len(findings)} total — Critical:{sev_counts['critical']} High:{sev_counts['high']} Medium:{sev_counts['medium']} Low:{sev_counts['low']}):
{findings_summary}

Return a JSON object with exactly these keys:
{{
  "executive_summary": "3-4 paragraph executive summary suitable for a CISO/board audience. Explain the engagement purpose, overall risk posture, and top concerns.",
  "conclusion": "2-3 paragraph conclusion covering overall security maturity, critical remediation priorities, and recommended next steps.",
  "finding_remediations": {{
    "<finding_title>": "Detailed step-by-step remediation for this specific finding — 4-8 concrete technical steps."
  }}
}}

Include a remediation entry for every finding listed above.
"""
        llm = get_llm()
        resp = await llm.ainvoke([SystemMessage(content=system), HumanMessage(content=prompt)])
        raw = str(resp.content).strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.rsplit("```", 1)[0].strip()
        return json.loads(raw)
    except Exception as exc:
        logger.warning("AI report generation failed: %s", exc)
        return {}


# ── From-Scan auto-generate ───────────────────────────────────────────────────

@router.post("/clients/{cid}/vapt-reports/from-scan/", status_code=status.HTTP_201_CREATED)
async def create_report_from_scan(
    cid: str,
    payload: VAPTReportFromScan,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """
    Create a fully populated VAPT report from an existing scan.
    Findings, scope, methodology are derived from scan data.
    Executive summary, conclusion, and per-finding remediation are AI-generated.
    """
    client = _get_client_or_404(cid, db)
    scan = db.query(Scan).filter(Scan.id == payload.scan_id, Scan.client_id == cid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings: List[Finding] = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    # Derive scan type label
    connector_type = ""
    if scan.connector:
        ct = scan.connector.connector_type
        connector_type = ct.value if hasattr(ct, "value") else str(ct)
    elif scan.scan_type:
        st = scan.scan_type
        connector_type = st.value if hasattr(st, "value") else str(st)

    # Build scope from unique assets
    assets = sorted({f.resource_id for f in findings if f.resource_id})
    scope = {
        "in_scope": assets[:50],
        "out_of_scope": [],
        "scan_type": connector_type,
        "scan_id": scan.id,
        "scan_name": scan.name or "",
    }

    # Methodology from template
    methodology = _METHODOLOGY.get(connector_type, _DEFAULT_METHODOLOGY)

    # Build findings dicts for AI
    findings_for_ai = [
        {
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "description": f.description or "",
            "resource_id": f.resource_id or "",
            "remediation": f.remediation or "",
            "evidence": json.dumps(f.evidence) if f.evidence else "",
            "cve_id": f.cve_id or "",
            "cvss_score": f.cvss_score,
        }
        for f in findings
    ]

    # AI generation (gracefully degrades if LLM unavailable)
    ai = await _ai_generate_report_content(
        client_name=client.name,
        scan_type=connector_type,
        findings=findings_for_ai,
        scope=scope,
    )

    title = payload.title or f"VAPT Report — {scan.name or connector_type.upper()} — {client.name}"

    report = VAPTReport(
        client_id=cid,
        scan_id=scan.id,
        title=title,
        classification=payload.classification,
        version="1.0",
        prepared_by=payload.prepared_by,
        report_date=datetime.now(timezone.utc),
        status="draft",
        executive_summary=ai.get("executive_summary", ""),
        scope_json=json.dumps(scope),
        methodology_json=json.dumps(methodology),
        conclusion=ai.get("conclusion", ""),
    )
    db.add(report)
    db.flush()

    # Import findings
    ai_remediations: Dict[str, str] = ai.get("finding_remediations", {})
    sev_order = ["critical", "high", "medium", "low", "informational", "info"]

    sorted_findings = sorted(
        findings_for_ai,
        key=lambda x: sev_order.index(x["severity"].lower()) if x["severity"].lower() in sev_order else 99,
    )

    for idx, fd in enumerate(sorted_findings):
        sev = fd["severity"].lower()
        if sev == "info":
            sev = "informational"
        enhanced_remediation = ai_remediations.get(fd["title"], fd.get("remediation", ""))
        vapt_finding = VAPTFinding(
            report_id=report.id,
            finding_id=f"F-{idx + 1:02d}",
            title=fd["title"],
            severity=sev,
            affected_asset=fd["resource_id"],
            description=fd["description"],
            impact="",
            evidence=fd["evidence"],
            reproduction_steps="",
            recommendation=enhanced_remediation,
            references=fd["cve_id"] if fd.get("cve_id") else "",
            retest_status="pending",
            order_index=idx,
        )
        db.add(vapt_finding)

    db.commit()
    db.refresh(report)
    d = _report_to_dict(report)
    d["findings"] = [_finding_to_dict(f) for f in report.findings]
    d["finding_counts"] = _sev_counts(report.findings)
    d["total_findings"] = len(report.findings)
    return d


# ── Get / Update / Delete ─────────────────────────────────────────────────────

@router.get("/clients/{cid}/vapt-reports/{rid}/")
async def get_vapt_report(
    cid: str,
    rid: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    report = _get_report_or_404(rid, cid, db)
    d = _report_to_dict(report)
    d["findings"] = [_finding_to_dict(f) for f in report.findings]
    d["finding_counts"] = _sev_counts(report.findings)
    d["total_findings"] = len(report.findings)
    return d


@router.patch("/clients/{cid}/vapt-reports/{rid}/")
async def update_vapt_report(
    cid: str,
    rid: str,
    payload: VAPTReportUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    report = _get_report_or_404(rid, cid, db)
    data = payload.model_dump(exclude_unset=True)

    # Parse date fields
    for date_field in ("report_date", "retest_date"):
        if date_field in data and data[date_field]:
            try:
                data[date_field] = datetime.fromisoformat(
                    str(data[date_field]).replace("Z", "+00:00")
                )
            except Exception:
                data[date_field] = None

    for key, value in data.items():
        setattr(report, key, value)
    report.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(report)
    d = _report_to_dict(report)
    d["findings"] = [_finding_to_dict(f) for f in report.findings]
    d["finding_counts"] = _sev_counts(report.findings)
    d["total_findings"] = len(report.findings)
    return d


@router.delete("/clients/{cid}/vapt-reports/{rid}/", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vapt_report(
    cid: str,
    rid: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    report = _get_report_or_404(rid, cid, db)
    db.delete(report)
    db.commit()


# ── Retest ────────────────────────────────────────────────────────────────────

@router.post("/clients/{cid}/vapt-reports/{rid}/retest/", status_code=status.HTTP_201_CREATED)
async def create_retest_version(
    cid: str,
    rid: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    original = _get_report_or_404(rid, cid, db)
    new_version = _bump_version(original.version)

    new_report = VAPTReport(
        client_id=cid,
        parent_report_id=original.id,
        title=original.title,
        version=new_version,
        classification=original.classification,
        prepared_by=original.prepared_by,
        reviewed_by=original.reviewed_by,
        report_date=original.report_date,
        status="draft",
        executive_summary=original.executive_summary,
        scope_json=original.scope_json,
        methodology_json=original.methodology_json,
        conclusion=original.conclusion,
        appendices=original.appendices,
    )
    db.add(new_report)
    db.flush()  # get new_report.id without committing

    # Copy all findings with retest_status reset to pending
    for fi, f in enumerate(original.findings):
        new_finding = VAPTFinding(
            report_id=new_report.id,
            finding_id=f.finding_id,
            title=f.title,
            severity=f.severity,
            affected_asset=f.affected_asset,
            description=f.description,
            impact=f.impact,
            evidence=f.evidence,
            reproduction_steps=f.reproduction_steps,
            recommendation=f.recommendation,
            references=f.references,
            retest_status="pending",
            retest_notes=None,
            order_index=f.order_index,
        )
        db.add(new_finding)

    db.commit()
    db.refresh(new_report)
    d = _report_to_dict(new_report)
    d["findings"] = [_finding_to_dict(f) for f in new_report.findings]
    d["finding_counts"] = _sev_counts(new_report.findings)
    d["total_findings"] = len(new_report.findings)
    return d


# ── Findings CRUD ─────────────────────────────────────────────────────────────

@router.post("/clients/{cid}/vapt-reports/{rid}/findings/", status_code=status.HTTP_201_CREATED)
async def add_finding(
    cid: str,
    rid: str,
    payload: VAPTFindingCreate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    report = _get_report_or_404(rid, cid, db)
    finding = VAPTFinding(
        report_id=rid,
        finding_id=payload.finding_id,
        title=payload.title,
        severity=payload.severity.lower(),
        affected_asset=payload.affected_asset,
        description=payload.description,
        impact=payload.impact,
        evidence=payload.evidence,
        reproduction_steps=payload.reproduction_steps,
        recommendation=payload.recommendation,
        references=payload.references,
        retest_status=payload.retest_status,
        retest_notes=payload.retest_notes,
        order_index=payload.order_index,
    )
    db.add(finding)
    report.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(finding)
    return _finding_to_dict(finding)


@router.patch("/clients/{cid}/vapt-reports/{rid}/findings/{fid}/")
async def update_finding(
    cid: str,
    rid: str,
    fid: str,
    payload: VAPTFindingUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    _get_report_or_404(rid, cid, db)
    finding = _get_finding_or_404(fid, rid, db)
    data = payload.model_dump(exclude_unset=True)
    if "severity" in data and data["severity"]:
        data["severity"] = data["severity"].lower()
    for key, value in data.items():
        setattr(finding, key, value)
    db.commit()
    db.refresh(finding)
    return _finding_to_dict(finding)


@router.delete("/clients/{cid}/vapt-reports/{rid}/findings/{fid}/", status_code=status.HTTP_204_NO_CONTENT)
async def delete_finding(
    cid: str,
    rid: str,
    fid: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    _get_report_or_404(rid, cid, db)
    finding = _get_finding_or_404(fid, rid, db)
    db.delete(finding)
    db.commit()


# ── Export endpoints ──────────────────────────────────────────────────────────

def _export_stream(data: bytes, media_type: str, filename: str) -> StreamingResponse:
    return StreamingResponse(
        io.BytesIO(data),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/clients/{cid}/vapt-reports/{rid}/export/pdf")
async def export_full_pdf(
    cid: str,
    rid: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    report = _get_report_or_404(rid, cid, db)
    client = _get_client_or_404(cid, db)
    from services.vapt_export import generate_pdf
    findings_dicts = [_finding_to_dict(f) for f in report.findings]
    pdf_bytes = generate_pdf(_report_to_dict(report), findings_dicts, client.name)
    filename = f"vapt-report-{report.version}-{rid[:8]}.pdf"
    return _export_stream(pdf_bytes, "application/pdf", filename)


@router.get("/clients/{cid}/vapt-reports/{rid}/export/docx")
async def export_full_docx(
    cid: str,
    rid: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    report = _get_report_or_404(rid, cid, db)
    client = _get_client_or_404(cid, db)
    from services.vapt_export import generate_docx
    findings_dicts = [_finding_to_dict(f) for f in report.findings]
    docx_bytes = generate_docx(_report_to_dict(report), findings_dicts, client.name)
    filename = f"vapt-report-{report.version}-{rid[:8]}.docx"
    return _export_stream(
        docx_bytes,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename,
    )


@router.get("/clients/{cid}/vapt-reports/{rid}/export/remediation-pdf")
async def export_remediation_pdf(
    cid: str,
    rid: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    report = _get_report_or_404(rid, cid, db)
    client = _get_client_or_404(cid, db)
    from services.vapt_export import generate_remediation_pdf
    findings_dicts = [_finding_to_dict(f) for f in report.findings]
    pdf_bytes = generate_remediation_pdf(_report_to_dict(report), findings_dicts, client.name)
    filename = f"vapt-remediation-{report.version}-{rid[:8]}.pdf"
    return _export_stream(pdf_bytes, "application/pdf", filename)


@router.get("/clients/{cid}/vapt-reports/{rid}/export/remediation-docx")
async def export_remediation_docx(
    cid: str,
    rid: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    report = _get_report_or_404(rid, cid, db)
    client = _get_client_or_404(cid, db)
    from services.vapt_export import generate_remediation_docx
    findings_dicts = [_finding_to_dict(f) for f in report.findings]
    docx_bytes = generate_remediation_docx(_report_to_dict(report), findings_dicts, client.name)
    filename = f"vapt-remediation-{report.version}-{rid[:8]}.docx"
    return _export_stream(
        docx_bytes,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename,
    )
