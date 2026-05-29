"""Structured AI verdict for a completed scan.

When a scan flips to COMPLETED via /scans/ingest/ (or via the synchronous
in-process scanners), we kick off `generate_verdict` to produce a single
structured JSON object that the Assessments detail page renders as:

  The Verdict           — one-line headline
  What We Found         — narrative of the findings
  Why It Matters        — business + regulatory consequence
  Executive Summary     — multi-paragraph CISO-level summary
  Capability Gaps       — recommendations grouped by gap
  Signal Coverage       — coverage scorecards per signal source
  Attack Path Evidence  — chained-exploit narratives
  Vendor Scorecard      — vendor-by-vendor coverage scores
  Automation Opportunities
  Data Completeness     — what's evidenced vs estimated vs unknown

Plus per-finding Risk Priority Scores (RPS) with factor-level source tags.

The LLM call is best-effort: if no AI provider is configured or the call
fails, we still persist a fallback verdict built purely from finding
counts so the UI has something to render.
"""
from __future__ import annotations
import json
import logging
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from api.models.models import Finding, Scan, Client, Connector, AgentRun

logger = logging.getLogger(__name__)


# ── Risk Priority Score ──────────────────────────────────────────────────────

SEV_TO_CVSS_FALLBACK = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 1.0}
SEV_TO_EPSS_ESTIMATE = {"critical": 0.55, "high": 0.20, "medium": 0.05, "low": 0.01, "info": 0.005}


def compute_rps(finding: Finding) -> Dict[str, Any]:
    """Compute the multi-signal Risk Priority Score for a single finding.

    RPS = CVSS × EPSS × KEV_multiplier × reachability × exploitability
          × asset_criticality × business_context

    Every factor carries a source tag (evidenced / estimated / unknown) so
    the UI can show how much of the score is grounded in connected tools
    vs LLM-inferred vs missing.
    """
    sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    factors: Dict[str, Dict[str, Any]] = {}

    # CVSS — evidenced if the scanner provided a real score, else estimated
    if finding.cvss_score and finding.cvss_score > 0:
        factors["cvss"] = {
            "value": round(float(finding.cvss_score), 1),
            "source": "evidenced",
            "provider": (finding.evidence or {}).get("primary_url") and "scanner" or "scanner",
            "rationale": "Base CVSS provided by scanner / NVD lookup.",
        }
    else:
        factors["cvss"] = {
            "value": SEV_TO_CVSS_FALLBACK.get(sev, 5.0),
            "source": "estimated",
            "rationale": f"No CVSS available; derived from severity={sev}.",
        }

    # EPSS — no FIRST.org feed wired yet, mark estimated
    factors["epss"] = {
        "value": SEV_TO_EPSS_ESTIMATE.get(sev, 0.05),
        "source": "estimated",
        "rationale": "No EPSS feed integration yet; severity-mapped fallback. Wire FIRST.org for evidenced values.",
    }

    # KEV multiplier — no CISA KEV catalog ingestion yet
    factors["kev_multiplier"] = {
        "value": 1.0,
        "source": "unknown",
        "rationale": "CISA KEV catalog not yet integrated. CVEs found in KEV will multiply by 3 once enabled.",
    }

    # Reachability — Wiz ∩ CrowdStrike Spotlight cross-join not wired
    factors["reachability"] = {
        "value": 1.0,
        "source": "unknown",
        "rationale": "Runtime reachability requires Wiz/CrowdStrike integration. Default 1.0 (assume reachable).",
    }

    # Exploitability — heuristic based on CVSS bucket
    cvss = factors["cvss"]["value"]
    if cvss >= 9:
        expl = 3.0
    elif cvss >= 7:
        expl = 2.0
    else:
        expl = 1.0
    factors["exploitability"] = {
        "value": expl,
        "source": "estimated",
        "rationale": f"CVSS-bucketed proxy (no Mandiant/GTI/Recorded Future integration). CVSS {cvss} → tier {int(expl)}.",
    }

    # Asset criticality — no asset crown-jewel ontology hookup yet
    factors["asset_criticality"] = {
        "value": 5.0,
        "source": "estimated",
        "rationale": "Default mid-tier (5/10). Hook the crown-jewel list / asset ontology for evidenced values.",
    }

    # Business context — mission-derived multiplier, default 1.0
    factors["business_context"] = {
        "value": 1.0,
        "source": "estimated",
        "rationale": "Default 1.0. Mission inputs (compliance scope, revenue) will lift to 1.0–1.5.",
    }

    # Drop unknown factors from the multiplicative score (don't penalise);
    # apply only evidenced + estimated.
    score = 1.0
    used = 0
    for k, f in factors.items():
        if f["source"] == "unknown":
            continue
        score *= float(f["value"])
        used += 1

    low_confidence = sum(1 for f in factors.values() if f["source"] == "evidenced") <= 1

    return {
        "rps": round(score, 2),
        "factors": factors,
        "factors_used": used,
        "low_confidence": low_confidence,
    }


# ── Heuristic / scaffolded verdict ───────────────────────────────────────────

def _category_for_connector(ct: str) -> str:
    if ct in {"semgrep", "codeql", "sonarqube"}: return "SAST"
    if ct in {"nmap", "openvas", "trivy"}: return "Network"
    if ct in {"owasp_dc", "gitleaks", "trufflehog"}: return "Dependency"
    if ct == "web": return "DAST"
    if ct in {"azure", "aws", "gcp", "entraid", "containers", "onprem", "servicenow", "okta", "github", "jira"}: return "Cloud"
    return "Other"


def _summarise_findings(findings: List[Finding]) -> Dict[str, Any]:
    counter = Counter()
    by_resource = Counter()
    cwe_seen = set()
    cves = set()
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        counter[sev] += 1
        if f.resource_id:
            by_resource[f.resource_id] += 1
        if f.cve_id:
            cves.add(f.cve_id)
        ev = f.evidence or {}
        cwe = ev.get("cwe") or ev.get("cwe_id")
        if cwe:
            cwe_seen.add(str(cwe))
    return {
        "counts": dict(counter),
        "total": sum(counter.values()),
        "top_resources": by_resource.most_common(5),
        "unique_cwes": len(cwe_seen),
        "unique_cves": len(cves),
    }


def _vendor_scorecard(findings: List[Finding], category: str) -> List[Dict[str, Any]]:
    """Heuristic vendor scorecard. Maps category → the vendor names a CISO
    expects to see in a scorecard. Each vendor row gets a coverage score
    inferred from whether their fingerprints appear in finding evidence.
    """
    catalog = {
        "Network": ["CrowdStrike", "Microsoft Defender", "Palo Alto", "Wiz", "Qualys", "Tenable", "Rapid7"],
        "DAST":    ["OWASP ZAP", "Burp", "Invicti", "Veracode DAST", "Checkmarx DAST"],
        "SAST":    ["Semgrep", "GitHub CodeQL", "SonarQube", "Checkmarx", "Veracode", "Snyk Code"],
        "Dependency": ["Snyk", "Dependabot", "Mend", "Black Duck", "OWASP Dependency-Check", "Gitleaks", "TruffleHog"],
        "Cloud":   ["Wiz", "Microsoft Defender for Cloud", "CrowdStrike Falcon Cloud", "Orca", "Lacework", "Prisma Cloud"],
    }
    vendors = catalog.get(category, catalog["Network"])
    out: List[Dict[str, Any]] = []
    blob = " ".join(
        ((f.title or "") + " " + (f.description or "") + " " + json.dumps(f.evidence or {}))
        for f in findings[:200]
    ).lower()
    for v in vendors:
        evidence_hits = blob.count(v.split()[0].lower())
        score = min(10.0, round(evidence_hits * 1.5, 1)) if evidence_hits else 0.0
        out.append({
            "vendor": v,
            "score": score,
            "evidence_hits": evidence_hits,
            "notes": (
                f"Detected {evidence_hits} reference(s) in scan output." if evidence_hits
                else "No fingerprints detected in this scan. Configure or correlate this vendor's signal for coverage."
            ),
        })
    out.sort(key=lambda x: x["score"], reverse=True)
    return out


def _signal_coverage(category: str, findings: List[Finding]) -> List[Dict[str, Any]]:
    """Rough self-report on what signals this scan covered vs gaps."""
    coverage = []
    if category == "DAST":
        coverage = [
            {"signal": "Passive crawl", "coverage_pct": 100, "notes": "ZAP baseline (passive) covers all reachable endpoints."},
            {"signal": "Authenticated active scan", "coverage_pct": 60, "notes": "Auth profile required for full coverage; baseline misses post-auth paths."},
            {"signal": "API spec import", "coverage_pct": 0, "notes": "OpenAPI/Swagger import not yet wired."},
        ]
    elif category == "SAST":
        coverage = [
            {"signal": "Source-code SAST", "coverage_pct": 90, "notes": "Curated security ruleset (Semgrep auto config)."},
            {"signal": "Custom org rules", "coverage_pct": 0, "notes": "Org-specific rule pack not loaded."},
        ]
    elif category == "Dependency":
        coverage = [
            {"signal": "Git history secret scan", "coverage_pct": 100, "notes": "Full git history walked."},
            {"signal": "Live secret verification", "coverage_pct": 60, "notes": "TruffleHog verifies a subset of detector types."},
        ]
    elif category == "Network":
        coverage = [
            {"signal": "Container image CVE", "coverage_pct": 100, "notes": "Trivy DB updated nightly."},
            {"signal": "Network host vuln (OpenVAS)", "coverage_pct": 0, "notes": "OpenVAS workflow not yet wired."},
        ]
    else:
        coverage = [
            {"signal": "Cloud config review", "coverage_pct": 80, "notes": "Native ARM/CIS checks executed."},
            {"signal": "Runtime threat detection", "coverage_pct": 0, "notes": "Runtime CWPP not yet integrated."},
        ]
    return coverage


def _attack_paths(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Best-effort attack-path narratives from finding clusters. The full
    graph engine isn't wired yet; we surface clear single-hop chains based
    on resource overlap.
    """
    paths: List[Dict[str, Any]] = []
    # Find resources with multiple high+ findings → single-hop path
    by_resource: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        if not f.resource_id:
            continue
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev in ("critical", "high"):
            by_resource[f.resource_id].append(f)
    for res, group in sorted(by_resource.items(), key=lambda x: -len(x[1]))[:3]:
        if len(group) < 2:
            continue
        titles = [g.title for g in group[:3]]
        paths.append({
            "path": f"Attacker chains {len(group)} flaws on `{res}` to escalate to a high-impact compromise.",
            "resource": res,
            "evidence": " → ".join(titles),
            "finding_count": len(group),
        })
    return paths


def _capability_gaps(category: str, summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    if summary["counts"].get("critical", 0) > 0:
        gaps.append({
            "gap": f"{summary['counts']['critical']} critical issue(s) currently unmitigated.",
            "recommendation": "Triage critical findings within 24h. Assign owners and SLA per remediation policy.",
        })
    if summary["unique_cves"] > 5:
        gaps.append({
            "gap": f"Vulnerability backlog: {summary['unique_cves']} unique CVEs.",
            "recommendation": "Establish CVE patch SLA (critical=7d, high=30d) and automate ticket creation.",
        })
    if category == "DAST":
        gaps.append({
            "gap": "Authenticated DAST coverage incomplete.",
            "recommendation": "Onboard authenticated active scan profiles for all user roles. Add API spec ingestion.",
        })
    if category == "Dependency":
        gaps.append({
            "gap": "Secret rotation runbook not codified.",
            "recommendation": "Adopt automated secret rotation + commit-hook detection (pre-receive).",
        })
    if not gaps:
        gaps.append({
            "gap": "No major gaps detected from this single scan.",
            "recommendation": "Maintain cadence + expand coverage to adjacent categories (DAST/SAST/Network/Dependency).",
        })
    return gaps


def _automation_opps(category: str, summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "title": "Auto-ticket critical findings",
            "description": f"Route the {summary['counts'].get('critical', 0)} critical finding(s) into Jira on scan-complete via a workflow trigger.",
            "estimated_effort": "1 day",
        },
        {
            "title": "Recurring scan schedule",
            "description": "Promote this scan into a scheduled workflow (Workflows page) so coverage doesn't drift.",
            "estimated_effort": "5 minutes",
        },
        {
            "title": "Risk-quant refresh",
            "description": "Wire the AI Risk Manager agent to re-quantify the risk portfolio on every scan completion.",
            "estimated_effort": "1 hour",
        },
    ]


def _data_completeness(findings: List[Finding]) -> Dict[str, Any]:
    """Roll up evidenced/estimated/unknown ratios for the scan."""
    counts = {"evidenced": 0, "estimated": 0, "unknown": 0}
    for f in findings:
        rps = compute_rps(f)
        for fac in rps["factors"].values():
            counts[fac["source"]] = counts.get(fac["source"], 0) + 1
    total = sum(counts.values()) or 1
    return {
        "evidenced_pct": round(100 * counts["evidenced"] / total, 1),
        "estimated_pct": round(100 * counts["estimated"] / total, 1),
        "unknown_pct": round(100 * counts["unknown"] / total, 1),
        "counts": counts,
        "notes": (
            "Plug EPSS, CISA KEV, Wiz reachability, and crown-jewel asset criticality feeds "
            "to flip estimated → evidenced. RPS already drops unknown factors so they don't penalise scores."
        ),
    }


# ── Generator ────────────────────────────────────────────────────────────────


async def _llm_summary(
    *, category: str, client_name: str, summary: Dict[str, Any], findings: List[Finding],
) -> Dict[str, str]:
    """Best-effort LLM narrative for The Verdict / What We Found / Why It Matters
    / Executive Summary. If no provider is configured, returns deterministic
    fallback text so the UI always has something to render."""
    fallback = {
        "verdict": (
            f"{summary['counts'].get('critical', 0)} critical, {summary['counts'].get('high', 0)} high — "
            f"{category} assessment for {client_name}."
        ),
        "what_we_found": (
            f"The scan surfaced {summary['total']} finding(s) across {len(summary['top_resources'])} top resources. "
            f"Severity breakdown: {summary['counts']}."
        ),
        "why_it_matters": (
            "Unmitigated critical/high findings expose the business to data loss, regulatory penalties, and "
            "operational disruption. Cost of inaction scales with dwell time and asset criticality."
        ),
        "executive_summary": (
            f"This {category} assessment ran against {client_name}'s environment and produced "
            f"{summary['total']} findings. The most pressing items concentrate on the top resources listed. "
            "Recommend prioritising critical/high issues in the next sprint."
        ),
    }
    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        sample_lines = []
        for f in findings[:30]:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sample_lines.append(f"- [{sev}] {f.title} on {f.resource_id or 'n/a'}")
        sample = "\n".join(sample_lines) or "(no findings)"
        system = (
            "You write concise security verdicts for CISOs. Return STRICT JSON with keys "
            "verdict (one sentence), what_we_found (3-5 sentences), why_it_matters (3-5 sentences), "
            "executive_summary (1 short paragraph). No prose outside JSON."
        )
        prompt = (
            f"Client: {client_name}\nAssessment category: {category}\n"
            f"Total findings: {summary['total']}\nSeverity counts: {summary['counts']}\n"
            f"Unique CVEs: {summary['unique_cves']} | Unique CWEs: {summary['unique_cwes']}\n"
            f"Sample findings:\n{sample}\n\n"
            "Return ONLY the JSON object."
        )
        llm = get_llm(temperature=0.2, max_tokens=1500)
        result = await llm.ainvoke([SystemMessage(content=system), HumanMessage(content=prompt)])
        text = result.content if hasattr(result, "content") else str(result)
        if isinstance(text, list):
            text = "\n".join(str(p) for p in text)
        # Find first { ... }
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            data = json.loads(text[start:end + 1])
            for k in ("verdict", "what_we_found", "why_it_matters", "executive_summary"):
                if k in data and isinstance(data[k], str):
                    fallback[k] = data[k]
    except Exception as exc:
        logger.warning("LLM verdict narrative failed; using fallback (%s)", exc)
    return fallback


async def generate_verdict(db: Session, scan: Scan) -> Dict[str, Any]:
    """Build the structured verdict, persist on the Scan, return it."""
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    client = db.query(Client).filter(Client.id == scan.client_id).first()
    client_name = client.name if client else "Unknown Client"

    connector_type = ""
    if scan.connector_id:
        conn = db.query(Connector).filter(Connector.id == scan.connector_id).first()
        if conn:
            ct = conn.connector_type
            connector_type = ct.value if hasattr(ct, "value") else str(ct)
    category = _category_for_connector(connector_type)

    summary = _summarise_findings(findings)
    narrative = await _llm_summary(
        category=category, client_name=client_name, summary=summary, findings=findings,
    )

    verdict_obj: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "client_name": client_name,
        "summary": summary,
        "verdict": narrative["verdict"],
        "what_we_found": narrative["what_we_found"],
        "why_it_matters": narrative["why_it_matters"],
        "executive_summary": narrative["executive_summary"],
        "capability_gaps": _capability_gaps(category, summary),
        "signal_coverage": _signal_coverage(category, findings),
        "attack_paths": _attack_paths(findings),
        "vendor_scorecard": _vendor_scorecard(findings, category),
        "automation_opportunities": _automation_opps(category, summary),
        "data_completeness": _data_completeness(findings),
    }

    scan.ai_verdict = verdict_obj
    scan.ai_verdict_generated_at = datetime.now(timezone.utc)
    db.flush()
    return verdict_obj


def generate_verdict_bg(scan_id: str) -> None:
    """Background entry point — open own session."""
    from db.database import SessionLocal
    import asyncio
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.warning("Verdict requested for missing scan %s", scan_id)
            return
        asyncio.run(generate_verdict(db, scan))
        db.commit()
    except Exception:
        logger.exception("Verdict generation failed for scan %s", scan_id)
        db.rollback()
    finally:
        db.close()
