"""
Scan result importer — parse offline scan files from any tool into Aegis findings.

Supports structured parsers for known formats, LLM fallback for unknown/PDF,
CVE enrichment from NVD, and delta diff against existing findings.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

# ── Schema ────────────────────────────────────────────────────────────────────

@dataclass
class ParsedFinding:
    title: str
    description: str = ""
    severity: str = "medium"           # critical/high/medium/low/info
    resource_id: str = ""
    resource_type: str = "unknown"     # host/url/file/container/cloud_resource/unknown
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: str = ""
    control_id: Optional[str] = None
    confidence: float = 1.0            # 0.0-1.0
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_finding_kwargs(self, scan_id: str, source_format: str) -> Dict[str, Any]:
        return {
            "scan_id": scan_id,
            "title": self.title[:500],
            "description": self.description[:5000],
            "severity": self.severity,
            "resource_id": self.resource_id[:500],
            "resource_type": self.resource_type,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation[:3000],
            "control_id": self.control_id,
            "status": "open",
            "source_format": source_format,
            "import_confidence": self.confidence,
            "evidence": {"raw": self.raw},
        }


@dataclass
class DeltaResult:
    new_count: int = 0
    fixed_count: int = 0
    persisting_count: int = 0
    new_titles: List[str] = field(default_factory=list)
    fixed_titles: List[str] = field(default_factory=list)
    persisting_titles: List[str] = field(default_factory=list)


# ── Format detection ──────────────────────────────────────────────────────────

def detect_format(content: bytes, filename: str) -> str:
    """Return one of: sarif, nessus, burp, openvas, qualys_xml, qualys_csv,
    checkmarx, csv, json, pdf, text, unknown."""
    fname = (filename or "").lower()
    if fname.endswith(".sarif") or fname.endswith(".sarif.json"):
        return "sarif"
    if fname.endswith(".nessus"):
        return "nessus"
    if fname.endswith(".pdf"):
        return "pdf"
    if fname.endswith(".csv"):
        # peek to distinguish Qualys CSV
        head = content[:2000].decode("utf-8", errors="replace")
        if "QID" in head or "CVSS_BASE" in head:
            return "qualys_csv"
        return "csv"

    # Try XML sniff
    snippet = content[:500].lstrip()
    if snippet.startswith(b"<"):
        text = snippet.decode("utf-8", errors="replace").lower()
        if "nessusclientdata" in text or "<policyname" in text:
            return "nessus"
        if "issues" in text and ("issue" in text) and ("severity" in text or "confidence" in text):
            return "burp"
        if "<report" in text and ("openvas" in text or "gsa" in text or "nvt" in text):
            return "openvas"
        if "<qualysguardscanreport" in text or "qualys" in text:
            return "qualys_xml"
        if "cxxml" in text or "checkmarx" in text or "<cxresult" in text:
            return "checkmarx"
        return "xml_unknown"

    # Try JSON sniff
    if snippet.startswith(b"{") or snippet.startswith(b"["):
        try:
            data = json.loads(content.decode("utf-8", errors="replace"))
            # SARIF has $schema or runs array
            if isinstance(data, dict):
                if "$schema" in data and "sarif" in str(data.get("$schema", "")).lower():
                    return "sarif"
                if "runs" in data and isinstance(data["runs"], list):
                    return "sarif"
            return "json"
        except Exception:
            pass

    return "unknown"


# ── Severity helpers ──────────────────────────────────────────────────────────

def _normalise_severity(raw: str) -> str:
    r = (raw or "").strip().lower()
    if r in ("critical", "4"):
        return "critical"
    if r in ("high", "3", "error"):
        return "high"
    if r in ("medium", "moderate", "2", "warning"):
        return "medium"
    if r in ("low", "1", "note", "informational", "information"):
        return "low"
    return "info"


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# ── Structured parsers ────────────────────────────────────────────────────────

def parse_sarif(content: bytes) -> List[ParsedFinding]:
    findings = []
    try:
        data = json.loads(content.decode("utf-8", errors="replace"))
        for run in data.get("runs", []):
            rules: Dict[str, Any] = {}
            driver = run.get("tool", {}).get("driver", {})
            for r in driver.get("rules", []):
                rules[r["id"]] = r
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule = rules.get(rule_id, {})
                msg = result.get("message", {})
                desc = msg.get("text") or msg.get("markdown") or ""
                rule_desc = (rule.get("fullDescription") or rule.get("shortDescription") or {}).get("text", "")
                title = rule.get("name") or rule_id or desc[:80] or "Unknown finding"
                level = result.get("level", "warning")
                sev = _normalise_severity(level)

                # Extract location
                locs = result.get("locations", [])
                resource = ""
                if locs:
                    pl = locs[0].get("physicalLocation", {})
                    uri = pl.get("artifactLocation", {}).get("uri", "")
                    line = pl.get("region", {}).get("startLine", "")
                    resource = f"{uri}:{line}" if line else uri

                findings.append(ParsedFinding(
                    title=title,
                    description=rule_desc or desc,
                    severity=sev,
                    resource_id=resource,
                    resource_type="file",
                    confidence=0.95,
                    raw={"ruleId": rule_id, "level": level},
                ))
    except Exception as exc:
        logger.warning("SARIF parse error: %s", exc)
    return findings


def parse_nessus(content: bytes) -> List[ParsedFinding]:
    findings = []
    try:
        root = ET.fromstring(content)
        for host in root.findall(".//ReportHost"):
            hostname = host.get("name", "unknown")
            for item in host.findall("ReportItem"):
                sev_num = int(item.get("severity", "0"))
                sev_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
                sev = sev_map.get(sev_num, "info")
                plugin_name = item.get("pluginName", "Unknown Plugin")
                port = item.get("port", "")
                protocol = item.get("protocol", "")
                resource = f"{hostname}:{port}/{protocol}" if port else hostname

                cve_el = item.find("cve")
                cve_id = cve_el.text.strip() if cve_el is not None and cve_el.text else None

                cvss_el = item.find("cvss_base_score") or item.find("cvss3_base_score")
                cvss = None
                if cvss_el is not None and cvss_el.text:
                    try:
                        cvss = float(cvss_el.text.strip())
                    except ValueError:
                        pass

                desc_el = item.find("description")
                desc = desc_el.text.strip() if desc_el is not None and desc_el.text else ""
                sol_el = item.find("solution")
                remediation = sol_el.text.strip() if sol_el is not None and sol_el.text else ""

                if sev == "info" and not cve_id:
                    continue  # skip pure info items without CVEs

                findings.append(ParsedFinding(
                    title=plugin_name,
                    description=desc,
                    severity=sev,
                    resource_id=resource,
                    resource_type="host",
                    cve_id=cve_id,
                    cvss_score=cvss,
                    remediation=remediation,
                    confidence=0.98,
                    raw={"pluginID": item.get("pluginID"), "port": port},
                ))
    except Exception as exc:
        logger.warning("Nessus parse error: %s", exc)
    return findings


def parse_burp(content: bytes) -> List[ParsedFinding]:
    findings = []
    try:
        root = ET.fromstring(content)
        for issue in root.findall(".//issue"):
            name_el = issue.find("name")
            sev_el = issue.find("severity")
            detail_el = issue.find("issueDetail") or issue.find("issueBackground")
            url_el = issue.find("url") or issue.find("host")
            remediation_el = issue.find("remediationDetail") or issue.find("remediationBackground")

            title = name_el.text.strip() if name_el is not None and name_el.text else "Unknown Issue"
            sev_raw = sev_el.text.strip() if sev_el is not None and sev_el.text else "Information"
            sev = _normalise_severity(sev_raw)
            desc = detail_el.text.strip() if detail_el is not None and detail_el.text else ""
            # Strip HTML tags from Burp descriptions
            desc = re.sub(r"<[^>]+>", " ", desc).strip()
            resource = url_el.text.strip() if url_el is not None and url_el.text else ""
            remediation = ""
            if remediation_el is not None and remediation_el.text:
                remediation = re.sub(r"<[^>]+>", " ", remediation_el.text).strip()

            if sev == "info":
                continue

            findings.append(ParsedFinding(
                title=title,
                description=desc,
                severity=sev,
                resource_id=resource,
                resource_type="url",
                remediation=remediation,
                confidence=0.97,
                raw={"severity_raw": sev_raw},
            ))
    except Exception as exc:
        logger.warning("Burp parse error: %s", exc)
    return findings


def parse_openvas(content: bytes) -> List[ParsedFinding]:
    findings = []
    try:
        root = ET.fromstring(content)
        for result in root.findall(".//result"):
            name_el = result.find("name")
            desc_el = result.find("description") or result.find("nvt/comment")
            host_el = result.find("host")
            port_el = result.find("port")
            threat_el = result.find("threat")
            severity_el = result.find("severity")
            solution_el = result.find("nvt/solution")
            cve_el = result.find("nvt/cve")

            title = name_el.text.strip() if name_el is not None and name_el.text else "Unknown"
            desc = desc_el.text.strip() if desc_el is not None and desc_el.text else ""
            host = host_el.text.strip() if host_el is not None and host_el.text else ""
            port = port_el.text.strip() if port_el is not None and port_el.text else ""
            resource = f"{host}:{port}" if port else host

            sev_raw = threat_el.text.strip() if threat_el is not None and threat_el.text else "Low"
            sev = _normalise_severity(sev_raw)
            cvss = None
            if severity_el is not None and severity_el.text:
                try:
                    cvss = float(severity_el.text.strip())
                    sev = _cvss_to_severity(cvss)
                except ValueError:
                    pass

            cve_raw = cve_el.text.strip() if cve_el is not None and cve_el.text else ""
            cve_id = cve_raw if re.match(r"CVE-\d{4}-\d+", cve_raw) else None
            remediation = solution_el.text.strip() if solution_el is not None and solution_el.text else ""

            if sev == "info":
                continue

            findings.append(ParsedFinding(
                title=title,
                description=desc,
                severity=sev,
                resource_id=resource,
                resource_type="host",
                cve_id=cve_id,
                cvss_score=cvss,
                remediation=remediation,
                confidence=0.96,
                raw={"threat": sev_raw},
            ))
    except Exception as exc:
        logger.warning("OpenVAS parse error: %s", exc)
    return findings


def parse_qualys_xml(content: bytes) -> List[ParsedFinding]:
    findings = []
    try:
        root = ET.fromstring(content)
        for vuln in root.findall(".//VULN") or root.findall(".//QID"):
            title_el = vuln.find("TITLE")
            sev_el = vuln.find("SEVERITY")
            ip_el = vuln.find("IP") or vuln.find("HOST")
            cve_el = vuln.find("CVE_ID") or vuln.find("CVE")
            cvss_el = vuln.find("CVSS_BASE") or vuln.find("CVSS3_BASE")
            solution_el = vuln.find("SOLUTION")
            consequence_el = vuln.find("CONSEQUENCE") or vuln.find("DIAGNOSIS")

            title = title_el.text.strip() if title_el is not None and title_el.text else "Unknown"
            # Qualys severity 1-5
            sev_map = {"1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}
            sev_raw = sev_el.text.strip() if sev_el is not None and sev_el.text else "3"
            sev = sev_map.get(sev_raw, "medium")
            resource = ip_el.text.strip() if ip_el is not None and ip_el.text else ""
            cve_id = cve_el.text.strip() if cve_el is not None and cve_el.text else None
            cvss = None
            if cvss_el is not None and cvss_el.text:
                try:
                    cvss = float(cvss_el.text.strip())
                except ValueError:
                    pass
            remediation = solution_el.text.strip() if solution_el is not None and solution_el.text else ""
            desc = consequence_el.text.strip() if consequence_el is not None and consequence_el.text else ""

            findings.append(ParsedFinding(
                title=title,
                description=desc,
                severity=sev,
                resource_id=resource,
                resource_type="host",
                cve_id=cve_id,
                cvss_score=cvss,
                remediation=remediation,
                confidence=0.96,
                raw={"qualys_severity": sev_raw},
            ))
    except Exception as exc:
        logger.warning("Qualys XML parse error: %s", exc)
    return findings


def parse_qualys_csv(content: bytes) -> List[ParsedFinding]:
    findings = []
    try:
        text = content.decode("utf-8", errors="replace")
        # Skip Qualys header lines that start with ----
        lines = [l for l in text.splitlines() if not l.startswith("----") and l.strip()]
        reader = csv.DictReader(lines)
        sev_map = {"1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}
        for row in reader:
            title = row.get("Title") or row.get("Vulnerability") or row.get("QID", "Unknown")
            sev_raw = str(row.get("Severity") or row.get("SEVERITY") or "3")
            sev = sev_map.get(sev_raw.strip(), "medium")
            resource = row.get("IP") or row.get("Host") or row.get("DNS") or ""
            cve_raw = row.get("CVE ID") or row.get("CVE") or ""
            cve_id = cve_raw.strip() if re.match(r"CVE-\d{4}-\d+", cve_raw.strip()) else None
            cvss = None
            for k in ("CVSS Base", "CVSS3 Base", "CVSS_BASE"):
                if row.get(k):
                    try:
                        cvss = float(row[k])
                        break
                    except ValueError:
                        pass
            findings.append(ParsedFinding(
                title=title.strip(),
                description=row.get("Results") or row.get("Description") or "",
                severity=sev,
                resource_id=resource.strip(),
                resource_type="host",
                cve_id=cve_id,
                cvss_score=cvss,
                remediation=row.get("Solution") or row.get("Remediation") or "",
                confidence=0.93,
                raw=dict(list(row.items())[:10]),
            ))
    except Exception as exc:
        logger.warning("Qualys CSV parse error: %s", exc)
    return findings


def parse_checkmarx(content: bytes) -> List[ParsedFinding]:
    findings = []
    try:
        root = ET.fromstring(content)
        for query in root.findall(".//Query"):
            name = query.get("name", "Unknown")
            sev_num = query.get("Severity", "1")
            sev_map = {"0": "info", "1": "low", "2": "medium", "3": "high"}
            sev = sev_map.get(sev_num, "medium")
            for result in query.findall("Result"):
                filename = result.get("FileName", "")
                line = result.get("Line", "")
                resource = f"{filename}:{line}" if line else filename
                findings.append(ParsedFinding(
                    title=name,
                    description=f"Checkmarx finding: {name} at {resource}",
                    severity=sev,
                    resource_id=resource,
                    resource_type="file",
                    confidence=0.95,
                    raw={"query": name, "severity_raw": sev_num},
                ))
    except Exception as exc:
        logger.warning("Checkmarx parse error: %s", exc)
    return findings


def parse_generic_csv(content: bytes) -> Tuple[List[ParsedFinding], float]:
    """Best-effort CSV parse. Returns (findings, confidence)."""
    findings = []
    confidence = 0.7
    try:
        text = content.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))

        def _find(keys):
            for k in keys:
                for h in (reader.fieldnames or []):
                    if k in h.lower():
                        return h
            return None

        title_col = _find(["title", "name", "vulnerability", "vuln", "finding", "issue"])
        sev_col = _find(["severity", "risk", "level", "priority", "cvss"])
        desc_col = _find(["description", "detail", "summary", "info"])
        resource_col = _find(["host", "ip", "url", "resource", "target", "asset", "file"])
        cve_col = _find(["cve"])
        remediation_col = _find(["remediation", "solution", "fix", "recommendation"])

        if not title_col:
            return [], 0.3

        for row in reader:
            title = (row.get(title_col) or "").strip()
            if not title:
                continue
            sev_raw = (row.get(sev_col) or "medium").strip() if sev_col else "medium"
            sev = _normalise_severity(sev_raw)
            desc = (row.get(desc_col) or "").strip() if desc_col else ""
            resource = (row.get(resource_col) or "").strip() if resource_col else ""
            cve_raw = (row.get(cve_col) or "").strip() if cve_col else ""
            cve_id = cve_raw if re.match(r"CVE-\d{4}-\d+", cve_raw) else None
            remediation = (row.get(remediation_col) or "").strip() if remediation_col else ""
            findings.append(ParsedFinding(
                title=title,
                description=desc,
                severity=sev,
                resource_id=resource,
                resource_type="unknown",
                cve_id=cve_id,
                remediation=remediation,
                confidence=confidence,
                raw={},
            ))
    except Exception as exc:
        logger.warning("Generic CSV parse error: %s", exc)
    return findings, confidence


def parse_generic_json(content: bytes) -> Tuple[List[ParsedFinding], float]:
    """Best-effort JSON parse for unknown formats."""
    findings = []
    try:
        data = json.loads(content.decode("utf-8", errors="replace"))
        items = (
            data if isinstance(data, list)
            else data.get("findings")
            or data.get("results")
            or data.get("vulnerabilities")
            or data.get("issues")
            or []
        )
        if not isinstance(items, list):
            return [], 0.3
        for item in items:
            if not isinstance(item, dict):
                continue
            title = (
                item.get("title") or item.get("name") or item.get("vulnerability")
                or item.get("check_id") or "Unknown"
            )
            sev_raw = str(item.get("severity") or item.get("risk") or item.get("level") or "medium")
            sev = _normalise_severity(sev_raw)
            desc = str(item.get("description") or item.get("detail") or item.get("message") or "")
            resource = str(
                item.get("resource") or item.get("host") or item.get("url")
                or item.get("file") or item.get("target") or ""
            )
            cve_raw = str(item.get("cve") or item.get("cve_id") or "")
            cve_id = cve_raw if re.match(r"CVE-\d{4}-\d+", cve_raw) else None
            cvss = None
            for k in ("cvss_score", "cvss", "cvss_base", "score"):
                if item.get(k) is not None:
                    try:
                        cvss = float(item[k])
                        break
                    except (ValueError, TypeError):
                        pass
            remediation = str(item.get("remediation") or item.get("solution") or item.get("fix") or "")
            findings.append(ParsedFinding(
                title=str(title)[:500],
                description=desc[:5000],
                severity=sev,
                resource_id=resource[:500],
                resource_type="unknown",
                cve_id=cve_id,
                cvss_score=cvss,
                remediation=remediation[:3000],
                confidence=0.75,
                raw={},
            ))
    except Exception as exc:
        logger.warning("Generic JSON parse error: %s", exc)
    return findings, 0.75


# ── LLM normalizer ────────────────────────────────────────────────────────────

async def parse_with_llm(content: bytes, filename: str, tool_hint: str = "") -> List[ParsedFinding]:
    """Use LLM to parse unknown/PDF formats into normalised findings."""
    from core.ai_providers import get_llm
    from services.rag_service import extract_text

    try:
        # Extract text (handles PDF, DOCX, TXT)
        text = extract_text(content, filename)
        if not text or len(text.strip()) < 50:
            return []
        # Limit to 12000 chars to avoid token overruns
        text_snippet = text[:12000]
    except Exception:
        text_snippet = content.decode("utf-8", errors="replace")[:12000]

    tool_line = f"The file was exported from: {tool_hint}." if tool_hint else ""
    prompt = f"""You are a security finding normalizer. {tool_line}
Extract ALL security vulnerabilities from the scan report below and return them as a JSON array.

Each finding must follow this exact schema:
{{
  "title": "<concise vulnerability name, max 120 chars>",
  "description": "<detailed description>",
  "severity": "<critical|high|medium|low|info>",
  "resource_id": "<affected host, IP, URL, file path, or component>",
  "resource_type": "<host|url|file|container|cloud_resource|unknown>",
  "cve_id": "<CVE-YYYY-NNNNN or null>",
  "cvss_score": <float 0.0-10.0 or null>,
  "remediation": "<specific remediation steps>",
  "confidence": <0.0-1.0 how confident you are in this extraction>
}}

Rules:
- severity MUST be one of: critical, high, medium, low, info
- Only include actual security findings — not informational banners or metadata
- If the text contains no security findings, return []
- Return ONLY a JSON array, no markdown, no explanation

Scan report:
---
{text_snippet}
---"""

    try:
        llm = get_llm()
        from langchain_core.messages import HumanMessage
        resp = await llm.ainvoke([HumanMessage(content=prompt)])
        raw_text = resp.content.strip()
        # Strip markdown code fences if present
        raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
        raw_text = re.sub(r"\s*```$", "", raw_text)
        items = json.loads(raw_text)
        findings = []
        for item in items:
            if not isinstance(item, dict) or not item.get("title"):
                continue
            sev = _normalise_severity(str(item.get("severity") or "medium"))
            cvss = None
            try:
                cvss = float(item["cvss_score"]) if item.get("cvss_score") is not None else None
            except (TypeError, ValueError):
                pass
            cve_raw = str(item.get("cve_id") or "")
            cve_id = cve_raw if re.match(r"CVE-\d{4}-\d+", cve_raw) else None
            conf = float(item.get("confidence") or 0.6)
            findings.append(ParsedFinding(
                title=str(item.get("title", ""))[:500],
                description=str(item.get("description") or ""),
                severity=sev,
                resource_id=str(item.get("resource_id") or ""),
                resource_type=str(item.get("resource_type") or "unknown"),
                cve_id=cve_id,
                cvss_score=cvss,
                remediation=str(item.get("remediation") or ""),
                confidence=max(0.0, min(1.0, conf)),
                raw={"llm_parsed": True},
            ))
        return findings
    except Exception as exc:
        logger.error("LLM normalizer failed: %s", exc)
        return []


# ── CVE enrichment ────────────────────────────────────────────────────────────

async def enrich_cves(findings: List[ParsedFinding], nvd_api_key: str = "") -> List[ParsedFinding]:
    """Pull CVSS scores + descriptions from NVD for findings with CVE IDs."""
    cve_ids = {f.cve_id for f in findings if f.cve_id and f.cvss_score is None}
    if not cve_ids:
        return findings

    headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
    cache: Dict[str, Dict] = {}

    async with httpx.AsyncClient(timeout=10.0) as client:
        for cve_id in list(cve_ids)[:20]:  # cap at 20 NVD calls
            try:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve_id},
                    headers=headers,
                )
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_data = vulns[0].get("cve", {})
                    metrics = cve_data.get("metrics", {})
                    score = None
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        m = metrics.get(key)
                        if m:
                            score = m[0].get("cvssData", {}).get("baseScore")
                            break
                    descs = cve_data.get("descriptions", [])
                    en_desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                    cache[cve_id] = {"score": score, "description": en_desc}
            except Exception:
                pass

    enriched = []
    for f in findings:
        if f.cve_id and f.cve_id in cache:
            nvd = cache[f.cve_id]
            if f.cvss_score is None and nvd.get("score"):
                f.cvss_score = nvd["score"]
                if f.severity in ("info", "low", "medium") and f.cvss_score:
                    f.severity = _cvss_to_severity(f.cvss_score)
            if not f.description and nvd.get("description"):
                f.description = nvd["description"]
        enriched.append(f)
    return enriched


# ── Delta diff ────────────────────────────────────────────────────────────────

def compute_delta(
    new_findings: List[ParsedFinding],
    existing_open: List[Any],   # Finding ORM objects
) -> DeltaResult:
    """Compare new parsed findings against existing open findings.

    Match on: exact CVE ID, or normalised title similarity (lowercase, stripped).
    """
    def _key(title: str, cve: Optional[str]) -> str:
        if cve:
            return f"cve:{cve}"
        return "title:" + re.sub(r"[^a-z0-9]", "", (title or "").lower())[:60]

    existing_keys = {_key(f.title, getattr(f, "cve_id", None)) for f in existing_open}
    new_keys = {_key(f.title, f.cve_id) for f in new_findings}

    new_titles = [f.title for f in new_findings if _key(f.title, f.cve_id) not in existing_keys]
    fixed_titles = [
        getattr(f, "title", "") for f in existing_open
        if _key(getattr(f, "title", ""), getattr(f, "cve_id", None)) not in new_keys
    ]
    persisting_titles = [f.title for f in new_findings if _key(f.title, f.cve_id) in existing_keys]

    return DeltaResult(
        new_count=len(new_titles),
        fixed_count=len(fixed_titles),
        persisting_count=len(persisting_titles),
        new_titles=new_titles[:20],
        fixed_titles=fixed_titles[:20],
        persisting_titles=persisting_titles[:20],
    )


# ── Main entry point ──────────────────────────────────────────────────────────

async def import_scan_file(
    content: bytes,
    filename: str,
    tool_hint: str = "",
    nvd_api_key: str = "",
) -> Tuple[str, List[ParsedFinding]]:
    """Parse a scan file and return (detected_format, findings).

    Uses structured parsers for known formats; LLM fallback for unknown/PDF.
    CVE enrichment is applied automatically.
    """
    fmt = detect_format(content, filename)
    logger.info("Importing scan file '%s' detected as format: %s", filename, fmt)

    if fmt == "sarif":
        findings = parse_sarif(content)
    elif fmt == "nessus":
        findings = parse_nessus(content)
    elif fmt == "burp":
        findings = parse_burp(content)
    elif fmt == "openvas":
        findings = parse_openvas(content)
    elif fmt == "qualys_xml":
        findings = parse_qualys_xml(content)
    elif fmt == "qualys_csv":
        findings = parse_qualys_csv(content)
    elif fmt == "checkmarx":
        findings = parse_checkmarx(content)
    elif fmt == "csv":
        findings, _ = parse_generic_csv(content)
        if not findings:
            findings = await parse_with_llm(content, filename, tool_hint)
            fmt = "llm"
    elif fmt == "json":
        findings, _ = parse_generic_json(content)
        if not findings:
            findings = await parse_with_llm(content, filename, tool_hint)
            fmt = "llm"
    else:
        # PDF, unknown, XML with no recognised schema → LLM
        findings = await parse_with_llm(content, filename, tool_hint)
        fmt = "llm"

    # CVE enrichment
    findings = await enrich_cves(findings, nvd_api_key=nvd_api_key)
    return fmt, findings
