"""
Scan result importer — parse offline scan files from any tool into Owlet findings.

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
            tool_name = driver.get("name", "")
            tool_version = driver.get("version", "")
            for r in driver.get("rules", []):
                rules[r["id"]] = r
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule = rules.get(rule_id, {})
                msg = result.get("message", {})
                desc = msg.get("text") or msg.get("markdown") or ""
                rule_desc = (rule.get("fullDescription") or rule.get("shortDescription") or {}).get("text", "")
                rule_name = rule.get("name") or ""
                title = rule_name or rule_id or desc[:80] or "Unknown finding"
                level = result.get("level", "warning")
                sev = _normalise_severity(level)

                # Extract location
                locs = result.get("locations", [])
                artifact_uri = ""
                region_start_line = None
                region_end_line = None
                region_start_col = None
                logical_loc = ""
                if locs:
                    pl = locs[0].get("physicalLocation", {})
                    artifact_uri = pl.get("artifactLocation", {}).get("uri", "")
                    reg = pl.get("region", {})
                    region_start_line = reg.get("startLine")
                    region_end_line = reg.get("endLine")
                    region_start_col = reg.get("startColumn")
                    ll = locs[0].get("logicalLocations", [])
                    if ll:
                        logical_loc = ll[0].get("fullyQualifiedName") or ll[0].get("name") or ""
                resource = f"{artifact_uri}:{region_start_line}" if region_start_line else artifact_uri

                fingerprint = ""
                fps = result.get("fingerprints") or result.get("partialFingerprints") or {}
                if fps:
                    fingerprint = str(list(fps.values())[0])[:200]

                tags = ",".join(rule.get("tags") or [])
                props = result.get("properties") or {}

                findings.append(ParsedFinding(
                    title=title,
                    description=rule_desc or desc,
                    severity=sev,
                    resource_id=resource,
                    resource_type="file",
                    confidence=0.95,
                    raw={
                        "_table": "sarif",
                        "tool_name": tool_name,
                        "tool_version": tool_version,
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "level": level,
                        "message": desc,
                        "artifact_uri": artifact_uri,
                        "region_start_line": region_start_line,
                        "region_end_line": region_end_line,
                        "region_start_column": region_start_col,
                        "logical_location": logical_loc,
                        "fingerprint": fingerprint,
                        "suppressed": result.get("suppressions") is not None and len(result.get("suppressions", [])) > 0,
                        "rank": result.get("rank"),
                        "tags": tags,
                        "properties_json": json.dumps(props) if props else None,
                    },
                ))
    except Exception as exc:
        logger.warning("SARIF parse error: %s", exc)
    return findings


def _el_text(el) -> Optional[str]:
    return el.text.strip() if el is not None and el.text else None


def _el_float(el) -> Optional[float]:
    t = _el_text(el)
    if t is None:
        return None
    try:
        return float(t)
    except ValueError:
        return None


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
                plugin_id = item.get("pluginID", "")
                plugin_name = item.get("pluginName", "Unknown Plugin")
                plugin_family = item.get("pluginFamily", "")
                port_str = item.get("port", "")
                protocol = item.get("protocol", "")
                resource = f"{hostname}:{port_str}/{protocol}" if port_str else hostname

                cve_el = item.find("cve")
                cve_id = _el_text(cve_el)

                cvss_base = _el_float(item.find("cvss_base_score"))
                cvss3_base = _el_float(item.find("cvss3_base_score"))
                cvss = cvss3_base or cvss_base
                cvss_vec = _el_text(item.find("cvss_vector")) or _el_text(item.find("cvss3_vector"))
                cvss_temporal = _el_float(item.find("cvss_temporal_score"))
                cvss3_temporal = _el_float(item.find("cvss3_temporal_score"))
                risk_factor = _el_text(item.find("risk_factor"))
                desc = _el_text(item.find("description")) or ""
                synopsis = _el_text(item.find("synopsis"))
                remediation = _el_text(item.find("solution")) or ""
                see_also = _el_text(item.find("see_also"))
                plugin_output = _el_text(item.find("plugin_output"))
                bid = _el_text(item.find("bid"))
                exploit_avail = _el_text(item.find("exploit_available"))
                exploit_ease = _el_text(item.find("exploitability_ease"))
                msf = _el_text(item.find("metasploit_name"))

                try:
                    port_int = int(port_str) if port_str else None
                except ValueError:
                    port_int = None

                if sev == "info" and not cve_id:
                    continue

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
                    raw={
                        "_table": "nessus",
                        "plugin_id": plugin_id,
                        "plugin_name": plugin_name,
                        "plugin_family": plugin_family,
                        "severity_id": sev_num,
                        "risk_factor": risk_factor,
                        "host": hostname,
                        "port": port_int,
                        "protocol": protocol,
                        "cvss_base_score": cvss_base,
                        "cvss_temporal_score": cvss_temporal,
                        "cvss_vector": cvss_vec,
                        "cvss3_base_score": cvss3_base,
                        "cvss3_temporal_score": cvss3_temporal,
                        "cvss3_vector": cvss_vec,
                        "cve": cve_id,
                        "bid": bid,
                        "synopsis": synopsis,
                        "description": desc,
                        "solution": remediation,
                        "see_also": see_also,
                        "plugin_output": plugin_output,
                        "exploit_available": exploit_avail == "true" if exploit_avail else None,
                        "exploitability_ease": exploit_ease,
                        "metasploit": msf is not None,
                        "patch_available": None,
                    },
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
            conf_el = issue.find("confidence")
            detail_el = issue.find("issueDetail")
            bg_el = issue.find("issueBackground")
            url_el = issue.find("url")
            host_el = issue.find("host")
            path_el = issue.find("path")
            port_el = issue.find("port")
            protocol_el = issue.find("protocol")
            type_id_el = issue.find("type")
            rem_detail_el = issue.find("remediationDetail")
            rem_bg_el = issue.find("remediationBackground")
            vuln_class_el = issue.find("vulnerabilityClassifications")
            refs_el = issue.find("references")
            cwe_el = issue.find("cwes") or issue.find("cwe")

            title = _el_text(name_el) or "Unknown Issue"
            sev_raw = _el_text(sev_el) or "Information"
            sev = _normalise_severity(sev_raw)
            confidence_str = _el_text(conf_el) or ""

            def _strip_html(s: Optional[str]) -> str:
                if not s:
                    return ""
                return re.sub(r"<[^>]+>", " ", s).strip()

            detail = _strip_html(_el_text(detail_el))
            background = _strip_html(_el_text(bg_el))
            desc = detail or background
            rem_detail = _strip_html(_el_text(rem_detail_el))
            rem_bg = _strip_html(_el_text(rem_bg_el))
            remediation = rem_detail or rem_bg

            url = _el_text(url_el) or ""
            host = _el_text(host_el) or ""
            path = _el_text(path_el) or ""
            resource = url or (f"{host}{path}" if path else host)
            try:
                port_int = int(_el_text(port_el) or "")
            except (ValueError, TypeError):
                port_int = None

            if sev == "info":
                continue

            req_resp = ""
            rr = issue.find("requestresponse") or issue.find("requestResponse")
            if rr is not None:
                req_resp = ET.tostring(rr, encoding="unicode")[:10000]

            findings.append(ParsedFinding(
                title=title,
                description=desc,
                severity=sev,
                resource_id=resource,
                resource_type="url",
                remediation=remediation,
                confidence=0.97,
                raw={
                    "_table": "burp",
                    "issue_type_id": _el_text(type_id_el),
                    "issue_name": title,
                    "issue_detail": detail,
                    "issue_background": background,
                    "remediation_detail": rem_detail,
                    "remediation_background": rem_bg,
                    "path": path,
                    "host": host,
                    "port": port_int,
                    "protocol": _el_text(protocol_el),
                    "confidence": confidence_str,
                    "severity": sev_raw,
                    "vulnerability_classifications": _strip_html(_el_text(vuln_class_el)),
                    "references": _strip_html(_el_text(refs_el)),
                    "cwes": _el_text(cwe_el),
                    "request_response": req_resp,
                },
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
            nvt_el = result.find("nvt")
            bid_el = result.find("nvt/bid")
            xref_el = result.find("nvt/xref")
            qod_el = result.find("qod/value") or result.find("qod")
            tags_el = result.find("nvt/tags")

            title = _el_text(name_el) or "Unknown"
            desc = _el_text(desc_el) or ""
            host = _el_text(host_el) or ""
            port = _el_text(port_el) or ""
            resource = f"{host}:{port}" if port else host

            nvt_oid = nvt_el.get("oid", "") if nvt_el is not None else ""
            nvt_name = _el_text(nvt_el.find("name")) if nvt_el is not None else None
            nvt_family = _el_text(nvt_el.find("family")) if nvt_el is not None else None
            nvt_version = nvt_el.get("version", "") if nvt_el is not None else None
            solution_type_el = solution_el.get("type") if solution_el is not None else None

            sev_raw = _el_text(threat_el) or "Low"
            sev = _normalise_severity(sev_raw)
            cvss = _el_float(severity_el)
            if cvss is not None:
                sev = _cvss_to_severity(cvss)

            cve_raw = _el_text(cve_el) or ""
            cve_id = cve_raw if re.match(r"CVE-\d{4}-\d+", cve_raw) else None
            remediation = _el_text(solution_el) or ""

            try:
                qod_val = int(_el_text(qod_el) or "")
            except (ValueError, TypeError):
                qod_val = None

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
                raw={
                    "_table": "openvas",
                    "nvt_oid": nvt_oid,
                    "nvt_name": nvt_name,
                    "nvt_family": nvt_family,
                    "nvt_version": nvt_version,
                    "host": host,
                    "port": port,
                    "threat": sev_raw,
                    "severity_score": cvss,
                    "qod": qod_val,
                    "description": desc,
                    "solution": remediation,
                    "solution_type": solution_type_el,
                    "cve": cve_id,
                    "bid": _el_text(bid_el),
                    "xref": _el_text(xref_el),
                    "tags": _el_text(tags_el),
                },
            ))
    except Exception as exc:
        logger.warning("OpenVAS parse error: %s", exc)
    return findings


def parse_qualys_xml(content: bytes) -> List[ParsedFinding]:
    findings = []
    try:
        root = ET.fromstring(content)
        for vuln in root.findall(".//VULN") or root.findall(".//QID"):
            title = _el_text(vuln.find("TITLE")) or "Unknown"
            sev_map = {"1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}
            sev_raw = _el_text(vuln.find("SEVERITY")) or "3"
            sev = sev_map.get(sev_raw, "medium")
            qid = _el_text(vuln.find("QID"))
            ip = _el_text(vuln.find("IP")) or _el_text(vuln.find("HOST")) or ""
            fqdn = _el_text(vuln.find("FQDN")) or _el_text(vuln.find("DNS"))
            os_str = _el_text(vuln.find("OS"))
            cve_raw = _el_text(vuln.find("CVE_ID")) or _el_text(vuln.find("CVE")) or ""
            cve_id = cve_raw if re.match(r"CVE-\d{4}-\d+", cve_raw) else None
            cvss_base = _el_float(vuln.find("CVSS_BASE"))
            cvss3_base = _el_float(vuln.find("CVSS3_BASE"))
            cvss = cvss3_base or cvss_base
            cvss_temp = _el_float(vuln.find("CVSS_TEMPORAL"))
            cvss3_temp = _el_float(vuln.find("CVSS3_TEMPORAL"))
            remediation = _el_text(vuln.find("SOLUTION")) or ""
            desc = _el_text(vuln.find("CONSEQUENCE")) or _el_text(vuln.find("DIAGNOSIS")) or ""
            threat = _el_text(vuln.find("THREAT"))
            impact = _el_text(vuln.find("IMPACT"))
            results = _el_text(vuln.find("RESULTS"))
            vendor_ref = _el_text(vuln.find("VENDOR_REFERENCE"))
            category = _el_text(vuln.find("CATEGORY"))
            port_el = vuln.find("PORT") or vuln.find("PROTOCOL")
            try:
                port_int = int(_el_text(vuln.find("PORT")) or "")
            except (ValueError, TypeError):
                port_int = None

            findings.append(ParsedFinding(
                title=title,
                description=desc or threat or "",
                severity=sev,
                resource_id=fqdn or ip,
                resource_type="host",
                cve_id=cve_id,
                cvss_score=cvss,
                remediation=remediation,
                confidence=0.96,
                raw={
                    "_table": "qualys",
                    "qid": qid,
                    "title": title,
                    "type_code": None,
                    "severity_level": int(sev_raw) if sev_raw.isdigit() else None,
                    "port": port_int,
                    "protocol": _el_text(vuln.find("PROTOCOL")),
                    "fqdn": fqdn,
                    "ip": ip,
                    "os": os_str,
                    "results": results,
                    "threat": threat,
                    "impact": impact,
                    "solution": remediation,
                    "cvss_base": cvss_base,
                    "cvss_temporal": cvss_temp,
                    "cvss3_base": cvss3_base,
                    "cvss3_temporal": cvss3_temp,
                    "cve_list": cve_raw,
                    "vendor_reference": vendor_ref,
                    "category": category,
                    "is_patchable": None,
                    "first_found": None,
                    "last_found": None,
                },
            ))
    except Exception as exc:
        logger.warning("Qualys XML parse error: %s", exc)
    return findings


def parse_qualys_csv(content: bytes) -> List[ParsedFinding]:
    findings = []
    try:
        text = content.decode("utf-8", errors="replace")
        lines = [l for l in text.splitlines() if not l.startswith("----") and l.strip()]
        reader = csv.DictReader(lines)
        sev_map = {"1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}
        for idx, row in enumerate(reader):
            title = row.get("Title") or row.get("Vulnerability") or row.get("QID", "Unknown")
            sev_raw = str(row.get("Severity") or row.get("SEVERITY") or "3")
            sev = sev_map.get(sev_raw.strip(), "medium")
            ip = row.get("IP") or row.get("Host") or ""
            fqdn = row.get("DNS") or row.get("FQDN") or ""
            resource = fqdn or ip
            cve_raw = row.get("CVE ID") or row.get("CVE") or ""
            cve_id = cve_raw.strip() if re.match(r"CVE-\d{4}-\d+", cve_raw.strip()) else None
            cvss_base = None
            cvss3_base = None
            for k in ("CVSS Base", "CVSS_BASE"):
                if row.get(k):
                    try:
                        cvss_base = float(row[k]); break
                    except ValueError:
                        pass
            for k in ("CVSS3 Base", "CVSS3_BASE"):
                if row.get(k):
                    try:
                        cvss3_base = float(row[k]); break
                    except ValueError:
                        pass
            cvss = cvss3_base or cvss_base
            try:
                port_int = int(row.get("Port") or row.get("PORT") or "")
            except (ValueError, TypeError):
                port_int = None
            try:
                sev_level = int(sev_raw.strip())
            except (ValueError, TypeError):
                sev_level = None

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
                raw={
                    "_table": "qualys",
                    "qid": row.get("QID"),
                    "title": title,
                    "type_code": row.get("Type"),
                    "severity_level": sev_level,
                    "port": port_int,
                    "protocol": row.get("Protocol"),
                    "fqdn": fqdn,
                    "ip": ip,
                    "os": row.get("OS"),
                    "results": row.get("Results"),
                    "threat": row.get("Threat"),
                    "impact": row.get("Impact"),
                    "solution": row.get("Solution") or row.get("Remediation") or "",
                    "cvss_base": cvss_base,
                    "cvss_temporal": None,
                    "cvss3_base": cvss3_base,
                    "cvss3_temporal": None,
                    "cve_list": cve_raw,
                    "vendor_reference": row.get("Vendor Reference"),
                    "category": row.get("Category"),
                    "is_patchable": None,
                    "first_found": None,
                    "last_found": None,
                },
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
                    raw={
                        "_table": "generic",
                        "source_format": "checkmarx",
                        "raw_row_json": json.dumps({"query": name, "severity_raw": sev_num, "filename": filename, "line": line}),
                    },
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
                raw={"_table": "generic", "source_format": "csv", "raw_row_json": json.dumps(dict(row))},
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
                raw={"_table": "generic", "source_format": "json", "raw_row_json": json.dumps(item)},
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
