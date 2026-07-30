"""Qualys VMDR scanner integration.

Two operating modes:
  Import mode  (no targets in config): pulls existing host detections from the
               Qualys portal using the VM Detection + KnowledgeBase APIs.
               This is the primary mode for existing Qualys customers.

  Scan mode    (targets provided): launches a new Qualys scan against the
               supplied IPs/CIDR and waits for results (legacy behaviour).
"""
import asyncio
import httpx
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_HEADERS = {"X-Requested-With": "Monitara", "Content-Type": "application/x-www-form-urlencoded"}
_KB_BATCH = 300   # QIDs per KnowledgeBase lookup request


# ── Severity mapping ──────────────────────────────────────────────────────────

def _norm_sev(score) -> str:
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 5:
        return "critical"
    if s == 4:
        return "high"
    if s == 3:
        return "medium"
    if s == 2:
        return "low"
    return "info"


# ── XML helpers ───────────────────────────────────────────────────────────────

def _txt(elem, tag: str, default: str = "") -> str:
    """Safe child-element text extraction."""
    child = elem.find(tag)
    return (child.text or "").strip() if child is not None else default


# ── KnowledgeBase enrichment ──────────────────────────────────────────────────

async def _fetch_kb(api_url: str, auth, qids: set) -> dict:
    """Return {qid_str: {title, description, solution, cve_id, cvss}} for every QID."""
    kb: dict = {}
    qid_list = list(qids)
    async with httpx.AsyncClient(timeout=120, verify=True) as client:
        for i in range(0, len(qid_list), _KB_BATCH):
            batch = qid_list[i:i + _KB_BATCH]
            resp = await client.post(
                f"{api_url}/api/2.0/fo/knowledge_base/vuln/",
                auth=auth,
                headers=_HEADERS,
                data={"action": "list", "ids": ",".join(str(q) for q in batch)},
            )
            resp.raise_for_status()
            try:
                root = ET.fromstring(resp.text)
            except ET.ParseError:
                continue
            for vuln in root.iter("VULN"):
                qid = _txt(vuln, "QID")
                if not qid:
                    continue
                # Primary CVE
                cve_elem = vuln.find(".//CVE_LIST/CVE/ID")
                cve_id = cve_elem.text.strip() if cve_elem is not None and cve_elem.text else ""
                # CVSS v3 preferred, fall back to v2
                cvss = 0.0
                for path in (".//CVSS_V3/BASE", ".//CVSS/BASE"):
                    node = vuln.find(path)
                    if node is not None and node.text:
                        try:
                            cvss = float(node.text.strip())
                            break
                        except ValueError:
                            pass
                kb[qid] = {
                    "title": _txt(vuln, "TITLE") or f"Qualys QID {qid}",
                    "description": _txt(vuln, "DIAGNOSIS"),
                    "solution": _txt(vuln, "SOLUTION"),
                    "cve_id": cve_id,
                    "cvss": cvss,
                }
    return kb


# ── Import mode: pull existing detections ────────────────────────────────────

async def _import_existing_detections(api_url: str, auth) -> list:
    """Fetch all active/new VM detections from the Qualys portal."""
    all_findings: list = {}  # keyed by (ip, qid) to deduplicate

    async with httpx.AsyncClient(timeout=180, verify=True) as client:

        # Paginated fetch of all host detections
        next_url: str | None = None
        page = 0
        while True:
            page += 1
            if next_url:
                resp = await client.get(next_url, auth=auth, headers=_HEADERS)
            else:
                resp = await client.post(
                    f"{api_url}/api/4.0/fo/asset/host/vm/detection/",
                    auth=auth,
                    headers=_HEADERS,
                    data={
                        "action": "list",
                        "status": "Active,New,Re-Opened",
                        "output_format": "XML",
                        "truncation_limit": "1000",
                        "show_results": "1",
                    },
                )
            resp.raise_for_status()

            try:
                root = ET.fromstring(resp.text)
            except ET.ParseError as exc:
                logger.warning("Qualys detection XML parse error page %d: %s", page, exc)
                break

            # Collect detections per host
            for host in root.iter("HOST"):
                ip = _txt(host, "IP")
                dns = _txt(host, "DNS")
                os_name = _txt(host, "OS")
                resource_id = dns or ip

                for det in host.iter("DETECTION"):
                    qid = _txt(det, "QID")
                    if not qid:
                        continue
                    key = (ip, qid)
                    if key in all_findings:
                        continue  # already captured from a prior page
                    severity = _norm_sev(_txt(det, "SEVERITY"))
                    port = _txt(det, "PORT")
                    protocol = _txt(det, "PROTOCOL")
                    cve_inline = _txt(det, "CVE_ID")
                    results = _txt(det, "RESULTS")
                    first_found = _txt(det, "FIRST_FOUND_DATETIME")
                    last_found = _txt(det, "LAST_FOUND_DATETIME")
                    all_findings[key] = {
                        "qid": qid,
                        "severity": severity,
                        "resource_id": resource_id,
                        "resource_type": "host",
                        "port": port,
                        "protocol": protocol,
                        "cve_id": cve_inline,
                        "results": results[:2000] if results else "",
                        "first_found": first_found,
                        "last_found": last_found,
                        "os": os_name,
                        "ip": ip,
                    }

            # Check for pagination continuation URL
            warning = root.find(".//WARNING")
            next_url = None
            if warning is not None:
                code = _txt(warning, "CODE")
                url_elem = warning.find("URL")
                if code == "1980" and url_elem is not None and url_elem.text:
                    next_url = url_elem.text.strip()
                    logger.info("Qualys detection page %d fetched, continuing…", page)
            if not next_url:
                break

    if not all_findings:
        logger.info("Qualys import: no active detections found")
        return []

    logger.info("Qualys import: %d raw detections across all hosts — enriching with KB…", len(all_findings))

    # Enrich with KnowledgeBase
    unique_qids = {v["qid"] for v in all_findings.values()}
    kb = await _fetch_kb(api_url, auth, unique_qids)

    findings = []
    for raw in all_findings.values():
        qid = raw["qid"]
        info = kb.get(qid, {})
        cve = info.get("cve_id") or raw["cve_id"]
        cvss = info.get("cvss", 0.0)

        # Compose description from KB diagnosis + scan results
        desc_parts = []
        if info.get("description"):
            desc_parts.append(info["description"])
        if raw["results"]:
            desc_parts.append(f"Detected output:\n{raw['results']}")
        if raw["os"]:
            desc_parts.append(f"Host OS: {raw['os']}")

        findings.append({
            "title": info.get("title") or f"Qualys QID {qid}",
            "description": "\n\n".join(desc_parts),
            "severity": raw["severity"],
            "resource_id": raw["resource_id"],
            "resource_type": "host",
            "cve_id": cve,
            "cvss_score": cvss,
            "remediation": info.get("solution", ""),
            "evidence": {
                "qualys_qid": qid,
                "port": raw["port"],
                "protocol": raw["protocol"],
                "ip": raw["ip"],
                "first_found": raw["first_found"],
                "last_found": raw["last_found"],
            },
            "status": "open",
        })

    logger.info("Qualys import: %d enriched findings ready", len(findings))
    return findings


# ── Scan mode: launch new scan against targets ────────────────────────────────

async def _launch_new_scan(api_url: str, auth, targets: str, config: dict, scan_label: str) -> list:
    """Launch a Qualys scan against target IPs/CIDR and return findings."""
    option_id = config.get("option_profile_id", "")

    async with httpx.AsyncClient(timeout=120, verify=True) as client:
        launch_data: dict = {
            "action": "launch",
            "scan_title": scan_label,
            "ip": targets,
        }
        if option_id:
            launch_data["option_id"] = option_id

        launch_resp = await client.post(
            f"{api_url}/api/2.0/fo/scan/",
            auth=auth,
            headers=_HEADERS,
            data=launch_data,
        )
        launch_resp.raise_for_status()

        root = ET.fromstring(launch_resp.text)
        scan_ref = ""
        for elem in root.iter("VALUE"):
            val = elem.text or ""
            if val.startswith("scan/"):
                scan_ref = val
                break

        if not scan_ref:
            raise ValueError("Could not parse scan reference from Qualys launch response")

        # Poll up to 2 hours (120 × 60s)
        for _ in range(120):
            await asyncio.sleep(60)
            st_resp = await client.post(
                f"{api_url}/api/2.0/fo/scan/",
                auth=auth,
                headers=_HEADERS,
                data={"action": "status", "scan_ref": scan_ref},
            )
            st_root = ET.fromstring(st_resp.text)
            state_elem = st_root.find(".//STATE")
            if state_elem is not None and state_elem.text in ("Finished", "Cancelled", "Error"):
                break

        fetch_resp = await client.post(
            f"{api_url}/api/2.0/fo/scan/",
            auth=auth,
            headers=_HEADERS,
            data={"action": "fetch", "scan_ref": scan_ref, "output_format": "CSV"},
        )
        fetch_resp.raise_for_status()
        return _parse_qualys_csv(fetch_resp.text)


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_qualys_scan(scan_id: str, db_url: str, creds: dict, config: dict) -> None:
    from db.database import SessionLocal
    from api.models.models import Scan, ScanStatus, Finding

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        api_url = creds.get("api_url", "https://qualysapi.qualys.com").rstrip("/")
        username = creds.get("username", "")
        password = creds.get("password", "")

        if not username or not password:
            raise ValueError("Qualys connector requires 'username' and 'password'")

        auth = (username, password)
        targets = config.get("targets") or config.get("target", "")

        if targets:
            logger.info("Qualys scan %s: scan mode → targets: %s", scan_id, targets)
            findings_data = await _launch_new_scan(
                api_url, auth, targets, config, f"Monitara-{scan_id[:8]}"
            )
        else:
            logger.info("Qualys scan %s: import mode → pulling existing portal detections", scan_id)
            findings_data = await _import_existing_detections(api_url, auth)

        for f in findings_data:
            db.add(Finding(scan_id=scan_id, **f))

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = {**(scan.summary or {}), "finding_count": len(findings_data)}
        db.commit()
        logger.info("Qualys scan %s completed — %d findings ingested", scan_id, len(findings_data))

    except Exception as exc:
        logger.error("Qualys scan %s failed: %s", scan_id, exc, exc_info=True)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:500]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


# ── CSV parser (scan mode fallback) ──────────────────────────────────────────

def _parse_qualys_csv(csv_text: str) -> list:
    findings = []
    lines = csv_text.splitlines()
    headers = []
    data_lines = []
    for line in lines:
        if line.startswith("IP") or line.startswith('"IP"'):
            headers = [h.strip().strip('"') for h in line.split(",")]
        elif headers and line and not line.startswith("-"):
            data_lines.append(line)

    for line in data_lines:
        parts = line.split(",")
        if len(parts) < 5:
            continue
        row = dict(zip(headers, [p.strip().strip('"') for p in parts])) if headers else {}
        ip = row.get("IP", parts[0] if parts else "")
        title = row.get("Title", parts[3] if len(parts) > 3 else "Qualys Finding")
        severity = _norm_sev(row.get("Severity", 0))
        cve = row.get("CVE ID", "")
        try:
            cvss = float(row.get("CVSS Base", 0) or 0)
        except ValueError:
            cvss = 0.0
        findings.append({
            "title": title,
            "description": row.get("Diagnosis", ""),
            "severity": severity,
            "resource_id": ip,
            "resource_type": "host",
            "cve_id": cve,
            "cvss_score": cvss,
            "remediation": row.get("Solution", ""),
            "evidence": {
                "qualys_id": row.get("QID", ""),
                "port": row.get("Port", ""),
                "protocol": row.get("Protocol", ""),
            },
            "status": "open",
        })
    return findings
