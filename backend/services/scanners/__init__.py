"""Enterprise scanner dispatcher."""
import logging

logger = logging.getLogger(__name__)

SCANNER_MAP = {
    "tenable":         "services.scanners.tenable_scanner:run_tenable_scan",
    "burp_enterprise": "services.scanners.burp_scanner:run_burp_scan",
    "snyk":            "services.scanners.snyk_scanner:run_snyk_scan",
    "rapid7":          "services.scanners.rapid7_scanner:run_rapid7_scan",
    "qualys":          "services.scanners.qualys_scanner:run_qualys_scan",
    "invicti":         "services.scanners.invicti_scanner:run_invicti_scan",
    "acunetix":        "services.scanners.acunetix_scanner:run_acunetix_scan",
}

async def run_enterprise_scan(scanner_type: str, scan_id: str, db_url: str, creds: dict, config: dict) -> None:
    entry = SCANNER_MAP.get(scanner_type)
    if not entry:
        raise ValueError(f"Unknown enterprise scanner: {scanner_type}")
    module_path, func_name = entry.rsplit(":", 1)
    import importlib
    mod = importlib.import_module(module_path)
    fn = getattr(mod, func_name)
    await fn(scan_id, db_url, creds, config)
