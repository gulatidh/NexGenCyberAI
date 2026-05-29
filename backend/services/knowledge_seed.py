"""Seed the Knowledge Base with the canonical files the AI specialist
agents reference. Runs once on startup; no-op if the table is non-empty.

Section types used:
  - disclaimer:        body = {"chars": N, "text": "..."}
  - items:             body = {"items": ["...", ...]}
  - matrix:            body = {"keys": {"capability": count}}
  - applicability:     body = {"keys": ["industry1", ...]}  (just labels)
"""
from __future__ import annotations
import logging
from typing import List, Dict, Any

from db.database import SessionLocal
from api.models.models import KnowledgeFile, KnowledgeFileSection

logger = logging.getLogger(__name__)


# ── Catalog ───────────────────────────────────────────────────────────────────

_SEED: List[Dict[str, Any]] = [
    {
        "name": "AI Governance Frameworks",
        "category": "frameworks_and_standards",
        "description": "Global AI governance frameworks, regulatory deadlines, and cross-framework capability matrix.",
        "version": "v1.0",
        "size_kb": 412,
        "used_by": ["framework_analyst", "compliance_monitor"],
        "sections": [
            {"name": "Disclaimer", "section_type": "disclaimer",
             "body": {"chars": 1820, "text": "This knowledge file summarizes publicly available AI governance frameworks for reference only. It is not legal advice."}},
            {"name": "Frameworks", "section_type": "items",
             "body": {"items": [
                 "NIST AI RMF 1.0", "ISO/IEC 42001:2023", "EU AI Act", "OECD AI Principles",
                 "Singapore Model AI Governance Framework", "UK AI Safety Institute Framework",
                 "Canada AIDA", "Brazil AI Law (PL 2338/2023)", "China Generative AI Measures",
                 "Japan AI Strategy 2022", "Australia AI Ethics Principles", "UAE AI Strategy 2031",
                 "G7 Hiroshima AI Process", "GPAI Principles", "Council of Europe AI Treaty",
                 "Bletchley Declaration", "OWASP ML Top 10", "MITRE ATLAS",
                 "NIST SP 800-218A (Secure SW for AI)", "ISO/IEC 23894 (AI Risk)",
                 "ISO/IEC 5338 (AI System Lifecycle)", "ISO/IEC 38507 (AI Governance)",
                 "ISO/IEC TR 24028 (Trustworthiness)", "ISO/IEC TR 24368 (AI Ethics)",
                 "IEEE 7000 series", "Asilomar AI Principles",
             ]}},
            {"name": "Regulatory Deadlines", "section_type": "items",
             "body": {"items": [
                 "EU AI Act — General-purpose AI obligations (Aug 2025)",
                 "EU AI Act — High-risk system compliance (Aug 2026)",
                 "Canada AIDA — Effective date (TBD post-Parliament)",
                 "Colorado AI Act SB-205 (Feb 2026)",
                 "New York City AEDT — Continuous compliance",
                 "California SB 1047 — Frontier model audits",
                 "China Generative AI Measures — Filing requirement (active)",
                 "Brazil AI Law — Working through Senate (2025+)",
                 "UK AI regulation white paper — Sectoral implementation",
                 "ISO/IEC 42001 certification — Voluntary, growing demand",
                 "G7 Code of Conduct — Annual review",
             ]}},
            {"name": "Cross Framework Capability Matrix", "section_type": "matrix",
             "body": {"keys": {
                 "Risk Assessment": 24, "Impact Assessment": 19, "Bias Testing": 21,
                 "Human Oversight": 26, "Transparency": 25, "Explainability": 22,
                 "Data Governance": 23, "Privacy Protection": 24, "Security Controls": 20,
                 "Robustness Testing": 18, "Documentation": 26, "Incident Response": 17,
                 "Continuous Monitoring": 19, "Third-Party Risk": 16,
                 "Model Cards / Datasheets": 14, "Lifecycle Management": 17,
                 "Conformity Assessment": 12, "Post-Market Monitoring": 11,
                 "Whistleblower Protections": 8, "Redress Mechanisms": 10,
                 "Algorithmic Audits": 13, "AI Inventory / Registry": 15,
                 "Use-Case Classification": 18, "Prohibited Practices": 11,
                 "Foundation Model Obligations": 9, "Open-Source Carve-outs": 6,
                 "Government Use Reporting": 9, "Sector-Specific Overlays": 14,
                 "Cross-Border Transfer Rules": 10, "Procurement Requirements": 12,
                 "Workforce / Skills": 8, "Education Mandates": 6,
                 "Research Sandbox Provisions": 9, "Innovation Programs": 10,
                 "Public Engagement": 11, "International Cooperation": 13,
             }}},
            {"name": "Framework Applicability", "section_type": "applicability",
             "body": {"keys": ["Financial Services", "Healthcare", "Critical Infrastructure", "Public Sector", "Education", "HR & Hiring", "Law Enforcement", "Insurance", "Retail / Consumer", "Manufacturing"]}},
            {"name": "Cross Mapping", "section_type": "applicability",
             "body": {"keys": ["NIST AI RMF ↔ ISO 42001", "EU AI Act ↔ NIST AI RMF", "OECD ↔ G7 Hiroshima", "OWASP ML Top 10 ↔ MITRE ATLAS", "NIST 800-53 ↔ NIST AI RMF"]}},
            {"name": "Industry Benchmarks", "section_type": "applicability",
             "body": {"keys": ["AIIB Trust Index", "Stanford AI Index", "MIT AI Risk Atlas", "Partnership on AI", "AI Verify (Singapore)"]}},
        ],
    },
    {
        "name": "AI Security Frameworks",
        "category": "frameworks_and_standards",
        "description": "AI/ML security threat models, vendor landscape, and GenAI risk benchmarks.",
        "version": "v1.0",
        "size_kb": 287,
        "used_by": ["framework_analyst", "threat_intel"],
        "sections": [
            {"name": "Threat Models", "section_type": "items",
             "body": {"items": ["MITRE ATLAS", "OWASP ML Top 10", "OWASP LLM Top 10", "Microsoft AI Threat Modeling", "Google SAIF", "NIST AI 100-2 (Adversarial ML)"]}},
            {"name": "Vendor Landscape", "section_type": "items",
             "body": {"items": ["Protect AI", "HiddenLayer", "Robust Intelligence", "Lakera", "Calypso AI", "Adversa AI", "Patronus AI", "WhyLabs", "Arize AI"]}},
            {"name": "GenAI Risk Benchmarks", "section_type": "matrix",
             "body": {"keys": {"Prompt Injection": 15, "Data Leakage": 12, "Model Extraction": 8, "Supply Chain": 10, "Hallucination": 14, "Jailbreak Resistance": 11}}},
        ],
    },
    {
        "name": "AppSec Frameworks",
        "category": "frameworks_and_standards",
        "description": "Application security vendor and tooling comparisons across SAST, DAST, SCA.",
        "version": "v1.0",
        "size_kb": 198,
        "used_by": ["va_scanner", "framework_analyst"],
        "sections": [
            {"name": "SAST Vendors", "section_type": "items",
             "body": {"items": ["Semgrep", "GitHub CodeQL", "SonarQube", "Checkmarx", "Veracode", "Fortify", "Snyk Code"]}},
            {"name": "DAST Vendors", "section_type": "items",
             "body": {"items": ["OWASP ZAP", "Burp Suite Enterprise", "Invicti", "Acunetix", "AppCheck"]}},
            {"name": "SCA Vendors", "section_type": "items",
             "body": {"items": ["OWASP Dependency-Check", "Snyk Open Source", "Mend (WhiteSource)", "Black Duck", "GitHub Dependabot"]}},
        ],
    },
    {
        "name": "Cloud Security Frameworks",
        "category": "frameworks_and_standards",
        "description": "CNAPP, CSPM, CWPP vendor comparisons and CIS benchmark coverage.",
        "version": "v1.0",
        "size_kb": 314,
        "used_by": ["va_scanner", "framework_analyst", "compliance_monitor"],
        "sections": [
            {"name": "CNAPP Vendors", "section_type": "items",
             "body": {"items": ["Wiz", "Orca Security", "Lacework", "Prisma Cloud", "CrowdStrike Falcon Cloud Security", "Microsoft Defender for Cloud", "Aqua Security"]}},
            {"name": "CIS Benchmarks", "section_type": "items",
             "body": {"items": ["CIS Azure Foundations", "CIS AWS Foundations", "CIS GCP Foundations", "CIS Kubernetes Benchmark", "CIS Docker Benchmark", "CIS M365 Foundations"]}},
            {"name": "Capability Matrix", "section_type": "matrix",
             "body": {"keys": {"CSPM": 7, "CWPP": 7, "CIEM": 6, "Container Scanning": 7, "IaC Scanning": 5, "Drift Detection": 4, "Runtime Protection": 5}}},
        ],
    },
    {
        "name": "CMMC Assessment Frameworks",
        "category": "frameworks_and_standards",
        "description": "All 110 NIST SP 800-171 Rev 2 practices with SPRS scoring values.",
        "version": "v1.0",
        "size_kb": 521,
        "used_by": ["compliance_monitor", "framework_analyst"],
        "sections": [
            {"name": "Disclaimer", "section_type": "disclaimer",
             "body": {"chars": 980, "text": "Reflects NIST SP 800-171 Rev 2 as of publication. CMMC 2.0 program updates may supersede individual practice scoring."}},
            {"name": "Practices", "section_type": "items",
             "body": {"items": [f"3.{family}.{idx}" for family, count in [
                 (1, 22), (2, 3), (3, 9), (4, 9), (5, 11), (6, 3), (7, 6),
                 (8, 9), (9, 2), (10, 6), (11, 4), (12, 4), (13, 16), (14, 7),
             ] for idx in range(1, count + 1)]}},
            {"name": "SPRS Scoring", "section_type": "matrix",
             "body": {"keys": {"-5 point deductions": 42, "-3 point deductions": 14, "-1 point deductions": 54, "Maximum score": 110}}},
        ],
    },
    {
        "name": "Compliance Frameworks",
        "category": "frameworks_and_standards",
        "description": "Cross-mapping of NIST, ISO, PCI, SOX, HIPAA, CMMC scoring matrices.",
        "version": "v1.0",
        "size_kb": 367,
        "used_by": ["compliance_monitor", "framework_analyst", "risk_manager"],
        "sections": [
            {"name": "Frameworks", "section_type": "items",
             "body": {"items": ["NIST CSF 2.0", "NIST SP 800-53 r5", "NIST SP 800-171 r2", "ISO/IEC 27001:2022", "ISO/IEC 27002:2022", "PCI DSS 4.0", "SOX (Sarbanes-Oxley)", "HIPAA Security Rule", "HITRUST CSF", "CMMC 2.0", "SOC 2 Type II", "FedRAMP"]}},
            {"name": "Scoring Matrices", "section_type": "matrix",
             "body": {"keys": {"NIST CSF Functions": 6, "NIST 800-53 Families": 20, "ISO 27001 Annex A Controls": 93, "PCI DSS Requirements": 12, "HIPAA Safeguards": 18, "CMMC Domains": 14, "SOC 2 TSCs": 5}}},
            {"name": "Cross Mapping", "section_type": "applicability",
             "body": {"keys": ["NIST 800-53 ↔ ISO 27001", "NIST CSF ↔ NIST 800-53", "PCI DSS ↔ NIST CSF", "HIPAA ↔ NIST 800-53", "CMMC ↔ NIST 800-171", "SOC 2 ↔ NIST CSF"]}},
        ],
    },
]


# ── Seeder ────────────────────────────────────────────────────────────────────


def seed_knowledge_base() -> None:
    """Idempotent on count — if the table has any rows, do nothing."""
    db = SessionLocal()
    try:
        existing = db.query(KnowledgeFile).count()
        if existing > 0:
            logger.info("Knowledge base already has %d files; skipping seed", existing)
            return
        for entry in _SEED:
            kf = KnowledgeFile(
                name=entry["name"],
                category=entry["category"],
                description=entry["description"],
                version=entry.get("version", "v1.0"),
                size_kb=entry.get("size_kb", 0),
                used_by=entry.get("used_by", []),
            )
            db.add(kf)
            db.flush()
            for i, sec in enumerate(entry.get("sections", [])):
                db.add(KnowledgeFileSection(
                    file_id=kf.id,
                    position=i,
                    name=sec["name"],
                    section_type=sec["section_type"],
                    body=sec.get("body", {}),
                ))
        db.commit()
        logger.info("Seeded %d knowledge files", len(_SEED))
    except Exception:
        db.rollback()
        logger.exception("Failed to seed knowledge base")
    finally:
        db.close()
