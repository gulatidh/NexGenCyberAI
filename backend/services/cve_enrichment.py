"""
CVE enrichment pipeline.

Design: the LLM is the primary source — it already knows CVE details from training.
We send only the minimal finding metadata (title + existing CVE hint), ask the LLM
for structured CVSS/CVE data, then optionally do a single targeted RAG query against
the client's knowledge base if the LLM returned low confidence.

No DB dumps, no external API calls, no token congestion.
Processes findings in small batches (5 at a time) to keep prompts compact.
"""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_BATCH_SIZE = 5

_ENRICH_PROMPT = """You are a vulnerability intelligence expert with deep knowledge of CVEs, CVSS scores, and security vulnerabilities.

For each finding below, use your training knowledge to return structured data. Be precise — if you know the CVE, return the exact CVSS v3.1 base score and vector from NVD. If a finding has no CVE or you are not confident, use null.

Respond ONLY with a valid JSON array (no markdown, no explanation), one object per finding in input order.
Schema per object:
{{
  "cve_id": "CVE-YYYY-NNNNN or null",
  "cve_ids": ["CVE-...", ...],
  "cvss_score": 9.8,
  "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H or null",
  "confidence": "high|medium|low",
  "context": "one sentence technical summary"
}}

Findings:
{findings_block}"""


def _build_finding_line(idx: int, finding) -> str:
    parts = [f"{idx + 1}. Title: {finding.title}"]
    if finding.cve_id:
        parts.append(f"CVE hint: {finding.cve_id}")
    if finding.resource_type:
        parts.append(f"Resource type: {finding.resource_type}")
    return " | ".join(parts)


async def _enrich_batch(findings_batch: list, db, client_id: str) -> list[dict]:
    """Send one compact LLM call for up to _BATCH_SIZE findings."""
    from core.ai_providers import get_llm

    findings_block = "\n".join(
        _build_finding_line(i, f) for i, f in enumerate(findings_batch)
    )
    prompt = _ENRICH_PROMPT.format(findings_block=findings_block)

    try:
        llm = get_llm()
        from langchain_core.messages import HumanMessage
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        raw = response.content.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        results = json.loads(raw)
        if not isinstance(results, list):
            results = [results]
        return results
    except Exception as exc:
        logger.warning("CVE enrichment LLM call failed: %s", exc)
        return [{}] * len(findings_batch)


async def _kb_fallback(cve_id: str, db, client_id: str) -> Optional[dict]:
    """Targeted single-question RAG query — only called when LLM confidence is low."""
    try:
        from api.models.models import SecurityDocument
        has_docs = db.query(SecurityDocument.id).filter(
            SecurityDocument.client_id == client_id,
            SecurityDocument.extracted_text.isnot(None),
        ).first()
        if not has_docs:
            return None

        from services.rag_service import query_documents
        result = await query_documents(
            db, client_id, f"CVSS v3 score vector severity for {cve_id}"
        )
        answer = result.get("answer", "")
        if not answer or "not in the documents" in answer.lower():
            return None

        # Ask LLM to extract score/vector from the KB answer — still compact
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage
        extract_prompt = (
            f"Extract CVSS v3.1 base score (float) and vector string from this text. "
            f"Return ONLY JSON: {{\"cvss_score\": float_or_null, \"cvss_vector\": \"string_or_null\"}}\n\n"
            f"Text: {answer[:600]}"
        )
        llm = get_llm()
        resp = await llm.ainvoke([HumanMessage(content=extract_prompt)])
        raw = resp.content.strip().lstrip("```json").rstrip("```").strip()
        return json.loads(raw)
    except Exception as exc:
        logger.debug("KB fallback failed for %s: %s", cve_id, exc)
        return None


async def enrich_scan_findings(scan_id: str, db, client_id: str) -> None:
    """
    Post-scan enrichment entry point.
    Fetches all findings for the scan, processes in batches, writes back
    cve_id / cve_ids / cvss_score / cvss_vector / enrichment_source.
    Designed to be called as a BackgroundTask — all failures are non-fatal.
    """
    from api.models.models import Finding

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .filter(Finding.title.isnot(None))
        .all()
    )
    if not findings:
        return

    logger.info("CVE enrichment: %d findings for scan %s", len(findings), scan_id)

    for batch_start in range(0, len(findings), _BATCH_SIZE):
        batch = findings[batch_start: batch_start + _BATCH_SIZE]
        results = await _enrich_batch(batch, db, client_id)

        for finding, result in zip(batch, results):
            if not result:
                continue
            try:
                cve_id = result.get("cve_id") or finding.cve_id
                cve_ids = result.get("cve_ids") or ([cve_id] if cve_id else [])
                cvss_score = result.get("cvss_score")
                cvss_vector = result.get("cvss_vector")
                confidence = result.get("confidence", "low")

                # If LLM was not confident and we have a CVE, try KB
                if confidence == "low" and cve_id:
                    kb = await _kb_fallback(cve_id, db, client_id)
                    if kb:
                        cvss_score = kb.get("cvss_score") or cvss_score
                        cvss_vector = kb.get("cvss_vector") or cvss_vector
                        source = "kb"
                    else:
                        source = "llm_low"
                else:
                    source = "llm"

                # Only write back if we actually got something useful
                if cve_id:
                    finding.cve_id = cve_id
                if cve_ids:
                    finding.cve_ids = json.dumps(cve_ids)
                if cvss_score is not None:
                    finding.cvss_score = float(cvss_score)
                if cvss_vector:
                    finding.cvss_vector = cvss_vector
                finding.enrichment_source = source

            except Exception as exc:
                logger.debug("Enrichment write failed for finding %s: %s", finding.id, exc)

        try:
            db.commit()
        except Exception as exc:
            logger.warning("CVE enrichment commit failed (batch %d): %s", batch_start, exc)
            db.rollback()

    logger.info("CVE enrichment complete for scan %s", scan_id)
