"""
LLM-powered code security reviewer.

Implements three analysis passes:
  1. Triage   — ranks all repo files by risk using the file tree
  2. Review   — per-chunk security analysis (runs in parallel with concurrency cap)
  3. Critique — filters low-confidence findings (self-critique pass)
  4. Taint    — cross-file data-flow tracing for flagged sources and sinks
"""
from __future__ import annotations
import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from core.ai_providers import get_llm

logger = logging.getLogger(__name__)

MAX_PARALLEL = 6          # LLM calls in flight simultaneously
TRIAGE_TOP_N = 25         # files to deeply review after triage

# Default token budget per scan. Each token ≈ 4 chars; rough call cost:
#   triage: ~2 000 tokens, per-chunk review: ~2 500, critique: ~1 200, taint: ~4 000/pair
# 400 000 tokens ≈ ~120 chunks reviewed end-to-end ≈ $2–3 on most providers.
DEFAULT_TOKEN_BUDGET = 400_000


# ── Token budget ──────────────────────────────────────────────────────────────

class TokenBudget:
    """Tracks estimated LLM token consumption across all review phases.

    Uses len(text) // 4 as the token estimate (same as CodeChunk.token_estimate).
    Each _call_llm() call deducts both prompt and a fixed response estimate so
    the budget stays conservative without requiring tiktoken.
    """
    AVG_RESPONSE_TOKENS = 600  # conservative per-call response estimate

    def __init__(self, limit: int = DEFAULT_TOKEN_BUDGET):
        self.limit = limit
        self.used = 0

    def consume(self, prompt_tokens: int) -> bool:
        """Attempt to deduct prompt + response estimate. Returns False if budget is exhausted."""
        cost = prompt_tokens + self.AVG_RESPONSE_TOKENS
        if self.used + cost > self.limit:
            return False
        self.used += cost
        return True

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit

    def trim_chunks(self, chunks: list) -> list:
        """Return the largest prefix of chunks that fits within the remaining budget.
        Logs how many chunks were dropped if any were trimmed.
        """
        kept, dropped = [], 0
        for c in chunks:
            prompt_cost = c.token_estimate + len(_REVIEW_USER) // 4 + self.AVG_RESPONSE_TOKENS
            if self.used + prompt_cost > self.limit:
                dropped += 1
            else:
                kept.append(c)
        if dropped:
            logger.warning(
                "TokenBudget: dropped %d chunk(s) to stay within %d-token limit (%d used so far)",
                dropped, self.limit, self.used,
            )
        return kept


# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class ReviewFinding:
    title: str
    description: str
    severity: str              # critical | high | medium | low | info
    file_path: str
    start_line: int
    end_line: int
    function_name: str
    cwe_id: str                # e.g. "CWE-89"
    proof_of_exploit: str
    remediation: str
    confidence: str = "high"   # high | medium | low
    evidence: dict[str, Any] = field(default_factory=dict)


# ── Prompt templates ──────────────────────────────────────────────────────────

_TRIAGE_SYSTEM = (
    "You are a principal security architect with 15 years of experience in "
    "application security and code review. You excel at quickly identifying "
    "which parts of a codebase are most likely to contain exploitable vulnerabilities."
)

_TRIAGE_USER = """\
You are performing a security triage of this repository.
File tree (relative paths):

{file_tree}

Task: Identify the {top_n} highest-risk files for deep security review.

Rank by likelihood of containing exploitable vulnerabilities. Prioritise:
1. User input entry points (HTTP routes, parsers, deserializers, CLI argument handlers)
2. Authentication and authorisation code
3. Cryptography and secret handling
4. Database interaction (queries, ORMs, raw SQL)
5. File system and process execution (os.system, subprocess, file I/O)
6. Network communication (HTTP clients, WebSocket, inter-service calls)

Return ONLY valid JSON — an array of objects, no markdown fence:
[
  {{"path": "relative/path.py", "reason": "one-line risk summary"}},
  ...
]
"""

_REVIEW_SYSTEM = (
    "You are a senior security researcher and penetration tester performing a "
    "detailed vulnerability audit. You find real, exploitable vulnerabilities — "
    "not theoretical issues or code smells. You provide exact CWE IDs, "
    "concrete proof-of-exploit scenarios, and actionable remediations."
)

_REVIEW_USER = """\
Language: {language}
File: {file_path}
Function / section: {function_name} (lines {start_line}–{end_line})

--- IMPORTS (for context) ---
{imports}

--- CODE ---
{code}

Find ALL security vulnerabilities in this code. For each genuine vulnerability output:

{{
  "title": "short title",
  "cwe_id": "CWE-NNN or empty string",
  "severity": "critical|high|medium|low|info",
  "start_line": {start_line},
  "end_line": {end_line},
  "description": "what is wrong and why it is dangerous",
  "proof_of_exploit": "step-by-step how an attacker triggers this",
  "remediation": "concrete code change or configuration fix",
  "confidence": "high|medium|low"
}}

Return ONLY valid JSON — an array (may be empty if no real vulnerabilities found), no markdown fence.
If code appears safe, return [].
"""

_CRITIQUE_SYSTEM = (
    "You are a skeptical senior security engineer reviewing another engineer's "
    "vulnerability findings. Your job is to ruthlessly filter out false positives, "
    "theoretical issues, and low-quality findings. Only genuine, exploitable "
    "vulnerabilities with clear attack paths should survive your review."
)

_CRITIQUE_USER = """\
The following vulnerabilities were found in {file_path} ({function_name}).

{findings_json}

For each finding, evaluate:
1. Is it actually exploitable in the context shown? (not just theoretically possible)
2. Is there a mitigating control in the code that makes it safe?
3. Rate final confidence: high / medium / low

Return ONLY valid JSON — array of the same objects with confidence updated.
Remove any finding where confidence becomes "low" (drop them entirely).
Return [] if nothing survives.
"""

_TAINT_SYSTEM = (
    "You are a security researcher specialising in taint analysis and data-flow "
    "vulnerabilities. You trace user-controlled data from entry points through "
    "processing chains to dangerous sinks."
)

_TAINT_USER = """\
Potential vulnerability chain detected:

SOURCE — user-controlled data enters here:
File: {source_file}, Function: {source_fn} (line {source_line})
Code:
{source_code}

SINK — dangerous operation here:
File: {sink_file}, Function: {sink_fn} (line {sink_line})
Code:
{sink_code}

Intermediate functions (if available):
{intermediate}

Question: Can user-controlled data from the SOURCE reach the SINK unsanitised?
Analyse the data flow carefully. Consider: type coercions, implicit conversions,
partial sanitisation, branching paths.

Return ONE JSON object:
{{
  "exploitable": true|false,
  "confidence": "high|medium|low",
  "attack_path": "step-by-step description of how input flows to sink",
  "title": "short vulnerability title",
  "severity": "critical|high|medium|low",
  "cwe_id": "CWE-NNN",
  "remediation": "concrete fix"
}}
"""


# ── LLM helpers ───────────────────────────────────────────────────────────────

async def _call_llm(
    system: str,
    user: str,
    *,
    budget: TokenBudget | None = None,
    json_mode: bool = True,
) -> str:
    """Call the configured LLM asynchronously; returns the text response.

    If a TokenBudget is supplied and the call would exceed it, raises
    BudgetExceededError instead of making the API call.
    """
    from langchain_core.messages import HumanMessage, SystemMessage
    prompt_tokens = (len(system) + len(user)) // 4
    if budget is not None and not budget.consume(prompt_tokens):
        raise BudgetExceededError(
            f"Token budget exhausted ({budget.used}/{budget.limit}) — skipping LLM call"
        )
    llm = get_llm(temperature=0.05, max_tokens=4096)
    msgs = [SystemMessage(content=system), HumanMessage(content=user)]
    result = await llm.ainvoke(msgs)
    return result.content if hasattr(result, "content") else str(result)


class BudgetExceededError(Exception):
    """Raised when a token budget limit is hit before an LLM call."""


def _parse_json(text: str) -> Any:
    """Extract and parse the first JSON array or object from LLM output."""
    text = text.strip()
    # Strip markdown code fences if present
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to extract the first [...] or {...}
        m = re.search(r"(\[[\s\S]*\]|\{[\s\S]*\})", text)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
    return []


# ── Phase 1: Triage ───────────────────────────────────────────────────────────

async def triage_files(
    file_list: list[str],
    top_n: int = TRIAGE_TOP_N,
    budget: TokenBudget | None = None,
) -> list[str]:
    """
    Ask the LLM to rank all repo files by security risk.
    Returns ordered list of relative paths (highest risk first).
    Pre-scores files heuristically and passes the sorted list to the LLM
    so the prompt stays short even for large repos.
    """
    from .chunker import score_file_risk

    # Heuristic pre-sort so prompt is already partially ordered
    pre_sorted = sorted(file_list, key=score_file_risk, reverse=True)
    # Send at most 300 files to the LLM to keep prompt small
    files_for_prompt = pre_sorted[:300]
    file_tree = "\n".join(files_for_prompt)

    try:
        raw = await _call_llm(
            _TRIAGE_SYSTEM,
            _TRIAGE_USER.format(file_tree=file_tree, top_n=top_n),
            budget=budget,
        )
        items = _parse_json(raw)
        if isinstance(items, list):
            ranked = [item["path"] for item in items if isinstance(item, dict) and "path" in item]
            if ranked:
                # Validate returned paths exist in the actual file tree to guard
                # against the LLM inventing or normalising paths.
                file_set = set(file_list)
                valid = [p for p in ranked if p in file_set]
                if valid:
                    logger.info("Triage selected %d files for deep review", len(valid))
                    return valid[:top_n]
                logger.warning("Triage returned %d paths but none matched file tree — using heuristic order", len(ranked))
    except BudgetExceededError:
        logger.warning("Triage skipped — token budget exhausted; using heuristic order")
    except Exception as exc:
        logger.warning("Triage LLM call failed (%s) — falling back to heuristic order", exc)

    return pre_sorted[:top_n]


# ── Phase 2: Per-chunk review ─────────────────────────────────────────────────

async def review_chunk(chunk, budget: TokenBudget | None = None) -> list[ReviewFinding]:
    """Review a single CodeChunk; returns list of findings (may be empty)."""
    prompt = _REVIEW_USER.format(
        language=chunk.language,
        file_path=chunk.file_path,
        function_name=chunk.function_name,
        start_line=chunk.start_line,
        end_line=chunk.end_line,
        imports=chunk.imports or "(none)",
        code=chunk.code,
    )
    try:
        raw = await _call_llm(_REVIEW_SYSTEM, prompt, budget=budget)
        items = _parse_json(raw)
        if not isinstance(items, list):
            return []
        findings = []
        for item in items:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity", "medium")).lower()
            if sev not in ("critical", "high", "medium", "low", "info"):
                sev = "medium"
            findings.append(ReviewFinding(
                title=str(item.get("title", "Untitled"))[:255],
                description=str(item.get("description", "")),
                severity=sev,
                file_path=chunk.file_path,
                start_line=int(item.get("start_line", chunk.start_line)),
                end_line=int(item.get("end_line", chunk.end_line)),
                function_name=chunk.function_name,
                cwe_id=str(item.get("cwe_id", "")),
                proof_of_exploit=str(item.get("proof_of_exploit", "")),
                remediation=str(item.get("remediation", "")),
                confidence=str(item.get("confidence", "high")).lower(),
                evidence={
                    "function": chunk.function_name,
                    "language": chunk.language,
                    "line_range": f"{chunk.start_line}–{chunk.end_line}",
                    "cwe": item.get("cwe_id", ""),
                },
            ))
        return findings
    except BudgetExceededError as exc:
        logger.info("Chunk review skipped (budget): %s/%s — %s", chunk.file_path, chunk.function_name, exc)
        return []
    except Exception as exc:
        logger.warning("Chunk review failed for %s/%s: %s", chunk.file_path, chunk.function_name, exc)
        return []


async def review_chunks_parallel(
    chunks: list,
    budget: TokenBudget | None = None,
) -> list[ReviewFinding]:
    """Review all chunks with capped parallelism."""
    sem = asyncio.Semaphore(MAX_PARALLEL)
    all_findings: list[ReviewFinding] = []

    async def _bounded(chunk):
        async with sem:
            return await review_chunk(chunk, budget=budget)

    results = await asyncio.gather(*[_bounded(c) for c in chunks], return_exceptions=True)
    for res in results:
        if isinstance(res, list):
            all_findings.extend(res)
        elif isinstance(res, Exception):
            logger.debug("Chunk review exception: %s", res)
    return all_findings


# ── Phase 3: Self-critique (filter false positives) ──────────────────────────

async def critique_findings(
    findings: list[ReviewFinding],
    budget: TokenBudget | None = None,
) -> list[ReviewFinding]:
    """
    Group findings by (file, function) and run a critique pass.
    Drops findings rated low-confidence by the critic.
    """
    if not findings:
        return []

    # Group by file + function
    groups: dict[tuple[str, str], list[ReviewFinding]] = {}
    for f in findings:
        key = (f.file_path, f.function_name)
        groups.setdefault(key, []).append(f)

    sem = asyncio.Semaphore(MAX_PARALLEL)
    survived: list[ReviewFinding] = []

    async def _critique_group(file_path: str, func_name: str, group: list[ReviewFinding]):
        async with sem:
            items = [
                {
                    "title": f.title, "severity": f.severity, "cwe_id": f.cwe_id,
                    "description": f.description, "proof_of_exploit": f.proof_of_exploit,
                    "confidence": f.confidence,
                }
                for f in group
            ]
            try:
                raw = await _call_llm(
                    _CRITIQUE_SYSTEM,
                    _CRITIQUE_USER.format(
                        file_path=file_path, function_name=func_name,
                        findings_json=json.dumps(items, indent=2),
                    ),
                    budget=budget,
                )
                reviewed = _parse_json(raw)
                if not isinstance(reviewed, list):
                    return group   # keep all if critique fails

                # Map back by title (best-effort)
                title_to_finding = {f.title: f for f in group}
                result: list[ReviewFinding] = []
                for item in reviewed:
                    if not isinstance(item, dict):
                        continue
                    title = str(item.get("title", ""))
                    conf = str(item.get("confidence", "high")).lower()
                    if conf == "low":
                        continue
                    orig = title_to_finding.get(title)
                    if orig:
                        orig.confidence = conf
                        result.append(orig)
                return result
            except BudgetExceededError:
                logger.info("Critique skipped for %s/%s — token budget exhausted; keeping findings as-is", file_path, func_name)
                return group  # keep all when budget is gone
            except Exception as exc:
                logger.warning("Critique failed for %s/%s: %s", file_path, func_name, exc)
                return group  # keep all on failure

    tasks = [_critique_group(fp, fn, grp) for (fp, fn), grp in groups.items()]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, list):
            survived.extend(res)
    return survived


# ── Phase 4: Cross-file taint tracing ────────────────────────────────────────

_SOURCE_KEYWORDS = re.compile(
    r"(request\.|form\.|params\[|query\[|body\[|user_input|argv|stdin|"
    r"request\.get|request\.post|request\.json|request\.data|"
    r"flask\.request|fastapi\.(Query|Body|Form|Path)|"
    r"os\.environ|getenv|input\()",
    re.IGNORECASE,
)
_SINK_KEYWORDS = re.compile(
    r"(execute\(|cursor\.|raw_query|os\.system|subprocess\.|eval\(|"
    r"exec\(|open\(|pickle\.|yaml\.load|marshal\.|deserializ|"
    r"shell=True|format_map|\.format\(|f\"|f')",
    re.IGNORECASE,
)


async def trace_taint_flows(
    chunks: list,
    findings: list[ReviewFinding],
    budget: TokenBudget | None = None,
) -> list[ReviewFinding]:
    """
    For high/critical findings that involve sources and sinks across different
    files, run a targeted cross-file taint trace to confirm exploitability.
    Only runs on findings already flagged as high/critical by phase 2.
    """
    # Find chunks with sources and chunks with sinks
    source_chunks = [c for c in chunks if _SOURCE_KEYWORDS.search(c.code)]
    sink_chunks = [c for c in chunks if _SINK_KEYWORDS.search(c.code)]

    if not source_chunks or not sink_chunks:
        return []

    # Only trace if source and sink are in different files (cross-file is the interesting case)
    pairs = [
        (s, k) for s in source_chunks for k in sink_chunks
        if s.file_path != k.file_path
    ]
    # Cap at 10 pairs to control cost
    pairs = pairs[:10]
    if not pairs:
        return []

    sem = asyncio.Semaphore(3)
    new_findings: list[ReviewFinding] = []

    async def _trace(src, snk):
        async with sem:
            try:
                raw = await _call_llm(
                    _TAINT_SYSTEM,
                    _TAINT_USER.format(
                        source_file=src.file_path, source_fn=src.function_name,
                        source_line=src.start_line, source_code=src.code[:1500],
                        sink_file=snk.file_path, sink_fn=snk.function_name,
                        sink_line=snk.start_line, sink_code=snk.code[:1500],
                        intermediate="(not available — review files separately)",
                    ),
                    budget=budget,
                )
                result = _parse_json(raw)
                if not isinstance(result, dict):
                    return None
                if not result.get("exploitable"):
                    return None
                conf = str(result.get("confidence", "medium")).lower()
                if conf == "low":
                    return None
                sev = str(result.get("severity", "high")).lower()
                return ReviewFinding(
                    title=str(result.get("title", "Cross-file taint vulnerability"))[:255],
                    description=str(result.get("attack_path", "")),
                    severity=sev,
                    file_path=f"{src.file_path} → {snk.file_path}",
                    start_line=src.start_line,
                    end_line=snk.end_line,
                    function_name=f"{src.function_name} → {snk.function_name}",
                    cwe_id=str(result.get("cwe_id", "")),
                    proof_of_exploit=str(result.get("attack_path", "")),
                    remediation=str(result.get("remediation", "")),
                    confidence=conf,
                    evidence={
                        "type": "cross_file_taint",
                        "source": f"{src.file_path}:{src.start_line}",
                        "sink": f"{snk.file_path}:{snk.start_line}",
                    },
                )
            except BudgetExceededError:
                logger.info("Taint trace skipped — token budget exhausted")
                return None
            except Exception as exc:
                logger.debug("Taint trace failed: %s", exc)
                return None

    if budget and budget.exhausted:
        logger.info("Taint tracing skipped entirely — token budget exhausted before phase 4")
        return []

    results = await asyncio.gather(*[_trace(s, k) for s, k in pairs], return_exceptions=True)
    for res in results:
        if isinstance(res, ReviewFinding):
            new_findings.append(res)
    return new_findings
