"""
AI Code Review — top-level orchestration.

Entry point: run_ai_code_review(scan_id, db_url, repo_url, archive_path, git_creds)

Pipeline:
  1. Acquire source  — git clone OR unzip uploaded archive
  2. Triage          — LLM ranks files by security risk
  3. Chunk           — split top-N files into function-level chunks
  4. Review          — parallel LLM vulnerability analysis
  5. Critique        — LLM self-critique, drops false positives
  6. Taint trace     — cross-file data-flow confirmation
  7. Ingest          — write findings to DB, update scan status
"""
from __future__ import annotations
import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
import zipfile
import tarfile
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

CODE_REVIEW_TMP = "/home/code_review"


# ── Source acquisition ────────────────────────────────────────────────────────

def _fetch_repo(repo_url: str, dest_dir: str, git_username: str = "", git_token: str = "") -> None:
    """Download a repository into dest_dir.

    Strategy (in order):
    1. GitHub / GitLab HTTPS archive download — no git binary required.
       Downloads the default-branch zip via the hosting API.
    2. git clone via subprocess — fallback for self-hosted or other hosts
       where a zip API is not available.
    """
    import httpx
    from urllib.parse import urlparse

    parsed = urlparse(repo_url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/")

    headers: dict = {}
    if git_token:
        headers["Authorization"] = f"token {git_token}"
    elif git_username and git_token:
        import base64
        creds = base64.b64encode(f"{git_username}:{git_token}".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"

    zip_url: str | None = None

    if "github.com" in host:
        # e.g. https://github.com/owner/repo  →  owner/repo
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 2:
            zip_url = f"https://api.github.com/repos/{parts[0]}/{parts[1]}/zipball"
            if git_token:
                headers["Authorization"] = f"Bearer {git_token}"
    elif "gitlab.com" in host or "gitlab" in host:
        # GitLab archive: /api/v4/projects/{url-encoded-path}/repository/archive.zip
        import urllib.parse
        project_path = urllib.parse.quote(path.lstrip("/"), safe="")
        zip_url = f"{parsed.scheme}://{parsed.netloc}/api/v4/projects/{project_path}/repository/archive.zip"
        if git_token:
            headers["PRIVATE-TOKEN"] = git_token
            headers.pop("Authorization", None)

    if zip_url:
        try:
            zip_path = os.path.join(dest_dir, "_repo.zip")
            with httpx.Client(timeout=300, follow_redirects=True) as client:
                resp = client.get(zip_url, headers=headers)
                resp.raise_for_status()
                with open(zip_path, "wb") as f:
                    f.write(resp.content)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(dest_dir)
            os.unlink(zip_path)
            logger.info("Fetched repo via archive download: %s", zip_url)
            return
        except Exception as exc:
            logger.warning("Archive download failed (%s), falling back to git clone: %s", zip_url, exc)

    # Fallback: git clone
    from urllib.parse import urlunparse
    if git_username and git_token:
        clone_url = urlunparse(parsed._replace(netloc=f"{git_username}:{git_token}@{parsed.netloc}"))
    else:
        clone_url = repo_url
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", "--single-branch", clone_url, dest_dir],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr[:500]}")
    except FileNotFoundError:
        raise RuntimeError(
            "git is not installed on this server and the archive download also failed. "
            "Use archive-upload mode instead: download your repo as a .zip and upload it."
        )


def _extract_archive(archive_path: str, dest_dir: str) -> None:
    """Extract a zip or tar.gz archive into dest_dir."""
    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dest_dir)
    elif archive_path.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(dest_dir)
    elif archive_path.endswith(".tar"):
        with tarfile.open(archive_path, "r:") as tf:
            tf.extractall(dest_dir)
    else:
        raise ValueError(f"Unsupported archive format: {archive_path}")

    # If the archive extracted a single top-level directory, use that as repo_dir
    entries = os.listdir(dest_dir)
    if len(entries) == 1 and os.path.isdir(os.path.join(dest_dir, entries[0])):
        return os.path.join(dest_dir, entries[0])
    return dest_dir


# ── DB helpers ────────────────────────────────────────────────────────────────

def _build_session(db_url: str):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    return Session()


def _update_scan_status(db, scan_id: str, status: str, error: str = "") -> None:
    from api.models.models import Scan, ScanStatus
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return
    scan.status = ScanStatus(status)
    if error:
        scan.error_message = error
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()


def _ingest_findings(db, scan_id: str, scan, findings) -> None:
    """Write ReviewFinding objects as DB Finding rows."""
    from api.models.models import Finding
    for f in findings:
        evidence = getattr(f, "evidence", {}) or {}
        evidence["proof_of_exploit"] = f.proof_of_exploit
        evidence["confidence"] = f.confidence
        if f.cwe_id:
            evidence["cwe_id"] = f.cwe_id

        db_finding = Finding(
            scan_id=scan_id,
            title=f.title[:255],
            description=f.description,
            severity=f.severity,
            resource_id=f.file_path,
            resource_type="code_file",
            control_id=f.cwe_id if f.cwe_id else None,
            framework=scan.framework,
            remediation=f.remediation,
            evidence=evidence,
        )
        db.add(db_finding)
    db.commit()


# ── Main orchestration ────────────────────────────────────────────────────────

async def run_ai_code_review(
    scan_id: str,
    db_url: str,
    repo_url: Optional[str] = None,
    archive_path: Optional[str] = None,
    git_username: str = "",
    git_token: str = "",
) -> None:
    """
    Full AI code review pipeline. Runs as a FastAPI BackgroundTask.
    Exactly one of repo_url or archive_path must be provided.
    """
    from api.models.models import Scan, ScanStatus
    from .chunker import get_file_tree, chunk_files
    from .reviewer import (
        TokenBudget, DEFAULT_TOKEN_BUDGET,
        triage_files, review_chunks_parallel, critique_findings, trace_taint_flows,
    )

    db = _build_session(db_url)
    work_dir = tempfile.mkdtemp(prefix=f"acr_{scan_id}_", dir="/tmp")
    repo_dir = work_dir

    try:
        # ── 0. Initialise token budget ────────────────────────────────────────
        token_limit = int(os.environ.get("CODE_REVIEW_MAX_TOKENS", DEFAULT_TOKEN_BUDGET))
        budget = TokenBudget(limit=token_limit)
        logger.info("AI code review [%s]: token budget = %d", scan_id, token_limit)

        # ── Mark running ──────────────────────────────────────────────────────
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("AI code review: scan %s not found", scan_id)
            return
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        # ── 1. Acquire source ─────────────────────────────────────────────────
        if archive_path and os.path.exists(archive_path):
            logger.info("AI code review [%s]: extracting archive %s", scan_id, archive_path)
            result = _extract_archive(archive_path, work_dir)
            if result != work_dir:
                repo_dir = result
        elif repo_url:
            logger.info("AI code review [%s]: fetching %s", scan_id, repo_url)
            clone_dir = os.path.join(work_dir, "repo")
            os.makedirs(clone_dir, exist_ok=True)
            _fetch_repo(repo_url, clone_dir, git_username, git_token)
            repo_dir = clone_dir
        else:
            raise ValueError("No source provided — supply a repo_url or upload a code archive")

        # ── 2. Discover files ─────────────────────────────────────────────────
        all_files = get_file_tree(repo_dir, max_files=600)
        logger.info("AI code review [%s]: discovered %d source files", scan_id, len(all_files))
        if not all_files:
            raise ValueError("No supported source files found in the repository")

        # ── 3. Triage ─────────────────────────────────────────────────────────
        logger.info("AI code review [%s]: triaging files …", scan_id)
        top_files = await triage_files(all_files, top_n=25, budget=budget)
        logger.info("AI code review [%s]: selected %d files for deep review (budget used: %d/%d tokens)",
                    scan_id, len(top_files), budget.used, budget.limit)

        # ── 4. Chunk ──────────────────────────────────────────────────────────
        chunks = chunk_files(repo_dir, top_files)
        logger.info("AI code review [%s]: %d raw chunks produced", scan_id, len(chunks))

        # Hard cap then budget-aware trim (drops chunks that would bust the limit)
        MAX_CHUNKS = 200
        if len(chunks) > MAX_CHUNKS:
            logger.warning("AI code review [%s]: capping at %d chunks (had %d)", scan_id, MAX_CHUNKS, len(chunks))
            chunks = chunks[:MAX_CHUNKS]
        chunks = budget.trim_chunks(chunks)

        if not chunks:
            raise ValueError("No code chunks fit within the token budget — raise CODE_REVIEW_MAX_TOKENS or reduce repo size")

        estimated_tokens = sum(c.token_estimate for c in chunks)
        logger.info("AI code review [%s]: reviewing %d chunks (~%d tokens)", scan_id, len(chunks), estimated_tokens)

        # ── 5. Review ─────────────────────────────────────────────────────────
        logger.info("AI code review [%s]: reviewing chunks (parallel) …", scan_id)
        raw_findings = await review_chunks_parallel(chunks, budget=budget)
        logger.info("AI code review [%s]: %d raw findings before critique (budget used: %d/%d)",
                    scan_id, len(raw_findings), budget.used, budget.limit)

        # ── 6. Critique ───────────────────────────────────────────────────────
        logger.info("AI code review [%s]: running self-critique pass …", scan_id)
        vetted_findings = await critique_findings(raw_findings, budget=budget)
        logger.info("AI code review [%s]: %d findings after critique (budget used: %d/%d)",
                    scan_id, len(vetted_findings), budget.used, budget.limit)

        # ── 7. Taint trace (optional — enriches cross-file chains) ────────────
        logger.info("AI code review [%s]: tracing cross-file taint flows …", scan_id)
        taint_findings = await trace_taint_flows(chunks, vetted_findings, budget=budget)
        logger.info("AI code review [%s]: %d taint findings (budget used: %d/%d)",
                    scan_id, len(taint_findings), budget.used, budget.limit)

        all_findings = vetted_findings + taint_findings

        # ── 8. Ingest to DB ───────────────────────────────────────────────────
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _ingest_findings(db, scan_id, scan, all_findings)

        # Build summary
        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        scan.summary = {
            **sev_counts,
            "total": len(all_findings),
            "files_triaged": len(top_files),
            "chunks_reviewed": len(chunks),
            "taint_findings": len(taint_findings),
            "tokens_used": budget.used,
            "token_budget": budget.limit,
            "budget_pct": round(budget.used / budget.limit * 100, 1),
        }
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()

        logger.info(
            "AI code review [%s]: complete — %d findings (%s)",
            scan_id, len(all_findings),
            ", ".join(f"{k}:{v}" for k, v in sev_counts.items() if v),
        )

    except Exception as exc:
        logger.exception("AI code review [%s] failed: %s", scan_id, exc)
        try:
            _update_scan_status(db, scan_id, "failed", str(exc)[:1000])
        except Exception:
            pass
    finally:
        try:
            db.close()
        except Exception:
            pass
        # Clean up temp directory
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass
        # Archive is kept in /home/code_review/ so rescans can reuse it.
