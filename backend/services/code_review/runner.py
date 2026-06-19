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

CODE_REVIEW_TMP = "/tmp/code_review"


# ── Source acquisition ────────────────────────────────────────────────────────

def _clone_repo(repo_url: str, dest_dir: str, git_username: str = "", git_token: str = "") -> None:
    """Clone a git repo into dest_dir. Injects credentials for private repos."""
    if git_username and git_token:
        # Inject credentials into URL for private repos
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(repo_url)
        authed = parsed._replace(netloc=f"{git_username}:{git_token}@{parsed.netloc}")
        clone_url = urlunparse(authed)
    else:
        clone_url = repo_url

    result = subprocess.run(
        ["git", "clone", "--depth=1", "--single-branch", clone_url, dest_dir],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr[:500]}")


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
    from .reviewer import triage_files, review_chunks_parallel, critique_findings, trace_taint_flows

    db = _build_session(db_url)
    work_dir = tempfile.mkdtemp(prefix=f"acr_{scan_id}_", dir="/tmp")
    repo_dir = work_dir

    try:
        # ── 0. Mark running ───────────────────────────────────────────────────
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
            logger.info("AI code review [%s]: cloning %s", scan_id, repo_url)
            clone_dir = os.path.join(work_dir, "repo")
            _clone_repo(repo_url, clone_dir, git_username, git_token)
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
        top_files = await triage_files(all_files, top_n=25)
        logger.info("AI code review [%s]: selected %d files for deep review", scan_id, len(top_files))

        # ── 4. Chunk ──────────────────────────────────────────────────────────
        chunks = chunk_files(repo_dir, top_files)
        logger.info("AI code review [%s]: %d chunks to review", scan_id, len(chunks))

        # Cap chunks to avoid extremely large LLM bills on huge repos
        MAX_CHUNKS = 200
        if len(chunks) > MAX_CHUNKS:
            logger.warning("AI code review [%s]: capping at %d chunks (had %d)", scan_id, MAX_CHUNKS, len(chunks))
            chunks = chunks[:MAX_CHUNKS]

        if not chunks:
            raise ValueError("No code chunks produced — check that the repo contains supported source files")

        # ── 5. Review ─────────────────────────────────────────────────────────
        logger.info("AI code review [%s]: reviewing chunks (parallel) …", scan_id)
        raw_findings = await review_chunks_parallel(chunks)
        logger.info("AI code review [%s]: %d raw findings before critique", scan_id, len(raw_findings))

        # ── 6. Critique ───────────────────────────────────────────────────────
        logger.info("AI code review [%s]: running self-critique pass …", scan_id)
        vetted_findings = await critique_findings(raw_findings)
        logger.info("AI code review [%s]: %d findings after critique", scan_id, len(vetted_findings))

        # ── 7. Taint trace (optional — enriches cross-file chains) ────────────
        logger.info("AI code review [%s]: tracing cross-file taint flows …", scan_id)
        taint_findings = await trace_taint_flows(chunks, vetted_findings)
        logger.info("AI code review [%s]: %d taint findings", scan_id, len(taint_findings))

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
        # Clean up archive if it was an upload
        if archive_path and os.path.exists(archive_path):
            try:
                os.unlink(archive_path)
            except Exception:
                pass
