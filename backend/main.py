"""
NexGenCyberAI - FastAPI Application Entry Point
"""
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import logging
import time

from core.config import get_settings
from db.database import Base, engine
from api.routers import clients, connectors, scans, scans_runner, scans_overview, risks, agents, dashboard, ai_settings, email, findings, assets, frameworks, risk_overview, projects, technologies, admin, missions, knowledge, agent_catalog, risk_portfolio, threat_models, sso

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("nexgencyberai")

settings = get_settings()

# Create DB tables
Base.metadata.create_all(bind=engine)


def _ensure_projects_schema() -> None:
    """One-shot migration to introduce the Project hierarchy.

    1. ALTER TABLE on connectors / scans / assets to add a nullable project_id
       column if it doesn't already exist.
    2. For Asset, add the renamed cloud_project_id column (was 'project_id'
       holding GCP cloud project strings before Projects shipped).
    3. For each client, create a "Default" project if none exist.
    4. Assign every NULL project_id row to that client's Default project.
    """
    from sqlalchemy import inspect, text
    from sqlalchemy.orm import Session
    try:
        inspector = inspect(engine)
        dialect = engine.dialect.name

        def _alter_add(table: str, column: str, sql_type: str = "NVARCHAR(36) NULL") -> None:
            try:
                cols = {c["name"] for c in inspector.get_columns(table)}
            except Exception:
                return
            if column in cols:
                return
            if dialect == "mssql":
                ddl = f"ALTER TABLE {table} ADD {column} {sql_type}"
            else:
                ddl = f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR(64)"
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added %s.%s column", table, column)
            except Exception as exc:
                logger.warning("ALTER %s.%s skipped: %s", table, column, exc)

        # Project FK columns
        for t in ("connectors", "scans", "assets"):
            _alter_add(t, "project_id")
        # Renamed GCP column on assets (was 'project_id' string before; now
        # 'project_id' holds the internal FK and 'cloud_project_id' holds GCP)
        _alter_add("assets", "cloud_project_id", sql_type="NVARCHAR(64) NULL")
        # Scan.name added for human-friendly scan labels
        _alter_add("scans", "name", sql_type="NVARCHAR(200) NULL")

        # Backfill: create Default project per client + reassign orphans
        from api.models.models import Client, Project, Connector, Scan, Asset
        with Session(engine) as db:
            for client in db.query(Client).all():
                default = db.query(Project).filter(
                    Project.client_id == client.id, Project.name == "Default"
                ).first()
                if not default:
                    default = Project(
                        client_id=client.id,
                        name="Default",
                        description="Auto-created when projects were introduced. "
                                    "Move existing connectors/assets/scans into specific projects as needed.",
                        environment="production",
                    )
                    db.add(default)
                    db.flush()
                    logger.info("Created Default project for client %s", client.id)

                for cls in (Connector, Scan, Asset):
                    db.query(cls).filter(
                        cls.client_id == client.id,
                        cls.project_id.is_(None),
                    ).update({"project_id": default.id}, synchronize_session=False)
            db.commit()
    except Exception as exc:
        logger.warning("_ensure_projects_schema failed: %s", exc)


def _ensure_added_columns() -> None:
    """Idempotent: ALTER TABLE for new columns added to existing tables.

    SQLAlchemy's create_all() only creates missing TABLES — it does not add
    new columns to existing tables. Introspect first; only ALTER if missing
    (avoids running expensive DDL on every worker startup, which has caused
    boot hangs on Azure SQL).
    """
    from sqlalchemy import inspect, text
    try:
        inspector = inspect(engine)
        dialect = engine.dialect.name  # 'mssql' | 'sqlite' | 'postgresql' | ...
        try:
            existing_cols = {c["name"] for c in inspector.get_columns("findings")}
        except Exception as exc:
            logger.warning("Could not inspect findings columns: %s", exc)
            return

        if "control_mappings" not in existing_cols:
            if dialect == "mssql":
                ddl = "ALTER TABLE findings ADD control_mappings NVARCHAR(MAX) NULL"
            else:
                ddl = "ALTER TABLE findings ADD COLUMN control_mappings TEXT"
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added findings.control_mappings column (%s)", dialect)
            except Exception as exc:
                logger.warning("findings.control_mappings ALTER failed (likely already added by another worker): %s", exc)

        # Add scans.ai_verdict + scans.ai_verdict_generated_at — structured
        # LLM verdict produced when a scan completes.
        try:
            scan_cols = {c["name"] for c in inspector.get_columns("scans")}
        except Exception:
            scan_cols = set()
        if "ai_verdict" not in scan_cols:
            ddl = ("ALTER TABLE scans ADD ai_verdict NVARCHAR(MAX) NULL"
                   if dialect == "mssql"
                   else "ALTER TABLE scans ADD COLUMN ai_verdict TEXT")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added scans.ai_verdict column (%s)", dialect)
            except Exception as exc:
                logger.warning("scans.ai_verdict ALTER failed: %s", exc)
        if "ai_verdict_generated_at" not in scan_cols:
            ddl = ("ALTER TABLE scans ADD ai_verdict_generated_at DATETIME2 NULL"
                   if dialect == "mssql"
                   else "ALTER TABLE scans ADD COLUMN ai_verdict_generated_at TIMESTAMP")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added scans.ai_verdict_generated_at column (%s)", dialect)
            except Exception as exc:
                logger.warning("scans.ai_verdict_generated_at ALTER failed: %s", exc)

        # Add scans.parent_scan_id — links a rescan to its predecessor so the
        # UI can walk the chain and render version history per target.
        if "parent_scan_id" not in scan_cols:
            ddl = ("ALTER TABLE scans ADD parent_scan_id NVARCHAR(36) NULL"
                   if dialect == "mssql"
                   else "ALTER TABLE scans ADD COLUMN parent_scan_id VARCHAR(36)")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added scans.parent_scan_id column (%s)", dialect)
            except Exception as exc:
                logger.warning("scans.parent_scan_id ALTER failed: %s", exc)

        # Add scheduled_mission_runs.report — structured LLM report per run.
        try:
            run_cols = {c["name"] for c in inspector.get_columns("scheduled_mission_runs")}
        except Exception:
            run_cols = set()
        if run_cols and "report" not in run_cols:
            ddl = ("ALTER TABLE scheduled_mission_runs ADD report NVARCHAR(MAX) NULL"
                   if dialect == "mssql"
                   else "ALTER TABLE scheduled_mission_runs ADD COLUMN report TEXT")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added scheduled_mission_runs.report column (%s)", dialect)
            except Exception as exc:
                logger.warning("scheduled_mission_runs.report ALTER failed: %s", exc)

        # Add threat_models.progress_json — live generation step progress for
        # the UI checklist (Discover assets → Gather context → Build → …).
        try:
            tm_cols = {c["name"] for c in inspector.get_columns("threat_models")}
        except Exception:
            tm_cols = set()
        if tm_cols and "progress_json" not in tm_cols:
            ddl = ("ALTER TABLE threat_models ADD progress_json NVARCHAR(MAX) NULL"
                   if dialect == "mssql"
                   else "ALTER TABLE threat_models ADD COLUMN progress_json TEXT")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added threat_models.progress_json column (%s)", dialect)
            except Exception as exc:
                logger.warning("threat_models.progress_json ALTER failed: %s", exc)
        if tm_cols and "scope_scan_ids" not in tm_cols:
            ddl = ("ALTER TABLE threat_models ADD scope_scan_ids NVARCHAR(MAX) NULL"
                   if dialect == "mssql"
                   else "ALTER TABLE threat_models ADD COLUMN scope_scan_ids TEXT")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added threat_models.scope_scan_ids column (%s)", dialect)
            except Exception as exc:
                logger.warning("threat_models.scope_scan_ids ALTER failed: %s", exc)
        if tm_cols and "source_diagram" not in tm_cols:
            ddl = ("ALTER TABLE threat_models ADD source_diagram NVARCHAR(MAX) NULL"
                   if dialect == "mssql"
                   else "ALTER TABLE threat_models ADD COLUMN source_diagram TEXT")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added threat_models.source_diagram column (%s)", dialect)
            except Exception as exc:
                logger.warning("threat_models.source_diagram ALTER failed: %s", exc)
        if tm_cols and "analyst_notes" not in tm_cols:
            ddl = ("ALTER TABLE threat_models ADD analyst_notes NVARCHAR(MAX) NULL"
                   if dialect == "mssql"
                   else "ALTER TABLE threat_models ADD COLUMN analyst_notes TEXT")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added threat_models.analyst_notes column (%s)", dialect)
            except Exception as exc:
                logger.warning("threat_models.analyst_notes ALTER failed: %s", exc)
        if tm_cols and "components_pinned" not in tm_cols:
            ddl = ("ALTER TABLE threat_models ADD components_pinned BIT NULL"
                   if dialect == "mssql"
                   else "ALTER TABLE threat_models ADD COLUMN components_pinned BOOLEAN")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added threat_models.components_pinned column (%s)", dialect)
            except Exception as exc:
                logger.warning("threat_models.components_pinned ALTER failed: %s", exc)

        # Add risks.source_threat_model_id + risks.source_threat_id — pin a
        # Risk row back to the threat it was converted from so the UI can
        # disable the convert button on already-converted threats.
        try:
            risk_cols = {c["name"] for c in inspector.get_columns("risks")}
        except Exception:
            risk_cols = set()
        if risk_cols and "source_threat_model_id" not in risk_cols:
            ddl = ("ALTER TABLE risks ADD source_threat_model_id NVARCHAR(36) NULL"
                   if dialect == "mssql"
                   else "ALTER TABLE risks ADD COLUMN source_threat_model_id VARCHAR(36)")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added risks.source_threat_model_id column (%s)", dialect)
            except Exception as exc:
                logger.warning("risks.source_threat_model_id ALTER failed: %s", exc)
        if risk_cols and "source_threat_id" not in risk_cols:
            ddl = ("ALTER TABLE risks ADD source_threat_id NVARCHAR(64) NULL"
                   if dialect == "mssql"
                   else "ALTER TABLE risks ADD COLUMN source_threat_id VARCHAR(64)")
            try:
                with engine.begin() as conn:
                    conn.execute(text(ddl))
                logger.info("Added risks.source_threat_id column (%s)", dialect)
            except Exception as exc:
                logger.warning("risks.source_threat_id ALTER failed: %s", exc)

        # Phase 8 — ThreatModel: coverage_decisions, trust_boundaries_json,
        # entry_points_json, maturity_scores.
        try:
            tm_cols = {c["name"] for c in inspector.get_columns("threat_models")}
        except Exception:
            tm_cols = set()
        _tm_additions = [
            ("coverage_decisions",     "NVARCHAR(MAX) NULL"),
            ("trust_boundaries_json",  "NVARCHAR(MAX) NULL"),
            ("entry_points_json",      "NVARCHAR(MAX) NULL"),
            ("maturity_scores",        "NVARCHAR(MAX) NULL"),
        ]
        for col, mssql_type in _tm_additions:
            if tm_cols and col not in tm_cols:
                sqlite_type = "TEXT"
                ddl = (f"ALTER TABLE threat_models ADD {col} {mssql_type}"
                       if dialect == "mssql"
                       else f"ALTER TABLE threat_models ADD COLUMN {col} {sqlite_type}")
                try:
                    with engine.begin() as conn:
                        conn.execute(text(ddl))
                    logger.info("Added threat_models.%s column (%s)", col, dialect)
                except Exception as exc:
                    logger.warning("threat_models.%s ALTER failed: %s", col, exc)

        # Phase 7A — AIAgent.output_kind + output_schema_json. Lets each
        # buddy declare what shape its output takes (risk_drafts /
        # control_mappings / runbook / etc.).
        try:
            agent_cols = {c["name"] for c in inspector.get_columns("ai_agents")}
        except Exception:
            agent_cols = set()
        _agent_additions = [
            ("output_kind",         "NVARCHAR(32) NULL",  "VARCHAR(32)"),
            ("output_schema_json",  "NVARCHAR(MAX) NULL", "TEXT"),
            # Phase 7C — personality fields
            ("avatar_url",          "NVARCHAR(512) NULL", "VARCHAR(512)"),
            ("signature_opening",   "NVARCHAR(300) NULL", "VARCHAR(300)"),
            ("accent_color",        "NVARCHAR(16) NULL",  "VARCHAR(16)"),
        ]
        for col, mssql_type, sqlite_type in _agent_additions:
            if agent_cols and col not in agent_cols:
                ddl = (f"ALTER TABLE ai_agents ADD {col} {mssql_type}"
                       if dialect == "mssql"
                       else f"ALTER TABLE ai_agents ADD COLUMN {col} {sqlite_type}")
                try:
                    with engine.begin() as conn:
                        conn.execute(text(ddl))
                    logger.info("Added ai_agents.%s column (%s)", col, dialect)
                except Exception as exc:
                    logger.warning("ai_agents.%s ALTER failed: %s", col, exc)

        # Phase 5 — AISettings feature flags + embedding model fields.
        try:
            ai_cols = {c["name"] for c in inspector.get_columns("ai_settings")}
        except Exception:
            ai_cols = set()
        _ai_additions = [
            ("embedding_provider",     "NVARCHAR(64) NULL",   "VARCHAR(64)"),
            ("embedding_model",        "NVARCHAR(128) NULL",  "VARCHAR(128)"),
            ("self_critique_enabled",  "BIT NULL",            "INTEGER"),
            ("semantic_learning_enabled", "BIT NULL",         "INTEGER"),
            ("blackboard_enabled",     "BIT NULL",            "INTEGER"),
        ]
        for col, mssql_type, sqlite_type in _ai_additions:
            if ai_cols and col not in ai_cols:
                ddl = (f"ALTER TABLE ai_settings ADD {col} {mssql_type}"
                       if dialect == "mssql"
                       else f"ALTER TABLE ai_settings ADD COLUMN {col} {sqlite_type}")
                try:
                    with engine.begin() as conn:
                        conn.execute(text(ddl))
                    logger.info("Added ai_settings.%s column (%s)", col, dialect)
                except Exception as exc:
                    logger.warning("ai_settings.%s ALTER failed: %s", col, exc)
    except Exception as exc:
        logger.warning("_ensure_added_columns failed: %s", exc)


def _normalize_enum_case() -> None:
    """One-time migration: lowercase all enum column values so they match the Python enum .values."""
    from sqlalchemy import text
    _cols = [
        ("connectors", "connector_type"), ("connectors", "status"),
        ("scans", "scan_type"), ("scans", "status"), ("scans", "framework"),
        ("findings", "severity"), ("findings", "framework"),
        ("risks", "risk_level"),
        ("agent_runs", "agent_type"),
        ("framework_assessments", "framework"),
    ]
    try:
        with engine.begin() as conn:
            for table, col in _cols:
                conn.execute(text(f"UPDATE {table} SET {col} = lower({col}) WHERE {col} != lower({col})"))
    except Exception as exc:
        logger.warning("enum normalization skipped: %s", exc)


def _provision_entraid_connector() -> None:
    """Create/update the Entra ID connector from env vars on startup.
    Uses a file lock so only one uvicorn worker runs this at a time.
    """
    import os, json, uuid, fcntl
    from datetime import datetime, timezone
    from sqlalchemy.orm import Session
    from api.models.models import Connector, ConnectorStatus, ConnectorType
    from core.encryption import encrypt

    tenant_id = os.environ.get("ENTRAID_CONNECTOR_TENANT_ID")
    client_id = os.environ.get("ENTRAID_CONNECTOR_CLIENT_ID")
    client_secret = os.environ.get("ENTRAID_CONNECTOR_CLIENT_SECRET")
    db_client_id = os.environ.get("ENTRAID_CONNECTOR_DB_CLIENT_ID")

    if not all([tenant_id, client_id, client_secret, db_client_id]):
        return  # env vars not configured; skip

    # File lock prevents concurrent workers from creating duplicates
    lock_path = "/home/.entraid_provision.lock"
    lf = None
    try:
        lf = open(lock_path, "a")
        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError):
        if lf is not None:
            lf.close()
        return  # another worker holds the lock or /home not writable; skip
    try:
        creds_enc = encrypt(json.dumps({
            "tenant_id": tenant_id,
            "client_id": client_id,
            "client_secret": client_secret,
        }))
        name = os.environ.get("ENTRAID_CONNECTOR_CLIENT_NAME", "My Organisation") + " — Entra ID"

        with Session(engine) as db:
            existing = db.query(Connector).filter(
                Connector.client_id == db_client_id,
                Connector.connector_type == ConnectorType.ENTRAID,
            ).first()
            if existing:
                existing.credentials_enc = creds_enc
                existing.status = ConnectorStatus.ACTIVE
                existing.name = name
                logger.info("Entra ID connector updated for client %s", db_client_id)
            else:
                db.add(Connector(
                    id=str(uuid.uuid4()),
                    client_id=db_client_id,
                    name=name,
                    connector_type=ConnectorType.ENTRAID,
                    status=ConnectorStatus.ACTIVE,
                    credentials_enc=creds_enc,
                    config={},
                    created_at=datetime.now(timezone.utc),
                ))
                logger.info("Entra ID connector created for client %s", db_client_id)
            db.commit()
    finally:
        fcntl.flock(lf, fcntl.LOCK_UN)
        lf.close()


def _provision_azure_connector() -> None:
    """Create/update the Azure subscription connector for Greta on startup."""
    import os, json, uuid, fcntl
    from datetime import datetime, timezone
    from sqlalchemy.orm import Session
    from api.models.models import Connector, ConnectorStatus, ConnectorType
    from core.encryption import encrypt

    tenant_id = os.environ.get("ENTRAID_CONNECTOR_TENANT_ID")
    client_id = os.environ.get("ENTRAID_CONNECTOR_CLIENT_ID")
    client_secret = os.environ.get("ENTRAID_CONNECTOR_CLIENT_SECRET")
    db_client_id = os.environ.get("ENTRAID_CONNECTOR_DB_CLIENT_ID")
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "4e6778be-a1f5-4b94-a58d-14a190484c15")
    client_name = os.environ.get("ENTRAID_CONNECTOR_CLIENT_NAME", "Greta")

    if not all([tenant_id, client_id, client_secret, db_client_id]):
        return

    lock_path = "/home/.azure_connector_provision.lock"
    lf = None
    try:
        lf = open(lock_path, "a")
        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError):
        if lf is not None:
            lf.close()
        return
    try:
        creds_enc = encrypt(json.dumps({
            "tenant_id": tenant_id,
            "client_id": client_id,
            "client_secret": client_secret,
            "subscription_id": subscription_id,
        }))
        name = f"{client_name} — Azure"

        with Session(engine) as db:
            existing = db.query(Connector).filter(
                Connector.client_id == db_client_id,
                Connector.connector_type == ConnectorType.AZURE,
            ).first()
            if existing:
                existing.credentials_enc = creds_enc
                existing.status = ConnectorStatus.ACTIVE
                existing.name = name
                logger.info("Azure connector updated for client %s", db_client_id)
            else:
                db.add(Connector(
                    id=str(uuid.uuid4()),
                    client_id=db_client_id,
                    name=name,
                    connector_type=ConnectorType.AZURE,
                    status=ConnectorStatus.ACTIVE,
                    credentials_enc=creds_enc,
                    config={"subscription_id": subscription_id},
                    created_at=datetime.now(timezone.utc),
                ))
                logger.info("Azure connector created for client %s (%s)", db_client_id, client_name)
            db.commit()
    finally:
        fcntl.flock(lf, fcntl.LOCK_UN)
        lf.close()


def _seed_framework_controls() -> None:
    """Idempotent: load JSON files in data/frameworks/, upsert FrameworkControl rows."""
    import os, glob, json, fcntl
    from sqlalchemy.orm import Session
    from api.models.models import FrameworkControl, FrameworkType

    data_dir = os.path.join(os.path.dirname(__file__), "data", "frameworks")
    files = sorted(glob.glob(os.path.join(data_dir, "*.json")))
    if not files:
        return

    lock_path = "/home/.frameworks_seed.lock"
    lf = None
    try:
        lf = open(lock_path, "a")
        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError):
        if lf is not None:
            lf.close()
        return
    try:
        with Session(engine) as db:
            for fp in files:
                payload = json.loads(open(fp, "r", encoding="utf-8").read())
                fw_value = payload["framework"]
                try:
                    fw_enum = FrameworkType(fw_value)
                except ValueError:
                    logger.warning("Unknown framework in %s: %s", fp, fw_value)
                    continue
                seen_ids = set()
                for c in payload.get("controls", []):
                    cid = c["control_id"]
                    seen_ids.add(cid)
                    existing = (
                        db.query(FrameworkControl)
                        .filter(FrameworkControl.framework == fw_enum, FrameworkControl.control_id == cid)
                        .first()
                    )
                    if existing:
                        existing.parent_control_id = c.get("parent")
                        existing.domain = c.get("domain")
                        existing.title = c.get("title") or cid
                        existing.description = c.get("description")
                        existing.weight = c.get("weight", 1)
                    else:
                        db.add(FrameworkControl(
                            framework=fw_enum,
                            control_id=cid,
                            parent_control_id=c.get("parent"),
                            domain=c.get("domain"),
                            title=c.get("title") or cid,
                            description=c.get("description"),
                            weight=c.get("weight", 1),
                        ))
                # Remove rows that vanished from the source JSON
                stale = (
                    db.query(FrameworkControl)
                    .filter(FrameworkControl.framework == fw_enum, ~FrameworkControl.control_id.in_(seen_ids))
                    .all()
                )
                for s in stale:
                    db.delete(s)
                db.commit()
                logger.info("Seeded %s: %d controls", fw_value, len(seen_ids))
    finally:
        fcntl.flock(lf, fcntl.LOCK_UN)
        lf.close()


def _migrate_risk_scale_v2() -> None:
    """One-time: migrate Risk likelihood/impact from the legacy 1-5 scale to
    1-10 and recompute risk_score = L×I/10.

    Threat-model-sourced risks are re-derived from each source threat's OWN
    likelihood/impact (recovering the per-threat variation the old
    severity-fixed conversion discarded, so two 'high' risks no longer look
    identical); all other legacy rows are rescaled ×2. Guarded by both a
    marker file (runs once) AND a 1-5 heuristic (only touches rows where both
    factors are ≤5) so a freshly-seeded 1-10 DB is never double-scaled."""
    import os, fcntl
    from sqlalchemy.orm import Session
    from core.paths import data_dir
    from api.models.models import Risk, ThreatModel
    from services.risk_scoring import clamp_scale, compute_risk_score, from_finding, sev_baseline

    base = str(data_dir())
    marker = os.path.join(base, ".risk_scale_v2.done")
    if os.path.exists(marker):
        return

    def _is_num(v):
        try:
            return v is not None and float(v) > 0
        except (TypeError, ValueError):
            return False

    lf = None
    try:
        lf = open(os.path.join(base, ".risk_scale_v2.lock"), "a")
        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError):
        if lf is not None:
            lf.close()
        return
    try:
        if os.path.exists(marker):
            return
        with Session(engine) as db:
            tm_cache: dict = {}
            migrated = 0
            for risk in db.query(Risk).all():
                old_l = int(risk.likelihood or 3)
                old_i = int(risk.impact or 3)
                # Skip rows already on the 1-10 scale (e.g. freshly seeded).
                if old_l > 5 or old_i > 5:
                    continue
                sev = (
                    risk.risk_level.value if hasattr(risk.risk_level, "value")
                    else str(risk.risk_level or "medium")
                ).lower()
                new_l = new_i = None
                # Threat-model-sourced risks: prefer the source threat's OWN
                # likelihood/impact (old 1-5 scale → ×2), recovering per-threat
                # variation the old severity-fixed conversion discarded.
                if risk.source_threat_model_id and risk.source_threat_id:
                    if risk.source_threat_model_id not in tm_cache:
                        tm_cache[risk.source_threat_model_id] = (
                            db.query(ThreatModel)
                            .filter(ThreatModel.id == risk.source_threat_model_id)
                            .first()
                        )
                    tm = tm_cache[risk.source_threat_model_id]
                    if tm is not None:
                        threat = next(
                            (t for t in (tm.threats_json or [])
                             if str(t.get("id")) == str(risk.source_threat_id)),
                            None,
                        )
                        if threat is not None and (_is_num(threat.get("likelihood")) or _is_num(threat.get("impact"))):
                            base_l, base_i = sev_baseline(threat.get("severity"))
                            tl, ti = threat.get("likelihood"), threat.get("impact")
                            new_l = clamp_scale(int(tl) * 2, base_l) if _is_num(tl) else base_l
                            new_i = clamp_scale(int(ti) * 2, base_i) if _is_num(ti) else base_i
                # Everything else (findings/agent-derived): re-derive distinct
                # likelihood vs impact from severity + the risk's text signals,
                # so the legacy all-equal pairs (4/4, 5/5) become differentiated.
                if new_l is None:
                    text = f"{risk.title or ''} {risk.description or ''} {risk.category or ''}"
                    new_l, new_i, _ = from_finding(sev, text=text)
                risk.likelihood = new_l
                risk.impact = new_i
                risk.risk_score = compute_risk_score(new_l, new_i)
                migrated += 1
            db.commit()
        with open(marker, "w") as mf:
            mf.write("done")
        logger.info("Risk scale v2 migration complete: %d legacy risks rescaled to 1-10", migrated)
    except Exception:
        logger.exception("Risk scale v2 migration failed")
    finally:
        fcntl.flock(lf, fcntl.LOCK_UN)
        lf.close()


def _prune_access_logs(retention_days: int = 90) -> None:
    """Delete access_logs rows older than the retention window. Runs at
    startup (workers recycle periodically, so this fires often enough)."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy.orm import Session
    from api.models.models import AccessLog
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    try:
        with Session(engine) as db:
            deleted = db.query(AccessLog).filter(AccessLog.created_at < cutoff).delete(synchronize_session=False)
            db.commit()
            if deleted:
                logger.info("Pruned %d access_logs rows older than %d days", deleted, retention_days)
    except Exception:
        logger.exception("Access-log prune failed")


def _bootstrap_initial_admin() -> None:
    """Ensure the UPN configured in INITIAL_ADMIN_UPN always has a global
    admin grant. Idempotent — checks per-UPN, not "any global admin
    exists". Without this, if a previous deploy left other admin rows in
    the table, the configured UPN never gets re-granted and is locked out
    after a DB reset / migration / inadvertent grant revoke."""
    import os
    from sqlalchemy.orm import Session
    from api.models.models import AccessRole, AccessScope, UserAccess

    upn = (os.environ.get("INITIAL_ADMIN_UPN") or "").strip().lower()
    if not upn:
        return
    try:
        with Session(engine) as db:
            existing = db.query(UserAccess).filter(
                UserAccess.email == upn,
                UserAccess.role == AccessRole.ADMIN,
                UserAccess.scope_type == AccessScope.GLOBAL,
            ).first()
            if existing:
                return
            db.add(UserAccess(
                email=upn,
                role=AccessRole.ADMIN,
                scope_type=AccessScope.GLOBAL,
                scope_id=None,
                granted_by="bootstrap",
            ))
            db.commit()
            logger.info("Bootstrapped global admin grant for %s", upn)
    except Exception as exc:
        logger.warning("Initial admin bootstrap failed: %s", exc)


def _fail_stale_threat_models() -> None:
    """Reconcile orphaned threat-model generations on startup.

    Generation runs as a FastAPI BackgroundTask in the web worker. If the
    worker is OOM-killed (or otherwise dies) mid-run, the `except` that sets
    status='failed' never executes, so the row is stuck at 'generating' /
    'pending' forever and the detail page polls indefinitely. Flip anything
    older than the threshold to 'failed' so the UI stops spinning and the
    user can rescan. Age-gated so a legitimately in-flight run started just
    before another worker restarted is never killed."""
    from datetime import datetime, timezone, timedelta
    from sqlalchemy.orm import Session
    from api.models.models import ThreatModel

    STALE_AFTER = timedelta(minutes=20)
    cutoff = datetime.now(timezone.utc) - STALE_AFTER
    try:
        with Session(engine) as db:
            stale = (
                db.query(ThreatModel)
                .filter(ThreatModel.status.in_(["generating", "pending"]))
                .all()
            )
            n = 0
            for tm in stale:
                created = tm.created_at
                # created_at may be naive (SQLite) or tz-aware (MSSQL).
                if created is not None and created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                if created is not None and created > cutoff:
                    continue  # still within the grace window — leave it running
                tm.status = "failed"
                tm.error_message = (
                    "Generation was interrupted (worker restart or timeout). "
                    "Please rescan."
                )
                tm.generated_at = datetime.now(timezone.utc)
                n += 1
            if n:
                db.commit()
                logger.info("Reconciled %d stale threat-model generation(s) to 'failed'", n)
    except Exception as exc:
        logger.warning("Stale threat-model reconcile failed: %s", exc)


def _fail_stale_scans() -> None:
    """Fail scans stuck in pending/running past the longest plausible scanner
    runtime. A workflow-driven scan that's cancelled, times out, or fails to
    dispatch never calls /scans/ingest, so the scan would otherwise sit
    'running' forever. Age-gated well beyond the slowest job (OWASP DC ~60m)
    so an in-flight scan is never killed."""
    from datetime import datetime, timezone, timedelta
    from sqlalchemy.orm import Session
    from api.models.models import Scan, ScanStatus

    STALE_AFTER = timedelta(minutes=90)
    now = datetime.now(timezone.utc)
    cutoff = now - STALE_AFTER
    try:
        with Session(engine) as db:
            stuck = db.query(Scan).filter(
                Scan.status.in_([ScanStatus.PENDING.value, ScanStatus.RUNNING.value])
            ).all()
            n = 0
            for s in stuck:
                ref = s.started_at or s.created_at
                if ref is not None and ref.tzinfo is None:
                    ref = ref.replace(tzinfo=timezone.utc)
                if ref is not None and ref > cutoff:
                    continue  # still within the grace window — leave it running
                s.status = ScanStatus.FAILED
                s.error_message = (
                    "Scan timed out — the scanner workflow didn't report back "
                    "(cancelled, timed out, or failed to dispatch). Re-run the scan."
                )
                s.completed_at = now
                n += 1
            if n:
                db.commit()
                logger.info("Reconciled %d stuck scan(s) to 'failed'", n)
    except Exception as exc:
        logger.warning("Stuck-scan reconcile failed: %s", exc)


_ensure_added_columns()
_ensure_projects_schema()
_normalize_enum_case()
_provision_entraid_connector()
_provision_azure_connector()
_seed_framework_controls()
_migrate_risk_scale_v2()
_bootstrap_initial_admin()
_fail_stale_threat_models()
_fail_stale_scans()
_prune_access_logs()

app = FastAPI(
    title="NexGenCyberAI API",
    version=settings.APP_VERSION,
    description="AI-powered Cybersecurity Posture Management Platform",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    redirect_slashes=False,
)

# CORS — allow the SPA and Azure App Service hostnames
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _record_access(token: str | None, method: str, path: str, status: int, ip: str | None, ua: str | None) -> None:
    """Best-effort: persist one access_logs row for an authenticated request.

    Runs in a threadpool (off the event loop) and swallows all errors so audit
    logging can never break or slow a request. Skips requests with no valid
    bearer token (anonymous / pre-auth) since the point is *who* accessed."""
    if not token:
        return
    try:
        from core.security import decode_azure_token
        from core.authz import _user_email
        from api.models.models import AccessLog
        from sqlalchemy.orm import Session

        try:
            claims = decode_azure_token(token)
        except Exception:
            return  # invalid/expired token → not a successful access
        email = _user_email(claims)
        if not email:
            return
        with Session(engine) as db:
            db.add(AccessLog(
                user_email=email,
                user_name=(claims.get("name") or "")[:255] or None,
                method=method[:8],
                path=path[:512],
                status_code=status,
                ip_address=(ip or "")[:64] or None,
                user_agent=(ua or "")[:512] or None,
            ))
            db.commit()
    except Exception:
        pass


# Paths excluded from access logging (noise / unauthenticated / self-polling).
_ACCESS_LOG_SKIP_PREFIXES = ("/api/health", "/api/docs", "/api/openapi", "/api/redoc")


# Latency + access-logging middleware
@app.middleware("http")
async def add_latency_header(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    response.headers["X-Response-Time"] = f"{(time.time() - start)*1000:.1f}ms"

    # Audit who accessed the portal — fire-and-forget so it never adds latency.
    try:
        path = request.url.path
        if (
            request.method != "OPTIONS"
            and path.startswith("/api/")
            and not path.endswith("/admin/access-logs/")
            and not any(path.startswith(p) for p in _ACCESS_LOG_SKIP_PREFIXES)
        ):
            auth = request.headers.get("authorization") or ""
            token = auth[7:] if auth.lower().startswith("bearer ") else None
            if token:
                xff = request.headers.get("x-forwarded-for")
                ip = (xff.split(",")[0].strip() if xff else None) or (request.client.host if request.client else None)
                import asyncio
                from starlette.concurrency import run_in_threadpool
                asyncio.create_task(run_in_threadpool(
                    _record_access, token, request.method, path,
                    response.status_code, ip, request.headers.get("user-agent"),
                ))
    except Exception:
        pass
    return response


# Routers
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(clients.router, prefix="/api/v1")
app.include_router(connectors.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(scans_runner.router, prefix="/api/v1")
app.include_router(risks.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")
app.include_router(frameworks.router, prefix="/api/v1")
app.include_router(risk_overview.router, prefix="/api/v1")
app.include_router(projects.router, prefix="/api/v1")
app.include_router(technologies.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(agents.router, prefix="/api/v1")
app.include_router(ai_settings.router, prefix="/api/v1")
app.include_router(email.router, prefix="/api/v1")
app.include_router(missions.router, prefix="/api/v1")
app.include_router(knowledge.router, prefix="/api/v1")
app.include_router(agent_catalog.router, prefix="/api/v1")
app.include_router(risk_portfolio.router, prefix="/api/v1")
app.include_router(threat_models.router, prefix="/api/v1")
app.include_router(threat_models.methodology_router, prefix="/api/v1")
app.include_router(scans_overview.router, prefix="/api/v1")
app.include_router(sso.router, prefix="/api/v1")


# ── Background scheduler (APScheduler for ScheduledMissions) ─────────────────

@app.on_event("startup")
async def _start_mission_scheduler() -> None:
    # Lazy import so the app still boots even if APScheduler isn't installed
    # (development without `pip install -r requirements.txt`).
    try:
        from services.mission_scheduler import start_scheduler
        start_scheduler()
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Failed to start mission scheduler")
    # Register the external-feed cron jobs on the same scheduler so EPSS,
    # KEV, NVD, ATT&CK, and CAPEC stay fresh without manual clicks.
    try:
        from services.sync_feeds import start_feed_schedules
        start_feed_schedules()
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Failed to start feed schedules")

    # Phase 7B — seed default buddy triggers + register weekly roundup.
    try:
        from services.buddy_triggers import seed_default_triggers, start_weekly_roundup
        from db.database import SessionLocal
        bg_db = SessionLocal()
        try:
            seed_default_triggers(bg_db)
        finally:
            bg_db.close()
        start_weekly_roundup()
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Failed to start buddy triggers")


@app.on_event("startup")
async def _start_scan_binary_cleanup() -> None:
    """Daily 02:00 UTC purge of uploaded scan binaries older than 30 days.
    Best-effort: failure to schedule never blocks boot. Admins can also
    trigger this manually via POST /admin/scan-binaries/cleanup."""
    import asyncio
    import logging
    log = logging.getLogger(__name__)

    async def _loop() -> None:
        from services.scan_binaries import cleanup_old_binaries
        # Run once shortly after boot to clean any stragglers, then every 24h.
        await asyncio.sleep(60)
        while True:
            try:
                result = await asyncio.to_thread(cleanup_old_binaries, 30)
                log.info("Scan binary cleanup: %s", result)
            except Exception:
                log.exception("Scan binary cleanup failed")
            await asyncio.sleep(24 * 3600)

    try:
        asyncio.create_task(_loop())
    except Exception:
        log.exception("Failed to schedule scan binary cleanup")


@app.on_event("startup")
async def _start_stuck_scan_watchdog() -> None:
    """Periodically fail scans whose workflow never reported back, so they
    don't sit 'running' forever (startup already does one pass)."""
    import asyncio
    import logging
    log = logging.getLogger(__name__)

    async def _loop() -> None:
        await asyncio.sleep(300)  # first periodic pass 5 min after boot
        while True:
            try:
                await asyncio.to_thread(_fail_stale_scans)
            except Exception:
                log.exception("Stuck-scan watchdog pass failed")
            await asyncio.sleep(20 * 60)  # every 20 minutes

    try:
        asyncio.create_task(_loop())
    except Exception:
        log.exception("Failed to schedule stuck-scan watchdog")


@app.on_event("startup")
async def _start_deleted_client_purge() -> None:
    """Daily 03:00 UTC hard-delete of clients soft-deleted more than 30 days ago."""
    import asyncio
    import logging
    log = logging.getLogger(__name__)

    async def _loop() -> None:
        await asyncio.sleep(120)  # wait 2 min after boot
        while True:
            try:
                from api.routers.admin import _purge_expired_deleted_clients
                from db.database import SessionLocal
                db = SessionLocal()
                try:
                    result = _purge_expired_deleted_clients(db)
                    if result["purged"]:
                        log.info("Auto-purged %d expired soft-deleted client(s)", result["purged"])
                finally:
                    db.close()
            except Exception:
                log.exception("Deleted-client auto-purge failed")
            await asyncio.sleep(24 * 3600)

    try:
        asyncio.create_task(_loop())
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Failed to schedule deleted-client purge")


@app.on_event("startup")
async def _warm_threat_intel_cache() -> None:
    """Load whatever threat-intel snapshot exists on disk from a prior sync.

    Sync is manual (admin-triggered via POST /admin/threat-intel/refresh)
    — there's no daily auto-refresh. We just warm the in-memory cache
    from the persisted JSON so RPS scoring has data available
    immediately after boot if a previous sync ran.
    """
    try:
        from services import threat_intel as _ti
        _ti._ensure_loaded()
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Failed to warm threat-intel cache")


@app.on_event("shutdown")
async def _stop_mission_scheduler() -> None:
    try:
        from services.mission_scheduler import shutdown_scheduler
        shutdown_scheduler()
    except Exception:
        pass


# ── Knowledge base seeding ───────────────────────────────────────────────────

def _seed_knowledge_base() -> None:
    try:
        from services.knowledge_seed import seed_knowledge_base
        seed_knowledge_base()
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Knowledge base seed failed")


def _seed_agents() -> None:
    try:
        from services.agent_seed import seed_agent_catalog
        seed_agent_catalog()
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Agent catalog seed failed")


_seed_knowledge_base()
_seed_agents()


@app.post("/api/internal/ai-review-test")
async def internal_ai_review_test(request: Request, background_tasks: BackgroundTasks):
    """Temporary internal endpoint — trigger an AI code review scan without browser auth."""
    from fastapi import HTTPException as _HTTPException
    secret = settings.SCAN_INGEST_SECRET
    if not secret or request.headers.get("X-Internal-Secret") != secret:
        raise _HTTPException(status_code=403, detail="Forbidden")
    data = await request.json()
    repo_url = data.get("repo_url", "")
    client_id = data.get("client_id", "")
    if not repo_url or not client_id:
        raise _HTTPException(status_code=400, detail="repo_url and client_id required")
    from db.database import SessionLocal as _SL
    from api.models.models import Scan, ScanStatus, ScanType
    from api.routers.scans import _execute_scan
    from core.encryption import encrypt as _enc
    _db = _SL()
    try:
        import uuid as _uuid
        _scan = Scan(
            id=str(_uuid.uuid4()),
            client_id=client_id,
            scan_type=ScanType.FULL,
            status=ScanStatus.PENDING,
            initiated_by="internal-test",
            summary={"repo_url": repo_url},
        )
        _db.add(_scan)
        _db.commit()
        _scan_id = _scan.id
    finally:
        _db.close()
    background_tasks.add_task(_execute_scan, _scan_id, settings.DATABASE_URL, None, None)
    return {"scan_id": _scan_id, "repo_url": repo_url, "status": "triggered"}


@app.get("/api/health")
async def health():
    db_status = "ok"
    try:
        with engine.connect() as conn:
            conn.execute(__import__("sqlalchemy").text("SELECT 1"))
    except Exception:
        db_status = "error"
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "db": db_status,
        "app": settings.APP_NAME,
    }


@app.get("/")
async def root():
    return {"message": "NexGenCyberAI API — visit /api/docs for documentation"}
