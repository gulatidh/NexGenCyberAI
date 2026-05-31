"""
NexGenCyberAI - FastAPI Application Entry Point
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import logging
import time

from core.config import get_settings
from db.database import Base, engine
from api.routers import clients, connectors, scans, scans_runner, scans_overview, risks, agents, dashboard, ai_settings, findings, assets, frameworks, risk_overview, projects, technologies, admin, missions, knowledge, agent_catalog, risk_portfolio, threat_models

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


_ensure_added_columns()
_ensure_projects_schema()
_normalize_enum_case()
_provision_entraid_connector()
_provision_azure_connector()
_seed_framework_controls()
_bootstrap_initial_admin()

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

# Latency logging middleware
@app.middleware("http")
async def add_latency_header(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    response.headers["X-Response-Time"] = f"{(time.time() - start)*1000:.1f}ms"
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
app.include_router(missions.router, prefix="/api/v1")
app.include_router(knowledge.router, prefix="/api/v1")
app.include_router(agent_catalog.router, prefix="/api/v1")
app.include_router(risk_portfolio.router, prefix="/api/v1")
app.include_router(threat_models.router, prefix="/api/v1")
app.include_router(threat_models.methodology_router, prefix="/api/v1")
app.include_router(scans_overview.router, prefix="/api/v1")


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
