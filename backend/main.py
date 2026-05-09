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
from api.routers import clients, connectors, scans, risks, agents, dashboard, ai_settings, findings, assets

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("nexgencyberai")

settings = get_settings()

# Create DB tables
Base.metadata.create_all(bind=engine)


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


_normalize_enum_case()
_provision_entraid_connector()
_provision_azure_connector()

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
app.include_router(risks.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")
app.include_router(agents.router, prefix="/api/v1")
app.include_router(ai_settings.router, prefix="/api/v1")


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
