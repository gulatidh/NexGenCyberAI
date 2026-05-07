"""
Create the Entra ID connector record from environment variables.
Credentials are sourced from App Service settings (Key Vault references),
never hardcoded. Safe to run in CI/CD or via Kudu.

Required env vars:
  ENTRAID_CONNECTOR_TENANT_ID
  ENTRAID_CONNECTOR_CLIENT_ID
  ENTRAID_CONNECTOR_CLIENT_SECRET
  ENTRAID_CONNECTOR_DB_CLIENT_ID  — UUID of the client row in the DB
  ENTRAID_CONNECTOR_CLIENT_NAME   — Display name (optional, for logging)
"""
import os, sys, json, sqlite3, uuid, base64, hashlib
from datetime import datetime, timezone
from cryptography.fernet import Fernet

REQUIRED = [
    "ENTRAID_CONNECTOR_TENANT_ID",
    "ENTRAID_CONNECTOR_CLIENT_ID",
    "ENTRAID_CONNECTOR_CLIENT_SECRET",
    "ENTRAID_CONNECTOR_DB_CLIENT_ID",
]
missing = [k for k in REQUIRED if not os.environ.get(k)]
if missing:
    print(f"Missing env vars: {missing}")
    sys.exit(1)

DB_PATH = os.environ.get("DATABASE_URL", "sqlite:////home/nexgencyberai.db")
if DB_PATH.startswith("sqlite:///"):
    DB_PATH = DB_PATH[len("sqlite:///"):]

ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "dev-insecure-key-replace-in-prod")
raw_key = base64.urlsafe_b64encode(hashlib.sha256(ENCRYPTION_KEY.encode()).digest())
fernet = Fernet(raw_key)

creds = {
    "tenant_id": os.environ["ENTRAID_CONNECTOR_TENANT_ID"],
    "client_id": os.environ["ENTRAID_CONNECTOR_CLIENT_ID"],
    "client_secret": os.environ["ENTRAID_CONNECTOR_CLIENT_SECRET"],
}
creds_enc = fernet.encrypt(json.dumps(creds).encode()).decode()

db_client_id = os.environ["ENTRAID_CONNECTOR_DB_CLIENT_ID"]
client_name = os.environ.get("ENTRAID_CONNECTOR_CLIENT_NAME", "My Organisation")
connector_name = f"{client_name} - Entra ID"

conn = sqlite3.connect(DB_PATH)
existing = conn.execute(
    "SELECT id FROM connectors WHERE client_id=? AND connector_type='entraid'",
    (db_client_id,)
).fetchone()

if existing:
    conn.execute(
        "UPDATE connectors SET credentials_enc=?, status='active', name=? WHERE id=?",
        (creds_enc, connector_name, existing[0])
    )
    print(f"Updated existing Entra ID connector {existing[0]}")
else:
    new_id = str(uuid.uuid4())
    conn.execute("""
        INSERT INTO connectors
          (id, client_id, name, connector_type, status, credentials_enc, config, created_at)
        VALUES (?, ?, ?, 'entraid', 'active', ?, '{}', ?)
    """, (new_id, db_client_id, connector_name, creds_enc, datetime.now(timezone.utc).isoformat()))
    print(f"Created Entra ID connector {new_id}")

conn.commit()
conn.close()
print("Done.")
