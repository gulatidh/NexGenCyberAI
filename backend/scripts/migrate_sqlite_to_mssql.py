"""
One-shot migration: SQLite → Azure SQL (mssql+pyodbc).

Usage:
    python3 migrate_sqlite_to_mssql.py \
        --sqlite  sqlite:////home/site/wwwroot/nexgencyberai.db \
        --mssql   "mssql+pyodbc://nexgenadmin:<PASSWORD>@ncai-dev-n3bg-sql.database.windows.net/nexgencyberai?driver=ODBC+Driver+17+for+SQL+Server&TrustServerCertificate=yes"

The script:
1. Creates all tables in Azure SQL (safe — skips existing).
2. Copies every row from every table, skipping rows whose PK already exists
   (so it's safe to re-run if interrupted).
3. Prints a row count summary at the end.

Run BEFORE flipping DATABASE_URL so the app can still serve traffic
during the migration window.
"""
import argparse
import sys
from sqlalchemy import create_engine, text, inspect as sa_inspect
from sqlalchemy.orm import Session

parser = argparse.ArgumentParser()
parser.add_argument("--sqlite", required=True, help="Source SQLite URL")
parser.add_argument("--mssql",  required=True, help="Target Azure SQL URL")
args = parser.parse_args()

print("Connecting to source (SQLite)...")
src_engine = create_engine(args.sqlite, echo=False)

print("Connecting to target (Azure SQL)...")
try:
    tgt_engine = create_engine(args.mssql, echo=False)
    with tgt_engine.connect() as c:
        c.execute(text("SELECT 1"))
    print("  Connected OK")
except Exception as exc:
    print(f"  FAILED: {exc}")
    sys.exit(1)

# Import models so create_all knows the full schema
sys.path.insert(0, ".")
from db.database import Base
from api.models import models as _  # noqa — registers all ORM classes

print("\nCreating tables in Azure SQL (safe, skips existing)...")
Base.metadata.create_all(bind=tgt_engine)
print("  Done")

# Get table list from source
src_inspector = sa_inspect(src_engine)
tables = src_inspector.get_table_names()
print(f"\nFound {len(tables)} tables in SQLite: {tables}\n")

summary = {}
for table in tables:
    with src_engine.connect() as src_conn:
        rows = src_conn.execute(text(f"SELECT * FROM \"{table}\"")).mappings().all()
    if not rows:
        summary[table] = 0
        continue

    # Get PK columns for skip-existing logic
    pk_cols = [c["name"] for c in src_inspector.get_pk_constraint(table).get("constrained_columns", [])]

    inserted = 0
    skipped = 0
    with Session(tgt_engine) as tgt_session:
        for row in rows:
            row_dict = dict(row)
            if pk_cols:
                # Check if PK already exists in target
                where = " AND ".join(f"\"{col}\" = :{col}" for col in pk_cols)
                exists = tgt_session.execute(
                    text(f"SELECT 1 FROM \"{table}\" WHERE {where}"),
                    {col: row_dict[col] for col in pk_cols},
                ).first()
                if exists:
                    skipped += 1
                    continue
            cols = ", ".join(f'"{k}"' for k in row_dict)
            placeholders = ", ".join(f":{k}" for k in row_dict)
            try:
                tgt_session.execute(
                    text(f'INSERT INTO "{table}" ({cols}) VALUES ({placeholders})'),
                    row_dict,
                )
                inserted += 1
            except Exception as exc:
                print(f"  [{table}] row insert error (skipping): {exc}")
                skipped += 1
        tgt_session.commit()

    summary[table] = inserted
    print(f"  {table:40s}  {inserted:5d} inserted  {skipped:5d} skipped")

print("\n=== Migration summary ===")
total = sum(summary.values())
for t, n in summary.items():
    print(f"  {t}: {n}")
print(f"\nTotal rows migrated: {total}")
print("\nDone. Now update DATABASE_URL in App Service and restart.")
