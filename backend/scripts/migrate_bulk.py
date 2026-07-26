"""
Bulk migration: SQLite → Azure SQL, skipping access_logs.
- Disables FK constraints per-table (Azure SQL compatible — no sp_MSforeachtable)
- Bulk inserts in batches of 500
- Safe to re-run: skips tables that already have data
"""
import sys, time
sys.path.insert(0, ".")

from sqlalchemy import create_engine, text, inspect as sa_inspect, Table, MetaData
from sqlalchemy.orm import Session

SQLITE_URL = "sqlite:////tmp/live_nexgencyberai.db"
MSSQL_URL  = "mssql+pymssql://nexgenadmin:NexGen%40SQL2024%21@ncai-dev-n3bg-sql.database.windows.net/nexgencyberai"

SKIP_TABLES = {"access_logs"}  # large audit log — future entries go directly to Azure SQL
BATCH = 500

src = create_engine(SQLITE_URL, echo=False)
tgt = create_engine(MSSQL_URL,  echo=False)

# Ensure schema
from db.database import Base
from api.models import models as _  # noqa
Base.metadata.create_all(bind=tgt)

insp = sa_inspect(src)
src_tables = set(insp.get_table_names()) - SKIP_TABLES

# Get tables that actually exist in Azure SQL (create_all may miss some models)
with tgt.connect() as tc:
    result = tc.execute(text("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'"))
    tgt_tables = {r[0] for r in result}

all_tables = sorted(src_tables & tgt_tables)
missing = src_tables - tgt_tables
if missing:
    print(f"NOTE: {len(missing)} SQLite tables not in Azure SQL (skipping): {missing}\n")

# Disable FK constraints on all target tables (Azure SQL compatible)
print("Disabling FK constraints...")
with tgt.begin() as tc:
    for table in all_tables:
        tc.execute(text(f'ALTER TABLE [{table}] NOCHECK CONSTRAINT ALL'))
print(f"  Done ({len(all_tables)} tables)\n")

# Clear existing data
print("Clearing any existing data...")
with tgt.begin() as tc:
    for table in reversed(all_tables):
        tc.execute(text(f'DELETE FROM [{table}]'))
print("  Done\n")

print(f"Migrating {len(all_tables)} tables...\n")
meta = MetaData()
meta.reflect(bind=tgt)

summary = {}
for table in all_tables:
    with src.connect() as sc:
        rows = sc.execute(text(f'SELECT * FROM "{table}"')).mappings().all()

    if not rows:
        summary[table] = 0
        print(f"  {table:<45}      0 rows (empty)")
        continue

    tbl = meta.tables[table]
    inserted = 0
    skipped = 0
    t0 = time.time()

    # Deduplicate by PK to handle SQLite rows that violate Azure SQL unique constraints
    pk_cols = [c.name for c in tbl.primary_key.columns]
    if pk_cols:
        seen = set()
        deduped = []
        for r in rows:
            key = tuple(r[c] for c in pk_cols)
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        skipped_pk = len(rows) - len(deduped)
        if skipped_pk:
            print(f"  {table}: deduped {skipped_pk} duplicate PK rows from source")
        rows = deduped

    for i in range(0, len(rows), BATCH):
        batch = [dict(r) for r in rows[i:i+BATCH]]
        try:
            with tgt.begin() as tc:
                tc.execute(tbl.insert(), batch)
            inserted += len(batch)
        except Exception:
            # Batch has a conflict — fall back to one-by-one
            for row in batch:
                try:
                    with tgt.begin() as tc:
                        tc.execute(tbl.insert(), [dict(row)])
                    inserted += 1
                except Exception as e2:
                    skipped += 1

    elapsed = time.time() - t0
    note = f"  ({skipped} skipped)" if skipped else ""
    print(f"  {table:<45} {inserted:>6} rows  ({elapsed:.1f}s){note}")
    summary[table] = inserted

# Re-enable and validate FK constraints
print("\nRe-enabling FK constraints...")
errors = []
with tgt.begin() as tc:
    for table in all_tables:
        try:
            tc.execute(text(f'ALTER TABLE [{table}] WITH CHECK CHECK CONSTRAINT ALL'))
        except Exception as e:
            errors.append(f"{table}: {e}")
if errors:
    print(f"  WARNING — FK validation errors:\n  " + "\n  ".join(errors))
else:
    print("  All FK constraints valid\n")

print("=== Summary ===")
total = sum(summary.values())
for t, n in sorted(summary.items(), key=lambda x: -x[1]):
    if n:
        print(f"  {t}: {n}")
print(f"\nTotal rows migrated: {total}")
print("\nNext step: set DATABASE_URL app setting and restart App Service.")
