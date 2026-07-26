"""
Azure SQL → Azure SQL migration: North Europe → West US.
- Reads from ncai-dev-n3bg-sql (northeurope)
- Writes to ncai-dev-westus-sql (westus)
- Disables FK constraints during insert (Azure SQL compatible)
- Bulk inserts in batches of 500 with per-row fallback on conflict
"""
import sys, time
sys.path.insert(0, ".")

from sqlalchemy import create_engine, text, inspect as sa_inspect, Table, MetaData

SRC_URL = "mssql+pymssql://nexgenadmin:NexGen%40SQL2024%21@ncai-dev-n3bg-sql.database.windows.net/nexgencyberai"
TGT_URL = "mssql+pymssql://nexgenadmin:NexGen%40SQL2024%21@ncai-dev-westus-sql.database.windows.net/nexgencyberai"

BATCH = 500

src = create_engine(SRC_URL, echo=False)
tgt = create_engine(TGT_URL, echo=False)

# Ensure schema on target
from db.database import Base
from api.models import models as _  # noqa
Base.metadata.create_all(bind=tgt)

# Get table lists from both sides
with src.connect() as sc:
    result = sc.execute(text("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'"))
    src_tables = {r[0] for r in result}

with tgt.connect() as tc:
    result = tc.execute(text("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'"))
    tgt_tables = {r[0] for r in result}

all_tables = sorted(src_tables & tgt_tables)
missing = src_tables - tgt_tables
if missing:
    print(f"NOTE: {len(missing)} source tables not in target (skipping): {missing}\n")

# Disable FK constraints on all target tables
print("Disabling FK constraints...")
with tgt.begin() as tc:
    for table in all_tables:
        tc.execute(text(f'ALTER TABLE [{table}] NOCHECK CONSTRAINT ALL'))
print(f"  Done ({len(all_tables)} tables)\n")

# Clear existing data on target
print("Clearing target tables...")
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
        rows = sc.execute(text(f'SELECT * FROM [{table}]')).mappings().all()

    if not rows:
        summary[table] = 0
        print(f"  {table:<45}      0 rows (empty)")
        continue

    tbl = meta.tables[table]
    inserted = 0
    skipped = 0
    t0 = time.time()

    # Deduplicate by PK
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

print("\n=== Summary ===")
total = sum(summary.values())
for t, n in sorted(summary.items(), key=lambda x: -x[1]):
    if n:
        print(f"  {t}: {n}")
print(f"\nTotal rows migrated: {total}")
