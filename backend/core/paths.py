"""Filesystem paths that must survive restarts and be shared across workers.

On Azure App Service the app directory (wwwroot) is EPHEMERAL and each
gunicorn worker sees its own copy — so caches written there (sync stats,
threat-intel) vanish on restart and aren't visible to sibling workers. Only
`/home` is a persistent, shared mount (the SQLite DB lives there too).

`data_dir()` resolves the durable cache directory:
  1. $SYNC_DATA_DIR if set (explicit override)
  2. /home/data  when /home is a writable directory (Azure)
  3. backend/data otherwise (local dev)
"""
import os
from pathlib import Path
from functools import lru_cache


@lru_cache()
def data_dir() -> Path:
    override = os.environ.get("SYNC_DATA_DIR")
    if override:
        p = Path(override)
    else:
        home = Path("/home")
        if home.is_dir() and os.access(home, os.W_OK):
            p = home / "data"
        else:
            p = Path(__file__).resolve().parent.parent / "data"
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Fall back to the in-repo data dir if the persistent path isn't writable.
        p = Path(__file__).resolve().parent.parent / "data"
        p.mkdir(parents=True, exist_ok=True)
    return p
