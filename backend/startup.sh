#!/bin/bash
# v3 — tar.gz bundle extracted to /tmp (ephemeral disk, fast)
set -e
cd /home/site/wwwroot

# Find the system Python 3.12 binary (path may vary by patch version)
if [ -x "/opt/python/3.12.13/bin/python3" ]; then
    PYTHON3="/opt/python/3.12.13/bin/python3"
elif [ -x "/opt/python/3.12.10/bin/python3" ]; then
    PYTHON3="/opt/python/3.12.10/bin/python3"
elif command -v python3.12 &>/dev/null; then
    PYTHON3="$(command -v python3.12)"
else
    PYTHON3="$(command -v python3)"
fi
echo "[startup] Using Python: $PYTHON3 ($($PYTHON3 --version 2>&1))"

# ── Fast path: pre-bundled packages shipped as a single tar.gz ───────────────
# CI creates .bundled-packages.tar.gz from site-packages and includes it in the
# deployment zip. Kudu writes ONE large file to wwwroot (fast). We extract it
# to /tmp/aegis-packages (ephemeral local disk, NOT Azure Files) — takes ~20s.
# Then run gunicorn via PYTHONPATH — no pip install, no Azure Files writes.
BUNDLED_TAR=/home/site/wwwroot/.bundled-packages.tar.gz
BUNDLED_EXTRACT=/tmp/aegis-packages

if [ -f "$BUNDLED_TAR" ]; then
    echo "[startup] Extracting pre-bundled packages to /tmp (~20s)..."
    mkdir -p "$BUNDLED_EXTRACT"
    tar -xzf "$BUNDLED_TAR" -C "$BUNDLED_EXTRACT"
    # Deep-import the Rust/C extension submodules that actually load .so files.
    # Top-level `import cryptography` doesn't load _rust.abi3.so — only the
    # submodule import does. Same for pydantic_core. A GLIBC mismatch (bundles
    # built on newer Ubuntu vs Azure's Debian Bullseye) shows up here, not at
    # the top-level import.
    if PYTHONPATH="$BUNDLED_EXTRACT" "$PYTHON3" -c "
import gunicorn, fastapi, uvicorn
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from pydantic_core import core_schema
" 2>/dev/null; then
        echo "[startup] Pre-bundled packages ready — starting immediately (no pip install)"
        export PYTHONPATH="$BUNDLED_EXTRACT"
        exec "$PYTHON3" -m gunicorn main:app \
            --worker-class uvicorn.workers.UvicornWorker \
            --workers 1 \
            --bind 0.0.0.0:8000 \
            --timeout 300 \
            --graceful-timeout 60 \
            --max-requests 600 \
            --max-requests-jitter 150 \
            --log-file -
    fi
    echo "[startup] Bundled packages incomplete — falling through to antenv"
fi

# ── Fallback: persistent venv at /home/data/antenv (Azure Files) ──────────────
echo "[startup] No bundled packages — using /home/data/antenv (pip install on first run)"

ANTENV=/home/data/antenv
REQS=/home/site/wwwroot/requirements.txt
HASH_FILE=/home/data/.reqs_hash

mkdir -p /home/data

CURRENT_HASH=$(md5sum "$REQS" 2>/dev/null | cut -d' ' -f1 || echo "nohash")
STORED_HASH=$(cat "$HASH_FILE" 2>/dev/null || echo "none")

# Oryx sets PYTHONPATH to include wwwroot/antenv site-packages, which can make
# the import check AND pip both think packages are already present — causing
# the gunicorn binary to never be created. Clear PYTHONPATH in all checks.
venv_ok=false
if [ -x "$ANTENV/bin/gunicorn" ] && PYTHONPATH="" "$ANTENV/bin/python3" -c "import fastapi, gunicorn" 2>/dev/null; then
    venv_ok=true
fi

needs_install=false
if ! $venv_ok; then
    echo "[startup] antenv missing or broken — full install required"
    needs_install=true
elif [ "$CURRENT_HASH" != "$STORED_HASH" ]; then
    echo "[startup] requirements.txt changed — updating packages"
    needs_install=true
fi

if $needs_install; then
    if ! $venv_ok; then
        echo "[startup] Creating fresh venv at $ANTENV..."
        rm -rf "$ANTENV"
        "$PYTHON3" -m venv "$ANTENV"
    fi
    echo "[startup] Running pip install from requirements.txt..."
    PYTHONPATH="" "$ANTENV/bin/pip" install -r "$REQS" || {
        echo "[startup] Full install had errors — retrying without pymssql..."
        grep -v "^pymssql" "$REQS" > /tmp/reqs_filtered.txt
        PYTHONPATH="" "$ANTENV/bin/pip" install -r /tmp/reqs_filtered.txt || true
    }
    if [ ! -x "$ANTENV/bin/gunicorn" ]; then
        echo "[startup] gunicorn binary missing — force-installing gunicorn+uvicorn..."
        PYTHONPATH="" "$ANTENV/bin/pip" install "gunicorn>=21" "uvicorn[standard]>=0.24"
    fi
    echo "$CURRENT_HASH" > "$HASH_FILE"
    echo "[startup] Package install complete"
fi

echo "[startup] Starting gunicorn from antenv..."
exec "$ANTENV/bin/gunicorn" main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers 1 \
    --bind 0.0.0.0:8000 \
    --timeout 300 \
    --graceful-timeout 60 \
    --max-requests 600 \
    --max-requests-jitter 150 \
    --log-file -
