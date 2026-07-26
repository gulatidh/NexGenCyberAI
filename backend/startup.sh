#!/bin/bash
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

# ── Fast path: pre-bundled packages shipped in the deployment zip ─────────────
# CI builds site-packages into .bundled-packages/ and includes it in backend.zip.
# These land in wwwroot (local disk, NOT Azure Files) so there is zero install
# time — the packages are already extracted by the time startup.sh runs.
# We invoke gunicorn via `python -m gunicorn` to avoid shebang path issues
# (the CI-built bin/ scripts reference the CI Python path, not Azure's).
BUNDLED=/home/site/wwwroot/.bundled-packages
if [ -d "$BUNDLED" ] && PYTHONPATH="$BUNDLED" "$PYTHON3" -c "import gunicorn, fastapi, uvicorn" 2>/dev/null; then
    echo "[startup] Pre-bundled packages found — starting immediately (no pip install)"
    exec PYTHONPATH="$BUNDLED" "$PYTHON3" -m gunicorn main:app \
        --worker-class uvicorn.workers.UvicornWorker \
        --workers 1 \
        --bind 0.0.0.0:8000 \
        --timeout 300 \
        --graceful-timeout 60 \
        --max-requests 600 \
        --max-requests-jitter 150 \
        --log-file -
fi

# ── Fallback: persistent venv at /home/data/antenv (Azure Files) ──────────────
# Used when deploying from a branch/commit that predates bundled packages,
# or if the bundled packages are somehow absent or broken.
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
