#!/bin/bash
set -e
cd /home/site/wwwroot

# /home/data/ is Azure Files persistent storage — survives zip-deploys.
# antenv inside wwwroot gets wiped every deployment; /home/data does not.
ANTENV=/home/data/antenv
REQS=/home/site/wwwroot/requirements.txt
HASH_FILE=/home/data/.reqs_hash

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

mkdir -p /home/data

CURRENT_HASH=$(md5sum "$REQS" 2>/dev/null | cut -d' ' -f1 || echo "nohash")
STORED_HASH=$(cat "$HASH_FILE" 2>/dev/null || echo "none")

# Oryx sets PYTHONPATH to include wwwroot/antenv site-packages, which can make
# the import check pass even when /home/data/antenv packages are missing.
# Clear PYTHONPATH before the check and also verify the binary exists.
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
        # Venv is broken/absent — delete and recreate
        echo "[startup] Creating fresh venv at $ANTENV..."
        rm -rf "$ANTENV"
        "$PYTHON3" -m venv "$ANTENV"
    fi
    # Clear PYTHONPATH so Oryx's wwwroot/antenv injection doesn't fool pip into
    # thinking packages are already installed (causing it to skip entry-point creation).
    echo "[startup] Running pip install from requirements.txt..."
    PYTHONPATH="" "$ANTENV/bin/pip" install -r "$REQS" || {
        echo "[startup] Full install had errors — retrying without pymssql..."
        grep -v "^pymssql" "$REQS" > /tmp/reqs_filtered.txt
        PYTHONPATH="" "$ANTENV/bin/pip" install -r /tmp/reqs_filtered.txt || true
    }
    # Explicit check: pip can skip entry-point creation if PYTHONPATH pollutes its view.
    if [ ! -x "$ANTENV/bin/gunicorn" ]; then
        echo "[startup] gunicorn binary missing — force-installing gunicorn+uvicorn..."
        PYTHONPATH="" "$ANTENV/bin/pip" install "gunicorn>=21" "uvicorn[standard]>=0.24"
    fi
    echo "$CURRENT_HASH" > "$HASH_FILE"
    echo "[startup] Package install complete"
fi

echo "[startup] Starting gunicorn..."
exec "$ANTENV/bin/gunicorn" main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers 1 \
    --bind 0.0.0.0:8000 \
    --timeout 300 \
    --graceful-timeout 60 \
    --max-requests 600 \
    --max-requests-jitter 150 \
    --log-file -
