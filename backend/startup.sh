#!/bin/bash
set -e
cd /home/site/wwwroot

# /home/data/ is Azure Files persistent storage — survives zip-deploys.
# antenv inside wwwroot gets wiped every deployment; /home/data does not.
ANTENV=/home/data/antenv
PYTHON3=/opt/python/3.12.13/bin/python3
REQS=/home/site/wwwroot/requirements.txt
HASH_FILE=/home/data/antenv/.reqs_hash

mkdir -p /home/data

CURRENT_HASH=$(md5sum "$REQS" 2>/dev/null | cut -d' ' -f1)
STORED_HASH=$(cat "$HASH_FILE" 2>/dev/null || echo "none")

needs_install=false

if ! "$ANTENV/bin/python3" -c "import fastapi" 2>/dev/null; then
    echo "[startup] antenv missing or broken — full install required"
    needs_install=true
elif [ "$CURRENT_HASH" != "$STORED_HASH" ]; then
    echo "[startup] requirements.txt changed ($STORED_HASH → $CURRENT_HASH) — reinstalling"
    needs_install=true
fi

if $needs_install; then
    echo "[startup] Installing packages from requirements.txt (~4-6 min first time)..."
    rm -rf "$ANTENV"
    "$PYTHON3" -m venv "$ANTENV"
    # pymssql needs build tools; install it separately with a fallback so it
    # doesn't block the whole install (SQLite is used in this deployment).
    "$ANTENV/bin/pip" install -r "$REQS" -q --no-cache-dir \
        --extra-index-url https://pypi.org/simple/ || {
        echo "[startup] Full install failed — retrying without pymssql..."
        grep -v "^pymssql" "$REQS" > /tmp/reqs_filtered.txt
        "$ANTENV/bin/pip" install -r /tmp/reqs_filtered.txt -q --no-cache-dir
    }
    echo "$CURRENT_HASH" > "$HASH_FILE"
    echo "[startup] Package install complete"
fi

exec "$ANTENV/bin/gunicorn" main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers 1 \
    --bind 0.0.0.0:8000 \
    --timeout 300 \
    --graceful-timeout 60 \
    --max-requests 600 \
    --max-requests-jitter 150 \
    --log-file -
