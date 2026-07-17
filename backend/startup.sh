#!/bin/bash
set -e
cd /home/site/wwwroot

ANTENV=/home/site/wwwroot/antenv
PYTHON3=/opt/python/3.12.13/bin/python3

if ! $ANTENV/bin/python3 -c "import fastapi" 2>/dev/null; then
    echo "[startup] fastapi missing — rebuilding antenv..."
    rm -rf $ANTENV
    $PYTHON3 -m venv $ANTENV
    $ANTENV/bin/pip install -r /home/site/wwwroot/requirements.txt -q --no-cache-dir
    echo "[startup] Full pip install complete"
elif ! $ANTENV/bin/python3 -c "import azure.identity; import langchain; import google.cloud.asset_v1" 2>/dev/null; then
    echo "[startup] Some packages missing — targeted install..."
    $ANTENV/bin/pip install \
        "azure-identity==1.25.3" \
        "azure-mgmt-authorization==4.0.0" \
        "google-cloud-asset==4.3.0" \
        "google-cloud-securitycenter==1.44.0" \
        "langchain==1.2.17" \
        "langchain-openai==1.2.1" \
        "langchain-community==0.4.1" \
        -q --no-cache-dir
    echo "[startup] Targeted install complete"
fi

exec $ANTENV/bin/gunicorn main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers 2 \
    --bind 0.0.0.0:8000 \
    --timeout 300 \
    --graceful-timeout 60 \
    --max-requests 600 \
    --max-requests-jitter 150 \
    --log-file -
