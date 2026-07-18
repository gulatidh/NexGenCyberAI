#!/bin/bash
set -e
cd /home/site/wwwroot

ANTENV=/home/site/wwwroot/antenv
PYTHON3=/opt/python/3.12.13/bin/python3

CORE_PACKAGES=(
    "fastapi==0.115.12"
    "uvicorn==0.34.0"
    "gunicorn==23.0.0"
    "sqlalchemy==2.0.40"
    "azure-identity==1.25.3"
    "azure-mgmt-authorization==4.0.0"
    "azure-mgmt-sql==3.0.1"
    "azure-mgmt-web==7.3.1"
    "azure-mgmt-containerservice==32.0.0"
    "azure-mgmt-containerregistry==10.3.0"
    "azure-mgmt-loganalytics==13.1.0"
    "google-cloud-asset==4.3.0"
    "google-cloud-securitycenter==1.44.0"
    "langchain==1.2.17"
    "langchain-openai==1.2.1"
    "langchain-community==0.4.1"
)

if ! $ANTENV/bin/python3 -c "import fastapi" 2>/dev/null; then
    echo "[startup] antenv missing or broken — installing core packages (~4 min)..."
    rm -rf $ANTENV
    $PYTHON3 -m venv $ANTENV
    $ANTENV/bin/pip install "${CORE_PACKAGES[@]}" \
        -q --no-cache-dir
    echo "[startup] Core install complete — app will start; background features load on first use"
elif ! $ANTENV/bin/python3 -c "import azure.identity; import langchain; import google.cloud.asset_v1; import azure.mgmt.sql; import azure.mgmt.web; import azure.mgmt.containerservice; import azure.mgmt.containerregistry; import azure.mgmt.loganalytics" 2>/dev/null; then
    echo "[startup] Some packages missing — targeted install..."
    $ANTENV/bin/pip install "${CORE_PACKAGES[@]}" \
        -q --no-cache-dir
    echo "[startup] Targeted install complete"
fi

exec $ANTENV/bin/gunicorn main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers 1 \
    --bind 0.0.0.0:8000 \
    --timeout 300 \
    --graceful-timeout 60 \
    --max-requests 600 \
    --max-requests-jitter 150 \
    --log-file -
