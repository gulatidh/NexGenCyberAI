# ── Stage 1: Build React frontend ────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci --silent
COPY frontend/ ./

ARG REACT_APP_API_URL=http://localhost:8080/api/v1
ARG REACT_APP_CLIENT_ID
ARG REACT_APP_TENANT_ID
ARG REACT_APP_REDIRECT_URI=http://localhost:8080

ENV REACT_APP_API_URL=$REACT_APP_API_URL \
    REACT_APP_CLIENT_ID=$REACT_APP_CLIENT_ID \
    REACT_APP_TENANT_ID=$REACT_APP_TENANT_ID \
    REACT_APP_REDIRECT_URI=$REACT_APP_REDIRECT_URI

RUN npm run build

# ── Stage 2: Python backend ───────────────────────────────────────────────────
FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev curl && rm -rf /var/lib/apt/lists/*

# Strip pymssql (requires freetds-dev; not needed for SQLite-only Docker builds)
COPY backend/requirements.txt ./
RUN grep -v pymssql requirements.txt > requirements_docker.txt && \
    pip install --no-cache-dir -r requirements_docker.txt

COPY backend/ ./

# Copy built React app
COPY --from=frontend-builder /build/frontend/build ./frontend_build

# Persistent data directory (mounted as Docker volume)
RUN mkdir -p /app/data

ENV SERVE_FRONTEND=true \
    DATABASE_URL=sqlite:////app/data/nexgencyberai.db \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
