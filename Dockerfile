FROM node:24-alpine AS workspace-build
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
RUN npm test && npm run build

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/srv/backend \
    TRAIL_ENV=sandbox \
    TRAIL_DATA_STATUS=synthetic \
    TRAIL_LIVE_INTEGRATIONS=false \
    TRAIL_AUDIT_PATH=/data/audit.jsonl \
    TRAIL_PREAUTH_PATH=/data/preauth.sqlite \
    TRAIL_CORS_ORIGINS=http://localhost:8000 \
    TRAIL_DEPENDENCY_LOCK=/srv/requirements-py312.lock \
    TRAIL_BIND_HOST=127.0.0.1

WORKDIR /srv
COPY requirements-py312.lock ./requirements-py312.lock
RUN pip install --no-cache-dir -r requirements-py312.lock \
    && pip check \
    && sha256sum requirements-py312.lock > requirements-py312.lock.sha256 \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin trail \
    && mkdir -p /data \
    && chown trail:trail /data

# Only application source and the static console enter the image. The
# .dockerignore excludes local data, secrets, virtualenvs, and checkpoints.
COPY backend ./backend
COPY frontend/index.html frontend/earlytrace-replay.json ./frontend/
COPY --from=workspace-build /web/dist ./frontend/dist
RUN chown -R trail:trail /srv/backend /srv/frontend

USER trail
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"
CMD ["sh", "-c", "exec uvicorn app.main:app --host ${TRAIL_BIND_HOST:-127.0.0.1} --port 8000 --workers 1"]
