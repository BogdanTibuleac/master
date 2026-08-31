ARG UV_VERSION=0.11.7
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

FROM python:3.12-slim-bookworm AS builder
COPY --from=uv /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /build

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --extra azure --no-editable

FROM python:3.12-slim-bookworm AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MALWARE_ARTIFACT_DIR=/app/artifacts \
    MALWARE_SCAN_DIR=/app/data/scans \
    MALWARE_MODEL_CACHE_DIR=/tmp/malware-model-cache

COPY --from=builder /opt/venv /opt/venv
RUN mkdir --parents /app/artifacts /app/data/scans /tmp/malware-model-cache \
    && chown --recursive app:app /app /tmp/malware-model-cache

WORKDIR /app
USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"]

CMD ["uvicorn", "malware_robustness.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips=*", "--no-server-header", "--timeout-keep-alive", "5", "--limit-concurrency", "20"]
