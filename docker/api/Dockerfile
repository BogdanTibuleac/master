# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONSAFEPATH=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --gid 10001 aegis && useradd --uid 10001 --gid 10001 --create-home aegis

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --upgrade pip && python -m pip install ".[runtime]"

RUN mkdir -p /app/data/raw /app/data/scans /app/data/quarantine /app/data/results /app/artifacts \
    && chown -R aegis:aegis /app

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "malware_robustness.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

