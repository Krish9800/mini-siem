# Multi-stage rootless Dockerfile for Mini SIEM

# Stage 1: Build virtual environment
FROM python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml /app/
RUN pip install --upgrade pip && \
    pip install .

COPY src/ /app/src/
RUN pip install .

# Stage 2: Minimal unprivileged production runtime
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    SIEM_DATA_DIR="/data" \
    SIEM_DATABASE_URL="/data/siem.db"

# Create non-root system user and group (UID/GID 10001)
RUN groupadd -g 10001 siemgroup && \
    useradd -u 10001 -g siemgroup -s /sbin/nologin -d /app siemuser && \
    mkdir -p /data && \
    chown -R siemuser:siemgroup /app /data

COPY --from=builder --chown=siemuser:siemgroup /opt/venv /opt/venv
COPY --chown=siemuser:siemgroup src/ /app/src/

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health').read()" || exit 1

ENTRYPOINT ["mini-siem"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
