FROM python:3.12-slim AS base

# libpcap-dev / libpcap0.8 — live packet capture (NFStream)
# libgomp1              — OpenMP runtime required by NFStream ML features
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        libpcap0.8 \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY services/agent/pyproject.toml services/agent/uv.lock ./
RUN uv sync --no-dev --frozen --no-install-project

ENV PATH="/app/.venv/bin:$PATH"

COPY services/agent/collector.py ./
RUN uv sync --no-dev --frozen
COPY services/agent/config ./config
COPY services/agent/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Runtime dirs for PID file and log file.
RUN mkdir -p /var/run /var/log

# Run as root: live capture requires CAP_NET_RAW / CAP_NET_ADMIN.
# In Kubernetes add those capabilities via securityContext instead of
# running privileged.
USER root

# Pass extra args (e.g. --interface eth0) via `docker run … <args>` or CMD override.
ENTRYPOINT ["docker-entrypoint.sh"]
