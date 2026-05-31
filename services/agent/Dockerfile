FROM python:3.12-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        libpcap0.8 \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY services/agent/pyproject.toml services/agent/uv.lock ./
RUN uv sync --no-dev --frozen

COPY services/agent/collector.py ./
COPY services/agent/config ./config

# NET_ADMIN + NET_RAW capabilities required in k8s for live capture.
ENTRYPOINT ["uv", "run", "nids-collector"]
