---
sidebar_position: 2
---

# Docker Deployment

The `agent/docker-compose.yml` starts NATS and ClickHouse for local
development and testing.

## `docker-compose.yml`

```yaml
services:
  nats:
    image: nats:2-alpine
    ports:
      - "4222:4222"
      - "8222:8222"   # monitoring UI

  clickhouse:
    image: clickhouse/clickhouse-server:24-alpine
    ports:
      - "8123:8123"   # HTTP interface
      - "9000:9000"   # native protocol
    volumes:
      - clickhouse_data:/var/lib/clickhouse
      - ./schema.sql:/docker-entrypoint-initdb.d/schema.sql:ro
    depends_on: [nats]

volumes:
  clickhouse_data:
```

ClickHouse runs `schema.sql` on first start and creates:

| Object | Type | Purpose |
|--------|------|---------|
| `nids.flows_nats` | NATS engine table | Live NATS subscription |
| `nids.flows_mv` | Materialized view | Routes rows to MergeTree |
| `nids.flows` | MergeTree | Persistent flow storage |
| `nids.security_events` | MergeTree | Threat detections |

## Common commands

```bash
# Start (idempotent)
cd agent
docker compose up -d

# Tail ClickHouse logs
docker compose logs -f clickhouse

# Query flows
docker compose exec clickhouse \
  clickhouse-client --query "SELECT count() FROM nids.flows"

# Query security events
docker compose exec clickhouse \
  clickhouse-client --query \
  "SELECT label, confidence, src_ip, dst_ip FROM nids.security_events ORDER BY detected_at DESC LIMIT 20"

# Stop and remove volumes
docker compose down -v
```

## E2E test

```bash
cd agent
bash start_test.sh
```

The script is fully idempotent: it kills any stale containers, starts fresh
infrastructure, injects attack PCAPs, validates row counts, and tears
everything down via an `EXIT` trap.

## Building the classifier image

```bash
cd services
docker build -f classifier/Dockerfile -t nids-classifier:latest .
```

The Dockerfile:
1. Compiles the Go binary with `CGO_ENABLED=1`
2. Downloads the ONNX Runtime shared library from GitHub releases
3. Produces a minimal `debian:bookworm-slim` image

Run locally (requires an ONNX model file):
```bash
docker run --rm \
  -v /path/to/models:/models \
  -p 50051:50051 \
  nids-classifier:latest \
    --model /models/classifier.onnx
```
