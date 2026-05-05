---
sidebar_position: 1
---

# Docker Deployment

## Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  clickhouse:
    image: clickhouse/clickhouse-server:latest
    container_name: nids-clickhouse
    ports:
      - "8123:8123"
      - "9000:9000"
    environment:
      CLICKHOUSE_DB: nids
      CLICKHOUSE_USER: nids_agent
      CLICKHOUSE_PASSWORD: ${CLICKHOUSE_PASSWORD:-changeme}
    volumes:
      - clickhouse-data:/var/lib/clickhouse
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8123/ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  nids:
    build:
      context: .
      dockerfile: infra/docker/Dockerfile.all-in-one
    container_name: nids-agent
    depends_on:
      clickhouse:
        condition: service_healthy
    environment:
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
      OPENAI_API_KEY:    ${OPENAI_API_KEY}
      CLICKHOUSE_HOST:     clickhouse
      CLICKHOUSE_PORT:     8123
      CLICKHOUSE_DATABASE: nids
      CLICKHOUSE_USERNAME: nids_agent
      CLICKHOUSE_PASSWORD: ${CLICKHOUSE_PASSWORD:-changeme}
    volumes:
      - ./agent/config:/app/config:ro
      - flows-output:/app/output
    # Uncomment for live capture:
    # network_mode: host
    # cap_add: [NET_RAW, NET_ADMIN]

volumes:
  clickhouse-data:
  flows-output:
```

## `.env` File

```bash
# Pick one LLM provider
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...

# ClickHouse
CLICKHOUSE_PASSWORD=strong-password-here
```

## Start and Inspect

```bash
# Start all services
docker-compose up -d

# Follow NIDS agent logs
docker-compose logs -f nids

# Follow ClickHouse logs
docker-compose logs -f clickhouse

# Stop
docker-compose down
```

## Analyse a PCAP File

Mount the PCAP and override the source:

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -e CLICKHOUSE_HOST=host.docker.internal \
  -v $(pwd)/capture.pcap:/data/capture.pcap:ro \
  nids-agent \
  nfstream-collector --pcap /data/capture.pcap --output /tmp/flows.jsonl
```

## Verify ClickHouse

```bash
# Check the schema was created
docker exec nids-clickhouse \
  clickhouse-client --query "SHOW TABLES FROM nids"

# Count stored flows
docker exec nids-clickhouse \
  clickhouse-client --query "SELECT count() FROM nids.flows"
```
