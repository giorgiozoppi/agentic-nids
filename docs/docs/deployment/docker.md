---
sidebar_position: 2
---

# Docker Deployment

Deploy Agentic NIDS using Docker and Docker Compose.

## Docker Compose (Recommended)

### 1. Create `docker-compose.yml`

```yaml
version: '3.8'

services:
  nats:
    image: nats:2.10
    container_name: nids-nats
    ports:
      - "${NATS_PORT:-4222}:4222"
      - "8222:8222"
    environment:
      - NATS_URL=nats://nats:4222

  influxdb:
    image: influxdb:2.7
    container_name: nids-influxdb
    ports:
      - "${INFLUXDB_PORT:-8086}:8086"
    environment:
      - DOCKER_INFLUXDB_INIT_MODE=setup
      - DOCKER_INFLUXDB_INIT_USERNAME=admin
      - DOCKER_INFLUXDB_INIT_PASSWORD=${INFLUXDB_PASSWORD:-password123}
      - DOCKER_INFLUXDB_INIT_ORG=${INFLUXDB_ORG:-nids}
      - DOCKER_INFLUXDB_INIT_BUCKET=${INFLUXDB_BUCKET:-network_security}
      - DOCKER_INFLUXDB_INIT_RETENTION=${INFLUXDB_RETENTION:-7d}
    volumes:
      - influxdb-data:/var/lib/influxdb2

  classifier:
    build:
      context: .
      dockerfile: infra/docker/Dockerfile.classifier
    container_name: nids-classifier
    ports:
      - "${CLASSIFIER_PORT:-50051}:50051"
    environment:
      - NATS_URL=${NATS_URL:-nats://nats:4222}
    depends_on:
      - nats

  nids:
    build:
      context: .
      dockerfile: infra/docker/Dockerfile.all-in-one
    container_name: nids-app
    environment:
      - LLM_PROVIDER=${LLM_PROVIDER:-openai}
      - LLM_MODEL=${LLM_MODEL:-gpt-4o-mini}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - PAGERDUTY_ROUTING_KEY=${PAGERDUTY_ROUTING_KEY}
      - NATS_URL=${NATS_URL:-nats://nats:4222}
      - INFLUXDB_URL=${INFLUXDB_URL:-http://influxdb:8086}
      - INFLUXDB_ORG=${INFLUXDB_ORG:-nids}
      - INFLUXDB_BUCKET=${INFLUXDB_BUCKET:-network_security}
    depends_on:
      - nats
      - influxdb
      - classifier

volumes:
  influxdb-data:
```

### 2. Create `.env` File

```bash
# LLM Provider
LLM_PROVIDER=anthropic
LLM_MODEL=claude-opus-4-5

# API Keys
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
PAGERDUTY_ROUTING_KEY=R0...

# Service URLs (optional, use defaults)
NATS_URL=nats://nats:4222
INFLUXDB_URL=http://influxdb:8086

# InfluxDB Config
INFLUXDB_ORG=nids
INFLUXDB_BUCKET=network_security
INFLUXDB_PASSWORD=secure-password-here
INFLUXDB_RETENTION=30d

# Ports (optional)
NATS_PORT=4222
INFLUXDB_PORT=8086
CLASSIFIER_PORT=50051
```

### 3. Start Services

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Environment Variables

All configuration uses environment variables:

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `LLM_PROVIDER` | `openai` | No | LLM provider |
| `LLM_MODEL` | `gpt-4o-mini` | No | Model name |
| `OPENAI_API_KEY` | - | If provider=openai | OpenAI key |
| `ANTHROPIC_API_KEY` | - | If provider=anthropic | Anthropic key |
| `NATS_URL` | `nats://localhost:4222` | No | NATS server |
| `INFLUXDB_URL` | `http://localhost:8086` | No | InfluxDB server |
| `INFLUXDB_ORG` | `nids` | No | Organization |
| `INFLUXDB_BUCKET` | `network_security` | No | Bucket name |

## Next Steps

- [Kubernetes Deployment](./kubernetes) - Production deployment
- [Configuration](../guides/configuration) - Advanced configuration
