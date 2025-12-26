---
sidebar_position: 1
---

# Quick Start Guide

Get your Agentic NIDS up and running in 5 minutes!

## Prerequisites

- Python 3.11+
- Docker (optional)
- Kubernetes cluster (optional for production)

## Local Development Setup

### 1. Install Dependencies

```bash
cd agent
pip install -e ".[all]"
```

### 2. Set Environment Variables

Choose your LLM provider:

**Option A: OpenAI (GPT-4)**
```bash
export OPENAI_API_KEY="sk-your-openai-key"
```

**Option B: Anthropic (Claude Opus)**
```bash
export ANTHROPIC_API_KEY="sk-ant-your-anthropic-key"
export LLM_PROVIDER="anthropic"
export LLM_MODEL="claude-opus-4-5"
```

**Optional Services:**
```bash
# PagerDuty (optional)
export PAGERDUTY_ROUTING_KEY="R0xxxxxxxxxxxxx"

# InfluxDB (defaults to http://localhost:8086)
export INFLUXDB_URL="http://localhost:8086"
export INFLUXDB_TOKEN="your-influxdb-token"
export INFLUXDB_ORG="nids"
export INFLUXDB_BUCKET="network_security"

# NATS (defaults to nats://localhost:4222)
export NATS_URL="nats://localhost:4222"
```

### 3. Run Quick Test

```bash
python main.py --mode test
```

**Expected Output:**
```
[INFO] Starting classifier agent on port 50051
[INFO] Classifier agent initialized
[INFO] LLM Explanation Agent initialized with Anthropic claude-opus-4-5

✓  [1/20] 192.168.1.100 -> 10.0.0.50     | normal     | risk: low      | conf: 0.85
⚠️ [2/20] 192.168.1.101 -> 203.0.113.45 | MALICIOUS  | risk: high     | conf: 0.87
    └─ Port scan detected with high confidence...

Test Summary: 6/20 malicious flows detected
```

## Docker Quick Start

### 1. Build Docker Image

```bash
docker build -t agentic-nids -f infra/docker/Dockerfile.all-in-one .
```

### 2. Run Container

```bash
docker run -it --rm \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -e PAGERDUTY_ROUTING_KEY=$PAGERDUTY_ROUTING_KEY \
  -e INFLUXDB_URL=http://host.docker.internal:8086 \
  -p 50051:50051 \
  agentic-nids
```

## Kubernetes Quick Start

### 1. Create Namespace

```bash
kubectl create namespace nids
```

### 2. Create Secrets

```bash
kubectl create secret generic agentic-nids-secrets \
  --from-literal=openaiApiKey=$OPENAI_API_KEY \
  --from-literal=anthropicApiKey=$ANTHROPIC_API_KEY \
  --from-literal=pagerdutyRoutingKey=$PAGERDUTY_ROUTING_KEY \
  --from-literal=influxdbToken=$(openssl rand -base64 32) \
  --from-literal=influxdbPassword=$(openssl rand -base64 32) \
  -n nids
```

### 3. Install Helm Chart

```bash
helm install agentic-nids ./infra/helm/agentic-nids \
  --namespace nids \
  --set llm.provider=anthropic \
  --set llm.model=claude-opus-4-5
```

### 4. Verify Deployment

```bash
kubectl get pods -n nids
kubectl get svc -n nids
```

## Configuration Options

### LLM Provider Selection

**OpenAI Models:**
- `gpt-4o`: Latest GPT-4 Omni
- `gpt-4o-mini`: Cost-effective option
- `gpt-4`: Standard GPT-4
- `gpt-3.5-turbo`: Fastest, cheapest

**Anthropic Models:**
- `claude-opus-4-5`: Most capable (recommended)
- `claude-sonnet-4-5`: Balanced performance/cost
- `claude-haiku-4`: Fastest, most cost-effective

### Collection Interval

Edit `agent/config/ndpi_agent.yaml`:
```yaml
collection_interval: 180  # 3 minutes (default)
# Or:
collection_interval: 60   # 1 minute (more frequent)
```

### Alert Threshold

```yaml
alert_threshold: 0.7  # 70% confidence (default)
```

## Next Steps

- [Architecture Overview](../architecture/overview) - Understand the system
- [Deployment Guide](../deployment/kubernetes) - Production deployment
- [Configuration](../guides/configuration) - Advanced configuration
- [API Reference](../api/agents) - Agent APIs

## Troubleshooting

### LLM Provider Not Working

```bash
# Verify API key is set
echo $OPENAI_API_KEY
echo $ANTHROPIC_API_KEY

# Test API key
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-opus-4-5","max_tokens":10,"messages":[{"role":"user","content":"test"}]}'
```

### NATS Connection Failed

```bash
# Start NATS server
docker run -d --name nats -p 4222:4222 nats:2.10

# Verify connection
nc -zv localhost 4222
```

### InfluxDB Not Available

```bash
# Start InfluxDB
docker run -d --name influxdb \
  -p 8086:8086 \
  -e DOCKER_INFLUXDB_INIT_MODE=setup \
  -e DOCKER_INFLUXDB_INIT_USERNAME=admin \
  -e DOCKER_INFLUXDB_INIT_PASSWORD=password123 \
  -e DOCKER_INFLUXDB_INIT_ORG=nids \
  -e DOCKER_INFLUXDB_INIT_BUCKET=network_security \
  influxdb:2.7

# Get token
docker exec influxdb influx auth list --json | jq -r '.[0].token'
```
