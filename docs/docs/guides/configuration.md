---
sidebar_position: 1
---

# Configuration Guide

## Environment Variables

```bash
# LLM Provider
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# NATS Message Broker
NATS_URL=nats://localhost:4222

# InfluxDB
INFLUXDB_URL=http://localhost:8086
INFLUXDB_TOKEN=your-token
INFLUXDB_ORG=agentic-nids
INFLUXDB_BUCKET=network-flows

# PagerDuty
PAGERDUTY_API_KEY=your-api-key
PAGERDUTY_INTEGRATION_KEY=your-integration-key
```

## Agent Configuration

Configuration files for each agent component.
