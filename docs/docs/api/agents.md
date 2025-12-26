---
sidebar_position: 1
---

# Agent APIs

## Packet Capture Agent

Captures network traffic and extracts flow features.

### Configuration

```python
capture_config = {
    "interface": "eth0",
    "filter": "tcp or udp",
    "max_flows": 10000
}
```

## Classification Agent

Performs ML-based threat detection using XGBoost models.

### API Endpoint

```
POST /classify
Content-Type: application/json

{
  "flow_features": [...]
}
```

## LLM Explanation Agent

Generates human-readable threat explanations.

### API Endpoint

```
POST /explain
Content-Type: application/json

{
  "flow_data": {...},
  "prediction": "malicious",
  "confidence": 0.95
}
```
