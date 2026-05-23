---
sidebar_position: 1
---

# Agentic NIDS

A network intrusion detection system that captures live traffic with **NFStream**, streams enriched flows over **NATS**, stores them in **ClickHouse**, and classifies threats with a Go **gRPC** microservice backed by an **ONNX** model.

## Pipeline overview

```
Network traffic
      │
      ▼
 NFStream collector   ← Python daemon — nDPI deep-packet inspection
      │  MsgPack
      ▼
    NATS               ← message broker  (subject: flows.raw)
      │
      ▼
 ClickHouse            ← NATS engine table → materialized view → MergeTree
      │
      ▼
 Orchestrator          ← Go CronJob — paginates flows, calls classifier
      │  gRPC
      ▼
 Classifier service    ← Go microservice — ONNX Runtime inference
      │
      ▼
 security_events       ← ClickHouse table (non-BENIGN flows only)
```

## Attack classes

The ONNX model outputs probabilities for eight classes. Only non-BENIGN
results are written to `nids.security_events`.

| Label | Description |
|-------|-------------|
| `BENIGN` | Normal traffic — filtered out, not stored |
| `DoS` | Denial-of-Service flood |
| `DDoS` | Distributed Denial-of-Service |
| `PortScan` | Port/host scanning |
| `BruteForce` | Credential brute-force (SSH, FTP, …) |
| `WebAttack` | SQL injection, XSS, command injection |
| `Botnet` | Bot-to-C2 communication |
| `Malware` | Generic malware traffic |

## Components

| Component | Language | Role |
|-----------|----------|------|
| `agent/collector.py` | Python | NFStream → NATS publisher (Unix daemon) |
| `services/classifier` | Go | gRPC server wrapping ONNX model |
| `services/orchestrator` | Go | K8s CronJob — ClickHouse reader + event writer |
| `infra/k8s` | YAML / Kustomize | NATS, ClickHouse, Vault, workload manifests |

## Quick start (local)

```bash
cd agent
docker compose up -d   # starts NATS + ClickHouse
bash start_test.sh     # injects sample PCAPs and validates flow counts
```

See [Quick Start](./getting-started/quick-start) for step-by-step instructions.
