---
sidebar_position: 1
---

# Architecture Overview

## System diagram

```mermaid
graph TB
    subgraph "Capture layer"
        NET[Network traffic]
        COL[NFStream collector<br/>Python daemon]
        NET --> COL
    end

    subgraph "Transport layer"
        NATS[NATS broker<br/>subject: flows.raw<br/>format: MsgPack]
        COL -->|MsgPack publish| NATS
    end

    subgraph "Storage layer"
        NATS_TBL[nids.flows_nats<br/>NATS engine table]
        MV[Materialized view]
        FLOWS[nids.flows<br/>MergeTree — 90-day TTL]
        NATS -->|native subscribe| NATS_TBL
        NATS_TBL --> MV --> FLOWS
    end

    subgraph "Classification layer"
        ORCH[Orchestrator<br/>Go CronJob]
        CLF[Classifier<br/>Go gRPC service]
        SE[nids.security_events<br/>MergeTree]
        FLOWS -->|FetchFlows| ORCH
        ORCH -->|ClassifyBatch gRPC| CLF
        CLF -->|probabilities| ORCH
        ORCH -->|non-BENIGN events| SE
    end

    style COL fill:#e1f5ff
    style NATS fill:#fff9c4
    style FLOWS fill:#e8f5e9
    style CLF fill:#fff4e6
    style SE fill:#ffebee
```

## NFStream collector

**Technology**: nfstream + nDPI  
**Runs as**: Unix daemon (double-fork, PID file, rotating log)

- Captures from a live interface **or** replays a PCAP file.
- nDPI provides Layer-7 protocol detection and statistical features.
- Each completed flow is serialised with **MsgPack** and published to NATS subject `flows.raw`.
- Configurable via `config/config.yaml`; all fields are overridable with CLI flags.

Key features extracted per flow: 22 numeric values including packet/byte counts, inter-arrival times, TCP flag counts, and derived rates.

## NATS

ClickHouse subscribes to NATS **natively** via its NATS table engine. There is no separate Python consumer. The schema defines:

```
nids.flows_nats  (ENGINE = NATS, nats_format = 'MsgPack')
       │
       └──[Materialized view]──► nids.flows  (MergeTree, 90-day TTL)
```

## Classifier gRPC service {#classifier}

**Technology**: Go 1.22 + ONNX Runtime (`github.com/microsoft/onnxruntime-go`)

- Loads a pre-trained ONNX model at startup from `/models/classifier.onnx`.
- Exposes a single RPC: `ClassifyBatch([]FlowFeatures) → []ClassifyResponse`.
- Pre-allocates tensors for up to 256 flows per call; reshapes per actual batch size.
- Returns for each flow:
  - `label` — the predicted attack class (e.g. `"DoS"`, `"BENIGN"`)
  - `confidence` — probability of the predicted class
  - `probabilities` — full 8-class probability vector

### Attack classes

| Index | Label | Description |
|-------|-------|-------------|
| 0 | `BENIGN` | Normal traffic |
| 1 | `DoS` | Denial-of-Service |
| 2 | `DDoS` | Distributed DoS |
| 3 | `PortScan` | Port scanning |
| 4 | `BruteForce` | Credential guessing |
| 5 | `WebAttack` | SQL injection / XSS |
| 6 | `Botnet` | Bot-to-C2 traffic |
| 7 | `Malware` | Generic malware |

## Orchestrator (CronJob)

**Technology**: Go 1.22 + `github.com/ClickHouse/clickhouse-go/v2`  
**Schedule**: every 5 minutes (`*/5 * * * *`), `concurrencyPolicy: Forbid`

1. Loads a persisted RFC3339Nano timestamp from a PVC-backed `/state` directory (defaults to `now − 24 h` on first run).
2. Paginates `nids.flows WHERE collected_at > cursor ORDER BY collected_at ASC LIMIT 256`.
3. Sends each page to `ClassifyBatch`.
4. **Immediately after the gRPC response arrives**, inserts all non-BENIGN results into `nids.security_events` and logs each stored event (`attack`, `confidence`).
5. Advances the cursor to `max(collected_at)` of the page and saves state.

## Vault secret injection

All workloads (NATS, ClickHouse, collector, orchestrator, classifier) receive credentials via the **Vault Agent Injector**:

- Secrets live at `kv/data/nids/{clickhouse,nats,collector}` (KV-v2).
- Injected as files under `/vault/secrets/*.env` on each pod.
- TLS is self-managed via `AGENT_INJECT_TLS_AUTO`.

## Security model

- Collector pod runs with `NET_ADMIN` / `NET_RAW` capabilities and `hostNetwork: true` (required for packet capture).
- All other pods run unprivileged.
- No hardcoded credentials anywhere in manifests — all via Vault.

## Next steps

- [Workflow](./workflow) — step-by-step data flow
- [Data Models](./data-models) — ClickHouse schema details
- [Kubernetes Deployment](../deployment/kubernetes) — production setup
