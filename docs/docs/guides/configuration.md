---
sidebar_position: 1
---

# Configuration Guide

## Collector (`agent/config/config.yaml`)

```yaml
nats:
  url: "nats://localhost:4222"   # NATS broker address
  subject: "flows.raw"           # publishing subject

capture:
  interface: null          # network interface (null = use --pcap)
  pcap_file: null          # PCAP replay path  (null = live capture)
  bpf_filter: null         # BPF filter expression, e.g. "tcp port 443"
  idle_timeout: 120        # seconds — expire idle flows
  active_timeout: 1800     # seconds — max flow lifetime
  decode_tunnels: true
  n_dissections: 20
  statistical_analysis: true   # enables packet-size & inter-arrival stats
  splt_analysis: 0
  promiscuous_mode: true
  snapshot_length: 1536
```

Override any key with a CLI flag:
```bash
nids-collector \
  --interface eth0 \
  --nats-url nats://10.0.0.5:4222 \
  --config /etc/nids/config.yaml
```

Run `nids-collector --help` for the full flag list.

## Classifier service

Flags accepted by the `classifier` binary (or K8s args):

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `:50051` | gRPC listen address |
| `--model` | `/models/classifier.onnx` | ONNX model path |
| `--ort-lib` | `/usr/lib/libonnxruntime.so` | ORT shared library path |
| `--input-name` | `float_input` | ONNX input tensor name |
| `--output-name` | `probabilities` | ONNX output tensor name |

## Orchestrator

Flags accepted by the `orchestrator` binary:

| Flag | Default | Description |
|------|---------|-------------|
| `--state-dir` | `/state` | Directory for cursor state file |
| `--ch-addr` | `clickhouse.nids.svc.cluster.local:9000` | ClickHouse native address |
| `--ch-db` | `nids` | ClickHouse database |
| `--ch-user` | `default` | ClickHouse username |
| `--ch-password` | `` | ClickHouse password |
| `--classifier-addr` | `classifier.nids.svc.cluster.local:50051` | Classifier gRPC address |
| `--batch-size` | `256` | Flows per gRPC call (also ONNX batch size) |
| `--limit` | `10000` | Max flows processed per CronJob run |

## Vault secrets

Secrets are stored in KV-v2 at `kv/nids/<component>`. Default keys:

### `kv/nids/clickhouse`
```
username = default
password = <generated>
```

### `kv/nids/nats`
```
username = nids
password = <generated>
```

### `kv/nids/collector`
```
nats_url = nats://nats.nids.svc.cluster.local:4222
interface = eth0
```

Update a secret:
```bash
vault kv put kv/nids/clickhouse username=admin password=mysecret
```

Pods pick up the new value after the Vault Agent lease expires (default ~1 minute). Restart the pod to force immediate refresh.

## CronJob schedule

Edit `infra/k8s/orchestrator-cronjob.yaml`:

```yaml
schedule: "*/5 * * * *"   # default: every 5 minutes
```

Standard cron syntax. `concurrencyPolicy: Forbid` ensures only one run at
a time — safe to reduce the interval if needed.
