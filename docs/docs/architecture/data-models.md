---
sidebar_position: 2
---

# Data Models

## ClickHouse schema

All tables live in the `nids` database.

### `nids.flows_nats` — NATS ingestion table

```sql
CREATE TABLE nids.flows_nats (
    collected_at             String,
    flow_id                  String,
    src_ip                   String,
    dst_ip                   String,
    src_port                 UInt16,
    dst_port                 UInt16,
    protocol                 UInt8,
    ip_version               UInt8,
    bidirectional_first_seen_ms  UInt64,
    bidirectional_last_seen_ms   UInt64,
    bidirectional_duration_ms    UInt64,
    bidirectional_packets    UInt32,
    bidirectional_bytes      UInt64,
    src2dst_packets          UInt32,
    src2dst_bytes            UInt64,
    dst2src_packets          UInt32,
    dst2src_bytes            UInt64,
    application_name         String,
    application_category_name String,
    application_is_guessed   UInt8,
    application_confidence   Float32,
    requested_server_name    String,
    packets_per_second       Float64,
    bytes_per_second         Float64,
    -- statistical features
    bidirectional_min_ps     Float32,
    bidirectional_mean_ps    Float32,
    bidirectional_stddev_ps  Float32,
    bidirectional_max_ps     Float32,
    bidirectional_min_piat_ms    Float32,
    bidirectional_mean_piat_ms   Float32,
    bidirectional_stddev_piat_ms Float32,
    bidirectional_max_piat_ms    Float32,
    bidirectional_syn_packets    UInt32,
    bidirectional_ack_packets    UInt32,
    bidirectional_psh_packets    UInt32,
    bidirectional_rst_packets    UInt32,
    bidirectional_fin_packets    UInt32
)
ENGINE = NATS
SETTINGS
    nats_url      = 'nats://nats:4222',
    nats_subjects = 'flows.raw',
    nats_format   = 'MsgPack';
```

### `nids.flows` — persistent flow storage

MergeTree table partitioned by month, TTL 90 days. Same columns as
`flows_nats` but `collected_at` is `DateTime` (converted by the
materialized view). Populated automatically via `nids.flows_mv`.

### `nids.security_events` — threat detections

Written by the orchestrator immediately after each gRPC `ClassifyBatch` response.
Only non-BENIGN results are inserted.

```sql
CREATE TABLE nids.security_events (
    event_id              UUID    DEFAULT generateUUIDv4(),
    detected_at           DateTime DEFAULT now(),
    flow_id               String,
    src_ip                String,
    dst_ip                String,
    src_port              UInt16,
    dst_port              UInt16,
    protocol              UInt8,
    label                 LowCardinality(String),   -- attack class
    confidence            Float32,                  -- P(label)
    probabilities         String,                   -- JSON: all 8 class probs
    bidirectional_packets UInt32,
    bidirectional_bytes   UInt64,
    bidirectional_duration_ms UInt64
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(detected_at)
ORDER BY (detected_at, label, src_ip);
```

## ONNX model feature vector

The classifier expects exactly **22 float32 features** in this order:

| # | Feature |
|---|---------|
| 1 | `bidirectional_duration_ms` |
| 2 | `bidirectional_packets` |
| 3 | `bidirectional_bytes` |
| 4 | `src2dst_packets` |
| 5 | `dst2src_packets` |
| 6 | `src2dst_bytes` |
| 7 | `dst2src_bytes` |
| 8 | `packets_per_second` |
| 9 | `bytes_per_second` |
| 10 | `bidirectional_min_ps` |
| 11 | `bidirectional_mean_ps` |
| 12 | `bidirectional_stddev_ps` |
| 13 | `bidirectional_max_ps` |
| 14 | `bidirectional_min_piat_ms` |
| 15 | `bidirectional_mean_piat_ms` |
| 16 | `bidirectional_stddev_piat_ms` |
| 17 | `bidirectional_max_piat_ms` |
| 18 | `bidirectional_syn_packets` |
| 19 | `bidirectional_ack_packets` |
| 20 | `bidirectional_psh_packets` |
| 21 | `bidirectional_rst_packets` |
| 22 | `bidirectional_fin_packets` |

## gRPC messages

Defined in `proto/classifier.proto`:

```protobuf
message FlowFeatures {
  string flow_id = 1;
  // ... 22 feature fields ...
}

message ClassifyResponse {
  string flow_id      = 1;
  string label        = 2;   // attack class name
  float  confidence   = 3;   // probability of predicted class
  repeated float probabilities = 4;  // all 8 class probabilities
}
```

## Collector NATS payload

The Python collector publishes each flow as a **MsgPack** binary blob.
Example (after decoding):

```python
{
  "collected_at": "2026-05-23T10:05:01.123456Z",
  "flow_id": "192.168.1.5-10.0.0.1-54321-443-6",
  "src_ip": "192.168.1.5",
  "dst_ip": "10.0.0.1",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": 6,
  "bidirectional_duration_ms": 1502,
  "bidirectional_packets": 14,
  "bidirectional_bytes": 8192,
  # ... statistical features ...
  "bidirectional_syn_packets": 1,
  "bidirectional_fin_packets": 1
}
```
