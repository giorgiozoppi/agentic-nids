---
sidebar_position: 3
---

# Data Models

## Network Flow Dict

Every NFStream `NFlow` is converted to a Python dict by `_nflow_to_dict()`.

### Core Fields (always present)

| Field | Type | Description |
|-------|------|-------------|
| `flow_id` | `str` | `"src:port->dst:port:proto"` |
| `src_ip` / `dst_ip` | `str` | Endpoint IP addresses |
| `src_port` / `dst_port` | `int` | Endpoint ports |
| `protocol` | `str` | `TCP`, `UDP`, `ICMP`, … |
| `ip_version` | `int` | `4` or `6` |
| `bidirectional_first_seen_ms` | `int` | Flow start (epoch ms) |
| `bidirectional_last_seen_ms` | `int` | Flow end (epoch ms) |
| `bidirectional_duration_ms` | `int` | Duration (ms) |
| `duration` | `float` | Duration (seconds) |
| `bidirectional_packets` | `int` | Total packets (both directions) |
| `bidirectional_bytes` | `int` | Total bytes (both directions) |
| `src2dst_packets` / `dst2src_packets` | `int` | Directional packet counts |
| `src2dst_bytes` / `dst2src_bytes` | `int` | Directional byte counts |
| `application_name` | `str` | nDPI application (e.g. `HTTPS`) |
| `application_category_name` | `str` | nDPI category (e.g. `Web`) |
| `application_confidence` | `float` | nDPI confidence score |
| `requested_server_name` | `str` | SNI / hostname |
| `packets_per_second` | `float` | Derived rate |
| `bytes_per_second` | `float` | Derived rate |

### Statistical Fields (`statistical_analysis: true`)

| Field | Type |
|-------|------|
| `bidirectional_min_ps` / `_mean_ps` / `_stddev_ps` / `_max_ps` | `float` |
| `bidirectional_min_piat_ms` / `_mean_piat_ms` / `_stddev_piat_ms` / `_max_piat_ms` | `float` |
| `bidirectional_syn_packets` / `_ack_packets` / `_psh_packets` / `_rst_packets` / `_fin_packets` | `int` |

### Payload Fields (`extract_payload: true`)

| Field | Type | Description |
|-------|------|-------------|
| `src2dst_payload` | `str` | Base64-encoded first N bytes (src→dst) |
| `dst2src_payload` | `str` | Base64-encoded first N bytes (dst→src) |
| `src2dst_payload_size` | `int` | Captured byte count |
| `dst2src_payload_size` | `int` | Captured byte count |
| `payload_packets_captured` | `int` | Packets that had a Raw layer |

:::note
Payload fields are intentionally excluded from ClickHouse. They are large and available in the JSONL fallback file if needed.
:::

## LangGraph Batch State

```python
class NIDSBatchState(TypedDict):
    flows: List[Dict]                          # slice of flow dicts above
    prompt: str                                # assembled LLM prompt
    llm_analysis: Optional[Dict]               # {"anomalies": [], "summary": str}
    errors: Annotated[List[str], operator.add] # appended per node
    retry_count: int
```

## ClickHouse Schema

```sql
CREATE TABLE nids.flows (
    collected_at              DateTime64(3, 'UTC'),
    flow_id                   String,
    src_ip                    String,
    dst_ip                    String,
    src_port                  UInt16,
    dst_port                  UInt16,
    protocol                  LowCardinality(String),
    ip_version                UInt8,
    duration_ms               UInt64,
    duration_s                Float64,
    bidirectional_packets     UInt64,
    bidirectional_bytes       UInt64,
    src2dst_packets           UInt64,
    src2dst_bytes             UInt64,
    dst2src_packets           UInt64,
    dst2src_bytes             UInt64,
    application_name          LowCardinality(String),
    application_category_name LowCardinality(String),
    application_confidence    Float32,
    requested_server_name     String,
    packets_per_second        Float64,
    bytes_per_second          Float64,
    bidirectional_syn_packets UInt32,
    bidirectional_rst_packets UInt32,
    bidirectional_fin_packets UInt32,
    llm_summary               String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(collected_at)
ORDER BY (collected_at, src_ip, dst_ip)
TTL collected_at + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;
```

**Design notes:**
- `LowCardinality(String)` on `protocol`, `application_name`, `application_category_name` reduces storage and speeds up `GROUP BY`
- Partitioned by day — queries scoped to a time range skip entire partitions
- 30-day TTL keeps the table bounded in production (adjust with `ALTER TABLE … MODIFY TTL`)
- `llm_summary` stores the LLM's free-text threat analysis alongside each row in the batch
