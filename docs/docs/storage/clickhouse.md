---
sidebar_position: 1
---

# ClickHouse Storage

**File:** `agent/agents/storage/clickhouse_store.py`

## Overview

`ClickHouseFlowStore` is the primary storage backend. It uses the official [clickhouse-connect](https://clickhouse.com/docs/en/integrations/python) HTTP client and bootstraps the `nids.flows` table automatically on first connection.

## Connection

Parameters are read from environment variables at startup:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLICKHOUSE_HOST` | `localhost` | ClickHouse server hostname |
| `CLICKHOUSE_PORT` | `8123` | HTTP interface port |
| `CLICKHOUSE_DATABASE` | `nids` | Database name |
| `CLICKHOUSE_USERNAME` | `default` | Username |
| `CLICKHOUSE_PASSWORD` | `""` | Password |

```bash
export CLICKHOUSE_HOST=clickhouse.internal
export CLICKHOUSE_PORT=8123
export CLICKHOUSE_DATABASE=nids
export CLICKHOUSE_USERNAME=nids_agent
export CLICKHOUSE_PASSWORD=secret
```

If the connection fails, the collector logs a warning and falls back to JSONL output.

## Schema

Created automatically by `_ensure_schema()`:

```sql
CREATE TABLE IF NOT EXISTS nids.flows (
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

## Write API

### `insert_flows(flows, llm_summary="")`

Batch-inserts a list of flow dicts. The `llm_summary` (from `state["llm_analysis"]["summary"]`) is stored alongside every row in the batch.

```python
store.insert_flows(batch, llm_summary="Port scan detected from 10.0.0.5...")
```

Payload fields (`src2dst_payload`, `dst2src_payload`) are intentionally excluded — they are large and available in the JSONL fallback file when needed.

## Read API

Used by the [Deep Search Agent](../agents/deep-search) tools. All queries use parameterised placeholders.

### `search_by_ip(ip, limit=50)`

Returns the most recent flows where `src_ip` or `dst_ip` matches.

```python
flows = store.search_by_ip("10.0.0.5")
# [{"flow_id": "...", "src_ip": "10.0.0.5", "application_name": "HTTPS", ...}, ...]
```

### `search_by_port(port, limit=50)`

Returns flows where `src_port` or `dst_port` matches.

### `search_by_application(app_name, limit=50)`

Case-insensitive partial match on `application_name`.

```python
store.search_by_application("dns")   # matches DNS, mDNS, DoT, etc.
```

### `get_top_talkers(minutes=60, limit=10)`

Top source IPs ranked by bytes transferred in the last N minutes.

```json
[
  {"src_ip": "10.0.0.5", "flow_count": 1240, "total_bytes": 8192000, "total_packets": 9600},
  {"src_ip": "10.0.0.12", "flow_count": 430, "total_bytes": 1048576, "total_packets": 3200}
]
```

### `get_flow_statistics(src_ip=None, minutes=60)`

Aggregate statistics for the time window. Optionally filter by source IP.

```json
{
  "total_flows": 4200,
  "total_bytes": 52428800,
  "avg_pps": 14.3,
  "rst_flows": 18,
  "half_open_flows": 7
}
```

`half_open_flows` counts flows with `bidirectional_syn_packets > 0` but `dst2src_packets = 0` (unanswered SYN — potential port scan).

## Docker Quick Start

```bash
docker run -d \
  --name clickhouse \
  -p 8123:8123 -p 9000:9000 \
  -e CLICKHOUSE_DB=nids \
  clickhouse/clickhouse-server:latest
```

## Useful Ad-Hoc Queries

```sql
-- Latest 100 flows
SELECT collected_at, src_ip, dst_ip, application_name, bidirectional_bytes
FROM nids.flows
ORDER BY collected_at DESC
LIMIT 100;

-- Flows with LLM threat summaries
SELECT collected_at, src_ip, dst_ip, llm_summary
FROM nids.flows
WHERE llm_summary != ''
ORDER BY collected_at DESC
LIMIT 20;

-- Top applications by traffic (last hour)
SELECT application_name, count() AS flows, sum(bidirectional_bytes) AS bytes
FROM nids.flows
WHERE collected_at >= now() - INTERVAL 1 HOUR
GROUP BY application_name
ORDER BY bytes DESC;

-- Potential port scans: many RSTs, few responses
SELECT src_ip, dst_ip, bidirectional_syn_packets, bidirectional_rst_packets
FROM nids.flows
WHERE bidirectional_rst_packets > 10
ORDER BY collected_at DESC
LIMIT 50;

-- Adjust TTL (e.g. keep only 7 days)
ALTER TABLE nids.flows MODIFY TTL collected_at + INTERVAL 7 DAY;
```
