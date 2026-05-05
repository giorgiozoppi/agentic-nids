---
sidebar_position: 3
---

# Monitoring

## Log Output

The NIDS agent logs at `DEBUG` level by default. Key patterns to watch:

| Log message | Meaning |
|-------------|---------|
| `✓ NFStreamer created successfully` | Capture started |
| `Flow #N` + JSON | Individual flow captured |
| `Batch full (N flows) - processing...` | LangGraph invoked |
| `LLM batch analysis completed` | Analysis succeeded |
| `Retrying LLM analysis (attempt N/3)` | Transient LLM failure |
| `Inserted N flows into ClickHouse` | Storage write OK |
| `ClickHouse unavailable — JSONL fallback` | Storage degraded |
| `Batch done — LLM summary: ...` | Full batch cycle complete |

## ClickHouse Health Checks

```bash
# HTTP ping
curl http://localhost:8123/ping
# → Ok.

# Row count
curl "http://localhost:8123/?query=SELECT+count()+FROM+nids.flows"

# Disk usage per partition
curl "http://localhost:8123/?query=SELECT+partition,formatReadableSize(sum(bytes_on_disk))+FROM+system.parts+WHERE+table%3D'flows'+AND+database%3D'nids'+GROUP+BY+partition+ORDER+BY+partition+DESC+LIMIT+7"
```

## Collector Statistics

Printed on shutdown and accessible via `agent.get_statistics()`:

```
══════════════════════════════════════════
NFStream Collector Agent Statistics
══════════════════════════════════════════
Uptime:           3600s (60.0 minutes)
Flows collected:  3600 (1.00/sec)
Flows saved:      3600
Output file:      collected_flows.jsonl
══════════════════════════════════════════
```

## Grafana + ClickHouse Plugin

Install the [ClickHouse Grafana datasource](https://grafana.com/grafana/plugins/grafana-clickhouse-datasource/) and point it at `nids`.

### Flows per minute

```sql
SELECT toStartOfMinute(collected_at) AS time, count() AS flows
FROM nids.flows
WHERE $__timeFilter(collected_at)
GROUP BY time ORDER BY time;
```

### Top source IPs

```sql
SELECT src_ip, count() AS flows
FROM nids.flows
WHERE $__timeFilter(collected_at)
GROUP BY src_ip ORDER BY flows DESC LIMIT 10;
```

### Application breakdown

```sql
SELECT application_name, count() AS flows
FROM nids.flows
WHERE $__timeFilter(collected_at)
GROUP BY application_name ORDER BY flows DESC;
```

### Batches flagged by LLM

```sql
SELECT collected_at, src_ip, dst_ip, llm_summary
FROM nids.flows
WHERE llm_summary != '' AND $__timeFilter(collected_at)
ORDER BY collected_at DESC;
```
