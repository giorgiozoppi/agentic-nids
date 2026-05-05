---
sidebar_position: 2
---

# Performance Tuning

## System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB | 100 GB (ClickHouse) |
| Network | 100 Mbps | 1 Gbps |

## Batch Size

`batch_size` in `nfstream_agent.yaml` is the primary tuning knob.

| Scenario | `batch_size` |
|----------|-------------|
| PCAP testing / debugging | 5–10 |
| Low-traffic network | 50 |
| High-traffic live capture | 100–200 |

Larger batches mean fewer LLM API calls but higher per-batch latency. Most models handle ~100 flows comfortably in a single prompt; beyond ~150, context window limits and response time become constraints.

## Batch Flush Triggers

The collector flushes a batch when **either** condition is met:

1. `len(batch) >= batch_size`
2. NFStream finishes (end-of-file for PCAP, or stream stopped)

There is no timer-based flush mid-capture; `collection_interval` controls how often NFStream reports idle flows.

## Disabling Expensive Features

```yaml
statistical_analysis: false  # skip packet-size and IAT stats
extract_payload: false        # skip PayloadExtractor plugin
n_dissections: 10             # reduce nDPI passes (still identifies most protocols)
splt_analysis: 0              # leave disabled unless you need early-termination features
```

## ClickHouse Tuning

```sql
-- Check table and partition sizes
SELECT
    partition,
    formatReadableSize(sum(bytes_on_disk)) AS disk_size,
    sum(rows) AS row_count
FROM system.parts
WHERE table = 'flows' AND database = 'nids' AND active
GROUP BY partition
ORDER BY partition DESC
LIMIT 10;

-- Shorten TTL if disk is tight
ALTER TABLE nids.flows MODIFY TTL collected_at + INTERVAL 7 DAY;

-- Force TTL cleanup
OPTIMIZE TABLE nids.flows FINAL;
```

For high-insert workloads (>10k flows/sec):
- Run ClickHouse on NVMe storage
- Increase `max_insert_block_size` in `config.xml`
- Use ClickHouse's built-in async insert buffer (`async_insert = 1`)

## LLM Latency

The `analyze_batch` node dominates end-to-end latency. Strategies:

| Strategy | Effect |
|----------|--------|
| Use `claude-haiku-4-5` or `gpt-4o-mini` | 2–3× faster, lower quality |
| Reduce `batch_size` | Faster per-batch, more total API calls |
| Shorten `llm_prompt` | Less input tokens → faster response |
| Disable ClickHouse | Removes `investigate_flows` tool; LLM analyses current batch only |

## LangGraph Retry Impact

Each LLM retry adds one full round-trip latency. With `_MAX_RETRIES = 3` and a 5 s LLM call, worst-case latency for a single batch is ~20 s. If your LLM provider is flaky, reduce retries:

```python
# agents/nids_graph.py
_MAX_RETRIES = 1   # fail fast
```
