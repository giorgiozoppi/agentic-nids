---
sidebar_position: 1
---

# NFStream Collector Agent

**File:** `agent/nfstream_collector_agent.py`

## Overview

`NFStreamCollectorAgent` is the entry point of the NIDS pipeline. It uses [nfstream](https://www.nfstream.org/) — which embeds [nDPI](https://www.ntop.org/products/deep-packet-inspection/ndpi/) — to capture network flows from a live interface or a PCAP file, extract 30+ statistical and application-layer features per flow, accumulate them into configurable batches, and hand each batch to the [LangGraph workflow](../architecture/workflow).

## Key Classes

### `PayloadExtractor` (NFStream Plugin)

An `NFPlugin` subclass that captures the first `max_payload_bytes` of raw payload per direction during the flow lifecycle. Payload is stored as `bytes` in `flow.udps` and later base64-encoded in the flow dict.

```python
plugin = PayloadExtractor(max_payload_bytes=200)
```

### `NFStreamAgentConfig`

Loaded from a YAML file via `NFStreamAgentConfig.from_yaml(path)`. All fields have sensible defaults.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `batch_size` | `100` | Flows per batch |
| `collection_interval` | `180` | Seconds between forced flushes |
| `idle_timeout` | `120` | Flow idle expiry (s) |
| `active_timeout` | `1800` | Max flow lifetime (s) |
| `capture_interface` | `null` | Live interface (e.g. `eth0`) |
| `pcap_file` | `null` | PCAP file path |
| `bpf_filter` | `null` | Berkeley Packet Filter expression |
| `promiscuous_mode` | `true` | Capture all frames |
| `snapshot_length` | `1536` | Snap length (bytes) |
| `n_dissections` | `20` | nDPI dissection passes |
| `statistical_analysis` | `true` | Packet-size and IAT stats |
| `splt_analysis` | `0` | Early-termination packets (0 = off) |
| `extract_payload` | `true` | Enable `PayloadExtractor` |
| `max_payload_bytes` | `200` | Max payload bytes per direction |
| `flows_output_file` | `collected_flows.jsonl` | JSONL fallback path |
| `llm_prompt` | `null` | Override the default analysis prompt |

### `NFStreamCollectorAgent`

#### `__init__(config, clickhouse_store=None)`

Creates the agent. `clickhouse_store` is an optional `ClickHouseFlowStore` injected at startup time.

#### `collect_flows(llm_agent=None)`

Main async collection loop. Iterates over NFStream flows, converts each to a dict, accumulates batches, and calls `_process_batch` when `batch_size` is reached. Processes any remaining flows when the stream ends.

#### `_process_batch(batch, llm_agent)`

Assembles the LLM prompt (using `config.llm_prompt` or a built-in default), then calls `nids_graph.ainvoke(...)` with the batch and graph configurables.

#### `stop()`

Clears the global `Event`, causing the collection loop to exit after the current flow.

#### `print_statistics()` / `get_statistics()`

Prints or returns uptime, flows collected, flows saved, and rates.

## Feature Extraction

`_nflow_to_dict()` extracts the following from every `NFlow`:

```
Core:         flow_id, src_ip, dst_ip, src_port, dst_port, protocol, ip_version
Timing:       bidirectional_{first,last}_seen_ms, bidirectional_duration_ms, duration
Volume:       bidirectional_{packets,bytes}, src2dst_{packets,bytes}, dst2src_{packets,bytes}
Application:  application_name, application_category_name, application_confidence,
              requested_server_name
Rates:        packets_per_second, bytes_per_second

Statistical (if enabled):
  Packet size:  bidirectional_{min,mean,stddev,max}_ps
  IAT:          bidirectional_{min,mean,stddev,max}_piat_ms
  TCP flags:    bidirectional_{syn,ack,psh,rst,fin}_packets

Payload (if enabled):
  src2dst_payload, dst2src_payload  (base64)
  src2dst_payload_size, dst2src_payload_size, payload_packets_captured
```

## CLI

```bash
# List interfaces
nfstream-collector list-interfaces

# Analyse a PCAP file
nfstream-collector --pcap traffic.pcap

# Live capture
sudo nfstream-collector --interface eth0

# Custom config + output
nfstream-collector --pcap traffic.pcap \
  --config config/nfstream_agent.yaml \
  --output flows.jsonl
```

## YAML Example

```yaml
# config/nfstream_agent.yaml
collection_interval: 60
batch_size: 10
capture_interface: null
pcap_file: null
statistical_analysis: true
extract_payload: true
max_payload_bytes: 200
flows_output_file: collected_flows.jsonl
n_dissections: 20
```
