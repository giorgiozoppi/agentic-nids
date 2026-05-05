---
sidebar_position: 1
---

# Quick Start

## Prerequisites

- Python ≥ 3.12
- An Anthropic or OpenAI API key
- ClickHouse (optional — collector falls back to JSONL)

## 1. Install

```bash
cd agent
pip install -e .
```

## 2. Set Environment Variables

Pick one LLM provider:

```bash
# Anthropic Claude (recommended)
export ANTHROPIC_API_KEY="sk-ant-..."

# — or — OpenAI GPT
export OPENAI_API_KEY="sk-..."
```

ClickHouse connection (optional — uses these defaults):

```bash
export CLICKHOUSE_HOST=localhost      # default: localhost
export CLICKHOUSE_PORT=8123           # default: 8123
export CLICKHOUSE_DATABASE=nids       # default: nids
export CLICKHOUSE_USERNAME=default    # default: default
export CLICKHOUSE_PASSWORD=""         # default: (empty)
```

## 3. Start ClickHouse (Docker)

```bash
docker run -d \
  --name clickhouse \
  -p 8123:8123 -p 9000:9000 \
  clickhouse/clickhouse-server:latest
```

The `nids` database and `flows` table are created automatically on first run.

## 4. Analyse a PCAP File

```bash
nfstream-collector --pcap path/to/capture.pcap
```

## 5. Live Capture

```bash
# List available interfaces
nfstream-collector list-interfaces

# Capture on eth0 (requires root / CAP_NET_RAW)
sudo nfstream-collector --interface eth0
```

## CLI Reference

```
nfstream-collector [OPTIONS] [COMMAND]

Commands:
  list-interfaces    Print available network interfaces and exit

Options:
  -c, --config PATH    YAML config file  [default: config/nfstream_agent.yaml]
  -i, --interface TEXT Live capture interface (e.g. eth0)
  -p, --pcap PATH      PCAP file to process
  -t, --interval INT   Collection interval in seconds
  -o, --output TEXT    JSONL output file path
```

## What Happens on Startup

```
STEP 1  Load YAML config (or write defaults)
STEP 2  Apply CLI overrides
STEP 3  Validate network interface (if live capture)
STEP 4  Connect to ClickHouse  →  warn + JSONL fallback if unavailable
STEP 5  Create NFStreamCollectorAgent
STEP 6  Config summary printed to log
STEP 7  Initialise LLM agent  →  exit if no API key found
STEP 8  Start flow collection loop
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ERROR: No LLM API key found!` | Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` |
| `ClickHouse unavailable — JSONL fallback` | Check `CLICKHOUSE_HOST`/port, or start ClickHouse |
| No flows from PCAP | Run `capinfos capture.pcap` to verify the file |
| `Permission denied` on live interface | Run with `sudo` or grant `CAP_NET_RAW` to Python |

## Next Steps

- [Configuration](../guides/configuration) — all YAML and env var options
- [Architecture](../architecture/overview) — understand the pipeline
- [ClickHouse Storage](../storage/clickhouse) — query your collected flows
