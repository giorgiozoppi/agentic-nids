---
sidebar_position: 1
---

# Configuration

## Environment Variables

### LLM Provider (required — pick one)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # Claude (recommended)
export OPENAI_API_KEY="sk-..."          # GPT
```

`ANTHROPIC_API_KEY` takes priority when both are set. The collector exits with an error if neither is present.

### ClickHouse (optional — JSONL fallback if unset or unreachable)

```bash
export CLICKHOUSE_HOST=localhost      # default
export CLICKHOUSE_PORT=8123           # default
export CLICKHOUSE_DATABASE=nids       # default
export CLICKHOUSE_USERNAME=default    # default
export CLICKHOUSE_PASSWORD=""         # default
```

## YAML Configuration File

Default path: `config/nfstream_agent.yaml` (created with defaults on first run).

```yaml
# ── Timing ───────────────────────────────────────────────────────────────────
collection_interval: 180   # seconds between forced batch flushes
idle_timeout: 120          # flow idle expiry (seconds)
active_timeout: 1800       # max flow lifetime (seconds)
batch_size: 100            # flows per batch before processing

# ── Capture source (set one) ─────────────────────────────────────────────────
capture_interface: null    # e.g. eth0, wlan0
pcap_file: null            # e.g. /data/traffic.pcap

# ── Capture options ───────────────────────────────────────────────────────────
bpf_filter: null           # e.g. "tcp port 443"
promiscuous_mode: true
snapshot_length: 1536

# ── nDPI / nfstream ───────────────────────────────────────────────────────────
decode_tunnels: true
n_dissections: 20          # nDPI dissection passes
statistical_analysis: true # packet-size and IAT statistics
splt_analysis: 0           # early-termination packets (0 = disabled)
system_visibility_mode: 0  # process visibility (0 = off)
max_nflows: 0              # 0 = unlimited

# ── Payload capture ───────────────────────────────────────────────────────────
extract_payload: true
max_payload_bytes: 200     # per direction

# ── Output ────────────────────────────────────────────────────────────────────
flows_output_file: collected_flows.jsonl   # JSONL fallback / backup
log_file: null

# ── Performance ───────────────────────────────────────────────────────────────
stats_interval: 60
performance_report: 0

# ── LLM prompt override ───────────────────────────────────────────────────────
# Set to a path ending in .txt to load from file, or inline text,
# or null to use the built-in default prompt.
llm_prompt: null
```

## CLI Overrides

Key settings can be overridden at runtime without editing the YAML:

```bash
nfstream-collector \
  --config config/nfstream_agent.yaml \
  --interface eth0 \
  --interval 60 \
  --output flows.jsonl
```

## LLM Models

The model is selected when `LLMExplanationAgent` is created in `run_agent`. Default selections:

| Provider | Default Model |
|----------|--------------|
| Anthropic | `claude-sonnet-4-5` |
| OpenAI | `gpt-4o-mini` |

**Anthropic options:** `claude-sonnet-4-6`, `claude-opus-4-7`, `claude-haiku-4-5`  
**OpenAI options:** `gpt-4o-mini`, `gpt-4o`, `gpt-4`

## Custom LLM Prompt

Set `llm_prompt` in the YAML to override the default batch analysis prompt:

```yaml
llm_prompt: |
  You are a SOC analyst. Review the following flows and identify:
  1. Any port scans or reconnaissance activity
  2. Unusual data exfiltration patterns
  3. Known malicious application signatures

  Flows:
  {flows}
```

Use `{flows}` as a placeholder — it is replaced with the JSON-serialised batch at runtime.

Or point to an external file:

```yaml
llm_prompt: config/prompts/soc_analysis.txt
```
