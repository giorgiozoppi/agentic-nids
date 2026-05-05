---
sidebar_position: 3
---

# Security

## API Key Management

- Store `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` in environment variables, not in YAML config or source code.
- Use `.env` files locally (add to `.gitignore`); use Kubernetes Secrets or a secrets manager in production.
- Rotate keys regularly; scope them to the minimum required permissions.

```bash
# .env (local dev only — never commit)
ANTHROPIC_API_KEY=sk-ant-...
CLICKHOUSE_PASSWORD=strong-password
```

## ClickHouse Access Control

Avoid using the `default` user in production. Create a scoped user:

```sql
CREATE USER nids_agent IDENTIFIED BY 'strong-password';
GRANT INSERT, SELECT ON nids.flows TO nids_agent;
-- Block DDL and system table access
```

Set `CLICKHOUSE_USERNAME=nids_agent` and `CLICKHOUSE_PASSWORD=strong-password`.

## Network Capture Privileges

Live capture requires `CAP_NET_RAW`. Grant it to the Python binary to avoid running as root:

```bash
sudo setcap cap_net_raw+eip $(which python3)

# Verify
getcap $(which python3)
# python3 = cap_net_raw+eip
```

For PCAP-only workflows, no elevated privileges are needed.

## Payload Handling

When `extract_payload: true`, base64-encoded payload bytes are stored in the JSONL fallback file. These may contain sensitive data — credentials in cleartext HTTP, session tokens, DNS queries.

If payload capture is not required for your use case:

```yaml
extract_payload: false
```

If you keep it enabled, restrict access to the output file:

```bash
chmod 600 collected_flows.jsonl
```

Payload fields are never written to ClickHouse by design.

## LLM Data Privacy

Flow metadata — IPs, hostnames, application names, byte counts, and TCP flags — is sent to the LLM provider API as part of the analysis prompt. Ensure this complies with your data classification policy.

Options for sensitive environments:

| Option | Notes |
|--------|-------|
| Anthropic / OpenAI DPA | Sign a Data Processing Agreement with your provider |
| Self-hosted model | Replace `ChatAnthropic`/`ChatOpenAI` with `ChatOllama` for air-gapped use |
| IP anonymisation | Hash or mask IPs before building the LLM prompt via a custom `llm_prompt` |

## ClickHouse Network Exposure

By default ClickHouse binds to all interfaces on ports 8123 (HTTP) and 9000 (native). In production:

```xml
<!-- /etc/clickhouse-server/config.d/network.xml -->
<clickhouse>
  <listen_host>127.0.0.1</listen_host>
</clickhouse>
```

Or use a firewall rule to restrict access to the NIDS host only.
