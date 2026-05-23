---
sidebar_position: 1
---

# Quick Start

## Prerequisites

- Python 3.11+
- Docker + Docker Compose
- `libpcap-dev` (for live capture): `apt-get install libpcap-dev`

## Local development (Docker Compose)

### 1. Start infrastructure

```bash
cd agent
docker compose up -d
```

This starts:
- **NATS** on port 4222 (management UI on 8222)
- **ClickHouse** on ports 8123 (HTTP) and 9000 (native)

ClickHouse automatically creates the `nids` database, NATS engine table,
materialized view, and `security_events` table via `schema.sql`.

### 2. Install the collector

```bash
cd agent
pip install -e .
```

### 3. Replay a PCAP file

```bash
nids-collector --pcap data/normal.pcap --nats-url nats://localhost:4222
```

### 4. Verify flows landed in ClickHouse

```bash
docker exec -it agent-clickhouse-1 \
  clickhouse-client --query "SELECT count() FROM nids.flows"
```

### 5. Run the full E2E test

```bash
cd agent
bash start_test.sh
```

The test script:
- Spins up Docker Compose (idempotent)
- Waits until ClickHouse is ready
- Replays 12 PCAPs (normal + attack scenarios) and validates row counts
- Runs a ClickHouse end-to-end insert check
- Tears down all containers at the end

## Live capture (daemon mode)

```bash
# Run as a daemon (double-fork, POSIX)
sudo nids-collector \
  --interface eth0 \
  --nats-url nats://localhost:4222 \
  --daemon \
  --pid-file /var/run/nids-collector.pid \
  --log-file /var/log/nids-collector.log
```

Stop it:
```bash
kill $(cat /var/run/nids-collector.pid)
```

### Systemd service

```bash
sudo cp agent/nids-collector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nids-collector
```

## Collector configuration

`agent/config/config.yaml`:

```yaml
nats:
  url: "nats://localhost:4222"
  subject: "flows.raw"

capture:
  interface: null          # set to interface name for live capture
  pcap_file: null          # set to path for PCAP replay
  idle_timeout: 120        # seconds — flow idle expiry
  active_timeout: 1800     # seconds — max flow duration
  statistical_analysis: true
  promiscuous_mode: true
```

All keys can be overridden with CLI flags — run `nids-collector --help` for
the full list.

## Available attack PCAPs

Pre-extracted in `data/`:

| File | Traffic type |
|------|-------------|
| `normal.pcap` | Benign baseline traffic |
| `synscan.pcap` | nmap SYN port scan |
| `malware.pcap` | Malware C2 communication |
| `WebattackSQLinj.pcap` | SQL injection |
| `WebattackXSS.pcap` | XSS attack |
| `dos_win98_smb_netbeui.pcap` | SMB DoS flood |
| `ftp_failed.pcap` | FTP brute-force |
| `ssh.pcap` | SSH session |
| `smtp-starttls.pcap` | SMTP with STARTTLS |

## Next steps

- [Architecture Overview](../architecture/overview) — understand the system
- [Kubernetes Deployment](../deployment/kubernetes) — production setup
- [Configuration](../guides/configuration) — advanced options
