# Agentic NIDS — Architecture

## Overview

The ingestion pipeline captures network traffic with **NFStream**, publishes
completed flows to **NATS**, and persists every flow in **ClickHouse** for
analytical queries and dashboards.

```
┌──────────────────────────────────────────────────────────────────┐
│                     Ingestion Pipeline                           │
│                                                                  │
│  ┌─────────────────┐   batches (JSON)   ┌──────────────────┐    │
│  │  NFStream        │ ──────────────────▶│  NATS            │    │
│  │  Collector       │                   │  subject:        │    │
│  │  (nDPI + stats)  │                   │  nids.flows      │    │
│  └─────────────────┘                   └────────┬─────────┘    │
│                                                  │               │
│                                    ┌─────────────▼────────────┐ │
│                                    │  NATS→ClickHouse Bridge   │ │
│                                    │  (queue group ch-bridge)  │ │
│                                    └─────────────┬────────────┘ │
│                                                  │               │
│                                    ┌─────────────▼────────────┐ │
│                                    │  ClickHouse              │ │
│                                    │  nids.flows              │ │
│                                    └──────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘

                                    ┌──────────────────────────────┐
                                    │  ch-ui  (port 5521)          │
                                    │  ClickHouse web dashboard    │
                                    └──────────────────────────────┘
```

---

## Components

### 1. NFStream Collector (`nfstream_collector_agent.py`)

Captures packets from a **live interface** or a **PCAP file** and assembles
them into bidirectional network flows using the nfstream / nDPI engine.

When a batch is full (configurable `batch_size`) the collector serialises it
as a JSON array and publishes it to the NATS subject `nids.flows`.

**Features extracted per flow**

| Category           | Fields                                                          |
|--------------------|-----------------------------------------------------------------|
| Identification     | `flow_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` |
| Timing             | `bidirectional_first/last_seen_ms`, `duration`                  |
| Volume             | packets & bytes in both directions                              |
| Application layer  | `application_name`, `application_category_name` (nDPI)         |
| Statistical        | min/mean/stddev/max of packet sizes and inter-arrival times     |
| TCP flags          | SYN, ACK, PSH, RST, FIN counts                                  |
| Payload            | first 200 bytes per direction (base64, optional)               |

**Configuration** — `agent/config/nfstream_agent.yaml`

```yaml
capture_interface: eth0      # live capture
# pcap_file: /data/traffic.pcap  # offline analysis
batch_size: 100
nats_url:  nats://localhost:4222
nats_subject: nids.flows
```

**Run**

```bash
# PCAP
nfstream-collector --pcap traffic.pcap

# Live (requires root / NET_RAW)
sudo nfstream-collector --interface eth0

# List interfaces
nfstream-collector list-interfaces
```

---

### 2. NATS (`nats:2.10`)

Lightweight pub/sub broker. The collector publishes to `nids.flows`; the
bridge and any future consumers subscribe.

- **JetStream** can be enabled for persistent replay (`-js` flag, already set
  in docker-compose).
- Scale the bridge horizontally: all instances share the queue group
  `ch-bridge`, so NATS distributes messages across them.

**Ports**

| Port | Purpose                    |
|------|----------------------------|
| 4222 | Client connections         |
| 8222 | HTTP monitoring / healthz  |

---

### 3. NATS→ClickHouse Bridge (`nats_clickhouse_bridge.py`)

Subscribes to `nids.flows`, accumulates rows in an in-memory buffer, and
batch-inserts into **ClickHouse** every 5 seconds or when the buffer reaches
200 rows (both configurable).

- Runs as a **queue group** consumer (`ch-bridge`) — add more instances for
  higher throughput.
- Creates the `nids` database and `nids.flows` table automatically on first
  start.
- On insert failure, rows are re-queued and retried on the next flush.

**Environment variables**

| Variable               | Default                  | Description                     |
|------------------------|--------------------------|---------------------------------|
| `NATS_URL`             | `nats://localhost:4222`  | NATS connection string          |
| `NATS_SUBJECT`         | `nids.flows`             | Subject to subscribe            |
| `NATS_QUEUE_GROUP`     | `ch-bridge`              | Queue group name                |
| `CLICKHOUSE_HOST`      | `localhost`              | ClickHouse host                 |
| `CLICKHOUSE_PORT`      | `8123`                   | ClickHouse HTTP port            |
| `CLICKHOUSE_USER`      | `default`                |                                 |
| `CLICKHOUSE_PASSWORD`  | *(empty)*                |                                 |
| `BRIDGE_BATCH_SIZE`    | `200`                    | Rows before a forced flush      |
| `BRIDGE_FLUSH_INTERVAL`| `5.0`                    | Seconds between timed flushes   |

**Run**

```bash
nats-ch-bridge
```

---

### 4. ClickHouse (`clickhouse/clickhouse-server:24.3`)

Columnar OLAP database. All network flows land in `nids.flows`.

**Schema** — `agent/clickhouse_schema.sql`

```sql
CREATE TABLE nids.flows (
    collected_at  DateTime64(3),
    flow_id       String,
    src_ip        String,
    ...
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(collected_at)
ORDER BY (collected_at, src_ip, dst_ip, protocol)
TTL collected_at + INTERVAL 7 DAY;
```

Useful built-in views:

| View                    | Description                              |
|-------------------------|------------------------------------------|
| `nids.v_top_talkers`    | Highest-volume source IPs (last 1 hour)  |
| `nids.v_protocol_dist`  | Protocol breakdown (last 24 hours)       |

**Ports**

| Port | Purpose                   |
|------|---------------------------|
| 8123 | HTTP interface (default)  |
| 9000 | Native TCP interface      |

---

### 5. ch-ui (`ghcr.io/caioricciuti/ch-ui`)

Web-based ClickHouse dashboard. Open **http://localhost:5521** in a browser.

Connect with:
- **URL**: `http://localhost:8123` (or `http://clickhouse:8123` from within Docker)
- **User**: `default`
- **Password**: *(empty)*

Source: https://github.com/caioricciuti/ch-ui

---

## Data flow detail

```
packet
  │
  ▼ NFStream (nDPI + statistical analysis)
bidirectional flow record
  │
  ▼ _flow_to_dict()  →  JSON dict (40+ fields + collected_at UTC)
  │
  ▼ batch accumulation (batch_size rows)
  │
  ▼ NATS publish  →  subject: nids.flows  payload: JSON array
  │
  ▼ bridge _on_message()  →  _coerce() per row  →  in-memory buffer
  │
  ▼ periodic flush (BRIDGE_FLUSH_INTERVAL) or size threshold
  │
  ▼ clickhouse_connect  →  INSERT INTO nids.flows
```

---

## Deployment

### Local (Docker Compose)

```bash
# Offline — mount a PCAP file
PCAP_FILE=/path/to/traffic.pcap docker compose up

# Live capture (requires root)
CAPTURE_IFACE=eth0 docker compose up
```

Services started:

| Service    | URL / Port                     |
|------------|--------------------------------|
| NATS       | `nats://localhost:4222`        |
| NATS mon.  | http://localhost:8222          |
| ClickHouse | http://localhost:8123          |
| ch-ui      | http://localhost:5521          |

### Kubernetes (Helm)

See `infra/helm/agentic-nids/`. Update `values.yaml` to replace the InfluxDB
section with a ClickHouse StatefulSet (work in progress).

---

## Scaling

| Concern                  | Solution                                                        |
|--------------------------|-----------------------------------------------------------------|
| Higher ingest throughput | Run multiple bridge instances; NATS distributes via queue group |
| More capture sources     | Run multiple collectors on different interfaces/hosts           |
| Long-term storage        | Adjust `TTL` in `nids.flows` or add ClickHouse tiered storage   |
| ClickHouse HA            | ClickHouse Keeper + replicated tables (production deployment)   |

---

## Repository layout (ingestion components)

```
agent/
  nfstream_collector_agent.py   # NFStream producer
  nats_clickhouse_bridge.py     # NATS→ClickHouse bridge
  clickhouse_schema.sql         # DDL reference
  config/
    nfstream_agent.yaml         # collector configuration
  pyproject.toml                # dependencies + CLI entry points

infra/
  docker/
    Dockerfile.collector        # image for collector + bridge
  helm/
    agentic-nids/               # Kubernetes Helm chart

docker-compose.yml              # full local stack
```

---

*Last updated: 2026-05-23*
