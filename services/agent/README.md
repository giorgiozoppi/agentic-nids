# NIDS Collector

NFStream-based network flow collector that captures packets from a live interface or a PCAP file, converts them into flow records, and publishes each flow as a MsgPack message to a NATS subject.

A lightweight HTTP API (FastAPI/uvicorn) runs alongside the collector and exposes health, readiness, and state endpoints.

## Requirements

| Requirement | Version |
|---|---|
| Python | ≥ 3.12 |
| [uv](https://github.com/astral-sh/uv) | latest |
| libpcap | system package |

Live capture requires root (or `CAP_NET_RAW` + `CAP_NET_ADMIN`).

Install system dependencies on Debian/Ubuntu:

```sh
sudo apt-get install libpcap-dev libpcap0.8 libgomp1
```

---

## Quick start

### 1. Install Python dependencies

```sh
make build
# or: uv sync
```

### 2. List available network interfaces

```sh
uv run nids-collector --list-interfaces
```

### 3. Run (live capture)

```sh
sudo -E uv run nids-collector --interface eth0
# or via Make (uses $CAPTURE_INTERFACE by default):
make run INTERFACE=eth0
```

### 4. Run (PCAP replay)

```sh
uv run nids-collector --pcap traffic.pcap
```

No root is required for PCAP replay.

---

## Configuration

Settings are resolved in priority order: **CLI flags > environment variables > `config/config.yaml`**.

### `config/config.yaml`

```yaml
nats:
  url: "nats://localhost:4222"
  subject: "flows.raw"

capture:
  interface: eth0          # live capture interface
  pcap_file: null          # path to a .pcap file (overrides interface)
  bpf_filter: null         # e.g. "tcp or udp"
  snapshot_length: 65535
  promiscuous_mode: true
  decode_tunnels: true
  n_dissections: 20
  statistical_analysis: true
  splt_analysis: 0
  idle_timeout: 120        # seconds
  active_timeout: 1800     # seconds

status:
  port: 8080

logging:
  level: debug             # debug | info | warning | error
```

When `logging.level` is `debug` (the default), each published flow is printed to the log with its 5-tuple, application name, packet count, and byte count.

### Environment variables (ConfigMap-friendly)

| Variable | Config key |
|---|---|
| `NATS_URL` | `nats.url` |
| `NATS_SUBJECT` | `nats.subject` |
| `CAPTURE_INTERFACE` | `capture.interface` |
| `CAPTURE_PCAP_FILE` | `capture.pcap_file` |
| `COLLECTOR_STATUS_PORT` | `status.port` |
| `LOG_LEVEL` | `logging.level` |

---

## CLI reference

```
Usage: nids-collector [OPTIONS]

  Collect network flows with NFStream and publish to NATS.

Options:
  -c, --config PATH          Config file  [default: config/config.yaml]
  -i, --interface TEXT       Live capture interface (requires root)
  -p, --pcap PATH            PCAP file
      --nats-url TEXT         NATS server URL
  -s, --subject TEXT         NATS subject
      --status-port INT       HTTP state API port  [default: 8080]
  -d, --daemon               Run as Unix daemon
      --pid-file TEXT         PID file path  [default: /var/run/nids-collector.pid]
      --log-file TEXT         Log file (daemon mode)  [default: /var/log/nids-collector.log]
      --list-interfaces       List available interfaces and exit
```

---

## HTTP API

The status server starts on `--status-port` (default `8080`).

| Endpoint | Description |
|---|---|
| `GET /health` | Liveness probe — 200 when running or stopping |
| `GET /readiness` | Readiness probe — 503 if NATS is disconnected |
| `GET /startup` | Startup probe — 503 while still initialising |
| `GET /state` | Full internal state (counters, uptime, queue size) |
| `GET /state/flows?limit=N` | Last N published flows (max 100), newest first |
| `GET /docs` | Swagger UI |

---

## Docker

### Build

The Docker context must be the **repository root** (two levels up), because the Dockerfile copies from `services/agent/`:

```sh
make docker
# or manually:
docker build -f Dockerfile -t nids-collector:latest ../..
```

### Run

Live capture needs host networking and packet-capture capabilities:

```sh
docker run --rm \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -e CAPTURE_INTERFACE=eth0 \
  nids-collector:latest \
  --interface eth0
```

```sh
# or via Make:
make docker-run INTERFACE=eth0
```

---

## Docker Compose

Starts NATS (with JetStream) and the collector together:

```sh
# Edit CAPTURE_INTERFACE in docker-compose.yml first, then:
docker compose up
```

The collector connects to NATS on the host network. The HTTP API is available at `http://localhost:8080`.

To tail flow output:

```sh
docker compose logs -f collector
```

---

## Tests

```sh
make test
# or: uv run pytest
```

---

## Makefile targets

| Target | Description |
|---|---|
| `make build` | Install / sync dependencies (`uv sync`) |
| `make test` | Run the test suite |
| `make run INTERFACE=eth0` | Run collector in the foreground |
| `make docker` | Build Docker image |
| `make docker-run INTERFACE=eth0` | Run collector in a container |
