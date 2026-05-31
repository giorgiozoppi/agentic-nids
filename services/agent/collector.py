#!/usr/bin/env python3
"""
NFStream → NATS collector (Unix daemon) with HTTP state API.

Reads network flows with NFStream (live interface or PCAP) and publishes
each completed flow as a MsgPack message to a NATS subject.

A lightweight FastAPI server runs on --status-port (default 8080) and exposes:
  GET /health  — liveness check
  GET /state   — full internal state as JSON

Run as daemon:
    sudo nids-collector --daemon --interface eth0

Run in foreground:
    nids-collector --interface eth0
    nids-collector --pcap traffic.pcap
"""

import asyncio
import collections
import dataclasses
import logging
import logging.handlers
import queue
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

RECENT_FLOWS_MAX = 20

import msgpack
import nats
import psutil
import yaml
from fastapi import FastAPI
from nfstream import NFStreamer

logger = logging.getLogger(__name__)

DEFAULT_PID_FILE = "/var/run/nids-collector.pid"
DEFAULT_LOG_FILE = "/var/log/nids-collector.log"
DEFAULT_STATUS_PORT = 8080


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class CollectorState:
    """Mutable snapshot of collector runtime state, read by the HTTP API."""

    status: str = "starting"       # starting | running | stopping | stopped
    started_at: str = ""           # ISO-8601 UTC
    capture_source: str = ""       # interface name or pcap path
    nats_url: str = ""
    nats_subject: str = ""
    nats_connected: bool = False
    flows_published: int = 0
    publish_errors: int = 0
    last_flow_at: str = ""         # ISO-8601 UTC of the last published flow

    def __post_init__(self) -> None:
        # Not dataclass fields — never appear in asdict() output.
        self._flow_queue: Optional[queue.Queue] = None
        # LRU ring buffer of the last RECENT_FLOWS_MAX published flow summaries.
        self._recent_flows: collections.deque = collections.deque(maxlen=RECENT_FLOWS_MAX)

    def record_flow(self, flow_dict: dict) -> None:
        """Append a compact summary of a published flow to the LRU buffer."""
        self._recent_flows.append({
            "collected_at":           flow_dict.get("collected_at", ""),
            "flow_id":                flow_dict.get("flow_id", ""),
            "src_ip":                 flow_dict.get("src_ip", ""),
            "dst_ip":                 flow_dict.get("dst_ip", ""),
            "src_port":               flow_dict.get("src_port", 0),
            "dst_port":               flow_dict.get("dst_port", 0),
            "protocol":               flow_dict.get("protocol", 0),
            "application_name":       flow_dict.get("application_name", ""),
            "bidirectional_packets":  flow_dict.get("bidirectional_packets", 0),
            "bidirectional_bytes":    flow_dict.get("bidirectional_bytes", 0),
            "bidirectional_duration_ms": flow_dict.get("bidirectional_duration_ms", 0),
            "packets_per_second":     round(flow_dict.get("packets_per_second", 0.0), 2),
            "bytes_per_second":       round(flow_dict.get("bytes_per_second", 0.0), 2),
        })

    def as_dict(self) -> dict:
        d = dataclasses.asdict(self)
        now = datetime.now(timezone.utc)
        if self.started_at:
            started = datetime.fromisoformat(self.started_at)
            uptime = (now - started).total_seconds()
            d["uptime_seconds"] = round(uptime, 1)
            d["flows_per_second"] = (
                round(self.flows_published / uptime, 2) if uptime > 0 else 0.0
            )
        else:
            d["uptime_seconds"] = 0.0
            d["flows_per_second"] = 0.0
        d["queue_size"] = self._flow_queue.qsize() if self._flow_queue is not None else 0
        d["recent_flows"] = list(self._recent_flows)
        return d


# ---------------------------------------------------------------------------
# FastAPI app — routes close over the module-level singleton
# ---------------------------------------------------------------------------

_state = CollectorState()
api = FastAPI(title="NIDS Collector", version="1.0.0")


@api.get("/health")
async def health():
    ok = _state.status in ("running", "stopping")
    return {"status": "ok" if ok else "degraded", "collector_status": _state.status}


@api.get("/state")
async def get_state():
    return _state.as_dict()


@api.get("/state/flows")
async def get_recent_flows():
    """Return the last up-to-20 published flow summaries (newest last)."""
    return {"recent_flows": list(_state._recent_flows)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_config(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _apply_env_overrides(cfg: dict) -> None:
    """Overlay NATS/capture settings from environment variables (ConfigMap-friendly).

    Env vars take precedence over the config file but are overridden by explicit
    CLI flags.  Variable names match standard Kubernetes ConfigMap conventions:
      NATS_URL, NATS_SUBJECT, CAPTURE_INTERFACE, CAPTURE_PCAP_FILE,
      COLLECTOR_STATUS_PORT
    """
    import os

    nats = cfg.setdefault("nats", {})
    cap = cfg.setdefault("capture", {})
    status = cfg.setdefault("status", {})

    if v := os.environ.get("NATS_URL"):
        nats["url"] = v
    if v := os.environ.get("NATS_SUBJECT"):
        nats["subject"] = v
    if v := os.environ.get("CAPTURE_INTERFACE"):
        cap["interface"] = v
    if v := os.environ.get("CAPTURE_PCAP_FILE"):
        cap["pcap_file"] = v
    if v := os.environ.get("COLLECTOR_STATUS_PORT"):
        status["port"] = int(v)


def flow_to_dict(flow, statistical: bool) -> dict:
    dur_s = flow.bidirectional_duration_ms / 1000.0 if flow.bidirectional_duration_ms > 0 else 0.0
    d = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "flow_id": f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}:{flow.protocol}",
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "ip_version": flow.ip_version,
        "bidirectional_first_seen_ms": flow.bidirectional_first_seen_ms,
        "bidirectional_last_seen_ms": flow.bidirectional_last_seen_ms,
        "bidirectional_duration_ms": flow.bidirectional_duration_ms,
        "bidirectional_packets": flow.bidirectional_packets,
        "bidirectional_bytes": flow.bidirectional_bytes,
        "src2dst_packets": flow.src2dst_packets,
        "src2dst_bytes": flow.src2dst_bytes,
        "dst2src_packets": flow.dst2src_packets,
        "dst2src_bytes": flow.dst2src_bytes,
        "application_name": flow.application_name,
        "application_category_name": flow.application_category_name,
        "application_is_guessed": int(flow.application_is_guessed),
        "application_confidence": getattr(flow, "application_confidence", 0),
        "requested_server_name": getattr(flow, "requested_server_name", ""),
        "packets_per_second": flow.bidirectional_packets / dur_s if dur_s > 0 else 0.0,
        "bytes_per_second": flow.bidirectional_bytes / dur_s if dur_s > 0 else 0.0,
    }
    if statistical:
        d.update({
            "bidirectional_min_ps": getattr(flow, "bidirectional_min_ps", 0.0),
            "bidirectional_mean_ps": getattr(flow, "bidirectional_mean_ps", 0.0),
            "bidirectional_stddev_ps": getattr(flow, "bidirectional_stddev_ps", 0.0),
            "bidirectional_max_ps": getattr(flow, "bidirectional_max_ps", 0.0),
            "bidirectional_min_piat_ms": getattr(flow, "bidirectional_min_piat_ms", 0.0),
            "bidirectional_mean_piat_ms": getattr(flow, "bidirectional_mean_piat_ms", 0.0),
            "bidirectional_stddev_piat_ms": getattr(flow, "bidirectional_stddev_piat_ms", 0.0),
            "bidirectional_max_piat_ms": getattr(flow, "bidirectional_max_piat_ms", 0.0),
            "bidirectional_syn_packets": getattr(flow, "bidirectional_syn_packets", 0),
            "bidirectional_ack_packets": getattr(flow, "bidirectional_ack_packets", 0),
            "bidirectional_psh_packets": getattr(flow, "bidirectional_psh_packets", 0),
            "bidirectional_rst_packets": getattr(flow, "bidirectional_rst_packets", 0),
            "bidirectional_fin_packets": getattr(flow, "bidirectional_fin_packets", 0),
        })
    return d


def _stream_to_queue(streamer: NFStreamer, q: queue.Queue, stop: threading.Event):
    try:
        for flow in streamer:
            if stop.is_set():
                break
            q.put(flow)
    finally:
        q.put(None)  # sentinel


# ---------------------------------------------------------------------------
# Core collector coroutine
# ---------------------------------------------------------------------------

async def _run(cfg: dict, state: CollectorState) -> None:
    cap = cfg.get("capture", {})
    nats_cfg = cfg.get("nats", {})

    source = cap.get("pcap_file") or cap.get("interface")
    if not source:
        raise ValueError("No capture source set (capture.interface or capture.pcap_file)")

    nats_url = nats_cfg.get("url", "nats://localhost:4222")
    subject = nats_cfg.get("subject", "flows.raw")

    state.capture_source = str(source)
    state.nats_url = nats_url
    state.nats_subject = subject
    state.started_at = datetime.now(timezone.utc).isoformat()

    nc = await nats.connect(nats_url)
    state.nats_connected = True
    logger.info("Connected to NATS, publishing to %r", subject)

    statistical = cap.get("statistical_analysis", True)
    streamer = NFStreamer(
        source=source,
        decode_tunnels=cap.get("decode_tunnels", True),
        bpf_filter=cap.get("bpf_filter") or None,
        promiscuous_mode=cap.get("promiscuous_mode", True),
        snapshot_length=cap.get("snapshot_length", 1536),
        idle_timeout=cap.get("idle_timeout", 120),
        active_timeout=cap.get("active_timeout", 1800),
        n_dissections=cap.get("n_dissections", 20),
        statistical_analysis=statistical,
        splt_analysis=cap.get("splt_analysis", 0),
    )

    flow_queue: queue.Queue = queue.Queue(maxsize=2000)
    state._flow_queue = flow_queue

    stop_event = threading.Event()
    thread = threading.Thread(
        target=_stream_to_queue, args=(streamer, flow_queue, stop_event), daemon=True
    )

    state.status = "running"
    thread.start()
    loop = asyncio.get_running_loop()

    try:
        while True:
            flow = await loop.run_in_executor(None, flow_queue.get)
            if flow is None:
                break
            try:
                fd = flow_to_dict(flow, statistical)
                payload = msgpack.packb(fd, use_bin_type=True)
                await nc.publish(subject, payload)
                state.flows_published += 1
                state.last_flow_at = datetime.now(timezone.utc).isoformat()
                state.record_flow(fd)
                if state.flows_published % 100 == 0:
                    logger.info("Published %d flows", state.flows_published)
            except Exception as e:
                state.publish_errors += 1
                logger.error("Publish error: %s", e)
    finally:
        state.status = "stopping"
        stop_event.set()
        thread.join()
        logger.info("Done. Published %d flows total.", state.flows_published)
        await nc.drain()
        state.nats_connected = False
        state.status = "stopped"
        state._flow_queue = None


# ---------------------------------------------------------------------------
# Combined startup: collector + HTTP status server
# ---------------------------------------------------------------------------

async def _start_all(cfg: dict, state: CollectorState, status_port: int) -> None:
    import uvicorn

    server = uvicorn.Server(
        uvicorn.Config(api, host="0.0.0.0", port=status_port, log_level="warning")
    )
    # Prevent uvicorn from overwriting our signal handlers.
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]

    loop = asyncio.get_running_loop()

    def _shutdown() -> None:
        logger.info("Shutdown signal received")
        state.status = "stopping"
        server.should_exit = True
        # Wake the queue-blocking executor call so _run() can see the sentinel.
        loop.call_soon_threadsafe(lambda: None)

    loop.add_signal_handler(signal.SIGINT, _shutdown)
    loop.add_signal_handler(signal.SIGTERM, _shutdown)

    collector_task = asyncio.create_task(_run(cfg, state))
    server_task = asyncio.create_task(server.serve())

    # The collector drives the lifecycle: when it finishes, stop the HTTP server.
    await collector_task
    server.should_exit = True
    await server_task


# ---------------------------------------------------------------------------
# Logging / daemonization helpers
# ---------------------------------------------------------------------------

def _setup_logging(log_file: Optional[str]) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    handler: logging.Handler
    if log_file:
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=50 * 1024 * 1024, backupCount=5
        )
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(fmt)
    root.addHandler(handler)


def _daemonize(pid_file: str, log_file: str) -> None:
    """Double-fork daemonization (POSIX)."""
    import atexit
    import os

    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    os.setsid()
    os.umask(0o022)

    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    log_fd = open(log_file, "a")
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = open(os.devnull, "r")
    os.dup2(devnull.fileno(), sys.stdin.fileno())
    os.dup2(log_fd.fileno(), sys.stdout.fileno())
    os.dup2(log_fd.fileno(), sys.stderr.fileno())

    Path(pid_file).write_text(str(os.getpid()))

    def _remove_pid() -> None:
        try:
            Path(pid_file).unlink(missing_ok=True)
        except Exception:
            pass

    atexit.register(_remove_pid)


def get_interfaces() -> list[str]:
    return list(psutil.net_if_addrs().keys())


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import typer

    app = typer.Typer(add_completion=False)

    @app.command()
    def cli(
        config: Path = typer.Option(
            Path("config/config.yaml"), "--config", "-c", help="Config file"
        ),
        interface: Optional[str] = typer.Option(
            None, "--interface", "-i", help="Live capture interface (requires root)"
        ),
        pcap: Optional[Path] = typer.Option(None, "--pcap", "-p", help="PCAP file"),
        nats_url: Optional[str] = typer.Option(None, "--nats-url", help="NATS server URL"),
        subject: Optional[str] = typer.Option(None, "--subject", "-s", help="NATS subject"),
        status_port: int = typer.Option(
            DEFAULT_STATUS_PORT, "--status-port", help="HTTP state API port"
        ),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Run as Unix daemon"),
        pid_file: str = typer.Option(DEFAULT_PID_FILE, "--pid-file", help="PID file path"),
        log_file: str = typer.Option(DEFAULT_LOG_FILE, "--log-file", help="Log file (daemon mode)"),
        list_interfaces: bool = typer.Option(
            False, "--list-interfaces", help="List available interfaces and exit"
        ),
    ):
        """Collect network flows with NFStream and publish to NATS."""
        if list_interfaces:
            for iface in get_interfaces():
                print(iface)
            return

        cfg: dict = {}
        if config.exists():
            cfg = load_config(config)

        _apply_env_overrides(cfg)  # env vars override config file, CLI flags override env

        if interface:
            cfg.setdefault("capture", {})["interface"] = interface
        if pcap:
            cfg.setdefault("capture", {})["pcap_file"] = str(pcap)
        if nats_url:
            cfg.setdefault("nats", {})["url"] = nats_url
        if subject:
            cfg.setdefault("nats", {})["subject"] = subject

        import os

        cap_cfg = cfg.get("capture", {})
        if not cap_cfg.get("interface") and not cap_cfg.get("pcap_file"):
            typer.echo("Error: no capture source specified.\n")
            typer.echo("You can set it via:")
            typer.echo("  --interface eth0              (CLI flag)")
            typer.echo("  --pcap traffic.pcap           (CLI flag)")
            typer.echo("  CAPTURE_INTERFACE=eth0        (env var / ConfigMap)")
            typer.echo("  CAPTURE_PCAP_FILE=file.pcap   (env var / ConfigMap)\n")
            typer.echo("Available interfaces:")
            for iface in get_interfaces():
                typer.echo(f"  {iface}")
            raise typer.Exit(code=1)

        # CLI --status-port takes precedence; otherwise fall back to config.
        effective_port = (
            status_port
            if status_port != DEFAULT_STATUS_PORT
            else cfg.get("status", {}).get("port", DEFAULT_STATUS_PORT)
        )

        nats_cfg = cfg.get("nats", {})
        effective_nats = nats_cfg.get("url", "nats://localhost:4222")
        effective_subject = nats_cfg.get("subject", "flows.raw")

        if cap_cfg.get("interface"):
            if interface:
                iface_source = "cli"
            elif os.environ.get("CAPTURE_INTERFACE"):
                iface_source = "env:CAPTURE_INTERFACE"
            else:
                iface_source = "config"
            capture_source = f"{cap_cfg['interface']} ({iface_source})"
        else:
            capture_source = f"{cap_cfg.get('pcap_file')} (pcap)"

        typer.echo("NIDS Collector starting")
        typer.echo(f"  capture source : {capture_source}")
        typer.echo(f"  NATS URL       : {effective_nats}")
        typer.echo(f"  NATS subject   : {effective_subject}")
        typer.echo(f"  status port    : {effective_port}")
        if daemon:
            typer.echo(f"  mode           : daemon (pid={pid_file}, log={log_file})")
            _daemonize(pid_file, log_file)
            _setup_logging(log_file)
        else:
            typer.echo( "  mode           : foreground")
            _setup_logging(None)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_start_all(cfg, _state, effective_port))
        finally:
            loop.close()

    app()


if __name__ == "__main__":
    main()
