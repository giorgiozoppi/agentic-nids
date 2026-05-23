#!/usr/bin/env python3
"""
NFStream → NATS collector (Unix daemon).

Reads network flows with NFStream (live interface or PCAP) and publishes
each completed flow as a MsgPack message to a NATS subject.

Run as daemon:
    sudo nids-collector --daemon --interface eth0

Run in foreground:
    nids-collector --interface eth0
    nids-collector --pcap traffic.pcap
"""

import asyncio
import logging
import logging.handlers
import queue
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import msgpack
import nats
import psutil
import yaml
from nfstream import NFStreamer

logger = logging.getLogger(__name__)

DEFAULT_PID_FILE = "/var/run/nids-collector.pid"
DEFAULT_LOG_FILE = "/var/log/nids-collector.log"


def load_config(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


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


async def _run(cfg: dict):
    cap = cfg.get("capture", {})
    nats_cfg = cfg.get("nats", {})

    source = cap.get("pcap_file") or cap.get("interface")
    if not source:
        logger.error("No capture source set (capture.interface or capture.pcap_file)")
        sys.exit(1)

    nc = await nats.connect(nats_cfg.get("url", "nats://localhost:4222"))
    subject = nats_cfg.get("subject", "flows.raw")
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
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_stream_to_queue, args=(streamer, flow_queue, stop_event), daemon=True
    )

    def _shutdown(*_):
        logger.info("Shutting down...")
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    thread.start()
    loop = asyncio.get_event_loop()
    count = 0

    while True:
        flow = await loop.run_in_executor(None, flow_queue.get)
        if flow is None:
            break
        try:
            payload = msgpack.packb(flow_to_dict(flow, statistical), use_bin_type=True)
            await nc.publish(subject, payload)
            count += 1
            if count % 100 == 0:
                logger.info("Published %d flows", count)
        except Exception as e:
            logger.error("Publish error: %s", e)

    thread.join()
    logger.info("Done. Published %d flows total.", count)
    await nc.drain()


def _setup_logging(log_file: Optional[str]):
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if log_file:
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=50 * 1024 * 1024, backupCount=5
        )
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(fmt)
    root.addHandler(handler)


def _daemonize(pid_file: str, log_file: str):
    """Double-fork daemonization (POSIX)."""
    import os
    import atexit

    # First fork
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    os.setsid()
    os.umask(0o022)

    # Second fork
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    # Redirect standard file descriptors
    log_fd = open(log_file, "a")
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = open(os.devnull, "r")
    os.dup2(devnull.fileno(), sys.stdin.fileno())
    os.dup2(log_fd.fileno(), sys.stdout.fileno())
    os.dup2(log_fd.fileno(), sys.stderr.fileno())

    # Write PID file
    Path(pid_file).write_text(str(os.getpid()))

    def _remove_pid():
        try:
            Path(pid_file).unlink(missing_ok=True)
        except Exception:
            pass

    atexit.register(_remove_pid)


def get_interfaces() -> list[str]:
    return list(psutil.net_if_addrs().keys())


def main():
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

        if interface:
            cfg.setdefault("capture", {})["interface"] = interface
        if pcap:
            cfg.setdefault("capture", {})["pcap_file"] = str(pcap)
        if nats_url:
            cfg.setdefault("nats", {})["url"] = nats_url
        if subject:
            cfg.setdefault("nats", {})["subject"] = subject

        if daemon:
            _daemonize(pid_file, log_file)
            _setup_logging(log_file)
        else:
            _setup_logging(None)

        # Create a fresh event loop — required after fork
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run(cfg))
        finally:
            loop.close()

    app()


if __name__ == "__main__":
    main()
