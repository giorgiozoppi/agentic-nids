#!/usr/bin/env python3
"""
NIDS Collector CLI client.

Subcommands:
    health      GET /health
    startup     GET /startup
    readiness   GET /readiness
    flows       GET /state/flows   (pretty table)
    state       GET /state         (with optional monitor loop)

Run via uv:
    uv run scripts/nids_client.py health
    uv run scripts/nids_client.py flows --limit 20
    uv run scripts/nids_client.py state --watch --times 10 --interval 2
"""

import json
import sys
import time
from datetime import datetime, timezone
from typing import Annotated, Optional

import httpx
import typer
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()

_URL_OPT = Annotated[str, typer.Option("--url", "-u", help="Collector base URL")]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _fetch(base_url: str, path: str) -> tuple[dict, int]:
    try:
        r = httpx.get(f"{base_url}{path}", timeout=5)
        return r.json(), r.status_code
    except httpx.ConnectError:
        console.print(f"[red]Connection refused — is the collector running at {base_url}?[/red]")
        raise typer.Exit(code=1)
    except httpx.TimeoutException:
        console.print(f"[red]Timed out connecting to {base_url}[/red]")
        raise typer.Exit(code=1)


def _status_colour(status: str) -> str:
    return {"running": "green", "stopping": "yellow", "stopped": "red"}.get(status, "white")


def _print_probe(data: dict, status_code: int, name: str) -> None:
    ok = status_code == 200
    colour = "green" if ok else "red"
    label = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
    lines = [f"{label}  ({status_code})"]
    for k, v in data.items():
        lines.append(f"  [dim]{k}:[/dim] {v}")
    console.print(Panel("\n".join(lines), title=name, border_style=colour))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
def health(url: _URL_OPT = "http://localhost:8080"):
    """Liveness check."""
    data, code = _fetch(url, "/health")
    _print_probe(data, code, "Health")
    raise typer.Exit(code=0 if code == 200 else 1)


@app.command()
def startup(url: _URL_OPT = "http://localhost:8080"):
    """Startup probe — non-zero exit if still starting."""
    data, code = _fetch(url, "/startup")
    _print_probe(data, code, "Startup probe")
    raise typer.Exit(code=0 if code == 200 else 1)


@app.command()
def readiness(url: _URL_OPT = "http://localhost:8080"):
    """Readiness probe — non-zero exit if not ready."""
    data, code = _fetch(url, "/readiness")
    _print_probe(data, code, "Readiness probe")
    raise typer.Exit(code=0 if code == 200 else 1)


@app.command()
def flows(
    url: _URL_OPT = "http://localhost:8080",
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max flows to show (1-100)")] = 20,
    json_out: Annotated[bool, typer.Option("--json", help="Raw JSON output")] = False,
):
    """Show the most recently captured flows."""
    limit = max(1, min(limit, 100))
    data, _ = _fetch(url, f"/state/flows?limit={limit}")

    if json_out:
        console.print_json(json.dumps(data))
        return

    flow_list = data.get("flows", [])
    total = data.get("total_published", 0)

    t = Table(
        title=f"Recent flows  [dim](total published: {total})[/dim]",
        show_lines=False,
        highlight=True,
    )
    t.add_column("Time (UTC)", style="dim", no_wrap=True)
    t.add_column("Source", no_wrap=True)
    t.add_column("Destination", no_wrap=True)
    t.add_column("Proto", justify="center")
    t.add_column("Application", style="cyan")
    t.add_column("Pkts", justify="right")
    t.add_column("Bytes", justify="right")
    t.add_column("Duration ms", justify="right")

    for f in flow_list:
        collected = f.get("collected_at", "")[:19].replace("T", " ")
        src = f"{f.get('src_ip', '')}:{f.get('src_port', '')}"
        dst = f"{f.get('dst_ip', '')}:{f.get('dst_port', '')}"
        proto = str(f.get("protocol", ""))
        app_name = f.get("application_name", "") or "[dim]unknown[/dim]"
        pkts = str(f.get("bidirectional_packets", ""))
        byt = str(f.get("bidirectional_bytes", ""))
        dur = str(f.get("bidirectional_duration_ms", ""))
        t.add_row(collected, src, dst, proto, app_name, pkts, byt, dur)

    console.print(t)


@app.command()
def state(
    url: _URL_OPT = "http://localhost:8080",
    watch: Annotated[bool, typer.Option("--watch", "-w", help="Poll repeatedly")] = False,
    times: Annotated[int, typer.Option("--times", "-n", help="Max poll iterations")] = 10,
    interval: Annotated[float, typer.Option("--interval", "-i", help="Seconds between polls")] = 5.0,
    json_out: Annotated[bool, typer.Option("--json", help="Raw JSON output")] = False,
):
    """Show full collector state. Use --watch to monitor over time."""
    iterations = times if watch else 1

    for i in range(iterations):
        data, code = _fetch(url, "/state")

        if json_out:
            console.print_json(json.dumps(data))
        else:
            _render_state(data, code, i + 1 if watch else None, iterations if watch else None)

        if watch and i < iterations - 1:
            try:
                time.sleep(interval)
            except KeyboardInterrupt:
                console.print("\n[yellow]Stopped.[/yellow]")
                raise typer.Exit()

    if watch:
        console.print(f"[dim]Completed {iterations} iteration(s).[/dim]")


def _render_state(data: dict, code: int, iteration: Optional[int], total: Optional[int]) -> None:
    status = data.get("status", "unknown")
    colour = _status_colour(status)

    header = f"Collector state  [bold {colour}]{status.upper()}[/bold {colour}]"
    if iteration is not None:
        now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        header += f"  [dim]{now}  ({iteration}/{total})[/dim]"

    panels = []

    # Connection info
    conn_lines = [
        f"NATS URL     : {data.get('nats_url', '')}",
        f"Subject      : {data.get('nats_subject', '')}",
        f"NATS conn.   : {'[green]yes[/green]' if data.get('nats_connected') else '[red]no[/red]'}",
        f"Capture      : {data.get('capture_source', '')}",
        f"Started at   : {(data.get('started_at', '') or '')[:19].replace('T', ' ')} UTC",
        f"Uptime       : {data.get('uptime_seconds', 0):.0f}s",
    ]
    panels.append(Panel("\n".join(conn_lines), title="Connection", border_style="blue"))

    # Flow metrics
    metric_lines = [
        f"Published     : {data.get('flows_published', 0):,}",
        f"Errors        : {data.get('publish_errors', 0)}",
        f"Rate          : {data.get('flows_per_second', 0):.2f} flows/s",
        f"Queue size    : {data.get('queue_size', 0)}",
        f"Last flow at  : {(data.get('last_flow_at', '') or 'none')[:19].replace('T', ' ')}",
    ]
    panels.append(Panel("\n".join(metric_lines), title="Metrics", border_style="magenta"))

    console.print()
    console.print(f"  {header}")
    console.print(Columns(panels, equal=True, expand=True))


if __name__ == "__main__":
    app()
