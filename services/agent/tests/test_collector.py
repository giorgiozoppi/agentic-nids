"""Unit tests for collector.py — no network or NFStream required."""
import queue
import textwrap
import types

import pytest
from fastapi.testclient import TestClient

import collector
from collector import CollectorState, api


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_flow(**overrides):
    defaults = dict(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=80,
        protocol=6,
        ip_version=4,
        bidirectional_first_seen_ms=1000,
        bidirectional_last_seen_ms=2000,
        bidirectional_duration_ms=1000,
        bidirectional_packets=10,
        bidirectional_bytes=1500,
        src2dst_packets=6,
        src2dst_bytes=900,
        dst2src_packets=4,
        dst2src_bytes=600,
        application_name="HTTP",
        application_category_name="Web",
        application_is_guessed=False,
        application_confidence=0,
        requested_server_name="",
    )
    defaults.update(overrides)
    return types.SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# flow_to_dict
# ---------------------------------------------------------------------------

def test_flow_to_dict_basic_fields():
    flow = _make_flow()
    d = collector.flow_to_dict(flow, statistical=False)

    assert d["src_ip"] == "10.0.0.1"
    assert d["dst_ip"] == "10.0.0.2"
    assert d["src_port"] == 12345
    assert d["dst_port"] == 80
    assert d["protocol"] == 6
    assert d["bidirectional_packets"] == 10
    assert d["bidirectional_bytes"] == 1500
    assert "collected_at" in d
    assert d["flow_id"] == "10.0.0.1:12345->10.0.0.2:80:6"


def test_flow_to_dict_rates():
    flow = _make_flow(bidirectional_duration_ms=2000, bidirectional_packets=20, bidirectional_bytes=4000)
    d = collector.flow_to_dict(flow, statistical=False)
    assert pytest.approx(d["packets_per_second"], rel=1e-3) == 10.0
    assert pytest.approx(d["bytes_per_second"], rel=1e-3) == 2000.0


def test_flow_to_dict_zero_duration():
    flow = _make_flow(bidirectional_duration_ms=0)
    d = collector.flow_to_dict(flow, statistical=False)
    assert d["packets_per_second"] == 0.0
    assert d["bytes_per_second"] == 0.0


def test_flow_to_dict_no_statistical_fields():
    flow = _make_flow()
    d = collector.flow_to_dict(flow, statistical=False)
    assert "bidirectional_min_ps" not in d
    assert "bidirectional_syn_packets" not in d


def test_flow_to_dict_statistical_fields():
    flow = _make_flow(
        bidirectional_min_ps=10.0,
        bidirectional_mean_ps=50.0,
        bidirectional_stddev_ps=5.0,
        bidirectional_max_ps=100.0,
        bidirectional_min_piat_ms=1.0,
        bidirectional_mean_piat_ms=10.0,
        bidirectional_stddev_piat_ms=2.0,
        bidirectional_max_piat_ms=50.0,
        bidirectional_syn_packets=2,
        bidirectional_ack_packets=8,
        bidirectional_psh_packets=3,
        bidirectional_rst_packets=0,
        bidirectional_fin_packets=1,
    )
    d = collector.flow_to_dict(flow, statistical=True)
    assert d["bidirectional_min_ps"] == 10.0
    assert d["bidirectional_syn_packets"] == 2
    assert d["bidirectional_fin_packets"] == 1


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

def test_load_config(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(textwrap.dedent("""
        nats:
          url: "nats://localhost:4222"
          subject: "flows.raw"
        capture:
          interface: eth0
          statistical_analysis: true
        status:
          port: 9090
    """))
    cfg = collector.load_config(cfg_file)
    assert cfg["nats"]["url"] == "nats://localhost:4222"
    assert cfg["nats"]["subject"] == "flows.raw"
    assert cfg["capture"]["interface"] == "eth0"
    assert cfg["status"]["port"] == 9090


def test_load_config_empty_file(tmp_path):
    cfg_file = tmp_path / "empty.yaml"
    cfg_file.write_text("")
    cfg = collector.load_config(cfg_file)
    assert cfg == {}


# ---------------------------------------------------------------------------
# CollectorState
# ---------------------------------------------------------------------------

def test_state_initial_values():
    state = CollectorState()
    assert state.status == "starting"
    assert state.flows_published == 0
    assert state.nats_connected is False


def test_state_as_dict_computed_fields():
    from datetime import datetime, timezone, timedelta

    state = CollectorState()
    state.flows_published = 60
    state.started_at = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()

    d = state.as_dict()
    assert d["uptime_seconds"] == pytest.approx(60.0, abs=1.0)
    assert d["flows_per_second"] == pytest.approx(1.0, abs=0.1)
    assert "queue_size" in d


def test_state_as_dict_queue_size():
    state = CollectorState()
    q = queue.Queue()
    q.put("a")
    q.put("b")
    state._flow_queue = q

    d = state.as_dict()
    assert d["queue_size"] == 2


def test_state_as_dict_no_private_fields_leaked():
    """Private attributes must never appear in the serialised dict."""
    state = CollectorState()
    d = state.as_dict()
    assert "_flow_queue" not in d
    assert "_recent_flows" not in d


def test_state_recent_flows_lru_capped():
    from collector import RECENT_FLOWS_MAX
    state = CollectorState()
    for i in range(RECENT_FLOWS_MAX + 5):
        state.record_flow({"flow_id": f"flow-{i}", "src_ip": "1.2.3.4",
                           "dst_ip": "5.6.7.8", "src_port": i, "dst_port": 80,
                           "protocol": 6, "application_name": "HTTP",
                           "bidirectional_packets": 10, "bidirectional_bytes": 1500,
                           "bidirectional_duration_ms": 100,
                           "packets_per_second": 10.0, "bytes_per_second": 150.0,
                           "collected_at": ""})
    d = state.as_dict()
    assert len(d["recent_flows"]) == RECENT_FLOWS_MAX
    # Oldest entries were evicted; the last entry is the most recently recorded.
    assert d["recent_flows"][-1]["flow_id"] == f"flow-{RECENT_FLOWS_MAX + 4}"


def test_state_recent_flows_empty_by_default():
    state = CollectorState()
    d = state.as_dict()
    assert d["recent_flows"] == []


# ---------------------------------------------------------------------------
# FastAPI endpoints
# ---------------------------------------------------------------------------

http = TestClient(api)


def test_health_starting():
    collector._state.status = "starting"
    resp = http.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["collector_status"] == "starting"


def test_health_running():
    collector._state.status = "running"
    resp = http.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_state_endpoint_returns_expected_keys():
    collector._state.status = "running"
    collector._state.nats_url = "nats://localhost:4222"
    collector._state.flows_published = 42

    resp = http.get("/state")
    assert resp.status_code == 200
    body = resp.json()
    assert body["flows_published"] == 42
    assert body["nats_url"] == "nats://localhost:4222"
    assert "uptime_seconds" in body
    assert "flows_per_second" in body
    assert "queue_size" in body
    assert "recent_flows" in body
    assert "_flow_queue" not in body
    assert "_recent_flows" not in body


def test_state_flows_endpoint_empty():
    collector._state._recent_flows.clear()
    resp = http.get("/state/flows")
    assert resp.status_code == 200
    assert resp.json() == {"recent_flows": []}


def test_state_flows_endpoint_returns_recorded_flows():
    collector._state._recent_flows.clear()
    collector._state.record_flow({
        "flow_id": "1.2.3.4:1000->5.6.7.8:80:6",
        "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
        "src_port": 1000, "dst_port": 80, "protocol": 6,
        "application_name": "HTTP",
        "bidirectional_packets": 5, "bidirectional_bytes": 500,
        "bidirectional_duration_ms": 200,
        "packets_per_second": 25.0, "bytes_per_second": 2500.0,
        "collected_at": "2026-05-30T10:00:00+00:00",
    })
    resp = http.get("/state/flows")
    assert resp.status_code == 200
    flows = resp.json()["recent_flows"]
    assert len(flows) == 1
    assert flows[0]["dst_port"] == 80
    assert flows[0]["application_name"] == "HTTP"
    assert flows[0]["packets_per_second"] == 25.0


# ---------------------------------------------------------------------------
# get_interfaces
# ---------------------------------------------------------------------------

def test_get_interfaces():
    ifaces = collector.get_interfaces()
    assert isinstance(ifaces, list)
    assert all(isinstance(i, str) for i in ifaces)
