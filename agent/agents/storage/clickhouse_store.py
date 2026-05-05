"""ClickHouse storage for network flows."""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import clickhouse_connect
from clickhouse_connect.driver.client import Client

logger = logging.getLogger(__name__)

_CREATE_DB = "CREATE DATABASE IF NOT EXISTS {db}"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS {db}.flows (
    collected_at              DateTime64(3, 'UTC'),
    flow_id                   String,
    src_ip                    String,
    dst_ip                    String,
    src_port                  UInt16,
    dst_port                  UInt16,
    protocol                  LowCardinality(String),
    ip_version                UInt8,
    duration_ms               UInt64,
    duration_s                Float64,
    bidirectional_packets     UInt64,
    bidirectional_bytes       UInt64,
    src2dst_packets           UInt64,
    src2dst_bytes             UInt64,
    dst2src_packets           UInt64,
    dst2src_bytes             UInt64,
    application_name          LowCardinality(String),
    application_category_name LowCardinality(String),
    application_confidence    Float32,
    requested_server_name     String,
    packets_per_second        Float64,
    bytes_per_second          Float64,
    bidirectional_syn_packets UInt32,
    bidirectional_rst_packets UInt32,
    bidirectional_fin_packets UInt32,
    llm_summary               String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(collected_at)
ORDER BY (collected_at, src_ip, dst_ip)
TTL collected_at + INTERVAL 30 DAY
SETTINGS index_granularity = 8192
"""

_COLS = [
    "collected_at", "flow_id", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "ip_version",
    "duration_ms", "duration_s",
    "bidirectional_packets", "bidirectional_bytes",
    "src2dst_packets", "src2dst_bytes",
    "dst2src_packets", "dst2src_bytes",
    "application_name", "application_category_name",
    "application_confidence", "requested_server_name",
    "packets_per_second", "bytes_per_second",
    "bidirectional_syn_packets", "bidirectional_rst_packets",
    "bidirectional_fin_packets",
    "llm_summary",
]


class ClickHouseFlowStore:
    """Stores and queries network flows in ClickHouse."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8123,
        database: str = "nids",
        username: str = "default",
        password: str = "",
        secure: bool = False,
    ):
        self.database = database
        self.client: Client = clickhouse_connect.get_client(
            host=host,
            port=port,
            username=username,
            password=password,
            secure=secure,
        )
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self.client.command(_CREATE_DB.format(db=self.database))
        self.client.command(_CREATE_TABLE.format(db=self.database))
        logger.info(f"ClickHouse schema ready ({self.database}.flows)")

    # ── Write ──────────────────────────────────────────────────────────────────

    def insert_flows(self, flows: List[Dict], llm_summary: str = "") -> None:
        """Batch-insert flows into ClickHouse. Payload fields are excluded."""
        if not flows:
            return

        now = datetime.now(timezone.utc)
        rows = []
        for f in flows:
            rows.append([
                now,
                str(f.get("flow_id", "")),
                str(f.get("src_ip", "")),
                str(f.get("dst_ip", "")),
                int(f.get("src_port", 0)),
                int(f.get("dst_port", 0)),
                str(f.get("protocol", "")),
                int(f.get("ip_version", 4)),
                int(f.get("bidirectional_duration_ms", 0)),
                float(f.get("duration", 0.0)),
                int(f.get("bidirectional_packets", 0)),
                int(f.get("bidirectional_bytes", 0)),
                int(f.get("src2dst_packets", 0)),
                int(f.get("src2dst_bytes", 0)),
                int(f.get("dst2src_packets", 0)),
                int(f.get("dst2src_bytes", 0)),
                str(f.get("application_name", "")),
                str(f.get("application_category_name", "")),
                float(f.get("application_confidence", 0.0)),
                str(f.get("requested_server_name", "")),
                float(f.get("packets_per_second", 0.0)),
                float(f.get("bytes_per_second", 0.0)),
                int(f.get("bidirectional_syn_packets", 0)),
                int(f.get("bidirectional_rst_packets", 0)),
                int(f.get("bidirectional_fin_packets", 0)),
                llm_summary,
            ])

        self.client.insert(f"{self.database}.flows", rows, column_names=_COLS)
        logger.info(f"Inserted {len(rows)} flows into ClickHouse")

    # ── Read (used by search tools) ────────────────────────────────────────────

    def _to_dicts(self, result) -> List[Dict]:
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def search_by_ip(self, ip: str, limit: int = 50) -> List[Dict]:
        """Return recent flows where src_ip or dst_ip matches."""
        r = self.client.query(
            f"SELECT flow_id, src_ip, dst_ip, src_port, dst_port, protocol, "
            f"application_name, bidirectional_packets, bidirectional_bytes, "
            f"packets_per_second, collected_at "
            f"FROM {self.database}.flows "
            f"WHERE src_ip = {{ip:String}} OR dst_ip = {{ip:String}} "
            f"ORDER BY collected_at DESC LIMIT {{limit:UInt32}}",
            parameters={"ip": ip, "limit": limit},
        )
        return self._to_dicts(r)

    def search_by_port(self, port: int, limit: int = 50) -> List[Dict]:
        """Return recent flows that used a given TCP/UDP port."""
        r = self.client.query(
            f"SELECT flow_id, src_ip, dst_ip, src_port, dst_port, protocol, "
            f"application_name, bidirectional_packets, bidirectional_bytes, collected_at "
            f"FROM {self.database}.flows "
            f"WHERE src_port = {{port:UInt16}} OR dst_port = {{port:UInt16}} "
            f"ORDER BY collected_at DESC LIMIT {{limit:UInt32}}",
            parameters={"port": port, "limit": limit},
        )
        return self._to_dicts(r)

    def search_by_application(self, app_name: str, limit: int = 50) -> List[Dict]:
        """Return recent flows for a given nDPI application name (partial, case-insensitive)."""
        r = self.client.query(
            f"SELECT flow_id, src_ip, dst_ip, src_port, dst_port, "
            f"application_name, application_category_name, "
            f"bidirectional_packets, bidirectional_bytes, collected_at "
            f"FROM {self.database}.flows "
            f"WHERE lower(application_name) LIKE {{pat:String}} "
            f"ORDER BY collected_at DESC LIMIT {{limit:UInt32}}",
            parameters={"pat": f"%{app_name.lower()}%", "limit": limit},
        )
        return self._to_dicts(r)

    def get_top_talkers(self, minutes: int = 60, limit: int = 10) -> List[Dict]:
        """Top source IPs ranked by bytes in the last N minutes."""
        r = self.client.query(
            f"SELECT src_ip, "
            f"count() AS flow_count, "
            f"sum(bidirectional_bytes) AS total_bytes, "
            f"sum(bidirectional_packets) AS total_packets "
            f"FROM {self.database}.flows "
            f"WHERE collected_at >= now() - INTERVAL {{minutes:UInt32}} MINUTE "
            f"GROUP BY src_ip ORDER BY total_bytes DESC LIMIT {{limit:UInt32}}",
            parameters={"minutes": minutes, "limit": limit},
        )
        return self._to_dicts(r)

    def get_flow_statistics(self, src_ip: Optional[str] = None, minutes: int = 60) -> Dict[str, Any]:
        """Aggregate stats for the last N minutes, optionally filtered by src_ip."""
        where = f"WHERE collected_at >= now() - INTERVAL {{minutes:UInt32}} MINUTE"
        params: Dict[str, Any] = {"minutes": minutes}
        if src_ip:
            where += " AND src_ip = {ip:String}"
            params["ip"] = src_ip

        r = self.client.query(
            f"SELECT "
            f"count() AS total_flows, "
            f"sum(bidirectional_bytes) AS total_bytes, "
            f"avg(packets_per_second) AS avg_pps, "
            f"countIf(bidirectional_rst_packets > 0) AS rst_flows, "
            f"countIf(bidirectional_syn_packets > 0 AND dst2src_packets = 0) AS half_open_flows "
            f"FROM {self.database}.flows {where}",
            parameters=params,
        )
        rows = self._to_dicts(r)
        return rows[0] if rows else {}
