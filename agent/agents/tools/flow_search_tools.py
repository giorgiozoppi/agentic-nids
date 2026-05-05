"""LangChain tools for querying historical flows from ClickHouse."""
import json
from typing import List

from langchain_core.tools import tool

from agents.storage.clickhouse_store import ClickHouseFlowStore


def make_flow_search_tools(store: ClickHouseFlowStore) -> List:
    """Return search tools bound to the given ClickHouseFlowStore."""

    @tool
    def search_flows_by_ip(ip_address: str) -> str:
        """
        Search the flow history for a specific IP address (as source or destination).
        Returns the 50 most recent matching flows with key metrics.
        """
        results = store.search_by_ip(ip_address)
        if not results:
            return f"No historical flows found for IP {ip_address}."
        return json.dumps(results, default=str, indent=2)

    @tool
    def search_flows_by_port(port: int) -> str:
        """
        Search the flow history for a specific TCP/UDP port number.
        Returns the 50 most recent flows that used that port.
        """
        results = store.search_by_port(port)
        if not results:
            return f"No historical flows found for port {port}."
        return json.dumps(results, default=str, indent=2)

    @tool
    def search_flows_by_application(application_name: str) -> str:
        """
        Search the flow history by nDPI-detected application name (e.g. 'HTTP', 'DNS', 'TLS').
        Case-insensitive partial match. Returns the 50 most recent matching flows.
        """
        results = store.search_by_application(application_name)
        if not results:
            return f"No historical flows found for application '{application_name}'."
        return json.dumps(results, default=str, indent=2)

    @tool
    def get_top_talkers(minutes: int = 60) -> str:
        """
        Return the top 10 source IPs ranked by bytes transferred in the last N minutes.
        Useful for detecting flood sources or data exfiltration.
        """
        results = store.get_top_talkers(minutes=minutes)
        if not results:
            return "No traffic data available for the requested time window."
        return json.dumps(results, default=str, indent=2)

    @tool
    def get_flow_statistics(src_ip: str = "", minutes: int = 60) -> str:
        """
        Get aggregate flow statistics for the last N minutes: total flows, bytes,
        average PPS, RST flow count, and half-open TCP connection count.
        Optionally filter by source IP (leave empty for all IPs).
        """
        results = store.get_flow_statistics(src_ip=src_ip or None, minutes=minutes)
        if not results:
            return "No statistics available for the requested time window."
        return json.dumps(results, default=str, indent=2)

    return [
        search_flows_by_ip,
        search_flows_by_port,
        search_flows_by_application,
        get_top_talkers,
        get_flow_statistics,
    ]
