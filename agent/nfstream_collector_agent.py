#!/usr/bin/env python3
"""
NFStream Flow Collector Agent

This agent uses the nfstream library for efficient network flow collection and analysis.
NFStream provides:
- Native nDPI integration for deep packet inspection
- Automatic flow aggregation and statistical feature extraction
- Support for PCAP files and live capture
- High performance with multiprocessing support

This agent:
1. Collects network flows using NFStream
2. Extracts statistical features and application identification
3. Saves flows to JSONL file for offline analysis
"""

import asyncio
import logging
import time
import yaml
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator
from dataclasses import dataclass, field
from datetime import datetime
import signal
from nfstream import NFStreamer, NFPlugin
from threading import Event
from agents.llm.llm_explanation_agent import LLMExplanationAgent
import base64

NFSTREAM_AVAILABLE = True
logger = logging.getLogger(__name__)
event = Event()
event.set()


class PayloadExtractor(NFPlugin):
    """
    NFStream plugin to extract and store payload data from network flows.

    Captures the first N bytes of payload from both directions (src->dst and dst->src).
    Stores payload in udp_parameters dictionary for safe storage.
    """

    def __init__(self, max_payload_bytes: int = 200):
        """
        Initialize payload extractor

        Args:
            max_payload_bytes: Maximum number of payload bytes to capture per direction
        """
        super().__init__()
        self.max_payload_bytes = max_payload_bytes

    def on_init(self, packet, flow):
        """Called when a new flow is created"""
        # udps attribute is automatically created by NFStream when udps plugin is used
        # Initialize payload storage
        flow.udps.src2dst_payload = b""
        flow.udps.dst2src_payload = b""
        flow.udps.src2dst_payload_size = 0
        flow.udps.dst2src_payload_size = 0
        flow.udps.payload_packets_captured = 0
        logger.debug(f"PayloadExtractor: New flow initialized - {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")

    def on_update(self, packet, flow):
        """Called for each packet in the flow"""
        # Only capture if we haven't reached the limit
        if hasattr(packet, 'payload') and packet.payload and len(packet.payload) > 0:
            flow.udps.payload_packets_captured += 1

            # Determine direction based on packet direction flag
            if packet.direction == 0:  # src -> dst
                if flow.udps.src2dst_payload_size < self.max_payload_bytes:
                    remaining = self.max_payload_bytes - flow.udps.src2dst_payload_size
                    payload_chunk = packet.payload[:remaining]
                    flow.udps.src2dst_payload += payload_chunk
                    flow.udps.src2dst_payload_size += len(payload_chunk)
                    logger.debug(f"PayloadExtractor: Captured {len(payload_chunk)} bytes (src->dst) - Total: {flow.udps.src2dst_payload_size}/{self.max_payload_bytes}")
            else:  # dst -> src
                if flow.udps.dst2src_payload_size < self.max_payload_bytes:
                    remaining = self.max_payload_bytes - flow.udps.dst2src_payload_size
                    payload_chunk = packet.payload[:remaining]
                    flow.udps.dst2src_payload += payload_chunk
                    flow.udps.dst2src_payload_size += len(payload_chunk)
                    logger.debug(f"PayloadExtractor: Captured {len(payload_chunk)} bytes (dst->src) - Total: {flow.udps.dst2src_payload_size}/{self.max_payload_bytes}")

@dataclass
class NFStreamAgentConfig:
    """Configuration for NFStream collector agent"""

    # Collection settings
    collection_interval: int = 180  # Save flows every 3 minutes
    idle_timeout: int = 120  # Flow idle timeout (seconds)
    active_timeout: int = 1800  # Flow active timeout (seconds)
    batch_size: int = 100  # Flows per batch before saving

    # Capture settings
    capture_interface: Optional[str] = None
    pcap_file: Optional[str] = None
    bpf_filter: Optional[str] = None
    promiscuous_mode: bool = True
    snapshot_length: int = 1536

    # NFStream-specific settings
    decode_tunnels: bool = True
    n_dissections: int = 20  # Number of nDPI dissections
    statistical_analysis: bool = True  # Enable statistical features
    splt_analysis: int = 0  # Early flow features (0 = disabled, 1-255 = packets)
    system_visibility_mode: int = 0  # System visibility (process info)
    max_nflows: int = 0  # Maximum flows (0 = unlimited)

    # Payload extraction settings
    extract_payload: bool = True  # Enable payload extraction
    max_payload_bytes: int = 200  # Maximum payload bytes to capture per direction

    # Output settings
    log_file: Optional[str] = None
    flows_output_file: Optional[str] = "collected_flows.jsonl"  # JSONL output for flows

    # Performance settings
    stats_interval: int = 60  # Print stats every minute
    performance_report: int = 0  # NFStream performance reporting (0 = disabled)

    llm_prompt: Optional[str] = None  # LLM prompt template

    @classmethod
    def from_yaml(cls, yaml_path: Path) -> 'NFStreamAgentConfig':
        """Load configuration from YAML file"""
        with open(yaml_path, 'r') as f:
            config_dict = yaml.safe_load(f)
        # If llm_prompt is a file, load its contents
        if 'llm_prompt' in config_dict and config_dict['llm_prompt'] and config_dict['llm_prompt'].endswith('.txt'):
            prompt_path = Path(config_dict['llm_prompt'])
            if prompt_path.exists():
                config_dict['llm_prompt'] = prompt_path.read_text()
        return cls(**config_dict)

    def to_yaml(self, yaml_path: Path):
        """Save configuration to YAML file"""
        config_dict = {
            'collection_interval': self.collection_interval,
            'idle_timeout': self.idle_timeout,
            'active_timeout': self.active_timeout,
            'batch_size': self.batch_size,
            'capture_interface': self.capture_interface,
            'pcap_file': self.pcap_file,
            'bpf_filter': self.bpf_filter,
            'promiscuous_mode': self.promiscuous_mode,
            'snapshot_length': self.snapshot_length,
            'decode_tunnels': self.decode_tunnels,
            'n_dissections': self.n_dissections,
            'statistical_analysis': self.statistical_analysis,
            'splt_analysis': self.splt_analysis,
            'system_visibility_mode': self.system_visibility_mode,
            'max_nflows': self.max_nflows,
            'log_file': self.log_file,
            'flows_output_file': self.flows_output_file,
            'stats_interval': self.stats_interval,
            'performance_report': self.performance_report,
            'llm_prompt': self.llm_prompt,
        }

        with open(yaml_path, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)


# Protocol number to name mapping (basic set)
PROTOCOL_MAP = {
    1: 'icmp',
    6: 'tcp',
    17: 'udp',
    41: 'ipv6',
    47: 'gre',
    50: 'esp',
    51: 'ah',
    58: 'ipv6-icmp',
    132: 'sctp'
}

class NFStreamCollectorAgent:
    """
    Pure NFStream collector agent for network flow data collection

    Uses nfstream library for efficient network flow collection with:
    - Automatic flow aggregation
    - nDPI-based application identification
    - Statistical feature extraction
    - Support for PCAP and live capture
    - JSONL output format for offline analysis
    """

    def __init__(self, config: NFStreamAgentConfig):
        """Initialize NFStream collector agent"""
     
        self.config = config
        self.running = False
        self.streamer: Optional[NFStreamer] = None
        self.flow_buffer: List[Dict] = []

        # Statistics
        self.stats = {
            'collections': 0,
            'flows_collected': 0,
            'flows_saved': 0,
            'start_time': time.time(),
        }

        logger.info("NFStream Collector Agent initialized")
        logger.info(f"Collection interval: {config.collection_interval}s")
        logger.info(f"Output file: {config.flows_output_file}")
        logger.info(f"Statistical analysis: {config.statistical_analysis}")
        logger.info(f"nDPI dissections: {config.n_dissections}")

    def _create_streamer(self) -> NFStreamer:
        """Create NFStreamer instance with configured parameters"""

        # Determine source (interface or PCAP file)
        if self.config.pcap_file:
            source = self.config.pcap_file
            logger.info(f"Creating streamer for PCAP file: {source}")
        elif self.config.capture_interface:
            source = self.config.capture_interface
            logger.info(f"Creating streamer for interface: {source}")
        else:
            raise ValueError("No capture source specified (interface or PCAP file)")

        # Setup payload extraction plugin if enabled
        udps = None
        if self.config.extract_payload:
            payload_plugin = PayloadExtractor(max_payload_bytes=self.config.max_payload_bytes)
            udps = payload_plugin
            logger.info(f"Payload extraction enabled: capturing up to {self.config.max_payload_bytes} bytes per direction")

        # Create NFStreamer with configuration
        streamer = NFStreamer(
            source=source,
            decode_tunnels=self.config.decode_tunnels,
            bpf_filter=self.config.bpf_filter,
            promiscuous_mode=self.config.promiscuous_mode,
            snapshot_length=self.config.snapshot_length,
            idle_timeout=self.config.idle_timeout,
            active_timeout=self.config.active_timeout,
            accounting_mode=0,  # Standard accounting
            udps=udps,  # Payload extraction plugin
            n_dissections=self.config.n_dissections,
            statistical_analysis=self.config.statistical_analysis,
            splt_analysis=self.config.splt_analysis,
            n_meters=0,  # No custom meters
            max_nflows=self.config.max_nflows,
            performance_report=self.config.performance_report,
            system_visibility_mode=self.config.system_visibility_mode,
            system_visibility_poll_ms=100,
        )

        return streamer

    def _nflow_to_dict(self, flow) -> Dict:
        """
        Convert NFStream NFlow object to dictionary for A2A message

        Args:
            flow: NFlow object from NFStream

        Returns:
            Dictionary with flow features
        """
        flow_dict = {
            # Basic flow identification
            'flow_id': f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}:{flow.protocol}",
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'protocol': self._decode_protocol(flow.protocol),
            'ip_version': flow.ip_version,

            # Timing information
            'bidirectional_first_seen_ms': flow.bidirectional_first_seen_ms,
            'bidirectional_last_seen_ms': flow.bidirectional_last_seen_ms,
            'bidirectional_duration_ms': flow.bidirectional_duration_ms,
            'duration': flow.bidirectional_duration_ms / 1000.0,  # Convert to seconds

            # Packet and byte counts
            'bidirectional_packets': flow.bidirectional_packets,
            'bidirectional_bytes': flow.bidirectional_bytes,
            'src2dst_packets': flow.src2dst_packets,
            'src2dst_bytes': flow.src2dst_bytes,
            'dst2src_packets': flow.dst2src_packets,
            'dst2src_bytes': flow.dst2src_bytes,

            # Application identification (nDPI)
            'application_name': flow.application_name,
            'application_category_name': flow.application_category_name,
            'application_is_guessed': flow.application_is_guessed,
            'application_confidence': getattr(flow, 'application_confidence', 0),
            'requested_server_name': getattr(flow, 'requested_server_name', ''),

            # Statistical features (if enabled)
            'packets_per_second': flow.bidirectional_packets / (flow.bidirectional_duration_ms / 1000.0) if flow.bidirectional_duration_ms > 0 else 0,
            'bytes_per_second': flow.bidirectional_bytes / (flow.bidirectional_duration_ms / 1000.0) if flow.bidirectional_duration_ms > 0 else 0,
        }

        # Add statistical features if available
        if self.config.statistical_analysis:
            flow_dict.update({
                # Packet size statistics
                'bidirectional_min_ps': getattr(flow, 'bidirectional_min_ps', 0),
                'bidirectional_mean_ps': getattr(flow, 'bidirectional_mean_ps', 0),
                'bidirectional_stddev_ps': getattr(flow, 'bidirectional_stddev_ps', 0),
                'bidirectional_max_ps': getattr(flow, 'bidirectional_max_ps', 0),

                # Packet inter-arrival time statistics
                'bidirectional_min_piat_ms': getattr(flow, 'bidirectional_min_piat_ms', 0),
                'bidirectional_mean_piat_ms': getattr(flow, 'bidirectional_mean_piat_ms', 0),
                'bidirectional_stddev_piat_ms': getattr(flow, 'bidirectional_stddev_piat_ms', 0),
                'bidirectional_max_piat_ms': getattr(flow, 'bidirectional_max_piat_ms', 0),

                # TCP flags
                'bidirectional_syn_packets': getattr(flow, 'bidirectional_syn_packets', 0),
                'bidirectional_ack_packets': getattr(flow, 'bidirectional_ack_packets', 0),
                'bidirectional_psh_packets': getattr(flow, 'bidirectional_psh_packets', 0),
                'bidirectional_rst_packets': getattr(flow, 'bidirectional_rst_packets', 0),
                'bidirectional_fin_packets': getattr(flow, 'bidirectional_fin_packets', 0),
            })

        # Add payload data if extracted
        if self.config.extract_payload and hasattr(flow, 'udps'):
            src2dst_payload = getattr(flow.udps, 'src2dst_payload', b"")
            dst2src_payload = getattr(flow.udps, 'dst2src_payload', b"")
            flow_dict.update({
                'src2dst_payload': base64.b64encode(src2dst_payload).decode('utf-8') if src2dst_payload else "",
                'dst2src_payload': base64.b64encode(dst2src_payload).decode('utf-8') if dst2src_payload else "",
                'src2dst_payload_size': getattr(flow.udps, 'src2dst_payload_size', 0),
                'dst2src_payload_size': getattr(flow.udps, 'dst2src_payload_size', 0),
                'payload_packets_captured': getattr(flow.udps, 'payload_packets_captured', 0),
            })

        return flow_dict

    @staticmethod
    def _decode_protocol(flow):
        """
        Decode the protocol from the flow's protocol number or name.
        """
        proto_map = {
            6: "TCP",
            17: "UDP",
            1: "ICMP",
            # Add more as needed
        }
        proto = getattr(flow, "protocol", None)
        if isinstance(proto, int):
            return proto_map.get(proto, str(proto))
        elif isinstance(proto, str):
            return proto.upper()
        return str(proto)

    async def save_raw_flows(self, flows: List[Dict]):
        """
        Save raw flow data to JSONL file (one JSON object per line).

        Args:
            flows: List of flow dictionaries to save
        """
        if not self.config.flows_output_file:
            logger.warning("No output file configured, flows will not be saved")
            return

        import json
        try:
            # Append to JSONL file (one JSON object per line)
            with open(self.config.flows_output_file, 'a') as f:
                for flow in flows:
                    # Add timestamp
                    flow['collected_at'] = datetime.now().isoformat()
                    f.write(json.dumps(flow) + '\n')
                    self.stats['flows_saved'] += 1

            logger.info(f"Saved {len(flows)} flows to {self.config.flows_output_file}")
        except Exception as e:
            logger.error(f"Failed to save raw flows: {e}")

    async def collect_flows(self, llm_agent=None, a2a_collector=None):
        """
        Continuously collect flows from NFStreamer in background.

        This method runs NFStream collection in a separate thread to avoid blocking
        the async event loop, while maintaining a queue for flow processing.
        """
        import threading
        import queue

        logger.info("=" * 80)
        logger.info("Starting continuous flow collection")
        logger.info("=" * 80)
        logger.debug(f"Creating NFStreamer with source: {self.config.pcap_file or self.config.capture_interface}")

        batch = []
        self.streamer = self._create_streamer()
        logger.info("✓ NFStreamer created successfully")
        logger.info("Waiting for flows...")
        logger.info("=" * 80)

        for flow in self.streamer:
            if not event.is_set():
                logger.info("Stop signal received, ending collection")
                return
            try:
                flow_dict = self._nflow_to_dict(flow)
                self.stats['flows_collected'] += 1

                # Print flow before adding to batch
                logger.info("=" * 80)
                logger.info(f"Flow #{self.stats['flows_collected']}")
                logger.info(json.dumps(flow_dict, indent=2))
                logger.info("=" * 80)

                batch.append(flow_dict)
                logger.debug(f"Added flow to batch (batch size: {len(batch)}/{self.config.batch_size})")

                if len(batch) >= self.config.batch_size:
                    logger.info(f"\n🔄 Batch full ({len(batch)} flows) - processing...")
                    await self._process_and_send_batch(batch, llm_agent, a2a_collector)
                    logger.info("✓ Batch processed successfully\n")
                    batch = []
            except Exception as e:
                logger.error(f"Error processing flow: {e}")
                continue

        # Process any remaining flows
        if batch:
            logger.info(f"\n🔄 Processing final batch ({len(batch)} flows)...")
            await self._process_and_send_batch(batch, llm_agent, a2a_collector)
            logger.info("✓ Final batch processed successfully\n")

    async def _process_and_send_batch(self, batch, llm_agent, a2a_collector):
        """
        Process a batch of flows, call the LLM (OpenAI or Anthropic), and send the result to the A2A collector.
        """
        logger.debug("Building LLM prompt...")
        prompt = self.config.llm_prompt or (
            "You are a network security expert. Given the following batch of network flows (in JSON format), "
            "analyze the flows for any signs of anomalies, suspicious activity, or potential threats. "
            "For each anomaly you find, provide: a clear description, the flow(s) involved, and hints. "
            "If no anomalies are found, briefly state that the batch appears normal.\n\nFlows:\n" +
            json.dumps(batch, indent=2)
        )
        if '{flows}' in prompt:
            prompt = prompt.replace('{flows}', json.dumps(batch, indent=2))

        logger.info(f"📤 Sending batch of {len(batch)} flows to LLM agent for analysis...")
        llm_result = {"anomalies": [], "summary": "(No LLM agent configured)"}
        if llm_agent:
            try:
                logger.debug("Calling LLM agent analyze_flows()...")
                llm_result = await llm_agent.analyze_flows(batch, prompt)
                logger.info("✓ LLM analysis completed")
                # Print LLM response
                logger.info("=" * 80)
                logger.info("LLM RESPONSE")
                logger.info("=" * 80)
                logger.info(json.dumps(llm_result, indent=2))
                logger.info("=" * 80)
            except Exception as e:
                logger.error(f"✗ LLM agent error: {e}")
                llm_result = {"anomalies": [], "summary": f"LLM error: {e}"}
        else:
            logger.warning("⚠ No LLM agent configured - skipping analysis")

        logger.debug("Combining flows with LLM analysis...")
        combined = {
            "flows": batch,
            "llm_analysis": llm_result
        }

        if a2a_collector:
            logger.info("📡 Sending combined data to A2A collector...")
            await a2a_collector.process_combined(combined)
            logger.info("✓ Data sent to A2A collector")
        else:
            logger.warning("⚠ No A2A collector configured - data not sent")

    async def run(self, llm_agent=None, a2a_collector=None):
        """
        Run the NFStream collector agent continuously.

        Runs in a loop until SIGTERM/SIGINT is received, then performs graceful shutdown.
        """
        self.running = True
        await self.collect_flows(llm_agent=llm_agent, a2a_collector=a2a_collector)
    
    def stop(self):
        """
        Stop the agent gracefully.

        Sets the running flag to False, which will cause all background loops
        to terminate and perform cleanup.
        """
        event.clear()
        logger.info("Stop signal received - shutting down gracefully")
        self.running = False
        
    def print_statistics(self):
        """Print statistics"""
        uptime = time.time() - self.stats['start_time']

        # Calculate rates
        flows_per_sec = self.stats['flows_collected'] / uptime if uptime > 0 else 0
        collections_per_hour = (self.stats['collections'] / uptime) * 3600 if uptime > 0 else 0

        print("\n" + "=" * 70)
        print("NFStream Collector Agent Statistics")
        print("=" * 70)
        print(f"Status:                  {'Running' if self.running else 'Stopped'}")
        print(f"Uptime:                  {uptime:.0f}s ({uptime/60:.1f} minutes)")
        print(f"Collections:             {self.stats['collections']} ({collections_per_hour:.1f}/hour)")
        print(f"Flows collected:         {self.stats['flows_collected']} ({flows_per_sec:.2f}/sec)")
        print(f"Flows saved:             {self.stats['flows_saved']}")
        print(f"Output file:             {self.config.flows_output_file}")
        print("=" * 70 + "\n")

    def get_statistics(self) -> Dict:
        """Get statistics dictionary"""
        return {
            **self.stats,
            'uptime': time.time() - self.stats['start_time'],
        }


# Mock A2A collector for streaming
class MockA2ACollector:
    async def process_combined(self, combined_json):
        # Simulate streaming by printing as soon as received
        print("\n--- A2A STREAMED BATCH ---")
        print(json.dumps(combined_json, indent=2))
        print("--- END OF BATCH ---\n")


def get_available_interfaces() -> List[str]:
    """Get list of available network interfaces"""
    import psutil
    try:
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())
    except Exception as e:
        logger.warning(f"Could not enumerate network interfaces: {e}")
        return []


def validate_interface(interface_name: str) -> bool:
    """
    Validate that the specified network interface exists

    Args:
        interface_name: Name of the interface to validate

    Returns:
        True if interface exists, False otherwise
    """
    available = get_available_interfaces()
    return interface_name in available


async def run_agent(
    config_path: Path,
    interface: Optional[str],
    pcap: Optional[Path],
    interval: Optional[int],
    output: Optional[str]
):
    """Run the NFStream collector agent"""
    # Configure logging (always DEBUG)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    logger.info("=" * 80)
    logger.info("STEP 1: Initializing NFStream Collector Agent")
    logger.info("=" * 80)

    # Load configuration
    logger.debug(f"Checking for configuration file at: {config_path}")
    if config_path.exists():
        logger.info(f"Configuration file found: {config_path}")
        config = NFStreamAgentConfig.from_yaml(config_path)
        logger.info(f"✓ Loaded configuration from {config_path}")
    else:
        logger.info(f"No configuration file found at {config_path}")
        config = NFStreamAgentConfig()
        logger.info("✓ Using default configuration")

        # Save default config
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config.to_yaml(config_path)
        logger.info(f"✓ Saved default configuration to {config_path}")

    logger.info("\n" + "=" * 80)
    logger.info("STEP 2: Processing Command Line Arguments")
    logger.info("=" * 80)

    # Override with command line arguments
    if interface:
        logger.info(f"✓ Override interface: {interface}")
        config.capture_interface = interface
    if pcap:
        logger.info(f"✓ Override PCAP file: {pcap}")
        config.pcap_file = str(pcap)
    if interval:
        logger.info(f"✓ Override collection interval: {interval}s")
        config.collection_interval = interval
    if output:
        logger.info(f"✓ Override output file: {output}")
        config.flows_output_file = output

    logger.info("\n" + "=" * 80)
    logger.info("STEP 3: Validating Network Interface")
    logger.info("=" * 80)

    # Validate interface if specified
    if config.capture_interface:
        logger.debug(f"Validating interface: {config.capture_interface}")
        if not validate_interface(config.capture_interface):
            available = get_available_interfaces()
            logger.error(f"✗ Network interface '{config.capture_interface}' does not exist!")
            logger.error(f"Available interfaces: {', '.join(available) if available else 'None found'}")
            import sys
            sys.exit(1)
        logger.info(f"✓ Network interface '{config.capture_interface}' validated successfully")
    else:
        logger.info("No network interface specified (will use PCAP file)")

    logger.info("\n" + "=" * 80)
    logger.info("STEP 4: Creating NFStream Collector Agent")
    logger.info("=" * 80)

    # Create agent
    agent = NFStreamCollectorAgent(config)
    logger.info("✓ Agent created successfully")

    logger.info("\n" + "=" * 80)
    logger.info("STEP 5: Configuration Summary")
    logger.info("=" * 80)
    logger.info(f"Source: {config.pcap_file or config.capture_interface or 'Not specified'}")
    logger.info(f"Output: {config.flows_output_file}")
    logger.info(f"Collection interval: {config.collection_interval}s")
    logger.info(f"Batch size: {config.batch_size}")
    logger.info(f"Extract payload: {config.extract_payload}")
    logger.info(f"Max payload bytes: {config.max_payload_bytes}")
    logger.info(f"Statistical analysis: {config.statistical_analysis}")
    logger.info("Press Ctrl+C to stop gracefully")
    logger.info("=" * 80)

    logger.info("\n" + "=" * 80)
    logger.info("STEP 6: Initializing LLM Agent and A2A Collector")
    logger.info("=" * 80)

    try:
        # Create LLM agent (mock or real)
        logger.debug("Creating LLM Explanation Agent...")
        llm_agent = LLMExplanationAgent()  # You may need to pass API key/config
        logger.info("✓ LLM Explanation Agent created")

        logger.debug("Creating Mock A2A Collector...")
        a2a_collector = MockA2ACollector()
        logger.info("✓ Mock A2A Collector created")

        logger.info("\n" + "=" * 80)
        logger.info("STEP 7: Starting Flow Collection")
        logger.info("=" * 80)

        # Run agent with A2A collector
        await agent.run(llm_agent=llm_agent, a2a_collector=a2a_collector)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
        agent.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise
    finally:
        # Cleanup
        logger.info("\n" + "=" * 70)
        logger.info("Shutdown Complete - Final Statistics")
        logger.info("=" * 70)
        agent.print_statistics()

        logger.info("NFStream collector agent terminated")
        logger.info("=" * 70)


def cli():
    """CLI entry point using Typer"""
    import typer
    from typing_extensions import Annotated
    import sys

    # Check if a subcommand was provided
    if len(sys.argv) > 1 and sys.argv[1] == "list-interfaces":
        # Run list-interfaces command
        interfaces = get_available_interfaces()
        if interfaces:
            print("Available network interfaces:")
            print("=" * 50)
            for iface in interfaces:
                print(f"  • {iface}")
            print("=" * 50)
        else:
            print("No network interfaces found or unable to enumerate.")
        return

    # Otherwise, run the main collector
    app = typer.Typer(add_completion=False)

    @app.command()
    def main(
        config: Annotated[
            Path,
            typer.Option(
                "--config",
                "-c",
                help="Path to YAML configuration file",
                exists=False,
            )
        ] = Path("config/nfstream_agent.yaml"),
        interface: Annotated[
            Optional[str],
            typer.Option(
                "--interface",
                "-i",
                help="Network interface to capture from (e.g., eth0, wlan0)",
            )
        ] = None,
        pcap: Annotated[
            Optional[Path],
            typer.Option(
                "--pcap",
                "-p",
                help="PCAP file to process",
                exists=True,
            )
        ] = None,
        interval: Annotated[
            Optional[int],
            typer.Option(
                "--interval",
                "-t",
                help="Collection interval in seconds (save flows every N seconds)",
                min=1,
            )
        ] = None,
        output: Annotated[
            Optional[str],
            typer.Option(
                "--output",
                "-o",
                help="Output JSONL file path",
            )
        ] = None,
    ):
        """
        NFStream Flow Collector Agent for Network Flow Data Collection

        Collects network flows using NFStream library with nDPI deep packet inspection.
        Saves flows to JSONL file for offline analysis.

        \b
        Examples:
          # List available network interfaces
          nfstream-collector list-interfaces

          # Analyze PCAP file
          nfstream-collector --pcap traffic.pcap

          # Live capture on eth0 (requires root/sudo)
          sudo nfstream-collector --interface eth0

          # Custom output file
          nfstream-collector --pcap traffic.pcap --output my_flows.jsonl

          # Custom configuration
          nfstream-collector --pcap data/test.pcap --interval 60
        """
        asyncio.run(run_agent(config, interface, pcap, interval, output))

    app()


if __name__ == "__main__":
    cli()
