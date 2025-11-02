#!/usr/bin/env python3
"""
nDPI Flow Collector Agent with A2A Protocol Integration

This agent:
1. Collects network flows using nDPI traffic aggregator
2. Aggregates flows based on configurable time windows
3. Sends flows to classifier agent via A2A protocol
4. Processes classification results and takes actions
5. Supports PCAP files and live capture
"""

import asyncio
import logging
import time
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import signal
from a2a_sdk import A2AClient, Message, DataPart
import scapy.all as scapy


logger = logging.getLogger(__name__)


@dataclass
class NDPIAgentConfig:
    """Configuration for nDPI collector agent"""

    # Collection settings
    collection_interval: int = 180  # 3 minutes in seconds
    flow_idle_timeout: int = 300
    flow_active_timeout: int = 1800
    max_flows: int = 100000

    # Classifier agent settings
    classifier_agent_url: str = "grpc://localhost:50051"
    classifier_timeout: int = 30
    batch_size: int = 100

    # Capture settings
    capture_interface: Optional[str] = None
    pcap_file: Optional[str] = None
    bpf_filter: Optional[str] = None

    # Processing settings
    enable_async_classification: bool = True
    max_concurrent_requests: int = 10
    retry_attempts: int = 3
    retry_delay: int = 5

    # Action settings
    alert_threshold: float = 0.7  # Risk score threshold for alerts
    auto_block: bool = False
    alert_webhook: Optional[str] = None

    # Output settings
    log_file: Optional[str] = None
    results_file: Optional[str] = "classification_results.json"
    save_malicious_flows: bool = True

    # Performance settings
    stats_interval: int = 60  # Print stats every minute

    @classmethod
    def from_yaml(cls, yaml_path: Path) -> 'NDPIAgentConfig':
        """Load configuration from YAML file"""
        with open(yaml_path, 'r') as f:
            config_dict = yaml.safe_load(f)

        return cls(**config_dict)

    def to_yaml(self, yaml_path: Path):
        """Save configuration to YAML file"""
        config_dict = {
            'collection_interval': self.collection_interval,
            'flow_idle_timeout': self.flow_idle_timeout,
            'flow_active_timeout': self.flow_active_timeout,
            'max_flows': self.max_flows,
            'classifier_agent_url': self.classifier_agent_url,
            'classifier_timeout': self.classifier_timeout,
            'batch_size': self.batch_size,
            'capture_interface': self.capture_interface,
            'pcap_file': self.pcap_file,
            'bpf_filter': self.bpf_filter,
            'enable_async_classification': self.enable_async_classification,
            'max_concurrent_requests': self.max_concurrent_requests,
            'retry_attempts': self.retry_attempts,
            'retry_delay': self.retry_delay,
            'alert_threshold': self.alert_threshold,
            'auto_block': self.auto_block,
            'alert_webhook': self.alert_webhook,
            'log_file': self.log_file,
            'results_file': self.results_file,
            'save_malicious_flows': self.save_malicious_flows,
            'stats_interval': self.stats_interval,
        }

        with open(yaml_path, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)


@dataclass
class FlowRecord:
    """Network flow record"""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    packets_forward: int = 0
    packets_reverse: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0

    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    detected_protocol: str = "Unknown"
    ndpi_protocol_id: int = 0
    tcp_flags_forward: int = 0
    tcp_flags_reverse: int = 0
    tos: int = 0
    ttl_min: int = 255
    ttl_max: int = 0
    risk_score: int = 0
    ndpi_risk_flags: int = 0

    def to_dict(self) -> Dict:
        """Convert to dictionary for A2A message"""
        duration = max(0.001, self.last_seen - self.first_seen)
        total_packets = self.packets_forward + self.packets_reverse
        total_bytes = self.bytes_forward + self.bytes_reverse

        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'packets_forward': self.packets_forward,
            'packets_reverse': self.packets_reverse,
            'bytes_forward': self.bytes_forward,
            'bytes_reverse': self.bytes_reverse,
            'duration': duration,
            'iat_mean': duration / total_packets if total_packets > 0 else 0,
            'iat_std': 0.01,  # Simplified - would calculate actual
            'iat_min': 0.001,
            'iat_max': duration / 2,
            'detected_protocol': self.detected_protocol,
            'tcp_flags_forward': self.tcp_flags_forward,
            'tcp_flags_reverse': self.tcp_flags_reverse,
            'tos': self.tos,
            'ttl_min': self.ttl_min,
            'ttl_max': self.ttl_max,
            'packets_per_second': total_packets / duration,
            'bytes_per_second': total_bytes / duration,
            'packet_size_mean': total_bytes / total_packets if total_packets > 0 else 0,
            'packet_size_std': 100.0,  # Simplified
            'ndpi_protocol_id': self.ndpi_protocol_id,
            'ndpi_risk_flags': self.ndpi_risk_flags,
            'risk_score': self.risk_score,
        }


class FlowCollector:
    """Collects and manages network flows"""

    def __init__(self, config: NDPIAgentConfig):
        self.config = config
        self.flows: Dict[str, FlowRecord] = {}
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'active_flows': 0,
            'flows_exported': 0,
        }

    def process_packet(self, packet):
        """Process a single packet and update flows"""

        try:
            if scapy.IP not in packet:
                return

            ip_layer = packet[scapy.IP]

            # Extract flow key
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            src_port = 0
            dst_port = 0

            if scapy.TCP in packet:
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
            elif scapy.UDP in packet:
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport

            flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"

            # Get or create flow
            if flow_key not in self.flows:
                self.flows[flow_key] = FlowRecord(
                    flow_id=flow_key,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol
                )
                self.stats['total_flows'] += 1

            flow = self.flows[flow_key]

            # Update flow statistics
            flow.last_seen = time.time()
            flow.packets_forward += 1
            flow.bytes_forward += len(packet)

            # Extract additional info
            if scapy.TCP in packet:
                flags = packet[scapy.TCP].flags
                flow.tcp_flags_forward |= int(flags)

            flow.tos = ip_layer.tos if hasattr(ip_layer, 'tos') else 0
            flow.ttl_min = min(flow.ttl_min, ip_layer.ttl)
            flow.ttl_max = max(flow.ttl_max, ip_layer.ttl)

            # Simple protocol detection
            flow.detected_protocol = self._detect_protocol(packet, dst_port)

            self.stats['total_packets'] += 1
            self.stats['active_flows'] = len(self.flows)

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _detect_protocol(self, packet, dst_port: int) -> str:
        """Simple protocol detection"""
        protocol_map = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            21: "FTP",
            25: "SMTP",
            53: "DNS",
            3306: "MySQL",
            5432: "PostgreSQL",
        }
        return protocol_map.get(dst_port, "Unknown")

    def get_flows_to_export(self) -> List[FlowRecord]:
        """Get all flows ready for export"""
        flows = list(self.flows.values())
        self.stats['flows_exported'] += len(flows)
        return flows

    def clear_flows(self):
        """Clear all flows after export"""
        self.flows.clear()
        self.stats['active_flows'] = 0


class NDPICollectorAgent:
    """
    Main nDPI collector agent with A2A integration
    """

    def __init__(self, config: NDPIAgentConfig):
        """Initialize nDPI collector agent"""
        self.config = config
        self.collector = FlowCollector(config)
        self.classifier_client: Optional[A2AClient] = None
        self.running = False

        # Statistics
        self.stats = {
            'collections': 0,
            'flows_classified': 0,
            'malicious_detected': 0,
            'classification_errors': 0,
            'start_time': time.time(),
        }

        # Results storage
        self.classification_results: List[Dict] = []
        self.malicious_flows: List[Dict] = []

        logger.info(f"nDPI Collector Agent initialized")
        logger.info(f"Collection interval: {config.collection_interval}s")
        logger.info(f"Classifier agent: {config.classifier_agent_url}")

    async def initialize(self):
        """Initialize agent and connect to classifier"""

        # Connect to classifier agent
        logger.info(f"Connecting to classifier agent at {self.config.classifier_agent_url}")
        self.classifier_client = A2AClient(self.config.classifier_agent_url)

        # Test connection
        try:
            agent_card = await self.classifier_client.get_agent_card()
            logger.info(f"Connected to classifier: {agent_card.get('name')}")
            logger.info(f"Capabilities: {agent_card.get('capabilities')}")
        except Exception as e:
            logger.error(f"Failed to connect to classifier: {e}")
            raise

    async def classify_flow(self, flow: FlowRecord) -> Optional[Dict]:
        """
        Classify a single flow via A2A protocol

        Args:
            flow: Flow record to classify

        Returns:
            Classification result or None on error
        """
        for attempt in range(self.config.retry_attempts):
            try:
                # Create A2A message with flow data
                message = Message(parts=[DataPart(data=flow.to_dict())])

                # Send to classifier agent
                result = await asyncio.wait_for(
                    self.classifier_client.send_message(message),
                    timeout=self.config.classifier_timeout
                )

                # Add flow ID to result
                result['flow_id'] = flow.flow_id
                result['timestamp'] = datetime.now().isoformat()

                return result

            except asyncio.TimeoutError:
                logger.warning(f"Classification timeout for flow {flow.flow_id} (attempt {attempt+1})")
                if attempt < self.config.retry_attempts - 1:
                    await asyncio.sleep(self.config.retry_delay)
            except Exception as e:
                logger.error(f"Classification error: {e}")
                self.stats['classification_errors'] += 1
                if attempt < self.config.retry_attempts - 1:
                    await asyncio.sleep(self.config.retry_delay)

        return None

    async def classify_flows_batch(self, flows: List[FlowRecord]) -> List[Dict]:
        """
        Classify multiple flows in batch

        Args:
            flows: List of flow records

        Returns:
            List of classification results
        """
        results = []

        if self.config.enable_async_classification:
            # Async classification with concurrency limit
            semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)

            async def classify_with_semaphore(flow):
                async with semaphore:
                    return await self.classify_flow(flow)

            tasks = [classify_with_semaphore(flow) for flow in flows]
            results = await asyncio.gather(*tasks)
            results = [r for r in results if r is not None]
        else:
            # Sequential classification
            for flow in flows:
                result = await self.classify_flow(flow)
                if result:
                    results.append(result)

        return results

    async def process_classification_results(self, results: List[Dict]):
        """
        Process classification results and take actions

        Args:
            results: List of classification results
        """
        for result in results:
            # Store result
            self.classification_results.append(result)
            self.stats['flows_classified'] += 1

            # Check if malicious
            if result.get('is_malicious', False):
                self.stats['malicious_detected'] += 1

                # Store malicious flow
                if self.config.save_malicious_flows:
                    self.malicious_flows.append(result)

                # Log alert
                logger.warning(
                    f"MALICIOUS FLOW DETECTED: {result['flow_id']} - "
                    f"Type: {result['attack_type']}, "
                    f"Risk: {result['risk_level']}, "
                    f"Confidence: {result['confidence']:.2f}"
                )

                # Check alert threshold
                if result.get('risk_score', 0) >= self.config.alert_threshold:
                    await self.handle_high_risk_flow(result)

    async def handle_high_risk_flow(self, result: Dict):
        """
        Handle high-risk flow detection

        Args:
            result: Classification result
        """
        logger.critical(
            f"HIGH RISK FLOW: {result['flow_id']} - "
            f"Risk score: {result['risk_score']:.2f}"
        )

        # Log recommended actions
        logger.info(f"Recommended actions: {result.get('recommended_actions', [])}")

        # Auto-block if enabled
        if self.config.auto_block:
            await self.block_flow(result)

        # Send webhook alert
        if self.config.alert_webhook:
            await self.send_webhook_alert(result)

    async def block_flow(self, result: Dict):
        """Block malicious flow (stub - implement actual blocking)"""
        # Extract source IP from flow_id
        flow_id = result['flow_id']
        src_ip = flow_id.split(':')[0] if ':' in flow_id else "unknown"

        logger.warning(f"AUTO-BLOCK: Would block source IP {src_ip}")
        # TODO: Implement actual firewall rule addition

    async def send_webhook_alert(self, result: Dict):
        """Send webhook alert (stub)"""
        logger.info(f"WEBHOOK: Sending alert to {self.config.alert_webhook}")
        # TODO: Implement actual webhook POST

    async def collection_loop(self):
        """Main collection and classification loop"""
        logger.info(f"Starting collection loop (interval: {self.config.collection_interval}s)")

        while self.running:
            try:
                # Wait for collection interval
                await asyncio.sleep(self.config.collection_interval)

                # Get flows to export
                flows = self.collector.get_flows_to_export()

                if not flows:
                    logger.info("No flows to classify")
                    continue

                logger.info(f"Collected {len(flows)} flows for classification")
                self.stats['collections'] += 1

                # Classify flows in batches
                all_results = []
                for i in range(0, len(flows), self.config.batch_size):
                    batch = flows[i:i + self.config.batch_size]
                    logger.info(f"Classifying batch {i//self.config.batch_size + 1} ({len(batch)} flows)")

                    results = await self.classify_flows_batch(batch)
                    all_results.extend(results)

                # Process results
                await self.process_classification_results(all_results)

                # Clear flows after classification
                self.collector.clear_flows()

                # Save results
                await self.save_results()

            except Exception as e:
                logger.error(f"Error in collection loop: {e}")

    async def stats_loop(self):
        """Periodic statistics reporting"""
        while self.running:
            await asyncio.sleep(self.config.stats_interval)
            self.print_statistics()

    async def capture_packets(self):
        """Capture packets from interface or PCAP file"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available for packet capture")
            return

        if self.config.pcap_file:
            # Read from PCAP file
            logger.info(f"Reading PCAP file: {self.config.pcap_file}")
            packets = scapy.rdpcap(self.config.pcap_file)
            for packet in packets:
                if not self.running:
                    break
                self.collector.process_packet(packet)
        elif self.config.capture_interface:
            # Live capture
            logger.info(f"Starting live capture on {self.config.capture_interface}")

            def packet_handler(packet):
                if self.running:
                    self.collector.process_packet(packet)

            scapy.sniff(
                iface=self.config.capture_interface,
                prn=packet_handler,
                filter=self.config.bpf_filter,
                store=False,
                stop_filter=lambda x: not self.running
            )
        else:
            logger.error("No capture source specified (interface or PCAP file)")

    async def run(self):
        """Run the nDPI collector agent"""
        self.running = True

        # Initialize
        await self.initialize()

        # Start tasks
        tasks = [
            asyncio.create_task(self.collection_loop()),
            asyncio.create_task(self.stats_loop()),
        ]

        # Start packet capture in background thread
        if self.config.pcap_file or self.config.capture_interface:
            import threading
            capture_thread = threading.Thread(target=self.capture_packets)
            capture_thread.daemon = True
            capture_thread.start()

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Agent tasks cancelled")
        finally:
            self.running = False

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping nDPI collector agent")
        self.running = False

    async def save_results(self):
        """Save classification results to file"""
        if self.config.results_file:
            import json
            try:
                with open(self.config.results_file, 'w') as f:
                    json.dump({
                        'timestamp': datetime.now().isoformat(),
                        'stats': self.get_statistics(),
                        'results': self.classification_results[-100:],  # Last 100 results
                        'malicious_flows': self.malicious_flows[-50:],  # Last 50 malicious
                    }, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save results: {e}")

    def print_statistics(self):
        """Print statistics"""
        uptime = time.time() - self.stats['start_time']

        print("\n" + "=" * 70)
        print("nDPI Collector Agent Statistics")
        print("=" * 70)
        print(f"Uptime:                  {uptime:.0f}s")
        print(f"Collections:             {self.stats['collections']}")
        print(f"Total packets:           {self.collector.stats['total_packets']}")
        print(f"Total flows:             {self.collector.stats['total_flows']}")
        print(f"Active flows:            {self.collector.stats['active_flows']}")
        print(f"Flows classified:        {self.stats['flows_classified']}")
        print(f"Malicious detected:      {self.stats['malicious_detected']}")
        print(f"Classification errors:   {self.stats['classification_errors']}")
        print("=" * 70 + "\n")

    def get_statistics(self) -> Dict:
        """Get statistics dictionary"""
        return {
            **self.stats,
            **self.collector.stats,
            'uptime': time.time() - self.stats['start_time'],
        }


async def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="nDPI Flow Collector Agent with A2A")
    parser.add_argument(
        "--config",
        type=Path,
        default="config/ndpi_agent.yaml",
        help="Path to YAML configuration file"
    )
    parser.add_argument("--interface", help="Network interface to capture from")
    parser.add_argument("--pcap", type=Path, help="PCAP file to process")
    parser.add_argument("--interval", type=int, help="Collection interval in seconds")
    parser.add_argument("--classifier", help="Classifier agent URL")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        filename=None  # Will be set from config
    )

    # Load configuration
    if args.config.exists():
        config = NDPIAgentConfig.from_yaml(args.config)
        logger.info(f"Loaded configuration from {args.config}")
    else:
        config = NDPIAgentConfig()
        logger.info("Using default configuration")

        # Save default config
        args.config.parent.mkdir(parents=True, exist_ok=True)
        config.to_yaml(args.config)
        logger.info(f"Saved default configuration to {args.config}")

    # Override with command line arguments
    if args.interface:
        config.capture_interface = args.interface
    if args.pcap:
        config.pcap_file = str(args.pcap)
    if args.interval:
        config.collection_interval = args.interval
    if args.classifier:
        config.classifier_agent_url = args.classifier

    # Create and run agent
    agent = NDPICollectorAgent(config)

    # Handle signals
    def signal_handler(sig, frame):
        logger.info("Received interrupt signal")
        agent.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        await agent.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        agent.print_statistics()
        await agent.save_results()


if __name__ == "__main__":
    asyncio.run(main())
