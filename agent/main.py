#!/usr/bin/env python3
"""
Main Integration Script: Agentic Network Intrusion Detection System

This is the main entry point for running the agentic NIDS with:
1. Classifier Agent (A2A server) - Classifies flows using ONNX ML models
2. nDPI Collector Agent (A2A client) - Collects flows and sends to classifier

Usage Examples:
    # Quick test with synthetic data
    python main.py --mode test

    # Analyze PCAP file
    python main.py --mode pcap --pcap data/traffic.pcap

    # Live capture from network interface
    sudo python main.py --mode live --interface eth0

    # Run only classifier agent
    python main.py --mode classifier

    # Run only collector agent (assumes classifier is already running)
    python main.py --mode collector --config config/ndpi_agent.yaml
"""

import asyncio
import logging
import sys
import signal
from pathlib import Path
from typing import Optional

from classifier_agent_a2a import FlowClassifierAgent, serve_a2a_agent
from ndpi_collector_agent import NDPICollectorAgent, NDPIAgentConfig

try:
    from client_a2a_example import SyntheticFlowGenerator
    from a2a.client.legacy import A2AClient
    from a2a.types import Message, DataPart
    A2A_AVAILABLE = True
except ImportError:
    A2A_AVAILABLE = False


logger = logging.getLogger(__name__)


class AgenticNIDS:
    """Main class for Agentic Network Intrusion Detection System"""

    def __init__(self):
        self.classifier_task: Optional[asyncio.Task] = None
        self.collector_task: Optional[asyncio.Task] = None
        self.running = False

    async def start_classifier(self, port: int = 50051, model_path: Optional[Path] = None):
        """Start the classifier agent"""
        logger.info(f"Starting classifier agent on port {port}")

        agent = FlowClassifierAgent(
            name="flow-classifier",
            description="Network flow classifier for agentic NIDS",
            model_path=model_path
        )

        await serve_a2a_agent(agent, host="0.0.0.0", port=port, use_grpc=True)

    async def start_collector(self, config: NDPIAgentConfig):
        """Start the nDPI collector agent"""
        logger.info("Starting nDPI collector agent")

        agent = NDPICollectorAgent(config)
        await agent.run()

    async def run_integrated(
        self,
        pcap_file: Optional[str] = None,
        interface: Optional[str] = None,
        collection_interval: int = 180,
        classifier_port: int = 50051,
        config_file: Optional[Path] = None
    ):
        """
        Run both classifier and collector together

        Args:
            pcap_file: PCAP file to analyze
            interface: Network interface to capture from
            collection_interval: Flow collection interval in seconds
            classifier_port: Port for classifier agent
            config_file: YAML configuration file
        """
        self.running = True

        # Load or create collector configuration
        if config_file and config_file.exists():
            config = NDPIAgentConfig.from_yaml(config_file)
            logger.info(f"Loaded configuration from {config_file}")
        else:
            config = NDPIAgentConfig(
                collection_interval=collection_interval,
                classifier_agent_url=f"grpc://localhost:{classifier_port}",
                pcap_file=pcap_file,
                capture_interface=interface,
                batch_size=50,
                enable_async_classification=True,
                max_concurrent_requests=20,
            )

        logger.info("=" * 70)
        logger.info("Agentic Network Intrusion Detection System")
        logger.info("=" * 70)
        logger.info(f"Mode: {'PCAP Analysis' if pcap_file else 'Live Capture' if interface else 'Test'}")
        if pcap_file:
            logger.info(f"PCAP file: {pcap_file}")
        if interface:
            logger.info(f"Interface: {interface}")
        logger.info(f"Collection interval: {config.collection_interval}s")
        logger.info(f"Classifier: {config.classifier_agent_url}")
        logger.info("=" * 70)

        try:
            # Start classifier agent
            self.classifier_task = asyncio.create_task(
                self.start_classifier(classifier_port)
            )

            # Wait for classifier to initialize
            await asyncio.sleep(3)
            logger.info("Classifier agent initialized")

            # Start collector agent
            self.collector_task = asyncio.create_task(
                self.start_collector(config)
            )

            # Wait for both tasks
            await asyncio.gather(self.classifier_task, self.collector_task)

        except asyncio.CancelledError:
            logger.info("Tasks cancelled")
        finally:
            self.running = False

    async def run_quick_test(self, classifier_port: int = 50051):
        """Run quick test with synthetic data"""
        if not A2A_AVAILABLE:
            logger.error("A2A SDK not available. Install with: pip install a2a-sdk")
            return

        logger.info("\n" + "=" * 70)
        logger.info("Quick Test Mode - Synthetic Data")
        logger.info("=" * 70)

        # Start classifier
        logger.info("Starting classifier agent...")
        self.classifier_task = asyncio.create_task(
            self.start_classifier(classifier_port)
        )
        await asyncio.sleep(3)

        # Test classification
        logger.info("Connecting to classifier...")
        client = A2AClient(f"grpc://localhost:{classifier_port}")

        # Generate and classify flows
        generator = SyntheticFlowGenerator()

        logger.info("\nClassifying synthetic flows...\n")
        malicious_count = 0

        for i in range(20):
            import random
            attack_type = random.choice(
                ["normal", "normal", "normal", "dos", "port_scan", "ddos", "brute_force"]
            )
            flow_data = generator.generate_flow(attack_type)

            # Classify
            message = Message(parts=[DataPart(data=flow_data)])
            result = await client.send_message(message)

            # Display result
            status_symbol = "⚠️ " if result['is_malicious'] else "✓ "
            logger.info(
                f"{status_symbol} [{i+1:2}/20] {flow_data['src_ip']:15} -> {flow_data['dst_ip']:15} | "
                f"{'MALICIOUS' if result['is_malicious'] else 'normal':10} | "
                f"{result['attack_type']:12} | "
                f"risk: {result['risk_level']:8} | "
                f"conf: {result['confidence']:.2f}"
            )

            if result['is_malicious']:
                malicious_count += 1
                logger.info(f"    └─ {result['explanation'][:100]}...")

        logger.info("\n" + "=" * 70)
        logger.info(f"Test Summary: {malicious_count}/20 malicious flows detected")
        logger.info("=" * 70)

        # Cancel classifier
        self.classifier_task.cancel()

    def stop(self):
        """Stop all agents"""
        logger.info("Stopping agents...")
        self.running = False

        if self.classifier_task and not self.classifier_task.done():
            self.classifier_task.cancel()

        if self.collector_task and not self.collector_task.done():
            self.collector_task.cancel()


async def main_async(args):
    """Async main function"""
    nids = AgenticNIDS()

    # Setup signal handlers
    def signal_handler(sig, frame):
        logger.info("\nReceived interrupt signal, shutting down...")
        nids.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        if args.mode == "test":
            # Quick test mode
            await nids.run_quick_test(args.port)

        elif args.mode == "classifier":
            # Run only classifier
            await nids.start_classifier(args.port, args.model)

        elif args.mode == "collector":
            # Run only collector
            if not args.config:
                logger.error("--config required for collector mode")
                return

            config = NDPIAgentConfig.from_yaml(Path(args.config))
            await nids.start_collector(config)

        elif args.mode in ["pcap", "live", "integrated"]:
            # Run full integration
            await nids.run_integrated(
                pcap_file=args.pcap,
                interface=args.interface,
                collection_interval=args.interval,
                classifier_port=args.port,
                config_file=Path(args.config) if args.config else None
            )

        else:
            logger.error(f"Unknown mode: {args.mode}")

    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        raise
    finally:
        nids.stop()


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Agentic Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick test with synthetic data
  python main.py --mode test

  # Analyze PCAP file
  python main.py --mode pcap --pcap data/traffic.pcap --interval 60

  # Live capture
  sudo python main.py --mode live --interface eth0 --interval 180

  # Run only classifier (in one terminal)
  python main.py --mode classifier --port 50051

  # Run only collector (in another terminal)
  python main.py --mode collector --config config/ndpi_agent.yaml

Configuration:
  Edit config/ndpi_agent.yaml to customize:
  - Collection interval (default: 3 minutes)
  - Classifier URL
  - Alert thresholds
  - Output settings
        """
    )

    parser.add_argument(
        "--mode",
        choices=["test", "pcap", "live", "integrated", "classifier", "collector"],
        default="test",
        help="Operation mode (default: test)"
    )
    parser.add_argument(
        "--config",
        type=str,
        help="YAML configuration file"
    )
    parser.add_argument(
        "--pcap",
        type=str,
        help="PCAP file to analyze"
    )
    parser.add_argument(
        "--interface",
        type=str,
        help="Network interface for live capture"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=180,
        help="Collection interval in seconds (default: 180)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=50051,
        help="Classifier agent port (default: 50051)"
    )
    parser.add_argument(
        "--model",
        type=Path,
        help="Path to ONNX model file"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.mode == "pcap" and not args.pcap:
        parser.error("--pcap required for pcap mode")
    if args.mode == "live" and not args.interface:
        parser.error("--interface required for live mode")
    if args.mode == "collector" and not args.config:
        parser.error("--config required for collector mode")

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Run
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        logger.info("\nShutdown complete")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
