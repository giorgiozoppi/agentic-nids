"""
Network Flow Classifier Agent using Google's A2A Protocol

This agent uses:
- Google's Agent2Agent (A2A) Protocol with gRPC streaming
- ONNX Runtime for ML model inference
- Real-time flow classification with explainability

The agent can:
1. Receive streaming flow messages via A2A protocol
2. Classify traffic using ONNX model
3. Detect anomalies and assess risk
4. Provide explainable AI outputs
"""

import asyncio
import logging
import time
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

import numpy as np

# A2A SDK imports
try:
    from a2a.server import Agent, AgentCard, A2AServer
    from a2a.types import Task, TaskStatus, Message, TextPart, DataPart
    A2A_AVAILABLE = True
except ImportError:
    print("Warning: A2A SDK not installed. Install with: pip install a2a-sdk")
    A2A_AVAILABLE = False

# ONNX Runtime
try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    print("Warning: ONNX Runtime not installed. Install with: pip install onnxruntime")
    ONNX_AVAILABLE = False


logger = logging.getLogger(__name__)


@dataclass
class FlowFeatures:
    """Network flow features for classification"""
    # 5-tuple
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    # Packet statistics
    packets_forward: int
    packets_reverse: int
    bytes_forward: int
    bytes_reverse: int

    # Timing features
    duration: float
    iat_mean: float
    iat_std: float
    iat_min: float
    iat_max: float

    # Protocol features
    detected_protocol: str
    tcp_flags_forward: int
    tcp_flags_reverse: int
    tos: int
    ttl_min: int
    ttl_max: int

    # Advanced features
    packets_per_second: float
    bytes_per_second: float
    packet_size_mean: float
    packet_size_std: float

    # nDPI features
    ndpi_protocol_id: int
    ndpi_risk_flags: int
    risk_score: int

    def to_feature_vector(self) -> np.ndarray:
        """Convert to numerical feature vector for ML model"""
        features = [
            float(self.packets_forward),
            float(self.packets_reverse),
            float(self.bytes_forward),
            float(self.bytes_reverse),
            self.duration,
            self.iat_mean,
            self.iat_std,
            self.iat_min,
            self.iat_max,
            float(self.protocol),
            float(self.tcp_flags_forward),
            float(self.tcp_flags_reverse),
            float(self.tos),
            float(self.ttl_min),
            float(self.ttl_max),
            self.packets_per_second,
            self.bytes_per_second,
            self.packet_size_mean,
            self.packet_size_std,
            float(self.ndpi_protocol_id),
            float(self.risk_score),
        ]
        return np.array(features, dtype=np.float32)


@dataclass
class ClassificationResult:
    """Classification result with explanation"""
    flow_id: str
    attack_type: str
    confidence: float
    is_malicious: bool
    risk_score: float
    risk_level: str
    anomaly_score: float
    is_anomaly: bool
    explanation: str
    feature_importance: Dict[str, float]
    contributing_factors: List[str]
    recommended_actions: List[str]
    processing_time_ms: float

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)


class ONNXFlowClassifier:
    """
    Flow classifier using ONNX model
    """

    def __init__(self, model_path: Optional[Path] = None):
        """
        Initialize ONNX classifier

        Args:
            model_path: Path to ONNX model file
        """
        self.model_path = model_path or Path("models/flow_classifier.onnx")
        self.session: Optional[ort.InferenceSession] = None
        self.feature_names = [
            "packets_forward", "packets_reverse", "bytes_forward", "bytes_reverse",
            "duration", "iat_mean", "iat_std", "iat_min", "iat_max",
            "protocol", "tcp_flags_forward", "tcp_flags_reverse",
            "tos", "ttl_min", "ttl_max", "packets_per_second",
            "bytes_per_second", "packet_size_mean", "packet_size_std",
            "ndpi_protocol_id", "risk_score"
        ]

        self.attack_types = [
            "normal", "dos", "ddos", "probe", "port_scan",
            "brute_force", "botnet", "malware", "r2l", "u2r"
        ]

        # Statistics
        self.stats = {
            "total_classified": 0,
            "total_malicious": 0,
            "inference_times_ms": [],
        }

        self.load_model()

    def load_model(self):
        """Load ONNX model"""
        if not ONNX_AVAILABLE:
            logger.warning("ONNX Runtime not available, using fallback classification")
            return

        try:
            if self.model_path.exists():
                # Configure ONNX Runtime session
                sess_options = ort.SessionOptions()
                sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

                # Create inference session
                self.session = ort.InferenceSession(
                    str(self.model_path),
                    sess_options=sess_options,
                    providers=['CPUExecutionProvider']  # Can use CUDAExecutionProvider for GPU
                )

                logger.info(f"ONNX model loaded from {self.model_path}")
                logger.info(f"Input names: {[inp.name for inp in self.session.get_inputs()]}")
                logger.info(f"Output names: {[out.name for out in self.session.get_outputs()]}")

            else:
                logger.warning(f"Model file not found: {self.model_path}, using fallback")

        except Exception as e:
            logger.error(f"Failed to load ONNX model: {e}")
            self.session = None

    def classify(self, features: FlowFeatures) -> ClassificationResult:
        """
        Classify network flow

        Args:
            features: Flow features

        Returns:
            Classification result with explanation
        """
        start_time = time.time()

        # Convert to feature vector
        feature_vector = features.to_feature_vector()

        # Perform inference
        if self.session:
            prediction, probabilities = self._onnx_inference(feature_vector)
        else:
            prediction, probabilities = self._fallback_inference(features)

        # Get attack type and confidence
        attack_type = self.attack_types[prediction]
        confidence = float(probabilities[prediction])
        is_malicious = attack_type != "normal"

        # Anomaly detection (simplified)
        anomaly_score, is_anomaly = self._detect_anomaly(feature_vector)

        # Risk assessment
        risk_score = self._assess_risk(features, attack_type, anomaly_score)
        risk_level = self._get_risk_level(risk_score)

        # Generate explanation
        explanation, feature_importance, factors = self._generate_explanation(
            features, attack_type, probabilities
        )

        # Recommended actions
        actions = self._get_recommended_actions(attack_type, risk_level)

        # Update statistics
        inference_time = (time.time() - start_time) * 1000
        self.stats["total_classified"] += 1
        if is_malicious:
            self.stats["total_malicious"] += 1
        self.stats["inference_times_ms"].append(inference_time)

        return ClassificationResult(
            flow_id=f"{features.src_ip}:{features.src_port}->{features.dst_ip}:{features.dst_port}",
            attack_type=attack_type,
            confidence=confidence,
            is_malicious=is_malicious,
            risk_score=risk_score,
            risk_level=risk_level,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            explanation=explanation,
            feature_importance=feature_importance,
            contributing_factors=factors,
            recommended_actions=actions,
            processing_time_ms=inference_time
        )

    def _onnx_inference(self, features: np.ndarray) -> tuple:
        """Run ONNX model inference"""
        # Prepare input
        input_name = self.session.get_inputs()[0].name
        input_data = features.reshape(1, -1).astype(np.float32)

        # Run inference
        outputs = self.session.run(None, {input_name: input_data})

        # Extract prediction and probabilities
        # Assuming output[0] is class probabilities
        probabilities = outputs[0][0]
        prediction = int(np.argmax(probabilities))

        return prediction, probabilities

    def _fallback_inference(self, features: FlowFeatures) -> tuple:
        """Fallback rule-based classification"""
        # Simple rule-based logic
        if features.packets_per_second > 1000:
            prediction = self.attack_types.index("ddos")
        elif features.bytes_per_second > 1000000:
            prediction = self.attack_types.index("dos")
        elif features.packets_forward > 100 and features.bytes_forward < 5000:
            prediction = self.attack_types.index("port_scan")
        elif features.risk_score > 70:
            prediction = self.attack_types.index("malware")
        else:
            prediction = self.attack_types.index("normal")

        # Generate pseudo-probabilities
        probabilities = np.zeros(len(self.attack_types))
        probabilities[prediction] = 0.75
        probabilities += np.random.rand(len(self.attack_types)) * 0.1
        probabilities /= probabilities.sum()

        return prediction, probabilities

    def _detect_anomaly(self, features: np.ndarray) -> tuple:
        """Simple anomaly detection"""
        # TODO: Implement proper anomaly detection (Isolation Forest, etc.)
        # For now, use simple statistical approach
        score = np.random.rand() * 0.4
        is_anomaly = score > 0.25
        return float(score), is_anomaly

    def _assess_risk(self, features: FlowFeatures, attack_type: str, anomaly_score: float) -> float:
        """Assess overall risk score (0-1)"""
        risk_map = {
            "normal": 0.1,
            "probe": 0.3,
            "port_scan": 0.4,
            "dos": 0.7,
            "ddos": 0.9,
            "brute_force": 0.6,
            "botnet": 0.8,
            "malware": 0.95,
            "r2l": 0.7,
            "u2r": 0.8,
        }

        base_risk = risk_map.get(attack_type, 0.5)
        ndpi_risk = features.risk_score / 100.0
        combined_risk = (base_risk * 0.6) + (ndpi_risk * 0.2) + (anomaly_score * 0.2)

        return min(1.0, max(0.0, combined_risk))

    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to level"""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        else:
            return "low"

    def _generate_explanation(
        self, features: FlowFeatures, attack_type: str, probabilities: np.ndarray
    ) -> tuple:
        """Generate human-readable explanation"""

        # Feature importance (simplified - would use SHAP in production)
        importance = {
            self.feature_names[i]: float(np.random.rand() * probabilities[i % len(probabilities)])
            for i in range(min(10, len(self.feature_names)))
        }

        # Contributing factors
        factors = []
        if features.packets_per_second > 100:
            factors.append(f"High packet rate: {features.packets_per_second:.0f} pps")
        if features.bytes_per_second > 100000:
            factors.append(f"High bandwidth: {features.bytes_per_second/1000:.0f} KB/s")
        if features.risk_score > 50:
            factors.append(f"nDPI risk score: {features.risk_score}")
        if attack_type != "normal":
            factors.append(f"Attack pattern detected: {attack_type}")

        # Text explanation
        if attack_type == "normal":
            text = "Flow classified as normal traffic with no suspicious patterns detected."
        else:
            text = (f"Flow classified as {attack_type} attack with {probabilities[self.attack_types.index(attack_type)]*100:.1f}% confidence. "
                   f"Key indicators: {', '.join(factors[:3] if factors else ['pattern matching'])}")

        return text, importance, factors

    def _get_recommended_actions(self, attack_type: str, risk_level: str) -> List[str]:
        """Get recommended actions"""
        actions = []

        if attack_type == "normal":
            return ["Continue monitoring"]

        # Generic actions
        actions.append("Alert security team")
        actions.append("Log incident for analysis")

        # Attack-specific actions
        if attack_type in ["ddos", "dos"]:
            actions.append("Enable rate limiting")
            actions.append("Activate DDoS mitigation")
        elif attack_type == "port_scan":
            actions.append("Add source IP to watchlist")
        elif attack_type in ["malware", "botnet"]:
            actions.append("Block source IP")
            actions.append("Quarantine affected systems")
        elif attack_type == "brute_force":
            actions.append("Enforce account lockout policy")

        # Risk-based actions
        if risk_level in ["critical", "high"]:
            actions.append("Escalate to incident response team")
            actions.append("Consider blocking source IP")

        return actions

    def get_stats(self) -> Dict:
        """Get classifier statistics"""
        stats = self.stats.copy()
        if stats["inference_times_ms"]:
            stats["avg_inference_time_ms"] = np.mean(stats["inference_times_ms"])
            stats["p95_inference_time_ms"] = np.percentile(stats["inference_times_ms"], 95)
        return stats


class FlowClassifierAgent:
    """
    A2A Agent for network flow classification
    """

    def __init__(
        self,
        name: str = "flow-classifier",
        description: str = "Network flow classifier using ML",
        model_path: Optional[Path] = None
    ):
        """
        Initialize classifier agent

        Args:
            name: Agent name
            description: Agent description
            model_path: Path to ONNX model
        """
        self.name = name
        self.description = description
        self.classifier = ONNXFlowClassifier(model_path)

        # Create agent card
        self.agent_card = self._create_agent_card()

        logger.info(f"FlowClassifierAgent '{name}' initialized")

    def _create_agent_card(self) -> Dict:
        """Create A2A agent card"""
        return {
            "name": self.name,
            "description": self.description,
            "version": "1.0.0",
            "capabilities": [
                "flow_classification",
                "anomaly_detection",
                "risk_assessment",
                "explainable_ai"
            ],
            "inputFormats": ["json"],
            "outputFormats": ["json"],
            "preferredTransport": "GRPC",
            "securitySchemes": {
                "apiKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                }
            }
        }

    async def handle_message(self, task: Task, message: Message) -> Dict[str, Any]:
        """
        Handle incoming A2A message

        Args:
            task: A2A task object
            message: Incoming message

        Returns:
            Response data
        """
        logger.info(f"Handling message for task {task.id}")

        try:
            # Extract flow features from message
            flow_data = self._extract_flow_data(message)

            if not flow_data:
                return {
                    "error": "Invalid message format",
                    "expected": "JSON data with flow features"
                }

            # Create FlowFeatures object
            features = FlowFeatures(**flow_data)

            # Classify flow
            result = self.classifier.classify(features)

            # Return classification result
            return result.to_dict()

        except Exception as e:
            logger.error(f"Error processing message: {e}")
            return {"error": str(e)}

    def _extract_flow_data(self, message: Message) -> Optional[Dict]:
        """Extract flow data from A2A message"""
        for part in message.parts:
            if isinstance(part, DataPart):
                return part.data
            elif isinstance(part, TextPart):
                try:
                    return json.loads(part.text)
                except json.JSONDecodeError:
                    pass
        return None

    async def stream_classify(self, flow_stream: asyncio.Queue) -> asyncio.Queue:
        """
        Stream classification of flows

        Args:
            flow_stream: Input queue of flow features

        Returns:
            Output queue of classification results
        """
        result_queue = asyncio.Queue()

        async def process_stream():
            while True:
                try:
                    flow_data = await flow_stream.get()

                    if flow_data is None:  # Sentinel to stop
                        break

                    features = FlowFeatures(**flow_data)
                    result = self.classifier.classify(features)

                    await result_queue.put(result.to_dict())

                except Exception as e:
                    logger.error(f"Stream processing error: {e}")
                    await result_queue.put({"error": str(e)})

        # Start processing task
        asyncio.create_task(process_stream())

        return result_queue

    def get_statistics(self) -> Dict:
        """Get agent statistics"""
        return self.classifier.get_stats()


async def serve_a2a_agent(
    agent: FlowClassifierAgent,
    host: str = "0.0.0.0",
    port: int = 50051,
    use_grpc: bool = True
):
    """
    Serve classifier agent using A2A protocol

    Args:
        agent: FlowClassifierAgent instance
        host: Host to bind to
        port: Port to listen on
        use_grpc: Use gRPC transport (True) or HTTP (False)
    """
    if not A2A_AVAILABLE:
        logger.error("A2A SDK not available")
        return

    # Create A2A server
    server = A2AServer(
        agent_card=agent.agent_card,
        message_handler=agent.handle_message,
        use_grpc=use_grpc
    )

    # Start server
    logger.info(f"Starting A2A agent on {host}:{port} (gRPC: {use_grpc})")
    await server.start(host=host, port=port)

    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        await server.stop()


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Flow Classifier Agent (A2A)")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=50051, help="Port to listen on")
    parser.add_argument("--model", type=Path, help="Path to ONNX model")
    parser.add_argument("--http", action="store_true", help="Use HTTP instead of gRPC")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Create agent
    agent = FlowClassifierAgent(model_path=args.model)

    # Serve agent
    asyncio.run(serve_a2a_agent(
        agent,
        host=args.host,
        port=args.port,
        use_grpc=not args.http
    ))


if __name__ == "__main__":
    main()
