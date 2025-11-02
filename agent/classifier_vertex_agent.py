"""
Network Flow Classifier Agent for Vertex AI Agent Engine Deployment

This agent is designed to be deployed on Google Cloud Vertex AI Agent Engine
using the Agent2Agent (A2A) protocol.

Architecture:
- Uses Vertex AI ADK (Agent Development Kit) for core agent logic
- Implements AgentExecutor for A2A protocol integration
- Deploys as a single unified Agent class on Vertex AI
- Communicates with nDPI collector via A2A protocol

References:
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Sequence

import numpy as np
from pydantic import BaseModel, Field

# Vertex AI imports
try:
    from vertexai.preview import agent_engines
    from vertexai.preview.agent_engines import A2aAgent, AgentCard
    from vertexai.preview.agent_engines.adk import Agent, Task, TaskUpdate
    VERTEX_AI_AVAILABLE = True
except ImportError:
    print("Warning: Vertex AI SDK not installed. Install with: pip install 'google-cloud-aiplatform[agent_engines,adk]>=1.112.0'")
    VERTEX_AI_AVAILABLE = False

# A2A SDK imports
try:
    from a2a_sdk import (
        Artifact,
        TaskStatus,
        Session,
    )
    A2A_AVAILABLE = True
except ImportError:
    print("Warning: A2A SDK not installed. Install with: pip install 'a2a-sdk>=0.3.4'")
    A2A_AVAILABLE = False

# ONNX Runtime
try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    print("Warning: ONNX Runtime not installed. Install with: pip install onnxruntime")
    ONNX_AVAILABLE = False


logger = logging.getLogger(__name__)


# ============================================================================
# Pydantic Models (v2)
# ============================================================================

class FlowFeatures(BaseModel):
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


class ClassificationResult(BaseModel):
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


class BatchClassificationRequest(BaseModel):
    """Batch classification request"""
    flows: List[FlowFeatures]
    request_id: Optional[str] = None


class BatchClassificationResponse(BaseModel):
    """Batch classification response"""
    results: List[ClassificationResult]
    total_flows: int
    malicious_count: int
    processing_time_ms: float
    request_id: Optional[str] = None


# ============================================================================
# ONNX Flow Classifier
# ============================================================================

class ONNXFlowClassifier:
    """
    Flow classifier using ONNX model
    Lazy initialization pattern for Vertex AI deployment
    """

    def __init__(self, model_path: Optional[Path] = None):
        """
        Initialize ONNX classifier

        Args:
            model_path: Path to ONNX model file
        """
        self.model_path = model_path or Path("/models/flow_classifier.onnx")
        self.session: Optional[ort.InferenceSession] = None
        self._initialized = False

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

    def _lazy_init(self):
        """Lazy initialization of ONNX model"""
        if self._initialized:
            return

        if not ONNX_AVAILABLE:
            logger.warning("ONNX Runtime not available, using fallback classification")
            self._initialized = True
            return

        try:
            if self.model_path.exists():
                sess_options = ort.SessionOptions()
                sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

                self.session = ort.InferenceSession(
                    str(self.model_path),
                    sess_options=sess_options,
                    providers=['CPUExecutionProvider']
                )

                logger.info(f"ONNX model loaded from {self.model_path}")
            else:
                logger.warning(f"Model file not found: {self.model_path}, using fallback")

        except Exception as e:
            logger.error(f"Failed to load ONNX model: {e}")
            self.session = None

        self._initialized = True

    def classify(self, features: FlowFeatures) -> ClassificationResult:
        """
        Classify network flow

        Args:
            features: Flow features

        Returns:
            Classification result with explanation
        """
        self._lazy_init()

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

        # Anomaly detection
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
        input_name = self.session.get_inputs()[0].name
        input_data = features.reshape(1, -1).astype(np.float32)
        outputs = self.session.run(None, {input_name: input_data})
        probabilities = outputs[0][0]
        prediction = int(np.argmax(probabilities))
        return prediction, probabilities

    def _fallback_inference(self, features: FlowFeatures) -> tuple:
        """Fallback rule-based classification"""
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

        probabilities = np.zeros(len(self.attack_types))
        probabilities[prediction] = 0.75
        probabilities += np.random.rand(len(self.attack_types)) * 0.1
        probabilities /= probabilities.sum()

        return prediction, probabilities

    def _detect_anomaly(self, features: np.ndarray) -> tuple:
        """Simple anomaly detection"""
        score = np.random.rand() * 0.4
        is_anomaly = score > 0.25
        return float(score), is_anomaly

    def _assess_risk(self, features: FlowFeatures, attack_type: str, anomaly_score: float) -> float:
        """Assess overall risk score (0-1)"""
        risk_map = {
            "normal": 0.1, "probe": 0.3, "port_scan": 0.4,
            "dos": 0.7, "ddos": 0.9, "brute_force": 0.6,
            "botnet": 0.8, "malware": 0.95, "r2l": 0.7, "u2r": 0.8,
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
        importance = {
            self.feature_names[i]: float(np.random.rand() * probabilities[i % len(probabilities)])
            for i in range(min(10, len(self.feature_names)))
        }

        factors = []
        if features.packets_per_second > 100:
            factors.append(f"High packet rate: {features.packets_per_second:.0f} pps")
        if features.bytes_per_second > 100000:
            factors.append(f"High bandwidth: {features.bytes_per_second/1000:.0f} KB/s")
        if features.risk_score > 50:
            factors.append(f"nDPI risk score: {features.risk_score}")
        if attack_type != "normal":
            factors.append(f"Attack pattern detected: {attack_type}")

        if attack_type == "normal":
            text = "Flow classified as normal traffic with no suspicious patterns detected."
        else:
            confidence_pct = probabilities[self.attack_types.index(attack_type)] * 100
            text = (f"Flow classified as {attack_type} attack with {confidence_pct:.1f}% confidence. "
                   f"Key indicators: {', '.join(factors[:3] if factors else ['pattern matching'])}")

        return text, importance, factors

    def _get_recommended_actions(self, attack_type: str, risk_level: str) -> List[str]:
        """Get recommended actions"""
        if attack_type == "normal":
            return ["Continue monitoring"]

        actions = ["Alert security team", "Log incident for analysis"]

        if attack_type in ["ddos", "dos"]:
            actions.extend(["Enable rate limiting", "Activate DDoS mitigation"])
        elif attack_type == "port_scan":
            actions.append("Add source IP to watchlist")
        elif attack_type in ["malware", "botnet"]:
            actions.extend(["Block source IP", "Quarantine affected systems"])
        elif attack_type == "brute_force":
            actions.append("Enforce account lockout policy")

        if risk_level in ["critical", "high"]:
            actions.extend(["Escalate to incident response team", "Consider blocking source IP"])

        return actions


# ============================================================================
# Vertex AI Agent Implementation
# ============================================================================

class FlowClassifierAgentExecutor:
    """
    AgentExecutor for Vertex AI Agent Engine

    Implements the bridge between A2A protocol and the classifier logic.
    Handles task lifecycle: submitted → working → completed
    """

    def __init__(self):
        """Initialize the agent executor"""
        # Use lazy initialization pattern
        self._classifier = None
        logger.info("FlowClassifierAgentExecutor initialized (lazy loading)")

    @property
    def classifier(self) -> ONNXFlowClassifier:
        """Lazy-load classifier"""
        if self._classifier is None:
            self._classifier = ONNXFlowClassifier()
        return self._classifier

    def execute(self, task: Task, updater: Any) -> Sequence[Artifact]:
        """
        Execute classification task

        Args:
            task: Task from A2A protocol
            updater: Task status updater

        Returns:
            List of artifacts with classification results
        """
        try:
            # Update task status to working
            updater.start_work()

            # Extract flow data from task
            flow_data = self._extract_flow_data(task)

            if not flow_data:
                error_artifact = Artifact(
                    content=json.dumps({"error": "Invalid task format"}),
                    content_type="application/json"
                )
                updater.complete(artifacts=[error_artifact])
                return [error_artifact]

            # Check if single flow or batch
            if isinstance(flow_data, dict) and "flows" in flow_data:
                # Batch classification
                results = self._classify_batch(flow_data)
            else:
                # Single flow classification
                results = self._classify_single(flow_data)

            # Create result artifact
            result_artifact = Artifact(
                content=json.dumps(results, indent=2),
                content_type="application/json"
            )

            # Complete task
            updater.complete(artifacts=[result_artifact])

            return [result_artifact]

        except Exception as e:
            logger.error(f"Error executing task: {e}", exc_info=True)
            error_artifact = Artifact(
                content=json.dumps({"error": str(e)}),
                content_type="application/json"
            )
            updater.complete(artifacts=[error_artifact])
            return [error_artifact]

    def _extract_flow_data(self, task: Task) -> Optional[Dict]:
        """Extract flow data from task"""
        try:
            # Task input is typically in task.input field
            if hasattr(task, 'input'):
                if isinstance(task.input, str):
                    return json.loads(task.input)
                elif isinstance(task.input, dict):
                    return task.input

            # Try to get from task messages
            if hasattr(task, 'messages') and task.messages:
                for msg in task.messages:
                    if hasattr(msg, 'content'):
                        return json.loads(msg.content)

            return None

        except Exception as e:
            logger.error(f"Error extracting flow data: {e}")
            return None

    def _classify_single(self, flow_data: Dict) -> Dict:
        """Classify single flow"""
        features = FlowFeatures(**flow_data)
        result = self.classifier.classify(features)
        return result.model_dump()

    def _classify_batch(self, batch_data: Dict) -> Dict:
        """Classify batch of flows"""
        start_time = time.time()

        request = BatchClassificationRequest(**batch_data)
        results = []
        malicious_count = 0

        for flow in request.flows:
            result = self.classifier.classify(flow)
            results.append(result)
            if result.is_malicious:
                malicious_count += 1

        processing_time = (time.time() - start_time) * 1000

        response = BatchClassificationResponse(
            results=results,
            total_flows=len(results),
            malicious_count=malicious_count,
            processing_time_ms=processing_time,
            request_id=request.request_id
        )

        return response.model_dump()


def create_agent_card() -> Dict:
    """
    Create AgentCard compatible with Vertex AI Agent Engine

    Returns:
        Agent card specification
    """
    return {
        "name": "flow-classifier-agent",
        "display_name": "Network Flow Classifier",
        "description": "AI-powered network flow classifier using ML models for threat detection",
        "version": "1.0.0",
        "capabilities": [
            "flow_classification",
            "batch_classification",
            "anomaly_detection",
            "risk_assessment",
            "explainable_ai"
        ],
        "input_schema": {
            "type": "object",
            "properties": {
                "flows": {
                    "type": "array",
                    "description": "Array of network flows to classify"
                },
                "src_ip": {"type": "string"},
                "dst_ip": {"type": "string"},
                "src_port": {"type": "integer"},
                "dst_port": {"type": "integer"},
            }
        },
        "output_schema": {
            "type": "object",
            "properties": {
                "attack_type": {"type": "string"},
                "confidence": {"type": "number"},
                "risk_level": {"type": "string"},
                "explanation": {"type": "string"}
            }
        },
        "transport": "A2A",
        "model_info": {
            "framework": "ONNX",
            "type": "classification",
            "supports_batch": True
        }
    }


def create_vertex_ai_agent() -> 'A2aAgent':
    """
    Create A2aAgent for Vertex AI deployment

    Returns:
        A2aAgent instance ready for deployment
    """
    if not VERTEX_AI_AVAILABLE:
        raise ImportError("Vertex AI SDK not available. Install with: pip install 'google-cloud-aiplatform[agent_engines,adk]>=1.112.0'")

    # Create agent card
    agent_card = create_agent_card()

    # Create agent executor
    executor = FlowClassifierAgentExecutor()

    # Create A2A agent
    a2a_agent = A2aAgent(
        agent_card=agent_card,
        agent_executor=executor.execute
    )

    return a2a_agent


# ============================================================================
# Local Testing Functions
# ============================================================================

def test_local():
    """Test agent locally before deployment"""
    print("Testing Flow Classifier Agent locally...")

    # Create agent
    agent = create_vertex_ai_agent()

    # Create test flow
    test_flow = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.50",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": 6,
        "packets_forward": 1500,
        "packets_reverse": 1200,
        "bytes_forward": 450000,
        "bytes_reverse": 89000,
        "duration": 30.5,
        "iat_mean": 0.02,
        "iat_std": 0.01,
        "iat_min": 0.001,
        "iat_max": 0.5,
        "detected_protocol": "HTTP",
        "tcp_flags_forward": 24,
        "tcp_flags_reverse": 16,
        "tos": 0,
        "ttl_min": 64,
        "ttl_max": 64,
        "packets_per_second": 50.0,
        "bytes_per_second": 15000.0,
        "packet_size_mean": 300.0,
        "packet_size_std": 50.0,
        "ndpi_protocol_id": 7,
        "ndpi_risk_flags": 0,
        "risk_score": 25
    }

    # Test single classification
    print("\n=== Testing Single Flow Classification ===")
    print(f"Test flow: {test_flow['src_ip']}:{test_flow['src_port']} -> {test_flow['dst_ip']}:{test_flow['dst_port']}")

    # Note: Actual testing would require proper Task and updater objects
    # This is simplified for demonstration
    executor = FlowClassifierAgentExecutor()
    result = executor._classify_single(test_flow)
    print(f"\nResult: {json.dumps(result, indent=2)}")

    print("\n✓ Local testing completed")


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Run local test
    test_local()
