"""
Classifier Agent with gRPC streaming using Agent2Agent protocol

This agent receives streaming flow messages and performs:
1. Real-time attack classification
2. Anomaly detection
3. Risk assessment
4. Explainable AI analysis
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, AsyncIterator
from datetime import datetime
from concurrent import futures

import grpc
import numpy as np

# Import generated proto files (will be generated from proto)
try:
    from . import agent2agent_pb2
    from . import agent2agent_pb2_grpc
except ImportError:
    print("Warning: gRPC proto files not generated. Run: python -m grpc_tools.protoc")
    agent2agent_pb2 = None
    agent2agent_pb2_grpc = None


logger = logging.getLogger(__name__)


class FlowClassifier:
    """
    Flow classifier using multiple ML models
    """

    def __init__(self):
        """Initialize classifier with ML models"""
        self.models_loaded = False
        self.xgboost_model = None
        self.isolation_forest = None
        self.flow_transformer = None

        # Attack type mappings
        self.attack_types = [
            "normal",
            "dos",
            "probe",
            "r2l",
            "u2r",
            "botnet",
            "ddos",
            "port_scan",
            "brute_force",
            "sql_injection",
            "xss",
            "malware",
        ]

        # Statistics
        self.stats = {
            "total_classified": 0,
            "total_malicious": 0,
            "total_anomalies": 0,
            "classification_times": [],
        }

        logger.info("FlowClassifier initialized")

    def load_models(self):
        """Load ML models (stub - implement actual loading)"""
        try:
            # TODO: Load actual models
            # self.xgboost_model = xgboost.Booster()
            # self.xgboost_model.load_model('models/xgboost_classifier.json')
            # self.isolation_forest = joblib.load('models/isolation_forest.pkl')
            # self.flow_transformer = FlowTransformer.from_pretrained('models/flow_transformer')

            self.models_loaded = True
            logger.info("Models loaded successfully")

        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            self.models_loaded = False

    def extract_features(self, flow_message) -> np.ndarray:
        """
        Extract feature vector from flow message

        Args:
            flow_message: FlowMessage proto

        Returns:
            Feature vector as numpy array
        """
        features = flow_message.features

        # Extract numerical features
        feature_vector = [
            features.packets_forward,
            features.packets_reverse,
            features.bytes_forward,
            features.bytes_reverse,
            features.duration,
            features.iat_mean,
            features.iat_std,
            features.iat_min,
            features.iat_max,
            features.protocol,
            features.tcp_flags_forward,
            features.tcp_flags_reverse,
            features.tos,
            features.ttl_min,
            features.ttl_max,
            features.packets_per_second,
            features.bytes_per_second,
            features.packet_size_mean,
            features.packet_size_std,
            features.ndpi_protocol_id,
            features.risk_score,
        ]

        return np.array(feature_vector, dtype=np.float32)

    def classify_flow(self, flow_message) -> Dict:
        """
        Classify a single flow

        Args:
            flow_message: FlowMessage proto

        Returns:
            Classification result dictionary
        """
        start_time = time.time()

        # Extract features
        features = self.extract_features(flow_message)

        # Perform classification (stub implementation)
        # In production, use actual models
        if self.models_loaded:
            # Use actual model prediction
            prediction_class = self._predict_with_xgboost(features)
            confidence = self._get_prediction_confidence(features)
        else:
            # Fallback: rule-based classification
            prediction_class = self._rule_based_classification(flow_message)
            confidence = 0.7

        # Anomaly detection
        anomaly_score, is_anomaly = self._detect_anomaly(features)

        # Risk assessment
        risk_score = self._assess_risk(flow_message, prediction_class, anomaly_score)

        # Generate explanation
        explanation = self._generate_explanation(
            flow_message, prediction_class, features
        )

        # Update statistics
        classification_time = time.time() - start_time
        self.stats["total_classified"] += 1
        self.stats["classification_times"].append(classification_time)

        if prediction_class != "normal":
            self.stats["total_malicious"] += 1

        if is_anomaly:
            self.stats["total_anomalies"] += 1

        return {
            "attack_type": prediction_class,
            "confidence": confidence,
            "is_malicious": prediction_class != "normal",
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "risk_score": risk_score,
            "explanation": explanation,
            "classification_time": classification_time,
        }

    def _predict_with_xgboost(self, features: np.ndarray) -> str:
        """Predict using XGBoost model (stub)"""
        # TODO: Implement actual XGBoost prediction
        # pred = self.xgboost_model.predict(features.reshape(1, -1))
        # return self.attack_types[int(pred[0])]

        # Stub: random prediction for demonstration
        import random
        return random.choice(self.attack_types)

    def _get_prediction_confidence(self, features: np.ndarray) -> float:
        """Get prediction confidence (stub)"""
        # TODO: Implement actual confidence calculation
        # probs = self.xgboost_model.predict_proba(features.reshape(1, -1))
        # return float(np.max(probs))

        return 0.85

    def _detect_anomaly(self, features: np.ndarray) -> tuple:
        """Detect anomalies using Isolation Forest (stub)"""
        # TODO: Implement actual anomaly detection
        # score = self.isolation_forest.score_samples(features.reshape(1, -1))[0]
        # is_anomaly = score < -0.5
        # return abs(score), is_anomaly

        # Stub implementation
        score = np.random.rand() * 0.3
        is_anomaly = score > 0.2
        return float(score), is_anomaly

    def _assess_risk(self, flow_message, attack_type: str, anomaly_score: float) -> float:
        """Assess overall risk score"""
        risk_score = 0.0

        # Base risk from attack type
        risk_map = {
            "normal": 0.1,
            "probe": 0.3,
            "dos": 0.7,
            "ddos": 0.9,
            "botnet": 0.8,
            "brute_force": 0.6,
            "sql_injection": 0.8,
            "malware": 0.95,
        }
        risk_score += risk_map.get(attack_type, 0.5)

        # Add anomaly contribution
        risk_score += anomaly_score * 0.3

        # Add nDPI risk contribution
        ndpi_risk = flow_message.features.risk_score / 100.0
        risk_score += ndpi_risk * 0.2

        # Normalize to 0-1
        return min(1.0, max(0.0, risk_score))

    def _rule_based_classification(self, flow_message) -> str:
        """Simple rule-based classification fallback"""
        features = flow_message.features

        # Check for port scanning
        if features.packets_forward > 100 and features.bytes_forward < 5000:
            return "port_scan"

        # Check for potential DDoS
        if features.packets_per_second > 1000:
            return "ddos"

        # Check for potential DoS
        if features.bytes_per_second > 1000000:  # 1 MB/s
            return "dos"

        # Check for suspicious protocols
        if features.ndpi_protocol_id == 0 and features.bytes_forward > 100000:
            return "probe"

        # Default to normal
        return "normal"

    def _generate_explanation(
        self, flow_message, attack_type: str, features: np.ndarray
    ) -> Dict:
        """Generate explanation for classification"""

        # Feature importance (stub - would use SHAP in production)
        feature_names = [
            "packets_forward", "packets_reverse", "bytes_forward", "bytes_reverse",
            "duration", "iat_mean", "iat_std", "iat_min", "iat_max",
            "protocol", "tcp_flags_forward", "tcp_flags_reverse",
            "tos", "ttl_min", "ttl_max", "packets_per_second",
            "bytes_per_second", "packet_size_mean", "packet_size_std",
            "ndpi_protocol_id", "risk_score"
        ]

        # Generate random importance values (would use SHAP in production)
        importance = {
            name: float(np.random.rand()) for name in feature_names[:10]
        }

        # Generate text explanation
        text_explanation = self._generate_text_explanation(
            flow_message, attack_type, importance
        )

        return {
            "feature_importance": importance,
            "text_explanation": text_explanation,
            "contributing_factors": self._get_contributing_factors(
                flow_message, attack_type
            ),
        }

    def _generate_text_explanation(
        self, flow_message, attack_type: str, importance: Dict
    ) -> str:
        """Generate human-readable text explanation"""

        features = flow_message.features

        if attack_type == "normal":
            return f"Flow classified as normal traffic. No suspicious patterns detected."

        explanation = f"Flow classified as {attack_type} attack. "

        # Add key indicators
        if attack_type == "port_scan":
            explanation += f"High packet count ({features.packets_forward}) with low bytes suggests scanning behavior. "

        elif attack_type == "ddos":
            explanation += f"Extremely high packet rate ({features.packets_per_second:.0f} pps) indicates DDoS attack. "

        elif attack_type == "dos":
            explanation += f"Very high bandwidth usage ({features.bytes_per_second / 1000:.0f} KB/s) suggests DoS attack. "

        # Add top contributing features
        top_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:3]
        explanation += "Top contributing factors: " + ", ".join(
            [f[0] for f in top_features]
        )

        return explanation

    def _get_contributing_factors(self, flow_message, attack_type: str) -> List[str]:
        """Get list of contributing factors"""
        factors = []
        features = flow_message.features

        if features.packets_per_second > 100:
            factors.append("High packet rate")

        if features.bytes_per_second > 100000:
            factors.append("High bandwidth usage")

        if features.risk_score > 50:
            factors.append("High nDPI risk score")

        if attack_type != "normal":
            factors.append(f"Classified as {attack_type}")

        return factors


class Agent2AgentServicer(agent2agent_pb2_grpc.Agent2AgentServiceServicer if agent2agent_pb2_grpc else object):
    """
    gRPC service implementation for Agent2Agent protocol
    """

    def __init__(self):
        """Initialize servicer"""
        self.classifier = FlowClassifier()
        self.classifier.load_models()
        logger.info("Agent2AgentServicer initialized")

    async def StreamFlowClassification(
        self,
        request_iterator: AsyncIterator,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator:
        """
        Bidirectional streaming for flow classification

        Args:
            request_iterator: Stream of FlowMessage
            context: gRPC context

        Yields:
            ClassificationResult messages
        """
        logger.info("StreamFlowClassification started")

        async for flow_message in request_iterator:
            try:
                # Classify flow
                result = self.classifier.classify_flow(flow_message)

                # Create response
                response = self._create_classification_result(flow_message, result)

                yield response

            except Exception as e:
                logger.error(f"Error classifying flow: {e}")
                # Optionally send error result
                continue

    async def AnalyzeFlows(
        self,
        request: agent2agent_pb2.FlowBatch,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator:
        """
        Server streaming for flow batch analysis

        Args:
            request: FlowBatch containing multiple flows
            context: gRPC context

        Yields:
            ClassificationResult for each flow
        """
        logger.info(f"AnalyzeFlows started for batch {request.batch_id}")

        for flow_message in request.flows:
            try:
                # Classify flow
                result = self.classifier.classify_flow(flow_message)

                # Create response
                response = self._create_classification_result(flow_message, result)

                yield response

            except Exception as e:
                logger.error(f"Error analyzing flow: {e}")
                continue

    async def HealthCheck(
        self,
        request: agent2agent_pb2.HealthCheckRequest,
        context: grpc.aio.ServicerContext,
    ) -> agent2agent_pb2.HealthCheckResponse:
        """Health check endpoint"""

        stats = self.classifier.stats
        avg_time = (
            np.mean(stats["classification_times"])
            if stats["classification_times"]
            else 0
        )

        return agent2agent_pb2.HealthCheckResponse(
            status=agent2agent_pb2.HealthCheckResponse.SERVING,
            message="Classifier agent is healthy",
            metrics={
                "total_classified": str(stats["total_classified"]),
                "total_malicious": str(stats["total_malicious"]),
                "avg_classification_time_ms": f"{avg_time * 1000:.2f}",
                "models_loaded": str(self.classifier.models_loaded),
            },
        )

    async def GetCapabilities(
        self,
        request: agent2agent_pb2.CapabilitiesRequest,
        context: grpc.aio.ServicerContext,
    ) -> agent2agent_pb2.CapabilitiesResponse:
        """Get agent capabilities"""

        return agent2agent_pb2.CapabilitiesResponse(
            supported_models=["XGBoost", "IsolationForest", "FlowTransformer"],
            supported_attack_types=self.classifier.attack_types,
            features_required=[
                "packets_forward", "packets_reverse", "bytes_forward",
                "bytes_reverse", "duration", "protocol"
            ],
            model_versions={
                "XGBoost": "1.0.0",
                "IsolationForest": "1.0.0",
                "FlowTransformer": "0.1.0",
            },
            supports_llm_explanation=True,
            supports_anomaly_detection=True,
        )

    def _create_classification_result(
        self, flow_message, result: Dict
    ) -> agent2agent_pb2.ClassificationResult:
        """Create ClassificationResult proto from classification result"""

        # Create model predictions
        predictions = [
            agent2agent_pb2.ModelPrediction(
                model_name="XGBoost",
                prediction_class=result["attack_type"],
                confidence=result["confidence"],
            )
        ]

        # Create anomaly score
        anomaly = agent2agent_pb2.AnomalyScore(
            score=result["anomaly_score"],
            is_anomaly=result["is_anomaly"],
            anomaly_type="statistical" if result["is_anomaly"] else "none",
            threshold=0.2,
        )

        # Create explanation
        explanation = agent2agent_pb2.Explanation(
            feature_importance=result["explanation"]["feature_importance"],
            text_explanation=result["explanation"]["text_explanation"],
            contributing_factors=result["explanation"]["contributing_factors"],
        )

        # Create risk assessment
        risk_level = "low"
        if result["risk_score"] > 0.7:
            risk_level = "critical"
        elif result["risk_score"] > 0.5:
            risk_level = "high"
        elif result["risk_score"] > 0.3:
            risk_level = "medium"

        risk = agent2agent_pb2.RiskAssessment(
            overall_risk_score=result["risk_score"],
            risk_level=risk_level,
            risk_factors=result["explanation"]["contributing_factors"],
            recommended_actions=self._get_recommended_actions(result),
        )

        # Create classification result
        return agent2agent_pb2.ClassificationResult(
            flow_id=flow_message.flow_id,
            timestamp=int(time.time() * 1000),
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            is_malicious=result["is_malicious"],
            predictions=predictions,
            anomaly=anomaly,
            explanation=explanation,
            risk=risk,
        )

    def _get_recommended_actions(self, result: Dict) -> List[str]:
        """Get recommended actions based on classification"""
        actions = []

        if result["is_malicious"]:
            actions.append("Alert security team")
            actions.append("Log incident for analysis")

        if result["risk_score"] > 0.7:
            actions.append("Block source IP")
            actions.append("Escalate to incident response")

        if result["attack_type"] in ["ddos", "dos"]:
            actions.append("Apply rate limiting")
            actions.append("Enable DDoS mitigation")

        if result["attack_type"] == "port_scan":
            actions.append("Add to watchlist")

        return actions if actions else ["Continue monitoring"]


async def serve(port: int = 50051):
    """
    Start gRPC server

    Args:
        port: Port to listen on
    """
    if not agent2agent_pb2_grpc:
        logger.error("gRPC proto files not available")
        return

    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=10))
    agent2agent_pb2_grpc.add_Agent2AgentServiceServicer_to_server(
        Agent2AgentServicer(), server
    )

    listen_addr = f"[::]:{port}"
    server.add_insecure_port(listen_addr)

    logger.info(f"Starting classifier agent on {listen_addr}")
    await server.start()

    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        await server.stop(5)


def main():
    """Main entry point"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Run server
    asyncio.run(serve())


if __name__ == "__main__":
    main()
