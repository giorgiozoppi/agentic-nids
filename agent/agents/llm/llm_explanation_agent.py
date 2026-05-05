"""
LLM Explanation Agent for Agentic NIDS

Generates human-readable threat explanations using Large Language Models.
Provides priority classification, threat assessment, and recommended actions.
The LLM backend is injected via an LLMStrategy, making it trivial to swap
between OpenAI, Anthropic, Gemini, or a local vLLM server.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser

from agents.llm.strategies import LLMStrategy, VLLMStrategy
from models import LLMExplanationResult, Priority, ThreatExplanation

logger = logging.getLogger(__name__)

_EXPLAIN_PROMPT = ChatPromptTemplate.from_messages([
    ("system", (
        "You are a cybersecurity expert analyzing network intrusion detection results. "
        "Your task is to explain ML classification results in clear, actionable language "
        "for security analysts. Focus on practical threat assessment and specific "
        "recommended actions.\n\n{format_instructions}"
    )),
    ("user", (
        "Analyze this network flow classification:\n\n"
        "FLOW INFORMATION:\n"
        "- Flow ID: {flow_id}\n"
        "- Source: {src_ip}:{src_port} → Destination: {dst_ip}:{dst_port}\n"
        "- Protocol: {protocol}\n"
        "- Application: {application_name}\n"
        "- Duration: {duration_ms} ms\n"
        "- Packets: {bidirectional_packets} (Forward: {forward_packets}, Reverse: {reverse_packets})\n"
        "- Bytes: {bidirectional_bytes} (Forward: {forward_bytes}, Reverse: {reverse_bytes})\n"
        "- Packet Rate: {packets_per_second:.2f} pps\n"
        "- Byte Rate: {bytes_per_second:.2f} Bps\n\n"
        "CLASSIFICATION RESULT:\n"
        "- Prediction: {prediction_label}\n"
        "- Confidence: {confidence:.1%}\n"
        "- Attack Type: {attack_type}\n"
        "- Risk Score: {risk_score:.2f}\n"
        "- Is Anomaly: {is_anomaly}\n\n"
        "FEATURE IMPORTANCE (Top Contributors):\n"
        "{feature_importance}\n\n"
        "Provide:\n"
        "1. Clear explanation of why this traffic was classified as {prediction_label}\n"
        "2. Threat assessment including risk level justification\n"
        "3. Specific recommended actions for the security team\n"
        "4. Key technical factors that influenced this classification\n"
        "5. Analysis of the attack vector (if malicious)"
    )),
])

_BATCH_PROMPT = ChatPromptTemplate.from_messages([
    ("system", "You are a network security expert. Analyze the provided network flows for threats and anomalies."),
    ("human", "{prompt}"),
])


class LLMExplanationAgent:
    """Generates human-readable threat explanations using a pluggable LLM strategy."""

    def __init__(self, strategy: LLMStrategy = None) -> None:
        if strategy is None:
            strategy = VLLMStrategy()
        self.llm = strategy.build()
        self.parser = PydanticOutputParser(pydantic_object=ThreatExplanation)
        self._chain = _EXPLAIN_PROMPT | self.llm | self.parser
        self._batch_chain = _BATCH_PROMPT | self.llm
        logger.info("LLMExplanationAgent ready (%s)", strategy.label)

    @staticmethod
    def classify_priority(confidence: float) -> Priority:
        if confidence >= 0.90:
            return Priority.CRITICAL
        if confidence >= 0.70:
            return Priority.HIGH
        if confidence >= 0.50:
            return Priority.MEDIUM
        return Priority.LOW

    async def explain_classification(
        self,
        flow_data: Dict[str, Any],
        classification_result: Dict[str, Any],
    ) -> LLMExplanationResult:
        start = time.monotonic()
        try:
            confidence = classification_result.get("confidence", 0.0)
            priority = self.classify_priority(confidence)

            feature_importance = classification_result.get("feature_importance", {})
            fi_str = "\n".join(
                f"  - {feat}: {imp:.3f}"
                for feat, imp in sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:5]
            ) or "  (No feature importance data)"

            prompt_vars = {
                "flow_id": flow_data.get("flow_id", "unknown"),
                "src_ip": flow_data.get("src_ip", "unknown"),
                "src_port": flow_data.get("src_port", 0),
                "dst_ip": flow_data.get("dst_ip", "unknown"),
                "dst_port": flow_data.get("dst_port", 0),
                "protocol": flow_data.get("protocol", "unknown"),
                "application_name": flow_data.get("application_name", "unknown"),
                "duration_ms": flow_data.get("duration_ms", 0),
                "bidirectional_packets": flow_data.get("bidirectional_packets", 0),
                "bidirectional_bytes": flow_data.get("bidirectional_bytes", 0),
                "forward_packets": flow_data.get("forward_packets", 0),
                "reverse_packets": flow_data.get("reverse_packets", 0),
                "forward_bytes": flow_data.get("forward_bytes", 0),
                "reverse_bytes": flow_data.get("reverse_bytes", 0),
                "packets_per_second": flow_data.get("packets_per_second", 0.0),
                "bytes_per_second": flow_data.get("bytes_per_second", 0.0),
                "prediction_label": classification_result.get("prediction_label", "unknown"),
                "confidence": confidence,
                "attack_type": classification_result.get("attack_type", "unknown"),
                "risk_score": classification_result.get("risk_score", 0.0),
                "is_anomaly": classification_result.get("is_anomaly", False),
                "feature_importance": fi_str,
                "format_instructions": self.parser.get_format_instructions(),
            }

            explanation: ThreatExplanation = await asyncio.to_thread(self._chain.invoke, prompt_vars)
            elapsed_ms = (time.monotonic() - start) * 1000

            result = LLMExplanationResult(
                flow_id=flow_data.get("flow_id", 0),
                priority=priority,
                explanation=explanation.explanation,
                threat_assessment=explanation.threat_assessment,
                recommended_actions=explanation.recommended_actions,
                key_reasoning_factors=explanation.key_reasoning_factors,
                attack_vector_analysis=explanation.attack_vector_analysis,
                generation_time_ms=elapsed_ms,
            )
            logger.info("Explained flow %s (priority=%s, %.0fms)", result.flow_id, priority.value, elapsed_ms)
            return result

        except Exception as exc:
            logger.error("Failed to generate explanation: %s", exc)
            return self._fallback(flow_data, classification_result, (time.monotonic() - start) * 1000, str(exc))

    def _fallback(
        self,
        flow_data: Dict[str, Any],
        classification_result: Dict[str, Any],
        elapsed_ms: float,
        error: str,
    ) -> LLMExplanationResult:
        confidence = classification_result.get("confidence", 0.0)
        priority = self.classify_priority(confidence)
        prediction = classification_result.get("prediction_label", "unknown")
        attack_type = classification_result.get("attack_type", "unknown")
        return LLMExplanationResult(
            flow_id=flow_data.get("flow_id", 0),
            priority=priority,
            explanation=(
                f"Flow classified as {prediction} with {confidence:.1%} confidence. "
                f"Attack type: {attack_type}. (LLM explanation unavailable: {error})"
            ),
            threat_assessment=f"{priority.value} priority threat detected",
            recommended_actions=[
                "Review flow details manually",
                "Investigate source and destination IPs",
                "Check for similar patterns",
                "Alert security team if confidence is high",
            ],
            key_reasoning_factors=[
                f"ML confidence: {confidence:.1%}",
                f"Attack type: {attack_type}",
            ],
            generation_time_ms=elapsed_ms,
        )

    async def explain_batch(
        self,
        flows_and_classifications: List[tuple[Dict[str, Any], Dict[str, Any]]],
    ) -> List[LLMExplanationResult]:
        tasks = [self.explain_classification(fd, cr) for fd, cr in flows_and_classifications]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        explanations: List[LLMExplanationResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                fd, cr = flows_and_classifications[i]
                logger.error("Batch explanation failed for flow %s: %s", fd.get("flow_id"), result)
                explanations.append(self._fallback(fd, cr, 0.0, str(result)))
            else:
                explanations.append(result)
        return explanations

    async def analyze_flows(self, flows: List[Dict[str, Any]], prompt: str) -> Dict[str, Any]:
        """Analyze a batch of flows with a free-form prompt. Returns anomalies and summary."""
        try:
            result = await self._batch_chain.ainvoke({"prompt": prompt})
            content = result.content if hasattr(result, "content") else str(result)
            return {"anomalies": [], "summary": content}
        except Exception as exc:
            logger.error("analyze_flows error: %s", exc)
            return {"anomalies": [], "summary": f"LLM error: {exc}"}


async def main() -> None:
    """Example usage — swap the strategy to change the LLM backend."""
    logging.basicConfig(level=logging.INFO)

    from agents.llm.strategies import create_strategy

    flow_data = {
        "flow_id": 12345, "src_ip": "192.168.1.100", "src_port": 54321,
        "dst_ip": "203.0.113.45", "dst_port": 443, "protocol": "TCP",
        "application_name": "HTTPS", "duration_ms": 45000,
        "bidirectional_packets": 1523, "bidirectional_bytes": 2048576,
        "forward_packets": 876, "reverse_packets": 647,
        "forward_bytes": 1182976, "reverse_bytes": 865600,
        "packets_per_second": 33.8, "bytes_per_second": 45523.9,
    }
    classification_result = {
        "prediction_label": "malicious", "confidence": 0.87,
        "attack_type": "port_scan", "risk_score": 0.75, "is_anomaly": True,
        "feature_importance": {
            "packets_forward": 0.25, "bytes_forward": 0.31,
            "packets_per_second": 0.18, "duration": 0.12, "port_number": 0.14,
        },
    }

    agent = LLMExplanationAgent(strategy=create_strategy("openai", model="gpt-4o-mini"))
    result = await agent.explain_classification(flow_data, classification_result)

    print(f"\n{'='*70}")
    print(f"LLM Explanation for Flow {result.flow_id}")
    print(f"{'='*70}")
    print(f"Priority: {result.priority.value}")
    print(f"\nExplanation:\n{result.explanation}")
    print(f"\nThreat Assessment:\n{result.threat_assessment}")
    print("\nRecommended Actions:")
    for action in result.recommended_actions:
        print(f"  - {action}")
    print("\nKey Reasoning Factors:")
    for factor in result.key_reasoning_factors:
        print(f"  - {factor}")
    if result.attack_vector_analysis:
        print(f"\nAttack Vector Analysis:\n{result.attack_vector_analysis}")
    print(f"\nGeneration Time: {result.generation_time_ms:.0f}ms")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    asyncio.run(main())
