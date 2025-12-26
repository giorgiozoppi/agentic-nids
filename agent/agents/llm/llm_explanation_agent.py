"""
LLM Explanation Agent for Agentic NIDS

Generates human-readable threat explanations using Large Language Models (GPT-4/GPT-3.5-turbo).
Provides priority classification, threat assessment, and recommended actions.
"""

import asyncio
import logging
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser

LANGCHAIN_AVAILABLE = True
logger = logging.getLogger(__name__)


class Priority(str, Enum):
    """Threat priority levels based on ML confidence"""
    CRITICAL = "Critical"  # >= 90%
    HIGH = "High"          # 70-90%
    MEDIUM = "Medium"      # 50-70%
    LOW = "Low"            # < 50%


class ThreatExplanation(BaseModel):
    """Structured threat explanation from LLM"""
    explanation: str = Field(description="Detailed explanation of the classification")
    threat_assessment: str = Field(description="Overall threat assessment and risk level")
    recommended_actions: List[str] = Field(description="List of recommended security actions")
    key_reasoning_factors: List[str] = Field(description="Key factors that led to this classification")
    attack_vector_analysis: Optional[str] = Field(
        default=None,
        description="Analysis of the attack vector and methodology"
    )


@dataclass
class LLMExplanationResult:
    """Result from LLM explanation generation"""
    flow_id: int
    priority: Priority
    explanation: str
    threat_assessment: str
    recommended_actions: List[str]
    key_reasoning_factors: List[str]
    attack_vector_analysis: Optional[str]
    generation_time_ms: float


class LLMExplanationAgent:
    """
    Agent for generating human-readable threat explanations using LLMs
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
        temperature: float = 0.3,
        max_tokens: int = 1000,
        timeout: float = 30.0,
        provider: str = "openai"
    ):
        """
        Initialize LLM Explanation Agent

        Args:
            api_key: API key (OpenAI or Anthropic, or use OPENAI_API_KEY/ANTHROPIC_API_KEY env var)
            model: Model name
                   - OpenAI: gpt-4, gpt-4o, gpt-4o-mini, gpt-3.5-turbo
                   - Anthropic: claude-opus-4-5, claude-sonnet-4-5, claude-haiku-4
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens in response
            timeout: Request timeout in seconds
            provider: LLM provider ("openai" or "anthropic")
        """
        self.provider = provider.lower()
        self.model_name = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

        # Initialize LLM based on provider
        if self.provider == "anthropic":
            self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
            if not self.api_key:
                raise ValueError("Anthropic API key required (set ANTHROPIC_API_KEY env var)")

            self.llm = ChatAnthropic(
                model=self.model_name,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                timeout=self.timeout,
                api_key=self.api_key
            )
            logger.info(f"LLM Explanation Agent initialized with Anthropic {self.model_name}")

        else:  # Default to OpenAI
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
            if not self.api_key:
                raise ValueError("OpenAI API key required (set OPENAI_API_KEY env var)")

            self.llm = ChatOpenAI(
                model=self.model_name,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                request_timeout=self.timeout,
                api_key=self.api_key
            )
            logger.info(f"LLM Explanation Agent initialized with OpenAI {self.model_name}")

        # Setup output parser
        self.parser = PydanticOutputParser(pydantic_object=ThreatExplanation)

        # Create prompt template
        self.prompt_template = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity expert analyzing network intrusion detection results.
Your task is to explain ML classification results in clear, actionable language for security analysts.
Focus on practical threat assessment and specific recommended actions.

{format_instructions}"""),
            ("user", """Analyze this network flow classification:

FLOW INFORMATION:
- Flow ID: {flow_id}
- Source: {src_ip}:{src_port} → Destination: {dst_ip}:{dst_port}
- Protocol: {protocol}
- Application: {application_name}
- Duration: {duration_ms} ms
- Packets: {bidirectional_packets} (Forward: {forward_packets}, Reverse: {reverse_packets})
- Bytes: {bidirectional_bytes} (Forward: {forward_bytes}, Reverse: {reverse_bytes})
- Packet Rate: {packets_per_second:.2f} pps
- Byte Rate: {bytes_per_second:.2f} Bps

CLASSIFICATION RESULT:
- Prediction: {prediction_label}
- Confidence: {confidence:.1%}
- Attack Type: {attack_type}
- Risk Score: {risk_score:.2f}
- Is Anomaly: {is_anomaly}

FEATURE IMPORTANCE (Top Contributors):
{feature_importance}

Provide:
1. Clear explanation of why this traffic was classified as {prediction_label}
2. Threat assessment including risk level justification
3. Specific recommended actions for the security team
4. Key technical factors that influenced this classification
5. Analysis of the attack vector (if malicious)""")
        ])

        self.chain = self.prompt_template | self.llm | self.parser

        logger.info(f"LLM Explanation Agent initialized (model: {model})")

    @staticmethod
    def classify_priority(confidence: float) -> Priority:
        """
        Classify priority based on ML confidence

        Args:
            confidence: Classification confidence (0.0-1.0)

        Returns:
            Priority level
        """
        if confidence >= 0.90:
            return Priority.CRITICAL
        elif confidence >= 0.70:
            return Priority.HIGH
        elif confidence >= 0.50:
            return Priority.MEDIUM
        else:
            return Priority.LOW

    async def explain_classification(
        self,
        flow_data: Dict[str, Any],
        classification_result: Dict[str, Any]
    ) -> LLMExplanationResult:
        """
        Generate explanation for a classification result

        Args:
            flow_data: Network flow data dictionary
            classification_result: ML classification result

        Returns:
            LLMExplanationResult with generated explanation
        """
        import time
        start_time = time.time()

        try:
            # Classify priority
            confidence = classification_result.get("confidence", 0.0)
            priority = self.classify_priority(confidence)

            # Format feature importance
            feature_importance = classification_result.get("feature_importance", {})
            feature_importance_str = "\n".join(
                f"  - {feature}: {importance:.3f}"
                for feature, importance in sorted(
                    feature_importance.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]  # Top 5 features
            )

            # Prepare prompt variables
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
                "feature_importance": feature_importance_str or "  (No feature importance data)",
                "format_instructions": self.parser.get_format_instructions()
            }

            # Generate explanation
            explanation = await asyncio.to_thread(
                self.chain.invoke,
                prompt_vars
            )

            generation_time_ms = (time.time() - start_time) * 1000

            result = LLMExplanationResult(
                flow_id=flow_data.get("flow_id", 0),
                priority=priority,
                explanation=explanation.explanation,
                threat_assessment=explanation.threat_assessment,
                recommended_actions=explanation.recommended_actions,
                key_reasoning_factors=explanation.key_reasoning_factors,
                attack_vector_analysis=explanation.attack_vector_analysis,
                generation_time_ms=generation_time_ms
            )

            logger.info(
                f"Generated explanation for flow {result.flow_id} "
                f"(priority: {priority.value}, {generation_time_ms:.0f}ms)"
            )

            return result

        except Exception as e:
            logger.error(f"Failed to generate explanation: {e}")
            # Return fallback explanation
            generation_time_ms = (time.time() - start_time) * 1000
            return self._create_fallback_explanation(
                flow_data,
                classification_result,
                generation_time_ms,
                error=str(e)
            )

    def _create_fallback_explanation(
        self,
        flow_data: Dict[str, Any],
        classification_result: Dict[str, Any],
        generation_time_ms: float,
        error: str
    ) -> LLMExplanationResult:
        """Create fallback explanation when LLM fails"""
        confidence = classification_result.get("confidence", 0.0)
        priority = self.classify_priority(confidence)
        prediction = classification_result.get("prediction_label", "unknown")
        attack_type = classification_result.get("attack_type", "unknown")

        return LLMExplanationResult(
            flow_id=flow_data.get("flow_id", 0),
            priority=priority,
            explanation=(
                f"Flow classified as {prediction} with {confidence:.1%} confidence. "
                f"Attack type: {attack_type}. "
                f"(LLM explanation unavailable: {error})"
            ),
            threat_assessment=f"{priority.value} priority threat detected",
            recommended_actions=[
                "Review flow details manually",
                "Investigate source and destination IPs",
                "Check for similar patterns",
                "Alert security team if confidence is high"
            ],
            key_reasoning_factors=[
                f"ML confidence: {confidence:.1%}",
                f"Attack type: {attack_type}"
            ],
            attack_vector_analysis=None,
            generation_time_ms=generation_time_ms
        )

    async def explain_batch(
        self,
        flows_and_classifications: List[tuple[Dict[str, Any], Dict[str, Any]]]
    ) -> List[LLMExplanationResult]:
        """
        Generate explanations for a batch of classifications

        Args:
            flows_and_classifications: List of (flow_data, classification_result) tuples

        Returns:
            List of LLMExplanationResult
        """
        tasks = [
            self.explain_classification(flow_data, classification_result)
            for flow_data, classification_result in flows_and_classifications
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions
        explanations = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                flow_data, classification_result = flows_and_classifications[i]
                logger.error(f"Batch explanation failed for flow {flow_data.get('flow_id')}: {result}")
                # Create fallback
                fallback = self._create_fallback_explanation(
                    flow_data,
                    classification_result,
                    0.0,
                    str(result)
                )
                explanations.append(fallback)
            else:
                explanations.append(result)

        return explanations

    async def analyze_flows(self, flows, prompt):
        """
        Analyze a batch of flows using the configured LLM (OpenAI or Anthropic).
        Returns a dict with 'anomalies' and 'summary'.
        """
        # Use the LLM chain to get a response (LangChain or direct API)
        try:
            # If using LangChain, call the chain with the prompt
            if hasattr(self, 'chain'):
                # LangChain expects input as a dict
                result = await self.chain.ainvoke({"input": prompt})
                # Try to parse result as dict
                if isinstance(result, dict):
                    return result
                # If result is a string, try to parse as JSON
                import json
                try:
                    return json.loads(result)
                except Exception:
                    return {"anomalies": [], "summary": str(result)}
            # Fallback: just echo the prompt
            return {"anomalies": [], "summary": "LLM did not return a structured result."}
        except Exception as e:
            return {"anomalies": [], "summary": f"LLM error: {e}"}


async def main():
    """Example usage"""
    logging.basicConfig(level=logging.INFO)

    # Example flow and classification
    flow_data = {
        "flow_id": 12345,
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dst_ip": "203.0.113.45",
        "dst_port": 443,
        "protocol": "TCP",
        "application_name": "HTTPS",
        "duration_ms": 45000,
        "bidirectional_packets": 1523,
        "bidirectional_bytes": 2048576,
        "forward_packets": 876,
        "reverse_packets": 647,
        "forward_bytes": 1182976,
        "reverse_bytes": 865600,
        "packets_per_second": 33.8,
        "bytes_per_second": 45523.9
    }

    classification_result = {
        "prediction_label": "malicious",
        "confidence": 0.87,
        "attack_type": "port_scan",
        "risk_score": 0.75,
        "is_anomaly": True,
        "feature_importance": {
            "packets_forward": 0.25,
            "bytes_forward": 0.31,
            "packets_per_second": 0.18,
            "duration": 0.12,
            "port_number": 0.14
        }
    }

    # Initialize agent
    agent = LLMExplanationAgent(model="gpt-4o-mini")

    # Generate explanation
    result = await agent.explain_classification(flow_data, classification_result)

    print(f"\n{'='*70}")
    print(f"LLM Explanation for Flow {result.flow_id}")
    print(f"{'='*70}")
    print(f"Priority: {result.priority.value}")
    print(f"\nExplanation:\n{result.explanation}")
    print(f"\nThreat Assessment:\n{result.threat_assessment}")
    print(f"\nRecommended Actions:")
    for action in result.recommended_actions:
        print(f"  - {action}")
    print(f"\nKey Reasoning Factors:")
    for factor in result.key_reasoning_factors:
        print(f"  - {factor}")
    if result.attack_vector_analysis:
        print(f"\nAttack Vector Analysis:\n{result.attack_vector_analysis}")
    print(f"\nGeneration Time: {result.generation_time_ms:.0f}ms")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    asyncio.run(main())
