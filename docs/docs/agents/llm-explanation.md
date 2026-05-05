---
sidebar_position: 2
---

# LLM Explanation Agent

**File:** `agent/agents/llm/llm_explanation_agent.py`

## Overview

`LLMExplanationAgent` initialises a LangChain chat model (Anthropic or OpenAI) and provides two interfaces:

1. **`explain_classification`** — structured Pydantic output for a single flow and its classification result
2. **`analyze_flows`** — plain-text batch analysis, called from the `analyze_batch` graph node

The raw `llm` handle (`llm_agent.llm`) is also passed directly into the LangGraph workflow so `create_react_agent` can build agent nodes from it.

## Initialisation

```python
from agents.llm.llm_explanation_agent import LLMExplanationAgent

# Anthropic (auto-picks ANTHROPIC_API_KEY from env if api_key omitted)
agent = LLMExplanationAgent(provider="anthropic", model="claude-sonnet-4-6")

# OpenAI
agent = LLMExplanationAgent(provider="openai", model="gpt-4o-mini")
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `provider` | `"openai"` | `"openai"` or `"anthropic"` |
| `model` | `"gpt-4o-mini"` | Model name for the selected provider |
| `temperature` | `0.3` | Sampling temperature (0–1) |
| `max_tokens` | `1000` | Maximum response tokens |
| `timeout` | `30.0` | Request timeout in seconds |
| `api_key` | env var | Falls back to `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` |

## Supported Models

| Provider | Recommended | Notes |
|----------|------------|-------|
| Anthropic | `claude-sonnet-4-6` | Best balance of speed and quality |
| Anthropic | `claude-opus-4-7` | Highest capability |
| Anthropic | `claude-haiku-4-5` | Fastest / cheapest |
| OpenAI | `gpt-4o-mini` | Default, cost-effective |
| OpenAI | `gpt-4o` | Higher capability |

## Chains

### Structured chain — `explain_classification`

Uses a detailed 15-field prompt template and a `PydanticOutputParser` to return a typed `LLMExplanationResult`.

```python
result = await agent.explain_classification(
    flow_data={
        "flow_id": "10.0.0.1:54321->8.8.8.8:443:TCP",
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
        "protocol": "TCP",
        "application_name": "HTTPS",
        "bidirectional_packets": 1523,
        "bidirectional_bytes": 2048576,
        "packets_per_second": 33.8,
        "bytes_per_second": 45523.9,
        # ...
    },
    classification_result={
        "prediction_label": "malicious",
        "confidence": 0.92,
        "attack_type": "port_scan",
        "risk_score": 0.81,
        "is_anomaly": True,
        "feature_importance": {"packets_per_second": 0.31, ...},
    },
)
print(result.priority)           # Priority.CRITICAL
print(result.explanation)        # "High-confidence HTTPS anomaly..."
print(result.recommended_actions)
```

### Batch chain — `analyze_flows`

A simpler `ChatPromptTemplate → LLM` chain (no structured parser). Returns a plain-text summary as:

```python
{"anomalies": [], "summary": "<LLM free-text response>"}
```

This is what the LangGraph `analyze_batch` node ultimately surfaces via the ReAct agent loop.

## `ThreatExplanation` Schema

```python
class ThreatExplanation(BaseModel):
    explanation: str
    threat_assessment: str
    recommended_actions: List[str]
    key_reasoning_factors: List[str]
    attack_vector_analysis: Optional[str]
```

## `LLMExplanationResult`

```python
@dataclass
class LLMExplanationResult:
    flow_id: int
    priority: Priority          # CRITICAL / HIGH / MEDIUM / LOW
    explanation: str
    threat_assessment: str
    recommended_actions: List[str]
    key_reasoning_factors: List[str]
    attack_vector_analysis: Optional[str]
    generation_time_ms: float
```

## Priority Classification

```python
@staticmethod
def classify_priority(confidence: float) -> Priority:
    if confidence >= 0.90: return Priority.CRITICAL
    if confidence >= 0.70: return Priority.HIGH
    if confidence >= 0.50: return Priority.MEDIUM
    return Priority.LOW
```

## Fallback Behaviour

If the LLM call fails, `_create_fallback_explanation` returns a minimal `LLMExplanationResult` with the raw confidence and attack type, plus a standard set of recommended actions. The graph's retry logic handles transient failures before falling back.
