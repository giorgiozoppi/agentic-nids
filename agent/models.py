from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field

class Priority(str, Enum):
    """Threat priority levels based on ML confidence."""
    CRITICAL = "Critical"  # >= 90%
    HIGH = "High"          # 70-90%
    MEDIUM = "Medium"      # 50-70%
    LOW = "Low"            # < 50%


class ThreatExplanation(BaseModel):
    """Structured threat explanation parsed from LLM output."""
    explanation: str = Field(description="Detailed explanation of the classification")
    threat_assessment: str = Field(description="Overall threat assessment and risk level")
    recommended_actions: List[str] = Field(description="List of recommended security actions")
    key_reasoning_factors: List[str] = Field(description="Key factors that led to this classification")
    attack_vector_analysis: Optional[str] = Field(
        default=None,
        description="Analysis of the attack vector and methodology",
    )


class LLMExplanationResult(BaseModel):
    """Result from LLM explanation generation."""
    flow_id: int
    priority: Priority
    explanation: str
    threat_assessment: str
    recommended_actions: List[str]
    key_reasoning_factors: List[str]
    attack_vector_analysis: Optional[str] = None
    generation_time_ms: float


PROTOCOL_MAP: dict[int, str] = {
    1: "icmp",
    6: "tcp",
    17: "udp",
    41: "ipv6",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "ipv6-icmp",
    132: "sctp",
}


class NFStreamAgentConfig(BaseModel):
    """Configuration for NFStream collector agent"""

    # Collection settings
    collection_interval: int = Field(default=180, ge=1)
    idle_timeout: int = Field(default=120, ge=1)
    active_timeout: int = Field(default=1800, ge=1)
    batch_size: int = Field(default=100, ge=1)

    # Capture settings
    capture_interface: Optional[str] = None
    pcap_file: Optional[str] = None
    bpf_filter: Optional[str] = None
    promiscuous_mode: bool = True
    snapshot_length: int = Field(default=1536, ge=64)

    # NFStream-specific settings
    decode_tunnels: bool = True
    n_dissections: int = Field(default=20, ge=0, le=20)
    statistical_analysis: bool = True
    splt_analysis: int = Field(default=0, ge=0, le=255)
    system_visibility_mode: int = Field(default=0, ge=0, le=1)
    max_nflows: int = Field(default=0, ge=0)

    # Payload extraction settings
    extract_payload: bool = True
    max_payload_bytes: int = Field(default=200, ge=0)

    # Output settings
    log_file: Optional[str] = None
    flows_output_file: Optional[str] = "collected_flows.jsonl"

    # Performance settings
    stats_interval: int = Field(default=60, ge=1)
    performance_report: int = Field(default=0, ge=0, le=1)

    llm_prompt: Optional[str] = None

    @classmethod
    def from_yaml(cls, yaml_path: Path) -> "NFStreamAgentConfig":
        with open(yaml_path) as f:
            config_dict = yaml.safe_load(f)
        llm_prompt = config_dict.get("llm_prompt")
        if isinstance(llm_prompt, str) and llm_prompt.endswith(".txt"):
            prompt_path = Path(llm_prompt)
            if prompt_path.exists():
                config_dict["llm_prompt"] = prompt_path.read_text()
        return cls.model_validate(config_dict)

    def to_yaml(self, yaml_path: Path) -> None:
        with open(yaml_path, "w") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False, sort_keys=False)
