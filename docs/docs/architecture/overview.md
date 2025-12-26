---
sidebar_position: 1
---

# Architecture Overview

## System Architecture

The Agentic NIDS implements a multi-agent architecture where specialized agents coordinate through message passing and state management.

```mermaid
graph TB
    subgraph "Network Layer"
        NET[Network Traffic]
    end

    subgraph "Capture Layer"
        NDPI[nDPI Collector Agent]
        NET --> NDPI
    end

    subgraph "Message Broker"
        NATS[NATS Server]
        NDPI -->|Publish flows| NATS
    end

    subgraph "Processing Layer"
        CLASSIFIER[XGBoost Classifier<br/>ONNX Runtime]
        LLM[LLM Explanation<br/>GPT-4 / Claude Opus]

        NATS -->|Subscribe| CLASSIFIER
        CLASSIFIER -->|ML Results| LLM
    end

    subgraph "Action Layer"
        PD[PagerDuty<br/>Alert Agent]
        INFLUX[InfluxDB<br/>Storage Agent]

        LLM -->|Malicious| PD
        LLM -->|All Flows| INFLUX
    end

    subgraph "Presentation Layer"
        UI[Vue.js Dashboard]
        INFLUX --> UI
    end

    style NET fill:#e1f5ff
    style CLASSIFIER fill:#fff4e6
    style LLM fill:#f3e5f5
    style PD fill:#ffebee
    style INFLUX fill:#e8f5e9
```

## Agent Components

### Packet Capture Agent

**Technology**: nfstream + nDPI

**Responsibilities**:
- Capture packets from live interface or PCAP file
- Deep packet inspection (Layer 7 protocol detection)
- Flow aggregation (configurable 3-minute windows)
- Feature extraction (16 features)

**Output**: Network flows with statistical features

### XGBoost Classifier Agent

**Technology**: ONNX Runtime + A2A Protocol

**Responsibilities**:
- ML inference on network flows
- Binary classification (benign/malicious)
- Attack type detection
- Feature importance calculation
- Risk scoring (0-1 scale)

**Performance**: &lt;10ms per flow

###  LLM Explanation Agent

**Technology**: LangChain + OpenAI/Anthropic

**Supported Models**:
- OpenAI: GPT-4, GPT-4o, GPT-4o-mini
- Anthropic: Claude Opus 4.5, Claude Sonnet 4.5

**Responsibilities**:
- Generate human-readable explanations
- Priority classification (Critical/High/Medium/Low)
- Threat assessment
- Recommended actions
- Attack vector analysis

**Performance**: 1-3 seconds per explanation

###  PagerDuty Alert Agent

**Technology**: PagerDuty Events API v2

**Responsibilities**:
- Create incidents for malicious flows
- Severity mapping (confidence → severity)
- Deduplication
- Rich context inclusion

**Trigger**: Conditional (malicious flows only)

### InfluxDB Storage Agent

**Technology**: InfluxDB 2.7+ (Time-Series DB)

**Responsibilities**:
- Persist network flows
- Store ML classifications
- Save LLM explanations
- Tag-based indexing

**Measurements**:
- `network_flow`: Raw flow data
- `flow_classification`: ML results
- `llm_explanation`: AI explanations

## Data Flow

```mermaid
sequenceDiagram
    participant Net as Network
    participant Cap as Capture Agent
    participant NATS as NATS Broker
    participant ML as Classifier
    participant LLM as LLM Agent
    participant PD as PagerDuty
    participant DB as InfluxDB

    Net->>Cap: Packets
    Cap->>Cap: Extract features
    Cap->>NATS: Publish flow
    NATS->>ML: Deliver flow
    ML->>ML: ONNX inference
    ML->>LLM: Classification result
    LLM->>LLM: Generate explanation

    alt Malicious flow
        LLM->>PD: Create incident
    end

    LLM->>DB: Store flow + classification + explanation
```

## State Management

The system uses an immutable state object (NIDSState) that flows through the workflow:

```typescript
interface NIDSState {
  // Configuration
  capture_source: string;
  collection_interval: number;
  nats_url: string;

  // Agent outputs
  flows: FlowData[];
  classifications: ClassificationResult[];
  explanations: LLMExplanation[];
  pagerduty_incidents: PagerDutyIncident[];

  // Metrics
  flows_captured: number;
  malicious_count: number;
  alerts_sent_count: number;

  // Status
  current_step: WorkflowStep;
  errors: string[];
}
```

## Communication Protocols

### Agent2Agent (A2A)

- **Transport**: gRPC with streaming
- **Port**: 50051 (default)
- **Use Case**: ML classifier requests
- **Features**: Task status tracking, bidirectional streaming

### NATS Messaging

- **Transport**: TCP
- **Port**: 4222 (default)
- **Use Case**: Asynchronous flow distribution
- **Features**: Pub/sub, JetStream persistence, load balancing

### InfluxDB Line Protocol

- **Transport**: HTTP
- **Port**: 8086 (default)
- **Use Case**: Time-series data storage
- **Features**: Tag-based indexing, retention policies

## Scalability

```mermaid
graph LR
    subgraph "Classifier Auto-Scaling"
        C1[Classifier Pod 1]
        C2[Classifier Pod 2]
        C3[Classifier Pod N]
    end

    LB[Load Balancer<br/>HPA: 2-10 replicas]

    LB --> C1
    LB --> C2
    LB --> C3

    style LB fill:#fff4e6
```

**Horizontal Scaling**:
- Classifier agents: 2-10 replicas (HPA)
- LLM agents: 2-5 replicas (HPA)
- UI: 2+ replicas

**Vertical Scaling**:
- Resource requests/limits configurable
- Node affinity for high-performance nodes

## Security

```mermaid
graph TD
    subgraph "Pod Security"
        PS1[Non-root user UID 1000]
        PS2[Read-only filesystem]
        PS3[Dropped capabilities]
        PS4[No privilege escalation]
    end

    subgraph "Network Security"
        NS1[NetworkPolicy]
        NS2[ClusterIP internal]
        NS3[LoadBalancer UI only]
        NS4[TLS/gRPC encryption]
    end

    subgraph "Secret Management"
        SM1[Kubernetes Secrets]
        SM2[Environment injection]
        SM3[No hardcoded credentials]
    end
```

## Next Steps

- [Data Models](./data-models) - Understand data structures
- [Workflow](./workflow) - Execution flow details
- [Deployment](../deployment/kubernetes) - Production setup
