# Agentic NIDS Architecture

## System Components

### 1. Agent Layer

#### Packet Capture Agent
- **Technology**: nfstream + nDPI
- **Features**: Deep packet inspection, L7 protocol detection
- **Output**: Network flows (16 features)
- **Interval**: Configurable (default: 3 minutes)

#### XGBoost Classifier Agent
- **Model Format**: ONNX
- **Protocol**: Agent2Agent (A2A) via gRPC
- **Features**: Binary classification, attack type detection, feature importance
- **Performance**: <10ms inference time

#### LLM Explanation Agent
- **Model**: OpenAI GPT-4o-mini / GPT-4
- **Framework**: LangChain
- **Output**: Structured explanations (Pydantic models)
- **Priority**: 4 levels (Critical, High, Medium, Low)

#### PagerDuty Alert Agent
- **API**: Events API v2
- **Trigger**: Conditional (malicious flows only)
- **Features**: Deduplication, severity mapping, rich context

#### InfluxDB Storage Agent
- **Database**: InfluxDB 2.7+
- **Measurements**: 3 types (network_flow, flow_classification, llm_explanation)
- **Indexing**: Tag-based (src_ip, dst_ip, protocol, attack_type)

### 2. Message Broker

#### NATS
- **Version**: 2.10+
- **Features**: Pub/sub, JetStream persistence, load balancing
- **Subjects**: Hierarchical (nids.flows, nids.alerts, etc.)
- **Performance**: 10M+ messages/second

### 3. Orchestration Layer

#### Workflow Orchestrator
- **State Management**: NIDSState (TypedDict)
- **Execution**: Step-by-step with error handling
- **Metrics**: Flows, classifications, alerts, storage points

## Data Models

### Network Flow (16 Features)
```python
[
    "bidirectional_packets",    # Total packets
    "bidirectional_bytes",      # Total bytes
    "duration_ms",              # Flow duration
    "src_port",                 # Source port
    "dst_port",                 # Destination port
    "protocol",                 # IP protocol (6=TCP, 17=UDP)
    "packet_size_mean",         # Average packet size
    "packet_size_std",          # Packet size std dev
    "packet_size_min",          # Min packet size
    "packet_size_max",          # Max packet size
    "iat_mean",                 # Inter-arrival time mean
    "iat_std",                  # Inter-arrival time std dev
    "forward_packets",          # Forward direction packets
    "reverse_packets",          # Reverse direction packets
    "forward_bytes",            # Forward direction bytes
    "reverse_bytes"             # Reverse direction bytes
]
```

### Classification Result
```python
{
    "flow_id": int,
    "prediction": int,              # 0=benign, 1=malicious
    "prediction_label": str,        # "benign" | "malicious"
    "confidence": float,            # 0.0-1.0
    "attack_type": str,             # dos, ddos, port_scan, etc.
    "risk_score": float,            # 0.0-1.0
    "is_anomaly": bool,
    "feature_importance": dict,
    "processing_time_ms": float
}
```

### LLM Explanation
```python
{
    "flow_id": int,
    "priority": str,                # Critical, High, Medium, Low
    "explanation": str,
    "threat_assessment": str,
    "recommended_actions": list,
    "key_reasoning_factors": list,
    "attack_vector_analysis": str,
    "generation_time_ms": float
}
```

## Communication Protocols

### Agent2Agent (A2A)
- **Transport**: gRPC streaming
- **Message Format**: Protobuf
- **Features**: Task status tracking, bidirectional streaming
- **Port**: 50051 (default)

### NATS Messaging
- **Transport**: TCP
- **Protocol**: NATS protocol
- **Subjects**: Hierarchical naming (nids.*)
- **Port**: 4222 (default)

### InfluxDB Line Protocol
- **Transport**: HTTP
- **Format**: InfluxDB line protocol
- **API**: v2 API with token auth
- **Port**: 8086 (default)

## State Transitions

```
INITIALIZED
    ↓
CAPTURING (Packet Capture Agent)
    ↓
CLASSIFYING (XGBoost Classifier)
    ↓
EXPLAINING (LLM Agent)
    ↓
    ├─→ ALERTING (PagerDuty - if malicious)
    └─→ STORING (InfluxDB - all flows)
    ↓
COMPLETED
```

## Priority Classification

| Confidence | Priority | PagerDuty Severity |
|-----------|----------|-------------------|
| ≥ 90% | Critical | critical |
| 70-90% | High | error |
| 50-70% | Medium | warning |
| < 50% | Low | info |

## Attack Types

- **normal**: Benign traffic
- **dos**: Denial of Service
- **ddos**: Distributed Denial of Service
- **port_scan**: Network reconnaissance
- **brute_force**: Authentication attacks
- **malware**: Malware communication
- **botnet**: Botnet C&C traffic
- **sql_injection**: Database attacks
- **xss**: Cross-site scripting
- **probe**: Network probing

## Kubernetes Architecture

```
┌─────────────────────────────────────┐
│         Namespace: nids             │
├─────────────────────────────────────┤
│                                     │
│  ┌──────────────────────────────┐  │
│  │ Deployment: classifier        │  │
│  │ - Replicas: 2-10 (HPA)       │  │
│  │ - Port: 50051 (gRPC)         │  │
│  │ - Service: ClusterIP         │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌──────────────────────────────┐  │
│  │ Deployment: llm               │  │
│  │ - Replicas: 2-5 (HPA)        │  │
│  │ - OpenAI API integration     │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌──────────────────────────────┐  │
│  │ StatefulSet: influxdb         │  │
│  │ - Replicas: 1                │  │
│  │ - PVC: 50Gi                  │  │
│  │ - Port: 8086                 │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌──────────────────────────────┐  │
│  │ Deployment: nats              │  │
│  │ - Replicas: 1                │  │
│  │ - Port: 4222                 │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌──────────────────────────────┐  │
│  │ Deployment: ui                │  │
│  │ - Replicas: 2                │  │
│  │ - Service: LoadBalancer      │  │
│  │ - Port: 80                   │  │
│  └──────────────────────────────┘  │
│                                     │
└─────────────────────────────────────┘
```

## Security Architecture

### Pod Security
- Non-root user (UID 1000)
- Read-only root filesystem
- Dropped capabilities (ALL)
- No privilege escalation

### Network Security
- NetworkPolicy: Ingress/egress rules
- ClusterIP for internal services
- LoadBalancer only for UI
- TLS/gRPC encryption

### Secret Management
- Kubernetes Secrets
- Environment variable injection
- No hardcoded credentials
- Token rotation support

## Performance Characteristics

### Latency (p50/p95/p99)
- NATS publish: <1ms / <2ms / <5ms
- ML inference: 5ms / 10ms / 15ms
- LLM generation: 1000ms / 2000ms / 3000ms
- End-to-end: 2000ms / 4000ms / 5000ms

### Throughput
- Packet capture: 10,000 flows/sec
- NATS broker: 10M+ msg/sec
- ML classification: 1,000 flows/sec
- LLM explanation: 500 req/min (OpenAI limit)

### Scalability
- Horizontal: HPA 2-10 replicas
- Vertical: Resource requests/limits
- Auto-scaling: CPU/memory based

## Monitoring & Observability

### Metrics
- Flows captured
- Malicious flow rate
- Alert count
- Processing latency
- Resource utilization

### Health Checks
- Liveness: TCP socket check
- Readiness: HTTP /health endpoint
- Startup: Grace period 30s

### Logging
- Structured JSON logs
- Log levels: DEBUG, INFO, WARNING, ERROR
- Centralized via stdout

## Deployment Patterns

### Single Node
- Docker Compose
- All-in-one container
- Local development

### Kubernetes Cluster
- Helm chart deployment
- Auto-scaling enabled
- Production-ready

### Hybrid
- NATS on separate cluster
- InfluxDB on dedicated nodes
- Agents distributed

## Cost Optimization

### Compute
- HPA min replicas: 2
- Resource requests tuning
- Spot instances support

### Storage
- InfluxDB retention policies
- Compaction enabled
- Size-based PVC

### API
- OpenAI model selection (gpt-4o-mini cheaper)
- Batch processing
- Caching strategies

---

**Last Updated**: 2025-12-26
**Version**: 1.0.0
