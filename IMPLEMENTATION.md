# Agentic NIDS Implementation Guide

## System Overview

This implementation realizes the complete Agentic Network Intrusion Detection System as specified in the intellectual property disclosure. The system implements a multi-agent architecture with the following components:

### Agent Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     NIDS Multi-Agent Workflow                        │
└─────────────────────────────────────────────────────────────────────┘

1. Packet Capture Agent (nDPI)
   ↓ (publishes to NATS: nids.flows)
2. NATS Message Broker
   ↓ (distributes flows)
3. XGBoost Classifier Agent (A2A Server)
   ↓ (ML inference + feature importance)
4. LLM Explanation Agent (OpenAI GPT-4)
   ↓ (generates human-readable explanations)
5a. PagerDuty Alert Agent (conditional - malicious flows only)
5b. InfluxDB Storage Agent (all flows)
   ↓
6. Vue.js Dashboard (visualization)
```

## Implemented Components

### 1. NATS Message Broker Integration
**Location:** `agent/agents/nats/`

- **NATSClient**: Async pub/sub client for flow distribution
- **Subject naming**: Hierarchical subject structure (nids.flows, nids.alerts, etc.)
- **JetStream support**: Optional persistence and replay
- **Load balancing**: Queue groups for horizontal scaling

**Usage:**
```python
from agents.nats import NATSClient, NATSConfig, NIDSSubjects

config = NATSConfig(servers=["nats://localhost:4222"])
client = NATSClient(config)
await client.connect()

# Publish flow
await client.publish(NIDSSubjects.FLOWS, flow_data)

# Subscribe to flows
async def handle_flow(flow_data):
    # Process flow
    pass

await client.subscribe(NIDSSubjects.FLOWS, handle_flow)
```

### 2. LLM Explanation Agent
**Location:** `agent/agents/llm/`

- **Model**: GPT-4o-mini (configurable)
- **Priority classification**: Critical (≥90%), High (70-90%), Medium (50-70%), Low (<50%)
- **Structured output**: Pydantic models for parsing
- **Prompt engineering**: Tailored prompts for security analysis

**Features:**
- Threat explanation and assessment
- Risk level justification
- Recommended security actions
- Key reasoning factors
- Attack vector analysis

**Usage:**
```python
from agents.llm import LLMExplanationAgent

agent = LLMExplanationAgent(
    api_key="sk-...",
    model="gpt-4o-mini"
)

result = await agent.explain_classification(flow_data, classification_result)
print(result.priority)  # Priority.HIGH
print(result.explanation)
print(result.recommended_actions)
```

### 3. PagerDuty Alert Agent
**Location:** `agent/agents/pagerduty/`

- **Events API v2**: Standard PagerDuty integration
- **Severity mapping**: Critical/Error/Warning based on ML confidence
- **Deduplication**: Flow-based dedup keys
- **Rich context**: Includes flow metadata, classification, LLM explanation

**Usage:**
```python
from agents.pagerduty import PagerDutyAlertAgent, PagerDutyConfig

config = PagerDutyConfig(routing_key="R0...")
async with PagerDutyAlertAgent(config) as agent:
    incident = await agent.send_alert(
        flow_data,
        classification_result,
        llm_explanation
    )
```

### 4. InfluxDB Storage Agent
**Location:** `agent/agents/influxdb/`

- **Three measurements**:
  - `network_flow`: Raw flow data
  - `flow_classification`: ML predictions
  - `llm_explanation`: AI explanations
- **Tag-based indexing**: src_ip, dst_ip, protocol, attack_type
- **Retention policies**: Configurable data lifecycle

**Usage:**
```python
from agents.influxdb import InfluxDBStorageAgent, InfluxDBConfig

config = InfluxDBConfig(
    url="http://localhost:8086",
    token="...",
    org="nids",
    bucket="network_security"
)

with InfluxDBStorageAgent(config) as agent:
    agent.write_complete_record(
        flow_data,
        classification_result,
        llm_explanation
    )
```

### 5. Workflow Orchestrator
**Location:** `agent/workflows/nids_workflow.py`

- **NIDSState**: Typed state dictionary with immutable transitions
- **Step-by-step execution**: Capture → Classify → Explain → Alert → Store
- **Error handling**: Graceful degradation and error tracking
- **Metrics collection**: Flows processed, malicious count, alerts sent

**Usage:**
```python
from workflows.nids_workflow import NIDSWorkflowOrchestrator, NIDSWorkflowConfig

config = NIDSWorkflowConfig(
    capture_source="eth0",
    openai_api_key="sk-...",
    pagerduty_routing_key="R0...",
    enable_llm_explanation=True,
    enable_pagerduty_alerts=True
)

orchestrator = NIDSWorkflowOrchestrator(config)
final_state = await orchestrator.execute_workflow(flows)

print(f"Processed: {final_state['flows_captured']}")
print(f"Malicious: {final_state['malicious_count']}")
print(f"Alerts: {final_state['alerts_sent_count']}")
```

## Deployment

### Docker Deployment

**Multi-stage Dockerfiles:**
- `infra/docker/Dockerfile.classifier`: XGBoost classifier agent
- `infra/docker/Dockerfile.all-in-one`: Complete NIDS system

**Build images:**
```bash
# Classifier only
docker build -t agentic-nids-classifier:latest \
  -f infra/docker/Dockerfile.classifier .

# All-in-one
docker build -t agentic-nids:latest \
  -f infra/docker/Dockerfile.all-in-one .
```

### Kubernetes Deployment

**Helm Chart:** `infra/helm/agentic-nids/`

**Components:**
- **Deployment**: Classifier agents (HPA enabled, 2-10 replicas)
- **StatefulSet**: InfluxDB (persistent storage)
- **Service**: ClusterIP for internal gRPC, LoadBalancer for UI
- **ConfigMap**: NATS URL, service endpoints
- **Secret**: API keys (OpenAI, PagerDuty, InfluxDB)
- **NetworkPolicy**: Restrict inter-pod communication

**Deploy:**
```bash
cd infra/helm

# Install
helm install agentic-nids ./agentic-nids \
  --namespace nids \
  --create-namespace \
  --set secrets.openaiApiKey="sk-..." \
  --set secrets.pagerdutyRoutingKey="R0..." \
  --set influxdb.persistence.size=50Gi

# Upgrade
helm upgrade agentic-nids ./agentic-nids \
  --namespace nids

# Uninstall
helm uninstall agentic-nids --namespace nids
```

**Access services:**
```bash
# Get UI LoadBalancer IP
kubectl get svc -n nids agentic-nids-ui

# Port-forward InfluxDB
kubectl port-forward -n nids svc/agentic-nids-influxdb-service 8086:8086

# Port-forward classifier (for testing)
kubectl port-forward -n nids svc/agentic-nids-classifier-service 50051:50051
```

## Model Training

**Script:** `agent/models/train_xgboost_model.py`

**Train with synthetic data:**
```bash
cd agent/models
python train_xgboost_model.py --synthetic --output xgboost_model.onnx
```

**Train with real data:**
```bash
python train_xgboost_model.py \
  --data /path/to/flows.csv \
  --output xgboost_model.onnx \
  --test-size 0.2
```

**Expected CSV format:**
```
bidirectional_packets,bidirectional_bytes,duration_ms,src_port,dst_port,protocol,...,label
1523,2048576,45000,54321,443,6,...,1
```

## Configuration

### Environment Variables

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."

# PagerDuty
export PAGERDUTY_ROUTING_KEY="R0..."

# InfluxDB
export INFLUXDB_URL="http://localhost:8086"
export INFLUXDB_TOKEN="..."
export INFLUXDB_ORG="nids"
export INFLUXDB_BUCKET="network_security"

# NATS
export NATS_URL="nats://localhost:4222"
```

### YAML Configuration

**Collector Agent:** `agent/config/ndpi_agent.yaml`
```yaml
collection_interval: 180  # 3 minutes
batch_size: 100
classifier_agent_url: "grpc://localhost:50051"
alert_threshold: 0.7
```

## Testing

### Unit Tests

```bash
cd agent
pytest tests/ -v --cov=agents
```

### Integration Tests

```bash
# Start dependencies
docker-compose up -d nats influxdb

# Run integration tests
pytest tests/integration/ -v

# Cleanup
docker-compose down
```

### End-to-End Test

```bash
# Run with synthetic data
python main.py --mode test

# Expected output:
# ✓  [1/20] ... | normal   | risk: low     | conf: 0.85
# ⚠️ [2/20] ... | MALICIOUS | risk: high    | conf: 0.87
# ...
# Test Summary: 6/20 malicious flows detected
```

## Performance Characteristics

Based on IP disclosure specifications:

**Throughput:**
- Packet Capture: ~10,000 flows/second
- NATS Broker: 10M+ messages/second capability
- XGBoost Classification: ~1,000 classifications/second
- LLM Explanation: Limited by OpenAI rate limits (500 req/min)

**Latency:**
- NATS Message Delivery: <1ms
- ML Inference (ONNX): <10ms per flow
- LLM Generation: 1-3 seconds
- End-to-End (capture to alert): <5 seconds

**Scalability:**
- Horizontal scaling via Kubernetes HPA
- Auto-scaling range: 2-10 classifier replicas
- Target CPU utilization: 70%

## Security Features

**Pod Security:**
- Non-root user execution (UID 1000)
- Read-only root filesystem
- Dropped Linux capabilities
- No privilege escalation

**Network Security:**
- Network policies enabled
- TLS/gRPC encryption
- ClusterIP for internal services
- LoadBalancer only for UI

**Secret Management:**
- Kubernetes Secrets for API keys
- Environment variable injection
- No hardcoded credentials

## Monitoring and Observability

**Metrics:**
- Flows captured/classified
- Malicious flow rate
- Alert count
- Processing latency
- Resource utilization

**Dashboards:**
- InfluxDB native dashboards
- Grafana integration (optional)
- Vue.js real-time UI

**Health Checks:**
- Liveness probes (TCP/HTTP)
- Readiness probes
- Startup probes

## Troubleshooting

### NATS Connection Issues
```bash
# Check NATS server
kubectl logs -n nids deployment/nats

# Test connectivity
nats-cli server ping nats://nats-service:4222
```

### Classifier Not Responding
```bash
# Check logs
kubectl logs -n nids deployment/agentic-nids-classifier

# Check HPA status
kubectl get hpa -n nids

# Manual scaling
kubectl scale deployment agentic-nids-classifier --replicas=5 -n nids
```

### InfluxDB Storage Full
```bash
# Check PVC usage
kubectl get pvc -n nids

# Resize PVC (if supported)
kubectl patch pvc influxdb-data -n nids -p '{"spec":{"resources":{"requests":{"storage":"100Gi"}}}}'
```

## Future Enhancements

1. **Enhanced ML Models**: Support for deep learning models (LSTM, Transformer)
2. **Real-time Streaming**: Apache Kafka integration
3. **Distributed Tracing**: OpenTelemetry instrumentation
4. **Advanced Alerting**: Slack, Teams, Email integrations
5. **Threat Intelligence**: Feed integration (STIX/TAXII)
6. **Auto-remediation**: Automated firewall rule updates

## References

- IP Disclosure Document: Full system specification
- [Google A2A Protocol](https://a2a-protocol.org/)
- [ONNX Runtime](https://onnxruntime.ai/)
- [NATS Messaging](https://nats.io/)
- [LangChain](https://python.langchain.com/)
- [PagerDuty Events API](https://developer.pagerduty.com/docs/events-api-v2/overview/)
- [InfluxDB](https://docs.influxdata.com/)
