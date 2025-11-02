# nDPI Flow Collector with A2A Classifier Integration

Complete guide for the nDPI-based flow collector agent that integrates with the classifier agent using Google's A2A protocol.

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Traffic                           │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│         nDPI Flow Collector Agent (A2A Client)              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ • Packet capture (live/PCAP)                          │  │
│  │ • Flow aggregation (configurable interval)            │  │
│  │ • nDPI protocol detection                             │  │
│  │ • Batch processing                                    │  │
│  └───────────────────────────────────────────────────────┘  │
└────────────────────┬────────────────────────────────────────┘
                     │ A2A Protocol (gRPC)
                     │ Every 3 minutes (configurable)
                     ▼
┌─────────────────────────────────────────────────────────────┐
│         Classifier Agent (A2A Server)                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ • ONNX model inference                                │  │
│  │ • Attack classification                               │  │
│  │ • Anomaly detection                                   │  │
│  │ • Risk assessment                                     │  │
│  │ • Explainable AI                                      │  │
│  └───────────────────────────────────────────────────────┘  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Results & Actions                              │
│  • Alerts on malicious flows                                │
│  • Automatic blocking (optional)                            │
│  • Webhook notifications                                    │
│  • JSON results export                                      │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Install Dependencies

```bash
cd agent
uv pip install -e ".[all]"

# Or with pip
pip install -e ".[all]"
```

### 2. Quick Test

```bash
# Run quick test with synthetic data
python main.py --mode test
```

### 3. Analyze PCAP File

```bash
# Process a PCAP file with 1-minute collection intervals
python main.py --mode pcap --pcap /path/to/traffic.pcap --interval 60
```

### 4. Live Capture

```bash
# Capture live traffic (requires root/sudo)
sudo python main.py --mode live --interface eth0 --interval 180
```

## Configuration

### YAML Configuration File

The system uses YAML for configuration. Default location: `config/ndpi_agent.yaml`

#### Key Configuration Parameters

```yaml
# Collection interval - how often to send flows to classifier
collection_interval: 180  # 3 minutes (180 seconds)

# Flow timeouts
flow_idle_timeout: 300    # 5 minutes
flow_active_timeout: 1800 # 30 minutes

# Classifier agent URL
classifier_agent_url: "grpc://localhost:50051"

# Batch processing
batch_size: 100
max_concurrent_requests: 10

# Alert settings
alert_threshold: 0.7  # Risk score (0-1) to trigger alerts
auto_block: false     # Enable automatic IP blocking
```

### Configuration Files

Three example configurations are provided:

1. **`config/ndpi_agent.yaml`** - Default configuration
2. **`config/ndpi_agent_live.yaml`** - Optimized for live capture
3. **`config/ndpi_agent_pcap.yaml`** - Optimized for PCAP analysis

### Edit Configuration

```bash
# Create config directory
mkdir -p config

# Edit default configuration
vim config/ndpi_agent.yaml
```

## Usage Modes

### Mode 1: Integrated (Recommended)

Run both classifier and collector together:

```bash
# PCAP analysis
python main.py --mode pcap --pcap data/traffic.pcap --interval 60

# Live capture
sudo python main.py --mode live --interface eth0 --interval 180
```

### Mode 2: Separate Processes

Run classifier and collector in separate terminals:

**Terminal 1 - Start Classifier:**
```bash
python main.py --mode classifier --port 50051
```

**Terminal 2 - Start Collector:**
```bash
python main.py --mode collector --config config/ndpi_agent.yaml
```

### Mode 3: Test Mode

Quick test with synthetic data:

```bash
python main.py --mode test
```

## Collection Interval

The collection interval determines how often flows are aggregated and sent for classification:

- **Short intervals (30-60s)**:
  - More frequent classification
  - Better for real-time detection
  - Higher overhead

- **Medium intervals (2-3 min)**:
  - Good balance (recommended default: 180s)
  - Efficient batching
  - Suitable for most use cases

- **Long intervals (5-10 min)**:
  - Lower overhead
  - Better for high-volume networks
  - Delayed detection

### Changing Collection Interval

**Via command line:**
```bash
python main.py --mode live --interface eth0 --interval 120  # 2 minutes
```

**Via YAML:**
```yaml
collection_interval: 120  # 2 minutes
```

## Flow Processing Pipeline

### 1. Packet Capture

```
Packet → Extract 5-tuple → Update flow record → Aggregate statistics
```

**Flow Key (5-tuple):**
- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol

### 2. Flow Aggregation

Every collection interval (default: 3 minutes), the collector:

1. Gathers all active flows
2. Extracts flow features
3. Batches flows (default: 100 per batch)
4. Sends to classifier via A2A protocol

### 3. Classification

The classifier agent:

1. Receives flow batch
2. Extracts features for ONNX model
3. Runs inference (classification + anomaly detection)
4. Generates explanation
5. Returns results

### 4. Action Handling

Based on classification results:

- **Normal flows**: Logged
- **Suspicious flows**: Alerted
- **High-risk flows** (risk_score >= 0.7):
  - Critical alert
  - Optional automatic blocking
  - Webhook notification

## Flow Features

Features sent to classifier:

### Basic Features
- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
- `packets_forward`, `packets_reverse`
- `bytes_forward`, `bytes_reverse`
- `duration`

### Timing Features
- `iat_mean`, `iat_std`, `iat_min`, `iat_max` (inter-arrival time)
- `packets_per_second`
- `bytes_per_second`

### Protocol Features
- `detected_protocol` (HTTP, HTTPS, DNS, etc.)
- `tcp_flags_forward`, `tcp_flags_reverse`
- `tos`, `ttl_min`, `ttl_max`

### nDPI Features
- `ndpi_protocol_id`
- `ndpi_risk_flags`
- `risk_score`

## Output Files

### Classification Results

Location: `results/classification_results.json`

Contains:
- Timestamp
- Statistics
- Last 100 classification results
- Last 50 malicious flows

```json
{
  "timestamp": "2025-11-02T14:30:00",
  "stats": {
    "flows_classified": 1523,
    "malicious_detected": 47
  },
  "results": [...],
  "malicious_flows": [...]
}
```

### Logs

Location: `logs/ndpi_agent.log`

Contains:
- Agent startup/shutdown
- Flow collection events
- Classification results
- Alerts and errors

## Advanced Features

### Async Classification

Enable parallel classification requests:

```yaml
enable_async_classification: true
max_concurrent_requests: 20
```

### Retry Logic

Automatic retry on classification failures:

```yaml
retry_attempts: 3
retry_delay: 5  # seconds
```

### BPF Filters

Filter captured traffic:

```yaml
bpf_filter: "tcp port 80 or tcp port 443"
```

### Automatic Blocking

⚠️ **Use with caution!**

```yaml
auto_block: true
```

This will attempt to block malicious source IPs (requires implementation of actual firewall rules).

### Webhook Alerts

Send alerts to external system:

```yaml
alert_webhook: "https://your-webhook-url.com/alerts"
```

## Statistics

The system prints statistics every minute (configurable):

```
======================================================================
nDPI Collector Agent Statistics
======================================================================
Uptime:                  3600s
Collections:             20
Total packets:           1523450
Total flows:             8234
Active flows:            421
Flows classified:        7813
Malicious detected:      47
Classification errors:   0
======================================================================
```

## Performance Tuning

### For Live Capture

```yaml
collection_interval: 180
batch_size: 100
max_concurrent_requests: 20
```

### For PCAP Analysis

```yaml
collection_interval: 60
batch_size: 200
max_concurrent_requests: 50
```

### For High-Volume Networks

```yaml
collection_interval: 300
max_flows: 500000
batch_size: 200
```

## Troubleshooting

### "Permission denied" on live capture

Run with sudo:
```bash
sudo python main.py --mode live --interface eth0
```

### "Failed to connect to classifier"

Ensure classifier is running:
```bash
# In separate terminal
python main.py --mode classifier
```

### High memory usage

Reduce max_flows and increase collection_interval:
```yaml
max_flows: 50000
collection_interval: 300
```

### Classification timeouts

Increase timeout and reduce concurrency:
```yaml
classifier_timeout: 60
max_concurrent_requests: 5
```

## Integration with C++ Components

The Python agent can integrate with C++ flow analysis components via:

1. **Shared PCAP files**: C++ writes, Python reads
2. **Named pipes**: Real-time communication
3. **Shared memory**: High-performance IPC
4. **gRPC**: C++ as A2A client

Example C++ integration (pseudo-code):

```cpp
// C++ flow analyzer sends to Python classifier via A2A
A2AClient client("grpc://localhost:50051");
FlowMessage msg = create_flow_message(flow);
ClassificationResult result = client.classify_flow(msg);
```

## Examples

### Example 1: Monitor Web Traffic

```bash
python main.py --mode live --interface eth0 --interval 60
```

Edit `config/ndpi_agent.yaml`:
```yaml
bpf_filter: "tcp port 80 or tcp port 443"
alert_threshold: 0.6
```

### Example 2: Analyze Suspicious PCAP

```bash
python main.py --mode pcap --pcap suspicious_traffic.pcap --interval 30
```

### Example 3: High-Security Mode

```yaml
collection_interval: 60  # More frequent
alert_threshold: 0.5     # Lower threshold
auto_block: true         # Auto-block malicious IPs
alert_webhook: "https://security-alerts.company.com/webhook"
```

## Development

### Adding Custom Features

Edit `ndpi_collector_agent.py`:

```python
def _detect_protocol(self, packet, dst_port: int) -> str:
    """Add your custom protocol detection logic"""
    # Your code here
    pass
```

### Custom Actions

Edit `handle_high_risk_flow()`:

```python
async def handle_high_risk_flow(self, result: Dict):
    # Add custom actions for high-risk flows
    await self.send_to_siem(result)
    await self.update_firewall(result)
    # etc.
```

## See Also

- [classifier_agent_a2a.py](classifier_agent_a2a.py) - Classifier agent implementation
- [client_a2a_example.py](client_a2a_example.py) - A2A client examples
- [README.md](README.md) - General agent documentation
- [A2A Protocol Specification](https://a2a-protocol.org/)

## License

MIT License - See LICENSE file
