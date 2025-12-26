# Agentic NIDS - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Option 1: Quick Test with Synthetic Data (Fastest)

```bash
# 1. Install dependencies
cd agent
pip install -e ".[all]"

# 2. Set OpenAI API key
export OPENAI_API_KEY="sk-your-key-here"

# 3. Run test
python main.py --mode test
```

**Expected Output:**
```
[INFO] Starting classifier agent on port 50051
[INFO] Classifier agent initialized
[INFO] Connecting to classifier...
[INFO] Classifying synthetic flows...

✓  [1/20] 192.168.1.100 -> 10.0.0.50     | normal     | risk: low      | conf: 0.85
⚠️ [2/20] 192.168.1.101 -> 203.0.113.45 | MALICIOUS  | risk: high     | conf: 0.87
    └─ Port scan detected with high confidence. Potential reconnaissance activity...
...
Test Summary: 6/20 malicious flows detected
```

### Option 2: Analyze PCAP File

```bash
# Download sample PCAP
wget https://example.com/sample-traffic.pcap -O data/pcap/sample.pcap

# Analyze
python main.py --mode pcap --pcap data/pcap/sample.pcap --interval 60
```

### Option 3: Live Capture (Requires Root)

```bash
# Capture from eth0 interface
sudo python main.py --mode live --interface eth0 --interval 180
```

## 🐳 Docker Quick Start

```bash
# Build all-in-one image
docker build -t agentic-nids -f infra/docker/Dockerfile.all-in-one .

# Run with environment variables
docker run -it \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -e PAGERDUTY_ROUTING_KEY=$PAGERDUTY_ROUTING_KEY \
  -p 50051:50051 \
  agentic-nids
```

## ☸️ Kubernetes Quick Start

```bash
# 1. Create namespace
kubectl create namespace nids

# 2. Create secrets
kubectl create secret generic agentic-nids-secrets \
  --from-literal=openaiApiKey=$OPENAI_API_KEY \
  --from-literal=pagerdutyRoutingKey=$PAGERDUTY_ROUTING_KEY \
  --from-literal=influxdbToken=$(openssl rand -base64 32) \
  --from-literal=influxdbPassword=$(openssl rand -base64 32) \
  -n nids

# 3. Install Helm chart
helm install agentic-nids ./infra/helm/agentic-nids \
  --namespace nids

# 4. Check deployment
kubectl get pods -n nids

# 5. Access UI
kubectl get svc agentic-nids-ui -n nids
# Open the EXTERNAL-IP in browser
```

## 🎯 What to Try Next

### 1. Train Your Own Model

```bash
cd agent/models

# Generate synthetic training data
python train_xgboost_model.py --synthetic --output custom_model.onnx

# Or use your own dataset
python train_xgboost_model.py --data your_flows.csv --output custom_model.onnx
```

### 2. Configure Collection Interval

Edit `agent/config/ndpi_agent.yaml`:
```yaml
collection_interval: 60  # Changed from 180 (3 min) to 60 (1 min)
```

### 3. Enable PagerDuty Alerts

```bash
# Set routing key
export PAGERDUTY_ROUTING_KEY="R0xxxxxxxxxxxxxxxxxxxxx"

# Run with PagerDuty enabled
python main.py --mode test
```

### 4. View Results in InfluxDB

```bash
# Start InfluxDB
docker run -d --name influxdb -p 8086:8086 influxdb:2.7

# Access UI
open http://localhost:8086

# Query malicious flows
# Bucket: network_security
# Measurement: flow_classification
# Filter: prediction = "malicious"
```

## 📊 Understanding the Output

### Classification Result
```json
{
  "flow_id": 12345,
  "prediction_label": "malicious",
  "confidence": 0.87,
  "attack_type": "port_scan",
  "risk_score": 0.75,
  "is_anomaly": true
}
```

### LLM Explanation
```json
{
  "priority": "High",
  "explanation": "Port scan detected...",
  "recommended_actions": [
    "Block source IP",
    "Investigate destination",
    "Alert security team"
  ]
}
```

## 🔧 Common Issues

### Issue: OPENAI_API_KEY not set
```bash
export OPENAI_API_KEY="sk-your-key-here"
```

### Issue: Port 50051 already in use
```bash
# Use different port
python main.py --mode classifier --port 50052
```

### Issue: Permission denied for live capture
```bash
# Run with sudo
sudo -E python main.py --mode live --interface eth0
```

### Issue: NATS connection failed
```bash
# Start NATS server
docker run -d --name nats -p 4222:4222 nats:2.10
```

## 📚 Next Steps

1. **Read the Docs**: See [README.md](README.md) for full documentation
2. **Deploy to Production**: See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
3. **Understand Architecture**: See [IMPLEMENTATION.md](IMPLEMENTATION.md)
4. **View Summary**: See [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)

## 💡 Pro Tips

- Use `--debug` flag for verbose logging
- Start with synthetic data to test the system
- Monitor resource usage with `kubectl top pods -n nids`
- Check logs with `kubectl logs -f deployment/classifier -n nids`
- Scale manually with `kubectl scale deployment classifier --replicas=5`

## 🆘 Getting Help

- Check [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for troubleshooting
- View agent logs for detailed error messages
- Ensure all environment variables are set correctly
- Verify network connectivity between components

---

**Ready to start?** Choose an option above and begin detecting network threats with AI! 🎉
