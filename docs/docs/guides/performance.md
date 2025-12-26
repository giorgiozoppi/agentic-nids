---
sidebar_position: 3
---

# Performance Tuning

## System Requirements

- CPU: 4+ cores recommended
- RAM: 8GB minimum, 16GB recommended
- Network: 1Gbps+ for high-traffic environments

## Optimization Tips

### ONNX Runtime

- Use GPU acceleration when available
- Configure thread pool size based on CPU cores

### NATS Configuration

- Tune message buffer sizes
- Enable JetStream for persistence

### InfluxDB

- Configure retention policies
- Optimize shard duration for your use case
