---
sidebar_position: 2
---

# Data Models

## Network Flow Data Structure

The system uses a standardized data model for network flows extracted from packet captures.

### Flow Features

```python
{
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.50",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "bytes_sent": 1024,
  "bytes_received": 2048,
  "duration": 1.5,
  "packet_count": 15
}
```

## ML Model Input Format

Feature vector for XGBoost classifier (ONNX format).

## Storage Schema

InfluxDB measurement schema for time-series storage.
