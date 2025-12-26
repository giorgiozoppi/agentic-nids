---
sidebar_position: 3
---

# System Workflow

## End-to-End Flow Detection Pipeline

1. **Packet Capture** - Network traffic collection
2. **Flow Extraction** - nDPI protocol detection
3. **ML Classification** - XGBoost threat detection
4. **LLM Explanation** - AI-generated threat analysis
5. **Alert Generation** - PagerDuty incident creation
6. **Data Storage** - InfluxDB persistence

## Real-Time Processing

The system processes network flows in real-time with sub-second latency.
