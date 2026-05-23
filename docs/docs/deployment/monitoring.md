---
sidebar_position: 3
---

# Monitoring and Operations

## Querying security events

```sql
-- Most recent threats
SELECT detected_at, label, confidence, src_ip, dst_ip, src_port, dst_port
FROM nids.security_events
ORDER BY detected_at DESC
LIMIT 50;

-- Attack breakdown by label (last 24 hours)
SELECT label, count() AS count, avg(confidence) AS avg_confidence
FROM nids.security_events
WHERE detected_at > now() - INTERVAL 1 DAY
GROUP BY label
ORDER BY count DESC;

-- Top attacking source IPs
SELECT src_ip, count() AS events
FROM nids.security_events
WHERE detected_at > now() - INTERVAL 1 HOUR
GROUP BY src_ip
ORDER BY events DESC
LIMIT 20;

-- Full probability breakdown for a specific flow
SELECT label, confidence,
       JSONExtractFloat(probabilities, 'BENIGN')     AS p_benign,
       JSONExtractFloat(probabilities, 'DoS')        AS p_dos,
       JSONExtractFloat(probabilities, 'DDoS')       AS p_ddos,
       JSONExtractFloat(probabilities, 'PortScan')   AS p_portscan,
       JSONExtractFloat(probabilities, 'BruteForce') AS p_bruteforce,
       JSONExtractFloat(probabilities, 'WebAttack')  AS p_webattack,
       JSONExtractFloat(probabilities, 'Botnet')     AS p_botnet,
       JSONExtractFloat(probabilities, 'Malware')    AS p_malware
FROM nids.security_events
WHERE flow_id = 'your-flow-id';
```

## Watching live flow ingestion

```bash
# Row count growing in real time
watch -n2 'docker exec agent-clickhouse-1 \
  clickhouse-client --query "SELECT count() FROM nids.flows"'

# Latest 10 ingested flows
docker exec agent-clickhouse-1 \
  clickhouse-client --query \
  "SELECT collected_at, src_ip, dst_ip, application_name, bidirectional_bytes
   FROM nids.flows ORDER BY collected_at DESC LIMIT 10"
```

## Classifier service health

```bash
# Using grpc_health_probe
grpc_health_probe -addr :50051

# Or use grpcurl
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 nids.classifier.v1.ClassifierService/ClassifyBatch
```

## Orchestrator run history (Kubernetes)

```bash
# List recent CronJob runs
kubectl get jobs -n nids --sort-by=.metadata.creationTimestamp

# Logs for the latest run
kubectl logs -n nids \
  -l job-name=$(kubectl get jobs -n nids --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{.items[-1].metadata.name}')

# Current cursor (last processed timestamp)
kubectl exec -n nids <orchestrator-pod> -- cat /state/last_processed_at
```

## Log fields

All Go components log structured JSON. Key fields:

| Component | Field | Description |
|-----------|-------|-------------|
| orchestrator | `attack` | Label of stored event |
| orchestrator | `confidence` | Predicted class probability |
| orchestrator | `flow_id` | Correlates to `nids.flows` |
| orchestrator | `cursor` | Timestamp after each page |
| classifier | `lib` | ORT library path at startup |
| classifier | `model` | ONNX model path at startup |

## ClickHouse table health

```sql
-- Storage size per table
SELECT table, formatReadableSize(sum(bytes)) AS size
FROM system.parts
WHERE database = 'nids' AND active
GROUP BY table;

-- Check NATS engine connection status
SELECT * FROM system.nats_consumers;
```
