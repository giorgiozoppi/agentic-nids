---
sidebar_position: 1
---

# Kubernetes Deployment

All manifests live in `infra/k8s/`. Apply them with Kustomize:

```bash
kubectl apply -k infra/k8s/
```

Kustomize ordering:
1. `namespace.yaml` — `nids` namespace with label `vault-injection: enabled`
2. `vault/vault-server.yaml` — Vault StatefulSet (Raft storage)
3. `vault/vault-agent-injector.yaml` — MutatingWebhookConfiguration
4. `vault/vault-init-job.yaml` — bootstrap Job (init + K8s auth + secrets)
5. `nats-deployment.yaml`
6. `clickhouse-statefulset.yaml`
7. `nids-collector-deployment.yaml`
8. `classifier-deployment.yaml`
9. `orchestrator-cronjob.yaml`

## Prerequisites

- Kubernetes 1.28+
- A default StorageClass for PVCs
- `kubectl` configured

## Vault bootstrap

The init Job runs once and:
1. Initialises Vault (`-key-shares=1 -key-threshold=1`)
2. Stores the unseal key and root token in K8s Secret `vault-keys`
3. Enables KV-v2 at `kv/`
4. Writes secrets at `kv/nids/{clickhouse,nats,collector}`
5. Configures Kubernetes auth and creates role `nids` bound to all service accounts in namespace `nids`

> **Production note**: Replace the single-key unseal with Vault auto-unseal
> (AWS KMS, GCP Cloud KMS, etc.) before going to production.

## Injected secrets

Each workload receives credentials via Vault Agent sidecar annotations.
Files are mounted at `/vault/secrets/`:

| Workload | Secret path | File |
|----------|-------------|------|
| NATS | `kv/data/nids/nats` | `nats.conf` |
| ClickHouse | `kv/data/nids/clickhouse` | `users.xml`, `clickhouse.env` |
| Collector | `kv/data/nids/collector` | `collector.env` |
| Orchestrator | `kv/data/nids/clickhouse` | `clickhouse.env` |
| Classifier | `kv/data/nids/nats` | `nats.env` |

## Workload overview

### NATS Deployment

```yaml
serviceAccountName: nats
image: nats:2-alpine
ports: [4222, 8222]
# vault annotations inject nats.conf with auth credentials
```

### ClickHouse StatefulSet

```yaml
serviceAccountName: clickhouse
image: clickhouse/clickhouse-server:24-alpine
volumeClaimTemplates:
  - name: data, 20Gi
# init-container copies /vault/secrets/users.xml to /etc/clickhouse-server/users.d/
```

### NFStream Collector Deployment

```yaml
serviceAccountName: nids-collector
hostNetwork: true               # required for packet capture
securityContext:
  capabilities:
    add: [NET_ADMIN, NET_RAW]   # required for packet capture
# collector.env and nats.env injected from Vault
```

### Classifier Deployment + Service

```yaml
image: nids-classifier:latest
volumeMounts:
  - name: models, mountPath: /models   # 2Gi PVC
ports: [50051]
---
apiVersion: v1
kind: Service
spec:
  clusterIP: true
  port: 50051
```

The ONNX model must be loaded into the PVC before the classifier starts.
One-time seeding:

```bash
kubectl cp /local/path/classifier.onnx \
  nids/$(kubectl get pod -n nids -l app=classifier -o jsonpath='{.items[0].metadata.name}'):/models/classifier.onnx
```

### Orchestrator CronJob

```yaml
schedule: "*/5 * * * *"
concurrencyPolicy: Forbid
restartPolicy: OnFailure
volumeMounts:
  - name: state, mountPath: /state   # 1Gi PVC — persists cursor
```

## Verification

```bash
# Check all pods
kubectl get pods -n nids

# Watch orchestrator runs
kubectl get jobs -n nids -w

# Query stored threats
kubectl exec -n nids deploy/clickhouse -- \
  clickhouse-client --query \
  "SELECT detected_at, label, confidence, src_ip, dst_ip
   FROM nids.security_events
   ORDER BY detected_at DESC LIMIT 20"

# Classifier logs
kubectl logs -n nids deploy/classifier -f

# Orchestrator logs (latest job)
kubectl logs -n nids -l job-name=$(kubectl get jobs -n nids --sort-by=.metadata.creationTimestamp -o name | tail -1 | cut -d/ -f2)
```

## Tear down

```bash
kubectl delete -k infra/k8s/
# PVCs are not deleted automatically — remove manually if needed:
kubectl delete pvc -n nids --all
```
